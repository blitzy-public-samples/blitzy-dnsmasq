// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Packet Dump Module
//!
//! Rust implementation of pcap-format packet dumping for debugging and
//! troubleshooting, replacing `src/dump.c` (815 lines). The module is
//! gated by the `dumpfile` Cargo feature, matching C's `HAVE_DUMPFILE`.
//!
//! ## Overview
//!
//! Writes DNS queries/responses, DHCP transactions, DHCPv6 messages,
//! Router Advertisement packets, and TFTP transfers to pcap files in
//! standard libpcap format.  Captured packets can be analysed using
//! Wireshark, tcpdump, tshark, or any libpcap-compatible tool.
//!
//! ## pcap Compatibility
//!
//! Files use **DLT_RAW** (data link type 101) — raw IP packets without
//! link-layer headers.  The global file header uses native byte order
//! identified by the magic number `0xa1b2c3d4`.
//!
//! ## Feature Gate
//!
//! All items require the `dumpfile` Cargo feature, matching C's
//! `#ifdef HAVE_DUMPFILE` guard in `src/dump.c`.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{error, info};

use crate::config::constants::EDNS_PKTSZ;
use crate::core::types::DnsmasqError;

// ---------------------------------------------------------------------------
// Protocol & Format Constants
// ---------------------------------------------------------------------------

/// pcap magic number for native byte order.
const PCAP_MAGIC: u32 = 0xa1b2c3d4;

/// pcap file format version 2.4 — major.
const PCAP_VERSION_MAJOR: u16 = 2;

/// pcap file format version 2.4 — minor.
const PCAP_VERSION_MINOR: u16 = 4;

/// Data link type: DLT_RAW — raw IP, no link-layer header.
/// See <http://www.tcpdump.org/linktypes.html>.
const DLT_RAW: u32 = 101;

/// IPv4 version nibble (4).
const IPVERSION: u8 = 4;

/// IPv6 version nibble (6).
const IP6VERSION: u8 = 6;

/// Default IP time-to-live / hop limit for constructed headers.
const IPDEFTTL: u8 = 64;

/// IPv4 IHL (Internet Header Length) in 32-bit words — 5 (no options).
const IPV4_IHL: u8 = 5;

/// IPv4 header size in bytes (5 × 4 = 20).
const IPV4_HEADER_LEN: usize = 20;

/// IPv6 fixed header size in bytes (40).
const IPV6_HEADER_LEN: usize = 40;

/// UDP header size in bytes (8).
const UDP_HEADER_LEN: usize = 8;

/// IP protocol number for UDP (17).
const IPPROTO_UDP: u8 = 17;

/// IP protocol number for ICMPv4 (1).
const IPPROTO_ICMP: u8 = 1;

/// IP protocol number for ICMPv6 (58).
const IPPROTO_ICMPV6: u8 = 58;

// ---------------------------------------------------------------------------
// Dump Mask Constants  (dnsmasq.h lines 922-933)
// ---------------------------------------------------------------------------

/// Dump mask bit-flags controlling which packet types are captured.
///
/// Each flag corresponds to a category of network traffic that can be
/// selectively captured to the pcap dump file.  Multiple flags may be
/// OR-combined.
///
/// Matches C `DUMP_*` defines in `src/dnsmasq.h` lines 922–933.
pub mod mask {
    /// DNS queries from clients to dnsmasq (0x0001).
    pub const DUMP_QUERY: u32 = 0x0001;
    /// DNS replies from dnsmasq to clients (0x0002).
    pub const DUMP_REPLY: u32 = 0x0002;
    /// DNS queries from dnsmasq to upstream servers (0x0004).
    pub const DUMP_UP_QUERY: u32 = 0x0004;
    /// DNS replies from upstream servers to dnsmasq (0x0008).
    pub const DUMP_UP_REPLY: u32 = 0x0008;
    /// DNSSEC validation queries (0x0010).
    pub const DUMP_SEC_QUERY: u32 = 0x0010;
    /// DNSSEC validation replies (0x0020).
    pub const DUMP_SEC_REPLY: u32 = 0x0020;
    /// Bogus DNS responses — failed validation (0x0040).
    pub const DUMP_BOGUS: u32 = 0x0040;
    /// DNSSEC bogus responses (0x0080).
    pub const DUMP_SEC_BOGUS: u32 = 0x0080;
    /// DHCPv4 transactions (0x1000).
    pub const DUMP_DHCP: u32 = 0x1000;
    /// DHCPv6 messages (0x2000).
    pub const DUMP_DHCPV6: u32 = 0x2000;
    /// IPv6 Router Advertisements (0x4000).
    pub const DUMP_RA: u32 = 0x4000;
    /// TFTP file transfers (0x8000).
    pub const DUMP_TFTP: u32 = 0x8000;
}

// ---------------------------------------------------------------------------
// pcap File Header  (dump.c lines 172-231)
// ---------------------------------------------------------------------------

/// libpcap global file header (24 bytes).
///
/// Written at the beginning of every pcap dump file.  Fields are in
/// **native** byte order; the magic number tells readers which
/// endianness to use.
///
/// See <https://wiki.wireshark.org/Development/LibpcapFileFormat>.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PcapFileHeader {
    /// Magic number: `0xa1b2c3d4` for native byte order.
    magic_number: u32,
    /// Major version number (2).
    version_major: u16,
    /// Minor version number (4).
    version_minor: u16,
    /// GMT to local timezone correction (0 for UTC).
    thiszone: u32,
    /// Timestamp accuracy — unused, set to 0.
    sigfigs: u32,
    /// Maximum captured packet length in bytes.
    snaplen: u32,
    /// Data link type: 101 = DLT_RAW (raw IP packets).
    network: u32,
}

impl PcapFileHeader {
    /// Create a new pcap file header with standard values.
    ///
    /// `snaplen` is the maximum capture length per packet, typically
    /// `EDNS_PKTSZ + 200` (matches C `dump_init()` line 387).
    fn new(snaplen: u32) -> Self {
        Self {
            magic_number: PCAP_MAGIC,
            version_major: PCAP_VERSION_MAJOR,
            version_minor: PCAP_VERSION_MINOR,
            thiszone: 0,
            sigfigs: 0,
            snaplen,
            network: DLT_RAW,
        }
    }

    /// Serialise to a writer in **native** byte order.
    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.magic_number.to_ne_bytes())?;
        w.write_all(&self.version_major.to_ne_bytes())?;
        w.write_all(&self.version_minor.to_ne_bytes())?;
        w.write_all(&self.thiszone.to_ne_bytes())?;
        w.write_all(&self.sigfigs.to_ne_bytes())?;
        w.write_all(&self.snaplen.to_ne_bytes())?;
        w.write_all(&self.network.to_ne_bytes())?;
        Ok(())
    }

    /// Deserialise from a reader in **native** byte order.
    ///
    /// Used when reopening an existing pcap file to validate the magic
    /// number (matches C `dump_init()` line 407).
    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut b4 = [0u8; 4];
        let mut b2 = [0u8; 2];

        r.read_exact(&mut b4)?;
        let magic_number = u32::from_ne_bytes(b4);
        r.read_exact(&mut b2)?;
        let version_major = u16::from_ne_bytes(b2);
        r.read_exact(&mut b2)?;
        let version_minor = u16::from_ne_bytes(b2);
        r.read_exact(&mut b4)?;
        let thiszone = u32::from_ne_bytes(b4);
        r.read_exact(&mut b4)?;
        let sigfigs = u32::from_ne_bytes(b4);
        r.read_exact(&mut b4)?;
        let snaplen = u32::from_ne_bytes(b4);
        r.read_exact(&mut b4)?;
        let network = u32::from_ne_bytes(b4);

        Ok(Self {
            magic_number,
            version_major,
            version_minor,
            thiszone,
            sigfigs,
            snaplen,
            network,
        })
    }
}

// ---------------------------------------------------------------------------
// pcap Record Header  (dump.c lines 257-292)
// ---------------------------------------------------------------------------

/// libpcap packet record header (16 bytes per packet).
///
/// Precedes each captured packet in the pcap file, providing timestamp
/// and length metadata for the packet data that follows.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct PcapRecordHeader {
    /// Seconds since Unix epoch.
    ts_sec: u32,
    /// Microseconds component.
    ts_usec: u32,
    /// Number of bytes saved in the file.
    incl_len: u32,
    /// Original packet length.
    orig_len: u32,
}

impl PcapRecordHeader {
    /// Serialise to a writer in **native** byte order.
    fn write_to<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.ts_sec.to_ne_bytes())?;
        w.write_all(&self.ts_usec.to_ne_bytes())?;
        w.write_all(&self.incl_len.to_ne_bytes())?;
        w.write_all(&self.orig_len.to_ne_bytes())?;
        Ok(())
    }

    /// Deserialise from a reader in **native** byte order.
    fn read_from<R: Read>(r: &mut R) -> io::Result<Self> {
        let mut b4 = [0u8; 4];

        r.read_exact(&mut b4)?;
        let ts_sec = u32::from_ne_bytes(b4);
        r.read_exact(&mut b4)?;
        let ts_usec = u32::from_ne_bytes(b4);
        r.read_exact(&mut b4)?;
        let incl_len = u32::from_ne_bytes(b4);
        r.read_exact(&mut b4)?;
        let orig_len = u32::from_ne_bytes(b4);

        Ok(Self {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
        })
    }
}

// ---------------------------------------------------------------------------
// PacketDumper  (replaces C static state + daemon fields)
// ---------------------------------------------------------------------------

/// State for the packet dumping subsystem.
///
/// Replaces C's static `packet_count` (`dump.c` line 141) and the
/// `dumpfd`, `dump_file`, `dump_mask` fields from `struct daemon`.
pub struct PacketDumper {
    /// Open file handle for the dump file (`None` when dumping is disabled).
    file: Option<File>,
    /// Path to the dump file (retained for error messages and file reopening).
    #[allow(dead_code)]
    dump_file: PathBuf,
    /// Bitmask controlling which packet types are captured.
    dump_mask: u32,
    /// Count of packets written since the file was opened.
    packet_count: u32,
    /// Maximum snapshot length declared in the pcap header (`edns_pktsz + 200`).
    /// Retained from C `struct daemon` for pcap-format compliance and
    /// potential runtime use by callers querying the capture configuration.
    #[allow(dead_code)]
    snaplen: u32,
}

impl PacketDumper {
    /// Initialise the packet dumping subsystem.
    ///
    /// Opens or creates the pcap dump file and writes the global header.
    /// Three scenarios are handled, matching C `dump_init()` (lines 374–420):
    ///
    /// 1. **New file** — created with mode `0o600`, pcap header written.
    /// 2. **Named pipe (FIFO)** — opened append+read/write, pcap header
    ///    written (consumer must be reading the pipe).
    /// 3. **Existing regular file** — header validated, existing records
    ///    counted, file pointer set to EOF for appending.
    ///
    /// # Errors
    ///
    /// * [`DnsmasqError::Io`] — file creation, open, or write failure.
    /// * [`DnsmasqError::Config`] — existing file has invalid pcap magic.
    /// * [`DnsmasqError::Fatal`] — unrecoverable initialisation failure.
    pub fn new<P: AsRef<Path>>(
        path: P,
        dump_mask: u32,
        edns_pktsz: Option<u16>,
    ) -> Result<Self, DnsmasqError> {
        let path = path.as_ref();
        let snaplen = u32::from(edns_pktsz.unwrap_or(EDNS_PKTSZ)) + 200;
        let header = PcapFileHeader::new(snaplen);
        let mut packet_count: u32 = 0;

        // Probe the file system to determine which scenario to follow.
        let file = match std::fs::metadata(path) {
            // ----------------------------------------------------------
            // Scenario 1: File does not exist — create new.
            // Matches C dump_init() lines 392-396.
            // ----------------------------------------------------------
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut f = open_new_file(path)?;
                header.write_to(&mut f).map_err(|e| DnsmasqError::Fatal {
                    code: 3, // EC_FILE
                    message: format!("cannot write pcap header to {}: {}", path.display(), e),
                })?;
                f
            }
            // ----------------------------------------------------------
            // stat() failed for a reason other than ENOENT.
            // ----------------------------------------------------------
            Err(e) => {
                return Err(DnsmasqError::Fatal {
                    code: 3,
                    message: format!("cannot access {}: {}", path.display(), e),
                });
            }
            // ----------------------------------------------------------
            // Scenario 2: Named pipe (FIFO).
            // Matches C dump_init() lines 398-404.
            // ----------------------------------------------------------
            #[cfg(unix)]
            Ok(ref meta) if meta.file_type().is_fifo() => {
                let mut f = OpenOptions::new()
                    .append(true)
                    .read(true)
                    .open(path)
                    .map_err(|e| DnsmasqError::Fatal {
                        code: 3,
                        message: format!("cannot open pipe {}: {}", path.display(), e),
                    })?;
                header.write_to(&mut f).map_err(|e| DnsmasqError::Fatal {
                    code: 3,
                    message: format!("cannot write pcap header to pipe {}: {}", path.display(), e),
                })?;
                f
            }
            // ----------------------------------------------------------
            // Scenario 3: Existing regular file — validate & append.
            // Matches C dump_init() lines 406-419.
            // ----------------------------------------------------------
            Ok(_) => {
                let mut f = OpenOptions::new()
                    .append(true)
                    .read(true)
                    .open(path)
                    .map_err(|e| DnsmasqError::Fatal {
                        code: 3,
                        message: format!("cannot open {}: {}", path.display(), e),
                    })?;

                // Seek to the beginning to read the header for validation.
                f.seek(SeekFrom::Start(0))?;

                let existing =
                    PcapFileHeader::read_from(&mut f).map_err(|e| DnsmasqError::Fatal {
                        code: 3,
                        message: format!("cannot read header from {}: {}", path.display(), e),
                    })?;

                if existing.magic_number != PCAP_MAGIC {
                    return Err(DnsmasqError::Config(format!(
                        "bad header in {}",
                        path.display()
                    )));
                }

                // Count existing packet records by iterating through
                // the file.  Matches C dump_init() lines 414-418.
                while let Ok(rec) = PcapRecordHeader::read_from(&mut f) {
                    if f.seek(SeekFrom::Current(i64::from(rec.incl_len))).is_err() {
                        break;
                    }
                    packet_count += 1;
                }

                // File position is now at EOF; subsequent writes append.
                f
            }
        };

        Ok(Self {
            file: Some(file),
            dump_file: path.to_path_buf(),
            dump_mask,
            packet_count,
            snaplen,
        })
    }

    /// Capture a UDP packet (DNS query/response, DHCP) to the pcap dump
    /// file.
    ///
    /// Retrieves the local socket address via `getsockname()` to fill
    /// in a missing source or destination, then delegates to the core
    /// [`do_dump_packet()`](Self::do_dump_packet) writer.
    ///
    /// Matches C `dump_packet_udp()` (lines 504–532).
    ///
    /// # Arguments
    ///
    /// * `request_mask` — `DUMP_*` flag identifying the packet type.
    /// * `packet` — Application-layer payload (without IP/UDP headers).
    /// * `src` — Source address (client for queries, server for replies).
    /// * `dst` — Destination address (server for queries, client for replies).
    /// * `fd` — Socket file descriptor.  If **negative**, its absolute
    ///   value is used as a port number.  If **non-negative**,
    ///   `getsockname()` retrieves the local address.
    pub fn dump_packet_udp(
        &mut self,
        request_mask: u32,
        packet: &[u8],
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
        fd: i32,
    ) {
        if self.file.is_none() || (request_mask & self.dump_mask) == 0 {
            return;
        }

        let mut actual_src = src;
        let mut actual_dst = dst;

        // If fd is negative, it carries a port number (negated).
        // Matches C dump_packet_udp() line 517.
        let port: i32 = if fd < 0 { -fd } else { -1 };

        // If fd >= 0, retrieve local socket address via getsockname().
        // Matches C dump_packet_udp() lines 521-528.
        if fd >= 0 {
            if let Some(local_addr) = get_sock_addr(fd) {
                if actual_src.is_none() {
                    actual_src = Some(local_addr);
                }
                if actual_dst.is_none() {
                    actual_dst = Some(local_addr);
                }
            }
        }

        // Make a mutable copy so that do_dump_packet can write ICMP
        // checksums when needed (harmless for UDP — no modification).
        let mut pkt_buf = packet.to_vec();
        self.do_dump_packet(
            request_mask,
            &mut pkt_buf,
            actual_src.as_ref(),
            actual_dst.as_ref(),
            port,
            IPPROTO_UDP,
        );
    }

    /// Capture an ICMP / ICMPv6 packet (Router Advertisement) to the
    /// pcap dump file.
    ///
    /// Matches C `dump_packet_icmp()` (lines 568–573).
    ///
    /// # Arguments
    ///
    /// * `request_mask` — `DUMP_*` flag (typically [`mask::DUMP_RA`]).
    /// * `packet` — ICMP/ICMPv6 packet payload.
    /// * `src` — Source address.
    /// * `dst` — Destination address.
    pub fn dump_packet_icmp(
        &mut self,
        request_mask: u32,
        packet: &[u8],
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
    ) {
        if self.file.is_none() || (request_mask & self.dump_mask) == 0 {
            return;
        }

        let mut pkt_buf = packet.to_vec();
        self.do_dump_packet(
            request_mask,
            &mut pkt_buf,
            src.as_ref(),
            dst.as_ref(),
            -1, // no socket fd for ICMP
            IPPROTO_ICMP,
        );
    }

    // -----------------------------------------------------------------------
    // Core packet writer  (dump.c lines 643-813)
    // -----------------------------------------------------------------------

    /// Core packet writing function.
    ///
    /// Constructs a complete pcap record comprising IP header (v4 or v6),
    /// optional UDP header, protocol checksums, and the application-layer
    /// payload.  Everything is written to the dump file in a single
    /// append operation.
    ///
    /// Matches C `do_dump_packet()` (lines 643–813).
    fn do_dump_packet(
        &mut self,
        mask_val: u32,
        packet: &mut [u8],
        src: Option<&SocketAddr>,
        dst: Option<&SocketAddr>,
        port: i32,
        mut proto: u8,
    ) {
        let file = match self.file.as_mut() {
            Some(f) => f,
            None => return,
        };

        // Determine address family from whichever address is available.
        // Matches C do_dump_packet() lines 669-672.
        let family_v6 = match (src, dst) {
            (Some(addr), _) => addr.is_ipv6(),
            (_, Some(addr)) => addr.is_ipv6(),
            (None, None) => return, // cannot construct packet headers
        };

        // Default ports from the port parameter.
        // Matches C do_dump_packet() line 648-654.
        let default_port: u16 = if port < 0 { 0 } else { port as u16 };
        let mut src_port = default_port;
        let mut dst_port = default_port;

        let ip_header: Vec<u8>;
        let ip_header_len: usize;
        let mut pseudo_sum: u32 = 0;

        if family_v6 {
            // -------------------------------------------------------
            // IPv6 header construction (40 bytes).
            // Matches C do_dump_packet() lines 674-708.
            // -------------------------------------------------------
            let mut hdr = [0u8; IPV6_HEADER_LEN];

            // Version (6) in upper nibble of byte 0.
            hdr[0] = IP6VERSION << 4;
            // Bytes 1-3: traffic class (0) + flow label (0) — already zero.

            // Next-header and hop-limit.
            if proto == IPPROTO_UDP {
                let payload_len = (UDP_HEADER_LEN + packet.len()) as u16;
                hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
                hdr[6] = IPPROTO_UDP;
            } else {
                // ICMPv6 — override proto for IPv6.
                // Matches C do_dump_packet() lines 687-688.
                proto = IPPROTO_ICMPV6;
                let payload_len = packet.len() as u16;
                hdr[4..6].copy_from_slice(&payload_len.to_be_bytes());
                hdr[6] = IPPROTO_ICMPV6;
            }
            hdr[7] = IPDEFTTL;

            // Source address (16 bytes at offset 8).
            if let Some(addr) = src {
                let octets = addr_to_v6_octets(addr);
                hdr[8..24].copy_from_slice(&octets);
                src_port = addr.port();
            }

            // Destination address (16 bytes at offset 24).
            if let Some(addr) = dst {
                let octets = addr_to_v6_octets(addr);
                hdr[24..40].copy_from_slice(&octets);
                dst_port = addr.port();
            }

            // Pseudo-header checksum: sum source + destination addresses.
            // Matches C do_dump_packet() lines 704-708.
            for i in (0..16).step_by(2) {
                pseudo_sum += u16::from_be_bytes([hdr[8 + i], hdr[8 + i + 1]]) as u32;
                pseudo_sum += u16::from_be_bytes([hdr[24 + i], hdr[24 + i + 1]]) as u32;
            }

            ip_header = hdr.to_vec();
            ip_header_len = IPV6_HEADER_LEN;
        } else {
            // -------------------------------------------------------
            // IPv4 header construction (20 bytes).
            // Matches C do_dump_packet() lines 711-752.
            // -------------------------------------------------------
            let mut hdr = [0u8; IPV4_HEADER_LEN];

            // Version (4) + IHL (5) → 0x45.
            hdr[0] = (IPVERSION << 4) | IPV4_IHL;
            // TOS: 0 (hdr[1] already zero).

            // Total length.
            let total_len: u16 = if proto == IPPROTO_UDP {
                (IPV4_HEADER_LEN + UDP_HEADER_LEN + packet.len()) as u16
            } else {
                // ICMP for IPv4 — ensure proto is IPPROTO_ICMP.
                // Matches C do_dump_packet() lines 723-726.
                proto = IPPROTO_ICMP;
                (IPV4_HEADER_LEN + packet.len()) as u16
            };
            hdr[2..4].copy_from_slice(&total_len.to_be_bytes());

            // Identification (0), Flags (0), Fragment Offset (0).
            // hdr[4..8] already zero.

            // TTL.
            hdr[8] = IPDEFTTL;
            // Protocol.
            hdr[9] = proto;
            // Header Checksum — filled below after addresses are set.
            // hdr[10..12] = 0 initially.

            // Source address (4 bytes at offset 12).
            if let Some(addr) = src {
                let octets = addr_to_v4_octets(addr);
                hdr[12..16].copy_from_slice(&octets);
                src_port = addr.port();
            }

            // Destination address (4 bytes at offset 16).
            if let Some(addr) = dst {
                let octets = addr_to_v4_octets(addr);
                hdr[16..20].copy_from_slice(&octets);
                dst_port = addr.port();
            }

            // IPv4 header checksum.
            // Matches C do_dump_packet() lines 740-745.
            let ip_cksum = ipv4_header_checksum(&hdr);
            hdr[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

            // Pseudo-header checksum: sum source + dest addresses.
            // Matches C do_dump_packet() lines 748-751.
            for i in (12..20).step_by(2) {
                pseudo_sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
            }

            ip_header = hdr.to_vec();
            ip_header_len = IPV4_HEADER_LEN;
        }

        // ---------------------------------------------------------------
        // Build record contents and compute protocol checksum.
        // ---------------------------------------------------------------
        let pcap_incl_len: u32;
        let udp_header_bytes: Option<[u8; UDP_HEADER_LEN]>;

        if proto == IPPROTO_UDP {
            // -----------------------------------------------------------
            // UDP checksum  (dump.c lines 757-778).
            // -----------------------------------------------------------

            // Pseudo-header: protocol + UDP-total-length.
            pseudo_sum += IPPROTO_UDP as u32;
            let udp_total = (UDP_HEADER_LEN + packet.len()) as u16;
            pseudo_sum += udp_total as u32;

            // Construct UDP header.
            let mut udp = [0u8; UDP_HEADER_LEN];
            udp[0..2].copy_from_slice(&src_port.to_be_bytes());
            udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
            udp[4..6].copy_from_slice(&udp_total.to_be_bytes());
            // Checksum field initially 0 (udp[6..8] already zero).

            // Accumulate UDP header words into checksum.
            for i in (0..UDP_HEADER_LEN).step_by(2) {
                pseudo_sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
            }

            // Accumulate payload into checksum.
            checksum_add_bytes(&mut pseudo_sum, packet);

            // Fold carries and complement.
            let cksum = checksum_finalize(pseudo_sum);
            udp[6..8].copy_from_slice(&cksum.to_be_bytes());

            pcap_incl_len = (ip_header_len + UDP_HEADER_LEN + packet.len()) as u32;
            udp_header_bytes = Some(udp);
        } else {
            // -----------------------------------------------------------
            // ICMP / ICMPv6 checksum  (dump.c lines 779-796).
            // -----------------------------------------------------------

            // Pseudo-header: protocol + ICMP data length.
            pseudo_sum += proto as u32;
            pseudo_sum += packet.len() as u32;

            // Zero the checksum field in the ICMP header (bytes 2-3).
            // Matches C do_dump_packet() line 788.
            if packet.len() >= 4 {
                packet[2] = 0;
                packet[3] = 0;
            }

            // Accumulate ICMP data into checksum.
            checksum_add_bytes(&mut pseudo_sum, packet);

            // Fold carries and complement.
            let cksum = checksum_finalize(pseudo_sum);

            // Write checksum back into the ICMP header.
            // Matches C do_dump_packet() line 793.
            if packet.len() >= 4 {
                packet[2..4].copy_from_slice(&cksum.to_be_bytes());
            }

            pcap_incl_len = (ip_header_len + packet.len()) as u32;
            udp_header_bytes = None;
        }

        // ---------------------------------------------------------------
        // Write pcap record to file.
        // Matches C do_dump_packet() lines 798-811.
        // ---------------------------------------------------------------

        // Current timestamp.
        let (ts_sec, ts_usec) = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(dur) => (dur.as_secs() as u32, dur.subsec_micros()),
            Err(_) => {
                error!("failed to get system time for packet dump");
                return;
            }
        };

        let pcap_rec = PcapRecordHeader {
            ts_sec,
            ts_usec,
            incl_len: pcap_incl_len,
            orig_len: pcap_incl_len,
        };

        // Perform all writes in a closure so we can handle errors once.
        let write_result = (|| -> io::Result<()> {
            pcap_rec.write_to(file)?;
            file.write_all(&ip_header)?;
            if let Some(ref udp) = udp_header_bytes {
                file.write_all(udp)?;
            }
            file.write_all(packet)?;
            Ok(())
        })();

        match write_result {
            Ok(()) => {
                self.packet_count += 1;
                // Log the captured packet.
                // Matches C do_dump_packet() lines 808-811.
                info!(
                    packet_count = self.packet_count,
                    mask = format_args!("0x{:04x}", mask_val),
                    "dumping packet {} mask 0x{:04x}",
                    self.packet_count,
                    mask_val,
                );
            }
            Err(_) => {
                // Matches C do_dump_packet() line 807.
                error!("failed to write packet dump");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// File-creation helper
// ---------------------------------------------------------------------------

/// Create a new file with POSIX mode `0o600` (owner read/write only).
///
/// Matches C `dump_init()` line 394: `creat(daemon->dump_file, S_IRUSR | S_IWUSR)`.
#[cfg(unix)]
fn open_new_file(path: &Path) -> Result<File, DnsmasqError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| DnsmasqError::Fatal {
            code: 3,
            message: format!("cannot create {}: {}", path.display(), e),
        })
}

/// Fallback file creation for non-Unix platforms (no POSIX mode bits).
#[cfg(not(unix))]
fn open_new_file(path: &Path) -> Result<File, DnsmasqError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| DnsmasqError::Fatal {
            code: 3,
            message: format!("cannot create {}: {}", path.display(), e),
        })
}

// ---------------------------------------------------------------------------
// Socket address helpers
// ---------------------------------------------------------------------------

/// Retrieve the local socket address bound to the given file descriptor.
///
/// Uses `nix::sys::socket::getsockname()` for safe POSIX socket
/// inspection.  Returns `None` if the syscall fails.
///
/// Matches C `dump_packet_udp()` lines 521-528: `getsockname()`.
#[cfg(unix)]
fn get_sock_addr(fd: i32) -> Option<SocketAddr> {
    // nix 0.30.1's getsockname() takes RawFd (i32) directly.
    match nix::sys::socket::getsockname::<nix::sys::socket::SockaddrStorage>(fd) {
        Ok(ref storage) => sockaddr_storage_to_socket_addr(storage),
        Err(_) => None,
    }
}

/// Fallback for non-Unix -- always returns `None`.
#[cfg(not(unix))]
fn get_sock_addr(_fd: i32) -> Option<SocketAddr> {
    None
}

/// Convert a `nix::sys::socket::SockaddrStorage` to a
/// `std::net::SocketAddr`.
///
/// Returns `None` if the storage holds neither IPv4 nor IPv6.
#[cfg(unix)]
fn sockaddr_storage_to_socket_addr(
    storage: &nix::sys::socket::SockaddrStorage,
) -> Option<SocketAddr> {
    if let Some(sin) = storage.as_sockaddr_in() {
        Some(SocketAddr::new(IpAddr::V4(sin.ip()), sin.port()))
    } else {
        storage.as_sockaddr_in6().map(|sin6| {
            SocketAddr::V6(std::net::SocketAddrV6::new(
                sin6.ip(),
                sin6.port(),
                sin6.flowinfo(),
                sin6.scope_id(),
            ))
        })
    }
}

// ---------------------------------------------------------------------------
// Address conversion helpers
// ---------------------------------------------------------------------------

/// Extract IPv4 octets (4 bytes, network order) from a `SocketAddr`.
///
/// For IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`), extracts the
/// embedded IPv4 address.  For pure IPv6, returns `[0, 0, 0, 0]`.
fn addr_to_v4_octets(addr: &SocketAddr) -> [u8; 4] {
    match addr.ip() {
        IpAddr::V4(v4) => v4.octets(),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                v4.octets()
            } else {
                [0u8; 4]
            }
        }
    }
}

/// Extract IPv6 octets (16 bytes, network order) from a `SocketAddr`.
///
/// For plain IPv4 addresses, creates an IPv4-mapped IPv6 address
/// (`::ffff:a.b.c.d`).
fn addr_to_v6_octets(addr: &SocketAddr) -> [u8; 16] {
    match addr.ip() {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
    }
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

/// Accumulate bytes into a running one's-complement checksum sum.
///
/// Processes the byte slice as big-endian 16-bit words.  For odd-length
/// data the trailing byte is padded with a virtual zero byte **without
/// modifying the original buffer**, unlike C `do_dump_packet()` line 754
/// which writes `packet[len] = 0` past the end of the payload.
fn checksum_add_bytes(sum: &mut u32, data: &[u8]) {
    let mut i = 0;
    while i + 1 < data.len() {
        *sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    // Handle odd trailing byte -- pad with zero.
    if i < data.len() {
        *sum += (data[i] as u32) << 8;
    }
}

/// Fold carries and compute the one's complement of the accumulated sum.
///
/// Special case: if the folded sum is `0xffff` (all ones), returns
/// `0xffff` rather than `0x0000`, because in UDP a checksum of `0x0000`
/// means "not computed".
///
/// Matches C `do_dump_packet()` lines 773-775, 791-793.
fn checksum_finalize(sum: u32) -> u16 {
    let mut s = sum;
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    let folded = s as u16;
    if folded == 0xffff {
        folded
    } else {
        !folded
    }
}

/// Compute the IPv4 header checksum over a 20-byte header buffer.
///
/// Reads the header as big-endian 16-bit words; the checksum field
/// (bytes 10-11) must be zero on entry.
///
/// Matches C `do_dump_packet()` lines 740-745.
fn ipv4_header_checksum(header: &[u8; IPV4_HEADER_LEN]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..IPV4_HEADER_LEN).step_by(2) {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let folded = sum as u16;
    if folded == 0xffff {
        folded
    } else {
        !folded
    }
}
