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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::field_reassign_with_default,
    clippy::needless_borrows_for_generic_args,
    clippy::unnecessary_cast,
    clippy::assertions_on_constants,
    clippy::len_zero,
    clippy::vec_init_then_push,
    clippy::unchecked_duration_subtraction,
    clippy::manual_string_new,
    clippy::cloned_ref_to_slice_refs,
    clippy::manual_range_contains,
    clippy::trim_split_whitespace,
    clippy::identity_op,
    clippy::io_other_error,
    clippy::useless_vec,
    clippy::const_is_empty,
    clippy::clone_on_copy,
    clippy::absurd_extreme_comparisons,
    clippy::overly_complex_bool_expr,
    clippy::write_literal,
    clippy::int_plus_one,
    clippy::write_with_newline,
    clippy::float_cmp,
    clippy::double_comparisons,
    clippy::large_stack_arrays,
    clippy::writeln_empty_string,
    unused_comparisons,
    unused_mut,
    unused_variables
)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ===== mask constants =============================================

    #[test]
    fn mask_constants_correct_values() {
        assert_eq!(mask::DUMP_QUERY, 0x0001);
        assert_eq!(mask::DUMP_REPLY, 0x0002);
        assert_eq!(mask::DUMP_UP_QUERY, 0x0004);
        assert_eq!(mask::DUMP_UP_REPLY, 0x0008);
        assert_eq!(mask::DUMP_SEC_QUERY, 0x0010);
        assert_eq!(mask::DUMP_SEC_REPLY, 0x0020);
        assert_eq!(mask::DUMP_BOGUS, 0x0040);
        assert_eq!(mask::DUMP_SEC_BOGUS, 0x0080);
        assert_eq!(mask::DUMP_DHCP, 0x1000);
        assert_eq!(mask::DUMP_DHCPV6, 0x2000);
        assert_eq!(mask::DUMP_RA, 0x4000);
        assert_eq!(mask::DUMP_TFTP, 0x8000);
    }

    #[test]
    fn mask_constants_no_overlap() {
        let all = [
            mask::DUMP_QUERY,
            mask::DUMP_REPLY,
            mask::DUMP_UP_QUERY,
            mask::DUMP_UP_REPLY,
            mask::DUMP_SEC_QUERY,
            mask::DUMP_SEC_REPLY,
            mask::DUMP_BOGUS,
            mask::DUMP_SEC_BOGUS,
            mask::DUMP_DHCP,
            mask::DUMP_DHCPV6,
            mask::DUMP_RA,
            mask::DUMP_TFTP,
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_eq!(
                    all[i] & all[j],
                    0,
                    "mask overlap between index {} and {}",
                    i,
                    j
                );
            }
        }
    }

    #[test]
    fn mask_combined_or() {
        let combined = mask::DUMP_QUERY | mask::DUMP_REPLY | mask::DUMP_DHCP;
        assert_eq!(combined, 0x1003);
        assert_ne!(combined & mask::DUMP_QUERY, 0);
        assert_ne!(combined & mask::DUMP_REPLY, 0);
        assert_ne!(combined & mask::DUMP_DHCP, 0);
        assert_eq!(combined & mask::DUMP_TFTP, 0);
    }

    // ===== Module-level constants =====================================

    #[test]
    fn pcap_constants() {
        assert_eq!(PCAP_MAGIC, 0xa1b2c3d4);
        assert_eq!(PCAP_VERSION_MAJOR, 2);
        assert_eq!(PCAP_VERSION_MINOR, 4);
        assert_eq!(DLT_RAW, 101);
    }

    #[test]
    fn protocol_constants() {
        assert_eq!(IPVERSION, 4);
        assert_eq!(IP6VERSION, 6);
        assert_eq!(IPDEFTTL, 64);
        assert_eq!(IPV4_IHL, 5);
        assert_eq!(IPV4_HEADER_LEN, 20);
        assert_eq!(IPV6_HEADER_LEN, 40);
        assert_eq!(UDP_HEADER_LEN, 8);
        assert_eq!(IPPROTO_UDP, 17);
        assert_eq!(IPPROTO_ICMP, 1);
        assert_eq!(IPPROTO_ICMPV6, 58);
    }

    // ===== PcapFileHeader =============================================

    #[test]
    fn pcap_file_header_new_fields() {
        let hdr = PcapFileHeader::new(65535);
        assert_eq!(hdr.magic_number, PCAP_MAGIC);
        assert_eq!(hdr.version_major, 2);
        assert_eq!(hdr.version_minor, 4);
        assert_eq!(hdr.thiszone, 0);
        assert_eq!(hdr.sigfigs, 0);
        assert_eq!(hdr.snaplen, 65535);
        assert_eq!(hdr.network, DLT_RAW);
    }

    #[test]
    fn pcap_file_header_write_read_roundtrip() {
        let original = PcapFileHeader::new(4296);
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 24, "pcap global header must be 24 bytes");

        let mut cursor = Cursor::new(&buf);
        let decoded = PcapFileHeader::read_from(&mut cursor).unwrap();
        assert_eq!(decoded.magic_number, original.magic_number);
        assert_eq!(decoded.version_major, original.version_major);
        assert_eq!(decoded.version_minor, original.version_minor);
        assert_eq!(decoded.thiszone, original.thiszone);
        assert_eq!(decoded.sigfigs, original.sigfigs);
        assert_eq!(decoded.snaplen, original.snaplen);
        assert_eq!(decoded.network, original.network);
    }

    #[test]
    fn pcap_file_header_different_snaplen() {
        for snaplen in [0u32, 1500, 4296, 65535, u32::MAX] {
            let hdr = PcapFileHeader::new(snaplen);
            let mut buf = Vec::new();
            hdr.write_to(&mut buf).unwrap();
            let mut cursor = Cursor::new(&buf);
            let decoded = PcapFileHeader::read_from(&mut cursor).unwrap();
            assert_eq!(decoded.snaplen, snaplen);
        }
    }

    #[test]
    fn pcap_file_header_read_from_short_buffer() {
        let buf = vec![0u8; 10]; // too short for 24 bytes
        let mut cursor = Cursor::new(&buf);
        let result = PcapFileHeader::read_from(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn pcap_file_header_magic_in_native_byte_order() {
        let hdr = PcapFileHeader::new(4096);
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let first_four: [u8; 4] = buf[0..4].try_into().unwrap();
        let magic = u32::from_ne_bytes(first_four);
        assert_eq!(magic, PCAP_MAGIC);
    }

    // ===== PcapRecordHeader ===========================================

    #[test]
    fn pcap_record_header_write_read_roundtrip() {
        let original = PcapRecordHeader {
            ts_sec: 1700000000,
            ts_usec: 123456,
            incl_len: 512,
            orig_len: 1024,
        };
        let mut buf = Vec::new();
        original.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), 16, "pcap record header must be 16 bytes");

        let mut cursor = Cursor::new(&buf);
        let decoded = PcapRecordHeader::read_from(&mut cursor).unwrap();
        assert_eq!(decoded.ts_sec, original.ts_sec);
        assert_eq!(decoded.ts_usec, original.ts_usec);
        assert_eq!(decoded.incl_len, original.incl_len);
        assert_eq!(decoded.orig_len, original.orig_len);
    }

    #[test]
    fn pcap_record_header_zero_values() {
        let hdr = PcapRecordHeader {
            ts_sec: 0,
            ts_usec: 0,
            incl_len: 0,
            orig_len: 0,
        };
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        let decoded = PcapRecordHeader::read_from(&mut cursor).unwrap();
        assert_eq!(decoded.ts_sec, 0);
        assert_eq!(decoded.incl_len, 0);
    }

    #[test]
    fn pcap_record_header_read_from_short_buffer() {
        let buf = vec![0u8; 8]; // too short for 16 bytes
        let mut cursor = Cursor::new(&buf);
        assert!(PcapRecordHeader::read_from(&mut cursor).is_err());
    }

    #[test]
    fn pcap_record_header_max_values() {
        let hdr = PcapRecordHeader {
            ts_sec: u32::MAX,
            ts_usec: u32::MAX,
            incl_len: u32::MAX,
            orig_len: u32::MAX,
        };
        let mut buf = Vec::new();
        hdr.write_to(&mut buf).unwrap();
        let mut cursor = Cursor::new(&buf);
        let decoded = PcapRecordHeader::read_from(&mut cursor).unwrap();
        assert_eq!(decoded.ts_sec, u32::MAX);
        assert_eq!(decoded.ts_usec, u32::MAX);
    }

    // ===== addr_to_v4_octets ==========================================

    #[test]
    fn addr_to_v4_octets_ipv4() {
        let addr: SocketAddr = "192.168.1.1:53".parse().unwrap();
        assert_eq!(addr_to_v4_octets(&addr), [192, 168, 1, 1]);
    }

    #[test]
    fn addr_to_v4_octets_loopback() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert_eq!(addr_to_v4_octets(&addr), [127, 0, 0, 1]);
    }

    #[test]
    fn addr_to_v4_octets_all_zeros() {
        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert_eq!(addr_to_v4_octets(&addr), [0, 0, 0, 0]);
    }

    #[test]
    fn addr_to_v4_octets_broadcast() {
        let addr: SocketAddr = "255.255.255.255:65535".parse().unwrap();
        assert_eq!(addr_to_v4_octets(&addr), [255, 255, 255, 255]);
    }

    #[test]
    fn addr_to_v4_octets_ipv6_mapped() {
        // ::ffff:10.0.0.1 — should extract the IPv4 part
        let addr: SocketAddr = "[::ffff:10.0.0.1]:53".parse().unwrap();
        assert_eq!(addr_to_v4_octets(&addr), [10, 0, 0, 1]);
    }

    #[test]
    fn addr_to_v4_octets_pure_ipv6_returns_zeros() {
        let addr: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        assert_eq!(addr_to_v4_octets(&addr), [0, 0, 0, 0]);
    }

    // ===== addr_to_v6_octets ==========================================

    #[test]
    fn addr_to_v6_octets_pure_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let octets = addr_to_v6_octets(&addr);
        assert_eq!(octets[0..2], [0x20, 0x01]);
        assert_eq!(octets[2..4], [0x0d, 0xb8]);
        assert_eq!(octets[14..16], [0x00, 0x01]);
    }

    #[test]
    fn addr_to_v6_octets_loopback() {
        let addr: SocketAddr = "[::1]:0".parse().unwrap();
        let octets = addr_to_v6_octets(&addr);
        assert_eq!(octets[..15], [0u8; 15]);
        assert_eq!(octets[15], 1);
    }

    #[test]
    fn addr_to_v6_octets_from_ipv4() {
        // IPv4 10.0.0.1 → ::ffff:10.0.0.1
        let addr: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let octets = addr_to_v6_octets(&addr);
        assert_eq!(octets[10..12], [0xff, 0xff]);
        assert_eq!(octets[12..16], [10, 0, 0, 1]);
    }

    #[test]
    fn addr_to_v6_octets_all_zeros() {
        let addr: SocketAddr = "[::]:0".parse().unwrap();
        assert_eq!(addr_to_v6_octets(&addr), [0u8; 16]);
    }

    #[test]
    fn addr_to_v6_octets_all_ones() {
        let addr: SocketAddr = "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:0"
            .parse()
            .unwrap();
        assert_eq!(addr_to_v6_octets(&addr), [0xff; 16]);
    }

    // ===== checksum_add_bytes =========================================

    #[test]
    fn checksum_add_bytes_empty() {
        let mut sum = 0u32;
        checksum_add_bytes(&mut sum, &[]);
        assert_eq!(sum, 0);
    }

    #[test]
    fn checksum_add_bytes_single_word() {
        let mut sum = 0u32;
        checksum_add_bytes(&mut sum, &[0x01, 0x02]);
        assert_eq!(sum, 0x0102);
    }

    #[test]
    fn checksum_add_bytes_two_words() {
        let mut sum = 0u32;
        checksum_add_bytes(&mut sum, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(sum, 0x0102 + 0x0304);
    }

    #[test]
    fn checksum_add_bytes_odd_length() {
        // Odd trailing byte 0xAB is padded with virtual zero → 0xAB00
        let mut sum = 0u32;
        checksum_add_bytes(&mut sum, &[0xAB]);
        assert_eq!(sum, 0xAB00);
    }

    #[test]
    fn checksum_add_bytes_three_bytes() {
        let mut sum = 0u32;
        checksum_add_bytes(&mut sum, &[0x01, 0x02, 0x03]);
        assert_eq!(sum, 0x0102 + 0x0300);
    }

    #[test]
    fn checksum_add_bytes_accumulates() {
        let mut sum = 100u32;
        checksum_add_bytes(&mut sum, &[0x00, 0x05]);
        assert_eq!(sum, 105);
    }

    #[test]
    fn checksum_add_bytes_large_payload() {
        let data = vec![0xFF; 256]; // 128 words of 0xFFFF
        let mut sum = 0u32;
        checksum_add_bytes(&mut sum, &data);
        assert_eq!(sum, 128 * 0xFFFF);
    }

    // ===== checksum_finalize ==========================================

    #[test]
    fn checksum_finalize_zero() {
        assert_eq!(checksum_finalize(0), 0xFFFF);
    }

    #[test]
    fn checksum_finalize_one() {
        // ~0x0001 = 0xFFFE
        assert_eq!(checksum_finalize(1), 0xFFFE);
    }

    #[test]
    fn checksum_finalize_max_u16() {
        // sum = 0xFFFF → folded = 0xFFFF → special case: return 0xFFFF
        assert_eq!(checksum_finalize(0xFFFF), 0xFFFF);
    }

    #[test]
    fn checksum_finalize_carry_fold() {
        // 0x1_0000 → fold carry: (0x0000 + 0x0001) = 0x0001 → ~0x0001 = 0xFFFE
        assert_eq!(checksum_finalize(0x10000), 0xFFFE);
    }

    #[test]
    fn checksum_finalize_large_carry() {
        // 0x3FFFE → fold: (0xFFFE + 0x0003) = 0x10001 → fold again: 0x0002 → ~0x0002 = 0xFFFD
        assert_eq!(checksum_finalize(0x3FFFE), 0xFFFD);
    }

    #[test]
    fn checksum_finalize_known_value() {
        // Typical DNS-like checksum: sum of some header words
        let sum = 0x4500u32 + 0x003Cu32 + 0x0000u32 + 0x4011u32 + 0xC0A80101u32;
        // This will have large carries to fold
        let result = checksum_finalize(sum);
        // Just verify it produces a valid u16 and is not zero
        assert!(result > 0);
        assert!(result <= 0xFFFF);
    }

    // ===== ipv4_header_checksum =======================================

    #[test]
    fn ipv4_header_checksum_all_zeros() {
        let header = [0u8; 20];
        let cksum = ipv4_header_checksum(&header);
        // Sum is 0, folded is 0, complement is 0xFFFF
        assert_eq!(cksum, 0xFFFF);
    }

    #[test]
    fn ipv4_header_checksum_known_packet() {
        // Construct a known IPv4 header for 192.168.1.1 → 192.168.1.2, UDP, TTL=64
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45; // version + IHL
        hdr[2..4].copy_from_slice(&60u16.to_be_bytes()); // total length
        hdr[8] = 64; // TTL
        hdr[9] = 17; // protocol: UDP
                     // checksum field at 10..12 is zero
        hdr[12..16].copy_from_slice(&[192, 168, 1, 1]); // source
        hdr[16..20].copy_from_slice(&[192, 168, 1, 2]); // destination

        let cksum = ipv4_header_checksum(&hdr);
        // Verify: place checksum back and re-sum should be 0 or 0xFFFF
        hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
        let mut verify_sum = 0u32;
        for i in (0..20).step_by(2) {
            verify_sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        }
        while verify_sum >> 16 != 0 {
            verify_sum = (verify_sum & 0xffff) + (verify_sum >> 16);
        }
        // After adding checksum back, the result should fold to 0xFFFF
        assert_eq!(verify_sum as u16, 0xFFFF, "IP checksum verification failed");
    }

    #[test]
    fn ipv4_header_checksum_loopback() {
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[2..4].copy_from_slice(&40u16.to_be_bytes());
        hdr[8] = 64;
        hdr[9] = 17;
        hdr[12..16].copy_from_slice(&[127, 0, 0, 1]);
        hdr[16..20].copy_from_slice(&[127, 0, 0, 1]);

        let cksum = ipv4_header_checksum(&hdr);
        // Verify using the same re-sum approach
        hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
        let mut verify = 0u32;
        for i in (0..20).step_by(2) {
            verify += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        }
        while verify >> 16 != 0 {
            verify = (verify & 0xffff) + (verify >> 16);
        }
        assert_eq!(verify as u16, 0xFFFF);
    }

    // ===== PacketDumper new / dump functionality ======================

    #[test]
    fn packet_dumper_new_creates_valid_pcap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pcap");
        let dumper = PacketDumper::new(&path, mask::DUMP_QUERY, None).unwrap();
        assert_eq!(dumper.packet_count, 0);
        assert_eq!(dumper.dump_mask, mask::DUMP_QUERY);
        assert!(dumper.file.is_some());

        // Read back and verify pcap header
        drop(dumper);
        let data = std::fs::read(&path).unwrap();
        assert!(data.len() >= 24, "file too small for pcap header");
        let mut cursor = Cursor::new(&data);
        let hdr = PcapFileHeader::read_from(&mut cursor).unwrap();
        assert_eq!(hdr.magic_number, PCAP_MAGIC);
        assert_eq!(hdr.network, DLT_RAW);
    }

    #[test]
    fn packet_dumper_custom_snaplen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("snap.pcap");
        let _dumper = PacketDumper::new(&path, 0xFFFF, Some(1232)).unwrap();
        drop(_dumper);
        let data = std::fs::read(&path).unwrap();
        let mut cursor = Cursor::new(&data);
        let hdr = PcapFileHeader::read_from(&mut cursor).unwrap();
        // snaplen = 1232 + 200 = 1432
        assert_eq!(hdr.snaplen, 1432);
    }

    #[test]
    fn packet_dumper_default_snaplen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.pcap");
        let _dumper = PacketDumper::new(&path, 0xFFFF, None).unwrap();
        drop(_dumper);
        let data = std::fs::read(&path).unwrap();
        let mut cursor = Cursor::new(&data);
        let hdr = PcapFileHeader::read_from(&mut cursor).unwrap();
        // default EDNS_PKTSZ + 200
        assert_eq!(hdr.snaplen, u32::from(EDNS_PKTSZ) + 200);
    }

    #[test]
    fn packet_dumper_reopen_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reopen.pcap");

        // Create initial file
        let dumper1 = PacketDumper::new(&path, mask::DUMP_QUERY, None).unwrap();
        drop(dumper1);

        // Reopen — should validate header and set packet_count=0
        let dumper2 = PacketDumper::new(&path, mask::DUMP_REPLY, None).unwrap();
        assert_eq!(dumper2.packet_count, 0);
    }

    #[test]
    fn packet_dumper_bad_magic_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_magic.pcap");
        // Write a file with wrong magic
        std::fs::write(
            &path,
            &[
                0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        )
        .unwrap();
        let result = PacketDumper::new(&path, 0xFFFF, None);
        assert!(result.is_err());
    }

    #[test]
    fn packet_dumper_nonexistent_parent_dir() {
        let result = PacketDumper::new("/nonexistent/dir/test.pcap", 0xFFFF, None);
        assert!(result.is_err());
    }

    #[test]
    fn packet_dumper_dump_udp_mask_mismatch_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("noop.pcap");
        let mut dumper = PacketDumper::new(&path, mask::DUMP_QUERY, None).unwrap();
        let initial_count = dumper.packet_count;

        // DUMP_REPLY doesn't match DUMP_QUERY mask — should be no-op
        dumper.dump_packet_udp(
            mask::DUMP_REPLY,
            &[0x00, 0x01],
            Some("192.168.1.1:53".parse().unwrap()),
            Some("192.168.1.2:1234".parse().unwrap()),
            -53,
        );
        assert_eq!(dumper.packet_count, initial_count);
    }

    #[test]
    fn packet_dumper_dump_udp_ipv4_writes_packet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("udp4.pcap");
        let mut dumper = PacketDumper::new(&path, mask::DUMP_QUERY, None).unwrap();

        let payload = vec![0xAA; 32]; // 32-byte fake DNS payload
        dumper.dump_packet_udp(
            mask::DUMP_QUERY,
            &payload,
            Some("10.0.0.1:53".parse().unwrap()),
            Some("10.0.0.2:1234".parse().unwrap()),
            -53,
        );
        assert_eq!(dumper.packet_count, 1);

        // Verify file grew beyond just the pcap header
        drop(dumper);
        let data = std::fs::read(&path).unwrap();
        // 24 (pcap header) + 16 (record header) + 20 (IPv4) + 8 (UDP) + 32 (payload) = 100
        assert_eq!(data.len(), 100);
    }

    #[test]
    fn packet_dumper_dump_udp_ipv6_writes_packet() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("udp6.pcap");
        let mut dumper = PacketDumper::new(&path, mask::DUMP_QUERY, None).unwrap();

        let payload = vec![0xBB; 16];
        dumper.dump_packet_udp(
            mask::DUMP_QUERY,
            &payload,
            Some("[2001:db8::1]:53".parse().unwrap()),
            Some("[2001:db8::2]:1234".parse().unwrap()),
            -53,
        );
        assert_eq!(dumper.packet_count, 1);

        drop(dumper);
        let data = std::fs::read(&path).unwrap();
        // 24 + 16 + 40 (IPv6) + 8 (UDP) + 16 (payload) = 104
        assert_eq!(data.len(), 104);
    }

    #[test]
    fn packet_dumper_dump_icmp_mask_mismatch_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("icmp_noop.pcap");
        let mut dumper = PacketDumper::new(&path, mask::DUMP_QUERY, None).unwrap();

        dumper.dump_packet_icmp(
            mask::DUMP_RA,
            &[0x86, 0x00, 0x00, 0x00],
            Some("[fe80::1]:0".parse().unwrap()),
            Some("[ff02::1]:0".parse().unwrap()),
        );
        assert_eq!(dumper.packet_count, 0);
    }

    #[test]
    fn packet_dumper_dump_icmp_ipv4() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("icmp4.pcap");
        let mut dumper = PacketDumper::new(&path, mask::DUMP_RA, None).unwrap();

        let payload = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]; // echo request
        dumper.dump_packet_icmp(
            mask::DUMP_RA,
            &payload,
            Some("10.0.0.1:0".parse().unwrap()),
            Some("10.0.0.2:0".parse().unwrap()),
        );
        assert_eq!(dumper.packet_count, 1);

        drop(dumper);
        let data = std::fs::read(&path).unwrap();
        // 24 + 16 + 20 (IPv4) + 8 (ICMP payload) = 68
        assert_eq!(data.len(), 68);
    }

    #[test]
    fn packet_dumper_dump_icmpv6() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("icmp6.pcap");
        let mut dumper = PacketDumper::new(&path, mask::DUMP_RA, None).unwrap();

        // Router Advertisement: type=134, code=0, checksum=0x0000
        let payload = vec![0x86, 0x00, 0x00, 0x00, 0x40, 0x00, 0x07, 0x08];
        dumper.dump_packet_icmp(
            mask::DUMP_RA,
            &payload,
            Some("[fe80::1]:0".parse().unwrap()),
            Some("[ff02::1]:0".parse().unwrap()),
        );
        assert_eq!(dumper.packet_count, 1);

        drop(dumper);
        let data = std::fs::read(&path).unwrap();
        // 24 + 16 + 40 (IPv6) + 8 (ICMPv6 payload) = 88
        assert_eq!(data.len(), 88);
    }

    #[test]
    fn packet_dumper_multiple_packets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.pcap");
        let mut dumper = PacketDumper::new(&path, 0xFFFF, None).unwrap();

        for _ in 0..5 {
            dumper.dump_packet_udp(
                mask::DUMP_QUERY,
                &[0x00; 12],
                Some("10.0.0.1:53".parse().unwrap()),
                Some("10.0.0.2:1234".parse().unwrap()),
                -53,
            );
        }
        assert_eq!(dumper.packet_count, 5);
    }

    #[test]
    fn packet_dumper_reopen_counts_existing_packets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("count.pcap");

        // Write 3 packets
        {
            let mut dumper = PacketDumper::new(&path, 0xFFFF, None).unwrap();
            for _ in 0..3 {
                dumper.dump_packet_udp(
                    mask::DUMP_QUERY,
                    &[0x00; 12],
                    Some("10.0.0.1:53".parse().unwrap()),
                    Some("10.0.0.2:1234".parse().unwrap()),
                    -53,
                );
            }
        }

        // Reopen and check count
        let dumper2 = PacketDumper::new(&path, 0xFFFF, None).unwrap();
        assert_eq!(dumper2.packet_count, 3);
    }

    #[test]
    fn packet_dumper_pcap_record_valid_structure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("structure.pcap");
        let mut dumper = PacketDumper::new(&path, 0xFFFF, None).unwrap();

        let payload = vec![0xCC; 20];
        dumper.dump_packet_udp(
            mask::DUMP_QUERY,
            &payload,
            Some("10.0.0.1:53".parse().unwrap()),
            Some("10.0.0.2:1234".parse().unwrap()),
            -53,
        );
        drop(dumper);

        let data = std::fs::read(&path).unwrap();
        let mut cursor = Cursor::new(&data);

        // Skip pcap header
        let _hdr = PcapFileHeader::read_from(&mut cursor).unwrap();

        // Read record header
        let rec = PcapRecordHeader::read_from(&mut cursor).unwrap();
        // incl_len = 20 (IPv4) + 8 (UDP) + 20 (payload) = 48
        assert_eq!(rec.incl_len, 48);
        assert_eq!(rec.orig_len, 48);
        assert!(rec.ts_sec > 0, "timestamp should be positive");
    }

    #[test]
    fn packet_dumper_dump_none_file_noop() {
        // A dumper with file=None should silently no-op
        let dumper_inner = PacketDumper {
            file: None,
            dump_file: PathBuf::from("/dev/null"),
            dump_mask: 0xFFFF,
            packet_count: 0,
            snaplen: 4296,
        };
        // dump_packet_udp checks file.is_none() first
        let mut d = dumper_inner;
        d.dump_packet_udp(
            mask::DUMP_QUERY,
            &[0],
            Some("10.0.0.1:53".parse().unwrap()),
            Some("10.0.0.2:53".parse().unwrap()),
            -53,
        );
        assert_eq!(d.packet_count, 0);
    }

    #[test]
    fn packet_dumper_ipv4_header_in_pcap_valid() {
        // Verify the IPv4 header within a captured packet has valid checksum
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v4check.pcap");
        let mut dumper = PacketDumper::new(&path, 0xFFFF, None).unwrap();

        dumper.dump_packet_udp(
            mask::DUMP_QUERY,
            &[0x00; 12],
            Some("10.0.0.1:53".parse().unwrap()),
            Some("10.0.0.2:1234".parse().unwrap()),
            -53,
        );
        drop(dumper);

        let data = std::fs::read(&path).unwrap();
        // pcap header(24) + record header(16) = 40, then IPv4 header starts
        let ip_hdr: &[u8] = &data[40..60];
        // Verify IP version
        assert_eq!(ip_hdr[0] >> 4, 4, "IP version should be 4");
        assert_eq!(ip_hdr[0] & 0x0F, 5, "IHL should be 5");
        assert_eq!(ip_hdr[8], 64, "TTL should be 64");
        assert_eq!(ip_hdr[9], 17, "protocol should be UDP (17)");
        // Source address
        assert_eq!(&ip_hdr[12..16], &[10, 0, 0, 1]);
        // Destination address
        assert_eq!(&ip_hdr[16..20], &[10, 0, 0, 2]);

        // Verify checksum
        let hdr_array: [u8; 20] = ip_hdr.try_into().unwrap();
        let mut sum = 0u32;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([hdr_array[i], hdr_array[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF, "IP header checksum verification failed");
    }

    #[test]
    fn packet_dumper_ipv6_header_in_pcap_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v6check.pcap");
        let mut dumper = PacketDumper::new(&path, 0xFFFF, None).unwrap();

        dumper.dump_packet_udp(
            mask::DUMP_QUERY,
            &[0x00; 12],
            Some("[2001:db8::1]:53".parse().unwrap()),
            Some("[2001:db8::2]:1234".parse().unwrap()),
            -53,
        );
        drop(dumper);

        let data = std::fs::read(&path).unwrap();
        // pcap header(24) + record header(16) = 40, then IPv6 header starts
        let ip6_hdr: &[u8] = &data[40..80];
        // Version should be 6
        assert_eq!(ip6_hdr[0] >> 4, 6, "IPv6 version should be 6");
        // Next header should be UDP (17)
        assert_eq!(ip6_hdr[6], 17, "next header should be UDP");
        // Hop limit
        assert_eq!(ip6_hdr[7], 64, "hop limit should be 64");
    }

    // ===== checksum end-to-end: UDP over IPv4 =========================

    #[test]
    fn checksum_udp_over_ipv4_valid() {
        // Manually compute a UDP checksum for a known payload and verify
        let src_addr: [u8; 4] = [10, 0, 0, 1];
        let dst_addr: [u8; 4] = [10, 0, 0, 2];
        let payload = b"hello";
        let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;

        // Pseudo-header sum: src + dst + proto + udp_len
        let mut pseudo_sum = 0u32;
        pseudo_sum += u16::from_be_bytes([src_addr[0], src_addr[1]]) as u32;
        pseudo_sum += u16::from_be_bytes([src_addr[2], src_addr[3]]) as u32;
        pseudo_sum += u16::from_be_bytes([dst_addr[0], dst_addr[1]]) as u32;
        pseudo_sum += u16::from_be_bytes([dst_addr[2], dst_addr[3]]) as u32;
        pseudo_sum += IPPROTO_UDP as u32;
        pseudo_sum += udp_len as u32;

        // UDP header
        let mut udp = [0u8; 8];
        udp[0..2].copy_from_slice(&53u16.to_be_bytes()); // src port
        udp[2..4].copy_from_slice(&1234u16.to_be_bytes()); // dst port
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
        // checksum at [6..8] is 0

        for i in (0..8).step_by(2) {
            pseudo_sum += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        }
        checksum_add_bytes(&mut pseudo_sum, payload);
        let cksum = checksum_finalize(pseudo_sum);

        // Checksum should be non-zero (valid)
        assert_ne!(cksum, 0);

        // Verify: adding checksum back should produce 0xFFFF
        let mut verify = pseudo_sum; // reuse the same sum
                                     // Actually we need to recompute with checksum included
        let mut total = 0u32;
        total += IPPROTO_UDP as u32 + udp_len as u32;
        total += u16::from_be_bytes([src_addr[0], src_addr[1]]) as u32;
        total += u16::from_be_bytes([src_addr[2], src_addr[3]]) as u32;
        total += u16::from_be_bytes([dst_addr[0], dst_addr[1]]) as u32;
        total += u16::from_be_bytes([dst_addr[2], dst_addr[3]]) as u32;
        udp[6..8].copy_from_slice(&cksum.to_be_bytes());
        for i in (0..8).step_by(2) {
            total += u16::from_be_bytes([udp[i], udp[i + 1]]) as u32;
        }
        checksum_add_bytes(&mut total, payload);
        while total >> 16 != 0 {
            total = (total & 0xffff) + (total >> 16);
        }
        assert_eq!(total as u16, 0xFFFF, "UDP checksum verification failed");
    }
}
