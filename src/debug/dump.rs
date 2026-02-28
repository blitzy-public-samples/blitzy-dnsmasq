//! Pcap packet capture for DNS/DHCP/TFTP protocol diagnostics.
//!
//! This module replaces `src/dump.c` (815 lines) from the C dnsmasq codebase,
//! implementing pcap-format packet dumping for DNS, DHCP, DHCPv6, Router Advertisement,
//! and TFTP protocol debugging. Captured packets can be analyzed with Wireshark, tcpdump,
//! or tshark.
//!
//! # Feature Gate
//! The entire module is gated behind `#[cfg(feature = "dump")]`, replacing the C
//! preprocessor guard `#ifdef HAVE_DUMPFILE`.
//!
//! # Pcap Format
//! Uses DLT_RAW (data link type 101) — raw IP packets without link-layer headers.
//! Compatible with all standard libpcap analysis tools.
//!
//! # Architecture
//! - [`PacketDumper`] struct encapsulates all dump state, replacing C static globals
//! - [`DumpMask`] bitflags control which packet types are captured
//! - The `pcap-file` crate handles pcap global header / packet writing for new files
//! - IP headers, UDP headers, and checksums are constructed in safe Rust
//!
//! # Source Reference
//! - `src/dump.c` lines 125–815 (C implementation)
//! - `src/dnsmasq.h` lines 922–933 (DUMP_* mask constants)

use std::borrow::Cow;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use log::{error, info};
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use pcap_file::{DataLink, Endianness};

use crate::core::daemon::{DaemonState, OPT_EXTRALOG};
use crate::types::addr::SocketAddress;

// ---------------------------------------------------------------------------
// DumpMask bitflags — replacing C #define DUMP_* from dnsmasq.h lines 922-933
// ---------------------------------------------------------------------------

bitflags! {
    /// Packet capture filter mask controlling which packet types are dumped.
    ///
    /// Each bit corresponds to a specific packet category. The mask is configured
    /// via the `--dumpmask` option and checked before each packet write.
    ///
    /// # Source
    /// Replaces C `DUMP_*` constants from `dnsmasq.h` lines 922–933.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DumpMask: u32 {
        /// DNS queries from clients to dnsmasq (C: `DUMP_QUERY = 0x0001`).
        const QUERY       = 0x0001;
        /// DNS replies from dnsmasq to clients (C: `DUMP_REPLY = 0x0002`).
        const REPLY       = 0x0002;
        /// DNS queries from dnsmasq to upstream servers (C: `DUMP_UP_QUERY = 0x0004`).
        const UP_QUERY    = 0x0004;
        /// DNS replies from upstream servers to dnsmasq (C: `DUMP_UP_REPLY = 0x0008`).
        const UP_REPLY    = 0x0008;
        /// DNSSEC validation queries (C: `DUMP_SEC_QUERY = 0x0010`).
        const SEC_QUERY   = 0x0010;
        /// DNSSEC validation replies (C: `DUMP_SEC_REPLY = 0x0020`).
        const SEC_REPLY   = 0x0020;
        /// DNS responses marked as bogus / failed validation (C: `DUMP_BOGUS = 0x0040`).
        const BOGUS       = 0x0040;
        /// DNSSEC bogus responses (C: `DUMP_SEC_BOGUS = 0x0080`).
        const SEC_BOGUS   = 0x0080;
        /// DHCPv4 transactions (DISCOVER/OFFER/REQUEST/ACK) (C: `DUMP_DHCP = 0x1000`).
        const DHCP        = 0x1000;
        /// DHCPv6 messages (SOLICIT/ADVERTISE/REQUEST/REPLY) (C: `DUMP_DHCPV6 = 0x2000`).
        const DHCPV6      = 0x2000;
        /// IPv6 Router Advertisement packets (C: `DUMP_RA = 0x4000`).
        const RA          = 0x4000;
        /// TFTP file transfers (C: `DUMP_TFTP = 0x8000`).
        const TFTP        = 0x8000;
    }
}

// ---------------------------------------------------------------------------
// IpProto — IP protocol numbers for header construction
// ---------------------------------------------------------------------------

/// IP protocol numbers used in IP header construction.
///
/// Replaces C `IPPROTO_UDP`, `IPPROTO_ICMP`, and `IPPROTO_ICMPV6` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpProto {
    /// UDP protocol (number 17) — used for DNS/DHCP/TFTP packets.
    Udp = 17,
    /// ICMPv4 protocol (number 1) — used for IPv4 ICMP error/info messages.
    Icmp = 1,
    /// ICMPv6 protocol (number 58) — used for Router Advertisements, Neighbor Discovery.
    Icmpv6 = 58,
}

impl IpProto {
    /// Return the numeric IP protocol number.
    #[inline]
    fn number(self) -> u8 {
        self as u8
    }
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default IPv4 TTL value (matches C `IPDEFTTL` = 64).
const IPDEFTTL: u8 = 64;

/// Size of IPv4 header in bytes (no options).
const IPV4_HEADER_SIZE: usize = 20;

/// Size of IPv6 header in bytes (fixed).
const IPV6_HEADER_SIZE: usize = 40;

/// Size of UDP header in bytes.
const UDP_HEADER_SIZE: usize = 8;

/// Pcap magic number for native byte-order validation of existing files.
const PCAP_MAGIC_LE: u32 = 0xa1b2c3d4;

/// Pcap global header size in bytes.
const PCAP_GLOBAL_HEADER_SIZE: usize = 24;

/// Pcap record header size: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4) = 16.
const PCAP_RECORD_HEADER_SIZE: usize = 16;

/// IN6ADDRSZ — size of an IPv6 address in bytes.
const IN6ADDRSZ: usize = 16;

// ---------------------------------------------------------------------------
// DumpOutput — internal writer mode
// ---------------------------------------------------------------------------

/// Internal writer state for the packet dumper.
///
/// Handles two modes:
/// - `PcapMode`: Uses the `pcap-file` crate's `PcapWriter` for new files and FIFOs
/// - `AppendMode`: Raw `File` handle for appending to existing pcap files
///
/// The distinction is necessary because `PcapWriter::with_header()` always writes
/// the pcap global header, which would corrupt an existing file opened in append mode.
enum DumpOutput {
    /// PcapWriter for new file creation and FIFO streaming.
    PcapMode(PcapWriter<File>),
    /// Raw file handle for appending to existing pcap files.
    /// The boolean indicates whether the file uses little-endian byte order.
    AppendMode { file: File, is_little_endian: bool },
}

// ---------------------------------------------------------------------------
// PacketDumper
// ---------------------------------------------------------------------------

/// Pcap packet capture writer for diagnostic dumps.
///
/// Encapsulates all dump state, replacing the C static `packet_count` variable
/// and the `daemon->dumpfd` file descriptor. Provides methods for capturing
/// UDP packets (DNS, DHCP, TFTP) and ICMPv6 packets (Router Advertisements).
///
/// # Pcap Format
/// Writes standard libpcap format with DLT_RAW (101) data link type.
/// Compatible with Wireshark, tcpdump, tshark, and other analysis tools.
///
/// # Thread Safety
/// Designed for single-threaded use within dnsmasq's event loop architecture.
///
/// # Source
/// Replaces: `static packet_count` + `daemon->dumpfd` from C `dump.c`.
pub struct PacketDumper {
    /// Internal writer state (None if closed or failed to initialize).
    output: Option<DumpOutput>,
    /// Path to the dump file (retained for error messages and re-open scenarios).
    #[allow(dead_code)]
    file_path: String,
    /// Active dump mask controlling which packets are captured.
    dump_mask: DumpMask,
    /// Counter of packets written (replaces static `packet_count` from dump.c line 141).
    packet_count: u32,
    /// Maximum snap length for captured packets (retained for packet truncation logic).
    #[allow(dead_code)]
    snaplen: u32,
}

impl PacketDumper {
    /// Initialize packet capture, replacing C `dump_init()` (dump.c lines 374–420).
    ///
    /// Handles three initialization scenarios:
    /// 1. **New file** — creates file with pcap header (C lines 390–397)
    /// 2. **Named pipe (FIFO)** — opens pipe and writes pcap header (C lines 398–404)
    /// 3. **Existing regular file** — validates header, counts records, appends (C lines 406–419)
    ///
    /// # Arguments
    /// * `file_path` — Path to the dump file or FIFO
    /// * `dump_mask` — Bitmask selecting which packet types to capture
    /// * `edns_pktsz` — EDNS0 UDP payload size, used to calculate snaplen
    ///
    /// # Returns
    /// `Ok(PacketDumper)` on success, `Err(io::Error)` on failure.
    ///
    /// # Snaplen Calculation
    /// `snaplen = edns_pktsz + 200` — matches C line 387.
    pub fn new(file_path: &str, dump_mask: DumpMask, edns_pktsz: u32) -> Result<Self, io::Error> {
        let snaplen = edns_pktsz + 200;
        let path = Path::new(file_path);

        // Build the pcap header matching C dump.c lines 382-388:
        //   magic_number = 0xa1b2c3d4, version 2.4, thiszone=0, sigfigs=0,
        //   snaplen = edns_pktsz + 200, network = 101 (DLT_RAW)
        let pcap_header = PcapHeader {
            version_major: 2,
            version_minor: 4,
            ts_correction: 0,
            ts_accuracy: 0,
            snaplen,
            datalink: DataLink::RAW,
            ts_resolution: pcap_file::TsResolution::MicroSecond,
            endianness: Endianness::native(),
        };

        if !path.exists() {
            // Scenario 1: New file — create and write pcap header (C lines 390-397)
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .read(true)
                .open(file_path)
                .map_err(|e| io::Error::new(e.kind(), format!("cannot create {}: {}", file_path, e)))?;

            // Set permissions to 0600 (owner read/write only)
            // Matches C creat() with S_IRUSR | S_IWUSR
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
            }

            let writer = PcapWriter::with_header(file, pcap_header).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("cannot write pcap header to {}: {}", file_path, e))
            })?;

            Ok(PacketDumper {
                output: Some(DumpOutput::PcapMode(writer)),
                file_path: file_path.to_string(),
                dump_mask,
                packet_count: 0,
                snaplen,
            })
        } else {
            // File exists — check if it's a FIFO or regular file
            let metadata = std::fs::metadata(file_path).map_err(|e| {
                io::Error::new(e.kind(), format!("cannot stat {}: {}", file_path, e))
            })?;

            if metadata.file_type().is_fifo() {
                // Scenario 2: Named pipe / FIFO (C lines 398-404)
                // Open pipe and write pcap header for real-time streaming
                let file = OpenOptions::new()
                    .write(true)
                    .read(true)
                    .open(file_path)
                    .map_err(|e| io::Error::new(e.kind(), format!("cannot open pipe {}: {}", file_path, e)))?;

                let writer = PcapWriter::with_header(file, pcap_header).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("cannot write pcap header to pipe {}: {}", file_path, e),
                    )
                })?;

                Ok(PacketDumper {
                    output: Some(DumpOutput::PcapMode(writer)),
                    file_path: file_path.to_string(),
                    dump_mask,
                    packet_count: 0,
                    snaplen,
                })
            } else {
                // Scenario 3: Existing regular file (C lines 406-419)
                // Validate pcap header, count existing records, position at EOF for append
                Self::open_existing(file_path, dump_mask, snaplen)
            }
        }
    }

    /// Open an existing pcap file for appending.
    ///
    /// Validates the pcap global header magic number, counts existing packet records
    /// by reading record headers and seeking past packet data, then positions at EOF.
    ///
    /// Replaces C dump.c lines 406–419.
    fn open_existing(file_path: &str, dump_mask: DumpMask, snaplen: u32) -> Result<Self, io::Error> {
        let mut packet_count: u32 = 0;
        let is_little_endian: bool;

        // Phase 1: Read header, count records
        {
            let mut file = File::open(file_path).map_err(|e| {
                io::Error::new(e.kind(), format!("cannot access {}: {}", file_path, e))
            })?;

            // Read pcap global header (24 bytes)
            let mut header_buf = [0u8; PCAP_GLOBAL_HEADER_SIZE];
            file.read_exact(&mut header_buf).map_err(|e| {
                io::Error::new(e.kind(), format!("cannot read header from {}: {}", file_path, e))
            })?;

            // Validate magic number (C line 409: header.magic_number != 0xa1b2c3d4)
            let magic_le = u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
            let magic_be = u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);

            if magic_le == PCAP_MAGIC_LE {
                is_little_endian = true;
            } else if magic_be == PCAP_MAGIC_LE {
                is_little_endian = false;
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("bad header in {}", file_path),
                ));
            }

            // Count existing records by reading pcaprec_hdr_s headers and seeking
            // past packet data (C lines 414-418)
            let mut rec_hdr = [0u8; PCAP_RECORD_HEADER_SIZE];
            loop {
                match file.read_exact(&mut rec_hdr) {
                    Ok(()) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                    Err(e) => {
                        return Err(io::Error::new(
                            e.kind(),
                            format!("error reading records from {}: {}", file_path, e),
                        ));
                    }
                }

                // incl_len is at bytes 8..12 of the record header
                let incl_len = if is_little_endian {
                    u32::from_le_bytes([rec_hdr[8], rec_hdr[9], rec_hdr[10], rec_hdr[11]])
                } else {
                    u32::from_be_bytes([rec_hdr[8], rec_hdr[9], rec_hdr[10], rec_hdr[11]])
                };

                // Seek past packet data (C: lseek(dumpfd, pcap_header.incl_len, SEEK_CUR))
                file.seek(SeekFrom::Current(i64::from(incl_len))).map_err(|e| {
                    io::Error::new(e.kind(), format!("error seeking in {}: {}", file_path, e))
                })?;

                packet_count += 1;
            }
        }

        // Phase 2: Reopen in append mode for writing new packets
        let file = OpenOptions::new()
            .append(true)
            .open(file_path)
            .map_err(|e| io::Error::new(e.kind(), format!("cannot open {} for appending: {}", file_path, e)))?;

        Ok(PacketDumper {
            output: Some(DumpOutput::AppendMode { file, is_little_endian }),
            file_path: file_path.to_string(),
            dump_mask,
            packet_count,
            snaplen,
        })
    }

    /// Capture a UDP packet to the pcap dump file.
    ///
    /// Replaces C `dump_packet_udp()` (dump.c lines 504–532).
    ///
    /// # Arguments
    /// * `mask` — Packet type mask (must intersect `dump_mask` for capture)
    /// * `packet` — DNS/DHCP/TFTP packet payload (without IP/UDP headers)
    /// * `src` — Source address (None if unknown)
    /// * `dst` — Destination address (None if unknown)
    /// * `fd` — Socket file descriptor:
    ///   - `Some(fd)` where `fd >= 0`: call getsockname() to fill missing src/dst
    ///   - `Some(fd)` where `fd < 0`: use `-fd` as port number for Wireshark ID
    ///   - `None`: use addresses as provided
    /// * `daemon` — Optional daemon state for extra logging
    pub fn dump_packet_udp(
        &mut self,
        mask: DumpMask,
        packet: &[u8],
        src: Option<&SocketAddress>,
        dst: Option<&SocketAddress>,
        fd: Option<i32>,
        daemon: Option<&DaemonState>,
    ) {
        if self.output.is_none() || !self.dump_mask.intersects(mask) {
            return;
        }

        let mut local_addr: Option<SocketAddress> = None;
        // C line 517: int port = (fd < 0) ? -fd : -1;
        let mut port: i32 = -1;

        if let Some(raw_fd) = fd {
            if raw_fd < 0 {
                // Negative fd carries a port number (negated) for Wireshark identification
                port = -raw_fd;
            } else {
                // fd >= 0: call getsockname() to determine local address (C lines 521-528)
                if let Some(addr) = getsockname_safe(raw_fd) {
                    local_addr = Some(addr);
                }
            }
        }

        // If both src and dst are specified and fd was non-negative, port stays -1
        // to avoid using the getsockname result (C line 516)
        if src.is_some() && dst.is_some() {
            port = -1;
        }

        // Fill in missing src/dst from local address (C lines 523-527)
        let effective_src = src.or(local_addr.as_ref());
        let effective_dst = dst.or(local_addr.as_ref());

        self.do_dump_packet(mask, packet, effective_src, effective_dst, port, IpProto::Udp, daemon);
    }

    /// Capture an ICMPv6 packet to the pcap dump file.
    ///
    /// Replaces C `dump_packet_icmp()` (dump.c lines 568–573).
    ///
    /// # Arguments
    /// * `mask` — Packet type mask (typically `DumpMask::RA`)
    /// * `packet` — ICMPv6 packet data
    /// * `src` — Source IPv6 address
    /// * `dst` — Destination IPv6 address (often multicast ff02::1)
    /// * `daemon` — Optional daemon state for extra logging
    pub fn dump_packet_icmp(
        &mut self,
        mask: DumpMask,
        packet: &[u8],
        src: Option<&SocketAddress>,
        dst: Option<&SocketAddress>,
        daemon: Option<&DaemonState>,
    ) {
        if self.output.is_none() || !self.dump_mask.intersects(mask) {
            return;
        }
        // C line 572: do_dump_packet(mask, packet, len, src, dst, -1, IPPROTO_ICMP)
        // Note: In C do_dump_packet, if family is IPv6, proto gets changed to ICMPV6
        self.do_dump_packet(mask, packet, src, dst, -1, IpProto::Icmp, daemon);
    }

    /// Close the packet dumper and flush any pending writes.
    pub fn close(&mut self) {
        if let Some(output) = self.output.take() {
            match output {
                DumpOutput::PcapMode(writer) => {
                    // PcapWriter's Drop flushes the underlying writer
                    let mut file = writer.into_writer();
                    let _ = file.flush();
                }
                DumpOutput::AppendMode { mut file, .. } => {
                    let _ = file.flush();
                }
            }
        }
    }

    /// Returns the total number of packets written to the dump file.
    ///
    /// Includes packets from a previously existing file when opened in append mode.
    #[inline]
    pub fn packet_count(&self) -> u32 {
        self.packet_count
    }

    /// Core packet writing function — constructs IP headers, checksums, and writes pcap record.
    ///
    /// Replaces C `do_dump_packet()` (dump.c lines 643–813).
    ///
    /// # Packet Construction
    /// 1. Determine address family (IPv4/IPv6) from source or destination address
    /// 2. Construct IP header (20 bytes for IPv4, 40 bytes for IPv6)
    /// 3. For UDP: construct 8-byte UDP header with checksum
    /// 4. For ICMP: calculate ICMPv6/ICMP checksum over payload
    /// 5. Write pcap record header + IP header + [UDP header] + payload
    fn do_dump_packet(
        &mut self,
        mask: DumpMask,
        packet: &[u8],
        src: Option<&SocketAddress>,
        dst: Option<&SocketAddress>,
        port: i32,
        mut proto: IpProto,
        daemon: Option<&DaemonState>,
    ) {
        // Need at least one address to determine family
        let is_ipv6 = match (src, dst) {
            (Some(addr), _) => addr.is_v6(),
            (_, Some(addr)) => addr.is_v6(),
            (None, None) => return, // Cannot determine address family
        };

        let len = packet.len();

        // Default UDP ports (C line 667: udp.uh_sport = udp.uh_dport = htons(port < 0 ? 0 : port))
        let default_port: u16 = if port < 0 { 0 } else { port as u16 };
        let mut sport: u16 = default_port;
        let mut dport: u16 = default_port;

        // Assemble the complete packet: IP header + [UDP header] + payload
        let mut full_packet: Vec<u8>;
        let pcap_data_len: u32;

        if is_ipv6 {
            // IPv6 Header Construction (C lines 674-708)

            // Adjust protocol for IPv6 (C lines 686-688)
            if proto == IpProto::Udp {
                // proto stays UDP
            } else {
                // For ICMP over IPv6, use ICMPv6 (C line 687)
                proto = IpProto::Icmpv6;
            }

            // Extract addresses and ports from SocketAddress variants
            let src_addr = match src {
                Some(SocketAddress::V6(a)) => {
                    sport = a.port();
                    *a.ip()
                }
                _ => Ipv6Addr::UNSPECIFIED,
            };
            let dst_addr = match dst {
                Some(SocketAddress::V6(a)) => {
                    dport = a.port();
                    *a.ip()
                }
                _ => Ipv6Addr::UNSPECIFIED,
            };

            // Payload length for IPv6 header
            let payload_len: u16 = if proto == IpProto::Udp {
                (UDP_HEADER_SIZE + len) as u16
            } else {
                len as u16
            };

            // Build 40-byte IPv6 header
            let mut ip6_hdr = [0u8; IPV6_HEADER_SIZE];
            // ip6_vfc = 6 << 4 (version 6)
            ip6_hdr[0] = 0x60; // Version=6, traffic class high nibble=0
            // ip6_plen at bytes 4-5 (payload length, network byte order)
            let plen_bytes = payload_len.to_be_bytes();
            ip6_hdr[4] = plen_bytes[0];
            ip6_hdr[5] = plen_bytes[1];
            // ip6_nxt at byte 6 (next header / protocol)
            ip6_hdr[6] = proto.number();
            // ip6_hops at byte 7 (hop limit = 64)
            ip6_hdr[7] = IPDEFTTL;
            // ip6_src at bytes 8-23
            ip6_hdr[8..24].copy_from_slice(&src_addr.octets());
            // ip6_dst at bytes 24-39
            ip6_hdr[24..40].copy_from_slice(&dst_addr.octets());

            // Calculate checksum seed from IPv6 source + destination addresses
            // (C lines 704-708)
            let mut cksum_seed: u32 = 0;
            let src_octets = src_addr.octets();
            let dst_octets = dst_addr.octets();
            for i in (0..IN6ADDRSZ).step_by(2) {
                let word = u16::from_be_bytes([src_octets[i], src_octets[i + 1]]);
                cksum_seed += u32::from(word);
                let word = u16::from_be_bytes([dst_octets[i], dst_octets[i + 1]]);
                cksum_seed += u32::from(word);
            }

            if proto == IpProto::Udp {
                // UDP packet (C lines 757-778)
                let udp_hdr = build_udp_header_and_checksum(
                    sport, dport, packet, cksum_seed, proto,
                );
                pcap_data_len = (IPV6_HEADER_SIZE + UDP_HEADER_SIZE + len) as u32;
                full_packet = Vec::with_capacity(pcap_data_len as usize);
                full_packet.extend_from_slice(&ip6_hdr);
                full_packet.extend_from_slice(&udp_hdr);
                full_packet.extend_from_slice(packet);
            } else {
                // ICMPv6 packet (C lines 779-796)
                let patched_payload = build_icmp_with_checksum(packet, cksum_seed, proto);
                pcap_data_len = (IPV6_HEADER_SIZE + len) as u32;
                full_packet = Vec::with_capacity(pcap_data_len as usize);
                full_packet.extend_from_slice(&ip6_hdr);
                full_packet.extend_from_slice(&patched_payload);
            }
        } else {
            // IPv4 Header Construction (C lines 710-752)

            // Adjust protocol for IPv4 (C lines 722-726)
            if proto != IpProto::Udp {
                proto = IpProto::Icmp;
            }

            // Extract addresses and ports from SocketAddress variants
            let src_addr = match src {
                Some(SocketAddress::V4(a)) => {
                    sport = a.port();
                    *a.ip()
                }
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let dst_addr = match dst {
                Some(SocketAddress::V4(a)) => {
                    dport = a.port();
                    *a.ip()
                }
                _ => Ipv4Addr::UNSPECIFIED,
            };

            // Total length for IPv4 header
            let total_len: u16 = if proto == IpProto::Udp {
                (IPV4_HEADER_SIZE + UDP_HEADER_SIZE + len) as u16
            } else {
                (IPV4_HEADER_SIZE + len) as u16
            };

            // Build 20-byte IPv4 header
            let mut ip4_hdr = [0u8; IPV4_HEADER_SIZE];
            // Byte 0: version(4) + IHL(5) = 0x45
            ip4_hdr[0] = 0x45;
            // Byte 1: TOS = 0
            // Bytes 2-3: total length (network byte order)
            let tlen_bytes = total_len.to_be_bytes();
            ip4_hdr[2] = tlen_bytes[0];
            ip4_hdr[3] = tlen_bytes[1];
            // Bytes 4-5: identification = 0
            // Bytes 6-7: flags + fragment offset = 0
            // Byte 8: TTL = 64
            ip4_hdr[8] = IPDEFTTL;
            // Byte 9: protocol
            ip4_hdr[9] = proto.number();
            // Bytes 10-11: header checksum (calculated below)
            // Bytes 12-15: source address
            ip4_hdr[12..16].copy_from_slice(&src_addr.octets());
            // Bytes 16-19: destination address
            ip4_hdr[16..20].copy_from_slice(&dst_addr.octets());

            // Calculate IPv4 header checksum (C lines 740-745)
            let ip_cksum = ipv4_header_checksum(&ip4_hdr);
            ip4_hdr[10] = (ip_cksum >> 8) as u8;
            ip4_hdr[11] = (ip_cksum & 0xff) as u8;

            // Calculate UDP/ICMP checksum seed from IPv4 src+dst addresses (C lines 747-751)
            let src_u32 = u32::from_be_bytes(src_addr.octets());
            let dst_u32 = u32::from_be_bytes(dst_addr.octets());
            let mut cksum_seed: u32 = 0;
            cksum_seed += src_u32 & 0xffff;
            cksum_seed += (src_u32 >> 16) & 0xffff;
            cksum_seed += dst_u32 & 0xffff;
            cksum_seed += (dst_u32 >> 16) & 0xffff;

            if proto == IpProto::Udp {
                // UDP packet (C lines 757-778)
                let udp_hdr = build_udp_header_and_checksum(
                    sport, dport, packet, cksum_seed, proto,
                );
                pcap_data_len = (IPV4_HEADER_SIZE + UDP_HEADER_SIZE + len) as u32;
                full_packet = Vec::with_capacity(pcap_data_len as usize);
                full_packet.extend_from_slice(&ip4_hdr);
                full_packet.extend_from_slice(&udp_hdr);
                full_packet.extend_from_slice(packet);
            } else {
                // ICMP packet (C lines 779-796)
                let patched_payload = build_icmp_with_checksum(packet, cksum_seed, proto);
                pcap_data_len = (IPV4_HEADER_SIZE + len) as u32;
                full_packet = Vec::with_capacity(pcap_data_len as usize);
                full_packet.extend_from_slice(&ip4_hdr);
                full_packet.extend_from_slice(&patched_payload);
            }
        }

        // Get current timestamp (C lines 798-800: gettimeofday(&time, NULL))
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);

        // Write the packet to the dump file
        let write_result = self.write_pcap_record(&full_packet, timestamp, pcap_data_len);

        match write_result {
            Err(e) => {
                // Non-fatal error logging (C line 807: my_syslog(LOG_ERR, "failed to write packet dump"))
                error!("failed to write packet dump: {}", e);
            }
            Ok(()) => {
                self.packet_count += 1;

                // Log the packet dump (C lines 808-811)
                let mask_bits = mask.bits();
                if let Some(ds) = daemon {
                    if ds.option_bool(OPT_EXTRALOG) && (mask_bits & 0x00ff) != 0 {
                        // Extra logging includes log_display_id (C line 809)
                        let display_id = ds.runtime.borrow().log_display_id;
                        info!(
                            "{} dumping packet {} mask 0x{:04x}",
                            display_id, self.packet_count, mask_bits
                        );
                    } else {
                        info!("dumping packet {} mask 0x{:04x}", self.packet_count, mask_bits);
                    }
                } else {
                    info!("dumping packet {} mask 0x{:04x}", self.packet_count, mask_bits);
                }
            }
        }
    }

    /// Write a pcap packet record to the output.
    ///
    /// Handles both PcapWriter mode (new file / FIFO) and raw append mode (existing file).
    fn write_pcap_record(
        &mut self,
        data: &[u8],
        timestamp: Duration,
        orig_len: u32,
    ) -> Result<(), io::Error> {
        match self.output.as_mut() {
            Some(DumpOutput::PcapMode(writer)) => {
                let packet = PcapPacket {
                    timestamp,
                    orig_len,
                    data: Cow::Borrowed(data),
                };
                writer.write_packet(&packet).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("pcap write error: {}", e))
                })?;
                Ok(())
            }
            Some(DumpOutput::AppendMode { file, is_little_endian }) => {
                // Write raw pcap record header + data in the file's byte order
                let ts_sec = timestamp.as_secs() as u32;
                let ts_usec = timestamp.subsec_micros();
                let incl_len = data.len() as u32;

                let le = *is_little_endian;
                let mut hdr = [0u8; PCAP_RECORD_HEADER_SIZE];

                if le {
                    hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
                    hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
                    hdr[8..12].copy_from_slice(&incl_len.to_le_bytes());
                    hdr[12..16].copy_from_slice(&orig_len.to_le_bytes());
                } else {
                    hdr[0..4].copy_from_slice(&ts_sec.to_be_bytes());
                    hdr[4..8].copy_from_slice(&ts_usec.to_be_bytes());
                    hdr[8..12].copy_from_slice(&incl_len.to_be_bytes());
                    hdr[12..16].copy_from_slice(&orig_len.to_be_bytes());
                }

                file.write_all(&hdr)?;
                file.write_all(data)?;
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::NotConnected, "dump file not open")),
        }
    }
}

// ---------------------------------------------------------------------------
// Free functions — checksum helpers and address utilities
// ---------------------------------------------------------------------------

/// Build UDP header (8 bytes) with correct checksum.
///
/// Implements the UDP checksum calculation from C dump.c lines 757–778,
/// including the pseudo-header required by RFC 768.
///
/// # Arguments
/// * `sport` — Source port
/// * `dport` — Destination port
/// * `payload` — UDP payload data
/// * `cksum_seed` — Accumulated checksum seed from IP pseudo-header (src + dst addrs)
/// * `proto` — IP protocol (must be `IpProto::Udp`)
///
/// # Returns
/// 8-byte UDP header with computed checksum.
fn build_udp_header_and_checksum(
    sport: u16,
    dport: u16,
    payload: &[u8],
    cksum_seed: u32,
    proto: IpProto,
) -> [u8; UDP_HEADER_SIZE] {
    let udp_len = (UDP_HEADER_SIZE + payload.len()) as u16;

    // Build UDP header (C: struct udphdr with sport, dport, ulen, sum)
    let mut udp = [0u8; UDP_HEADER_SIZE];
    udp[0..2].copy_from_slice(&sport.to_be_bytes());
    udp[2..4].copy_from_slice(&dport.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // udp[6..8] = checksum, initially 0

    // Pseudo-header remainder: protocol + length (C lines 763-764)
    let mut sum = cksum_seed;
    sum += u32::from(proto.number()); // htons(IPPROTO_UDP) in network byte order context
    sum += u32::from(udp_len);

    // Sum UDP header words (C lines 769-770)
    sum += sum_words(&udp);

    // Sum payload words (C lines 771-772)
    sum += sum_words(payload);

    // Fold and complement (C lines 773-775)
    let cksum = fold_checksum(sum);
    udp[6] = (cksum >> 8) as u8;
    udp[7] = (cksum & 0xff) as u8;

    udp
}

/// Build ICMP payload with correct checksum.
///
/// Implements the ICMP/ICMPv6 checksum calculation from C dump.c lines 779–796.
/// For ICMPv6, includes the IPv6 pseudo-header per RFC 4443.
/// For ICMPv4, uses the same algorithm with the IPv4 pseudo-header.
///
/// # Arguments
/// * `payload` — ICMP packet data (including ICMP header)
/// * `cksum_seed` — Accumulated checksum seed from IP pseudo-header
/// * `proto` — IP protocol (IpProto::Icmp or IpProto::Icmpv6)
///
/// # Returns
/// Copy of payload with checksum field (bytes 2-3) set correctly.
fn build_icmp_with_checksum(payload: &[u8], cksum_seed: u32, proto: IpProto) -> Vec<u8> {
    let mut data = payload.to_vec();

    // Zero out ICMP checksum field at bytes 2-3 (C line 788: icmp->icmp6_cksum = 0)
    if data.len() >= 4 {
        data[2] = 0;
        data[3] = 0;
    }

    // Pseudo-header: protocol + length (C lines 785-786)
    let mut sum = cksum_seed;
    sum += u32::from(proto.number());
    sum += data.len() as u32;

    // Sum payload words (C lines 789-790)
    sum += sum_words(&data);

    // Fold and complement (C lines 791-793)
    let cksum = fold_checksum(sum);

    // Write checksum back into ICMP header bytes 2-3
    if data.len() >= 4 {
        data[2] = (cksum >> 8) as u8;
        data[3] = (cksum & 0xff) as u8;
    }

    data
}

/// Calculate IPv4 header checksum (one's complement of one's complement sum).
///
/// Replaces C dump.c lines 740–745:
/// ```c
/// ip.ip_sum = 0;
/// for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
///     sum += ((u16 *)&ip)[i];
/// while (sum >> 16)
///     sum = (sum & 0xffff) + (sum >> 16);
/// ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
/// ```
///
/// # Arguments
/// * `header` — 20-byte IPv4 header with checksum field (bytes 10-11) set to zero.
///
/// # Returns
/// The computed checksum value in network byte order.
fn ipv4_header_checksum(header: &[u8; IPV4_HEADER_SIZE]) -> u16 {
    let sum = sum_words(header);
    fold_checksum(sum)
}

/// Sum 16-bit words from a byte slice.
///
/// Replaces the C pattern:
/// ```c
/// for (i = 0; i < (len + 1) / 2; i++)
///     sum += ((u16 *)packet)[i];
/// ```
///
/// Handles odd-length data by padding the last byte with zero.
fn sum_words(data: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0;
    let len = data.len();

    // Process complete 16-bit words
    while i + 1 < len {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += u32::from(word);
        i += 2;
    }

    // Handle trailing odd byte (pad with zero)
    if i < len {
        let word = u16::from_be_bytes([data[i], 0]);
        sum += u32::from(word);
    }

    sum
}

/// Fold a 32-bit sum to 16-bit with carry and return the one's complement.
///
/// Replaces C pattern (dump.c lines 773-775):
/// ```c
/// while (sum >> 16)
///     sum = (sum & 0xffff) + (sum >> 16);
/// result = (sum == 0xffff) ? sum : ~sum;
/// ```
fn fold_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let result = sum as u16;
    if result == 0xffff {
        result
    } else {
        !result
    }
}

/// Safe wrapper around getsockname() to retrieve the local address of a socket.
///
/// Replaces C `getsockname(fd, (struct sockaddr *)&fd_addr, &addr_len)` (dump.c line 521).
///
/// Uses `nix::sys::socket::getsockname()` for safe POSIX socket address retrieval.
///
/// # Arguments
/// * `fd` — Raw file descriptor of an open socket
///
/// # Returns
/// `Some(SocketAddress)` on success, `None` on failure.
fn getsockname_safe(fd: i32) -> Option<SocketAddress> {
    // nix 0.30.1 getsockname takes RawFd (i32) directly.
    // Replaces C: getsockname(fd, (struct sockaddr *)&fd_addr, &addr_len) at dump.c line 521.
    match nix::sys::socket::getsockname::<nix::sys::socket::SockaddrStorage>(fd) {
        Ok(addr) => {
            if let Some(v4) = addr.as_sockaddr_in() {
                // nix SockaddrIn::ip() returns Ipv4Addr directly
                let ip = v4.ip();
                let port = v4.port();
                Some(SocketAddress::new_v4(ip, port))
            } else if let Some(v6) = addr.as_sockaddr_in6() {
                let ip = v6.ip();
                let port = v6.port();
                Some(SocketAddress::new_v6(ip, port, v6.flowinfo(), v6.scope_id()))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcap::PcapReader;

    // -- DumpMask tests --

    #[test]
    fn test_dump_mask_values() {
        // Verify exact C values from dnsmasq.h lines 922-933
        assert_eq!(DumpMask::QUERY.bits(), 0x0001);
        assert_eq!(DumpMask::REPLY.bits(), 0x0002);
        assert_eq!(DumpMask::UP_QUERY.bits(), 0x0004);
        assert_eq!(DumpMask::UP_REPLY.bits(), 0x0008);
        assert_eq!(DumpMask::SEC_QUERY.bits(), 0x0010);
        assert_eq!(DumpMask::SEC_REPLY.bits(), 0x0020);
        assert_eq!(DumpMask::BOGUS.bits(), 0x0040);
        assert_eq!(DumpMask::SEC_BOGUS.bits(), 0x0080);
        assert_eq!(DumpMask::DHCP.bits(), 0x1000);
        assert_eq!(DumpMask::DHCPV6.bits(), 0x2000);
        assert_eq!(DumpMask::RA.bits(), 0x4000);
        assert_eq!(DumpMask::TFTP.bits(), 0x8000);
    }

    #[test]
    fn test_dump_mask_intersects() {
        let mask = DumpMask::QUERY | DumpMask::REPLY;
        assert!(mask.intersects(DumpMask::QUERY));
        assert!(mask.intersects(DumpMask::REPLY));
        assert!(!mask.intersects(DumpMask::UP_QUERY));
        assert!(!mask.intersects(DumpMask::DHCP));
    }

    #[test]
    fn test_dump_mask_contains() {
        let mask = DumpMask::QUERY | DumpMask::REPLY | DumpMask::UP_QUERY;
        assert!(mask.contains(DumpMask::QUERY | DumpMask::REPLY));
        assert!(!mask.contains(DumpMask::QUERY | DumpMask::DHCP));
    }

    #[test]
    fn test_dump_mask_empty() {
        let empty = DumpMask::empty();
        assert_eq!(empty.bits(), 0);
        assert!(!empty.intersects(DumpMask::QUERY));
    }

    // -- Checksum tests --

    #[test]
    fn test_sum_words_even_length() {
        // Two 16-bit words: 0x0102 + 0x0304 = 0x0406
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(sum_words(&data), 0x0102 + 0x0304);
    }

    #[test]
    fn test_sum_words_odd_length() {
        // 0x0102 + 0x0300 (last byte padded with 0)
        let data = [0x01, 0x02, 0x03];
        assert_eq!(sum_words(&data), 0x0102 + 0x0300);
    }

    #[test]
    fn test_sum_words_empty() {
        assert_eq!(sum_words(&[]), 0);
    }

    #[test]
    fn test_sum_words_single_byte() {
        assert_eq!(sum_words(&[0xAB]), u32::from(u16::from_be_bytes([0xAB, 0x00])));
    }

    #[test]
    fn test_fold_checksum_no_carry() {
        // Sum fits in 16 bits
        assert_eq!(fold_checksum(0x1234), !0x1234u16);
    }

    #[test]
    fn test_fold_checksum_with_carry() {
        // 0x1_FFFF: upper=1, lower=0xFFFF -> 0xFFFF + 1 = 0x10000
        // -> second fold: 0x0000 + 1 = 0x0001 -> ~0x0001 = 0xFFFE
        assert_eq!(fold_checksum(0x1_FFFF), 0xFFFE);
    }

    #[test]
    fn test_fold_checksum_all_ones() {
        // 0xFFFF stays 0xFFFF (special case per C code)
        assert_eq!(fold_checksum(0xFFFF), 0xFFFF);
    }

    #[test]
    fn test_fold_checksum_zero() {
        // ~0 = 0xFFFF
        assert_eq!(fold_checksum(0), 0xFFFF);
    }

    // -- IPv4 header checksum test --

    #[test]
    fn test_ipv4_header_checksum() {
        // Construct a known IPv4 header and verify the checksum
        // Version=4, IHL=5, TOS=0, TotalLen=40, ID=0, Flags=0, TTL=64, Proto=17(UDP)
        // Src=192.168.1.1, Dst=8.8.8.8
        let mut hdr = [0u8; IPV4_HEADER_SIZE];
        hdr[0] = 0x45; // version + IHL
        hdr[2] = 0x00;
        hdr[3] = 0x28; // total length = 40
        hdr[8] = 64; // TTL
        hdr[9] = 17; // UDP
        // Checksum field stays 0
        hdr[12..16].copy_from_slice(&[192, 168, 1, 1]); // src
        hdr[16..20].copy_from_slice(&[8, 8, 8, 8]); // dst

        let cksum = ipv4_header_checksum(&hdr);

        // Verify by recalculating with the checksum inserted — should sum to 0xFFFF
        hdr[10] = (cksum >> 8) as u8;
        hdr[11] = (cksum & 0xff) as u8;
        let verify_sum = sum_words(&hdr);
        let folded = fold_checksum(verify_sum);
        // A correct checksum means the folded result is 0xFFFF or 0x0000
        // (since fold_checksum returns the complement, valid = 0xFFFF or the
        // raw fold is 0xFFFF meaning fold_checksum returns 0xFFFF)
        assert!(folded == 0xFFFF || folded == 0x0000,
            "IPv4 header checksum verification failed: folded = 0x{:04x}", folded);
    }

    // -- IPv6 header construction test --

    #[test]
    fn test_ipv6_header_structure() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let payload_len: u16 = 100;

        let mut hdr = [0u8; IPV6_HEADER_SIZE];
        hdr[0] = 0x60; // version 6
        let plen = payload_len.to_be_bytes();
        hdr[4] = plen[0];
        hdr[5] = plen[1];
        hdr[6] = IpProto::Udp.number();
        hdr[7] = IPDEFTTL;
        hdr[8..24].copy_from_slice(&src.octets());
        hdr[24..40].copy_from_slice(&dst.octets());

        // Verify version field
        assert_eq!(hdr[0] >> 4, 6);
        // Verify next header
        assert_eq!(hdr[6], 17);
        // Verify hop limit
        assert_eq!(hdr[7], 64);
        // Verify payload length
        assert_eq!(u16::from_be_bytes([hdr[4], hdr[5]]), 100);
        // Verify addresses
        assert_eq!(&hdr[8..24], &src.octets());
        assert_eq!(&hdr[24..40], &dst.octets());
    }

    // -- UDP checksum test --

    #[test]
    fn test_udp_header_construction() {
        let payload = [0x01, 0x02, 0x03, 0x04]; // 4-byte payload
        let udp = build_udp_header_and_checksum(
            53,   // sport
            1234, // dport
            &payload,
            0,    // no pseudo-header seed (for isolated test)
            IpProto::Udp,
        );

        // Verify source port (network byte order)
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 53);
        // Verify destination port
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 1234);
        // Verify UDP length = 8 + 4 = 12
        assert_eq!(u16::from_be_bytes([udp[4], udp[5]]), 12);
        // Checksum should be non-zero (with payload data)
        let cksum = u16::from_be_bytes([udp[6], udp[7]]);
        // Non-trivial checksum verification: sum of pseudo-header + UDP header + payload
        // should fold to 0xFFFF
        assert_ne!(cksum, 0, "UDP checksum should be computed");
    }

    // -- ICMP checksum test --

    #[test]
    fn test_icmp_checksum() {
        // Minimal ICMPv6 echo request: type=128, code=0, checksum=0, id=1, seq=1
        let payload = vec![128, 0, 0, 0, 0, 1, 0, 1];
        let result = build_icmp_with_checksum(&payload, 0, IpProto::Icmpv6);

        // Checksum field (bytes 2-3) should be set
        let cksum = u16::from_be_bytes([result[2], result[3]]);
        assert_ne!(cksum, 0, "ICMP checksum should be non-zero");

        // Verify: sum of result words should fold to 0xFFFF
        // (since pseudo-header seed is 0 and proto + len are added)
        let mut verify_sum: u32 = 0;
        verify_sum += u32::from(IpProto::Icmpv6.number());
        verify_sum += result.len() as u32;
        verify_sum += sum_words(&result);
        let folded = fold_checksum(verify_sum);
        assert!(
            folded == 0xFFFF || folded == 0x0000,
            "ICMP checksum verification failed: folded = 0x{:04x}",
            folded
        );
    }

    // -- PacketDumper initialization tests --

    #[test]
    fn test_packet_dumper_new_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_new.pcap");
        let path_str = path.to_str().unwrap();

        // Clean up from any previous test run
        let _ = std::fs::remove_file(path_str);

        let result = PacketDumper::new(path_str, DumpMask::QUERY | DumpMask::REPLY, 4096);
        assert!(result.is_ok(), "Failed to create new dump file: {:?}", result.err());

        let dumper = result.unwrap();
        assert_eq!(dumper.packet_count(), 0);
        assert_eq!(dumper.snaplen, 4096 + 200);

        // Verify pcap file was created and has valid header
        let file = File::open(path_str).unwrap();
        let reader = PcapReader::new(file);
        assert!(reader.is_ok(), "Created file is not a valid pcap");

        let reader = reader.unwrap();
        let header = reader.header();
        assert_eq!(header.version_major, 2);
        assert_eq!(header.version_minor, 4);
        assert_eq!(header.snaplen, 4296);
        assert_eq!(header.datalink, DataLink::RAW);

        // Clean up
        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_packet_dumper_write_and_read() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_write.pcap");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        let mut dumper = PacketDumper::new(path_str, DumpMask::QUERY, 4096).unwrap();

        // Create a simple DNS-like packet
        let dns_payload = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let src = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 100), 12345);
        let dst = SocketAddress::new_v4(Ipv4Addr::new(192, 168, 1, 1), 53);

        dumper.dump_packet_udp(
            DumpMask::QUERY,
            &dns_payload,
            Some(&src),
            Some(&dst),
            None,
            None,
        );

        assert_eq!(dumper.packet_count(), 1);

        dumper.close();

        // Read back and verify
        let file = File::open(path_str).unwrap();
        let mut reader = PcapReader::new(file).unwrap();
        let pkt = reader.next_packet();
        assert!(pkt.is_some(), "Expected at least one packet in the dump");
        let pkt = pkt.unwrap().unwrap();
        assert!(pkt.data.len() > 0, "Packet data should not be empty");

        // Verify it starts with a valid IPv4 header
        assert_eq!(pkt.data[0], 0x45, "Expected IPv4 version+IHL");

        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_packet_dumper_append_existing() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_append.pcap");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        // Write 2 packets
        {
            let mut dumper = PacketDumper::new(path_str, DumpMask::QUERY, 4096).unwrap();
            let payload = vec![0x00; 12];
            let src = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 1), 53);
            let dst = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 2), 53);

            dumper.dump_packet_udp(DumpMask::QUERY, &payload, Some(&src), Some(&dst), None, None);
            dumper.dump_packet_udp(DumpMask::QUERY, &payload, Some(&src), Some(&dst), None, None);
            assert_eq!(dumper.packet_count(), 2);
            dumper.close();
        }

        // Reopen and append 1 more packet
        {
            let mut dumper = PacketDumper::new(path_str, DumpMask::QUERY, 4096).unwrap();
            assert_eq!(dumper.packet_count(), 2, "Should have counted 2 existing records");

            let payload = vec![0x01; 12];
            let src = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 1), 53);
            let dst = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 2), 53);

            dumper.dump_packet_udp(DumpMask::QUERY, &payload, Some(&src), Some(&dst), None, None);
            assert_eq!(dumper.packet_count(), 3);
            dumper.close();
        }

        // Verify total packets
        let file = File::open(path_str).unwrap();
        let mut reader = PcapReader::new(file).unwrap();
        let mut count = 0;
        while let Some(pkt_result) = reader.next_packet() {
            let _pkt: PcapPacket = pkt_result.unwrap();
            count += 1;
        }
        assert_eq!(count, 3, "Expected 3 total packets in the dump file");

        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_packet_dumper_ipv6_packet() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_ipv6.pcap");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        let mut dumper = PacketDumper::new(path_str, DumpMask::QUERY, 4096).unwrap();

        let dns_payload = vec![0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let src = SocketAddress::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            12345, 0, 0,
        );
        let dst = SocketAddress::new_v6(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
            53, 0, 0,
        );

        dumper.dump_packet_udp(
            DumpMask::QUERY,
            &dns_payload,
            Some(&src),
            Some(&dst),
            None,
            None,
        );

        assert_eq!(dumper.packet_count(), 1);
        dumper.close();

        // Read back and verify IPv6 header
        let file = File::open(path_str).unwrap();
        let mut reader = PcapReader::new(file).unwrap();
        let pkt = reader.next_packet().unwrap().unwrap();

        // Verify it starts with IPv6 version field (0x60)
        assert_eq!(pkt.data[0] >> 4, 6, "Expected IPv6 version");
        // Verify next header is UDP (17)
        assert_eq!(pkt.data[6], 17, "Expected UDP next header");

        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_packet_dumper_mask_filtering() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_filter.pcap");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        // Only capture QUERY, not REPLY
        let mut dumper = PacketDumper::new(path_str, DumpMask::QUERY, 4096).unwrap();

        let payload = vec![0x00; 12];
        let src = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 1), 53);
        let dst = SocketAddress::new_v4(Ipv4Addr::new(10, 0, 0, 2), 53);

        // This should be captured (QUERY matches)
        dumper.dump_packet_udp(DumpMask::QUERY, &payload, Some(&src), Some(&dst), None, None);
        // This should NOT be captured (REPLY doesn't match QUERY mask)
        dumper.dump_packet_udp(DumpMask::REPLY, &payload, Some(&src), Some(&dst), None, None);

        assert_eq!(dumper.packet_count(), 1, "Only QUERY should have been captured");
        dumper.close();
        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_packet_dumper_icmp() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_icmp.pcap");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        let mut dumper = PacketDumper::new(path_str, DumpMask::RA, 4096).unwrap();

        // Simulated Router Advertisement ICMPv6 packet
        // Type=134 (RA), Code=0, Checksum=0, Hop Limit=64, M|O flags, Lifetime
        let ra_payload = vec![134, 0, 0, 0, 64, 0, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0];
        let src = SocketAddress::new_v6(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            0, 0, 0,
        );
        let dst = SocketAddress::new_v6(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            0, 0, 0,
        );

        dumper.dump_packet_icmp(DumpMask::RA, &ra_payload, Some(&src), Some(&dst), None);
        assert_eq!(dumper.packet_count(), 1);
        dumper.close();

        // Read back and verify
        let file = File::open(path_str).unwrap();
        let mut reader = PcapReader::new(file).unwrap();
        let pkt = reader.next_packet().unwrap().unwrap();

        // Should be IPv6 (version 6)
        assert_eq!(pkt.data[0] >> 4, 6);
        // Next header should be ICMPv6 (58)
        assert_eq!(pkt.data[6], 58);

        let _ = std::fs::remove_file(path_str);
    }

    #[test]
    fn test_bad_header_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join("blitzy_adhoc_test_dump_bad.pcap");
        let path_str = path.to_str().unwrap();

        // Write a file with bad magic number
        {
            let mut file = File::create(path_str).unwrap();
            file.write_all(&[0xFF; 24]).unwrap();
        }

        let result = PacketDumper::new(path_str, DumpMask::QUERY, 4096);
        assert!(result.is_err(), "Should reject file with bad magic number");
        match result {
            Err(err) => {
                assert!(
                    err.to_string().contains("bad header"),
                    "Error message should mention bad header: {}",
                    err
                );
            }
            Ok(_) => panic!("Expected error for bad magic number"),
        }

        let _ = std::fs::remove_file(path_str);
    }
}
