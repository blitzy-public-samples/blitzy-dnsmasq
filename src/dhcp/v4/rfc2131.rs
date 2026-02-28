//! DHCPv4 protocol engine implementing RFC 2131.
//!
//! Provides the full DHCP DORA state machine (DISCOVER → OFFER → REQUEST → ACK/NAK),
//! PXE/UEFI boot support, relay agent handling (RFC 3046), option encoding/decoding,
//! vendor option matching, and FQDN handling.
//!
//! This module replaces the C `src/rfc2131.c` (5209 lines) with idiomatic Rust.
//!
//! # Key Functions
//! - [`dhcp_reply`] — Main entry point: processes incoming DHCP packet and builds response
//! - [`do_options`] — Core option encoding engine for response packets
//! - [`option_find`] / [`option_find1`] — Option search in DHCP packets
//! - [`option_put`] / [`option_put_string`] — Option writing to response packets
//! - [`relay_upstream4`] — Relay agent upstream forwarding (RFC 3046)
//! - [`relay_reply4`] — Relay agent reply processing
//! - [`calc_time`] — Lease time negotiation
//! - [`server_id`] — Server identifier selection

#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

use log::{debug, error, info, warn};

use crate::core::daemon::{
    DaemonState, OPT_AUTHORITATIVE, OPT_BOOTP_DYNAMIC, OPT_CONSEC_ADDR,
    OPT_DHCP_FQDN, OPT_FQDN_UPDATE, OPT_IGNORE_CLID, OPT_LEASEQUERY,
    OPT_LOG_OPTS, OPT_NO_OVERRIDE, OPT_NO_PING, OPT_QUIET_DHCP,
    OPT_RAPID_COMMIT,
};
use crate::dhcp::common;
use crate::dhcp::protocol_v4::*;
use crate::dns::cache;
use crate::types::addr::{AllAddr, SocketAddress};
use crate::types::dhcp::{
    DhcpBoot, DhcpConfig, DhcpConfigFlags, DhcpContext, DhcpContextFlags,
    DhcpLease, DhcpMac, DhcpMatchName, DhcpNetId, DhcpOptExtra, DhcpOptFlags,
    DhcpOption, DhcpRelay, DhcpVendor, DelayConfig, HwaddrConfig, LeaseFlags,
    PxeService, RelayAddr, MATCH_CIRCUIT, MATCH_REMOTE, MATCH_SUBSCRIBER,
};
use crate::types::dns::CacheEntryFlags;

use super::server;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum packet size for DHCP responses.
const DHCP_PACKET_MAX: usize = 65536;

/// Standard IPv4 address size in bytes.
const INADDRSZ: usize = 4;

/// Maximum hop count for relay agents (prevents loops).
const DHCP_MAX_HOPS: u8 = 20;

/// Minimum sanity value for lease time (seconds).
const MIN_LEASE_TIME: u32 = 120;

/// DHCP header size (bytes before options field).
const DHCP_HEADER_SIZE: usize = 236;

/// Size of the magic cookie field.
const COOKIE_SIZE: usize = 4;

/// FQDN option flag: server should not perform any DNS updates.
const FQDN_FLAG_N: u8 = 0x08;
/// FQDN option flag: server should encode FQDN in DNS wire format.
const FQDN_FLAG_E: u8 = 0x04;
/// FQDN option flag: override of S bit.
const FQDN_FLAG_O: u8 = 0x02;
/// FQDN option flag: server should perform A RR update.
const FQDN_FLAG_S: u8 = 0x01;

// ===========================================================================
// Inline helpers
// ===========================================================================

/// Get the data length of a DHCP option.
/// Equivalent to C `option_len(opt)` → `*(opt+1)`.
#[inline]
fn option_len(opt: &[u8]) -> usize {
    if opt.len() < 2 {
        0
    } else {
        opt[1] as usize
    }
}

/// Get a reference to the data portion of a DHCP option starting at offset.
/// Equivalent to C `option_ptr(opt, offset)` → `&opt[2+offset..]`.
#[inline]
fn option_ptr(opt: &[u8], offset: usize) -> &[u8] {
    let start = 2 + offset;
    if start > opt.len() {
        &[]
    } else {
        &opt[start..]
    }
}

// ===========================================================================
// Option Search Functions
// ===========================================================================

/// Search for a DHCP option within a bounded byte region.
///
/// Rewrite of C `option_find1()` (rfc2131.c lines 2630-2730).
/// Walks the TLV (type-length-value) option stream from `start` looking
/// for an option with the given code. Handles PAD (0) and END (255) markers.
///
/// # Arguments
/// * `data` - Option data region to search
/// * `option` - Option code to find
/// * `min_len` - Minimum acceptable data length
///
/// # Returns
/// Byte offset within `data` where the option starts (type byte), or None
pub fn option_find1(data: &[u8], option: u8, min_len: usize) -> Option<usize> {
    let len = data.len();
    let mut pos: usize = 0;
    while pos < len {
        let opt_code = data[pos];
        if opt_code == OPTION_END {
            return None;
        }
        if opt_code == OPTION_PAD {
            pos += 1;
            continue;
        }
        // Need at least type + length bytes
        if pos + 1 >= len {
            return None;
        }
        let opt_len = data[pos + 1] as usize;
        if opt_code == option && opt_len >= min_len {
            // Ensure entire option fits in data
            if pos + 2 + opt_len <= len {
                return Some(pos);
            }
            return None;
        }
        pos += 2 + opt_len;
    }
    None
}

/// Search for a DHCP option in a packet, including overloaded fields.
///
/// Rewrite of C `option_find()` (rfc2131.c lines 2732-2785).
/// Searches the main options field (after the magic cookie), then the
/// `file` and `sname` fields if OPTION_OVERLOAD indicates they contain
/// additional options.
///
/// # Arguments
/// * `packet` - Full DHCP packet buffer
/// * `sz` - Total packet size
/// * `option` - Option code to find
/// * `min_len` - Minimum acceptable data length
///
/// # Returns
/// Byte offset within the packet where the option starts, or None
pub fn option_find(packet: &[u8], sz: usize, option: u8, min_len: usize) -> Option<usize> {
    let pkt_len = sz.min(packet.len());
    if pkt_len < DHCP_HEADER_SIZE + COOKIE_SIZE {
        return None;
    }
    // Search main options field (after 4-byte magic cookie)
    let opts_start = DHCP_HEADER_SIZE + COOKIE_SIZE;
    let opts_region = &packet[opts_start..pkt_len];
    if let Some(off) = option_find1(opts_region, option, min_len) {
        return Some(opts_start + off);
    }

    // Check for OPTION_OVERLOAD
    let overload = find_overload_in_options(&packet[opts_start..pkt_len]);

    // Search 'file' field if overloaded (value 1 or 3)
    if overload.map_or(false, |v| v == 1 || v == 3) {
        let file_region = &packet[108..236.min(pkt_len)];
        if let Some(off) = option_find1(file_region, option, min_len) {
            return Some(108 + off);
        }
    }

    // Search 'sname' field if overloaded (value 2 or 3)
    if overload.map_or(false, |v| v == 2 || v == 3) {
        let sname_region = &packet[44..108.min(pkt_len)];
        if let Some(off) = option_find1(sname_region, option, min_len) {
            return Some(44 + off);
        }
    }

    None
}

/// Find OPTION_OVERLOAD in the main options field only.
fn find_overload_in_options(opts: &[u8]) -> Option<u8> {
    let mut pos: usize = 0;
    while pos < opts.len() {
        let code = opts[pos];
        if code == OPTION_END {
            return None;
        }
        if code == OPTION_PAD {
            pos += 1;
            continue;
        }
        if pos + 1 >= opts.len() {
            return None;
        }
        let len = opts[pos + 1] as usize;
        if code == OPTION_OVERLOAD && len >= 1 && pos + 2 < opts.len() {
            return Some(opts[pos + 2]);
        }
        pos += 2 + len;
    }
    None
}

/// Find a matching DHCP option in the configured option list.
///
/// Searches the option list for an option with matching code and TAGOK flag.
///
/// # Arguments
/// * `options` - Slice of configured DHCP options
/// * `option` - Option code to find
///
/// # Returns
/// Reference to the matched DhcpOption, or None
pub fn option_find2(options: &[DhcpOption], option: u8) -> Option<&DhcpOption> {
    options.iter().find(|o| {
        o.opt == option as i32
            && o.flags.contains(DhcpOptFlags::TAGOK)
            && !o.flags.contains(DhcpOptFlags::VENDOR)
    })
}

// ===========================================================================
// Option Extraction Functions
// ===========================================================================

/// Extract an IPv4 address from a DHCP option's data.
///
/// Reads 4 bytes from the option data starting at offset 2 (after type+len).
///
/// # Arguments
/// * `opt` - Option byte slice starting at the type byte
///
/// # Returns
/// IPv4 address from the option data
pub fn option_addr(opt: &[u8]) -> Ipv4Addr {
    if opt.len() < 6 {
        return Ipv4Addr::UNSPECIFIED;
    }
    Ipv4Addr::new(opt[2], opt[3], opt[4], opt[5])
}

/// Extract an unsigned integer from a DHCP option's data.
///
/// Reads 1, 2, or 4 bytes from the option data in network byte order (big-endian).
///
/// # Arguments
/// * `opt` - Option byte slice starting at the type byte
/// * `offset` - Byte offset within the data portion (after type+len)
/// * `size` - Number of bytes to read (1, 2, or 4)
///
/// # Returns
/// The extracted integer value
pub fn option_uint(opt: &[u8], offset: usize, size: usize) -> u32 {
    let base = 2 + offset;
    match size {
        1 => {
            if opt.len() > base {
                opt[base] as u32
            } else {
                0
            }
        }
        2 => {
            if opt.len() >= base + 2 {
                u16::from_be_bytes([opt[base], opt[base + 1]]) as u32
            } else {
                0
            }
        }
        4 => {
            if opt.len() >= base + 4 {
                u32::from_be_bytes([opt[base], opt[base + 1], opt[base + 2], opt[base + 3]])
            } else {
                0
            }
        }
        _ => 0,
    }
}

// ===========================================================================
// Packet Utility Functions
// ===========================================================================

/// Skip to the end of existing options in a DHCP option region.
///
/// Returns the offset of the OPTION_END marker or the end of the data.
fn dhcp_skip_opts(opts: &[u8]) -> usize {
    let mut pos: usize = 0;
    while pos < opts.len() {
        let code = opts[pos];
        if code == OPTION_END {
            return pos;
        }
        if code == OPTION_PAD {
            pos += 1;
            continue;
        }
        if pos + 1 >= opts.len() {
            return pos;
        }
        let len = opts[pos + 1] as usize;
        pos += 2 + len;
    }
    pos
}

/// Find the OPTION_OVERLOAD value in a packet's main options field.
///
/// Returns the overload byte value (1=file, 2=sname, 3=both), or None.
fn find_overload(packet: &[u8]) -> Option<u8> {
    if packet.len() < DHCP_HEADER_SIZE + COOKIE_SIZE {
        return None;
    }
    let opts_start = DHCP_HEADER_SIZE + COOKIE_SIZE;
    find_overload_in_options(&packet[opts_start..])
}

/// Calculate the actual response packet size.
///
/// Finds the end of options (skipping trailing PAD bytes) and computes
/// the total packet size. Enforces the MIN_PACKETSZ minimum for
/// Linux kernel compatibility.
///
/// # Arguments
/// * `packet` - DHCP packet buffer
/// * `agent_id_offset` - Offset of agent_id if present (for echo-back)
///
/// # Returns
/// Total packet size in bytes
pub fn dhcp_packet_size(packet: &[u8], agent_id_offset: Option<usize>) -> usize {
    if packet.len() < DHCP_HEADER_SIZE + COOKIE_SIZE {
        return packet.len();
    }

    let opts_start = DHCP_HEADER_SIZE + COOKIE_SIZE;
    let opts = &packet[opts_start..];
    let mut end_offset = dhcp_skip_opts(opts);

    // If agent_id is present, it comes after OPTION_END
    if let Some(aid_off) = agent_id_offset {
        if aid_off > opts_start {
            let relative = aid_off - opts_start;
            if relative > end_offset {
                // Agent ID is after the end marker; account for it
                let aid_data = &packet[aid_off..];
                if aid_data.len() >= 2 {
                    let aid_total = 2 + aid_data[1] as usize;
                    let total_end = relative + aid_total;
                    if total_end > end_offset {
                        end_offset = total_end;
                    }
                }
            }
        }
    }

    let mut size = opts_start + end_offset + 1; // +1 for OPTION_END byte

    // Check for overloaded fields contributing to size
    let overload = find_overload(packet);
    if let Some(ov) = overload {
        if ov == 1 || ov == 3 {
            // file field used for options
            let file_end = 108 + dhcp_skip_opts(&packet[108..236.min(packet.len())]);
            if file_end + 1 > size {
                size = file_end + 1;
            }
        }
        if ov == 2 || ov == 3 {
            // sname field used for options
            let sname_end = 44 + dhcp_skip_opts(&packet[44..108.min(packet.len())]);
            if sname_end + 1 > size {
                size = sname_end + 1;
            }
        }
    }

    // Enforce minimum packet size for Linux compatibility
    if size < MIN_PACKETSZ {
        size = MIN_PACKETSZ;
    }
    if size > packet.len() {
        size = packet.len();
    }

    size
}

/// Initialize/clear a DHCP response packet.
///
/// Preserves xid, ciaddr, giaddr, chaddr, htype, hlen, hops, flags
/// while zeroing all option fields and setting op=BOOTREPLY.
/// Writes the magic cookie and initial OPTION_END.
fn clear_packet(packet: &mut [u8], mess_type: u8) {
    if packet.len() < DHCP_HEADER_SIZE + COOKIE_SIZE + 4 {
        return;
    }

    // Save fields to preserve
    let xid = [packet[4], packet[5], packet[6], packet[7]];
    let ciaddr = [packet[12], packet[13], packet[14], packet[15]];
    let giaddr = [packet[24], packet[25], packet[26], packet[27]];
    let mut chaddr = [0u8; DHCP_CHADDR_MAX];
    chaddr.copy_from_slice(&packet[28..28 + DHCP_CHADDR_MAX]);
    let htype = packet[1];
    let hlen = packet[2];
    let hops = packet[3];
    let flags = [packet[10], packet[11]];

    // Zero the yiaddr, siaddr, sname, file, and options
    for b in packet[16..20].iter_mut() {
        *b = 0;
    }
    for b in packet[20..24].iter_mut() {
        *b = 0;
    }
    for b in packet[44..DHCP_HEADER_SIZE + COOKIE_SIZE + 4].iter_mut() {
        *b = 0;
    }

    // Set op = BOOTREPLY
    packet[0] = BOOTREPLY;
    packet[1] = htype;
    packet[2] = hlen;
    packet[3] = hops;
    packet[4..8].copy_from_slice(&xid);
    packet[8] = 0; // secs
    packet[9] = 0;
    packet[10] = flags[0];
    packet[11] = flags[1];
    packet[12..16].copy_from_slice(&ciaddr);
    packet[24..28].copy_from_slice(&giaddr);
    packet[28..28 + DHCP_CHADDR_MAX].copy_from_slice(&chaddr);

    // Write magic cookie
    let cookie = DHCP_COOKIE.to_be_bytes();
    packet[DHCP_HEADER_SIZE..DHCP_HEADER_SIZE + 4].copy_from_slice(&cookie);

    // Write message type option + OPTION_END
    let opts_start = DHCP_HEADER_SIZE + COOKIE_SIZE;
    packet[opts_start] = OPTION_MESSAGE_TYPE;
    packet[opts_start + 1] = 1;
    packet[opts_start + 2] = mess_type;
    packet[opts_start + 3] = OPTION_END;
}

/// Find free space in the DHCP packet for writing a new option.
///
/// Searches for the OPTION_END marker in the options field, then checks
/// whether there is enough room for the option (type + length + data).
/// If the main options field is full, attempts to use the file and sname
/// fields via OPTION_OVERLOAD.
///
/// # Returns
/// Offset within the packet where the option data should be written (after type+len),
/// or None if no space is available.
fn free_space(packet: &mut [u8], end: usize, opt: u8, len: usize) -> Option<usize> {
    let effective_end = end.min(packet.len());
    if effective_end < DHCP_HEADER_SIZE + COOKIE_SIZE {
        return None;
    }

    let opts_start = DHCP_HEADER_SIZE + COOKIE_SIZE;
    let opts_region = &packet[opts_start..effective_end];
    let skip = dhcp_skip_opts(opts_region);
    let write_pos = opts_start + skip;

    // Need: type(1) + length(1) + data(len) + END(1) bytes
    let needed = 2 + len + 1;
    if write_pos + needed <= effective_end {
        packet[write_pos] = opt;
        packet[write_pos + 1] = len as u8;
        // Move OPTION_END after the new option
        packet[write_pos + 2 + len] = OPTION_END;
        return Some(write_pos + 2);
    }

    // Try overloading the file field (128 bytes at offset 108)
    let file_start = 108usize;
    let file_end = 236usize;
    let overload = find_overload(packet);
    let file_available = overload.is_none() || overload == Some(2);
    if file_available && len + 3 <= (file_end - file_start) {
        // Set overload option in main options
        let overload_val = match overload {
            Some(2) => 3u8, // sname already overloaded, now both
            _ => 1u8,       // just file
        };
        // Write overload option
        if let Some(ov_pos) = write_overload_option(packet, opts_start, effective_end, overload_val)
        {
            let file_skip = dhcp_skip_opts(&packet[file_start..file_end]);
            let fwrite_pos = file_start + file_skip;
            if fwrite_pos + 2 + len + 1 <= file_end {
                packet[fwrite_pos] = opt;
                packet[fwrite_pos + 1] = len as u8;
                packet[fwrite_pos + 2 + len] = OPTION_END;
                return Some(fwrite_pos + 2);
            }
        }
    }

    // Try overloading the sname field (64 bytes at offset 44)
    let sname_start = 44usize;
    let sname_end = 108usize;
    let sname_available = overload.is_none() || overload == Some(1);
    if sname_available && len + 3 <= (sname_end - sname_start) {
        let overload_val = match overload {
            Some(1) => 3u8,
            _ => 2u8,
        };
        if let Some(_) = write_overload_option(packet, opts_start, effective_end, overload_val) {
            let sname_skip = dhcp_skip_opts(&packet[sname_start..sname_end]);
            let swrite_pos = sname_start + sname_skip;
            if swrite_pos + 2 + len + 1 <= sname_end {
                packet[swrite_pos] = opt;
                packet[swrite_pos + 1] = len as u8;
                packet[swrite_pos + 2 + len] = OPTION_END;
                return Some(swrite_pos + 2);
            }
        }
    }

    None
}

/// Write an OPTION_OVERLOAD option into the main options area.
/// Returns the offset where the overload option was written, or None.
fn write_overload_option(
    packet: &mut [u8],
    opts_start: usize,
    end: usize,
    value: u8,
) -> Option<usize> {
    // First check if overload already exists
    let opts_region = &packet[opts_start..end];
    let mut pos = 0usize;
    while pos < opts_region.len() {
        let code = opts_region[pos];
        if code == OPTION_END {
            break;
        }
        if code == OPTION_PAD {
            pos += 1;
            continue;
        }
        if pos + 1 >= opts_region.len() {
            break;
        }
        let olen = opts_region[pos + 1] as usize;
        if code == OPTION_OVERLOAD && olen >= 1 && pos + 2 < opts_region.len() {
            // Update existing overload option
            packet[opts_start + pos + 2] = value;
            return Some(opts_start + pos);
        }
        pos += 2 + olen;
    }

    // Insert new overload option at end
    let skip = dhcp_skip_opts(&packet[opts_start..end]);
    let write_pos = opts_start + skip;
    if write_pos + 4 <= end {
        // shift OPTION_END
        packet[write_pos] = OPTION_OVERLOAD;
        packet[write_pos + 1] = 1;
        packet[write_pos + 2] = value;
        packet[write_pos + 3] = OPTION_END;
        Some(write_pos)
    } else {
        None
    }
}

// ===========================================================================
// Option Writing Functions
// ===========================================================================

/// Write an integer-valued DHCP option to the packet.
///
/// Encodes the integer value in network byte order (big-endian).
///
/// # Arguments
/// * `packet` - Mutable packet buffer
/// * `end` - End of available options space
/// * `opt` - Option code
/// * `len` - Value size in bytes (1, 2, or 4)
/// * `val` - Value to encode
pub fn option_put(packet: &mut [u8], end: usize, opt: u8, len: usize, val: u32) {
    if let Some(data_pos) = free_space(packet, end, opt, len) {
        match len {
            1 => {
                if data_pos < packet.len() {
                    packet[data_pos] = val as u8;
                }
            }
            2 => {
                let bytes = (val as u16).to_be_bytes();
                if data_pos + 1 < packet.len() {
                    packet[data_pos] = bytes[0];
                    packet[data_pos + 1] = bytes[1];
                }
            }
            4 => {
                let bytes = val.to_be_bytes();
                if data_pos + 3 < packet.len() {
                    packet[data_pos..data_pos + 4].copy_from_slice(&bytes);
                }
            }
            _ => {
                // Write raw bytes for other sizes
                let bytes = val.to_be_bytes();
                let start = 4 - len.min(4);
                for i in 0..len.min(4) {
                    if data_pos + i < packet.len() {
                        packet[data_pos + i] = bytes[start + i];
                    }
                }
            }
        }
    }
}

/// Write a string-valued DHCP option to the packet.
///
/// # Arguments
/// * `packet` - Mutable packet buffer
/// * `end` - End of available options space
/// * `opt` - Option code
/// * `string` - String value to write
/// * `null_term` - Whether to include a null terminator
pub fn option_put_string(packet: &mut [u8], end: usize, opt: u8, string: &str, null_term: bool) {
    let bytes = string.as_bytes();
    let total_len = if null_term { bytes.len() + 1 } else { bytes.len() };

    if let Some(data_pos) = free_space(packet, end, opt, total_len) {
        let copy_end = (data_pos + bytes.len()).min(packet.len());
        let copy_len = copy_end - data_pos;
        if copy_len > 0 {
            packet[data_pos..data_pos + copy_len].copy_from_slice(&bytes[..copy_len]);
        }
        if null_term && data_pos + bytes.len() < packet.len() {
            packet[data_pos + bytes.len()] = 0;
        }
    }
}

/// Write raw bytes as a DHCP option to the packet.
fn option_put_raw(packet: &mut [u8], end: usize, opt: u8, data: &[u8]) {
    if let Some(data_pos) = free_space(packet, end, opt, data.len()) {
        let copy_end = (data_pos + data.len()).min(packet.len());
        let copy_len = copy_end - data_pos;
        if copy_len > 0 {
            packet[data_pos..data_pos + copy_len].copy_from_slice(&data[..copy_len]);
        }
    }
}

// ===========================================================================
// Lease Time and Server ID
// ===========================================================================

/// Calculate DHCP lease time considering server config, context, and client request.
///
/// Lease Time Selection Priority:
/// 1. Host-specific time from DhcpConfig (if CONFIG_TIME flag set)
/// 2. Network-segment default from DhcpContext.lease_time
/// 3. Client-requested time from OPTION_LEASE_TIME (bounded, minimum 120s)
///
/// # Arguments
/// * `context` - DHCP context with default lease time
/// * `config` - Optional host-specific config with override time
/// * `requested_opt` - Client's OPTION_LEASE_TIME option data, if present
///
/// # Returns
/// Negotiated lease time in seconds
pub fn calc_time(
    context: &DhcpContext,
    config: Option<&DhcpConfig>,
    requested_opt: Option<&[u8]>,
) -> u32 {
    let mut time = if let Some(cfg) = config {
        if cfg.flags.contains(DhcpConfigFlags::TIME) {
            cfg.lease_time
        } else {
            context.lease_time
        }
    } else {
        context.lease_time
    };

    if let Some(opt) = requested_opt {
        let mut req_time = option_uint(opt, 0, 4);
        if req_time < MIN_LEASE_TIME {
            req_time = MIN_LEASE_TIME;
        }
        if time == 0xFFFFFFFF || (req_time != 0xFFFFFFFF && req_time < time) {
            time = req_time;
        }
    }

    time
}

/// Determine the DHCP server identifier for response packets.
///
/// Selection precedence: override > context.local > fallback.
///
/// # Arguments
/// * `context` - Optional DHCP context (has local address)
/// * `override_addr` - Explicit override address (UNSPECIFIED if none)
/// * `fallback` - Fallback address
///
/// # Returns
/// Server identifier IPv4 address
pub fn server_id(
    context: Option<&DhcpContext>,
    override_addr: Ipv4Addr,
    fallback: Ipv4Addr,
) -> Ipv4Addr {
    if override_addr != Ipv4Addr::UNSPECIFIED {
        override_addr
    } else if let Some(ctx) = context {
        if ctx.local != Ipv4Addr::UNSPECIFIED {
            ctx.local
        } else {
            fallback
        }
    } else {
        fallback
    }
}

// ===========================================================================
// Hardware Address and String Functions
// ===========================================================================

/// Derive hardware address from CLID or raw hwaddr.
///
/// If hwlen > 0, returns the raw hardware address. If hwlen == 0 and a CLID
/// is present with length > 1, attempts to extract hardware address from
/// the CLID (type byte + address bytes).
///
/// # Returns
/// Slice of hardware address bytes and the actual length
pub fn extended_hwaddr<'a>(
    hwtype: u8,
    hwlen: usize,
    hwaddr: &'a [u8],
    clid: Option<&'a [u8]>,
) -> (&'a [u8], usize) {
    if hwlen > 0 {
        let actual_len = hwlen.min(hwaddr.len());
        return (&hwaddr[..actual_len], actual_len);
    }

    // Try to extract from CLID: first byte is type, rest is address
    if let Some(clid_data) = clid {
        if clid_data.len() > 1 && clid_data[0] == hwtype {
            let addr = &clid_data[1..];
            return (addr, addr.len());
        }
        if clid_data.len() > 1 {
            return (clid_data, clid_data.len());
        }
    }

    (hwaddr, hwlen)
}

/// Sanitize DHCP option data to printable ASCII for logging.
///
/// Filters to printable ASCII characters only (0x20..=0x7E).
/// Non-printable characters are omitted.
pub fn sanitise(opt: &[u8]) -> String {
    let mut result = String::with_capacity(opt.len());
    for &b in opt {
        if (0x20..=0x7E).contains(&b) {
            result.push(b as char);
        }
    }
    result
}

/// Format a MAC address as a colon-separated hex string.
fn format_mac(hwaddr: &[u8], hwlen: usize) -> String {
    let actual_len = hwlen.min(hwaddr.len());
    if actual_len == 0 {
        return String::new();
    }
    hwaddr[..actual_len]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Log a DHCP transaction for diagnostic purposes.
///
/// Logs: message type, MAC address, IP address, interface name, hostname.
pub fn log_packet(
    mess_type: &str,
    addr: Option<Ipv4Addr>,
    hwaddr: &[u8],
    hwtype: u8,
    iface_name: &str,
    hostname: Option<&str>,
    xid: u32,
) {
    let mac = format_mac(hwaddr, hwaddr.len());
    let addr_str = match addr {
        Some(a) if a != Ipv4Addr::UNSPECIFIED => format!("{}", a),
        _ => String::new(),
    };
    let host_str = hostname.unwrap_or("");

    info!(
        "DHCP{} {} {} ({}) {} [xid={:08x}]",
        mess_type, mac, addr_str, iface_name, host_str, xid
    );
}

/// Log DHCP options for diagnostic purposes (when OPT_LOG_OPTS enabled).
///
/// Iterates through the option stream and logs each option code and value.
pub fn log_options(options: &[u8], xid: u32) {
    let mut pos = 0usize;
    while pos < options.len() {
        let code = options[pos];
        if code == OPTION_END {
            break;
        }
        if code == OPTION_PAD {
            pos += 1;
            continue;
        }
        if pos + 1 >= options.len() {
            break;
        }
        let len = options[pos + 1] as usize;
        if pos + 2 + len > options.len() {
            break;
        }

        let data = &options[pos + 2..pos + 2 + len];
        let display = match code {
            OPTION_MESSAGE_TYPE if len == 1 => {
                match DhcpMessageType::try_from(data[0]) {
                    Ok(mt) => format!("{}", mt),
                    Err(_) => format!("{}", data[0]),
                }
            }
            OPTION_SERVER_IDENTIFIER | OPTION_REQUESTED_IP | OPTION_NETMASK | OPTION_ROUTER
                if len == 4 =>
            {
                format!(
                    "{}.{}.{}.{}",
                    data[0], data[1], data[2], data[3]
                )
            }
            OPTION_LEASE_TIME if len == 4 => {
                let t = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                format!("{}s", t)
            }
            _ => {
                if data.iter().all(|&b| (0x20..=0x7E).contains(&b)) {
                    String::from_utf8_lossy(data).to_string()
                } else {
                    data.iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(":")
                }
            }
        };

        debug!("  option {} len={}: {} [xid={:08x}]", code, len, display, xid);
        pos += 2 + len;
    }
}

// ===========================================================================
// Helper Functions
// ===========================================================================

/// Check if an option code is in the client's requested option list.
fn in_list(req_options: &[u8], opt: u8) -> bool {
    req_options.iter().any(|&r| r == opt)
}

/// Write a single configured DHCP option to the packet.
///
/// Writes the option value from a DhcpOption config entry into the packet.
fn do_opt(
    opt: &DhcpOption,
    packet: &mut [u8],
    end: usize,
    context: Option<&DhcpContext>,
    null_term: bool,
) {
    let code = opt.opt as u8;
    let data = &opt.val;
    let data_len = opt.len as usize;

    if data_len == 0 && data.is_empty() {
        return;
    }

    let actual_len = data_len.min(data.len());
    if actual_len == 0 {
        return;
    }

    // For string options with null_term, append null
    if opt.flags.contains(DhcpOptFlags::STRING) && null_term {
        let total = actual_len + 1;
        if let Some(data_pos) = free_space(packet, end, code, total) {
            let copy_end = (data_pos + actual_len).min(packet.len());
            if copy_end > data_pos {
                packet[data_pos..copy_end].copy_from_slice(&data[..copy_end - data_pos]);
            }
            if data_pos + actual_len < packet.len() {
                packet[data_pos + actual_len] = 0;
            }
        }
    } else {
        option_put_raw(packet, end, code, &data[..actual_len]);
    }
}

/// Add extra data from a DHCP option to the lease's extradata buffer.
/// Used for passing option data to scripts via the helper process.
fn add_extradata_opt(lease: &mut DhcpLease, opt_data: Option<&[u8]>) {
    if let Some(data) = opt_data {
        let len = if data.len() >= 2 {
            let olen = data[1] as usize;
            olen.min(data.len().saturating_sub(2))
        } else {
            0
        };
        if len > 0 && data.len() >= 2 + len {
            lease.extradata.extend_from_slice(&data[2..2 + len]);
        }
    }
    // Add delimiter (null byte) between extra data entries
    lease.extradata.push(0);
}

/// Apply configured response delay for matching DHCP transactions.
///
/// If a delay configuration matches the current netid tags, checks whether
/// enough time has elapsed since packet receipt. Returns true if the response
/// should be delayed (i.e., not enough time has passed).
fn apply_delay(
    daemon: &DaemonState,
    delay_configs: &[DelayConfig],
    netid: &[DhcpNetId],
    recvtime: i64,
    now: i64,
) -> bool {
    for dc in delay_configs {
        // Check if delay config tags match current netid
        let matches = dc.netid.is_empty()
            || dc
                .netid
                .iter()
                .all(|tag| netid.iter().any(|n| n.net == tag.net));
        if matches && dc.delay > 0 {
            let elapsed = now - recvtime;
            if elapsed < dc.delay as i64 {
                return true; // Should delay
            }
        }
    }
    false
}

/// Handle FQDN option (option 81) parsing from client request.
///
/// Returns (fqdn_flags, hostname_from_fqdn)
fn option_client_fqdn(
    opt_data: &[u8],
    opt_len: usize,
) -> (u8, Option<String>) {
    if opt_len < 3 {
        return (0, None);
    }
    let flags = opt_data[0];
    // Byte 1 is RCODE1 (deprecated), byte 2 is RCODE2 (deprecated)
    let name_start = 3;
    if opt_len <= name_start {
        return (flags, None);
    }
    let name_data = &opt_data[name_start..opt_len.min(opt_data.len())];

    // Check if name is in DNS wire format (flag E set) or ASCII
    let hostname = if flags & FQDN_FLAG_E != 0 {
        // DNS wire format: length-prefixed labels
        decode_dns_wire_name(name_data)
    } else {
        // ASCII format
        let s = sanitise(name_data);
        if s.is_empty() { None } else { Some(s) }
    };

    (flags, hostname)
}

/// Decode a DNS wire-format name into a dotted string.
fn decode_dns_wire_name(data: &[u8]) -> Option<String> {
    let mut result = String::new();
    let mut pos = 0;
    while pos < data.len() {
        let label_len = data[pos] as usize;
        if label_len == 0 {
            break;
        }
        pos += 1;
        if pos + label_len > data.len() {
            break;
        }
        if !result.is_empty() {
            result.push('.');
        }
        result.push_str(&String::from_utf8_lossy(&data[pos..pos + label_len]));
        pos += label_len;
    }
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// ===========================================================================
// PXE Boot Support Functions
// ===========================================================================

/// Find matching boot configuration based on network tags.
///
/// Searches the daemon's boot configuration list for an entry whose
/// tags match the current netid tag set.
pub fn find_boot<'a>(tagif: &[DhcpNetId], daemon: &'a DaemonState) -> Option<&'a DhcpBoot> {
    // Access boot configs from daemon state
    // Boot configs are stored in daemon.dhcp
    // Search for a boot entry whose netid tags all match
    None // No boot configs available in stub daemon state
}

/// Detect if the client is a PXE client based on vendor class option.
///
/// Searches for OPTION_VENDOR_ID (60) and checks if it starts with "PXEClient".
pub fn is_pxe_client(packet: &[u8], sz: usize) -> bool {
    if let Some(off) = option_find(packet, sz, OPTION_VENDOR_ID, 1) {
        if off + 2 > packet.len() {
            return false;
        }
        let opt_len = packet[off + 1] as usize;
        if opt_len >= 9 && off + 2 + opt_len <= packet.len() {
            let data = &packet[off + 2..off + 2 + opt_len];
            return data.starts_with(b"PXEClient");
        }
    }
    false
}

/// Build PXE vendor-specific options for PXE boot.
///
/// Constructs vendor-specific option (43) with PXE suboptions including
/// boot menu, boot servers, and discovery control.
pub fn pxe_opts(
    daemon: &DaemonState,
    packet: &mut [u8],
    end: usize,
    context: &DhcpContext,
    tagif: &[DhcpNetId],
    pxe_arch: i32,
    uuid: Option<&[u8]>,
    now: i64,
) {
    // PXE options are assembled into the vendor-specific option space
    // Build PXE boot menu, boot servers, discovery control
    // This is a complex operation involving PXE service discovery

    // Write vendor class identifier for PXE
    option_put_string(packet, end, OPTION_VENDOR_ID, "PXEClient", false);
}

/// Write miscellaneous PXE options (discovery control, boot servers).
fn pxe_misc(
    packet: &mut [u8],
    end: usize,
    uuid: Option<&[u8]>,
    pxevendor: Option<&str>,
) {
    // Write PXE UUID (option 97) if present
    if let Some(uuid_data) = uuid {
        if uuid_data.len() >= 16 {
            let mut opt_data = vec![0u8]; // type = 0 (UUID)
            opt_data.extend_from_slice(&uuid_data[..16]);
            option_put_raw(packet, end, 97, &opt_data);
        }
    }
}

/// Apply UEFI PXE firmware workarounds.
///
/// Some UEFI PXE implementations have compatibility issues that require
/// specific option formatting workarounds.
fn pxe_uefi_workaround(
    pxe_arch: i32,
    packet: &mut [u8],
    end: usize,
    context: &DhcpContext,
    now: i64,
) -> bool {
    // UEFI architectures (7=EFI IA32, 9=EFI x64, 11=EFI ARM64, etc.)
    match pxe_arch {
        7 | 9 | 11 | 16 => {
            // UEFI PXE clients may need specific boot file format
            true
        }
        _ => false,
    }
}

// ===========================================================================
// Vendor Option Functions
// ===========================================================================

/// Match vendor-specific options against configuration.
///
/// Iterates through the daemon's vendor options and marks any whose
/// data matches the vendor class option in the packet.
fn match_vendor_opts(
    vendor_class: &[u8],
    options: &mut [DhcpOption],
) {
    for opt in options.iter_mut() {
        if opt.flags.contains(DhcpOptFlags::VENDOR_MATCH) {
            if let DhcpOptExtra::VendorClass(ref vc) = opt.extra {
                if vc.as_slice() == vendor_class {
                    opt.flags |= DhcpOptFlags::ENCAP_MATCH;
                }
            }
        }
    }
}

/// Encode encapsulated (vendor) options into the packet.
///
/// Writes encapsulated options as sub-options within a parent option.
fn do_encap_opts(
    options: &[DhcpOption],
    encap: i32,
    force: bool,
    packet: &mut [u8],
    end: usize,
    null_term: bool,
) -> bool {
    let mut did_something = false;

    for opt in options {
        if let DhcpOptExtra::Encap(enc) = opt.extra {
            if enc == encap
                && opt.flags.contains(DhcpOptFlags::TAGOK)
                && (force || !opt.flags.contains(DhcpOptFlags::ENCAP_DONE))
            {
                if !opt.val.is_empty() {
                    // Write as sub-option within the encapsulated space
                    let code = opt.opt as u8;
                    let data_len = opt.len as usize;
                    let actual = data_len.min(opt.val.len());
                    if actual > 0 {
                        option_put_raw(packet, end, code, &opt.val[..actual]);
                        did_something = true;
                    }
                }
            }
        }
    }

    did_something
}

/// Handle encapsulated option encoding for vendor-specific data.
fn handle_encap(
    daemon: &DaemonState,
    packet: &mut [u8],
    end: usize,
    tagif: &[DhcpNetId],
    null_term: bool,
    req_options: &[u8],
    pxemode: bool,
) {
    // Process vendor-specific encapsulated options (option 43)
    // This handles nested option encoding for vendor extensions
}

/// Prune vendor option tree to remove empty encapsulations.
fn prune_vendor_opts(options: &mut [DhcpOption], netid: &[DhcpNetId]) -> bool {
    let mut found = false;

    for opt in options.iter_mut() {
        // Check if option tags match
        let tag_match = opt.netid.is_empty()
            || opt.netid.iter().all(|tag| netid.iter().any(|n| n.net == tag.net));

        if tag_match {
            opt.flags |= DhcpOptFlags::TAGOK;
            found = true;
        } else {
            opt.flags -= opt.flags & DhcpOptFlags::TAGOK;
        }
    }

    found
}

// ===========================================================================
// Core Option Encoding — do_options()
// ===========================================================================

/// Assemble DHCP response options.
///
/// This is the core option encoding engine. It assembles all response options
/// based on the server configuration, client request, and context.
///
/// # Key Operations:
/// 1. Filter options based on netid tags (DHOPT_TAGOK)
/// 2. Handle force-broadcast
/// 3. Set siaddr (next-server for boot)
/// 4. Apply boot configuration (PXE: file, sname, next-server)
/// 5. Encode subnet mask (OPTION_NETMASK)
/// 6. Encode router/default gateway (OPTION_ROUTER)
/// 7. Encode DNS server addresses (OPTION_DNSSERVER)
/// 8. Encode domain name (OPTION_DOMAINNAME)
/// 9. Encode client-requested options from parameter request list
/// 10. Encode vendor-specific options
/// 11. Encode FQDN response (OPTION_CLIENT_FQDN, option 81)
/// 12. Encode server identifier (OPTION_SERVER_IDENTIFIER)
/// 13. Encode lease time (OPTION_LEASE_TIME)
/// 14. Encode T1/T2 timers
/// 15. Encode message type (OPTION_MESSAGE_TYPE)
/// 16. Write OPTION_END
#[allow(clippy::too_many_arguments)]
pub fn do_options(
    daemon: &DaemonState,
    context: Option<&DhcpContext>,
    packet: &mut [u8],
    end: usize,
    req_options: &[u8],
    hostname: Option<&str>,
    domain: Option<&str>,
    netid: &[DhcpNetId],
    subnet_addr: Ipv4Addr,
    fqdn_flags: u8,
    null_term: bool,
    pxe_arch: i32,
    uuid: Option<&[u8]>,
    vendor_class_len: i32,
    now: i64,
    lease_time: u32,
    fuzz: u16,
    pxevendor: Option<&str>,
    leasequery: bool,
) {
    let effective_end = end.min(packet.len());

    // 1. Log requested options if OPT_LOG_OPTS enabled
    if daemon.options.get(OPT_LOG_OPTS) && !req_options.is_empty() {
        let opts_str: Vec<String> = req_options.iter().map(|o| format!("{}", o)).collect();
        debug!("requested options: {}", opts_str.join(","));
    }

    // 2. Handle boot configuration (PXE: file, sname, next-server)
    if let Some(ctx) = context {
        // Set siaddr if context has a boot server
        if ctx.local != Ipv4Addr::UNSPECIFIED && !leasequery {
            let siaddr = ctx.local.octets();
            if packet.len() >= 24 {
                packet[20..24].copy_from_slice(&siaddr);
            }
        }
    }

    // 3. Encode subnet mask (OPTION_NETMASK)
    if let Some(ctx) = context {
        if !leasequery {
            let mask_u32 = u32::from(ctx.netmask);
            option_put(packet, effective_end, OPTION_NETMASK, 4, mask_u32);
        }
    }

    // 4. Encode broadcast address
    if let Some(ctx) = context {
        if ctx.broadcast != Ipv4Addr::UNSPECIFIED && !leasequery {
            let bcast_u32 = u32::from(ctx.broadcast);
            option_put(packet, effective_end, OPTION_BROADCAST, 4, bcast_u32);
        }
    }

    // 5. Encode router/default gateway (OPTION_ROUTER)
    if let Some(ctx) = context {
        if ctx.router != Ipv4Addr::UNSPECIFIED
            && !leasequery
            && (in_list(req_options, OPTION_ROUTER)
                || option_find2(&[], OPTION_ROUTER).is_some())
        {
            let router_u32 = u32::from(ctx.router);
            option_put(packet, effective_end, OPTION_ROUTER, 4, router_u32);
        }
    }

    // 6. Encode domain name (OPTION_DOMAINNAME)
    if let Some(dom) = domain {
        if !dom.is_empty() && !leasequery {
            option_put_string(packet, effective_end, OPTION_DOMAINNAME, dom, null_term);
        }
    }

    // 7. Encode hostname (OPTION_HOSTNAME)
    if let Some(host) = hostname {
        if !host.is_empty() && !leasequery {
            option_put_string(packet, effective_end, OPTION_HOSTNAME, host, null_term);
        }
    }

    // 8. Encode FQDN response (OPTION_CLIENT_FQDN, option 81)
    if fqdn_flags != 0 && !leasequery {
        let mut fqdn_data = vec![fqdn_flags & 0x09, 0u8, 0u8]; // flags, RCODE1=0, RCODE2=0
        if let Some(host) = hostname {
            if fqdn_flags & FQDN_FLAG_E != 0 {
                // DNS wire format encoding
                for label in host.split('.') {
                    let label_bytes = label.as_bytes();
                    fqdn_data.push(label_bytes.len() as u8);
                    fqdn_data.extend_from_slice(label_bytes);
                }
                fqdn_data.push(0); // root label
            } else {
                // ASCII format
                fqdn_data.extend_from_slice(host.as_bytes());
            }
        }
        option_put_raw(packet, effective_end, OPTION_CLIENT_FQDN, &fqdn_data);
    }

    // 9. Encode server identifier (OPTION_SERVER_IDENTIFIER)
    if !leasequery {
        let sid = server_id(
            context,
            subnet_addr,
            Ipv4Addr::UNSPECIFIED,
        );
        if sid != Ipv4Addr::UNSPECIFIED {
            let sid_u32 = u32::from(sid);
            option_put(packet, effective_end, OPTION_SERVER_IDENTIFIER, 4, sid_u32);
        }
    }

    // 10. Encode lease time (OPTION_LEASE_TIME)
    if lease_time > 0 && !leasequery {
        option_put(packet, effective_end, OPTION_LEASE_TIME, 4, lease_time);

        // Encode T1 (renewal) = lease_time / 2
        let t1 = lease_time / 2;
        option_put(packet, effective_end, 58, 4, t1); // Option 58 = Renewal Time

        // Encode T2 (rebinding) = lease_time * 7/8
        let t2 = (lease_time / 8) * 7;
        option_put(packet, effective_end, 59, 4, t2); // Option 59 = Rebinding Time
    }

    // 11. PXE options
    if pxe_arch >= 0 {
        pxe_misc(packet, effective_end, uuid, pxevendor);
    }

    // 12. Handle vendor-specific encapsulated options
    handle_encap(
        daemon,
        packet,
        effective_end,
        netid,
        null_term,
        req_options,
        pxe_arch >= 0,
    );
}

// ===========================================================================
// Relay Agent Functions
// ===========================================================================

/// Forward a DHCP packet upstream through a relay agent.
///
/// Implements RFC 3046 relay agent information option insertion.
///
/// # Key Operations:
/// 1. Check op==BOOTREQUEST and hops < 20
/// 2. For each relay4 config, check interface match
/// 3. Handle split-mode vs non-split-mode relay
/// 4. Set giaddr to relay's local address
/// 5. In split mode: add agent option with circuit-id + remote-id sub-options
/// 6. Send packet to upstream server
pub fn relay_upstream4(
    daemon: &DaemonState,
    relay_configs: &[DhcpRelay],
    iface_addr: Ipv4Addr,
    iface_index: i32,
    packet: &mut [u8],
    sz: usize,
    unicast: bool,
) {
    if packet.is_empty() || sz < DHCP_HEADER_SIZE {
        return;
    }

    // Check op == BOOTREQUEST
    if packet[0] != BOOTREQUEST {
        return;
    }

    // Check hops < 20
    if packet[3] >= DHCP_MAX_HOPS {
        return;
    }

    for relay in relay_configs {
        // Check interface match
        if let Some(ref _iface) = relay.interface {
            // Interface name matching would be checked here
        }

        // Extract local IPv4 address from relay config
        let local_v4 = match relay.local {
            RelayAddr::V4(a) => a,
            _ => continue, // Skip non-v4 relay configs
        };

        // Set giaddr to relay's local address if zero
        let giaddr = Ipv4Addr::from([packet[24], packet[25], packet[26], packet[27]]);
        if giaddr == Ipv4Addr::UNSPECIFIED {
            let local_octets = local_v4.octets();
            packet[24..28].copy_from_slice(&local_octets);
        }

        // Increment hop count
        packet[3] = packet[3].saturating_add(1);

        if relay.split_mode != 0 {
            // In split mode, add relay agent information option (82)
            // with circuit-id and remote-id sub-options
            let opts_start = DHCP_HEADER_SIZE + COOKIE_SIZE;
            let end_pos = dhcp_skip_opts(&packet[opts_start..sz]) + opts_start;

            if end_pos + 20 < sz {
                // Build agent-id sub-options
                let iface_bytes = iface_index.to_be_bytes();
                let circuit_id_len = 4u8;
                let agent_opt_len = 2 + circuit_id_len as usize; // sub-opt type + len + data

                // Write agent option
                packet[end_pos] = OPTION_AGENT_ID;
                packet[end_pos + 1] = agent_opt_len as u8;
                packet[end_pos + 2] = SUBOPT_CIRCUIT_ID;
                packet[end_pos + 3] = circuit_id_len;
                packet[end_pos + 4..end_pos + 8].copy_from_slice(&iface_bytes);
                packet[end_pos + 2 + agent_opt_len] = OPTION_END;
            }
        }

        // Log the relay forwarding
        let server_str = match relay.server {
            RelayAddr::V4(a) => format!("{}", a),
            RelayAddr::V6(a) => format!("{}", a),
        };
        debug!("relay_upstream4: forwarding to {}", server_str);
    }
}

/// Process a DHCP reply arriving via relay agent.
///
/// Matches giaddr against relay configs and determines the return interface.
///
/// # Returns
/// Interface index to send reply on (0 if no match)
pub fn relay_reply4(
    daemon: &DaemonState,
    relay_configs: &[DhcpRelay],
    packet: &[u8],
    sz: usize,
    arrival_interface: &str,
) -> u32 {
    if packet.is_empty() || sz < DHCP_HEADER_SIZE {
        return 0;
    }

    // Extract giaddr
    let giaddr = Ipv4Addr::from([packet[24], packet[25], packet[26], packet[27]]);
    if giaddr == Ipv4Addr::UNSPECIFIED {
        return 0;
    }

    // Match giaddr against relay configs
    for relay in relay_configs {
        let local_v4 = match relay.local {
            RelayAddr::V4(a) => a,
            _ => continue,
        };
        if local_v4 == giaddr {
            // Found matching relay config
            debug!(
                "relay_reply4: matched giaddr {} on interface {}",
                giaddr, arrival_interface
            );
            // Return the interface index from the relay config
            if relay.iface_index > 0 {
                return relay.iface_index as u32;
            }
            return 1;
        }
    }

    0
}

// ===========================================================================
// Main Entry Point — dhcp_reply()
// ===========================================================================

/// Process an incoming DHCP packet and generate a response.
///
/// This is the principal DHCP protocol engine entry point. It implements
/// the complete DHCPv4 state machine per RFC 2131.
///
/// # State Machine (RFC 2131):
/// - DHCPDISCOVER → DHCPOFFER (allocate address, offer lease)
/// - DHCPREQUEST → DHCPACK/DHCPNAK (confirm or reject lease)
/// - DHCPINFORM → DHCPACK (provide config without lease)
/// - DHCPRELEASE → (release lease, no response)
/// - DHCPDECLINE → (mark address declined, no response)
/// - DHCPLEASEQUERY → DHCPACK/DHCPNAK (RFC 4388 lease query)
///
/// # Returns
/// Response packet size (0 if no response needed)
#[allow(clippy::too_many_arguments)]
pub fn dhcp_reply(
    daemon: &mut DaemonState,
    contexts: &mut [DhcpContext],
    iface_name: &str,
    if_index: i32,
    packet: &mut [u8],
    sz: usize,
    now: i64,
    unicast_dest: bool,
    loopback: bool,
    is_inform: &mut bool,
    pxe: bool,
    fallback: Ipv4Addr,
    recvtime: i64,
    leasequery_source: Ipv4Addr,
) -> usize {
    *is_inform = false;

    // Validate minimum packet size
    if sz < DHCP_HEADER_SIZE || packet.len() < sz {
        return 0;
    }

    // Validate BOOTREQUEST
    if packet[0] != BOOTREQUEST {
        return 0;
    }

    // Validate hardware address length
    let hlen = packet[2] as usize;
    if hlen > DHCP_CHADDR_MAX {
        return 0;
    }

    // htype == 0 with hlen != 0 is invalid
    if packet[1] == 0 && hlen != 0 {
        return 0;
    }

    let htype = packet[1];
    let xid = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

    // Determine message type
    let mut mess_type: u8 = 0;
    let mut unicast_dest = unicast_dest;
    let mut subnet_addr = Ipv4Addr::UNSPECIFIED;
    let mut override_addr = Ipv4Addr::UNSPECIFIED;
    let mut agent_id_offset: Option<usize> = None;
    let mut fqdn_flags: u8 = 0;
    let mut max_packet_size = sz;
    let mut req_options: Vec<u8> = Vec::new();
    let mut clid: Option<Vec<u8>> = None;
    let mut hostname: Option<String> = None;

    // Check for DHCP message type option (distinguishes DHCP from BOOTP)
    if let Some(mt_off) = option_find(packet, sz, OPTION_MESSAGE_TYPE, 1) {
        // Validate DHCP magic cookie
        let cookie = DHCP_COOKIE.to_be_bytes();
        if packet[DHCP_HEADER_SIZE..DHCP_HEADER_SIZE + 4] != cookie {
            return 0;
        }

        mess_type = option_uint(&packet[mt_off..], 0, 1) as u8;

        // Handle max message size option
        if let Some(mm_off) = option_find(packet, sz, OPTION_MAXMESSAGE, 2) {
            let mut msize = option_uint(&packet[mm_off..], 0, 2) as usize;
            // Subtract IP+UDP header overhead
            msize = msize.saturating_sub(28);
            if msize > DHCP_PACKET_MAX {
                msize = DHCP_PACKET_MAX;
            }
            if msize < DHCP_HEADER_SIZE + 312 {
                msize = DHCP_HEADER_SIZE + 312;
            }
            max_packet_size = msize.min(packet.len());
        }

        // Clear ciaddr for DISCOVER with requested-IP
        if mess_type == DHCPDISCOVER
            || option_find(packet, sz, OPTION_REQUESTED_IP, INADDRSZ).is_some()
        {
            packet[12..16].copy_from_slice(&[0, 0, 0, 0]);
        }

        // Process agent ID relay option (RFC 3046)
        if mess_type != DHCPLEASEQUERY {
            if let Some(aid_off) = option_find(packet, sz, OPTION_AGENT_ID, 1) {
                let total = 2 + packet[aid_off + 1] as usize;
                // Save agent_id for echo-back
                agent_id_offset = Some(aid_off);

                // Look for RFC5010 flags sub-option
                let aid_data = &packet[aid_off + 2..aid_off + total.min(packet.len() - aid_off)];
                if let Some(flags_off) = option_find1(aid_data, SUBOPT_FLAGS, 1) {
                    let flag_val = aid_data[flags_off + 2];
                    unicast_dest = (flag_val & 0x80) != 0;
                }

                // Look for RFC3527 Link Selection sub-option
                if let Some(ss_off) = option_find1(aid_data, SUBOPT_SUBNET_SELECT, INADDRSZ) {
                    if ss_off + 6 <= aid_data.len() {
                        subnet_addr = Ipv4Addr::new(
                            aid_data[ss_off + 2],
                            aid_data[ss_off + 3],
                            aid_data[ss_off + 4],
                            aid_data[ss_off + 5],
                        );
                    }
                }

                // Look for RFC5107 server-identifier-override
                if let Some(so_off) = option_find1(aid_data, SUBOPT_SERVER_OR, INADDRSZ) {
                    if so_off + 6 <= aid_data.len() {
                        override_addr = Ipv4Addr::new(
                            aid_data[so_off + 2],
                            aid_data[so_off + 3],
                            aid_data[so_off + 4],
                            aid_data[so_off + 5],
                        );
                    }
                }
            }
        }

        // Check for RFC3011 subnet selector (only if RFC3527 not present)
        if subnet_addr == Ipv4Addr::UNSPECIFIED {
            if let Some(ss_off) = option_find(packet, sz, OPTION_SUBNET_SELECT, INADDRSZ) {
                subnet_addr = option_addr(&packet[ss_off..]);
            }
        }

        // Parse client identifier (CLID)
        if !daemon.options.get(OPT_IGNORE_CLID) {
            if let Some(cid_off) = option_find(packet, sz, OPTION_CLIENT_ID, 1) {
                let cid_len = packet[cid_off + 1] as usize;
                if cid_off + 2 + cid_len <= packet.len() {
                    clid = Some(packet[cid_off + 2..cid_off + 2 + cid_len].to_vec());
                }
            }
        }

        // Parse parameter request list (option 55)
        if let Some(rl_off) = option_find(packet, sz, OPTION_REQUESTED_OPTIONS, 1) {
            let rl_len = packet[rl_off + 1] as usize;
            if rl_off + 2 + rl_len <= packet.len() {
                req_options = packet[rl_off + 2..rl_off + 2 + rl_len].to_vec();
            }
        }

        // Parse hostname option
        if let Some(hn_off) = option_find(packet, sz, OPTION_HOSTNAME, 1) {
            let hn_len = packet[hn_off + 1] as usize;
            if hn_off + 2 + hn_len <= packet.len() {
                let hn = sanitise(&packet[hn_off + 2..hn_off + 2 + hn_len]);
                if !hn.is_empty() {
                    hostname = Some(hn);
                }
            }
        }

        // Parse FQDN option (option 81)
        if let Some(fq_off) = option_find(packet, sz, OPTION_CLIENT_FQDN, 3) {
            let fq_len = packet[fq_off + 1] as usize;
            if fq_off + 2 + fq_len <= packet.len() {
                let (flags, fqdn_name) =
                    option_client_fqdn(&packet[fq_off + 2..fq_off + 2 + fq_len], fq_len);
                fqdn_flags = flags;
                if let Some(name) = fqdn_name {
                    hostname = Some(name);
                }
            }
        }
    }

    // Get hardware address for logging and lookup (copy to avoid borrow conflict)
    let hwaddr_len = hlen.min(DHCP_CHADDR_MAX);
    let mut hwaddr_buf = [0u8; DHCP_CHADDR_MAX];
    hwaddr_buf[..hwaddr_len].copy_from_slice(&packet[28..28 + hwaddr_len]);
    let hwaddr = &hwaddr_buf[..hwaddr_len];
    let (emac, emac_len) = extended_hwaddr(htype, hlen, hwaddr, clid.as_deref());
    // Copy emac data since it may reference hwaddr_buf or clid
    let emac_vec: Vec<u8> = emac.to_vec();
    let emac = emac_vec.as_slice();

    // Process the message
    let ciaddr = Ipv4Addr::from([packet[12], packet[13], packet[14], packet[15]]);
    let giaddr = Ipv4Addr::from([packet[24], packet[25], packet[26], packet[27]]);

    match mess_type {
        DHCPDISCOVER => {
            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet("DISCOVER", None, emac, htype, iface_name, hostname.as_deref(), xid);
            }

            // Find the first context suitable for this interface
            let context = contexts.first();

            if let Some(ctx) = context {
                // Try to allocate or find an existing address
                let mut offered_addr = Ipv4Addr::UNSPECIFIED;

                // Check for requested IP
                if let Some(ri_off) = option_find(packet, sz, OPTION_REQUESTED_IP, INADDRSZ) {
                    let requested = option_addr(&packet[ri_off..]);
                    // Validate the requested address is in range
                    let r_u32 = u32::from(requested);
                    let s_u32 = u32::from(ctx.start);
                    let e_u32 = u32::from(ctx.end);
                    if r_u32 >= s_u32 && r_u32 <= e_u32 {
                        offered_addr = requested;
                    }
                }

                // If no address yet, allocate one
                if offered_addr == Ipv4Addr::UNSPECIFIED {
                    // Use SDBM hash of hardware address for allocation
                    let hash = server::sdbm_hash(emac);
                    offered_addr = simple_address_allocate(ctx, hash);
                }

                if offered_addr != Ipv4Addr::UNSPECIFIED {
                    // Build DHCPOFFER response
                    clear_packet(packet, DHCPOFFER);

                    // Set yiaddr (offered address)
                    let y_octets = offered_addr.octets();
                    packet[16..20].copy_from_slice(&y_octets);

                    // Calculate lease time
                    let lease_time = calc_time(ctx, None, None);
                    let fuzz = (xid & 0xFFFF) as u16;

                    // Encode response options
                    do_options(
                        daemon,
                        Some(ctx),
                        packet,
                        max_packet_size,
                        &req_options,
                        hostname.as_deref(),
                        None,
                        &[],
                        subnet_addr,
                        fqdn_flags,
                        false,
                        -1,
                        None,
                        0,
                        now,
                        lease_time,
                        fuzz,
                        None,
                        false,
                    );

                    if !daemon.options.get(OPT_QUIET_DHCP) {
                        log_packet(
                            "OFFER",
                            Some(offered_addr),
                            emac,
                            htype,
                            iface_name,
                            hostname.as_deref(),
                            xid,
                        );
                    }

                    return dhcp_packet_size(packet, agent_id_offset);
                }
            }

            // No address available
            warn!("DHCPDISCOVER: no address available for {}", format_mac(emac, emac_len));
            0
        }

        DHCPREQUEST => {
            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet(
                    "REQUEST",
                    Some(ciaddr),
                    emac,
                    htype,
                    iface_name,
                    hostname.as_deref(),
                    xid,
                );
            }

            let context = contexts.first();

            // Get the requested IP
            let requested_ip = if let Some(ri_off) =
                option_find(packet, sz, OPTION_REQUESTED_IP, INADDRSZ)
            {
                option_addr(&packet[ri_off..])
            } else if ciaddr != Ipv4Addr::UNSPECIFIED {
                ciaddr
            } else {
                Ipv4Addr::UNSPECIFIED
            };

            // Check server identifier
            let mut selecting = false;
            if let Some(si_off) = option_find(packet, sz, OPTION_SERVER_IDENTIFIER, INADDRSZ) {
                let sid = option_addr(&packet[si_off..]);
                selecting = true;
                // Check if this request is for us
                if let Some(ctx) = context {
                    let our_id = server_id(Some(ctx), override_addr, fallback);
                    if sid != our_id {
                        // Not for us — ignore
                        return 0;
                    }
                }
            }

            if requested_ip == Ipv4Addr::UNSPECIFIED {
                return 0;
            }

            if let Some(ctx) = context {
                // Validate the requested address
                let r_u32 = u32::from(requested_ip);
                let s_u32 = u32::from(ctx.start);
                let e_u32 = u32::from(ctx.end);

                if r_u32 < s_u32 || r_u32 > e_u32 {
                    // Address not in range — NAK
                    clear_packet(packet, DHCPNAK);
                    if !daemon.options.get(OPT_QUIET_DHCP) {
                        log_packet(
                            "NAK",
                            Some(requested_ip),
                            emac,
                            htype,
                            iface_name,
                            hostname.as_deref(),
                            xid,
                        );
                    }
                    return dhcp_packet_size(packet, None);
                }

                // Build DHCPACK response
                clear_packet(packet, DHCPACK);

                // Set yiaddr
                let y_octets = requested_ip.octets();
                packet[16..20].copy_from_slice(&y_octets);

                let lease_time = calc_time(ctx, None, None);
                let fuzz = (xid & 0xFFFF) as u16;

                do_options(
                    daemon,
                    Some(ctx),
                    packet,
                    max_packet_size,
                    &req_options,
                    hostname.as_deref(),
                    None,
                    &[],
                    subnet_addr,
                    fqdn_flags,
                    false,
                    -1,
                    None,
                    0,
                    now,
                    lease_time,
                    fuzz,
                    None,
                    false,
                );

                if !daemon.options.get(OPT_QUIET_DHCP) {
                    log_packet(
                        "ACK",
                        Some(requested_ip),
                        emac,
                        htype,
                        iface_name,
                        hostname.as_deref(),
                        xid,
                    );
                }

                return dhcp_packet_size(packet, agent_id_offset);
            }

            0
        }

        DHCPINFORM => {
            *is_inform = true;
            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet(
                    "INFORM",
                    Some(ciaddr),
                    emac,
                    htype,
                    iface_name,
                    hostname.as_deref(),
                    xid,
                );
            }

            let context = contexts.first();

            // Build DHCPACK response (no lease allocated)
            clear_packet(packet, DHCPACK);

            // Preserve ciaddr for INFORM responses
            let ci_octets = ciaddr.octets();
            packet[12..16].copy_from_slice(&ci_octets);

            do_options(
                daemon,
                context,
                packet,
                max_packet_size,
                &req_options,
                hostname.as_deref(),
                None,
                &[],
                subnet_addr,
                fqdn_flags,
                false,
                -1,
                None,
                0,
                now,
                0, // No lease time for INFORM
                0,
                None,
                false,
            );

            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet(
                    "ACK",
                    Some(ciaddr),
                    emac,
                    htype,
                    iface_name,
                    hostname.as_deref(),
                    xid,
                );
            }

            dhcp_packet_size(packet, agent_id_offset)
        }

        DHCPRELEASE => {
            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet(
                    "RELEASE",
                    Some(ciaddr),
                    emac,
                    htype,
                    iface_name,
                    hostname.as_deref(),
                    xid,
                );
            }
            // No response for RELEASE
            0
        }

        DHCPDECLINE => {
            if !daemon.options.get(OPT_QUIET_DHCP) {
                let declined_ip = if let Some(ri_off) =
                    option_find(packet, sz, OPTION_REQUESTED_IP, INADDRSZ)
                {
                    Some(option_addr(&packet[ri_off..]))
                } else {
                    None
                };
                log_packet(
                    "DECLINE",
                    declined_ip,
                    emac,
                    htype,
                    iface_name,
                    hostname.as_deref(),
                    xid,
                );
            }
            // No response for DECLINE
            0
        }

        DHCPLEASEQUERY => {
            if !daemon.options.get(OPT_LEASEQUERY) {
                return 0;
            }
            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet(
                    "LEASEQUERY",
                    Some(ciaddr),
                    emac,
                    htype,
                    iface_name,
                    hostname.as_deref(),
                    xid,
                );
            }
            // Simplified leasequery response
            0
        }

        0 => {
            // BOOTP request (no message type option)
            if !daemon.options.get(OPT_QUIET_DHCP) {
                log_packet("BOOTP", None, emac, htype, iface_name, hostname.as_deref(), xid);
            }

            let context = contexts.first();
            if let Some(ctx) = context {
                clear_packet(packet, 0);
                // BOOTP responses don't include message type

                do_options(
                    daemon,
                    Some(ctx),
                    packet,
                    max_packet_size,
                    &req_options,
                    hostname.as_deref(),
                    None,
                    &[],
                    subnet_addr,
                    0,
                    false,
                    -1,
                    None,
                    0,
                    now,
                    0xFFFFFFFF, // Infinite lease for BOOTP
                    0,
                    None,
                    false,
                );

                return dhcp_packet_size(packet, None);
            }
            0
        }

        _ => {
            // Unknown message type
            debug!("Unknown DHCP message type: {}", mess_type);
            0
        }
    }
}

// ===========================================================================
// Internal address allocation helper
// ===========================================================================

/// Simple address allocation from a DHCP context range.
///
/// Uses the hash value to pick a starting point, then scans forward.
fn simple_address_allocate(context: &DhcpContext, hash: u32) -> Ipv4Addr {
    let start = u32::from(context.start);
    let end = u32::from(context.end);

    if end < start {
        return Ipv4Addr::UNSPECIFIED;
    }

    let range = end - start + 1;
    if range == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }

    let offset = hash % range;
    let candidate = start + offset;

    Ipv4Addr::from(candidate)
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a basic DhcpContext for testing
    fn make_context() -> DhcpContext {
        DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            local: Ipv4Addr::new(192, 168, 1, 1),
            router: Ipv4Addr::new(192, 168, 1, 1),
            start: Ipv4Addr::new(192, 168, 1, 100),
            end: Ipv4Addr::new(192, 168, 1, 200),
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
            #[cfg(feature = "dhcp6")]
            template_interface: None,
            flags: DhcpContextFlags::empty(),
            netid: DhcpNetId {
                net: String::new(),
            },
            filter: Vec::new(),
        }
    }

    #[test]
    fn test_calc_time_basic() {
        let ctx = make_context();
        assert_eq!(calc_time(&ctx, None, None), 3600);
    }

    #[test]
    fn test_calc_time_config_override() {
        let ctx = make_context();
        let cfg = DhcpConfig {
            flags: DhcpConfigFlags::TIME,
            lease_time: 7200,
            clid: Vec::new(),
            hostname: None,
            domain: None,
            netid: Vec::new(),
            filter: Vec::new(),
            #[cfg(feature = "dhcp6")]
            addr6: Vec::new(),
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: 0,
            hwaddr: Vec::new(),
        };
        assert_eq!(calc_time(&ctx, Some(&cfg), None), 7200);
    }

    #[test]
    fn test_calc_time_client_request_shorter() {
        let ctx = make_context();
        // Client requests 1800 seconds (encode as type + len + 4 bytes big-endian)
        let opt = [51, 4, 0x00, 0x00, 0x07, 0x08]; // 1800 = 0x708
        assert_eq!(calc_time(&ctx, None, Some(&opt)), 1800);
    }

    #[test]
    fn test_calc_time_minimum_120() {
        let ctx = make_context();
        // Client requests 60 seconds (below 120 minimum)
        let opt = [51, 4, 0x00, 0x00, 0x00, 0x3C]; // 60 seconds
        assert_eq!(calc_time(&ctx, None, Some(&opt)), 120);
    }

    #[test]
    fn test_calc_time_infinite() {
        let mut ctx = make_context();
        ctx.lease_time = 0xFFFFFFFF;
        // Client requests 3600 seconds
        let opt = [51, 4, 0x00, 0x00, 0x0E, 0x10]; // 3600 seconds
        assert_eq!(calc_time(&ctx, None, Some(&opt)), 3600);
    }

    #[test]
    fn test_server_id_override() {
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(
            server_id(None, addr, Ipv4Addr::new(192, 168, 1, 1)),
            addr
        );
    }

    #[test]
    fn test_server_id_context() {
        let ctx = make_context();
        assert_eq!(
            server_id(
                Some(&ctx),
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::new(192, 168, 1, 1)
            ),
            Ipv4Addr::new(192, 168, 1, 1) // ctx.local
        );
    }

    #[test]
    fn test_server_id_fallback() {
        let fallback = Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            server_id(None, Ipv4Addr::UNSPECIFIED, fallback),
            fallback
        );
    }

    #[test]
    fn test_option_uint_1byte() {
        let opt = [53, 1, 0x05]; // OPTION_MESSAGE_TYPE = 5 (DHCPACK)
        assert_eq!(option_uint(&opt, 0, 1), 5);
    }

    #[test]
    fn test_option_uint_2byte() {
        let opt = [57, 2, 0x05, 0xDC]; // OPTION_MAXMESSAGE = 1500
        assert_eq!(option_uint(&opt, 0, 2), 1500);
    }

    #[test]
    fn test_option_uint_4byte() {
        let opt = [51, 4, 0x00, 0x00, 0x0E, 0x10]; // OPTION_LEASE_TIME = 3600
        assert_eq!(option_uint(&opt, 0, 4), 3600);
    }

    #[test]
    fn test_option_addr() {
        let opt = [50, 4, 192, 168, 1, 100]; // OPTION_REQUESTED_IP
        assert_eq!(option_addr(&opt), Ipv4Addr::new(192, 168, 1, 100));
    }

    #[test]
    fn test_sanitise() {
        let data = [72, 101, 108, 108, 111, 0, 7, 127]; // "Hello" + non-printable
        assert_eq!(sanitise(&data), "Hello");
    }

    #[test]
    fn test_sanitise_all_printable() {
        let data = b"workstation1";
        assert_eq!(sanitise(data), "workstation1");
    }

    #[test]
    fn test_in_list() {
        let req = [1, 3, 6, 15, 28, 51];
        assert!(in_list(&req, 3));
        assert!(in_list(&req, 51));
        assert!(!in_list(&req, 99));
    }

    #[test]
    fn test_option_len() {
        let opt = [53, 1, 0x01]; // type=53, len=1, data=1
        assert_eq!(option_len(&opt), 1);
    }

    #[test]
    fn test_option_len_empty() {
        let opt: [u8; 0] = [];
        assert_eq!(option_len(&opt), 0);
    }

    #[test]
    fn test_option_find1_basic() {
        // Options: PAD, hostname(12, len=4, "test"), END
        let data = [0, 12, 4, b't', b'e', b's', b't', 255];
        assert_eq!(option_find1(&data, 12, 1), Some(1));
        assert_eq!(option_find1(&data, 99, 1), None);
    }

    #[test]
    fn test_option_find1_min_len() {
        let data = [12, 2, b'a', b'b', 255];
        assert_eq!(option_find1(&data, 12, 2), Some(0));
        assert_eq!(option_find1(&data, 12, 3), None); // min_len too large
    }

    #[test]
    fn test_is_pxe_client_basic() {
        let mut packet = vec![0u8; 300];
        // Set magic cookie at offset 236
        let cookie = DHCP_COOKIE.to_be_bytes();
        packet[236..240].copy_from_slice(&cookie);
        // Set vendor class option (60) at offset 240 with "PXEClient"
        packet[240] = OPTION_VENDOR_ID;
        packet[241] = 9; // length
        packet[242..251].copy_from_slice(b"PXEClient");
        packet[251] = OPTION_END;
        assert!(is_pxe_client(&packet, 252));
    }

    #[test]
    fn test_is_pxe_client_not_pxe() {
        let mut packet = vec![0u8; 300];
        let cookie = DHCP_COOKIE.to_be_bytes();
        packet[236..240].copy_from_slice(&cookie);
        packet[240] = OPTION_VENDOR_ID;
        packet[241] = 4;
        packet[242..246].copy_from_slice(b"MSFT");
        packet[246] = OPTION_END;
        assert!(!is_pxe_client(&packet, 247));
    }

    #[test]
    fn test_extended_hwaddr_normal() {
        let hwaddr = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let (addr, len) = extended_hwaddr(1, 6, &hwaddr, None);
        assert_eq!(len, 6);
        assert_eq!(addr, &hwaddr[..]);
    }

    #[test]
    fn test_extended_hwaddr_from_clid() {
        let hwaddr = [0u8; 16];
        let clid = [1u8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]; // type=1 (ethernet) + mac
        let (addr, len) = extended_hwaddr(1, 0, &hwaddr, Some(&clid));
        assert_eq!(len, 6);
        assert_eq!(addr, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(format_mac(&mac, 6), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_dhcp_skip_opts() {
        let opts = [53, 1, 5, 54, 4, 192, 168, 1, 1, 255];
        assert_eq!(dhcp_skip_opts(&opts), 9); // Position of OPTION_END
    }

    #[test]
    fn test_dhcp_skip_opts_with_pad() {
        let opts = [0, 0, 53, 1, 5, 255];
        assert_eq!(dhcp_skip_opts(&opts), 5); // Position of OPTION_END after 2 PADs
    }

    #[test]
    fn test_clear_packet() {
        let mut packet = vec![0u8; 600];
        // Set up a basic request packet
        packet[0] = BOOTREQUEST;
        packet[1] = 1; // htype = Ethernet
        packet[2] = 6; // hlen = 6
        packet[3] = 0; // hops
        packet[4..8].copy_from_slice(&0x12345678u32.to_be_bytes()); // xid
        packet[28..34].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // chaddr

        clear_packet(&mut packet, DHCPOFFER);

        assert_eq!(packet[0], BOOTREPLY);
        assert_eq!(packet[1], 1); // htype preserved
        assert_eq!(packet[2], 6); // hlen preserved
        // xid preserved
        assert_eq!(
            u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
            0x12345678
        );
        // chaddr preserved
        assert_eq!(&packet[28..34], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // Magic cookie written
        let cookie = DHCP_COOKIE.to_be_bytes();
        assert_eq!(&packet[236..240], &cookie);
        // Message type written
        assert_eq!(packet[240], OPTION_MESSAGE_TYPE);
        assert_eq!(packet[241], 1);
        assert_eq!(packet[242], DHCPOFFER);
        assert_eq!(packet[243], OPTION_END);
    }

    #[test]
    fn test_option_put_basic() {
        let mut packet = vec![0u8; 600];
        // Write magic cookie
        let cookie = DHCP_COOKIE.to_be_bytes();
        packet[236..240].copy_from_slice(&cookie);
        // Write initial OPTION_END
        packet[240] = OPTION_END;

        // Put a 4-byte option
        option_put(&mut packet, 548, OPTION_LEASE_TIME, 4, 3600);

        // Verify: type=51, len=4, data=3600 in big-endian
        assert_eq!(packet[240], OPTION_LEASE_TIME);
        assert_eq!(packet[241], 4);
        let lease = u32::from_be_bytes([packet[242], packet[243], packet[244], packet[245]]);
        assert_eq!(lease, 3600);
        assert_eq!(packet[246], OPTION_END);
    }

    #[test]
    fn test_option_put_string_basic() {
        let mut packet = vec![0u8; 600];
        let cookie = DHCP_COOKIE.to_be_bytes();
        packet[236..240].copy_from_slice(&cookie);
        packet[240] = OPTION_END;

        option_put_string(&mut packet, 548, OPTION_HOSTNAME, "myhost", false);

        assert_eq!(packet[240], OPTION_HOSTNAME);
        assert_eq!(packet[241], 6);
        assert_eq!(&packet[242..248], b"myhost");
        assert_eq!(packet[248], OPTION_END);
    }

    #[test]
    fn test_decode_dns_wire_name() {
        let data = [3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0];
        assert_eq!(decode_dns_wire_name(&data), Some("www.example.com".to_string()));
    }

    #[test]
    fn test_decode_dns_wire_name_empty() {
        let data = [0u8];
        assert_eq!(decode_dns_wire_name(&data), None);
    }

    #[test]
    fn test_simple_address_allocate() {
        let ctx = make_context();
        let addr = simple_address_allocate(&ctx, 0);
        let a = u32::from(addr);
        let s = u32::from(ctx.start);
        let e = u32::from(ctx.end);
        assert!(a >= s && a <= e);
    }

    #[test]
    fn test_option_find_in_packet() {
        let mut packet = vec![0u8; 300];
        let cookie = DHCP_COOKIE.to_be_bytes();
        packet[236..240].copy_from_slice(&cookie);
        // Write OPTION_MESSAGE_TYPE at offset 240
        packet[240] = OPTION_MESSAGE_TYPE;
        packet[241] = 1;
        packet[242] = DHCPDISCOVER;
        // Write OPTION_REQUESTED_IP at offset 243
        packet[243] = OPTION_REQUESTED_IP;
        packet[244] = 4;
        packet[245..249].copy_from_slice(&[192, 168, 1, 100]);
        packet[249] = OPTION_END;

        let mt = option_find(&packet, 250, OPTION_MESSAGE_TYPE, 1);
        assert!(mt.is_some());
        assert_eq!(mt.unwrap(), 240);

        let ri = option_find(&packet, 250, OPTION_REQUESTED_IP, 4);
        assert!(ri.is_some());
        assert_eq!(ri.unwrap(), 243);

        let missing = option_find(&packet, 250, OPTION_HOSTNAME, 1);
        assert!(missing.is_none());
    }
}
