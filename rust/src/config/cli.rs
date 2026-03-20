// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # CLI Argument Processing via Clap
//!
//! Rust replacement for the CLI argument parsing section of C `src/option.c`.
//! Implements command-line argument processing using the `clap` derive API,
//! mapping **every** dnsmasq CLI flag to a corresponding struct field for
//! drop-in replacement compatibility.
//!
//! ## Source Reference
//!
//! - `src/option.c` lines 197–535: `OPTSTRING` short options, `opts[]` long option array
//! - `src/option.c` lines 543–742: `usage[]` help text array
//! - `src/config.h`: Default values for options (CACHESIZ, CHUSER, CHGRP, etc.)
//! - `src/dnsmasq.h`: `OPT_*` option bit flags
//!
//! ## Design Decisions
//!
//! - Uses `#[derive(Parser)]` (clap derive API) for maintainability
//! - Every short option from `OPTSTRING` is mapped with `#[arg(short = ...)]`
//! - Every long option from `opts[]` is mapped with `#[arg(long = ...)]`
//! - Feature-gated arguments use `#[cfg(feature = "...")]`
//! - Default values reference constants from [`crate::config::constants`]
//! - Validation logic in [`CliArgs::validate()`] replaces C `die()` error reporting
//!
//! ## CLI Compatibility
//!
//! The Rust binary accepts identical command-line arguments to the C binary.
//! Users need not change their command-line invocations when migrating.

use clap::Parser;

use crate::config::constants::{
    CACHESIZ, CHGRP, CHUSER, EDNS_PKTSZ, FTABSIZ, MAXLEASES, MAX_PROCS, TFTP_MAX_CONNECTIONS,
};
use crate::core::types::DnsmasqError;

// =============================================================================
// Main CLI Argument Structure
// =============================================================================

/// dnsmasq command-line arguments.
///
/// Maps every CLI flag from the C `OPTSTRING` and `opts[]` array in `src/option.c`.
/// Uses clap derive API for automatic argument parsing, replacing C's
/// `getopt_long()` processing.
///
/// # Usage
///
/// ```no_run
/// use clap::Parser;
/// use dnsmasq::config::cli::CliArgs;
///
/// let args = CliArgs::parse();
/// args.validate().expect("CLI validation failed");
/// ```
#[derive(Parser, Debug, Clone)]
#[command(
    name = "dnsmasq",
    version = "2.92",
    about = "A lightweight DHCP and caching DNS server",
    long_about = "Dnsmasq provides DNS forwarding, DHCP, DHCPv6, Router Advertisement, \
                  TFTP, and PXE network boot services with a small footprint. \
                  This is the memory-safe Rust implementation.",
    disable_help_flag = true,
    disable_version_flag = true
)]
pub struct CliArgs {
    // =========================================================================
    // Short Options from OPTSTRING
    // "951yZDNLERKzowefnbvhdkqr:m:p:c:l:s:i:t:u:g:a:x:S:C:A:T:H:Q:I:B:F:G:O:M:X:V:U:j:P:J:W:Y:2:4:6:7:8:0:3:"
    // =========================================================================

    // --- DNS Options ---
    /// Specify local address(es) to listen on.
    ///
    /// Restricts dnsmasq to listening on the specified IP address(es) only.
    /// May be repeated to listen on multiple addresses.
    #[arg(short = 'a', long = "listen-address", num_args = 1.., help_heading = "DNS Options")]
    pub listen_address: Vec<String>,

    /// Return ipaddr for all hosts in specified domains.
    ///
    /// Format: `/<domain>/<ipaddr>` — synthesize A/AAAA records for all names
    /// in the given domain, pointing to the specified IP address.
    #[arg(short = 'A', long = "address", num_args = 1.., help_heading = "DNS Options")]
    pub address: Vec<String>,

    /// Fake reverse lookups for RFC1918 private address ranges.
    ///
    /// All reverse lookups for private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x)
    /// which are not found in `/etc/hosts` or DHCP leases are answered with NXDOMAIN
    /// instead of being forwarded upstream.
    #[arg(short = 'b', long = "bogus-priv", help_heading = "DNS Options")]
    pub bogus_priv: bool,

    /// Treat ipaddr as NXDOMAIN (defeats Verisign wildcard).
    ///
    /// Transform replies which contain the given IP address into NXDOMAIN responses.
    /// Used to defeat ISP DNS hijacking and Verisign Site Finder.
    #[arg(short = 'B', long = "bogus-nxdomain", num_args = 1.., help_heading = "DNS Options")]
    pub bogus_nxdomain: Vec<String>,

    /// Specify the size of the cache in entries (defaults to 150).
    ///
    /// Sets the number of DNS resource records that can be cached.
    /// Setting to 0 disables caching entirely.
    #[arg(short = 'c', long = "cache-size", help_heading = "DNS Options")]
    pub cache_size: Option<u32>,

    /// Specify configuration file (defaults to /etc/dnsmasq.conf).
    ///
    /// Read the specified configuration file. May be given multiple times
    /// to read multiple configuration files.
    #[arg(short = 'C', long = "conf-file", num_args = 1.., help_heading = "Advanced Options")]
    pub conf_file: Vec<String>,

    /// Do NOT fork into the background: run in debug mode.
    ///
    /// Enables debug mode: run in foreground, log to stderr, and do not
    /// write a PID file. Equivalent to `--keep-in-foreground --log-debug`.
    #[arg(short = 'd', long = "no-daemon", help_heading = "Advanced Options")]
    pub no_daemon: bool,

    /// Do NOT forward queries with no domain part.
    ///
    /// Queries for plain names (without any dots or domain parts) are never
    /// forwarded to upstream servers and are answered with NXDOMAIN.
    #[arg(short = 'D', long = "domain-needed", help_heading = "DNS Options")]
    pub domain_needed: bool,

    /// Return self-pointing MX records for local hosts.
    ///
    /// For each machine with an entry in `/etc/hosts`, return an MX record
    /// pointing to the machine itself with preference 0.
    #[arg(short = 'e', long = "selfmx", help_heading = "DNS Options")]
    pub selfmx: bool,

    /// Expand simple names in /etc/hosts with domain-suffix.
    ///
    /// Add the domain suffix configured with `--domain` to simple names
    /// (without a period) found in `/etc/hosts`.
    #[arg(short = 'E', long = "expand-hosts", help_heading = "DNS Options")]
    pub expand_hosts: bool,

    /// Don't forward spurious DNS requests from Windows hosts.
    ///
    /// Filter out DNS queries for Windows-specific names like WPAD and
    /// ISATAP that are unlikely to be resolvable upstream.
    #[arg(short = 'f', long = "filterwin2k", help_heading = "DNS Options")]
    pub filterwin2k: bool,

    /// Change to this group after startup (defaults to dip).
    ///
    /// After binding privileged ports, dnsmasq drops to this group for
    /// privilege separation.
    #[arg(short = 'g', long = "group", help_heading = "Security Options")]
    pub group: Option<String>,

    /// Do NOT load /etc/hosts file.
    ///
    /// Prevents reading the system hosts file at startup and on reload.
    #[arg(short = 'h', long = "no-hosts", help_heading = "DNS Options")]
    pub no_hosts: bool,

    /// Specify a hosts file to be read in addition to /etc/hosts.
    ///
    /// Read the specified file in addition to `/etc/hosts`. May be repeated.
    #[arg(short = 'H', long = "addn-hosts", num_args = 1.., help_heading = "DNS Options")]
    pub addn_hosts: Vec<String>,

    /// Specify interface(s) to listen on.
    ///
    /// Listen only on the specified network interfaces. May be repeated.
    #[arg(short = 'i', long = "interface", num_args = 1.., help_heading = "DNS Options")]
    pub interface: Vec<String>,

    /// Specify interface(s) NOT to listen on.
    ///
    /// Exclude the specified interfaces from listening. May be repeated.
    #[arg(short = 'I', long = "except-interface", num_args = 1.., help_heading = "DNS Options")]
    pub except_interface: Vec<String>,

    /// Map DHCP user class to tag.
    ///
    /// Format: `set:<tag>,<class>` — set the specified tag when a DHCP client
    /// sends the given user class.
    #[arg(short = 'j', long = "dhcp-userclass", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_userclass: Vec<String>,

    /// Don't do DHCP for hosts with tag set.
    ///
    /// Format: `tag:<tag>...` — ignore DHCP requests from hosts matching
    /// the specified tags.
    #[arg(short = 'J', long = "dhcp-ignore", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_ignore: Vec<String>,

    /// Do NOT fork into the background, do NOT run in debug mode.
    ///
    /// Run in foreground but without debug-mode logging. Useful when
    /// managed by systemd or another process supervisor.
    #[arg(
        short = 'k',
        long = "keep-in-foreground",
        help_heading = "Advanced Options"
    )]
    pub keep_in_foreground: bool,

    /// Assume we are the only DHCP server on the local network.
    ///
    /// Enables authoritative DHCP mode, allowing faster lease assignment
    /// by skipping the DISCOVER/OFFER probe cycle.
    #[arg(
        short = 'K',
        long = "dhcp-authoritative",
        help_heading = "DHCP Options"
    )]
    pub dhcp_authoritative: bool,

    /// Specify where to store DHCP leases.
    ///
    /// Path to the DHCP lease persistence file. Defaults to platform-specific
    /// location (e.g., `/var/lib/misc/dnsmasq.leases` on Linux).
    #[arg(short = 'l', long = "dhcp-leasefile", help_heading = "DHCP Options")]
    pub dhcp_leasefile: Option<String>,

    /// Return MX records for local hosts.
    ///
    /// Return an MX record pointing to the host given by `--mx-target` (or
    /// the machine's own hostname) for each local machine.
    #[arg(short = 'L', long = "localmx", help_heading = "DNS Options")]
    pub localmx: bool,

    /// Specify an MX record.
    ///
    /// Format: `<host_name>,<target>,<pref>` — add a custom MX record.
    #[arg(short = 'm', long = "mx-host", num_args = 1.., help_heading = "DNS Options")]
    pub mx_host: Vec<String>,

    /// Specify BOOTP options to DHCP server.
    ///
    /// Format: `<bootp opts>` — set the BOOTP filename, server, and next-server
    /// for network boot.
    #[arg(short = 'M', long = "dhcp-boot", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_boot: Vec<String>,

    /// Do NOT poll resolv.conf file, reload only on SIGHUP.
    ///
    /// Disables automatic detection of changes to `/etc/resolv.conf`.
    /// Changes are only picked up on explicit SIGHUP signal.
    #[arg(short = 'n', long = "no-poll", help_heading = "DNS Options")]
    pub no_poll: bool,

    /// Do NOT cache failed search results.
    ///
    /// Disables negative caching (NXDOMAIN and SERVFAIL responses are not cached).
    #[arg(short = 'N', long = "no-negcache", help_heading = "DNS Options")]
    pub no_negcache: bool,

    /// Use nameservers strictly in the order given in resolv.conf.
    ///
    /// By default dnsmasq sends queries to all upstream servers and uses
    /// the fastest responder. With this option, servers are tried in order.
    #[arg(short = 'o', long = "strict-order", help_heading = "DNS Options")]
    pub strict_order: bool,

    /// Specify options to be sent to DHCP clients.
    ///
    /// Format: `<optspec>` — send the specified DHCP option to clients.
    /// May be repeated for multiple options.
    #[arg(short = 'O', long = "dhcp-option", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_option: Vec<String>,

    /// Specify port to listen for DNS requests on (defaults to 53).
    ///
    /// Setting to 0 disables DNS functionality entirely, leaving only
    /// DHCP and/or TFTP services active.
    #[arg(short = 'p', long = "port", help_heading = "DNS Options")]
    pub port: Option<u16>,

    /// Maximum supported UDP packet size for EDNS.0 (defaults to 1232).
    ///
    /// Sets the maximum UDP payload size advertised to clients via EDNS0.
    /// The DNS Flag Day 2020 recommendation is 1232 bytes.
    #[arg(short = 'P', long = "edns-packet-max", help_heading = "DNS Options")]
    pub edns_packet_max: Option<u16>,

    /// Log DNS queries.
    ///
    /// Log each DNS query received. Optionally specify `extra` for additional
    /// detail including the upstream server used.
    #[arg(short = 'q', long = "log-queries", num_args = 0..=1, default_missing_value = "", help_heading = "Logging Options")]
    pub log_queries: Option<String>,

    /// Force the originating port for upstream DNS queries.
    ///
    /// Normally dnsmasq uses random ports for source port randomization.
    /// This option forces a specific port, which may be required by some firewalls.
    #[arg(short = 'Q', long = "query-port", help_heading = "DNS Options")]
    pub query_port: Option<u16>,

    /// Do NOT read resolv.conf.
    ///
    /// Do not read `/etc/resolv.conf` for upstream DNS server discovery.
    /// Upstream servers must be specified explicitly with `--server`.
    #[arg(short = 'R', long = "no-resolv", help_heading = "DNS Options")]
    pub no_resolv: bool,

    /// Specify path to resolv.conf (defaults to /etc/resolv.conf).
    ///
    /// Read upstream DNS server addresses from the specified file.
    /// May be repeated to read multiple resolv.conf-format files.
    #[arg(short = 'r', long = "resolv-file", num_args = 1.., help_heading = "DNS Options")]
    pub resolv_file: Vec<String>,

    /// Specify the domain to be assigned in DHCP leases.
    ///
    /// Format: `<domain>[,<range>]` — assign the given domain to DHCP clients,
    /// optionally limited to the specified IP address range.
    #[arg(short = 's', long = "domain", num_args = 1.., help_heading = "DHCP Options")]
    pub domain: Vec<String>,

    /// Specify address(es) of upstream servers with optional domains.
    ///
    /// Format: `/<domain>/<ipaddr>` — use the given upstream server for queries
    /// in the specified domain. Without a domain, adds a general upstream server.
    #[arg(short = 'S', long = "server", num_args = 1.., help_heading = "DNS Options")]
    pub server: Vec<String>,

    /// Specify default target in an MX record.
    ///
    /// Set the default target hostname for MX records returned by `--localmx`
    /// and `--selfmx`.
    #[arg(short = 't', long = "mx-target", help_heading = "DNS Options")]
    pub mx_target: Option<String>,

    /// Specify time-to-live in seconds for replies from /etc/hosts.
    ///
    /// Set the TTL value included in DNS responses sourced from `/etc/hosts`
    /// and DHCP lease data.
    #[arg(short = 'T', long = "local-ttl", help_heading = "DNS Options")]
    pub local_ttl: Option<u32>,

    /// Change to this user after startup (defaults to nobody).
    ///
    /// After binding privileged ports (< 1024), dnsmasq drops privileges
    /// to run as this user.
    #[arg(short = 'u', long = "user", help_heading = "Security Options")]
    pub user: Option<String>,

    /// Map DHCP vendor class to tag.
    ///
    /// Format: `set:<tag>,<class>` — set the specified tag when a DHCP client
    /// sends the given vendor class.
    #[arg(short = 'U', long = "dhcp-vendorclass", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_vendorclass: Vec<String>,

    /// Display dnsmasq version and copyright information.
    #[arg(short = 'v', long = "version", help_heading = "Advanced Options")]
    pub version_flag: bool,

    /// Translate IPv4 addresses from upstream servers.
    ///
    /// Format: `<ipaddr>,<ipaddr>,<netmask>` — map addresses in DNS responses
    /// from one range to another, useful for NAT environments.
    #[arg(short = 'V', long = "alias", num_args = 1.., help_heading = "DNS Options")]
    pub alias: Vec<String>,

    /// Display this message. Use --help dhcp or --help dhcp6 for known DHCP options.
    #[arg(short = 'w', long = "help", help_heading = "Advanced Options")]
    pub help_flag: bool,

    /// Specify a SRV record.
    ///
    /// Format: `<name>,<target>,...` — add a DNS SRV resource record.
    #[arg(short = 'W', long = "srv-host", num_args = 1.., help_heading = "DNS Options")]
    pub srv_host: Vec<String>,

    /// Specify path of PID file.
    ///
    /// Write the process ID to this file after forking. Defaults to
    /// platform-specific location (e.g., `/var/run/dnsmasq.pid`).
    #[arg(short = 'x', long = "pid-file", help_heading = "Advanced Options")]
    pub pid_file: Option<String>,

    /// Specify maximum number of DHCP leases (defaults to 1000).
    ///
    /// Limits the total number of active DHCP address leases.
    #[arg(short = 'X', long = "dhcp-lease-max", help_heading = "DHCP Options")]
    pub dhcp_lease_max: Option<u32>,

    /// Answer DNS queries based on the interface a query was sent to.
    ///
    /// If a machine has addresses on multiple subnets, return only
    /// addresses on the subnet from which the query arrived.
    #[arg(short = 'y', long = "localise-queries", help_heading = "DNS Options")]
    pub localise_queries: bool,

    /// Specify TXT DNS record.
    ///
    /// Format: `<name>,<txt>[,<txt>]` — add a DNS TXT resource record.
    #[arg(short = 'Y', long = "txt-record", num_args = 1.., help_heading = "DNS Options")]
    pub txt_record: Vec<String>,

    /// Read DHCP static host information from /etc/ethers.
    ///
    /// Read the `/etc/ethers` file for MAC-to-hostname mappings and create
    /// static DHCP reservations.
    #[arg(short = 'Z', long = "read-ethers", help_heading = "DHCP Options")]
    pub read_ethers: bool,

    /// Bind only to interfaces in use.
    ///
    /// Bind to specific interface addresses rather than wildcard.
    /// Required when running multiple DNS/DHCP daemons on the same machine.
    #[arg(short = 'z', long = "bind-interfaces", help_heading = "DNS Options")]
    pub bind_interfaces: bool,

    // =========================================================================
    // Numeric short options (digits used as short flags in C)
    // =========================================================================
    /// Enable the DBus interface for setting upstream servers, etc.
    ///
    /// Optionally specify a custom bus name (default: `uk.org.thekelleys.dnsmasq`).
    #[cfg(feature = "dbus")]
    #[arg(short = '1', long = "enable-dbus", num_args = 0..=1, default_missing_value = "", help_heading = "Advanced Options")]
    pub enable_dbus: Option<String>,

    /// Provide a default value when dbus feature is disabled.
    #[cfg(not(feature = "dbus"))]
    #[arg(skip)]
    pub enable_dbus: Option<String>,

    /// Do not provide DHCP on this interface, only provide DNS.
    ///
    /// Disable DHCP service on the specified interface while continuing
    /// to provide DNS. May be repeated.
    #[arg(short = '2', long = "no-dhcp-interface", num_args = 1.., help_heading = "DHCP Options")]
    pub no_dhcp_interface: Vec<String>,

    /// Enable dynamic address allocation for bootp.
    ///
    /// Format: `[=tag:<tag>]...` — allow BOOTP clients to receive
    /// dynamically allocated IP addresses.
    #[arg(short = '3', long = "bootp-dynamic", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub bootp_dynamic: Option<String>,

    /// Map MAC address (with wildcards) to option set.
    ///
    /// Format: `set:<tag>,<mac address>` — set the tag when a client with
    /// the matching MAC address is seen.
    #[arg(short = '4', long = "dhcp-mac", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_mac: Vec<String>,

    /// Disable ICMP echo address checking in the DHCP server.
    ///
    /// By default, dnsmasq pings an address before offering it to verify
    /// it is not in use. This disables that check.
    #[arg(short = '5', long = "no-ping", help_heading = "DHCP Options")]
    pub no_ping: bool,

    /// Shell script to run on DHCP lease creation and destruction.
    ///
    /// The script is called with arguments describing the lease event.
    #[arg(short = '6', long = "dhcp-script", help_heading = "DHCP Options")]
    pub dhcp_script: Option<String>,

    /// Read configuration from all the files in this directory.
    ///
    /// Recursively read all configuration files from the specified directory.
    /// May be repeated.
    #[arg(short = '7', long = "conf-dir", num_args = 1.., help_heading = "Advanced Options")]
    pub conf_dir: Vec<String>,

    /// Log to this syslog facility or file (defaults to DAEMON).
    ///
    /// Specify a syslog facility name (e.g., `local0`) or a file path
    /// for log output.
    #[arg(short = '8', long = "log-facility", help_heading = "Logging Options")]
    pub log_facility: Option<String>,

    /// Do not use leasefile.
    ///
    /// Makes the lease database read-only. Useful when the lease file
    /// is on a read-only filesystem.
    #[arg(short = '9', long = "leasefile-ro", help_heading = "DHCP Options")]
    pub leasefile_ro: bool,

    /// Maximum number of concurrent DNS queries (defaults to 150).
    ///
    /// Limits the size of the forward query table.
    #[arg(short = '0', long = "dns-forward-max", help_heading = "DNS Options")]
    pub dns_forward_max: Option<u32>,

    // =========================================================================
    // Long-Only Options (LOPT_* from option.c lines 200-332)
    // Mapped from the opts[] array (lines 340-534)
    // =========================================================================

    // --- DNS Long-Only Options ---
    /// Specify path to file with server= options.
    #[arg(long = "servers-file", help_heading = "DNS Options")]
    pub servers_file: Option<String>,

    /// Accept queries only from directly-connected networks.
    #[arg(long = "local-service", num_args = 0..=1, default_missing_value = "", help_heading = "DNS Options")]
    pub local_service: Option<String>,

    /// Don't include IPv4 addresses in DNS answers.
    #[arg(long = "filter-A", help_heading = "DNS Options")]
    pub filter_a: bool,

    /// Don't include IPv6 addresses in DNS answers.
    #[arg(long = "filter-AAAA", help_heading = "DNS Options")]
    pub filter_aaaa: bool,

    /// Don't include resource records of the given type in DNS answers.
    #[arg(long = "filter-rr", num_args = 1.., help_heading = "DNS Options")]
    pub filter_rr: Vec<String>,

    /// Ignore DNS responses containing ipaddr.
    #[arg(long = "ignore-address", num_args = 1.., help_heading = "DNS Options")]
    pub ignore_address: Vec<String>,

    /// Specify address of upstream servers for reverse address queries.
    ///
    /// Format: `<addr>/<prefix>,<ipaddr>` — direct reverse DNS queries for
    /// the given prefix to the specified upstream server.
    #[arg(long = "rev-server", num_args = 1.., help_heading = "DNS Options")]
    pub rev_server: Vec<String>,

    /// Never forward queries to specified domains.
    ///
    /// Format: `/<domain>/` — queries for names in the specified domain
    /// are never forwarded and always answered locally.
    #[arg(long = "local", num_args = 1.., help_heading = "DNS Options")]
    pub local: Vec<String>,

    /// Specify time-to-live in seconds for negative caching.
    #[arg(long = "neg-ttl", help_heading = "DNS Options")]
    pub neg_ttl: Option<u32>,

    /// Specify time-to-live in seconds for maximum TTL to send to clients.
    #[arg(long = "max-ttl", help_heading = "DNS Options")]
    pub max_ttl: Option<u32>,

    /// Specify time-to-live floor for cache.
    #[arg(long = "min-cache-ttl", help_heading = "DNS Options")]
    pub min_cache_ttl: Option<u32>,

    /// Specify time-to-live ceiling for cache.
    #[arg(long = "max-cache-ttl", help_heading = "DNS Options")]
    pub max_cache_ttl: Option<u32>,

    /// Suppress round-robin ordering of DNS records.
    #[arg(long = "no-round-robin", help_heading = "DNS Options")]
    pub no_round_robin: bool,

    /// Suppress DNS bit 0x20 encoding.
    #[arg(long = "no-0x20-encode", help_heading = "DNS Options")]
    pub no_0x20_encode: bool,

    /// Enable DNS bit 0x20 encoding.
    #[arg(long = "do-0x20-encode", help_heading = "DNS Options")]
    pub do_0x20_encode: bool,

    /// Cache this DNS resource record type.
    #[arg(long = "cache-rr", num_args = 1.., help_heading = "DNS Options")]
    pub cache_rr: Vec<String>,

    /// Read hosts files from a directory.
    #[arg(long = "hostsdir", num_args = 1.., help_heading = "DNS Options")]
    pub hostsdir: Vec<String>,

    /// Give DNS name to IPv4 address of interface.
    ///
    /// Format: `<name>,<interface>` — create an A record mapping the given
    /// name to the IPv4 address of the specified interface.
    #[arg(long = "interface-name", num_args = 1.., help_heading = "DNS Options")]
    pub interface_name: Vec<String>,

    /// Specify PTR DNS record.
    ///
    /// Format: `<name>,<target>` — add a DNS PTR resource record.
    #[arg(long = "ptr-record", num_args = 1.., help_heading = "DNS Options")]
    pub ptr_record: Vec<String>,

    /// Specify NAPTR DNS record.
    ///
    /// Format: `<name>,<naptr>` — add a DNS NAPTR resource record.
    #[arg(long = "naptr-record", num_args = 1.., help_heading = "DNS Options")]
    pub naptr_record: Vec<String>,

    /// Specify certification authority authorization record.
    ///
    /// Format: `<name>,<flags>,<tag>,<value>` — add a DNS CAA record.
    #[arg(long = "caa-record", num_args = 1.., help_heading = "DNS Options")]
    pub caa_record: Vec<String>,

    /// Specify arbitrary DNS resource record.
    ///
    /// Format: `<name>,<RR-number>,[<data>]` — add a custom DNS RR.
    #[arg(long = "dns-rr", num_args = 1.., help_heading = "DNS Options")]
    pub dns_rr: Vec<String>,

    /// Specify alias name for LOCAL DNS name.
    ///
    /// Format: `<alias>,<target>[,<ttl>]` — create a CNAME alias.
    #[arg(long = "cname", num_args = 1.., help_heading = "DNS Options")]
    pub cname: Vec<String>,

    /// Specify host (A/AAAA and PTR) records.
    ///
    /// Format: `<name>,<address>[,<ttl>]` — add host records.
    #[arg(long = "host-record", num_args = 1.., help_heading = "DNS Options")]
    pub host_record: Vec<String>,

    /// Specify host record in interface subnet.
    ///
    /// Format: `<name>,[<IPv4>][,<IPv6>],<interface-name>` — dynamically
    /// create host records based on interface addresses.
    #[arg(long = "dynamic-host", num_args = 1.., help_heading = "DNS Options")]
    pub dynamic_host: Vec<String>,

    /// Specify a domain and address range for synthesised names.
    ///
    /// Format: `<domain>,<range>,[<prefix>]` — generate DNS entries for
    /// addresses in the given range.
    #[arg(long = "synth-domain", num_args = 1.., help_heading = "DNS Options")]
    pub synth_domain: Vec<String>,

    /// Stop DNS rebinding. Filter private IP ranges when resolving.
    ///
    /// Reject upstream DNS answers that contain private IP addresses.
    /// Prevents DNS rebinding attacks.
    #[arg(long = "stop-dns-rebind", help_heading = "Security Options")]
    pub stop_dns_rebind: bool,

    /// Inhibit DNS-rebind protection on this domain.
    ///
    /// Format: `/<domain>/` — allow private IP addresses in answers
    /// for the specified domain even with `--stop-dns-rebind` enabled.
    #[arg(long = "rebind-domain-ok", num_args = 1.., help_heading = "Security Options")]
    pub rebind_domain_ok: Vec<String>,

    /// Allow rebinding of 127.0.0.0/8, for RBL servers.
    #[arg(long = "rebind-localhost-ok", help_heading = "Security Options")]
    pub rebind_localhost_ok: bool,

    /// Always perform DNS queries to all servers.
    ///
    /// Send DNS queries to all configured upstream servers simultaneously,
    /// rather than just the fastest/healthiest.
    #[arg(long = "all-servers", help_heading = "DNS Options")]
    pub all_servers: bool,

    /// Clear DNS cache when reloading resolv.conf.
    #[arg(long = "clear-on-reload", help_heading = "DNS Options")]
    pub clear_on_reload: bool,

    /// Specify lowest port available for DNS query transmission.
    #[arg(long = "min-port", help_heading = "DNS Options")]
    pub min_port: Option<u16>,

    /// Specify highest port available for DNS query transmission.
    #[arg(long = "max-port", help_heading = "DNS Options")]
    pub max_port: Option<u16>,

    /// Set maximum number of random originating ports for a query.
    #[arg(long = "port-limit", help_heading = "DNS Options")]
    pub port_limit: Option<u32>,

    /// Retry DNS queries after this many milliseconds.
    #[arg(long = "fast-dns-retry", num_args = 0..=1, default_missing_value = "", help_heading = "DNS Options")]
    pub fast_dns_retry: Option<String>,

    /// Use expired cache data for faster reply.
    ///
    /// When enabled, serve stale cache entries while refreshing in the background.
    #[arg(long = "use-stale-cache", num_args = 0..=1, default_missing_value = "", help_heading = "DNS Options")]
    pub use_stale_cache: Option<String>,

    /// Do not add CHAOS TXT records.
    ///
    /// Suppress responses to CHAOS TXT queries for version and bind information.
    #[arg(long = "no-ident", help_heading = "DNS Options")]
    pub no_ident: bool,

    /// Detect and remove DNS forwarding loops.
    #[cfg(feature = "loop-detect")]
    #[arg(long = "dns-loop-detect", help_heading = "DNS Options")]
    pub dns_loop_detect: bool,

    #[cfg(not(feature = "loop-detect"))]
    #[arg(skip)]
    pub dns_loop_detect: bool,

    /// Maximum number of concurrent tcp connections.
    #[arg(long = "max-tcp-connections", help_heading = "DNS Options")]
    pub max_tcp_connections: Option<u32>,

    /// Add requestor's MAC address to forwarded DNS queries.
    ///
    /// Format: `[=base64|text]` — optionally specify encoding format.
    #[arg(long = "add-mac", num_args = 0..=1, default_missing_value = "", help_heading = "DNS Options")]
    pub add_mac: Option<String>,

    /// Strip MAC information from queries.
    #[arg(long = "strip-mac", help_heading = "DNS Options")]
    pub strip_mac: bool,

    /// Add specified IP subnet to forwarded DNS queries.
    ///
    /// Format: `<v4 pref>[,<v6 pref>]` — add client subnet option (EDNS0).
    #[arg(long = "add-subnet", num_args = 0..=1, default_missing_value = "", help_heading = "DNS Options")]
    pub add_subnet: Option<String>,

    /// Strip ECS information from queries.
    #[arg(long = "strip-subnet", help_heading = "DNS Options")]
    pub strip_subnet: bool,

    /// Add client identification to forwarded DNS queries.
    #[arg(long = "add-cpe-id", help_heading = "DNS Options")]
    pub add_cpe_id: Option<String>,

    /// Proxy DNSSEC validation results from upstream nameservers.
    #[arg(long = "proxy-dnssec", help_heading = "DNS Options")]
    pub proxy_dnssec: bool,

    /// Send Cisco Umbrella identifiers including remote IP.
    #[arg(long = "umbrella", num_args = 0..=1, default_missing_value = "", help_heading = "DNS Options")]
    pub umbrella: Option<String>,

    /// Don't include resource records of given types in DNS answers.
    #[arg(long = "no-rr", num_args = 1.., help_heading = "DNS Options")]
    pub no_rr: Vec<String>,

    // --- DHCP Long-Only Options ---
    /// Enable DHCP in the range given with lease duration.
    #[arg(short = 'F', long = "dhcp-range", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_range: Vec<String>,

    /// Set address or hostname for a specified machine.
    #[arg(short = 'G', long = "dhcp-host", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_host: Vec<String>,

    /// Read DHCP host specs from file.
    #[arg(long = "dhcp-hostsfile", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_hostsfile: Vec<String>,

    /// Read DHCP option specs from file.
    #[arg(long = "dhcp-optsfile", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_optsfile: Vec<String>,

    /// Read DHCP host specs from a directory.
    #[arg(long = "dhcp-hostsdir", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_hostsdir: Vec<String>,

    /// Read DHCP options from a directory.
    #[arg(long = "dhcp-optsdir", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_optsdir: Vec<String>,

    /// Evaluate conditional tag expression.
    #[arg(long = "tag-if", num_args = 1.., help_heading = "DHCP Options")]
    pub tag_if: Vec<String>,

    /// DHCP option sent even if the client does not request it.
    #[arg(long = "dhcp-option-force", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_option_force: Vec<String>,

    /// DHCP option sent only to PXE clients.
    #[arg(long = "dhcp-option-pxe", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_option_pxe: Vec<String>,

    /// Set tag if client includes matching option in request.
    ///
    /// Format: `set:<tag>,<optspec>` — match DHCP options.
    #[arg(long = "dhcp-match", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_match: Vec<String>,

    /// Set tag if client provides given name.
    ///
    /// Format: `set:<tag>,<string>[*]` — match DHCP hostnames.
    #[arg(long = "dhcp-name-match", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_name_match: Vec<String>,

    /// Force broadcast replies for hosts with tag set.
    #[arg(long = "dhcp-broadcast", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub dhcp_broadcast: Option<String>,

    /// Use alternative ports for DHCP.
    #[arg(long = "dhcp-alternate-port", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub dhcp_alternate_port: Option<String>,

    /// Run lease-change scripts as this user.
    #[arg(long = "dhcp-scriptuser", help_heading = "DHCP Options")]
    pub dhcp_scriptuser: Option<String>,

    /// Use only fully qualified domain names for DHCP clients.
    #[arg(long = "dhcp-fqdn", help_heading = "DHCP Options")]
    pub dhcp_fqdn: bool,

    /// Generate hostnames based on MAC address for nameless clients.
    #[arg(long = "dhcp-generate-names", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub dhcp_generate_names: Option<String>,

    /// Use these DHCP relays as full proxies.
    #[arg(long = "dhcp-proxy", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub dhcp_proxy: Option<String>,

    /// Relay DHCP requests to a remote server.
    ///
    /// Format: `<local-addr>,<server>[,<iface>]`
    #[arg(long = "dhcp-relay", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_relay: Vec<String>,

    /// Relay DHCP requests to a remote server (with interface split).
    ///
    /// Format: `<local-addr>,<server>,<iface>`
    #[arg(long = "dhcp-split-relay", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_split_relay: Vec<String>,

    /// Attempt to allocate sequential IP addresses to DHCP clients.
    #[arg(long = "dhcp-sequential-ip", help_heading = "DHCP Options")]
    pub dhcp_sequential_ip: bool,

    /// Prompt to send to PXE clients.
    ///
    /// Format: `<prompt>,[<timeout>]`
    #[arg(long = "pxe-prompt", num_args = 1.., help_heading = "DHCP Options")]
    pub pxe_prompt: Vec<String>,

    /// Boot service for PXE menu.
    #[arg(long = "pxe-service", num_args = 1.., help_heading = "DHCP Options")]
    pub pxe_service: Vec<String>,

    /// Specify vendor class to match for PXE requests.
    #[arg(long = "dhcp-pxe-vendor", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_pxe_vendor: Vec<String>,

    /// Set TTL in DNS responses with DHCP-derived addresses.
    #[arg(long = "dhcp-ttl", help_heading = "DHCP Options")]
    pub dhcp_ttl: Option<u32>,

    /// Treat DHCP requests on aliases as arriving from interface.
    ///
    /// Format: `<iface>,<alias>..`
    #[arg(long = "bridge-interface", num_args = 1.., help_heading = "DHCP Options")]
    pub bridge_interface: Vec<String>,

    /// Specify extra networks sharing a broadcast domain for DHCP.
    ///
    /// Format: `<iface>|<addr>,<addr>`
    #[arg(long = "shared-network", num_args = 1.., help_heading = "DHCP Options")]
    pub shared_network: Vec<String>,

    /// Ignore hostnames provided by DHCP clients.
    #[arg(long = "dhcp-ignore-names", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub dhcp_ignore_names: Option<String>,

    /// Do NOT reuse filename and server fields for extra DHCP options.
    #[arg(long = "dhcp-no-override", help_heading = "DHCP Options")]
    pub dhcp_no_override: bool,

    /// Allow DHCP clients to do their own DDNS updates.
    #[arg(long = "dhcp-client-update", help_heading = "DHCP Options")]
    pub dhcp_client_update: bool,

    /// Ignore client identifier option sent by DHCP clients.
    #[arg(long = "dhcp-ignore-clid", help_heading = "DHCP Options")]
    pub dhcp_ignore_clid: bool,

    /// Enables DHCPv4 Rapid Commit option.
    #[arg(long = "dhcp-rapid-commit", help_heading = "DHCP Options")]
    pub dhcp_rapid_commit: bool,

    /// Delay DHCP replies for at least number of seconds.
    #[arg(long = "dhcp-reply-delay", help_heading = "DHCP Options")]
    pub dhcp_reply_delay: Option<u32>,

    /// Map RFC3046 circuit-id to tag.
    ///
    /// Format: `set:<tag>,<circuit>`
    #[arg(long = "dhcp-circuitid", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_circuitid: Vec<String>,

    /// Map RFC3046 remote-id to tag.
    ///
    /// Format: `set:<tag>,<remote>`
    #[arg(long = "dhcp-remoteid", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_remoteid: Vec<String>,

    /// Map RFC3993 subscriber-id to tag.
    ///
    /// Format: `set:<tag>,<remote>`
    #[arg(long = "dhcp-subscrid", num_args = 1.., help_heading = "DHCP Options")]
    pub dhcp_subscrid: Vec<String>,

    /// Do not provide DHCPv6 on this interface.
    #[arg(long = "no-dhcpv6-interface", num_args = 1.., help_heading = "DHCP Options")]
    pub no_dhcpv6_interface: Vec<String>,

    /// Do not provide DHCPv4 on this interface.
    #[arg(long = "no-dhcpv4-interface", num_args = 1.., help_heading = "DHCP Options")]
    pub no_dhcpv4_interface: Vec<String>,

    /// Send router-advertisements for interfaces doing DHCPv6.
    #[arg(long = "enable-ra", help_heading = "DHCP Options")]
    pub enable_ra: bool,

    /// Specify DUID_EN-type DHCPv6 server DUID.
    ///
    /// Format: `<enterprise>,<duid>`
    #[arg(long = "dhcp-duid", help_heading = "DHCP Options")]
    pub dhcp_duid: Option<String>,

    /// Set MTU, priority, resend-interval and router-lifetime.
    ///
    /// Format: `<iface>,[mtu:<value>|<interface>|off,][<prio>,]<intval>[,<lifetime>]`
    #[arg(long = "ra-param", num_args = 1.., help_heading = "DHCP Options")]
    pub ra_param: Vec<String>,

    /// Enable RFC 4388 leasequery functions for DHCPv4.
    #[arg(long = "leasequery", num_args = 0..=1, default_missing_value = "", help_heading = "DHCP Options")]
    pub leasequery: Option<String>,

    // --- TFTP Long-Only Options ---
    /// Enable integrated read-only TFTP server.
    ///
    /// Optionally specify interfaces to enable TFTP on.
    #[cfg(feature = "tftp")]
    #[arg(long = "enable-tftp", num_args = 0..=1, default_missing_value = "", help_heading = "TFTP Options")]
    pub enable_tftp: Option<String>,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub enable_tftp: Option<String>,

    /// Export files by TFTP only from the specified subtree.
    ///
    /// Format: `<dir>[,<iface>]`
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-root", num_args = 1.., help_heading = "TFTP Options")]
    pub tftp_root: Vec<String>,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_root: Vec<String>,

    /// Maximum number of concurrent TFTP transfers (defaults to 50).
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-max", help_heading = "TFTP Options")]
    pub tftp_max: Option<u32>,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_max: Option<u32>,

    /// Allow access only to files owned by the user running dnsmasq.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-secure", help_heading = "TFTP Options")]
    pub tftp_secure: bool,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_secure: bool,

    /// Do not terminate the service if TFTP directories are inaccessible.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-no-fail", help_heading = "TFTP Options")]
    pub tftp_no_fail: bool,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_no_fail: bool,

    /// Add client IP or hardware address to tftp-root.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-unique-root", num_args = 0..=1, default_missing_value = "", help_heading = "TFTP Options")]
    pub tftp_unique_root: Option<String>,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_unique_root: Option<String>,

    /// Maximum MTU to use for TFTP transfers.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-mtu", help_heading = "TFTP Options")]
    pub tftp_mtu: Option<u32>,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_mtu: Option<u32>,

    /// Convert TFTP filenames to lowercase.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-lowercase", help_heading = "TFTP Options")]
    pub tftp_lowercase: bool,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_lowercase: bool,

    /// Use only one port for TFTP server.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-single-port", help_heading = "TFTP Options")]
    pub tftp_single_port: bool,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_single_port: bool,

    /// Disable the TFTP blocksize extension.
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-no-blocksize", help_heading = "TFTP Options")]
    pub tftp_no_blocksize: bool,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_no_blocksize: bool,

    /// Ephemeral port range for use by TFTP transfers.
    ///
    /// Format: `<start>,<end>`
    #[cfg(feature = "tftp")]
    #[arg(long = "tftp-port-range", help_heading = "TFTP Options")]
    pub tftp_port_range: Option<String>,

    #[cfg(not(feature = "tftp"))]
    #[arg(skip)]
    pub tftp_port_range: Option<String>,

    // --- DNSSEC Long-Only Options ---
    /// Activate DNSSEC validation.
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec", help_heading = "Security Options")]
    pub dnssec: bool,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub dnssec: bool,

    /// Specify trust anchor key digest.
    ///
    /// Format: `<domain>,[<class>,]...`
    #[cfg(feature = "dnssec")]
    #[arg(long = "trust-anchor", num_args = 1.., help_heading = "Security Options")]
    pub trust_anchor: Vec<String>,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub trust_anchor: Vec<String>,

    /// Disable upstream checking for DNSSEC debugging.
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-debug", help_heading = "Security Options")]
    pub dnssec_debug: bool,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub dnssec_debug: bool,

    /// Ensure answers without DNSSEC are in unsigned zones.
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-check-unsigned", num_args = 0..=1, default_missing_value = "", help_heading = "Security Options")]
    pub dnssec_check_unsigned: Option<String>,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub dnssec_check_unsigned: Option<String>,

    /// Don't check DNSSEC signature timestamps until first cache-reload.
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-no-timecheck", help_heading = "Security Options")]
    pub dnssec_no_timecheck: bool,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub dnssec_no_timecheck: bool,

    /// Timestamp file to verify system clock for DNSSEC.
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-timestamp", help_heading = "Security Options")]
    pub dnssec_timestamp: Option<String>,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub dnssec_timestamp: Option<String>,

    /// Set resource limits for DNSSEC validation.
    #[cfg(feature = "dnssec")]
    #[arg(long = "dnssec-limits", help_heading = "Security Options")]
    pub dnssec_limits: Option<String>,

    #[cfg(not(feature = "dnssec"))]
    #[arg(skip)]
    pub dnssec_limits: Option<String>,

    // --- Authoritative DNS Options ---
    /// Domain to export to global DNS.
    ///
    /// Format: `<domain>,[<subnet>...]`
    #[cfg(feature = "auth")]
    #[arg(long = "auth-zone", num_args = 1.., help_heading = "DNS Options")]
    pub auth_zone: Vec<String>,

    #[cfg(not(feature = "auth"))]
    #[arg(skip)]
    pub auth_zone: Vec<String>,

    /// Export local names to global DNS.
    ///
    /// Format: `<NS>,<interface>`
    #[cfg(feature = "auth")]
    #[arg(long = "auth-server", help_heading = "DNS Options")]
    pub auth_server: Option<String>,

    #[cfg(not(feature = "auth"))]
    #[arg(skip)]
    pub auth_server: Option<String>,

    /// Set TTL for authoritative replies.
    #[cfg(feature = "auth")]
    #[arg(long = "auth-ttl", help_heading = "DNS Options")]
    pub auth_ttl: Option<u32>,

    #[cfg(not(feature = "auth"))]
    #[arg(skip)]
    pub auth_ttl: Option<u32>,

    /// Set authoritative zone information.
    ///
    /// Format: `<serial>[,...]`
    #[cfg(feature = "auth")]
    #[arg(long = "auth-soa", help_heading = "DNS Options")]
    pub auth_soa: Option<String>,

    #[cfg(not(feature = "auth"))]
    #[arg(skip)]
    pub auth_soa: Option<String>,

    /// Secondary authoritative nameservers for forward domains.
    #[cfg(feature = "auth")]
    #[arg(long = "auth-sec-servers", num_args = 1.., help_heading = "DNS Options")]
    pub auth_sec_servers: Vec<String>,

    #[cfg(not(feature = "auth"))]
    #[arg(skip)]
    pub auth_sec_servers: Vec<String>,

    /// Peers which are allowed to do zone transfer.
    #[cfg(feature = "auth")]
    #[arg(long = "auth-peer", num_args = 1.., help_heading = "DNS Options")]
    pub auth_peer: Vec<String>,

    #[cfg(not(feature = "auth"))]
    #[arg(skip)]
    pub auth_peer: Vec<String>,

    // --- Integration Options ---
    /// Enable the UBus interface (OpenWrt).
    #[cfg(feature = "ubus")]
    #[arg(long = "enable-ubus", num_args = 0..=1, default_missing_value = "", help_heading = "Advanced Options")]
    pub enable_ubus: Option<String>,

    #[cfg(not(feature = "ubus"))]
    #[arg(skip)]
    pub enable_ubus: Option<String>,

    /// Specify ipsets to which matching domains should be added.
    ///
    /// Format: `/<domain>[/<domain>...]/<ipset>...`
    #[cfg(feature = "ipset")]
    #[arg(long = "ipset", num_args = 1.., help_heading = "Advanced Options")]
    pub ipset: Vec<String>,

    #[cfg(not(feature = "ipset"))]
    #[arg(skip)]
    pub ipset: Vec<String>,

    /// Specify nftables sets to which matching domains should be added.
    ///
    /// Format: `/<domain>[/<domain>...]/<nftset>...`
    #[cfg(feature = "nftset")]
    #[arg(long = "nftset", num_args = 1.., help_heading = "Advanced Options")]
    pub nftset: Vec<String>,

    #[cfg(not(feature = "nftset"))]
    #[arg(skip)]
    pub nftset: Vec<String>,

    /// Copy connection-track mark from queries to upstream connections.
    #[cfg(feature = "conntrack")]
    #[arg(long = "conntrack", help_heading = "Advanced Options")]
    pub conntrack: bool,

    #[cfg(not(feature = "conntrack"))]
    #[arg(skip)]
    pub conntrack: bool,

    /// Enable filtering of DNS queries with connection-track marks.
    #[cfg(feature = "conntrack")]
    #[arg(long = "connmark-allowlist-enable", num_args = 0..=1, default_missing_value = "", help_heading = "Advanced Options")]
    pub connmark_allowlist_enable: Option<String>,

    #[cfg(not(feature = "conntrack"))]
    #[arg(skip)]
    pub connmark_allowlist_enable: Option<String>,

    /// Set allowed DNS patterns for a connection-track mark.
    #[cfg(feature = "conntrack")]
    #[arg(long = "connmark-allowlist", num_args = 1.., help_heading = "Advanced Options")]
    pub connmark_allowlist: Vec<String>,

    #[cfg(not(feature = "conntrack"))]
    #[arg(skip)]
    pub connmark_allowlist: Vec<String>,

    /// Lua script to run on DHCP lease creation and destruction.
    #[cfg(feature = "luascript")]
    #[arg(long = "dhcp-luascript", help_heading = "DHCP Options")]
    pub dhcp_luascript: Option<String>,

    #[cfg(not(feature = "luascript"))]
    #[arg(skip)]
    pub dhcp_luascript: Option<String>,

    // --- Logging Options ---
    /// Extra logging for DHCP.
    #[arg(long = "log-dhcp", help_heading = "Logging Options")]
    pub log_dhcp: bool,

    /// Enable async. logging; optionally set queue length.
    #[arg(long = "log-async", num_args = 0..=1, default_missing_value = "", help_heading = "Logging Options")]
    pub log_async: Option<String>,

    /// Log debugging information.
    #[arg(long = "log-debug", help_heading = "Logging Options")]
    pub log_debug: bool,

    /// Do not log routine DHCP.
    #[arg(long = "quiet-dhcp", help_heading = "Logging Options")]
    pub quiet_dhcp: bool,

    /// Do not log routine DHCPv6.
    #[arg(long = "quiet-dhcp6", help_heading = "Logging Options")]
    pub quiet_dhcp6: bool,

    /// Do not log RA.
    #[arg(long = "quiet-ra", help_heading = "Logging Options")]
    pub quiet_ra: bool,

    /// Do not log routine TFTP.
    #[arg(long = "quiet-tftp", help_heading = "Logging Options")]
    pub quiet_tftp: bool,

    // --- Diagnostics & Dump Options ---
    /// Path to debug packet dump file.
    #[cfg(feature = "dumpfile")]
    #[arg(long = "dumpfile", help_heading = "Advanced Options")]
    pub dumpfile: Option<String>,

    #[cfg(not(feature = "dumpfile"))]
    #[arg(skip)]
    pub dumpfile: Option<String>,

    /// Mask which packets to dump.
    #[cfg(feature = "dumpfile")]
    #[arg(long = "dumpmask", help_heading = "Advanced Options")]
    pub dumpmask: Option<String>,

    #[cfg(not(feature = "dumpfile"))]
    #[arg(skip)]
    pub dumpmask: Option<String>,

    // --- Security & Privilege Options ---
    /// Bind to interfaces in use - check for new interfaces.
    ///
    /// Like `--bind-interfaces` but also monitors for new interfaces
    /// appearing and binds to them automatically.
    #[arg(long = "bind-dynamic", help_heading = "DNS Options")]
    pub bind_dynamic: bool,

    /// Check configuration syntax.
    ///
    /// Parse configuration files and check for errors without starting
    /// the daemon. Exits with 0 on success, 1 on error.
    #[arg(long = "test", help_heading = "Advanced Options")]
    pub test: bool,

    /// Call dhcp-script with changes to local ARP table.
    #[arg(long = "script-arp", help_heading = "DHCP Options")]
    pub script_arp: bool,

    /// Call dhcp-script when lease expiry changes.
    #[arg(long = "script-on-renewal", help_heading = "DHCP Options")]
    pub script_on_renewal: bool,

    /// Execute file and read configuration from stdin.
    #[arg(long = "conf-script", num_args = 1.., help_heading = "Advanced Options")]
    pub conf_script: Vec<String>,

    /// Configuration option passed as argument.
    #[arg(long = "conf-opt", num_args = 1.., help_heading = "Advanced Options")]
    pub conf_opt: Vec<String>,
}

// =============================================================================
// Validation Implementation
// =============================================================================

impl CliArgs {
    /// Validate CLI arguments for mutual exclusivity, value ranges, and
    /// cross-option consistency.
    ///
    /// Replaces C `option.c` validation logic that used `die()` for error
    /// reporting. Returns `Result<(), DnsmasqError>` for Rust-idiomatic
    /// error propagation via the `?` operator.
    ///
    /// # Validation Rules
    ///
    /// - Port values are within valid range (0–65535)
    /// - Cache size is non-negative (u32 enforced by type)
    /// - `--no-resolv` and `--resolv-file` are mutually exclusive warnings
    /// - EDNS packet max is within safe bounds
    /// - Min/max port ordering is correct
    /// - Feature gate checks for feature-dependent options
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError::Config`] with a descriptive message for any
    /// validation failure.
    pub fn validate(&self) -> Result<(), DnsmasqError> {
        // Validate port range
        if let Some(port) = self.port {
            // port is u16, so 0–65535 is already enforced by the type system.
            // Log a note if port 0 is used (disables DNS).
            let _ = port; // Port 0 is valid (disables DNS)
        }

        // Validate EDNS packet max
        if let Some(edns_max) = self.edns_packet_max {
            if edns_max < 512 {
                return Err(DnsmasqError::Config(format!(
                    "EDNS packet max ({edns_max}) must be at least 512 bytes (RFC 1035 minimum)"
                )));
            }
        }

        // Validate cache size
        // cache_size is Option<u32>, so non-negative is guaranteed by the type.

        // Validate dns-forward-max
        if let Some(fwd_max) = self.dns_forward_max {
            if fwd_max == 0 {
                return Err(DnsmasqError::Config(
                    "dns-forward-max must be greater than 0".to_string(),
                ));
            }
        }

        // Validate max-tcp-connections
        if let Some(max_tcp) = self.max_tcp_connections {
            if max_tcp == 0 {
                return Err(DnsmasqError::Config(
                    "max-tcp-connections must be greater than 0".to_string(),
                ));
            }
        }

        // Validate dhcp-lease-max
        if let Some(lease_max) = self.dhcp_lease_max {
            if lease_max == 0 {
                return Err(DnsmasqError::Config(
                    "dhcp-lease-max must be greater than 0".to_string(),
                ));
            }
        }

        // Validate min-port / max-port ordering
        if let (Some(min_p), Some(max_p)) = (self.min_port, self.max_port) {
            if min_p > max_p {
                return Err(DnsmasqError::Config(format!(
                    "min-port ({min_p}) must not exceed max-port ({max_p})"
                )));
            }
        }

        // Warn about no-resolv + resolv-file combination.
        // C dnsmasq silently accepts this (resolv-file simply has no effect
        // when no-resolv is set). We match C's permissive behavior and log
        // a warning instead of rejecting the combination to maintain
        // drop-in replacement compatibility.
        if self.no_resolv && !self.resolv_file.is_empty() {
            tracing::warn!(
                "--no-resolv and --resolv-file both specified; \
                 --resolv-file will have no effect"
            );
        }

        // Validate conflicting options: no-daemon + keep-in-foreground
        // (Not actually conflicting in C, but warn: both keep in foreground)

        // Warn about large neg-ttl values.
        // Note: C dnsmasq does not enforce an upper bound on neg-ttl;
        // we issue a warning rather than an error to maintain backward
        // compatibility as a drop-in replacement.
        if let Some(neg_ttl) = self.neg_ttl {
            if neg_ttl > 86400 {
                tracing::warn!(
                    neg_ttl,
                    "neg-ttl ({neg_ttl}) exceeds 86400 seconds (1 day); \
                     this may cause stale negative cache entries"
                );
            }
        }

        // Warn about unusually large min-cache-ttl values.
        // C dnsmasq does not enforce an upper bound; we match that behavior
        // and only warn when the value exceeds the recommended floor limit.
        if let Some(min_cttl) = self.min_cache_ttl {
            if min_cttl > crate::config::constants::TTL_FLOOR_LIMIT {
                tracing::warn!(
                    min_cache_ttl = min_cttl,
                    limit = crate::config::constants::TTL_FLOOR_LIMIT,
                    "min-cache-ttl ({min_cttl}) exceeds recommended maximum of {} seconds",
                    crate::config::constants::TTL_FLOOR_LIMIT
                );
            }
        }

        // Validate min-cache-ttl vs max-cache-ttl ordering
        if let (Some(min_cttl), Some(max_cttl)) = (self.min_cache_ttl, self.max_cache_ttl) {
            if min_cttl > max_cttl {
                return Err(DnsmasqError::Config(format!(
                    "min-cache-ttl ({min_cttl}) must not exceed max-cache-ttl ({max_cttl})"
                )));
            }
        }

        // Validate TFTP-max if set
        #[cfg(feature = "tftp")]
        if let Some(tftp_max) = self.tftp_max {
            if tftp_max == 0 {
                return Err(DnsmasqError::Config(
                    "tftp-max must be greater than 0".to_string(),
                ));
            }
        }

        // Validate log-async queue depth
        if let Some(ref async_val) = self.log_async {
            if !async_val.is_empty() {
                if let Ok(depth) = async_val.parse::<u32>() {
                    if depth == 0 {
                        return Err(DnsmasqError::Config(
                            "log-async queue depth must be greater than 0".to_string(),
                        ));
                    }
                }
            }
        }

        // Validate dhcp-reply-delay if set
        if let Some(delay) = self.dhcp_reply_delay {
            if delay > 300 {
                return Err(DnsmasqError::Config(format!(
                    "dhcp-reply-delay ({delay}) exceeds maximum of 300 seconds"
                )));
            }
        }

        // All validations passed
        Ok(())
    }

    /// Returns the effective cache size, applying the default from constants
    /// if not explicitly specified.
    pub fn effective_cache_size(&self) -> u32 {
        self.cache_size.unwrap_or(CACHESIZ)
    }

    /// Returns the effective DNS forward max, applying the default from constants
    /// if not explicitly specified.
    pub fn effective_dns_forward_max(&self) -> u32 {
        self.dns_forward_max.unwrap_or(FTABSIZ)
    }

    /// Returns the effective EDNS packet max, applying the default from constants
    /// if not explicitly specified.
    pub fn effective_edns_packet_max(&self) -> u16 {
        self.edns_packet_max.unwrap_or(EDNS_PKTSZ)
    }

    /// Returns the effective user for privilege separation, applying the default
    /// from constants if not explicitly specified.
    pub fn effective_user(&self) -> &str {
        self.user.as_deref().unwrap_or(CHUSER)
    }

    /// Returns the effective group for privilege separation, applying the default
    /// from constants if not explicitly specified.
    pub fn effective_group(&self) -> &str {
        self.group.as_deref().unwrap_or(CHGRP)
    }

    /// Returns the effective port, defaulting to 53 if not specified.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or(53)
    }

    /// Returns the effective DHCP lease max, applying the default from constants
    /// if not explicitly specified.
    pub fn effective_dhcp_lease_max(&self) -> u32 {
        self.dhcp_lease_max.unwrap_or(MAXLEASES)
    }

    /// Returns the effective max TCP connections, applying the default from
    /// constants if not explicitly specified.
    pub fn effective_max_tcp_connections(&self) -> u32 {
        self.max_tcp_connections.unwrap_or(MAX_PROCS)
    }

    /// Returns the effective TFTP max connections, applying the default from
    /// constants if not explicitly specified.
    pub fn effective_tftp_max(&self) -> u32 {
        #[cfg(feature = "tftp")]
        {
            self.tftp_max.unwrap_or(TFTP_MAX_CONNECTIONS)
        }
        #[cfg(not(feature = "tftp"))]
        {
            TFTP_MAX_CONNECTIONS
        }
    }
}

// =============================================================================
// Unit Tests
// =============================================================================

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

    /// Helper to create a CliArgs with all defaults for testing.
    fn default_args() -> CliArgs {
        CliArgs::try_parse_from(["dnsmasq"]).unwrap()
    }

    #[test]
    fn test_default_parse() {
        let args = default_args();
        assert_eq!(args.port, None);
        assert_eq!(args.cache_size, None);
        assert!(!args.no_daemon);
        assert!(!args.bogus_priv);
        assert!(args.server.is_empty());
        assert!(args.interface.is_empty());
    }

    #[test]
    fn test_effective_defaults() {
        let args = default_args();
        assert_eq!(args.effective_cache_size(), CACHESIZ);
        assert_eq!(args.effective_dns_forward_max(), FTABSIZ);
        assert_eq!(args.effective_edns_packet_max(), EDNS_PKTSZ);
        assert_eq!(args.effective_user(), CHUSER);
        assert_eq!(args.effective_group(), CHGRP);
        assert_eq!(args.effective_port(), 53);
        assert_eq!(args.effective_dhcp_lease_max(), MAXLEASES);
        assert_eq!(args.effective_max_tcp_connections(), MAX_PROCS);
        assert_eq!(args.effective_tftp_max(), TFTP_MAX_CONNECTIONS);
    }

    #[test]
    fn test_validate_success() {
        let args = default_args();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_edns_too_small() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-P", "100"]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("512"));
    }

    #[test]
    fn test_validate_min_max_port_conflict() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--min-port", "2000", "--max-port", "1000"])
            .unwrap();
        let result = args.validate();
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("min-port"));
    }

    #[test]
    fn test_validate_no_resolv_with_resolv_file() {
        // C dnsmasq silently accepts --no-resolv + --resolv-file (resolv-file
        // simply has no effect). Our Rust version matches this permissive
        // behavior — validate() succeeds with a warning instead of an error.
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--no-resolv",
            "--resolv-file",
            "/etc/resolv2.conf",
        ])
        .unwrap();
        let result = args.validate();
        assert!(
            result.is_ok(),
            "validate() should accept --no-resolv + --resolv-file (matching C behavior)"
        );
    }

    #[test]
    fn test_short_flags() {
        let args = CliArgs::try_parse_from([
            "dnsmasq", "-d", "-D", "-E", "-b", "-k", "-n", "-N", "-o", "-R", "-Z", "-z", "-h",
        ])
        .unwrap();
        assert!(args.no_daemon);
        assert!(args.domain_needed);
        assert!(args.expand_hosts);
        assert!(args.bogus_priv);
        assert!(args.keep_in_foreground);
        assert!(args.no_poll);
        assert!(args.no_negcache);
        assert!(args.strict_order);
        assert!(args.no_resolv);
        assert!(args.read_ethers);
        assert!(args.bind_interfaces);
        assert!(args.no_hosts);
    }

    #[test]
    fn test_port_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-p", "5353"]).unwrap();
        assert_eq!(args.port, Some(5353));
        assert_eq!(args.effective_port(), 5353);
    }

    #[test]
    fn test_cache_size_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-c", "1000"]).unwrap();
        assert_eq!(args.cache_size, Some(1000));
        assert_eq!(args.effective_cache_size(), 1000);
    }

    #[test]
    fn test_server_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-S", "8.8.8.8", "-S", "1.1.1.1"]).unwrap();
        assert_eq!(args.server.len(), 2);
    }

    #[test]
    fn test_interface_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-i", "eth0", "-i", "wlan0"]).unwrap();
        assert_eq!(args.interface.len(), 2);
    }

    #[test]
    fn test_long_only_options() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--stop-dns-rebind",
            "--all-servers",
            "--clear-on-reload",
            "--bind-dynamic",
            "--no-ident",
        ])
        .unwrap();
        assert!(args.stop_dns_rebind);
        assert!(args.all_servers);
        assert!(args.clear_on_reload);
        assert!(args.bind_dynamic);
        assert!(args.no_ident);
    }

    #[test]
    fn test_user_group_options() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-u", "dnsmasq", "-g", "nogroup"]).unwrap();
        assert_eq!(args.effective_user(), "dnsmasq");
        assert_eq!(args.effective_group(), "nogroup");
    }

    #[test]
    fn test_validate_min_cache_ttl_limit() {
        // C dnsmasq does not enforce upper bounds on min-cache-ttl.
        // Our Rust version matches this permissive behavior — validate()
        // succeeds with a warning instead of an error for backward compat.
        let args = CliArgs::try_parse_from(["dnsmasq", "--min-cache-ttl", "7200"]).unwrap();
        let result = args.validate();
        assert!(
            result.is_ok(),
            "validate() should accept large min-cache-ttl values (matching C behavior)"
        );
    }

    #[test]
    fn test_validate_dns_forward_max_zero() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dns-forward-max", "0"]).unwrap();
        let result = args.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_test_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--test"]).unwrap();
        assert!(args.test);
    }

    // =========================================================================
    // Additional validation tests
    // =========================================================================

    #[test]
    fn test_validate_max_tcp_connections_zero() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--max-tcp-connections", "0"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_max_tcp_connections_valid() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--max-tcp-connections", "20"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_dhcp_lease_max_zero() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-lease-max", "0"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_dhcp_lease_max_valid() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-lease-max", "500"]).unwrap();
        assert!(args.validate().is_ok());
        assert_eq!(args.effective_dhcp_lease_max(), 500);
    }

    #[test]
    fn test_validate_min_max_port_equal() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--min-port", "1024", "--max-port", "1024"])
            .unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_min_max_port_valid_range() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--min-port", "1024", "--max-port", "65535"])
                .unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_edns_exactly_512() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-P", "512"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_edns_511() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-P", "511"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_edns_large() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-P", "4096"]).unwrap();
        assert!(args.validate().is_ok());
        assert_eq!(args.effective_edns_packet_max(), 4096);
    }

    #[test]
    fn test_validate_min_max_cache_ttl_conflict() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--min-cache-ttl",
            "600",
            "--max-cache-ttl",
            "300",
        ])
        .unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_min_max_cache_ttl_equal() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--min-cache-ttl",
            "300",
            "--max-cache-ttl",
            "300",
        ])
        .unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_min_max_cache_ttl_valid() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--min-cache-ttl",
            "60",
            "--max-cache-ttl",
            "3600",
        ])
        .unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_dhcp_reply_delay_max() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-reply-delay", "301"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_dhcp_reply_delay_boundary() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-reply-delay", "300"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_dhcp_reply_delay_zero() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-reply-delay", "0"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_log_async_zero() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--log-async", "0"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[test]
    fn test_validate_log_async_valid() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--log-async", "25"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_neg_ttl_very_large() {
        // Should still succeed (warning only, matching C behavior)
        let args = CliArgs::try_parse_from(["dnsmasq", "--neg-ttl", "100000"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_validate_neg_ttl_normal() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--neg-ttl", "300"]).unwrap();
        assert!(args.validate().is_ok());
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn test_validate_tftp_max_zero() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--tftp-max", "0"]).unwrap();
        assert!(args.validate().is_err());
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn test_validate_tftp_max_valid() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--tftp-max", "100"]).unwrap();
        assert!(args.validate().is_ok());
        assert_eq!(args.effective_tftp_max(), 100);
    }

    // =========================================================================
    // Effective value tests with explicit values
    // =========================================================================

    #[test]
    fn test_effective_cache_size_explicit() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--cache-size", "5000"]).unwrap();
        assert_eq!(args.effective_cache_size(), 5000);
    }

    #[test]
    fn test_effective_dns_forward_max_explicit() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dns-forward-max", "300"]).unwrap();
        assert_eq!(args.effective_dns_forward_max(), 300);
    }

    #[test]
    fn test_effective_user_explicit() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-u", "nobody"]).unwrap();
        assert_eq!(args.effective_user(), "nobody");
    }

    #[test]
    fn test_effective_group_explicit() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-g", "nogroup"]).unwrap();
        assert_eq!(args.effective_group(), "nogroup");
    }

    #[test]
    fn test_effective_port_zero_disables_dns() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-p", "0"]).unwrap();
        assert_eq!(args.effective_port(), 0);
    }

    #[test]
    fn test_effective_max_tcp_explicit() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--max-tcp-connections", "50"]).unwrap();
        assert_eq!(args.effective_max_tcp_connections(), 50);
    }

    // =========================================================================
    // CLI arg parsing for various options
    // =========================================================================

    #[test]
    fn test_listen_address() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-a", "127.0.0.1", "-a", "::1"]).unwrap();
        assert_eq!(args.listen_address.len(), 2);
        assert_eq!(args.listen_address[0], "127.0.0.1");
        assert_eq!(args.listen_address[1], "::1");
    }

    #[test]
    fn test_address_override() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-A", "/example.com/1.2.3.4"]).unwrap();
        assert_eq!(args.address.len(), 1);
        assert_eq!(args.address[0], "/example.com/1.2.3.4");
    }

    #[test]
    fn test_bogus_nxdomain() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-B", "1.2.3.4"]).unwrap();
        assert_eq!(args.bogus_nxdomain.len(), 1);
    }

    #[test]
    fn test_conf_file() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-C", "/etc/dnsmasq.d/test.conf"]).unwrap();
        assert_eq!(args.conf_file.len(), 1);
    }

    #[test]
    fn test_except_interface() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-I", "lo"]).unwrap();
        assert_eq!(args.except_interface.len(), 1);
    }

    #[test]
    fn test_leasefile() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "-l", "/var/lib/misc/dnsmasq.leases"]).unwrap();
        assert_eq!(
            args.dhcp_leasefile.as_deref(),
            Some("/var/lib/misc/dnsmasq.leases")
        );
    }

    #[test]
    fn test_pid_file() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-x", "/run/dnsmasq.pid"]).unwrap();
        assert_eq!(args.pid_file.as_deref(), Some("/run/dnsmasq.pid"));
    }

    #[test]
    fn test_dhcp_range() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--dhcp-range", "192.168.1.50,192.168.1.150,12h"])
                .unwrap();
        assert_eq!(args.dhcp_range.len(), 1);
    }

    #[test]
    fn test_dhcp_host() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--dhcp-host", "aa:bb:cc:dd:ee:ff,192.168.1.100"])
                .unwrap();
        assert_eq!(args.dhcp_host.len(), 1);
    }

    #[test]
    fn test_multiple_boolean_flags() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--stop-dns-rebind",
            "--rebind-localhost-ok",
            "--all-servers",
            "--clear-on-reload",
            "--no-round-robin",
            "--bind-dynamic",
            "--no-ident",
            "--local-service",
        ])
        .unwrap();
        assert!(args.stop_dns_rebind);
        assert!(args.rebind_localhost_ok);
        assert!(args.all_servers);
        assert!(args.clear_on_reload);
        assert!(args.no_round_robin);
        assert!(args.bind_dynamic);
        assert!(args.no_ident);
    }

    #[test]
    fn test_dhcp_flags() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--dhcp-authoritative",
            "--dhcp-fqdn",
            "--dhcp-sequential-ip",
            "--dhcp-no-override",
            "--dhcp-client-update",
            "--dhcp-ignore-clid",
            "--dhcp-rapid-commit",
            "--no-ping",
        ])
        .unwrap();
        assert!(args.dhcp_authoritative);
        assert!(args.dhcp_fqdn);
        assert!(args.dhcp_sequential_ip);
        assert!(args.dhcp_no_override);
        assert!(args.dhcp_client_update);
        assert!(args.dhcp_ignore_clid);
        assert!(args.dhcp_rapid_commit);
        assert!(args.no_ping);
    }

    #[test]
    fn test_query_port() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-Q", "10053"]).unwrap();
        assert_eq!(args.query_port, Some(10053));
    }

    #[test]
    fn test_local_ttl() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-T", "300"]).unwrap();
        assert_eq!(args.local_ttl, Some(300));
    }

    #[test]
    fn test_max_ttl() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--max-ttl", "3600"]).unwrap();
        assert_eq!(args.max_ttl, Some(3600));
    }

    #[test]
    fn test_log_queries_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--log-queries"]).unwrap();
        // log-queries is an optional value: Some("") when flag set w/o value
        assert!(args.log_queries.is_some());
    }

    #[test]
    fn test_log_dhcp_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--log-dhcp"]).unwrap();
        assert!(args.log_dhcp);
    }

    #[test]
    fn test_log_debug_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--log-debug"]).unwrap();
        assert!(args.log_debug);
    }

    #[test]
    fn test_quiet_flags() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--quiet-dhcp",
            "--quiet-dhcp6",
            "--quiet-ra",
            "--quiet-tftp",
        ])
        .unwrap();
        assert!(args.quiet_dhcp);
        assert!(args.quiet_dhcp6);
        assert!(args.quiet_ra);
        assert!(args.quiet_tftp);
    }

    #[test]
    fn test_filter_flags() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--filter-A", "--filter-AAAA"]).unwrap();
        assert!(args.filter_a);
        assert!(args.filter_aaaa);
    }

    #[test]
    fn test_domain_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-s", "local.lan"]).unwrap();
        assert_eq!(args.domain.len(), 1);
        assert_eq!(args.domain[0], "local.lan");
    }

    #[test]
    fn test_conf_dir() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--conf-dir", "/etc/dnsmasq.d"]).unwrap();
        assert_eq!(args.conf_dir.len(), 1);
    }

    #[test]
    fn test_servers_file() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--servers-file", "/etc/dnsmasq.servers"]).unwrap();
        assert_eq!(args.servers_file.as_deref(), Some("/etc/dnsmasq.servers"));
    }

    #[test]
    fn test_hostsdir() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--hostsdir", "/etc/hosts.d"]).unwrap();
        assert_eq!(args.hostsdir.len(), 1);
    }

    #[test]
    fn test_addn_hosts() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-H", "/etc/hosts.extra"]).unwrap();
        assert_eq!(args.addn_hosts.len(), 1);
    }

    #[test]
    fn test_leasefile_ro() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--leasefile-ro"]).unwrap();
        assert!(args.leasefile_ro);
    }

    #[test]
    fn test_enable_ra() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--enable-ra"]).unwrap();
        assert!(args.enable_ra);
    }

    #[test]
    fn test_selfmx_localmx() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--selfmx", "--localmx"]).unwrap();
        assert!(args.selfmx);
        assert!(args.localmx);
    }

    #[test]
    fn test_mx_host() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-m", "mail.example.com"]).unwrap();
        assert_eq!(args.mx_host.len(), 1);
    }

    #[test]
    fn test_mx_target() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-t", "relay.example.com"]).unwrap();
        assert_eq!(args.mx_target.as_deref(), Some("relay.example.com"));
    }

    #[test]
    fn test_srv_host() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--srv-host",
            "_http._tcp.example.com,server.example.com,80",
        ])
        .unwrap();
        assert_eq!(args.srv_host.len(), 1);
    }

    #[test]
    fn test_txt_record() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--txt-record",
            "example.com,v=spf1 include:_spf.google.com",
        ])
        .unwrap();
        assert_eq!(args.txt_record.len(), 1);
    }

    #[test]
    fn test_cname() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--cname", "alias.example.com,example.com"])
            .unwrap();
        assert_eq!(args.cname.len(), 1);
    }

    #[test]
    fn test_host_record() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--host-record", "server.example.com,10.0.0.1"])
                .unwrap();
        assert_eq!(args.host_record.len(), 1);
    }

    #[test]
    fn test_ptr_record() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--ptr-record",
            "1.0.0.10.in-addr.arpa,server.example.com",
        ])
        .unwrap();
        assert_eq!(args.ptr_record.len(), 1);
    }

    #[test]
    fn test_interface_name() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--interface-name", "hostname,eth0"]).unwrap();
        assert_eq!(args.interface_name.len(), 1);
    }

    #[test]
    fn test_bridge_interface() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--bridge-interface", "br0,eth0,eth1"]).unwrap();
        assert_eq!(args.bridge_interface.len(), 1);
    }

    #[test]
    fn test_rebind_domain_ok() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--stop-dns-rebind",
            "--rebind-domain-ok",
            "/example.com/",
        ])
        .unwrap();
        assert!(args.stop_dns_rebind);
        assert_eq!(args.rebind_domain_ok.len(), 1);
    }

    #[test]
    fn test_alias() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--alias", "1.2.3.0,6.7.8.0,255.255.255.0"])
            .unwrap();
        assert_eq!(args.alias.len(), 1);
    }

    #[test]
    fn test_rev_server() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--rev-server", "192.168.0.0/24,192.168.0.1"])
                .unwrap();
        assert_eq!(args.rev_server.len(), 1);
    }

    #[test]
    fn test_local() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--local", "/localnet/"]).unwrap();
        assert_eq!(args.local.len(), 1);
    }

    #[test]
    fn test_no_dhcp_interface() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--no-dhcp-interface", "eth2"]).unwrap();
        assert_eq!(args.no_dhcp_interface.len(), 1);
    }

    #[test]
    fn test_log_facility() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--log-facility", "/var/log/dnsmasq.log"]).unwrap();
        assert_eq!(args.log_facility.as_deref(), Some("/var/log/dnsmasq.log"));
    }

    #[test]
    fn test_dhcp_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-O", "option:router,192.168.1.1"]).unwrap();
        assert_eq!(args.dhcp_option.len(), 1);
    }

    #[test]
    fn test_dhcp_boot() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--dhcp-boot", "pxelinux.0,server,10.0.0.1"])
                .unwrap();
        assert_eq!(args.dhcp_boot.len(), 1);
    }

    #[test]
    fn test_dhcp_userclass() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-j", "set:windows,MSFT"]).unwrap();
        assert_eq!(args.dhcp_userclass.len(), 1);
    }

    #[test]
    fn test_dhcp_vendorclass() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-U", "set:pxe,PXEClient"]).unwrap();
        assert_eq!(args.dhcp_vendorclass.len(), 1);
    }

    #[test]
    fn test_port_limit() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--port-limit", "10"]).unwrap();
        assert_eq!(args.port_limit, Some(10));
    }

    #[test]
    fn test_dhcp_ttl() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-ttl", "64"]).unwrap();
        assert_eq!(args.dhcp_ttl, Some(64));
    }

    #[test]
    fn test_script_arp() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--script-arp"]).unwrap();
        assert!(args.script_arp);
    }

    #[test]
    fn test_script_on_renewal() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--script-on-renewal"]).unwrap();
        assert!(args.script_on_renewal);
    }

    #[test]
    fn test_strip_mac() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--strip-mac"]).unwrap();
        assert!(args.strip_mac);
    }

    #[test]
    fn test_strip_subnet() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--strip-subnet"]).unwrap();
        assert!(args.strip_subnet);
    }

    #[test]
    fn test_combined_dns_dhcp_options() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--port",
            "5353",
            "--cache-size",
            "500",
            "--dhcp-range",
            "192.168.1.50,192.168.1.100,24h",
            "--dhcp-lease-max",
            "100",
            "--dns-forward-max",
            "200",
            "--domain",
            "test.local",
            "--no-daemon",
            "--log-dhcp",
        ])
        .unwrap();
        assert_eq!(args.effective_port(), 5353);
        assert_eq!(args.effective_cache_size(), 500);
        assert_eq!(args.dhcp_range.len(), 1);
        assert_eq!(args.effective_dhcp_lease_max(), 100);
        assert_eq!(args.effective_dns_forward_max(), 200);
        assert!(args.no_daemon);
        assert!(args.log_dhcp);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_multiple_servers() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "-S",
            "8.8.8.8",
            "-S",
            "8.8.4.4",
            "-S",
            "/google.com/8.8.8.8",
        ])
        .unwrap();
        assert_eq!(args.server.len(), 3);
    }

    #[test]
    fn test_multiple_interfaces() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "-i", "eth0", "-i", "wlan0", "-i", "br0"]).unwrap();
        assert_eq!(args.interface.len(), 3);
    }

    #[test]
    fn test_multiple_dhcp_options() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "-O",
            "option:router,192.168.1.1",
            "-O",
            "option:dns-server,8.8.8.8",
            "-O",
            "option:domain-name,local.lan",
        ])
        .unwrap();
        assert_eq!(args.dhcp_option.len(), 3);
    }

    #[test]
    fn test_version_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-v"]).unwrap();
        assert!(args.version_flag);
    }

    #[test]
    fn test_help_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-w"]).unwrap();
        assert!(args.help_flag);
    }

    #[test]
    fn test_default_args_all_vecs_empty() {
        let args = default_args();
        assert!(args.server.is_empty());
        assert!(args.interface.is_empty());
        assert!(args.listen_address.is_empty());
        assert!(args.address.is_empty());
        assert!(args.bogus_nxdomain.is_empty());
        assert!(args.dhcp_range.is_empty());
        assert!(args.dhcp_host.is_empty());
        assert!(args.dhcp_option.is_empty());
        assert!(args.conf_file.is_empty());
        assert!(args.resolv_file.is_empty());
    }

    #[test]
    fn test_default_args_all_bools_false() {
        let args = default_args();
        assert!(!args.no_daemon);
        assert!(!args.no_resolv);
        assert!(!args.no_hosts);
        assert!(!args.no_poll);
        assert!(!args.no_negcache);
        assert!(!args.no_ping);
        assert!(!args.no_ident);
        assert!(!args.strict_order);
        assert!(!args.all_servers);
        assert!(!args.keep_in_foreground);
        assert!(!args.bind_interfaces);
        assert!(!args.bind_dynamic);
        assert!(!args.bogus_priv);
        assert!(!args.domain_needed);
        assert!(!args.expand_hosts);
        assert!(!args.filterwin2k);
        assert!(!args.read_ethers);
        assert!(!args.localise_queries);
        assert!(!args.test);
        assert!(!args.version_flag);
        assert!(!args.help_flag);
    }

    #[test]
    fn test_default_args_all_options_none() {
        let args = default_args();
        assert!(args.port.is_none());
        assert!(args.cache_size.is_none());
        assert!(args.dns_forward_max.is_none());
        assert!(args.edns_packet_max.is_none());
        assert!(args.user.is_none());
        assert!(args.group.is_none());
        assert!(args.pid_file.is_none());
        assert!(args.dhcp_lease_max.is_none());
        assert!(args.max_tcp_connections.is_none());
        assert!(args.local_ttl.is_none());
        assert!(args.neg_ttl.is_none());
        assert!(args.max_ttl.is_none());
        assert!(args.min_cache_ttl.is_none());
        assert!(args.max_cache_ttl.is_none());
        assert!(args.min_port.is_none());
        assert!(args.max_port.is_none());
        assert!(args.query_port.is_none());
        assert!(args.dhcp_leasefile.is_none());
        assert!(args.mx_target.is_none());
    }

    #[test]
    fn test_validate_all_defaults() {
        let args = default_args();
        assert!(args.validate().is_ok());
        // All effective defaults should match constants
        assert_eq!(args.effective_cache_size(), CACHESIZ);
        assert_eq!(args.effective_dns_forward_max(), FTABSIZ);
        assert_eq!(args.effective_edns_packet_max(), EDNS_PKTSZ);
        assert_eq!(args.effective_user(), CHUSER);
        assert_eq!(args.effective_group(), CHGRP);
        assert_eq!(args.effective_port(), 53);
        assert_eq!(args.effective_dhcp_lease_max(), MAXLEASES);
        assert_eq!(args.effective_max_tcp_connections(), MAX_PROCS);
        assert_eq!(args.effective_tftp_max(), TFTP_MAX_CONNECTIONS);
    }

    #[test]
    fn test_cli_args_clone() {
        let args = CliArgs::try_parse_from(["dnsmasq", "-p", "5353", "--no-daemon"]).unwrap();
        let cloned = args.clone();
        assert_eq!(cloned.port, Some(5353));
        assert!(cloned.no_daemon);
    }

    #[test]
    fn test_cli_args_debug() {
        let args = default_args();
        let debug_str = format!("{:?}", args);
        assert!(debug_str.contains("CliArgs"));
    }

    #[test]
    fn test_dhcp_script() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--dhcp-script", "/usr/local/sbin/dhcp-script"])
                .unwrap();
        assert_eq!(
            args.dhcp_script.as_deref(),
            Some("/usr/local/sbin/dhcp-script")
        );
    }

    #[test]
    fn test_synth_domain() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--synth-domain",
            "thekelleys.org.uk,192.168.0.0/24,internal-",
        ])
        .unwrap();
        assert_eq!(args.synth_domain.len(), 1);
    }

    #[test]
    fn test_dhcp_relay() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--dhcp-relay", "10.0.0.1,10.0.0.2"]).unwrap();
        assert_eq!(args.dhcp_relay.len(), 1);
    }

    #[test]
    fn test_ra_param() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--ra-param", "eth0,60,600"]).unwrap();
        assert_eq!(args.ra_param.len(), 1);
    }

    #[test]
    fn test_shared_network() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--shared-network", "eth0,192.168.0.0/24"])
            .unwrap();
        assert_eq!(args.shared_network.len(), 1);
    }

    #[test]
    fn test_naptr_record() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--naptr-record",
            "example.com,100,10,\"S\",\"SIP+D2U\",\"\",_sip._udp.example.com",
        ])
        .unwrap();
        assert_eq!(args.naptr_record.len(), 1);
    }

    #[test]
    fn test_caa_record() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--caa-record",
            "example.com,0,issue,letsencrypt.org",
        ])
        .unwrap();
        assert_eq!(args.caa_record.len(), 1);
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_dnssec_flags() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--dnssec",
            "--dnssec-debug",
            "--dnssec-no-timecheck",
        ])
        .unwrap();
        assert!(args.dnssec);
        assert!(args.dnssec_debug);
        assert!(args.dnssec_no_timecheck);
    }

    #[cfg(feature = "dnssec")]
    #[test]
    fn test_trust_anchor() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--trust-anchor",
            ".,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        ])
        .unwrap();
        assert_eq!(args.trust_anchor.len(), 1);
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_auth_zone() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--auth-zone", "example.com,eth0"]).unwrap();
        assert_eq!(args.auth_zone.len(), 1);
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_auth_server() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--auth-server", "ns1.example.com,eth0"]).unwrap();
        assert!(args.auth_server.is_some());
    }

    #[cfg(feature = "dbus")]
    #[test]
    fn test_enable_dbus_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--enable-dbus"]).unwrap();
        assert!(args.enable_dbus.is_some());
    }

    #[cfg(feature = "conntrack")]
    #[test]
    fn test_conntrack_flag() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--conntrack"]).unwrap();
        assert!(args.conntrack);
    }

    #[cfg(feature = "ipset")]
    #[test]
    fn test_ipset_option() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--ipset", "/google.com/myset"]).unwrap();
        assert_eq!(args.ipset.len(), 1);
    }

    #[cfg(feature = "nftset")]
    #[test]
    fn test_nftset_option() {
        let args =
            CliArgs::try_parse_from(["dnsmasq", "--nftset", "/google.com/4#ip#table#set"]).unwrap();
        assert_eq!(args.nftset.len(), 1);
    }

    #[cfg(feature = "tftp")]
    #[test]
    fn test_tftp_options() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--enable-tftp",
            "--tftp-root",
            "/srv/tftp",
            "--tftp-secure",
            "--tftp-no-fail",
            "--tftp-lowercase",
            "--tftp-single-port",
            "--tftp-no-blocksize",
        ])
        .unwrap();
        assert!(args.enable_tftp.is_some());
        assert_eq!(args.tftp_root.len(), 1);
        assert!(args.tftp_secure);
        assert!(args.tftp_no_fail);
        assert!(args.tftp_lowercase);
        assert!(args.tftp_single_port);
        assert!(args.tftp_no_blocksize);
    }

    #[cfg(feature = "dumpfile")]
    #[test]
    fn test_dumpfile_option() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--dumpfile",
            "/tmp/dns_dump.pcap",
            "--dumpmask",
            "0x0001",
        ])
        .unwrap();
        assert_eq!(args.dumpfile.as_deref(), Some("/tmp/dns_dump.pcap"));
        assert_eq!(args.dumpmask.as_deref(), Some("0x0001"));
    }

    #[test]
    fn test_ignore_address() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--ignore-address", "1.2.3.4"]).unwrap();
        assert_eq!(args.ignore_address.len(), 1);
    }

    #[test]
    fn test_cache_rr() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--cache-rr", "SRV"]).unwrap();
        assert_eq!(args.cache_rr.len(), 1);
    }

    #[test]
    fn test_tag_if() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--tag-if", "set:lan,tag:known"]).unwrap();
        assert_eq!(args.tag_if.len(), 1);
    }

    #[test]
    fn test_dhcp_match() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--dhcp-match", "set:ipxe,175"]).unwrap();
        assert_eq!(args.dhcp_match.len(), 1);
    }

    #[test]
    fn test_pxe_service() {
        let args = CliArgs::try_parse_from([
            "dnsmasq",
            "--pxe-service",
            "x86PC,\"Install Linux\",pxelinux",
        ])
        .unwrap();
        assert_eq!(args.pxe_service.len(), 1);
    }

    #[test]
    fn test_filter_rr() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--filter-rr", "HTTPS"]).unwrap();
        assert_eq!(args.filter_rr.len(), 1);
    }

    #[test]
    fn test_no_rr() {
        let args = CliArgs::try_parse_from(["dnsmasq", "--no-rr", "HTTPS"]).unwrap();
        assert_eq!(args.no_rr.len(), 1);
    }
}
