// Copyright (c) 2000-2025 Simon Kelley
// SPDX-License-Identifier: GPL-2.0-or-later
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.

//! # Configuration File Backward Compatibility Tests
//!
//! Integration tests verifying 100% backward compatibility with existing
//! `dnsmasq.conf` configuration files. The Rust config parser
//! (`rust/src/config/options.rs`, derived from `src/option.c`) must accept
//! every valid configuration directive from the C version without behavioral
//! changes.
//!
//! Tests use the reference `dnsmasq.conf.example` as the primary compatibility
//! baseline. Every commented-out directive in that file represents a valid
//! configuration option that must be parseable.
//!
//! ## Test Organisation
//!
//! - **Phase 2**: Basic config syntax (empty file, comments, whitespace, blank lines)
//! - **Phase 3**: DNS configuration directives (port, server, cache, domain, etc.)
//! - **Phase 4**: DHCP configuration directives (feature-gated: `dhcp`, `dhcp6`)
//! - **Phase 5**: DNSSEC configuration directives (feature-gated: `dnssec`)
//! - **Phase 6**: Integration and network directives (interface, logging, daemon)
//! - **Phase 7**: Config file include and multi-file tests (`conf-file`, `conf-dir`)
//! - **Phase 8**: Reference configuration file test (all uncommented directives)
//! - **Phase 9**: Default value verification against `src/config.h` constants

use dnsmasq::config::constants;
use dnsmasq::config::options::DnsmasqConfig;
use std::io::Write;

use tempfile::{NamedTempFile, TempDir};

// ============================================================================
// Helper Function
// ============================================================================

/// Parse a configuration string by writing it to a temporary file and
/// calling `DnsmasqConfig::from_file()`.
///
/// This mirrors the dnsmasq pattern of reading configuration from a file.
/// Each test gets its own isolated temp file for clean test isolation.
fn parse_config(content: &str) -> DnsmasqConfig {
    let mut tmp = NamedTempFile::new().expect("failed to create temp config file");
    writeln!(tmp, "{}", content).expect("failed to write config content");
    tmp.flush().expect("failed to flush config file");

    let path = tmp.path().to_str().expect("invalid temp file path");
    DnsmasqConfig::from_file(path).expect("failed to parse config file")
}

// ============================================================================
// Phase 2: Basic Config Syntax Tests
// ============================================================================

#[test]
fn test_empty_config_file() {
    // An empty configuration file should parse without error, using all
    // default values. This matches C dnsmasq behavior where a missing or
    // empty config file simply uses compiled-in defaults.
    let config = parse_config("");
    assert_eq!(config.dns_port, 53);
    assert_eq!(config.cache_size, constants::CACHESIZ);
    assert!(!config.domain_needed);
    assert!(!config.bogus_priv);
    assert!(!config.no_resolv);
}

#[test]
fn test_comment_only_config() {
    // A config file with only comment lines should parse successfully
    // with all default values, matching C behavior where comments are
    // stripped before parsing.
    let config = parse_config(
        "# This is a comment\n\
         # Another comment\n\
         # port=1234\n",
    );
    assert_eq!(config.dns_port, 53);
    assert_eq!(config.cache_size, constants::CACHESIZ);
}

#[test]
fn test_whitespace_handling() {
    // Leading and trailing whitespace on directives should be stripped.
    // This matches C behavior where fgets() + strip_cr() + whitespace
    // skip is performed in read_file()/one_file().
    let config = parse_config("  port=5353  \n");
    assert_eq!(config.dns_port, 5353);
}

#[test]
fn test_blank_lines_ignored() {
    // Blank lines intermixed with directives should be silently ignored.
    let config = parse_config("\n\n\nport=5353\n\n\ncache-size=500\n\n");
    assert_eq!(config.dns_port, 5353);
    assert_eq!(config.cache_size, 500);
}

#[test]
fn test_inline_comments() {
    // Inline comments (# at end of line) are handled by the parser.
    // The C parser strips them, and the Rust parser should too.
    let config = parse_config("port=5353 # custom port\n");
    assert_eq!(config.dns_port, 5353);
}

// ============================================================================
// Phase 3: DNS Configuration Directives
// ============================================================================

#[test]
fn test_port_directive() {
    let config = parse_config("port=5353\n");
    assert_eq!(config.dns_port, 5353);
}

#[test]
fn test_listen_address_directive() {
    let config = parse_config("listen-address=127.0.0.1\n");
    assert_eq!(config.listen_addresses.len(), 1);
    assert_eq!(
        config.listen_addresses[0],
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap()
    );
}

#[test]
fn test_bind_interfaces_directive() {
    let config = parse_config("bind-interfaces\n");
    assert!(config.bind_interfaces);
}

#[test]
fn test_no_resolv_directive() {
    let config = parse_config("no-resolv\n");
    assert!(config.no_resolv);
}

#[test]
fn test_resolv_file_directive() {
    // resolv-file= replaces the default /etc/resolv.conf with a custom path.
    // The C parser clears defaults and replaces with the specified path.
    let config = parse_config("resolv-file=/custom/resolv.conf\n");
    assert!(config
        .resolv_files
        .contains(&"/custom/resolv.conf".to_string()));
}

#[test]
fn test_server_directive_simple() {
    let config = parse_config("server=8.8.8.8\n");
    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.servers[0].address.ip().to_string(), "8.8.8.8");
    assert!(config.servers[0].domain.is_none());
}

#[test]
fn test_server_directive_with_domain() {
    // server=/example.com/8.8.8.8 — domain-specific forwarding.
    let config = parse_config("server=/example.com/8.8.8.8\n");
    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.servers[0].address.ip().to_string(), "8.8.8.8");
    assert_eq!(config.servers[0].domain.as_deref(), Some("example.com"));
}

#[test]
fn test_server_directive_with_port() {
    // server=8.8.8.8#5353 — upstream server with custom port.
    let config = parse_config("server=8.8.8.8#5353\n");
    assert_eq!(config.servers.len(), 1);
    assert_eq!(config.servers[0].address.ip().to_string(), "8.8.8.8");
    assert_eq!(config.servers[0].address.port(), 5353);
}

#[test]
fn test_address_directive() {
    // address=/doubleclick.net/127.0.0.1 — address override for a domain.
    let config = parse_config("address=/doubleclick.net/127.0.0.1\n");
    assert_eq!(config.addresses.len(), 1);
    assert_eq!(config.addresses[0].domain, "doubleclick.net");
    assert_eq!(
        config.addresses[0].address,
        Some("127.0.0.1".parse().unwrap())
    );
}

#[test]
fn test_cache_size_directive() {
    // cache-size=1000 overrides the default CACHESIZ=150.
    let config = parse_config("cache-size=1000\n");
    assert_eq!(config.cache_size, 1000);
}

#[test]
fn test_no_negcache_directive() {
    let config = parse_config("no-negcache\n");
    assert!(config.no_negcache);
}

#[test]
fn test_domain_needed_directive() {
    let config = parse_config("domain-needed\n");
    assert!(config.domain_needed);
}

#[test]
fn test_bogus_priv_directive() {
    let config = parse_config("bogus-priv\n");
    assert!(config.bogus_priv);
}

#[test]
fn test_expand_hosts_directive() {
    let config = parse_config("expand-hosts\n");
    assert!(config.expand_hosts);
}

#[test]
fn test_domain_directive() {
    // domain=thekelleys.org.uk — sets the domain for DHCP clients and
    // expand-hosts. The parser canonicalises the domain (lowercase).
    let config = parse_config("domain=thekelleys.org.uk\n");
    assert!(!config.domains.is_empty());
    assert_eq!(config.domains[0].domain, "thekelleys.org.uk");
}

#[test]
fn test_local_directive() {
    // local=/localnet/ — forces local resolution for a domain (no upstream).
    let config = parse_config("local=/localnet/\n");
    assert!(!config.local_domains.is_empty());
    assert!(config.local_domains.contains(&"localnet".to_string()));
}

#[test]
fn test_host_record_directive() {
    // host-record=myhost.example.com,192.168.1.1 — static A record.
    let config = parse_config("host-record=myhost.example.com,192.168.1.1\n");
    assert_eq!(config.host_records.len(), 1);
    assert_eq!(config.host_records[0].name, "myhost.example.com");
    assert_eq!(
        config.host_records[0].ipv4,
        Some("192.168.1.1".parse().unwrap())
    );
}

#[test]
fn test_txt_record_directive() {
    // txt-record=example.com,"v=spf1 a -all" — TXT record.
    let config = parse_config("txt-record=example.com,\"v=spf1 a -all\"\n");
    assert_eq!(config.txt_records.len(), 1);
    assert_eq!(config.txt_records[0].name, "example.com");
    assert!(!config.txt_records[0].text.is_empty());
}

#[test]
fn test_cname_directive() {
    // cname=alias.example.com,target.example.com — CNAME alias.
    let config = parse_config("cname=alias.example.com,target.example.com\n");
    assert_eq!(config.cnames.len(), 1);
    assert_eq!(config.cnames[0].alias, "alias.example.com");
    assert_eq!(config.cnames[0].target, "target.example.com");
}

// ============================================================================
// Phase 4: DHCP Configuration Directives (Feature-Gated)
// ============================================================================

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_range_directive() {
    // dhcp-range=192.168.0.50,192.168.0.150,12h — basic DHCP range.
    let config = parse_config("dhcp-range=192.168.0.50,192.168.0.150,12h\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert_eq!(dhcp.ranges.len(), 1);
    assert_eq!(dhcp.ranges[0].start, "192.168.0.50");
    assert_eq!(dhcp.ranges[0].end, "192.168.0.150");
    assert_eq!(dhcp.ranges[0].lease_time.as_deref(), Some("12h"));
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_range_with_netmask() {
    // dhcp-range with explicit netmask.
    let config = parse_config("dhcp-range=192.168.0.50,192.168.0.150,255.255.255.0,12h\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert_eq!(dhcp.ranges.len(), 1);
    assert_eq!(dhcp.ranges[0].start, "192.168.0.50");
    assert_eq!(dhcp.ranges[0].end, "192.168.0.150");
    assert_eq!(dhcp.ranges[0].netmask.as_deref(), Some("255.255.255.0"));
    assert_eq!(dhcp.ranges[0].lease_time.as_deref(), Some("12h"));
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_host_directive() {
    // dhcp-host=11:22:33:44:55:66,192.168.0.60 — MAC-to-IP mapping.
    let config = parse_config("dhcp-host=11:22:33:44:55:66,192.168.0.60\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert_eq!(dhcp.hosts.len(), 1);
    assert_eq!(dhcp.hosts[0].mac.as_deref(), Some("11:22:33:44:55:66"));
    assert_eq!(dhcp.hosts[0].ip.as_deref(), Some("192.168.0.60"));
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_host_with_hostname() {
    // dhcp-host=11:22:33:44:55:66,fred,192.168.0.60,45m — full host entry.
    let config = parse_config("dhcp-host=11:22:33:44:55:66,fred,192.168.0.60,45m\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert_eq!(dhcp.hosts.len(), 1);
    assert_eq!(dhcp.hosts[0].mac.as_deref(), Some("11:22:33:44:55:66"));
    assert_eq!(dhcp.hosts[0].hostname.as_deref(), Some("fred"));
    assert_eq!(dhcp.hosts[0].ip.as_deref(), Some("192.168.0.60"));
    assert_eq!(dhcp.hosts[0].lease_time.as_deref(), Some("45m"));
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_option_directive() {
    // dhcp-option=option:router,192.168.1.1 — DHCP option by name.
    let config = parse_config("dhcp-option=option:router,192.168.1.1\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert!(!dhcp.options.is_empty());
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_option_numeric() {
    // dhcp-option=6,192.168.1.1,192.168.1.2 — DHCP option by number (DNS servers).
    let config = parse_config("dhcp-option=6,192.168.1.1,192.168.1.2\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert!(!dhcp.options.is_empty());
    // Option 6 is DNS server
    assert_eq!(dhcp.options[0].option_num, 6);
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_leasefile_directive() {
    // dhcp-leasefile=/var/lib/dnsmasq/leases — lease persistence path.
    let config = parse_config("dhcp-leasefile=/var/lib/dnsmasq/leases\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert_eq!(dhcp.leasefile, "/var/lib/dnsmasq/leases");
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_authoritative_directive() {
    // dhcp-authoritative — boolean, sets authoritative DHCP mode.
    let config = parse_config("dhcp-authoritative\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert!(dhcp.authoritative);
}

#[cfg(feature = "dhcp")]
#[test]
fn test_enable_ra_directive() {
    // enable-ra — enables Router Advertisement (requires dhcp feature as RA
    // depends on the DHCPv6 infrastructure in the C codebase).
    let config = parse_config("enable-ra\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert!(dhcp.enable_ra);
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_range_v6_directive() {
    // DHCPv6 range with constructor syntax.
    // dhcp-range=::,constructor:eth0,ra-names — sets up DHCPv6 with RA on eth0.
    let config = parse_config("dhcp-range=::,constructor:eth0,ra-names\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp config should be present");
    assert!(!dhcp.ranges.is_empty());
    // The start address is "::" (all-zeros IPv6)
    assert_eq!(dhcp.ranges[0].start, "::");
}

// ============================================================================
// Phase 5: DNSSEC Configuration Directives (Feature-Gated)
// ============================================================================

#[cfg(feature = "dnssec")]
#[test]
fn test_dnssec_directive() {
    // dnssec — enables DNSSEC validation.
    let config = parse_config("dnssec\n");
    let dnssec = config
        .dnssec
        .as_ref()
        .expect("dnssec config should be present");
    assert!(dnssec.enabled);
}

#[cfg(feature = "dnssec")]
#[test]
fn test_trust_anchor_directive() {
    // trust-anchor=.,20326,8,2,<hash> — root zone trust anchor.
    let config = parse_config(
        "trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
    );
    let dnssec = config
        .dnssec
        .as_ref()
        .expect("dnssec config should be present");
    assert!(!dnssec.trust_anchors.is_empty());
    assert!(dnssec.trust_anchors[0].starts_with(".,20326,8,2,"));
}

#[cfg(feature = "dnssec")]
#[test]
fn test_dnssec_check_unsigned_directive() {
    // dnssec-check-unsigned — enables checking of unsigned DNSSEC zones.
    let config = parse_config("dnssec-check-unsigned\n");
    let dnssec = config
        .dnssec
        .as_ref()
        .expect("dnssec config should be present");
    assert!(dnssec.check_unsigned);
}

// ============================================================================
// Phase 6: Integration and Network Directives
// ============================================================================

#[test]
fn test_interface_directive() {
    // interface=eth0 — bind to a specific interface.
    let config = parse_config("interface=eth0\n");
    assert_eq!(config.interfaces.len(), 1);
    assert_eq!(config.interfaces[0], "eth0");
}

#[test]
fn test_except_interface_directive() {
    // except-interface=lo — exclude loopback from listening.
    let config = parse_config("except-interface=lo\n");
    assert_eq!(config.except_interfaces.len(), 1);
    assert_eq!(config.except_interfaces[0], "lo");
}

#[test]
fn test_log_queries_directive() {
    // log-queries — enable query logging.
    let config = parse_config("log-queries\n");
    assert!(config.log_queries);
}

#[test]
fn test_log_facility_directive() {
    // log-facility=/var/log/dnsmasq.log — set log output path.
    let config = parse_config("log-facility=/var/log/dnsmasq.log\n");
    assert_eq!(config.log.facility.as_deref(), Some("/var/log/dnsmasq.log"));
}

#[test]
fn test_user_directive() {
    // user=nobody — set privilege drop user.
    let config = parse_config("user=nobody\n");
    assert_eq!(config.user.as_deref(), Some("nobody"));
}

#[test]
fn test_group_directive() {
    // group=nogroup — set privilege drop group.
    let config = parse_config("group=nogroup\n");
    assert_eq!(config.group.as_deref(), Some("nogroup"));
}

#[test]
fn test_pid_file_directive() {
    // pid-file=/var/run/dnsmasq.pid — set PID file location.
    let config = parse_config("pid-file=/var/run/dnsmasq.pid\n");
    assert_eq!(config.pid_file.as_deref(), Some("/var/run/dnsmasq.pid"));
}

// ============================================================================
// Phase 7: Config File Include and Multi-File Tests
// ============================================================================

#[test]
fn test_conf_file_include() {
    // Create a main config file that includes another config file via conf-file=.
    // Verify directives from the included file are applied.
    let included = NamedTempFile::new().expect("failed to create included temp file");
    let included_path = included.path().to_str().unwrap().to_string();
    std::fs::write(included.path(), "port=5454\n").expect("failed to write included config");

    let main_content = format!("conf-file={}\ncache-size=500\n", included_path);
    let config = parse_config(&main_content);

    // The included file's port=5454 should be applied
    assert_eq!(config.dns_port, 5454);
    // The main file's cache-size=500 should also be applied
    assert_eq!(config.cache_size, 500);
}

#[test]
fn test_conf_dir_include() {
    // Create a directory with multiple .conf files, and reference it via conf-dir=.
    let dir = TempDir::new().expect("failed to create temp dir");

    // Create two config files in the directory
    let conf1_path = dir.path().join("01-dns.conf");
    std::fs::write(&conf1_path, "port=6363\n").expect("failed to write conf1");

    let conf2_path = dir.path().join("02-cache.conf");
    std::fs::write(&conf2_path, "cache-size=2000\n").expect("failed to write conf2");

    let main_content = format!("conf-dir={}\n", dir.path().to_str().unwrap());
    let config = parse_config(&main_content);

    // Both included files' directives should be applied
    assert_eq!(config.dns_port, 6363);
    assert_eq!(config.cache_size, 2000);
}

#[test]
fn test_conf_dir_with_filter() {
    // conf-dir=<dir>,*.conf — only include files matching the glob filter.
    let dir = TempDir::new().expect("failed to create temp dir");

    // Create a .conf file (should be included)
    let conf_path = dir.path().join("dns.conf");
    std::fs::write(&conf_path, "port=7474\n").expect("failed to write conf file");

    // Create a .txt file (should NOT be included)
    let txt_path = dir.path().join("notes.txt");
    std::fs::write(&txt_path, "port=9999\n").expect("failed to write txt file");

    let main_content = format!("conf-dir={},*.conf\n", dir.path().to_str().unwrap());
    let config = parse_config(&main_content);

    // Only the .conf file should be processed
    assert_eq!(config.dns_port, 7474);
}

// ============================================================================
// Phase 8: Reference Configuration File Test
// ============================================================================

/// Test that a representative group of DNS directives from the example
/// config all parse correctly together without conflicts.
#[test]
fn test_example_conf_dns_directives() {
    let config = parse_config(
        "\
port=5353\n\
domain-needed\n\
bogus-priv\n\
no-resolv\n\
strict-order\n\
no-poll\n\
server=8.8.8.8\n\
server=8.8.4.4\n\
local=/localnet/\n\
address=/double-click.net/127.0.0.1\n\
cache-size=1000\n\
no-negcache\n\
log-queries\n\
log-async=25\n\
expand-hosts\n\
domain=thekelleys.org.uk\n\
",
    );
    assert_eq!(config.dns_port, 5353);
    assert!(config.domain_needed);
    assert!(config.bogus_priv);
    assert!(config.no_resolv);
    assert!(config.strict_order);
    assert!(config.no_poll);
    assert_eq!(config.servers.len(), 2);
    assert!(!config.local_domains.is_empty());
    assert!(!config.addresses.is_empty());
    assert_eq!(config.cache_size, 1000);
    assert!(config.no_negcache);
    assert!(config.log_queries);
    assert!(config.expand_hosts);
    assert!(!config.domains.is_empty());
}

#[test]
fn test_example_conf_network_directives() {
    let config = parse_config(
        "\
listen-address=127.0.0.1\n\
bind-interfaces\n\
interface=eth0\n\
except-interface=lo\n\
",
    );
    assert_eq!(config.listen_addresses.len(), 1);
    assert!(config.bind_interfaces);
    assert_eq!(config.interfaces[0], "eth0");
    assert_eq!(config.except_interfaces[0], "lo");
}

#[cfg(feature = "dhcp")]
#[test]
fn test_example_conf_dhcp_directives() {
    let config = parse_config(
        "\
dhcp-range=192.168.0.50,192.168.0.150,12h\n\
dhcp-host=11:22:33:44:55:66,192.168.0.60\n\
dhcp-option=option:router,192.168.0.1\n\
dhcp-authoritative\n\
dhcp-leasefile=/var/lib/misc/dnsmasq.leases\n\
",
    );
    let dhcp = config.dhcp.as_ref().expect("dhcp should be present");
    assert!(!dhcp.ranges.is_empty());
    assert!(!dhcp.hosts.is_empty());
    assert!(!dhcp.options.is_empty());
    assert!(dhcp.authoritative);
    assert_eq!(dhcp.leasefile, "/var/lib/misc/dnsmasq.leases");
}

#[test]
fn test_example_conf_daemon_directives() {
    let config = parse_config(
        "\
user=nobody\n\
group=nogroup\n\
pid-file=/var/run/dnsmasq.pid\n\
no-daemon\n\
log-facility=/var/log/dnsmasq.log\n\
",
    );
    assert_eq!(config.user.as_deref(), Some("nobody"));
    assert_eq!(config.group.as_deref(), Some("nogroup"));
    assert_eq!(config.pid_file.as_deref(), Some("/var/run/dnsmasq.pid"));
    assert!(config.no_daemon);
    assert_eq!(config.log.facility.as_deref(), Some("/var/log/dnsmasq.log"));
}

// ============================================================================
// Phase 9: Default Value Verification
// ============================================================================

#[test]
fn test_default_cache_size() {
    // Empty config should use CACHESIZ default (150) from constants.rs,
    // matching C config.h: #define CACHESIZ 150
    let config = parse_config("");
    assert_eq!(config.cache_size, constants::CACHESIZ);
    assert_eq!(config.cache_size, 150);
}

#[test]
fn test_default_port() {
    // Default DNS port is 53, standard DNS port.
    let config = parse_config("");
    assert_eq!(config.dns_port, 53);
}

#[test]
fn test_default_edns_packet_size() {
    // Default EDNS packet size is EDNS_PKTSZ from constants.rs,
    // matching C config.h: #define EDNS_PKTSZ 1232
    let config = parse_config("");
    assert_eq!(config.edns_packet_max, constants::EDNS_PKTSZ);
    assert_eq!(config.edns_packet_max, 1232);
}

// ============================================================================
// Additional Directive Coverage Tests
// ============================================================================

#[test]
fn test_multiple_server_directives() {
    // Multiple server directives accumulate (list semantics).
    let config = parse_config("server=8.8.8.8\nserver=8.8.4.4\nserver=1.1.1.1\n");
    assert_eq!(config.servers.len(), 3);
}

#[test]
fn test_multiple_interface_directives() {
    // Multiple interface directives accumulate.
    let config = parse_config("interface=eth0\ninterface=wlan0\n");
    assert_eq!(config.interfaces.len(), 2);
    assert!(config.interfaces.contains(&"eth0".to_string()));
    assert!(config.interfaces.contains(&"wlan0".to_string()));
}

#[test]
fn test_boolean_defaults_are_false() {
    // Verify all boolean directives default to false.
    let config = parse_config("");
    assert!(!config.domain_needed);
    assert!(!config.bogus_priv);
    assert!(!config.bind_interfaces);
    assert!(!config.bind_dynamic);
    assert!(!config.no_resolv);
    assert!(!config.expand_hosts);
    assert!(!config.log_queries);
    assert!(!config.no_negcache);
    assert!(!config.strict_order);
    assert!(!config.no_poll);
    assert!(!config.no_hosts);
    assert!(!config.filterwin2k);
    assert!(!config.all_servers);
    assert!(!config.localise_queries);
    assert!(!config.no_round_robin);
    assert!(!config.stop_dns_rebind);
    assert!(!config.no_daemon);
    assert!(!config.keep_in_foreground);
    assert!(!config.test_mode);
}

#[test]
fn test_default_user_group() {
    // Default user/group from constants: CHUSER="nobody", CHGRP="dip"
    let config = parse_config("");
    assert_eq!(config.user.as_deref(), Some(constants::CHUSER));
    assert_eq!(config.group.as_deref(), Some(constants::CHGRP));
}

#[test]
fn test_default_pid_file() {
    // Default pid file from constants: RUNFILE="/var/run/dnsmasq.pid"
    let config = parse_config("");
    assert_eq!(config.pid_file.as_deref(), Some(constants::RUNFILE));
}

#[test]
fn test_default_resolv_file() {
    // Default resolv file from constants: RESOLVFILE="/etc/resolv.conf"
    let config = parse_config("");
    assert!(config
        .resolv_files
        .contains(&constants::RESOLVFILE.to_string()));
}

#[test]
fn test_no_hosts_directive() {
    let config = parse_config("no-hosts\n");
    assert!(config.no_hosts);
}

#[test]
fn test_filterwin2k_directive() {
    let config = parse_config("filterwin2k\n");
    assert!(config.filterwin2k);
}

#[test]
fn test_strict_order_directive() {
    let config = parse_config("strict-order\n");
    assert!(config.strict_order);
}

#[test]
fn test_all_servers_directive() {
    let config = parse_config("all-servers\n");
    assert!(config.all_servers);
}

#[test]
fn test_no_daemon_directive() {
    let config = parse_config("no-daemon\n");
    assert!(config.no_daemon);
}

#[test]
fn test_keep_in_foreground_directive() {
    let config = parse_config("keep-in-foreground\n");
    assert!(config.keep_in_foreground);
}

#[test]
fn test_stop_dns_rebind_directive() {
    let config = parse_config("stop-dns-rebind\n");
    assert!(config.stop_dns_rebind);
}

#[test]
fn test_localise_queries_directive() {
    let config = parse_config("localise-queries\n");
    assert!(config.localise_queries);
}

#[test]
fn test_log_dhcp_directive() {
    let config = parse_config("log-dhcp\n");
    assert!(config.log.log_dhcp);
}

#[test]
fn test_log_async_directive() {
    let config = parse_config("log-async=50\n");
    assert_eq!(config.log.log_async, Some(50));
}

#[test]
fn test_log_async_default_value() {
    // log-async without a value defaults to 25.
    let config = parse_config("log-async\n");
    assert_eq!(config.log.log_async, Some(25));
}

#[test]
fn test_addn_hosts_directive() {
    let config = parse_config("addn-hosts=/etc/dnsmasq.hosts\n");
    assert!(config
        .addn_hosts
        .contains(&"/etc/dnsmasq.hosts".to_string()));
}

#[test]
fn test_no_poll_directive() {
    let config = parse_config("no-poll\n");
    assert!(config.no_poll);
}

#[test]
fn test_clear_on_reload_directive() {
    let config = parse_config("clear-on-reload\n");
    assert!(config.clear_on_reload);
}

#[test]
fn test_dns_forward_max_directive() {
    let config = parse_config("dns-forward-max=500\n");
    assert_eq!(config.dns_forward_max, 500);
}

#[test]
fn test_edns_packet_max_directive() {
    let config = parse_config("edns-packet-max=4096\n");
    assert_eq!(config.edns_packet_max, 4096);
}

#[test]
fn test_multiple_addresses_directive() {
    let config = parse_config(
        "address=/ads.example.com/127.0.0.1\n\
         address=/tracker.example.com/127.0.0.1\n",
    );
    assert_eq!(config.addresses.len(), 2);
}

#[test]
fn test_local_service_directive() {
    let config = parse_config("local-service\n");
    assert!(config.local_service);
}

#[test]
fn test_rebind_localhost_ok_directive() {
    let config = parse_config("rebind-localhost-ok\n");
    assert!(config.rebind_localhost_ok);
}

#[test]
fn test_max_ttl_directive() {
    let config = parse_config("max-ttl=3600\n");
    assert_eq!(config.max_ttl, Some(3600));
}

#[test]
fn test_min_cache_ttl_directive() {
    let config = parse_config("min-cache-ttl=300\n");
    assert_eq!(config.min_cache_ttl, Some(300));
}

#[test]
fn test_neg_ttl_directive() {
    let config = parse_config("neg-ttl=300\n");
    assert_eq!(config.neg_ttl, Some(300));
}

#[test]
fn test_local_ttl_directive() {
    let config = parse_config("local-ttl=600\n");
    assert_eq!(config.local_ttl, Some(600));
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_multiple_ranges() {
    // Multiple dhcp-range directives should accumulate.
    let config = parse_config(
        "dhcp-range=192.168.0.50,192.168.0.150,12h\n\
         dhcp-range=10.0.0.50,10.0.0.150,24h\n",
    );
    let dhcp = config.dhcp.as_ref().expect("dhcp should be present");
    assert_eq!(dhcp.ranges.len(), 2);
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_no_ping_directive() {
    let config = parse_config("no-ping\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp should be present");
    assert!(dhcp.no_ping);
}

#[cfg(feature = "dhcp")]
#[test]
fn test_dhcp_rapid_commit_directive() {
    let config = parse_config("dhcp-rapid-commit\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp should be present");
    assert!(dhcp.rapid_commit);
}

#[cfg(feature = "dhcp")]
#[test]
fn test_read_ethers_directive() {
    let config = parse_config("read-ethers\n");
    let dhcp = config.dhcp.as_ref().expect("dhcp should be present");
    assert!(!dhcp.hostfiles.is_empty());
}

#[cfg(feature = "tftp")]
#[test]
fn test_enable_tftp_directive() {
    // enable-tftp — enables the TFTP server for PXE boot support.
    let config = parse_config("enable-tftp\n");
    assert!(config.tftp.is_some());
}

#[cfg(feature = "tftp")]
#[test]
fn test_tftp_root_directive() {
    let config = parse_config("enable-tftp\ntftp-root=/var/lib/tftpboot\n");
    let tftp = config.tftp.as_ref().expect("tftp should be present");
    assert_eq!(tftp.root.as_deref(), Some("/var/lib/tftpboot"));
}

#[cfg(feature = "loop-detect")]
#[test]
fn test_dns_loop_detect_directive() {
    let config = parse_config("dns-loop-detect\n");
    assert!(config.loop_detect);
}

#[test]
fn test_selfmx_directive() {
    let config = parse_config("selfmx\n");
    assert!(config.selfmx);
}

#[test]
fn test_localmx_directive() {
    let config = parse_config("localmx\n");
    assert!(config.localmx);
}

#[test]
fn test_proxy_dnssec_directive() {
    let config = parse_config("proxy-dnssec\n");
    assert!(config.proxy_dnssec);
}

#[test]
fn test_add_mac_directive() {
    let config = parse_config("add-mac\n");
    assert!(config.add_mac);
}

#[test]
fn test_add_subnet_directive() {
    let config = parse_config("add-subnet\n");
    assert!(config.add_subnet.is_some());
}

#[test]
fn test_max_tcp_connections_directive() {
    let config = parse_config("max-tcp-connections=100\n");
    assert_eq!(config.max_tcp_connections, 100);
}

#[test]
fn test_default_forward_max() {
    // dns-forward-max defaults to FTABSIZ (150).
    let config = parse_config("");
    assert_eq!(config.dns_forward_max, constants::FTABSIZ);
}

#[test]
fn test_srv_host_directive() {
    let config = parse_config("srv-host=_http._tcp.example.com,server.example.com,80\n");
    assert_eq!(config.srv_hosts.len(), 1);
    assert_eq!(config.srv_hosts[0].name, "_http._tcp.example.com");
    assert_eq!(config.srv_hosts[0].target, "server.example.com");
    assert_eq!(config.srv_hosts[0].port, 80);
}

#[test]
fn test_ptr_record_directive() {
    let config = parse_config("ptr-record=1.168.192.in-addr.arpa,myhost.example.com\n");
    assert_eq!(config.ptr_records.len(), 1);
    assert_eq!(config.ptr_records[0].name, "1.168.192.in-addr.arpa");
    assert_eq!(
        config.ptr_records[0].target.as_deref(),
        Some("myhost.example.com")
    );
}

#[test]
fn test_mx_host_directive() {
    let config = parse_config("mx-host=example.com,mail.example.com,10\n");
    assert_eq!(config.mx_hosts.len(), 1);
    assert_eq!(config.mx_hosts[0].name, "example.com");
    assert_eq!(config.mx_hosts[0].target, "mail.example.com");
    assert_eq!(config.mx_hosts[0].preference, 10);
}

#[test]
fn test_multiple_cnames_directive() {
    let config = parse_config(
        "cname=alias1.example.com,target.example.com\n\
         cname=alias2.example.com,target.example.com\n",
    );
    assert_eq!(config.cnames.len(), 2);
}

#[test]
fn test_hostsdir_directive() {
    let config = parse_config("hostsdir=/etc/dnsmasq.d/hosts\n");
    assert!(config
        .hosts_dirs
        .contains(&"/etc/dnsmasq.d/hosts".to_string()));
}

#[test]
fn test_query_port_directive() {
    let config = parse_config("query-port=0\n");
    assert_eq!(config.query_port, 0);
}

#[test]
fn test_min_port_directive() {
    let config = parse_config("min-port=4096\n");
    assert_eq!(config.min_port, 4096);
}

#[test]
fn test_max_port_directive() {
    let config = parse_config("max-port=65535\n");
    assert_eq!(config.max_port, 65535);
}
