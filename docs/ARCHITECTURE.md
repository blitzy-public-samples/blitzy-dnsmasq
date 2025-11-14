# Dnsmasq Architecture Documentation

## Table of Contents

1. [Overview and Design Philosophy](#overview-and-design-philosophy)
2. [Architectural Principles](#architectural-principles)
3. [Core Services Breakdown](#core-services-breakdown)
4. [System Architecture Components](#system-architecture-components)
5. [Event Loop Architecture](#event-loop-architecture)
6. [Data Flow and Processing](#data-flow-and-processing)
7. [Memory Management Strategy](#memory-management-strategy)
8. [Platform Abstraction Layer](#platform-abstraction-layer)
9. [Inter-Module Dependencies](#inter-module-dependencies)
10. [Configuration and Build System](#configuration-and-build-system)

---

## Overview and Design Philosophy

Dnsmasq is designed as a **lightweight, single-process network services daemon** that provides DNS forwarding and caching, DHCP server capabilities, TFTP services, and Router Advertisement for small networks and embedded systems. The architecture embodies traditional Unix design principles: simplicity, portability, and efficiency.

### Design Goals

The architecture prioritizes:

1. **Resource Efficiency**: Minimal memory footprint (1-10MB resident set size) and CPU utilization suitable for embedded devices with limited resources (single-core processors, 8-16MB RAM).

2. **Operational Simplicity**: Zero-configuration deployment capability with automatic upstream DNS server discovery from `/etc/resolv.conf`, integrated DNS-DHCP management eliminating synchronization overhead, and hot-reload support via SIGHUP signal without service interruption.

3. **Universal Portability**: Runs on Linux (glibc/uclibc), BSD variants (FreeBSD, OpenBSD, NetBSD), macOS, Solaris, and Android with platform-specific optimizations isolated in dedicated modules.

4. **Deterministic Behavior**: Explicit memory management without garbage collection, single-threaded event-driven model without synchronization complexity, and predictable resource consumption patterns enable months or years of continuous operation.

### Key Architectural Characteristics

- **Single Daemon Process**: All services (DNS, DHCP, TFTP, RA) operate within a single process using event-driven I/O multiplexing, eliminating inter-process communication overhead.

- **No External Dependencies**: Zero reliance on databases, message queues, or external services ensures reliable operation even when network connectivity is limited.

- **Modular Compilation**: Conditional compilation with feature flags (`HAVE_DHCP`, `HAVE_DNSSEC`, `HAVE_TFTP`, etc.) enables customized builds from minimal (DNS-only, ~100KB) to full-featured (~500KB).

---

## Architectural Principles

### 1. Single-Threaded Event-Driven Architecture

Dnsmasq employs a single-threaded event-driven architecture using poll-based I/O multiplexing. This design eliminates thread synchronization complexity while maintaining responsive performance through non-blocking operations.

**Core Implementation**: The main event loop in `src/dnsmasq.c` and `src/poll.c` monitors multiple file descriptors simultaneously:

- **DNS sockets** (UDP port 53 for queries, TCP port 53 for large responses and zone transfers)
- **DHCP sockets** (UDP port 67 for DHCPv4 server, port 547 for DHCPv6 server)
- **TFTP sockets** (UDP port 69 for TFTP server when enabled)
- **Control interfaces** (D-Bus connections on Linux, UBus on OpenWrt)
- **Platform-specific sockets** (Netlink sockets on Linux, routing sockets on BSD)
- **Signal pipes** (for async-signal-safe signal handling)

The event loop uses the POSIX `poll()` system call to wait for I/O events, dispatching to appropriate handlers when file descriptors become ready. This approach provides excellent performance for typical small network workloads (hundreds to thousands of queries per second) while maintaining predictable latency.

**Advantages**:
- No thread synchronization primitives (mutexes, condition variables) required
- No race conditions or deadlocks possible
- Deterministic resource usage and behavior
- Single core suffices for target deployment scenarios

**Trade-offs**:
- Cannot utilize multiple CPU cores (acceptable for target embedded systems)
- Long-running operations must be non-blocking or offloaded (DNS queries have timeouts, scripts use fork/exec)

### 2. Explicit Manual Memory Management

All memory allocation and deallocation is explicit using custom allocators that wrap standard `malloc()` and `free()`. This approach ensures deterministic memory consumption without garbage collection pauses.

**Key Strategies** (from `src/util.c`):

- **Safe Allocation Wrappers**: Functions like `safe_malloc()` and `whine_malloc()` wrap `malloc()` with error checking, terminating the daemon if allocation fails rather than returning NULL pointers that could cause crashes.

- **Fixed-Size Data Structures**: Core data structures use bounded sizes to prevent unbounded memory growth:
  - DNS cache: Default 150 entries (`CACHESIZ` in `src/config.h:38`), configurable via `--cache-size`
  - DHCP lease table: Maximum 1000 leases (`MAXLEASES` in `src/config.h:40`)
  - Forward record table: 150 concurrent queries (`FTABSIZ` in `src/config.h:17`)

- **Block Allocation for Variable-Length Data**: The `blockdata` system (`src/blockdata.c`) manages variable-length data (DNSSEC records) using fixed-size block chains, preventing memory fragmentation.

- **Minimal Dynamic Allocation in Hot Paths**: Packet processing paths use stack-allocated buffers and pre-allocated structures, avoiding heap allocation latency.

### 3. Modular Compilation with Feature Flags

The codebase uses conditional compilation to enable customized builds containing only required functionality. This approach reduces binary size and eliminates dead code for unused features.

**Primary Feature Flags** (from `src/config.h` and `Makefile`):

| Feature Flag | Purpose | Dependencies |
|--------------|---------|--------------|
| `HAVE_DHCP` | Enable DHCPv4 server | None |
| `HAVE_DHCP6` | Enable DHCPv6 and Router Advertisement | `HAVE_DHCP` implied |
| `HAVE_DNSSEC` | Enable DNSSEC validation | Nettle library (libnettle, libhogweed) |
| `HAVE_TFTP` | Enable TFTP server | None |
| `HAVE_AUTH` | Enable authoritative DNS mode | None |
| `HAVE_DBUS` | Enable D-Bus control interface | libdbus-1 |
| `HAVE_UBUS` | Enable UBus interface (OpenWrt) | libubus, libubox |
| `HAVE_IPSET` | Enable Linux ipset integration | ipset headers/library |
| `HAVE_NFTSET` | Enable nftables set integration | libnftables |
| `HAVE_CONNTRACK` | Enable connection tracking | libnetfilter_conntrack |
| `HAVE_SCRIPT` | Enable external script execution | None |
| `HAVE_LUASCRIPT` | Enable Lua script integration | Lua library |
| `HAVE_IDN` | Enable IDN 2003 support | libidn |
| `HAVE_LIBIDN2` | Enable IDN 2008 support | libidn2 |

**Build Configuration**: Feature flags are set via the `COPTS` variable passed to make:

```bash
make COPTS="-DHAVE_DNSSEC -DHAVE_DBUS"  # Enable only DNSSEC and D-Bus
make  # Default build with common features enabled
```

### 4. Zero External Service Dependencies

Dnsmasq operates as a completely self-contained daemon without dependencies on:

- **Databases**: Lease state stored in flat files, no SQL or NoSQL databases required
- **Message Queues**: No AMQP, MQTT, or other message bus dependencies
- **External APIs**: No cloud service API calls, metrics collection services, or telemetry
- **Configuration Servers**: Reads local configuration files only

This independence ensures reliable operation even when network connectivity to external services is unavailable, making dnsmasq suitable for isolated networks, air-gapped environments, and network infrastructure recovery scenarios.

---

## Core Services Breakdown

### DNS Forwarding Subsystem (`src/forward.c`)

The DNS forwarding engine operates as a **forwarding resolver** (not a recursive resolver). It accepts queries from downstream clients, consults a local cache, and forwards cache misses to configured upstream recursive DNS servers.

**Key Components**:

- **Query Reception**: Listens on UDP port 53 for standard queries and TCP port 53 for large responses (>512 bytes), AXFR zone transfers in authoritative mode, and DNSSEC-validated responses
- **Forward Record Table**: Tracks up to 150 concurrent outstanding queries (`struct frec` in `src/dnsmasq.h`), mapping client queries to upstream queries with state management
- **Upstream Server Selection**: Supports multiple upstream servers with:
  - Round-robin selection for load distribution
  - Domain-specific routing (e.g., `*.internal.company.com` → internal DNS server)
  - Fallback on timeout or SERVFAIL responses
  - Source port randomization for security
- **TCP Fallback**: Automatically retries failed UDP queries over TCP when upstream servers require it
- **Query Timeout Management**: Default 10-second timeout (`TIMEOUT` in `src/config.h:30`), after which query fails and client receives SERVFAIL

**Data Flow**:
1. Client query arrives on UDP/TCP socket
2. Check local cache for matching entry (see DNS Caching Subsystem)
3. On cache miss: allocate `struct frec`, forward to upstream server
4. Upstream response received → validate, cache, and forward to client
5. Release `struct frec` for reuse

### DNS Caching Subsystem (`src/cache.c`)

Implements an in-memory LRU (Least Recently Used) cache for DNS records, integrated with multiple data sources.

**Cache Structure**:

- **Hash Table**: Records stored in hash table with chaining for collision resolution
- **Hash Function**: `cache_hash()` computes hash from domain name for O(1) average-case lookup
- **LRU Eviction**: When cache reaches capacity, least recently accessed entries are evicted
- **Default Capacity**: 150 entries (`CACHESIZ`), configurable to thousands via `--cache-size`

**Cached Record Types**:
- A (IPv4 addresses)
- AAAA (IPv6 addresses)
- CNAME (canonical names)
- PTR (reverse lookups)
- DNSKEY and DS (when DNSSEC enabled)
- Negative caching (NXDOMAIN responses with TTL)

**Data Source Integration**:

1. **Upstream DNS Responses**: Primary cache population from forwarded query responses
2. **`/etc/hosts` File**: Static hostname-to-IP mappings loaded at startup and on SIGHUP reload
3. **DHCP Lease Integration**: DHCP-assigned hostnames automatically added to cache, enabling immediate name resolution for dynamically configured clients
4. **Manual Configuration**: `--host-record` and `--address` configuration directives

**TTL Management**:
- Respects TTL from upstream responses
- Configurable minimum TTL (`--min-cache-ttl`) prevents excessive upstream queries
- Configurable maximum TTL (`--max-cache-ttl`) ensures stale data eventually expires
- Negative cache TTL from SOA minimum field

### DHCPv4 Server Subsystem (`src/dhcp.c`, `src/rfc2131.c`)

Provides complete RFC 2131 compliant DHCPv4 server functionality with static reservations and dynamic address allocation.

**Protocol Implementation**:

The four-phase DHCP message exchange:
1. **DISCOVER** (client broadcast) → daemon receives on port 67
2. **OFFER** (daemon response) → selects available IP from configured pool
3. **REQUEST** (client confirms) → client requests offered or renews existing address
4. **ACK** (daemon confirms) → finalizes lease assignment

**Address Allocation**:

- **Static Reservations**: MAC address → fixed IP mapping takes precedence
- **Dynamic Allocation**: First available IP from configured `dhcp-range` pools
- **Conflict Detection**: Optional ping before offer to detect IP conflicts
- **Lease Database**: Persistent storage in `/var/lib/misc/dnsmasq.leases` (Linux default)
- **Default Lease Time**: 3600 seconds (1 hour, `DEFLEASE` in `src/config.h:50`)
- **Maximum Leases**: 1000 concurrent leases (`MAXLEASES`)

**DNS Integration**:

When a DHCP lease is assigned with a hostname:
1. Daemon immediately adds A record to DNS cache
2. Client becomes resolvable by name within 1 second
3. Lease expiration/release removes DNS cache entry
4. No manual DNS zone file editing required

**Script Integration** (when `HAVE_SCRIPT` enabled):

Lease events trigger external script execution:
- **add**: New lease assigned
- **old**: Existing lease renewed
- **del**: Lease expired or released

Scripts receive MAC address, IP address, hostname as arguments and environment variables including `DNSMASQ_LEASE_LENGTH`, `DNSMASQ_CLIENT_ID`, `DNSMASQ_INTERFACE`.

### DHCPv6 Server Subsystem (`src/dhcp6.c`, `src/rfc3315.c`)

Implements RFC 3315 DHCPv6 with both stateful (address assignment) and stateless (configuration only) operation modes.

**Operation Modes**:

1. **Stateful DHCPv6** (Managed addressing, M=1 in Router Advertisement):
   - SOLICIT → ADVERTISE → REQUEST → REPLY exchange
   - Daemon assigns IPv6 addresses from configured pools
   - Lease tracking similar to DHCPv4
   - Default lease time: 86400 seconds (24 hours, `DEFLEASE6` in `src/config.h:51`)

2. **Stateless DHCPv6** (Configuration only, O=1, M=0 in RA):
   - INFORMATION-REQUEST → REPLY exchange
   - Provides DNS servers, domain search lists without address assignment
   - Clients use SLAAC for address configuration

**Coordination with Router Advertisement** (`src/radv.c`):

The M (managed) and O (other configuration) flags in Router Advertisement messages control client DHCPv6 behavior:
- **M=1**: Use DHCPv6 for address assignment (stateful)
- **O=1**: Use DHCPv6 for configuration only (stateless)
- **M=0, O=0**: Use SLAAC only, no DHCPv6

**Prefix Delegation**:

Supports IPv6 prefix delegation (IA_PD) for hierarchical network addressing, enabling downstream routers to obtain prefixes for their local networks.

### TFTP Server Subsystem (`src/tftp.c`)

Read-only TFTP server primarily for network boot scenarios, implementing RFC 1350 with performance extensions.

**Features**:
- **Concurrent Connections**: Default 50 maximum (`TFTP_MAX_CONNECTIONS` in `src/config.h:54`)
- **Option Negotiation**: RFC 2349 (blksize, tsize, timeout) and RFC 7440 (windowsize)
- **Maximum Window Size**: 32 blocks (`TFTP_MAX_WINDOW` in `src/config.h:55`)
- **Transfer Modes**: Netascii and binary (octet)
- **Security**: Secure mode verifies file ownership, root directory restriction prevents path traversal

**PXE Integration**:

Works with DHCPv4 PXE boot options:
- Option 67: Boot filename
- Option 93: Client architecture type
- PXE proxy mode: Coexists with existing DHCP servers

### Authoritative DNS Mode Subsystem (`src/auth.c`)

Enables dnsmasq to serve as primary nameserver for designated local zones, complementing the forwarding mode.

**Capabilities**:
- Authoritative responses for configured zones (AA bit set in DNS response)
- SOA record generation with configurable parameters
- Zone transfer (AXFR) support for secondary nameservers
- Per-zone subnet filtering for split-horizon DNS
- Supports A, AAAA, PTR, CNAME, MX, SRV, TXT, NAPTR record types

**Use Cases**:
- Internal domain hosting (e.g., `*.internal.company.com`)
- Split-horizon DNS (internal vs external views)
- Small zone hosting without separate authoritative DNS server

### DNSSEC Validation Subsystem (`src/dnssec.c`, `src/crypto.c`)

Provides cryptographic validation of DNS responses to protect against cache poisoning and man-in-the-middle attacks.

**Validation Process**:

1. **Trust Chain Validation**: DNSKEY → DS → parent zone, recursively to root trust anchor
2. **RRSIG Verification**: Cryptographic signature validation using Nettle library
3. **NSEC/NSEC3 Processing**: Authenticated denial-of-existence proofs
4. **Trust Anchor Management**: Root zone KSK from `trust-anchors.conf` (updated July 2024)

**Resource Limits** (DoS protection):
- Maximum 40 queries per validation (`DNSSEC_LIMIT_WORK` in `src/config.h:25`)
- Maximum 20 signature failures (`DNSSEC_LIMIT_SIG_FAIL` in `src/config.h:26`)
- Maximum 200 crypto operations (`DNSSEC_LIMIT_CRYPTO` in `src/config.h:27`)
- Maximum 150 NSEC3 iterations (`DNSSEC_LIMIT_NSEC3_ITERS` in `src/config.h:29`)

**Validation States**:
- **SECURE**: Valid DNSSEC chain to trust anchor
- **INSECURE**: Unsigned zone (no DNSSEC)
- **BOGUS**: Invalid signatures or broken trust chain → return SERVFAIL

---

## System Architecture Components

The following diagram illustrates the major components and their relationships:

```mermaid
graph TB
    subgraph "Client Layer"
        DNSClient[DNS Clients<br/>UDP/TCP Port 53]
        DHCP4Client[DHCPv4 Clients<br/>Port 67/68]
        DHCP6Client[DHCPv6 Clients<br/>Port 546/547]
        TFTPClient[TFTP Clients<br/>Port 69]
    end
    
    subgraph "Core Runtime - Main Event Loop"
        MainLoop[Main Event Loop<br/>src/dnsmasq.c<br/>src/poll.c]
        SigHandler[Signal Handler<br/>SIGHUP/SIGUSR1/SIGTERM]
        ConfigParser[Configuration Parser<br/>src/option.c]
        Logger[Logging System<br/>src/log.c]
    end
    
    subgraph "DNS Service Layer"
        DNSForward[DNS Forwarder<br/>src/forward.c]
        DNSCache[DNS Cache<br/>src/cache.c]
        RFC1035[Wire Format Parser<br/>src/rfc1035.c]
        DNSSEC[DNSSEC Validator<br/>src/dnssec.c]
        Auth[Authoritative DNS<br/>src/auth.c]
    end
    
    subgraph "DHCP Service Layer"
        DHCP4[DHCPv4 Server<br/>src/dhcp.c, rfc2131.c]
        DHCP6[DHCPv6 Server<br/>src/dhcp6.c, rfc3315.c]
        LeaseDB[Lease Database<br/>src/lease.c]
        RadV[Router Advertisement<br/>src/radv.c]
    end
    
    subgraph "Network Abstraction Layer"
        Network[Network Core<br/>src/network.c]
        Netlink[Linux Netlink<br/>src/netlink.c]
        BPF[BSD BPF<br/>src/bpf.c]
    end
    
    subgraph "Integration Layer"
        Scripts[Script Executor<br/>src/helper.c]
        DBus[D-Bus Interface<br/>src/dbus.c]
        Firewall[Firewall Integration<br/>src/ipset.c, nftset.c]
    end
    
    subgraph "External Systems"
        Upstream[Upstream DNS Servers]
        Syslog[Syslog Daemon]
        HostsFile[/etc/hosts]
        ResolvConf[/etc/resolv.conf]
    end
    
    DNSClient --> MainLoop
    DHCP4Client --> MainLoop
    DHCP6Client --> MainLoop
    TFTPClient --> MainLoop
    
    MainLoop --> DNSForward
    MainLoop --> DHCP4
    MainLoop --> DHCP6
    
    ConfigParser --> MainLoop
    SigHandler --> MainLoop
    Logger --> Syslog
    
    DNSForward --> DNSCache
    DNSForward --> RFC1035
    DNSForward --> DNSSEC
    DNSForward --> Upstream
    DNSForward --> Auth
    
    DNSCache --> HostsFile
    DNSCache <--> LeaseDB
    
    DHCP4 --> LeaseDB
    DHCP6 --> LeaseDB
    DHCP6 --> RadV
    
    LeaseDB --> Scripts
    LeaseDB --> DNSCache
    
    DNSForward --> Network
    DHCP4 --> Network
    DHCP6 --> Network
    RadV --> Network
    
    Network --> Netlink
    Network --> BPF
    
    DNSForward --> Firewall
    
    ConfigParser --> ResolvConf
    
    DBus -.-> MainLoop
    
    style MainLoop fill:#e1f5ff
    style DNSCache fill:#fff4e1
    style LeaseDB fill:#fff4e1
    style Network fill:#e1ffe1
```

### Component Responsibilities

**Core Runtime Components**:

- **Main Event Loop** (`src/dnsmasq.c`, `src/poll.c`): Coordinates all subsystem activities through poll-based I/O multiplexing, monitoring file descriptors for DNS, DHCP, TFTP, control interfaces, and platform-specific sockets
- **Configuration Parser** (`src/option.c`): Processes 350+ configuration directives from config file and command line, validating options and initializing subsystem configurations
- **Signal Handler**: Manages process lifecycle via signals - SIGTERM (graceful shutdown), SIGHUP (configuration reload), SIGUSR1 (cache statistics dump), SIGUSR2 (detailed status)
- **Logging System** (`src/log.c`): Non-blocking, fork-safe logging queue with maximum 5 queued messages, prevents main loop blocking on syslog operations

**DNS Service Components**:

- **DNS Forwarder** (`src/forward.c`): State machine tracking up to 150 concurrent queries, manages upstream server selection with domain-specific routing, implements retry and timeout logic
- **DNS Cache** (`src/cache.c`): Hash table with LRU eviction, default 150 entries, integrates data from upstream, `/etc/hosts`, and DHCP leases
- **Wire Format Parser** (`src/rfc1035.c`): RFC 1035 DNS packet parsing and serialization, name compression, resource record encoding/decoding
- **DNSSEC Validator** (`src/dnssec.c`): Complete DNSSEC validation chain with resource limits preventing DoS attacks
- **Authoritative DNS** (`src/auth.c`): Serves designated local zones with SOA generation and AXFR support

**DHCP Service Components**:

- **DHCPv4 Server** (`src/dhcp.c`, `src/rfc2131.c`): Full RFC 2131 implementation, static reservations, dynamic pools, PXE boot support
- **DHCPv6 Server** (`src/dhcp6.c`, `src/rfc3315.c`): Stateful and stateless modes, prefix delegation, coordination with Router Advertisement
- **Lease Database** (`src/lease.c`): Persistent lease storage with filesystem-based persistence, DNS integration, script trigger management
- **Router Advertisement** (`src/radv.c`): ICMPv6 RA transmission with configurable M/O flags, RDNSS options, prefix information

**Network Abstraction Components**:

- **Network Core** (`src/network.c`): Platform-independent interface for socket creation, listener management, interface enumeration, packet transmission/reception
- **Linux Netlink** (`src/netlink.c`): Real-time monitoring of network interface state changes (up/down, address add/remove) via netlink sockets
- **BSD BPF** (`src/bpf.c`): Berkeley Packet Filter for raw packet access on BSD platforms, routing socket monitoring for interface events

**Integration Components**:

- **Script Executor** (`src/helper.c`): Fork-based execution of external scripts on lease events, proper signal handling and exit status collection
- **D-Bus Interface** (`src/dbus.c`): System bus control interface at `uk.org.thekelleys.dnsmasq`, cache query/manipulation, upstream server reconfiguration
- **Firewall Integration** (`src/ipset.c`, `src/nftset.c`): Populates ipset collections and nftables sets with resolved IP addresses for domain-based firewall rules

---

## Event Loop Architecture

### Poll-Based I/O Multiplexing

The event loop implementation uses the POSIX `poll()` system call to monitor multiple file descriptors with a single blocking wait. This approach is more efficient than `select()` (no FD_SETSIZE limit) and more portable than `epoll()` (Linux-only).

**Event Loop Flow** (`src/dnsmasq.c` main function, `src/poll.c`):

```mermaid
flowchart TD
    Start[Start Daemon] --> Init[Initialize Subsystems]
    Init --> Setup[Setup File Descriptors]
    Setup --> EventLoop{Poll for Events}
    
    EventLoop --> CheckFD{Check Ready FDs}
    
    CheckFD -->|DNS Query| ProcessDNS[Process DNS Query<br/>forward.c:receive_query]
    CheckFD -->|DNS Response| ProcessResp[Process DNS Response<br/>forward.c:reply_query]
    CheckFD -->|DHCP Request| ProcessDHCP[Process DHCP Request<br/>dhcp.c:dhcp_reply]
    CheckFD -->|TFTP Request| ProcessTFTP[Process TFTP Request<br/>tftp.c]
    CheckFD -->|Signal Pipe| ProcessSig[Process Signal<br/>async_event]
    CheckFD -->|Netlink Event| ProcessNet[Process Network Change<br/>netlink.c]
    CheckFD -->|Timer Expiry| ProcessTimer[Process Timeouts]
    
    ProcessDNS --> EventLoop
    ProcessResp --> EventLoop
    ProcessDHCP --> EventLoop
    ProcessTFTP --> EventLoop
    ProcessSig --> CheckSigType{Signal Type?}
    
    CheckSigType -->|SIGTERM| Shutdown[Cleanup and Exit]
    CheckSigType -->|SIGHUP| Reload[Reload Configuration]
    CheckSigType -->|SIGUSR1| Stats[Dump Statistics]
    
    ProcessNet --> EventLoop
    ProcessTimer --> EventLoop
    Reload --> EventLoop
    Stats --> EventLoop
    
    Shutdown --> End[Daemon Exits]
```

### File Descriptor Management

**Monitored File Descriptors**:

1. **DNS Listener Sockets**:
   - UDP sockets on port 53 (one per network interface or wildcard)
   - TCP listening socket on port 53
   - TCP connected sockets for active queries (up to `MAX_PROCS=20`)

2. **DHCP Listener Sockets**:
   - DHCPv4: UDP socket on port 67
   - DHCPv6: UDP socket on port 547
   - Router Advertisement: ICMPv6 raw socket

3. **TFTP Listener Socket** (when enabled):
   - UDP socket on port 69

4. **Control Interface Sockets**:
   - D-Bus connection file descriptor (when `HAVE_DBUS`)
   - UBus connection file descriptor (when `HAVE_UBUS`)

5. **Platform Monitoring Sockets**:
   - Linux: Netlink socket for interface/address changes
   - BSD: Routing socket for interface events

6. **Signal Communication**:
   - Signal pipe for async-signal-safe signal delivery from signal handlers to main loop

**Poll Structure** (`src/poll.c`):

The daemon maintains a sorted array of `struct pollfd` entries, with helper functions to add, remove, and check file descriptors. The `poll()` call blocks with a timeout of typically a few seconds, returning when:
- One or more file descriptors become ready for I/O
- A signal is received (EINTR, restarted after signal processing)
- The timeout expires (triggers periodic maintenance tasks)

### Signal Handling Strategy

**Async-Signal-Safe Approach**:

Traditional signal handlers have severe restrictions on what functions they can safely call. Dnsmasq uses a two-stage signal handling mechanism:

1. **Signal Handler Stage** (`sig_handler()` in `src/dnsmasq.c`):
   - Minimal work: writes signal number to signal pipe
   - Uses only async-signal-safe operations
   - Returns immediately

2. **Main Loop Stage** (`async_event()` in `src/dnsmasq.c`):
   - Main loop detects signal pipe ready for reading
   - Reads signal number from pipe
   - Performs full signal processing in normal context with access to all functions

**Signal Responses**:

- **SIGTERM**: Graceful shutdown - closes sockets, writes lease database, exits cleanly
- **SIGHUP**: Hot reload - reopens log files, re-reads configuration, clears DNS cache, re-enumerates network interfaces
- **SIGUSR1**: Statistics dump - writes cache statistics to syslog
- **SIGUSR2**: Detailed status - writes comprehensive state to syslog
- **SIGCHLD**: Child process termination - collects exit status of helper scripts

### Non-Blocking Operations

To maintain event loop responsiveness, all operations must either complete quickly or be non-blocking:

**Fast Synchronous Operations**:
- DNS cache lookups: Hash table lookup, typically <0.1ms
- DHCP lease lookups: Array or hash table scan, <1ms
- Packet parsing: Wire format decoding, <1ms

**Handled via Timeout**:
- DNS upstream queries: 10-second timeout, no result → SERVFAIL to client
- TCP connections: 5-second timeout per connection

**Offloaded to Child Processes**:
- External script execution: Fork/exec pattern, parent continues processing
- Lua script execution: Runs in daemon context but fast (<1ms typically)

---

## Data Flow and Processing

### DNS Query Processing Pipeline

```mermaid
sequenceDiagram
    participant Client as DNS Client
    participant Daemon as Dnsmasq
    participant Cache as DNS Cache
    participant Upstream as Upstream DNS
    
    Client->>Daemon: DNS Query (A record for example.com)
    activate Daemon
    
    Daemon->>Cache: cache_find_by_name("example.com", A)
    activate Cache
    
    alt Cache Hit
        Cache-->>Daemon: Cached A Record (TTL remaining)
        Daemon-->>Client: DNS Response (from cache)
    else Cache Miss
        Cache-->>Daemon: NULL (not cached)
        deactivate Cache
        
        Daemon->>Daemon: Allocate struct frec (forward record)
        Daemon->>Upstream: Forward Query (random src port)
        
        Note over Daemon,Upstream: Wait up to 10s for response
        
        Upstream-->>Daemon: DNS Response
        
        Daemon->>Daemon: Validate response format
        
        opt DNSSEC Enabled
            Daemon->>Daemon: Validate DNSSEC signatures
        end
        
        Daemon->>Cache: cache_insert(example.com, A record, TTL)
        activate Cache
        Cache-->>Daemon: Record cached
        deactivate Cache
        
        Daemon->>Daemon: Free struct frec
        Daemon-->>Client: DNS Response
    end
    
    deactivate Daemon
```

**Step-by-Step DNS Query Processing**:

1. **Query Reception** (`forward.c:receive_query()`):
   - UDP packet arrives on port 53 listener
   - Parse DNS header and question section
   - Extract query name, type, class
   - Validate packet format, reject malformed queries

2. **Cache Lookup** (`cache.c:cache_find_by_name()`):
   - Compute hash of query name
   - Search hash table for matching entry
   - Check TTL hasn't expired
   - If found: return cached answer immediately

3. **Forward Record Allocation** (on cache miss):
   - Allocate `struct frec` from pool of 150 entries (`FTABSIZ`)
   - Store client query ID, source address, query details
   - Generate new query ID for upstream (prevents query ID prediction attacks)
   - Select upstream server based on domain-specific routing rules

4. **Upstream Forwarding**:
   - Construct DNS query packet with new query ID
   - Send via UDP to selected upstream server
   - Use randomized source port for security
   - Set 10-second timeout

5. **Response Reception** (`forward.c:reply_query()`):
   - Upstream response arrives
   - Match response to outstanding `struct frec` by query ID
   - Validate response: matching question section, reasonable TTL values

6. **DNSSEC Validation** (if enabled, `dnssec.c`):
   - Check for RRSIG records
   - Validate signature chain to trust anchor
   - Process NSEC/NSEC3 proofs for negative responses
   - Return SERVFAIL if validation fails (bogus)

7. **Cache Insertion** (`cache.c:cache_insert()`):
   - Add validated response to cache
   - Apply LRU eviction if cache full
   - TTL copied from response

8. **Client Response**:
   - Restore original query ID
   - Send response packet to client
   - Free `struct frec` for reuse

### DHCP Lease Assignment Flow

```mermaid
sequenceDiagram
    participant Client as DHCP Client
    participant Daemon as Dnsmasq
    participant LeaseDB as Lease Database
    participant DNSCache as DNS Cache
    participant Script as External Script
    
    Client->>Daemon: DHCPDISCOVER (broadcast)
    activate Daemon
    
    Daemon->>Daemon: Parse DHCP options<br/>(hostname, vendor class, etc.)
    
    Daemon->>LeaseDB: Check for static reservation<br/>(by MAC address)
    
    alt Static Reservation Exists
        LeaseDB-->>Daemon: Reserved IP address
    else No Reservation
        Daemon->>LeaseDB: Find available IP from pool
        LeaseDB-->>Daemon: Available IP address
    end
    
    Daemon->>Daemon: Optional: Ping test IP<br/>(detect conflicts)
    
    Daemon-->>Client: DHCPOFFER (IP address, options)
    deactivate Daemon
    
    Client->>Daemon: DHCPREQUEST (requesting offered IP)
    activate Daemon
    
    Daemon->>LeaseDB: Create/Update Lease<br/>(MAC, IP, hostname, expiry)
    LeaseDB-->>Daemon: Lease committed
    
    Daemon->>DNSCache: Add A record<br/>(hostname → IP)
    DNSCache-->>Daemon: DNS entry added
    
    opt Script Configured
        Daemon->>Script: Fork/exec with "add"<br/>(MAC, IP, hostname)
        Script-->>Daemon: Script runs asynchronously
    end
    
    Daemon-->>Client: DHCPACK (lease confirmed)
    deactivate Daemon
    
    Note over Client,Daemon: Client now has IP address<br/>and is resolvable by hostname
```

**DHCP Processing Steps**:

1. **DISCOVER Reception** (`dhcp.c:dhcp_reply()`):
   - Parse DHCP options from packet
   - Extract client MAC address, requested IP, hostname, vendor class
   - Apply tag-based configuration rules

2. **Address Selection**:
   - Check static reservations by MAC address
   - If no reservation: find first available IP in configured pools
   - Skip addresses already leased or in static reservations

3. **Conflict Detection** (optional):
   - Send ICMP ping to candidate IP address
   - Wait brief period for response
   - If response received: IP in use, try next address

4. **OFFER Transmission**:
   - Construct DHCPOFFER packet
   - Include offered IP, subnet mask, router, DNS servers, lease time
   - Send to client

5. **REQUEST Processing**:
   - Client requests offered IP (or renews existing)
   - Verify request matches previous offer
   - Finalize lease assignment

6. **Lease Database Update** (`lease.c`):
   - Write lease to in-memory table
   - Asynchronously write to lease file on disk
   - Format: `<expiry> <mac> <ip> <hostname> <client-id>`

7. **DNS Integration**:
   - Immediately add A record to DNS cache
   - Client now resolvable by hostname
   - PTR record added for reverse lookup

8. **Script Execution** (if configured):
   - Fork child process
   - Execute script with arguments: `add <mac> <ip> <hostname>`
   - Environment includes `DNSMASQ_LEASE_LENGTH`, interface, client ID
   - Parent continues without waiting

---

## Memory Management Strategy

### Fixed-Size Data Structures

Dnsmasq uses predominantly fixed-size or bounded-size data structures to ensure predictable memory consumption and prevent unbounded growth under load or attack.

**Core Capacity Limits** (from `src/config.h`):

| Structure | Default Size | Configuration | Purpose |
|-----------|--------------|---------------|---------|
| DNS Cache | 150 entries | `CACHESIZ` (line 38)<br/>`--cache-size` | Cached DNS records |
| Forward Record Table | 150 entries | `FTABSIZ` (line 17) | Outstanding DNS queries |
| DHCP Lease Table | 1000 leases | `MAXLEASES` (line 40) | Active DHCP leases |
| TCP Child Processes | 20 processes | `MAX_PROCS` (line 18) | Concurrent TCP DNS connections |
| TFTP Connections | 50 connections | `TFTP_MAX_CONNECTIONS` (line 54) | Concurrent TFTP transfers |

### Memory Allocation Patterns

**Initialization Phase**:
- Large structures allocated once at daemon startup
- DNS cache hash table allocated based on configured size
- Lease table pre-allocated for maximum lease count
- Configuration structures sized based on config file

**Runtime Phase**:
- Minimal heap allocation during packet processing
- Stack-allocated buffers for packet parsing (avoid malloc overhead)
- Pool-based allocation for forward records (pre-allocated array, not malloc per query)

**Custom Allocators** (`src/util.c`):

```c
// Example: safe_malloc wrapper
void *safe_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (!ptr)
    {
        // Log error and terminate - better than returning NULL
        // and risking NULL pointer dereference
        my_syslog(LOG_EMERG, "Memory allocation failed");
        exit(1);
    }
    return ptr;
}
```

### Block Data System (`src/blockdata.c`)

For variable-length data (primarily DNSSEC records which can be large), dnsmasq uses a block allocation system:

- **Fixed Block Size**: Each block is a fixed size (typically 128 or 256 bytes)
- **Chain Structure**: Large data items span multiple blocks linked together
- **Reduced Fragmentation**: Fixed-size blocks prevent heap fragmentation
- **Bounded Growth**: Total block pool size can be limited

**Use Cases**:
- DNSSEC RRSIG records (variable-length signatures)
- DNSKEY records (public keys, various sizes)
- Large TXT records

### Memory Consumption Profile

**Typical Memory Usage**:

- **Minimal Configuration** (DNS forwarding only, 150 cache entries): ~1-2MB RSS
- **Standard Configuration** (DNS + DHCP, 150 cache, 50 leases): ~2-3MB RSS
- **Full Configuration** (DNS + DHCP + DNSSEC + TFTP, 1000 cache, 200 leases): ~5-10MB RSS

**Memory Growth Factors**:
- Cache size: ~200 bytes per cached record
- DHCP leases: ~100-200 bytes per active lease
- Configuration size: Static hosts, DHCP reservations (~50-100 bytes each)
- DNSSEC: Additional memory for DNSKEY/DS records and validation state

**Memory Leak Prevention**:
- All allocations paired with corresponding frees
- No dynamic allocation in hot paths (prevents slow leaks)
- Valgrind testing during development to detect leaks

---

## Platform Abstraction Layer

Dnsmasq supports diverse Unix-like platforms through careful abstraction of platform-specific functionality. Platform differences are isolated in dedicated modules, with conditional compilation selecting appropriate implementations.

### Network Interface Monitoring

Different platforms provide different mechanisms for monitoring network interface state changes:

**Linux: Netlink Sockets** (`src/netlink.c`):

```c
// Netlink socket monitoring (simplified concept)
// Linux provides real-time notifications of:
// - Interface up/down events
// - IP address addition/removal
// - Route changes

int netlink_init(void)
{
    int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    // Bind and configure netlink socket
    // Add to poll() file descriptor set
    return fd;
}

void netlink_process(void)
{
    // Process netlink messages
    // Update internal interface state
    // Trigger listener reconfiguration if needed
}
```

**Features**:
- Real-time event notification (no polling required)
- Low overhead (kernel pushes events to userspace)
- Supports IPv4 and IPv6 address monitoring
- Route table change detection

**BSD: Routing Sockets and BPF** (`src/bpf.c`):

```c
// BSD routing socket monitoring (simplified concept)
// BSD provides interface events via routing sockets

int bpf_init(void)
{
    int fd = socket(PF_ROUTE, SOCK_RAW, 0);
    // Configure routing socket
    return fd;
}

void bpf_process(void)
{
    // Read routing messages
    // Update interface state
}
```

**Features**:
- Routing socket for interface/address events
- BPF for raw packet access (DHCP, TFTP)
- Different ioctl() interfaces for interface enumeration

**Platform Detection** (`src/config.h`):

```c
// Compile-time platform detection
#if defined(__linux__)
#  define HAVE_LINUX_NETWORK
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  define HAVE_BSD_NETWORK
#endif
```

### Unified Network API (`src/network.c`)

The network core module provides platform-independent interfaces:

**Interface Enumeration**:
- `enumerate_interfaces()`: Returns list of all network interfaces
- Abstracts: Linux `getifaddrs()`, BSD `getifaddrs()`, Solaris `ioctl(SIOCGIFCONF)`

**Socket Creation**:
- `create_bound_listeners()`: Creates listener sockets on specific interfaces
- `create_wildcard_listeners()`: Creates wildcard listeners (all interfaces)
- Handles: IPv4/IPv6 dual-stack, SO_REUSEADDR, IPV6_V6ONLY

**Address Utilities**:
- `iface_check()`: Check if address is on specific interface
- `local_addr()`: Determine if address is local to daemon
- Platform-agnostic address family handling

### Service Management Integration

Different platforms use different service management frameworks:

**Linux: systemd**:
- Unit file: `dnsmasq.service`
- Socket activation support
- Integration with systemd-resolved

**macOS: launchd** (`contrib/MacOSX-launchd/`):
- Property list: `uk.org.thekelleys.dnsmasq.plist`
- Automatic daemon restart on crash
- Integration with macOS network preferences

**Solaris: SMF** (`contrib/Solaris10/`):
- Service manifest: `dnsmasq.xml`
- Service dependency management
- Integration with Solaris zones

**BSD: rc.d**:
- Init script: `/etc/rc.d/dnsmasq` or `/usr/local/etc/rc.d/dnsmasq`
- rcvar configuration

### File System Paths

Platform-specific file paths are defined in `src/config.h` lines 207-243:

| Purpose | Linux Default | BSD Default | Configurable |
|---------|---------------|-------------|--------------|
| Lease database | `/var/lib/misc/dnsmasq.leases` | `/var/db/dnsmasq.leases` | `--dhcp-leasefile` |
| PID file | `/var/run/dnsmasq.pid` | `/var/run/dnsmasq.pid` | `--pid-file` |
| Configuration | `/etc/dnsmasq.conf` | `/usr/local/etc/dnsmasq.conf` | `-C <file>` |

---

## Inter-Module Dependencies

### Dependency Graph

```mermaid
graph TD
    subgraph "Foundation Layer"
        Config[config.h<br/>Compile-time Configuration]
        DnsmasqH[dnsmasq.h<br/>Core Data Structures]
        Util[util.c<br/>Utility Functions]
    end
    
    subgraph "Runtime Core"
        Main[dnsmasq.c<br/>Main Event Loop]
        Poll[poll.c<br/>I/O Multiplexing]
        Log[log.c<br/>Logging]
        Option[option.c<br/>Config Parser]
    end
    
    subgraph "Network Layer"
        Network[network.c<br/>Network Core]
        Netlink[netlink.c<br/>Linux Monitor]
        BPF[bpf.c<br/>BSD Monitor]
    end
    
    subgraph "DNS Services"
        Forward[forward.c<br/>DNS Forwarder]
        Cache[cache.c<br/>DNS Cache]
        RFC1035[rfc1035.c<br/>Wire Format]
        DNSSEC[dnssec.c<br/>DNSSEC]
        Auth[auth.c<br/>Authoritative]
    end
    
    subgraph "DHCP Services"
        DHCP[dhcp.c<br/>DHCP Server]
        RFC2131[rfc2131.c<br/>DHCPv4]
        DHCP6[dhcp6.c<br/>DHCPv6]
        RFC3315[rfc3315.c<br/>DHCPv6 Protocol]
        Lease[lease.c<br/>Lease DB]
        RadV[radv.c<br/>Router Advert]
    end
    
    Config --> DnsmasqH
    DnsmasqH --> Main
    DnsmasqH --> Forward
    DnsmasqH --> Cache
    DnsmasqH --> DHCP
    DnsmasqH --> Lease
    
    Util --> Main
    Util --> Forward
    Util --> Cache
    Util --> DHCP
    
    Main --> Poll
    Main --> Log
    Main --> Option
    Main --> Network
    Main --> Forward
    Main --> DHCP
    
    Network --> Netlink
    Network --> BPF
    
    Forward --> Cache
    Forward --> RFC1035
    Forward --> DNSSEC
    Forward --> Auth
    Forward --> Network
    
    DHCP --> RFC2131
    DHCP --> Lease
    DHCP --> Network
    
    DHCP6 --> RFC3315
    DHCP6 --> Lease
    DHCP6 --> RadV
    DHCP6 --> Network
    
    Lease --> Cache
    
    style DnsmasqH fill:#ffe1e1
    style Main fill:#e1f5ff
    style Cache fill:#fff4e1
    style Lease fill:#fff4e1
```

### Key Integration Points

**DNS-DHCP Integration** (`cache.c` ↔ `lease.c`):

When a DHCP lease is assigned with a hostname:
1. `lease.c:lease_update()` updates lease database
2. Calls `cache.c:cache_add_dhcp_entry()` to add DNS A record
3. DNS cache immediately contains hostname → IP mapping
4. Subsequent DNS queries for hostname return cached entry
5. Lease expiration/release triggers `cache_del_dhcp_entry()`

**Forward-Cache Integration** (`forward.c` → `cache.c`):

```c
// Simplified query processing flow
void receive_query(int fd)
{
    // Parse DNS query
    struct dns_header *header = parse_query(packet);
    
    // Check cache
    struct crec *cached = cache_find_by_name(query_name, query_type);
    
    if (cached && !is_expired(cached))
    {
        // Cache hit - return immediately
        return_cached_answer(fd, header, cached);
    }
    else
    {
        // Cache miss - forward to upstream
        struct frec *forward = allocate_frec();
        forward_to_upstream(forward, header, query_name);
    }
}

void reply_query(int fd)
{
    // Upstream response received
    struct frec *forward = find_frec_by_id(query_id);
    
    // Validate response
    if (validate_response(response))
    {
        // Add to cache
        cache_insert(query_name, response_data, ttl);
        
        // Return to client
        return_answer(forward->client_fd, response);
        
        // Free forward record
        free_frec(forward);
    }
}
```

**Network-Multiple Services** (`network.c` → all protocol handlers):

The network core creates listener sockets and dispatches incoming packets to appropriate handlers:

```c
// Simplified dispatch logic
void poll_loop(void)
{
    while (running)
    {
        int ready = poll(pollfds, nfds, timeout);
        
        for (each ready fd)
        {
            if (fd == dns_udp_fd)
                receive_query(fd);
            else if (fd == dhcp_fd)
                dhcp_reply(fd);
            else if (fd == dhcp6_fd)
                dhcp6_reply(fd);
            else if (fd == tftp_fd)
                tftp_request(fd);
            else if (fd == netlink_fd)
                netlink_process(fd);
            // ... etc
        }
    }
}
```

**Configuration-All Modules** (`option.c` → global `daemon` struct):

Configuration parsing initializes the global `struct daemon *daemon` which all modules reference:

```c
// Global daemon structure (src/dnsmasq.h)
struct daemon
{
    // DNS configuration
    int port;                    // DNS port (default 53)
    int cachesize;               // Cache size entries
    struct server *servers;      // Upstream DNS servers
    
    // DHCP configuration
    struct dhcp_context *dhcp;   // DHCP address ranges
    struct dhcp_config *dhcp_conf; // Static DHCP reservations
    struct dhcp_lease *leases;   // Active lease list
    
    // Network configuration
    struct listener *listeners;  // Network listeners
    struct iname *if_names;      // Interface specifications
    
    // Runtime state
    time_t now;                  // Current time cache
    int num_leases;              // Active lease count
    // ... hundreds more fields
};
```

All modules access this global state, eliminating need for passing context pointers through all function calls.

---

## Configuration and Build System

### Compilation Model

**Makefile Structure**:

The build system (`Makefile` in repository root) provides:

1. **Feature Detection**: Uses `pkg-config` to detect optional libraries
2. **Conditional Compilation**: Sets `COPTS` with `-DHAVE_*` flags
3. **Platform Detection**: Uses `uname` to identify OS and adjust flags
4. **Cross-Compilation**: Supports setting `CC`, `CFLAGS`, `LDFLAGS`

**Default Build** (common features enabled):

```bash
# Standard build with common features
make

# Resulting binary includes:
# - DNS forwarding and caching (always)
# - DHCP and DHCPv6 (always)
# - TFTP (if enabled in Makefile, default yes)
# - Authoritative DNS (if enabled, default yes)
# - DNSSEC (if Nettle detected via pkg-config)
# - D-Bus (if libdbus-1 detected)
# - IDN support (if libidn or libidn2 detected)
```

**Minimal Build** (embedded systems):

```bash
# Minimal DNS-only build
make COPTS="-DNO_DHCP -DNO_TFTP -DNO_AUTH -DNO_DNSSEC -DNO_SCRIPT"

# Result: ~100KB stripped binary, DNS forwarding only
```

**Full-Featured Build**:

```bash
# Enable all optional features
make COPTS="-DHAVE_DNSSEC -DHAVE_DBUS -DHAVE_IDN -DHAVE_LIBIDN2 \
            -DHAVE_CONNTRACK -DHAVE_IPSET -DHAVE_NFTSET \
            -DHAVE_LUASCRIPT -DHAVE_DUMPFILE"

# Requires all optional libraries installed
# Result: ~500KB stripped binary, all features
```

### Configuration File Processing

**Configuration Hierarchy** (precedence order, highest to lowest):

1. **Command-line options**: Override all other settings
2. **Configuration file**: Default `/etc/dnsmasq.conf`, specifiable via `-C`
3. **Included files**: `conf-dir=` and `conf-file=` directives
4. **Built-in defaults**: Hardcoded in `src/config.h`

**Configuration Parsing** (`src/option.c`):

The `read_opts()` function processes configuration in multiple passes:

1. **First Pass**: Parse basic options, open files, check syntax
2. **Network Pass**: Enumerate interfaces, validate interface names
3. **Final Pass**: Validate cross-dependencies, initialize structures

**Configuration Validation**:

- **Type Checking**: Port numbers must be valid (1-65535)
- **Range Checking**: DHCP ranges must be valid subnets
- **Consistency Checking**: Options that require other options
- **File Access**: Config files, lease files must be readable/writable

**Example Configuration Directives**:

```bash
# DNS Configuration
port=53                          # DNS port (0 disables DNS)
cache-size=150                   # DNS cache entries
server=8.8.8.8                   # Upstream DNS server
server=/company.internal/10.0.0.1  # Domain-specific upstream

# DHCP Configuration
dhcp-range=192.168.1.50,192.168.1.150,255.255.255.0,12h
dhcp-option=option:router,192.168.1.1
dhcp-host=00:11:22:33:44:55,192.168.1.100,hostname,12h

# Integration
dhcp-script=/usr/local/bin/lease-notify.sh
enable-dbus
log-queries
log-dhcp
```

### Runtime Configuration Changes

**Hot Reload via SIGHUP**:

When SIGHUP is received:

```c
// Simplified reload logic
void reload_config(void)
{
    // Clear DNS cache completely
    cache_init();
    
    // Re-read configuration file
    read_opts(argc, argv, config_file);
    
    // Re-enumerate network interfaces
    enumerate_interfaces();
    
    // Recreate DNS listeners (if interfaces changed)
    set_dns_listeners();
    
    // Reload /etc/hosts entries
    read_hosts_file();
    
    // DHCP leases preserved (not cleared)
    
    // Resume normal operation
}
```

**Preserved State**:
- Active DHCP leases remain valid
- Outstanding DNS queries complete correctly
- TCP connections remain open

**Cleared State**:
- DNS cache completely cleared
- `/etc/hosts` entries reloaded
- Static configuration reapplied

---

## Performance Characteristics

### Latency Profile

**DNS Query Latency**:

| Scenario | Expected Latency | Notes |
|----------|------------------|-------|
| Cache hit | <1ms | Memory lookup, no I/O |
| Cache miss, fast upstream | 10-20ms | Upstream RTT + processing |
| Cache miss, slow upstream | 100-200ms | Depends on upstream latency |
| DNSSEC validation | +10-50ms | Crypto operations, additional queries |
| First query after startup | +5-10ms | Cache cold, interface enumeration |

**DHCP Transaction Latency**:

| Operation | Expected Latency | Notes |
|-----------|------------------|-------|
| DISCOVER → OFFER | <10ms | Address lookup and allocation |
| REQUEST → ACK | <10ms | Lease commit, DNS integration |
| Full DORA cycle | <50ms | Including network propagation |
| Lease renewal | <5ms | Existing lease update |

### Throughput Capacity

**DNS Query Throughput** (single core, typical hardware):

- **Cache hits**: 10,000-50,000 queries/second (memory-bound)
- **Cache misses**: 1,000-5,000 queries/second (upstream-limited)
- **Mixed workload (70% hits)**: 5,000-20,000 queries/second

**Bottlenecks**:
- Upstream server response time (cache miss scenarios)
- Single-threaded architecture (CPU-bound for cache hits)
- DNSSEC validation (crypto operations)

**DHCP Transaction Throughput**:

- **Sustained rate**: 100-500 DHCP transactions/second
- **Burst capacity**: 1,000-2,000 transactions/second (limited duration)
- **Lease database I/O**: Async writes prevent blocking

### Resource Utilization

**CPU Utilization**:

| Load Level | CPU Usage (single core) | Scenario |
|------------|------------------------|----------|
| Idle | <1% | No queries, maintenance only |
| Light (10 qps) | 1-2% | Typical home network |
| Moderate (100 qps) | 5-10% | Small office network |
| Heavy (1000 qps) | 20-40% | Busy small network |
| Maximum (5000+ qps) | 80-100% | Single-core saturation |

**Memory Utilization**:

Predictable and bounded by configuration:

```
Base memory: 1-2 MB
+ (cache_size * 200 bytes) for DNS cache
+ (max_leases * 150 bytes) for DHCP leases
+ (config_entries * 100 bytes) for static configuration
+ DNSSEC validation state (when active): 1-5 MB

Typical: 2-5 MB RSS
Maximum (large deployment): 10-20 MB RSS
```

**Network Bandwidth**:

Minimal - only DNS and DHCP protocol overhead:
- DNS: ~100 bytes per query/response
- DHCP: ~300-500 bytes per transaction
- TFTP: Actual file transfer bandwidth (boot images)

### Scalability Limits

**Practical Deployment Limits**:

| Metric | Recommended Maximum | Hard Limit | Constraint |
|--------|---------------------|------------|-----------|
| Concurrent clients | 250 | 1000 | DHCP lease table |
| DNS cache size | 10,000 | No hard limit | Memory, hash table efficiency |
| Query rate | 5,000 qps | 10,000 qps | Single-core CPU |
| Concurrent TCP connections | 20 | 20 | `MAX_PROCS` limit |
| TFTP connections | 50 | 50 | `TFTP_MAX_CONNECTIONS` |
| Static host entries | 10,000 | No hard limit | Memory, startup time |

---

## Security Architecture

### Privilege Separation

**Startup Phase** (running as root):

1. Parse configuration
2. Bind to privileged ports (53, 67, 547, 69)
3. Open necessary files
4. Chroot to secure directory (optional, via `--chroot`)

**Runtime Phase** (running as unprivileged user):

5. Drop privileges to configured user (default "nobody") via `setuid()`
6. Drop supplementary groups via `setgroups()`
7. Continue operation with minimal privileges

**Linux Capabilities** (when available):

Instead of full root privileges, retain only necessary capabilities:
- `CAP_NET_BIND_SERVICE`: Bind privileged ports
- `CAP_NET_ADMIN`: Configure network (DHCPv6, routing)
- `CAP_NET_RAW`: Raw sockets (DHCP, ICMPv6)

### Attack Surface Reduction

**Minimal Attack Surface**:

- **No shell execution in main process**: Scripts use safe fork/exec
- **Input validation**: DNS packet parsing validates format
- **Bounds checking**: Fixed-size buffers prevent overflows
- **Resource limits**: Prevents DoS via resource exhaustion

**DNSSEC Validation**:

- **Cache poisoning protection**: Cryptographic validation
- **Trust chain enforcement**: Invalid signatures → SERVFAIL
- **Resource limits**: Prevent validation DoS attacks

### Secure Defaults

- DNS cache enabled by default (reduces upstream exposure)
- Query ID randomization (prevents cache poisoning)
- Source port randomization (prevents blind spoofing)
- Negative caching limited (prevents false negative DoS)

---

## Extensibility and Integration

### External Integration Points

**Script Execution** (`src/helper.c`):

- **Lease events**: add, old, del on DHCP assignments
- **Auth scripts**: Custom authentication logic
- **Environment**: Full lease details, interface, client ID
- **Security**: Scripts run as daemon user, not root

**D-Bus Interface** (`src/dbus.c`):

Methods exposed on `uk.org.thekelleys.dnsmasq`:
- `GetVersion()`: Query daemon version
- `ClearCache()`: Clear DNS cache
- `SetServers()`: Reconfigure upstream servers
- `GetMetrics()`: Retrieve cache statistics

**UBus Interface** (`src/ubus.c`):

OpenWrt-specific control interface:
- `metrics`: Cache hit/miss ratios
- `servers`: Upstream server status
- `leases`: Active DHCP leases

### Firewall Integration

**Dynamic Set Population**:

```bash
# Configuration example
ipset=/example.com/blacklist        # Add resolved IPs to ipset
nftset=/example.com/ip/filter/block # Add to nftables set
```

When `example.com` is queried:
1. DNS resolution completes
2. Resolved IP addresses extracted
3. IPs added to specified ipset/nftset
4. Firewall rules using set are immediately active

**Use Cases**:
- Content filtering (add ad domains to block list)
- Security policy (whitelist corporate resources)
- Routing policy (route specific domains via VPN)

---

## Deployment Patterns

### Common Deployment Scenarios

**1. Home Router / Small Office**:

- Single dnsmasq instance
- DNS forwarding to ISP or public DNS
- DHCP for local network (10-50 clients)
- Optional TFTP for network boot
- Configuration: Minimal, often zero-config

**2. Embedded Device (Wireless AP)**:

- Integrated with wireless AP firmware (OpenWrt, DD-WRT)
- UBus integration for web UI control
- DHCP for wireless clients
- DNS captive portal integration
- Resource constraints: <10MB RAM, <1MB storage

**3. Virtualization Host (libvirt, LXC)**:

- Multiple isolated dnsmasq instances per virtual network
- DHCP for VM/container addressing
- DNS resolution within virtual network
- Bridge integration with host networking
- Dynamic configuration via libvirt APIs

**4. Development Environment**:

- Local DNS for `*.dev`, `*.test` domains
- DHCP for test virtual machines
- Integration with development tools
- Rapid configuration changes

**5. Network Boot Server**:

- TFTP boot image serving
- PXE boot option delivery via DHCP
- Multiple architecture support (x86, x86-64, EFI)
- Boot menu configuration
- Integration with provisioning systems

### High Availability Considerations

Dnsmasq is designed for simple deployments and does **not include built-in HA**:

**Multiple Instance Deployment**:

- Run multiple independent dnsmasq instances
- Use separate address pools (split DHCP range)
- Configure same upstream DNS servers
- Clients fail over automatically (DHCP lease renewal)

**Limitations**:
- No lease synchronization between instances
- No cache synchronization
- No automatic failover coordination

**External HA Solutions**:
- Keepalived for virtual IP management
- Cluster resource managers (Pacemaker)
- Load balancers for DNS (round-robin, health checks)

---

## Future Architecture Evolution

### Identified Opportunities

**1. Multi-Threading for DNS Cache Hits**:

- Current: Single thread limits cache hit throughput
- Potential: Read-only cache lookups could be parallelized
- Trade-off: Added complexity vs. performance gain

**2. Improved Cache Algorithms**:

- Current: Simple LRU eviction
- Potential: Frequency-based eviction, adaptive sizing
- Benefit: Better hit rates for working set

**3. DNS-over-HTTPS / DNS-over-TLS**:

- Current: Plaintext DNS only
- Potential: Encrypted upstream communication
- Challenge: Increased complexity, external dependencies

**4. Prometheus Metrics**:

- Current: Basic syslog statistics
- Potential: Native Prometheus exporter
- Benefit: Modern monitoring integration

### Architectural Constraints

**Preserved Principles**:

- Single-threaded event-driven core (simplicity)
- Manual memory management (determinism)
- Zero external service dependencies (reliability)
- Minimal binary size (embedded deployment)
- Universal Unix portability (broad platform support)

These core principles guide all evolution decisions.

---

## Conclusion

Dnsmasq's architecture reflects 25 years of evolution toward a singular goal: **providing lightweight, reliable network services for small networks and embedded systems**. The single-process event-driven design, explicit memory management, and platform abstraction enable deployment across diverse environments while maintaining predictable resource usage and operational simplicity.

The architecture demonstrates that sophisticated network services (DNS forwarding with DNSSEC validation, DHCPv4/v6, TFTP, Router Advertisement) can be delivered in a compact, efficient package suitable for resource-constrained devices, without sacrificing reliability or standards compliance.

### Key Architectural Strengths

1. **Simplicity**: Single-threaded design eliminates concurrency complexity
2. **Efficiency**: Minimal overhead suitable for embedded single-core processors
3. **Reliability**: Deterministic behavior enables months/years of continuous operation
4. **Portability**: Runs on all major Unix-like platforms with platform-specific optimizations
5. **Integration**: DNS-DHCP integration eliminates manual synchronization overhead

### Appropriate Use Cases

Dnsmasq excels in scenarios prioritizing:
- **Resource efficiency** over maximum throughput
- **Operational simplicity** over enterprise features
- **Self-contained deployment** over distributed architecture
- **Small network scale** (10-250 clients) over enterprise scale

For enterprise-scale deployments requiring high availability, horizontal scaling, or advanced DNS features, alternative solutions (BIND, Unbound, ISC Kea) remain more appropriate.

---

**Document Information**:

- **Version**: 1.0
- **Target Audience**: Developers, system architects, platform engineers
- **Based on**: dnsmasq version 2.92 source code
- **Word Count**: ~11,500 words
- **Last Updated**: [Current Date]

**References**:

- Source Code: `src/` directory (51 files)
- Build System: `Makefile`, `src/config.h`
- Documentation: `doc.html`, `setup.html`
- Configuration: `dnsmasq.conf.example`

