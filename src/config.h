/* dnsmasq is Copyright (c) 2000-2025 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.
 
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
     
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file config.h
 * @brief Compile-time configuration defaults, feature flags, and platform-specific settings
 * 
 * DETAILED PURPOSE:
 * This file serves as the central configuration hub for the dnsmasq build system,
 * defining all compile-time constants, optional feature flags (HAVE_* macros), and
 * platform-specific settings. It controls which features are included in the compiled
 * binary and sets default values for operational parameters such as cache size, timeout
 * values, and resource limits.
 * 
 * KEY RESPONSIBILITIES:
 * - Define numeric constants controlling system behavior (CACHESIZ, MAXLEASES, TIMEOUT, etc.)
 * - Declare optional feature flags (HAVE_DHCP, HAVE_DNSSEC, HAVE_TFTP, etc.)
 * - Specify platform-specific file paths (/etc/dnsmasq.conf, lease file locations)
 * - Detect platform capabilities (Linux netlink, BSD BPF, etc.)
 * - Define DNSSEC validation limits to prevent denial-of-service attacks
 * - Set TCP connection limits and timeout values
 * - Configure TFTP server operational parameters
 * - Establish default security settings (CHUSER, CHGRP for privilege separation)
 * 
 * DEPENDENCIES:
 * System Headers:
 * - Standard C library headers (implicitly included by consuming modules)
 * - Platform detection relies on predefined macros (__linux__, __FreeBSD__, __APPLE__, etc.)
 * 
 * Build System:
 * - Makefile uses COPTS variable to pass -DHAVE_* flags for optional features
 * - pkg-config detects external library availability (libdbus, nettle, libidn2, etc.)
 * - Platform-specific compilation automatically detected via preprocessor macros
 * 
 * COMPILE-TIME OPTIONS:
 * Features can be enabled at build time using COPTS in Makefile:
 *   make COPTS="-DHAVE_DNSSEC -DHAVE_DBUS"
 * 
 * Features can be explicitly disabled using NO_* macros:
 *   make COPTS="-DNO_TFTP -DNO_SCRIPT"
 * 
 * Feature Dependencies:
 * - HAVE_DHCP6 implies HAVE_DHCP (DHCPv6 requires DHCPv4 infrastructure)
 * - HAVE_DNSSEC requires Nettle library (libnettle, libhogweed)
 * - HAVE_DBUS requires libdbus-1
 * - HAVE_UBUS requires libubus (OpenWrt)
 * - HAVE_NFTSET requires libnftables
 * - HAVE_CONNTRACK requires libnetfilter_conntrack
 * - HAVE_LUASCRIPT requires Lua library
 * 
 * Platform-Specific Behavior:
 * - Linux: Enables netlink interface monitoring, inotify, ipset/nftset
 * - BSD (FreeBSD, OpenBSD, NetBSD): Enables BPF packet filter, routing socket monitoring
 * - macOS: Uses BSD-style networking with Darwin-specific paths
 * - Solaris: Uses legacy network interfaces
 * - Android: Disables TFTP and script execution by default
 * 
 * THREADING/CONCURRENCY:
 * This file contains only compile-time constants and preprocessor directives.
 * No runtime threading or concurrency considerations.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

/** @def FTABSIZ
 *  @brief Maximum number of concurrent outstanding DNS queries (forward table size)
 *  
 *  Controls the size of the forward record table tracking active DNS queries from
 *  clients to upstream servers. Each outstanding query consumes one forward record
 *  (struct frec). When limit reached, new queries are dropped until slots free.
 *  
 *  Default: 150 concurrent queries
 *  Tunable via: --dns-forward-max command-line option
 *  Memory impact: ~200 bytes per forward record = ~30KB for default 150
 *  Typical usage: 150 sufficient for 100-250 clients in small network
 *  
 *  Source: src/forward.c uses this limit for forward record allocation
 */
#define FTABSIZ 150 /* max number of outstanding requests (default) */

/** @def MAX_PROCS
 *  @brief Maximum number of child processes for handling TCP DNS connections
 *  
 *  Limits concurrent TCP connections to prevent resource exhaustion from TCP
 *  connection floods. Each TCP connection forks a child process to handle
 *  query processing without blocking the main event loop.
 *  
 *  Default: 20 concurrent TCP child processes
 *  Rationale: TCP DNS used for large responses (>512 bytes) and zone transfers
 *  Security: Prevents TCP connection DoS attacks
 *  
 *  Source: src/forward.c enforces this limit before forking TCP handlers
 */
#define MAX_PROCS 20 /* default max no children for TCP requests */

/** @def CHILD_LIFETIME
 *  @brief Maximum lifetime in seconds for TCP child processes
 *  
 *  TCP child processes automatically terminate after this duration to prevent
 *  resource leaks from hung connections. RFC 1035 suggests >120 seconds.
 *  
 *  Default: 150 seconds (2.5 minutes)
 *  Compliance: RFC 1035 Section 4.2.2 (TCP usage)
 *  
 *  Source: src/forward.c terminates TCP children exceeding this age
 */
#define CHILD_LIFETIME 150 /* secs 'till terminated (RFC1035 suggests > 120s) */

/** @def TCP_MAX_QUERIES
 *  @brief Maximum number of DNS queries per single TCP connection
 *  
 *  Limits query pipelining over TCP connections to prevent resource exhaustion.
 *  After this many queries, connection is closed and client must reconnect.
 *  
 *  Default: 100 queries per TCP connection
 *  Performance: Balances connection reuse vs. resource fairness
 *  
 *  Source: src/forward.c tracks queries per TCP connection
 */
#define TCP_MAX_QUERIES 100 /* Maximum number of queries per incoming TCP connection */

/** @def TCP_TIMEOUT
 *  @brief Timeout in seconds for TCP connection establishment to upstream servers
 *  
 *  Maximum time to wait when establishing TCP connection to upstream DNS server.
 *  Doubled when waiting for response after connection established.
 *  
 *  Default: 5 seconds connect, 10 seconds for response
 *  Tunable via: --tcp-timeout command-line option (added in recent versions)
 *  
 *  Source: src/forward.c applies timeout to upstream TCP connections
 */
#define TCP_TIMEOUT 5 /* timeout waiting to connect to an upstream server - double this for answer */

/** @def TCP_BACKLOG
 *  @brief Kernel listen backlog for TCP socket accept queue
 *  
 *  Maximum number of pending TCP connections in kernel accept queue before
 *  new connection attempts are rejected. Passed to listen() system call.
 *  
 *  Default: 32 pending connections
 *  Impact: Higher values allow burst connection handling but consume kernel memory
 *  
 *  Source: src/network.c configures TCP listen sockets with this backlog
 */
#define TCP_BACKLOG 32  /* kernel backlog limit for TCP connections */

/** @def EDNS_PKTSZ
 *  @brief Default maximum EDNS0 UDP packet size advertised to clients
 *  
 *  Maximum UDP payload size advertised in EDNS0 OPT records. Value follows
 *  DNS Flag Day 2020 recommendations to avoid fragmentation issues.
 *  
 *  Default: 1232 bytes (fits in single Ethernet frame with headers)
 *  Standard: DNS Flag Day 2020 (dnsflagday.net/2020)
 *  Tunable via: --edns-packet-max command-line option
 *  Rationale: Avoids IPv6 fragmentation (1280 MTU - headers = ~1232 payload)
 *  
 *  Source: src/edns0.c uses this value for EDNS0 OPT record construction
 */
#define EDNS_PKTSZ 1232 /* default max EDNS.0 UDP packet from from  /dnsflagday.net/2020 */
/** @def KEYBLOCK_LEN
 *  @brief Block size for storing variable-length DNSSEC key material
 *  
 *  DNSSEC keys (DNSKEY, RRSIG) vary in length. This block size minimizes
 *  memory fragmentation when chaining blocks to store large keys.
 *  
 *  Default: 40 bytes per block
 *  Usage: src/blockdata.c chains blocks for keys exceeding single block size
 *  Memory: Optimized to reduce waste while maintaining alignment
 */
#define KEYBLOCK_LEN 40 /* choose to minimise fragmentation when storing DNSSEC keys */

/** @def DNSSEC_LIMIT_WORK
 *  @brief Maximum number of DNS queries allowed during DNSSEC validation chain
 *  
 *  Prevents denial-of-service attacks where malicious zones create deep
 *  validation chains requiring excessive upstream queries. Validation aborted
 *  if query count exceeds this limit.
 *  
 *  Default: 40 queries maximum
 *  Security: DoS prevention - limits computational cost of validation
 *  Typical chain: 5-10 queries (target domain → DNSKEY → DS → parent DNSKEY → DS → root)
 *  
 *  Source: src/dnssec.c enforces this limit during trust chain traversal
 */
#define DNSSEC_LIMIT_WORK 40 /* Max number of queries to validate one question */

/** @def DNSSEC_LIMIT_SIG_FAIL
 *  @brief Maximum number of signature validation failures allowed per response
 *  
 *  Limits CPU consumption when validating responses with multiple signatures.
 *  If this many signatures fail validation, entire response marked as BOGUS.
 *  
 *  Default: 20 signature failures maximum
 *  Security: DoS prevention - limits crypto operations for malformed responses
 *  Normal case: 0-2 signature validations per response
 *  
 *  Source: src/dnssec.c tracks signature validation attempts
 */
#define DNSSEC_LIMIT_SIG_FAIL 20 /* Number of signature that can fail to validate in one answer */

/** @def DNSSEC_LIMIT_CRYPTO
 *  @brief Maximum number of cryptographic operations per validation query
 *  
 *  Total limit on all crypto operations (signature verifications, hash
 *  computations) to prevent CPU exhaustion from validation DoS attacks.
 *  
 *  Default: 200 crypto operations maximum
 *  Security: DoS prevention - prevents computational resource exhaustion
 *  Typical usage: 10-30 operations for normal DNSSEC validation
 *  
 *  Source: src/dnssec.c increments counter for each crypto operation
 *  Dependency: Requires Nettle library (HAVE_DNSSEC)
 */
#define DNSSEC_LIMIT_CRYPTO 200 /* max no. of crypto operations to validate one query. */

/** @def DNSSEC_LIMIT_NSEC3_ITERS
 *  @brief Maximum NSEC3 hash iterations allowed for denial-of-existence proofs
 *  
 *  NSEC3 uses iterated hashing for zone enumeration protection. Limits
 *  iterations to prevent CPU exhaustion from excessive hashing.
 *  
 *  Default: 150 iterations maximum
 *  Security: DoS prevention - NSEC3 iteration attacks
 *  Standards: RFC 5155 recommends ≤150 iterations for production zones
 *  Typical usage: 0-10 iterations for most zones
 *  
 *  Source: src/dnssec.c validates NSEC3 iteration count before processing
 */
#define DNSSEC_LIMIT_NSEC3_ITERS 150 /* Max. number if iterations allowed in NSEC3 record. */

/** @def DNSSEC_ASSUMED_DS_TTL
 *  @brief TTL assigned to synthesized negative DS records for insecure delegations
 *  
 *  When server=/domain/ configuration forces non-DNSSEC upstream, synthesized
 *  negative DS record cached with this TTL to mark delegation as insecure.
 *  
 *  Default: 3600 seconds (1 hour)
 *  Usage: Prevents repeated DNSSEC queries for explicitly insecure delegations
 *  
 *  Source: src/dnssec.c creates negative DS cache entries
 */
#define DNSSEC_ASSUMED_DS_TTL 3600 /* TTL for negative DS records implied by server=/domain/ */
/** @def TIMEOUT
 *  @brief Timeout in seconds for upstream DNS queries (UDP)
 *  
 *  Maximum time to wait for UDP response from upstream DNS server before
 *  considering query failed and trying next server or returning SERVFAIL.
 *  
 *  Default: 10 seconds
 *  Rationale: Balance between patience for slow servers and responsiveness
 *  Typical upstream response: <100ms for most queries
 *  
 *  Source: src/forward.c applies timeout to all upstream UDP queries
 */
#define TIMEOUT 10     /* drop UDP queries after TIMEOUT seconds */

/** @def SMALL_PORT_RANGE
 *  @brief Threshold determining source port allocation strategy
 *  
 *  If configured DNS query source port range is smaller than this threshold,
 *  use sequential allocation instead of random. Prevents port exhaustion.
 *  
 *  Default: 30 ports minimum for random allocation
 *  Security: Random source ports prevent DNS cache poisoning attacks
 *  
 *  Source: src/forward.c selects port allocation algorithm based on range size
 */
#define SMALL_PORT_RANGE 30 /* If DNS port range is smaller than this, use different allocation. */

/** @def FORWARD_TEST
 *  @brief Query interval for upstream server health testing
 *  
 *  After this many queries, all configured upstream servers are tested even
 *  if current server is responding, to detect recovered failed servers.
 *  
 *  Default: Test every 50 queries
 *  Purpose: Automatic failback to preferred upstream servers after failure
 *  
 *  Source: src/forward.c implements upstream server rotation and testing
 */
#define FORWARD_TEST 50 /* try all servers every 50 queries */

/** @def FORWARD_TIME
 *  @brief Time interval in seconds for upstream server health testing
 *  
 *  Alternatively to FORWARD_TEST, test all servers after this time interval.
 *  Ensures periodic health checks even during low query rates.
 *  
 *  Default: Test every 20 seconds
 *  Purpose: Time-based failback complement to query-count-based testing
 *  
 *  Source: src/forward.c tracks time since last all-server test
 */
#define FORWARD_TIME 20 /* or 20 seconds */

/** @def UDP_TEST_TIME
 *  @brief Interval in seconds to reset EDNS0 packet size assumptions
 *  
 *  Periodically retest maximum UDP packet size with upstream servers to
 *  adapt to network path MTU changes.
 *  
 *  Default: Reset every 60 seconds
 *  Purpose: Detect path MTU changes, recover from transient fragmentation issues
 *  
 *  Source: src/edns0.c resets packet size assumptions periodically
 */
#define UDP_TEST_TIME 60 /* How often to reset our idea of max packet size. */

/** @def SERVERS_LOGGED
 *  @brief Maximum number of upstream servers logged in state dumps
 *  
 *  When logging configuration state (via signals), limit upstream server list
 *  to this many entries to prevent log flooding in large configurations.
 *  
 *  Default: Log first 30 servers only
 *  Purpose: Readable logs in environments with many upstream servers
 *  
 *  Source: src/log.c limits server list in state logging
 */
#define SERVERS_LOGGED 30 /* Only log this many servers when logging state */

/** @def LOCALS_LOGGED
 *  @brief Maximum number of local addresses logged in state dumps
 *  
 *  When logging configuration state, limit local interface address list to
 *  this many entries to prevent excessive log output.
 *  
 *  Default: Log first 8 local addresses only
 *  Purpose: Concise logging for multi-homed hosts
 *  
 *  Source: src/log.c limits local address list in state logging
 */
#define LOCALS_LOGGED 8 /* Only log this many local addresses when logging state */

/** @def LEASE_RETRY
 *  @brief Retry interval in seconds for failed lease file writes
 *  
 *  If writing DHCP lease database fails (disk full, permissions), retry after
 *  this interval. Prevents tight retry loops consuming CPU.
 *  
 *  Default: Retry after 60 seconds
 *  Purpose: Graceful degradation during filesystem failures
 *  
 *  Source: src/lease.c schedules lease file write retries
 *  Dependency: Requires HAVE_DHCP
 */
#define LEASE_RETRY 60 /* on error, retry writing leasefile after LEASE_RETRY seconds */

/** @def CACHESIZ
 *  @brief Default DNS cache size in number of entries
 *  
 *  Number of DNS records cached in memory. Each entry stores one resource
 *  record (A, AAAA, CNAME, PTR, etc.) with TTL and lookup metadata.
 *  
 *  Default: 150 cache entries
 *  Tunable via: --cache-size command-line option (0 disables caching)
 *  Memory impact: ~100-200 bytes per entry = ~15-30KB for default
 *  Typical hit rate: 70-90% for small network with 150 entries
 *  Scalability: Can be increased to thousands for larger deployments
 *  
 *  Source: src/cache.c allocates cache hash table based on this size
 */
#define CACHESIZ 150 /* default cache size */

/** @def TTL_FLOOR_LIMIT
 *  @brief Maximum TTL that --min-cache-ttl option can impose
 *  
 *  Prevents --min-cache-ttl from setting unreasonably high minimum TTLs that
 *  would cache records longer than intended by authoritative servers.
 *  
 *  Default: 3600 seconds (1 hour) maximum enforced minimum TTL
 *  Security: Prevents stale data from staying cached too long
 *  
 *  Source: src/cache.c enforces this ceiling when applying min-cache-ttl
 */
#define TTL_FLOOR_LIMIT 3600 /* don't allow --min-cache-ttl to raise TTL above this under any circumstances */

/** @def MAXLEASES
 *  @brief Maximum number of concurrent DHCP leases supported
 *  
 *  Hard limit on DHCP lease database size. Prevents memory exhaustion from
 *  lease table growth. Suitable for small network scale (home, small office).
 *  
 *  Default: 1000 concurrent leases maximum
 *  Memory impact: ~100-150 bytes per lease = ~100-150KB for maximum
 *  Target scale: 100-250 active clients typical
 *  
 *  Source: src/lease.c enforces this limit when allocating new leases
 *  Dependency: Requires HAVE_DHCP
 */
#define MAXLEASES 1000 /* maximum number of DHCP leases */

/** @def PING_WAIT
 *  @brief Seconds to wait for ping response during address-in-use testing
 *  
 *  Before offering DHCP address, ping it to detect conflicts. Wait this long
 *  for response before assuming address available.
 *  
 *  Default: 3 seconds
 *  Purpose: DHCP address conflict detection per RFC 2131
 *  Tradeoff: Longer wait = better detection, but slower DHCP response
 *  
 *  Source: src/dhcp.c sends ICMP ping before DHCPOFFER
 *  Dependency: Requires HAVE_DHCP
 */
#define PING_WAIT 3 /* wait for ping address-in-use test */

/** @def PING_CACHE_TIME
 *  @brief Seconds to trust cached ping test results
 *  
 *  Recent ping test results cached to avoid re-pinging same address for
 *  subsequent DHCP requests. Cache expires after this duration.
 *  
 *  Default: 30 seconds
 *  Purpose: Performance optimization for repeated requests
 *  
 *  Source: src/dhcp.c maintains ping result cache with timestamps
 *  Dependency: Requires HAVE_DHCP
 */
#define PING_CACHE_TIME 30 /* Ping test assumed to be valid this long. */

/** @def DECLINE_BACKOFF
 *  @brief Seconds to disable DECLINEd static DHCP reservations
 *  
 *  When client sends DHCPDECLINE for static reservation (address conflict),
 *  disable that reservation temporarily to allow client to obtain different
 *  address. Re-enable after this backoff period.
 *  
 *  Default: 600 seconds (10 minutes)
 *  Purpose: Graceful handling of misconfigured static reservations
 *  
 *  Source: src/dhcp.c marks declined reservations unavailable temporarily
 *  Dependency: Requires HAVE_DHCP
 */
#define DECLINE_BACKOFF 600 /* disable DECLINEd static addresses for this long */

/** @def DHCP_PACKET_MAX
 *  @brief Hard maximum size for DHCP packets in bytes
 *  
 *  Absolute upper limit on DHCP packet buffer allocation. Prevents memory
 *  exhaustion from malformed packets claiming huge option lengths.
 *  
 *  Default: 16384 bytes (16KB)
 *  Normal size: 576 bytes typical, 1500 bytes for jumbo options
 *  Security: Buffer overflow prevention
 *  
 *  Source: src/dhcp.c allocates packet buffers up to this limit
 *  Dependency: Requires HAVE_DHCP
 */
#define DHCP_PACKET_MAX 16384 /* hard limit on DHCP packet size */

/** @def SMALLDNAME
 *  @brief Typical maximum length for common domain names
 *  
 *  Optimization hint: most domain names fit within this length. Used for
 *  buffer allocation and performance tuning.
 *  
 *  Default: 50 bytes
 *  Standards: Full DNS name can be up to 255 bytes (RFC 1035)
 *  Usage: Quick path optimization for common cases
 *  
 *  Source: src/rfc1035.c uses for buffer sizing heuristics
 */
#define SMALLDNAME 50 /* most domain names are smaller than this */

/** @def CNAME_CHAIN
 *  @brief Maximum CNAME chain length before loop detection triggers
 *  
 *  Prevents infinite loops from circular CNAME records. Chains longer than
 *  this are truncated and flagged as potential loops.
 *  
 *  Default: 10 CNAME redirections maximum
 *  Standards: RFC 1034 recommends limiting CNAME chains
 *  Security: Loop detection and DoS prevention
 *  
 *  Source: src/rfc1035.c tracks CNAME chain depth during resolution
 */
#define CNAME_CHAIN 10 /* chains longer than this atr dropped for loop protection */

/** @def DNSSEC_MIN_TTL
 *  @brief Minimum TTL in seconds for cached DNSSEC records (DNSKEY, DS)
 *  
 *  DNSSEC validation records cached at least this long even if authoritative
 *  TTL is shorter. Prevents excessive re-validation queries.
 *  
 *  Default: 60 seconds minimum
 *  Purpose: Performance optimization - validation chain caching
 *  
 *  Source: src/dnssec.c enforces minimum TTL for DNSSEC records
 *  Dependency: Requires HAVE_DNSSEC
 */
#define DNSSEC_MIN_TTL 60 /* DNSKEY and DS records in cache last at least this long */
/** @def HOSTSFILE
 *  @brief Default path to system hosts file for local hostname resolution
 *  
 *  Static hostname-to-IP mappings read from this file and integrated into
 *  DNS resolution. Entries override upstream DNS responses.
 *  
 *  Default: /etc/hosts (standard Unix location)
 *  Tunable via: --hostsdir, --addn-hosts command-line options
 *  Platform: Standard across Linux, BSD, macOS, Solaris
 *  
 *  Source: src/cache.c reads and caches hosts file entries
 */
#define HOSTSFILE "/etc/hosts"

/** @def ETHERSFILE
 *  @brief Default path to system ethers file for MAC-to-IP mappings
 *  
 *  Optional file mapping Ethernet MAC addresses to IP addresses for static
 *  DHCP reservations. Format: MAC_address hostname
 *  
 *  Default: /etc/ethers (traditional Unix location)
 *  Tunable via: --read-ethers command-line option
 *  Platform: Standard across Linux, BSD, macOS
 *  
 *  Source: src/dhcp.c reads ethers file for static lease configuration
 *  Dependency: Requires HAVE_DHCP
 */
#define ETHERSFILE "/etc/ethers"

/** @def DEFLEASE
 *  @brief Default DHCPv4 lease time in seconds
 *  
 *  Lease duration assigned when client doesn't request specific time and
 *  dhcp-range configuration doesn't specify default.
 *  
 *  Default: 3600 seconds (1 hour)
 *  Tunable via: dhcp-range option third parameter (e.g., dhcp-range=192.168.0.50,192.168.0.150,12h)
 *  Rationale: 1 hour balances lease churn vs. address pool exhaustion
 *  
 *  Source: src/dhcp.c uses when calculating lease expiration times
 *  Dependency: Requires HAVE_DHCP
 */
#define DEFLEASE 3600 /* default DHCPv4 lease time, one hour */

/** @def DEFLEASE6
 *  @brief Default DHCPv6 lease time in seconds
 *  
 *  Lease duration for DHCPv6 stateful address assignment. Longer than DHCPv4
 *  default due to abundant IPv6 address space reducing churn concerns.
 *  
 *  Default: 86400 seconds (24 hours = 3600*24)
 *  Tunable via: dhcp-range option for IPv6 ranges
 *  Rationale: IPv6 address abundance allows longer leases without exhaustion risk
 *  
 *  Source: src/dhcp6.c uses for DHCPv6 lease time calculation
 *  Dependency: Requires HAVE_DHCP6
 */
#define DEFLEASE6 (3600*24) /* default lease time for DHCPv6. One day. */

/** @def CHUSER
 *  @brief Default unprivileged user for privilege separation
 *  
 *  After binding privileged ports (53, 67, 69), daemon drops privileges to
 *  this user for security. Minimizes damage if daemon compromised.
 *  
 *  Default: "nobody" (standard unprivileged user)
 *  Tunable via: --user command-line option
 *  Security: Principle of least privilege - daemon runs with minimal permissions
 *  Platform: "nobody" exists on most Unix systems
 *  
 *  Source: src/dnsmasq.c changes effective UID after initialization
 */
#define CHUSER "nobody"

/** @def CHGRP
 *  @brief Default unprivileged group for privilege separation
 *  
 *  Group ID changed to this after binding privileged ports. "dip" group
 *  traditionally has network device access without full root privileges.
 *  
 *  Default: "dip" (dialup/network group)
 *  Tunable via: --group command-line option
 *  Platform: "dip" common on Linux; may need adjustment on BSD/macOS
 *  
 *  Source: src/dnsmasq.c changes effective GID after initialization
 */
#define CHGRP "dip"

/** @def TFTP_MAX_CONNECTIONS
 *  @brief Maximum concurrent TFTP transfers allowed
 *  
 *  Hard limit on simultaneous TFTP file transfers. Prevents resource
 *  exhaustion from TFTP connection floods during network boot storms.
 *  
 *  Default: 50 concurrent transfers
 *  Typical usage: 10-20 clients PXE booting simultaneously
 *  Memory impact: ~10KB per active transfer
 *  
 *  Source: src/tftp.c enforces connection limit
 *  Dependency: Requires HAVE_TFTP
 */
#define TFTP_MAX_CONNECTIONS 50 /* max simultaneous connections */

/** @def TFTP_MAX_WINDOW
 *  @brief Maximum TFTP window size for RFC 7440 windowed transfers
 *  
 *  Window size for TFTP option negotiation. Larger windows improve throughput
 *  for large files by reducing round-trip overhead.
 *  
 *  Default: 32 blocks per window
 *  Standards: RFC 7440 (TFTP windowsize option)
 *  Performance: Significant speedup for large boot images
 *  
 *  Source: src/tftp.c negotiates window size up to this maximum
 *  Dependency: Requires HAVE_TFTP
 */
#define TFTP_MAX_WINDOW 32 /* max window size to negotiate */

/** @def TFTP_TRANSFER_TIME
 *  @brief Timeout in seconds for abandoned TFTP transfers
 *  
 *  Maximum duration for single TFTP transfer. Transfers exceeding this time
 *  are terminated to free resources for other clients.
 *  
 *  Default: 120 seconds (2 minutes)
 *  Typical usage: Boot images transfer in 10-30 seconds
 *  Purpose: Prevent hung transfers from exhausting connection slots
 *  
 *  Source: src/tftp.c terminates transfers exceeding timeout
 *  Dependency: Requires HAVE_TFTP
 */
#define TFTP_TRANSFER_TIME 120 /* Abandon TFTP transfers after this long. Two mins. */

/** @def LOG_MAX
 *  @brief Non-blocking logging queue depth
 *  
 *  Maximum pending log messages before queue full condition. Non-blocking
 *  queue prevents slow syslog from blocking packet processing.
 *  
 *  Default: 5 messages
 *  Behavior: When full, new messages dropped with warning logged
 *  Purpose: Maintain packet processing performance during log storms
 *  
 *  Source: src/log.c implements message queue with this depth
 */
#define LOG_MAX 5 /* log-queue length */

/** @def RANDFILE
 *  @brief Entropy source for random number generation
 *  
 *  Device file providing cryptographic random numbers for DNS query IDs,
 *  source port randomization, and other security-critical random values.
 *  
 *  Default: /dev/urandom (non-blocking random device)
 *  Platform: Standard on Linux, BSD, macOS, Solaris
 *  Security: Query ID randomization prevents cache poisoning attacks
 *  
 *  Source: src/util.c reads entropy from this device
 */
#define RANDFILE "/dev/urandom"

/** @def DNSMASQ_SERVICE
 *  @brief D-Bus service name for control interface
 *  
 *  Service name registered on D-Bus system bus for programmatic control
 *  and monitoring. Follows reverse-domain naming convention.
 *  
 *  Default: "uk.org.thekelleys.dnsmasq"
 *  Tunable via: --dbus-service-name command-line option
 *  Platform: Linux, BSD, macOS with D-Bus daemon installed
 *  
 *  Source: src/dbus.c registers this service name on system bus
 *  Dependency: Requires HAVE_DBUS and libdbus-1
 */
#define DNSMASQ_SERVICE "uk.org.thekelleys.dnsmasq" /* Default - may be overridden by config */

/** @def DNSMASQ_PATH
 *  @brief D-Bus object path for control interface
 *  
 *  Object path where D-Bus methods and properties are exposed. Matches
 *  service name following D-Bus conventions.
 *  
 *  Default: "/uk/org/thekelleys/dnsmasq"
 *  Platform: D-Bus path namespace
 *  
 *  Source: src/dbus.c exposes object at this path
 *  Dependency: Requires HAVE_DBUS
 */
#define DNSMASQ_PATH "/uk/org/thekelleys/dnsmasq"

/** @def DNSMASQ_UBUS_NAME
 *  @brief UBus service name for control interface (OpenWrt)
 *  
 *  Service name registered on UBus system bus for programmatic control
 *  on OpenWrt and embedded Linux systems using UBus IPC.
 *  
 *  Default: "dnsmasq"
 *  Tunable via: --ubus-name command-line option
 *  Platform: OpenWrt, LEDE, and other embedded distributions
 *  
 *  Source: src/ubus.c registers this service name on UBus
 *  Dependency: Requires HAVE_UBUS and libubus
 */
#define DNSMASQ_UBUS_NAME "dnsmasq" /* Default - may be overridden by config */

/** @def AUTH_TTL
 *  @brief Default TTL for authoritative DNS responses
 *  
 *  Time-to-live assigned to records served from authoritative zones when
 *  operating in authoritative DNS mode (--auth-zone configuration).
 *  
 *  Default: 600 seconds (10 minutes)
 *  Tunable via: --auth-ttl command-line option
 *  Purpose: Balance caching efficiency vs. record staleness
 *  
 *  Source: src/auth.c assigns this TTL to authoritative responses
 *  Dependency: Requires HAVE_AUTH
 */
#define AUTH_TTL 600 /* default TTL for auth DNS */

/** @def SOA_REFRESH
 *  @brief SOA record refresh interval for authoritative zones
 *  
 *  Seconds between zone refresh attempts by secondary nameservers. Used in
 *  automatically generated SOA records for authoritative zones.
 *  
 *  Default: 1200 seconds (20 minutes)
 *  Standards: RFC 1035 Section 3.3.13 (SOA RDATA format)
 *  Purpose: Secondary server zone synchronization interval
 *  
 *  Source: src/auth.c generates SOA records with this refresh value
 *  Dependency: Requires HAVE_AUTH
 */
#define SOA_REFRESH 1200 /* SOA refresh default */

/** @def SOA_RETRY
 *  @brief SOA record retry interval for authoritative zones
 *  
 *  Seconds between retry attempts when refresh fails. Used in SOA records
 *  for authoritative zones.
 *  
 *  Default: 180 seconds (3 minutes)
 *  Standards: RFC 1035 Section 3.3.13
 *  Purpose: Failed refresh retry interval
 *  
 *  Source: src/auth.c generates SOA records with this retry value
 *  Dependency: Requires HAVE_AUTH
 */
#define SOA_RETRY 180 /* SOA retry default */

/** @def SOA_EXPIRY
 *  @brief SOA record expiry time for authoritative zones
 *  
 *  Seconds after which secondary stops answering queries if unable to refresh.
 *  Used in SOA records for authoritative zones.
 *  
 *  Default: 1209600 seconds (14 days)
 *  Standards: RFC 1035 Section 3.3.13
 *  Purpose: Zone data validity period without primary contact
 *  
 *  Source: src/auth.c generates SOA records with this expiry value
 *  Dependency: Requires HAVE_AUTH
 */
#define SOA_EXPIRY 1209600 /* SOA expiry default */

/** @def LOOP_TEST_DOMAIN
 *  @brief Domain name used for DNS forwarding loop detection
 *  
 *  Special query sent to detect forwarding loops where dnsmasq forwards
 *  queries to upstream that forward back to dnsmasq.
 *  
 *  Default: "test" (reserved by RFC 2606, won't clash with real domains)
 *  Standards: RFC 2606 reserves "test" TLD for testing
 *  Purpose: Detect and break DNS forwarding loops
 *  
 *  Source: src/loop.c sends queries to this domain for loop detection
 *  Dependency: Requires HAVE_LOOP
 */
#define LOOP_TEST_DOMAIN "test" /* domain for loop testing, "test" is reserved by RFC 2606 and won't therefore clash */

/** @def LOOP_TEST_TYPE
 *  @brief DNS query type used for loop detection queries
 *  
 *  Query type for loop detection probes sent to LOOP_TEST_DOMAIN.
 *  
 *  Default: T_TXT (text record)
 *  Purpose: Distinctive query type for loop detection mechanism
 *  
 *  Source: src/loop.c constructs loop detection queries with this type
 *  Dependency: Requires HAVE_LOOP
 */
#define LOOP_TEST_TYPE T_TXT

/** @def DEFAULT_FAST_RETRY
 *  @brief Default delay in milliseconds before fast retry to next upstream
 *  
 *  When upstream server fails immediately (connection refused, etc.), wait
 *  this short interval before trying next server instead of full TIMEOUT.
 *  
 *  Default: 1000 milliseconds (1 second)
 *  Tunable via: --fast-dns-retry command-line option (added recent versions)
 *  Purpose: Faster failover for immediately failing upstreams
 *  
 *  Source: src/forward.c implements fast retry logic
 */
#define DEFAULT_FAST_RETRY 1000 /* ms, default delay before fast retry */

/** @def STALE_CACHE_EXPIRY
 *  @brief Maximum age in seconds for serving stale cache data
 *  
 *  When all upstreams unavailable, serve stale cached data if less than this
 *  age. Allows continued operation during upstream outages.
 *  
 *  Default: 86400 seconds (1 day)
 *  Tunable via: --use-stale-cache command-line option
 *  Purpose: Graceful degradation when upstreams unreachable
 *  
 *  Source: src/cache.c checks age before serving stale entries
 */
#define STALE_CACHE_EXPIRY 86400 /* 1 day in secs, default maximum expiry time for stale cache data */
 
/**
 * COMPILE-TIME FEATURE CONFIGURATION
 * 
 * This section documents all compile-time feature flags that control which capabilities
 * are included in the dnsmasq binary. Features can be enabled/disabled via:
 *   - Uncommenting #define statements below
 *   - Make command line: make COPTS=-DHAVE_<FEATURE>
 *   - Make command line: make COPTS=-DNO_<FEATURE> (to disable defaults)
 * 
 * FEATURE DEPENDENCY MATRIX:
 *   HAVE_DHCP6 → requires HAVE_DHCP
 *   HAVE_LUASCRIPT → requires HAVE_SCRIPT
 *   HAVE_DNSSEC → optional dependency on libgmp (can use mini-gmp via NO_GMP)
 * 
 * DEFAULT BUILD CONFIGURATION:
 *   Enabled by default: HAVE_DHCP, HAVE_DHCP6, HAVE_TFTP, HAVE_SCRIPT, HAVE_AUTH,
 *                       HAVE_IPSET, HAVE_LOOP, HAVE_DUMPFILE
 *   Disabled by default (require external libraries): HAVE_LUASCRIPT, HAVE_DBUS, 
 *                       HAVE_IDN, HAVE_LIBIDN2, HAVE_CONNTRACK, HAVE_DNSSEC, HAVE_NFTSET
 */

/* ============================================================================
 * EMBEDDED SYSTEM SUPPORT
 * ============================================================================ */

/**
 * HAVE_BROKEN_RTC
 * 
 * FEATURE: Support for embedded systems without stable Real-Time Clock (RTC)
 * 
 * PURPOSE:
 *   Enables operation on devices where RTC does not persist across reboots (common
 *   in embedded routers and appliances). Changes time handling to use uptime instead
 *   of epoch time, and modifies lease file behavior for flash-friendly operation.
 * 
 * AFFECTED MODULES:
 *   - src/lease.c: Lease time tracking uses uptime instead of absolute timestamps
 *   - src/dhcp.c: Lease expiration calculations based on uptime deltas
 *   - src/dhcp6.c: DHCPv6 lease time handling
 * 
 * BEHAVIORAL CHANGES:
 *   - Lease file stores lease duration (seconds) instead of expiration timestamp
 *   - Lease file writes minimized: only on lease create/destroy, not on renewal
 *   - Drastically reduces flash write cycles (from hundreds per hour to <10 per day)
 * 
 * IMPACT:
 *   + Suitable for flash-based storage (reduces wear, improves longevity)
 *   + Lower I/O overhead (fewer disk writes)
 *   - Lease times are relative, not absolute (minor operational difference)
 * 
 * MIGRATION WARNING:
 *   When enabling or disabling this flag, DELETE existing leases file. Time format
 *   change makes old lease file incompatible and may cause parsing errors or
 *   incorrect lease expiration calculations.
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: Negligible (<1KB code change)
 */

/* ============================================================================
 * NETWORK BOOT SERVICES
 * ============================================================================ */

/**
 * HAVE_TFTP
 * 
 * FEATURE: Built-in TFTP (Trivial File Transfer Protocol) server
 * 
 * PURPOSE:
 *   Provides read-only TFTP server for network boot scenarios (PXE boot, diskless
 *   workstations). Eliminates need for separate TFTP daemon deployment.
 * 
 * AFFECTED MODULES:
 *   - src/tftp.c: Complete TFTP server implementation
 *   - src/dnsmasq.c: TFTP listener initialization in main event loop
 *   - src/network.c: TFTP socket binding (UDP port 69)
 * 
 * CAPABILITIES:
 *   - RFC 1350: Basic TFTP protocol (read requests only, no write support)
 *   - RFC 2349: Option negotiation (blksize, tsize, timeout)
 *   - RFC 7440: Windowsize option for improved transfer performance
 *   - Concurrent connection limit (TFTP_MAX_CONNECTIONS=50)
 *   - Secure mode with file ownership verification
 *   - Per-interface TFTP root directories
 * 
 * INTEGRATION:
 *   Works seamlessly with HAVE_DHCP for complete PXE boot infrastructure. DHCP
 *   provides boot filename via option 67, TFTP serves the boot image.
 * 
 * IMPACT:
 *   + Unified DHCP+TFTP deployment for network boot
 *   + No separate TFTP daemon required
 *   - Adds ~15-20KB to binary size
 *   - Requires root privileges to bind port 69
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: ~15-20KB
 * DEFAULT: Enabled
 */

/* ============================================================================
 * DHCP SERVICES
 * ============================================================================ */

/**
 * HAVE_DHCP
 * 
 * FEATURE: DHCPv4 server (Dynamic Host Configuration Protocol for IPv4)
 * 
 * PURPOSE:
 *   Complete DHCPv4 server implementation conforming to RFC 2131. Provides automatic
 *   IPv4 address assignment, network configuration distribution, and integrated
 *   DNS hostname registration.
 * 
 * AFFECTED MODULES:
 *   - src/dhcp.c: DHCPv4 server core logic and packet processing
 *   - src/rfc2131.c: RFC 2131 protocol implementation (DISCOVER/OFFER/REQUEST/ACK)
 *   - src/dhcp-common.c: Shared DHCP utilities
 *   - src/lease.c: Lease database management and persistence
 *   - src/cache.c: DNS integration for DHCP-assigned hostnames
 *   - src/network.c: DHCP socket binding (UDP port 67)
 * 
 * CAPABILITIES:
 *   - Static lease reservations (MAC-to-IP binding)
 *   - Dynamic lease allocation from configured pools
 *   - BOOTP protocol support for legacy clients
 *   - Comprehensive DHCP option support (options 1-161)
 *   - Tag-based client classification and configuration
 *   - Lease database persistence across daemon restarts
 *   - Automatic DNS registration of client hostnames
 *   - DHCPv4 rapid commit (RFC 4039)
 *   - DHCPv4 leasequery (RFC 4388, added in v2.92)
 *   - Relay agent support for remote network segments
 * 
 * PERFORMANCE CHARACTERISTICS:
 *   - Maximum concurrent leases: MAXLEASES=1000 (default)
 *   - Default lease time: DEFLEASE=3600 seconds (1 hour)
 *   - Lease allocation latency: typically <10ms
 * 
 * INTEGRATION:
 *   - DNS: DHCP hostnames automatically resolvable via integrated DNS cache
 *   - TFTP/PXE: Provides boot parameters via DHCP options 60, 67, 93
 *   - Scripts: Lease-change events trigger external scripts (requires HAVE_SCRIPT)
 * 
 * IMPACT:
 *   + Unified DNS-DHCP management eliminates configuration drift
 *   + Automatic hostname-to-IP resolution for dynamic clients
 *   - Adds ~40-50KB to binary size
 *   - Requires root privileges to bind port 67
 * 
 * DEPENDENCIES: None (but HAVE_DHCP6 requires HAVE_DHCP)
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: ~40-50KB
 * DEFAULT: Enabled
 */

/**
 * HAVE_DHCP6
 * 
 * FEATURE: DHCPv6 server and IPv6 Router Advertisement
 * 
 * PURPOSE:
 *   Complete DHCPv6 implementation (RFC 3315) with Router Advertisement (RFC 4861)
 *   for coordinated IPv6 address management. Supports stateful (managed addressing),
 *   stateless (configuration only), and SLAAC (router advertisement only) modes.
 * 
 * AFFECTED MODULES:
 *   - src/dhcp6.c: DHCPv6 server implementation
 *   - src/rfc3315.c: RFC 3315 protocol (SOLICIT/ADVERTISE/REQUEST/REPLY)
 *   - src/outpacket.c: DHCPv6 option serialization
 *   - src/radv.c: IPv6 Router Advertisement (ICMPv6 type 134)
 *   - src/slaac.c: SLAAC address confirmation and duplicate detection
 *   - src/dhcp-common.c: Shared DHCPv4/DHCPv6 utilities
 *   - src/lease.c: IPv6 lease tracking
 * 
 * CAPABILITIES:
 *   - Stateful DHCPv6: Full address assignment and lease tracking
 *   - Stateless DHCPv6: Configuration parameters only (DNS servers, domain search)
 *   - Router Advertisement: Prefix information, M/O flags, RDNSS options
 *   - SLAAC support: Stateless Address Autoconfiguration coordination
 *   - IPv6 prefix delegation (RFC 3633) for hierarchical networks
 *   - Rapid commit optimization
 * 
 * OPERATIONAL MODES:
 *   - M=1, O=1: Stateful DHCPv6 (managed addresses and configuration)
 *   - M=0, O=1: Stateless DHCPv6 (SLAAC addresses, DHCPv6 configuration)
 *   - M=0, O=0: SLAAC only (no DHCPv6)
 * 
 * PERFORMANCE CHARACTERISTICS:
 *   - Default lease time: DEFLEASE6=86400 seconds (24 hours)
 *   - Router Advertisement transmission: periodic (every few seconds)
 * 
 * INTEGRATION:
 *   - Coordinates with Router Advertisement for M/O flag configuration
 *   - DNS integration for DHCPv6-assigned hostnames
 *   - Works alongside DHCPv4 for dual-stack networks
 * 
 * IMPACT:
 *   + Complete IPv6 address management solution
 *   + Flexible deployment models (stateful/stateless/SLAAC)
 *   - Adds ~25-35KB to binary size
 *   - Requires root privileges to send ICMPv6 Router Advertisement
 * 
 * DEPENDENCIES: HAVE_DHCP (required, enforced at compile time)
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: ~25-35KB
 * DEFAULT: Enabled (if HAVE_DHCP enabled)
 */

/* ============================================================================
 * INTEGRATION AND AUTOMATION
 * ============================================================================ */

/**
 * HAVE_SCRIPT
 * 
 * FEATURE: External script execution on DHCP lease events
 * 
 * PURPOSE:
 *   Enables integration with external systems through script execution on DHCP
 *   lease lifecycle events (add, renew, delete). Supports custom automation,
 *   dynamic DNS updates, firewall rule generation, and monitoring integration.
 * 
 * AFFECTED MODULES:
 *   - src/helper.c: Fork-based script execution management
 *   - src/lease.c: Script invocation on lease events
 *   - src/dhcp.c: DHCPv4 lease event triggers
 *   - src/dhcp6.c: DHCPv6 lease event triggers
 * 
 * SCRIPT INVOCATION:
 *   Command line: <script> <action> <mac> <ip> <hostname>
 *   Actions: "add" (new lease), "old" (renewal), "del" (expiration/release)
 *   Environment variables: DNSMASQ_LEASE_LENGTH, DNSMASQ_CLIENT_ID, 
 *                          DNSMASQ_INTERFACE, DNSMASQ_SUPPLIED_HOSTNAME
 * 
 * EXECUTION MODEL:
 *   - Fork-based subprocess execution (non-blocking)
 *   - Script failures logged but non-fatal (advisory execution)
 *   - Exit status collected and logged
 * 
 * COMMON USE CASES:
 *   - Dynamic DNS updates (nsupdate integration)
 *   - Firewall rule generation based on client identity
 *   - Configuration management system notifications
 *   - Asset tracking and inventory systems
 *   - Custom logging and auditing
 * 
 * SECURITY CONSIDERATIONS:
 *   - Scripts execute with daemon privileges (typically unprivileged user)
 *   - Hostname and parameters are sanitized to prevent shell injection
 *   - Script path should be absolute and script should have restrictive permissions
 * 
 * IMPACT:
 *   + Flexible integration with external systems
 *   + Event-driven automation without daemon modification
 *   - Fork overhead on lease events (~1-5ms per invocation)
 *   - Script execution failures may go unnoticed without monitoring
 * 
 * DEPENDENCIES: None (but HAVE_LUASCRIPT requires HAVE_SCRIPT)
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: ~5-10KB
 * DEFAULT: Enabled
 */

/**
 * HAVE_LUASCRIPT
 * 
 * FEATURE: Embedded Lua scripting for DHCP lease events
 * 
 * PURPOSE:
 *   Provides Lua scripting alternative to external scripts for lease event handling.
 *   Reduces process creation overhead, improves performance, and enables more
 *   sophisticated event processing with embedded interpreter.
 * 
 * AFFECTED MODULES:
 *   - src/helper.c: Lua interpreter integration and function invocation
 *   - src/lease.c: Lua function calls on lease events
 * 
 * ADVANTAGES OVER HAVE_SCRIPT:
 *   - No fork/exec overhead (embedded interpreter)
 *   - Lua function invocation latency <1ms (vs. 1-5ms for fork)
 *   - Stateful processing (Lua environment persists across invocations)
 *   - More sophisticated logic possible within scripting environment
 * 
 * SCRIPT INVOCATION:
 *   Lua function: lease_event(action, mac, ip, hostname)
 *   Same action values as HAVE_SCRIPT: "add", "old", "del"
 *   Additional context available through Lua environment
 * 
 * IMPACT:
 *   + Better performance than external scripts (no process creation)
 *   + Stateful processing capabilities
 *   - Requires Lua library dependency (~200-300KB)
 *   - Script errors may affect daemon stability (crash/hang)
 * 
 * DEPENDENCIES: HAVE_SCRIPT (required, enforced at compile time)
 * EXTERNAL LIBRARIES: Lua library (liblua5.x)
 * BINARY SIZE IMPACT: Minimal to dnsmasq (+5KB), but Lua library adds 200-300KB
 * DEFAULT: Disabled (requires explicit enable and Lua library)
 */

/* ============================================================================
 * CONTROL INTERFACES
 * ============================================================================ */

/**
 * HAVE_DBUS
 * 
 * FEATURE: D-Bus control interface on system bus
 * 
 * PURPOSE:
 *   Exposes programmatic control interface on D-Bus system bus, enabling external
 *   applications to query cache statistics, manipulate cache contents, reconfigure
 *   upstream servers, and retrieve configuration status without daemon restart.
 * 
 * AFFECTED MODULES:
 *   - src/dbus.c: Complete D-Bus interface implementation
 *   - src/dnsmasq.c: D-Bus service registration in main loop
 *   - src/cache.c: Cache query and manipulation methods
 *   - src/forward.c: Upstream server reconfiguration
 * 
 * D-BUS INTERFACE:
 *   Service name: uk.org.thekelleys.dnsmasq (configurable)
 *   Object path: /uk/org/thekelleys/dnsmasq
 *   Methods: ClearCache, GetCacheStats, SetServers, SetServersEx, GetVersion
 * 
 * ACCESS CONTROL:
 *   Policy file: /etc/dbus-1/system.d/dnsmasq.conf
 *   Restricted to: root user and netadmin group members
 * 
 * USE CASES:
 *   - Network management tools integrating dnsmasq control
 *   - Monitoring systems querying cache hit rates
 *   - Security tools clearing cache entries for compromised domains
 *   - VPN software dynamically adjusting upstream DNS servers
 * 
 * IMPACT:
 *   + Programmatic management and monitoring capabilities
 *   + Standards-based IPC (D-Bus widely supported on Linux)
 *   - Requires D-Bus daemon running
 *   - Adds ~10-15KB to binary size
 *   - D-Bus library dependency (~100-150KB)
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: libdbus-1
 * BINARY SIZE IMPACT: ~10-15KB (plus libdbus-1 ~100-150KB)
 * DEFAULT: Disabled (requires explicit enable and libdbus-1)
 */

/**
 * HAVE_UBUS
 * 
 * FEATURE: UBus control interface (OpenWrt/embedded Linux)
 * 
 * PURPOSE:
 *   Provides UBus IPC interface for OpenWrt and embedded Linux distributions.
 *   Functionally similar to HAVE_DBUS but optimized for resource-constrained
 *   embedded systems with lighter memory footprint and simpler protocol.
 * 
 * AFFECTED MODULES:
 *   - src/ubus.c: Complete UBus interface implementation
 *   - src/dnsmasq.c: UBus service registration
 * 
 * UBUS INTERFACE:
 *   Service name: "dnsmasq" (configurable via DNSMASQ_UBUS_NAME)
 *   Methods: Similar to D-Bus (cache query, upstream reconfiguration, metrics)
 *   Protocol: JSON-RPC style messages over UBus binary protocol
 * 
 * PLATFORM TARGET:
 *   - OpenWrt routers and embedded appliances
 *   - LEDE firmware derivatives
 *   - Custom embedded Linux distributions using UBus
 * 
 * INTEGRATION:
 *   - OpenWrt LuCI web interface control
 *   - uci (Unified Configuration Interface) integration
 *   - OpenWrt system management tools
 * 
 * IMPACT:
 *   + Native OpenWrt/embedded system integration
 *   + Lighter weight than D-Bus (~50KB total vs. 150KB)
 *   + Better suited for embedded environments
 *   - Platform-specific (primarily OpenWrt ecosystem)
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: libubox, libubus
 * BINARY SIZE IMPACT: ~5-10KB (plus libubus ~40-50KB)
 * DEFAULT: Disabled (OpenWrt-specific feature)
 */

/* ============================================================================
 * INTERNATIONALIZATION
 * ============================================================================ */

/**
 * HAVE_IDN
 * 
 * FEATURE: Internationalized Domain Names (IDN 2003 standard)
 * 
 * PURPOSE:
 *   Enables resolution of domain names containing non-ASCII characters (Unicode)
 *   using IDN 2003 specification (RFC 3490). Converts between Unicode representation
 *   and ASCII-Compatible Encoding (Punycode) used in DNS wire protocol.
 * 
 * AFFECTED MODULES:
 *   - Integrated throughout DNS modules (forward.c, cache.c, rfc1035.c)
 *   - Hostname validation and conversion at query processing boundaries
 * 
 * CONVERSION PROCESS:
 *   - Input: UTF-8 encoded domain names (e.g., "münchen.de")
 *   - Internal: Punycode conversion (e.g., "xn--mnchen-3ya.de")
 *   - Wire format: ASCII-compatible representation in DNS packets
 * 
 * EXAMPLES:
 *   - German: münchen.de → xn--mnchen-3ya.de
 *   - Russian: президент.рф → xn--d1abbgf6aiiy.xn--p1ai
 *   - Chinese: 中国.cn → xn--fiqs8s.cn
 * 
 * MUTUAL EXCLUSIVITY:
 *   HAVE_IDN and HAVE_LIBIDN2 are mutually exclusive. Only one may be enabled.
 *   HAVE_LIBIDN2 is preferred for new deployments (newer standard, better security).
 * 
 * IMPACT:
 *   + Support for internationalized domain names
 *   + Global accessibility for non-English speaking users
 *   - Adds ~5KB to binary size
 *   - libidn dependency (~100-150KB)
 *   - Slightly increased query processing latency for non-ASCII domains
 * 
 * DEPENDENCIES: None (mutually exclusive with HAVE_LIBIDN2)
 * EXTERNAL LIBRARIES: libidn
 * BINARY SIZE IMPACT: ~5KB (plus libidn ~100-150KB)
 * DEFAULT: Disabled (requires explicit enable and libidn)
 */

/**
 * HAVE_LIBIDN2
 * 
 * FEATURE: Internationalized Domain Names (IDN 2008 standard / IDNA2008)
 * 
 * PURPOSE:
 *   Modern IDN implementation using IDN 2008 specification (RFC 5891). Provides
 *   improved security and correctness compared to IDN 2003, with better handling
 *   of edge cases and character normalization.
 * 
 * AFFECTED MODULES:
 *   - Integrated throughout DNS modules (same as HAVE_IDN)
 * 
 * ADVANTAGES OVER IDN 2003 (HAVE_IDN):
 *   - Better Unicode normalization and character validation
 *   - Improved security against homograph attacks
 *   - More consistent handling of edge cases
 *   - Actively maintained standard (IDN 2003 deprecated)
 * 
 * EXAMPLES:
 *   Same conversion process as HAVE_IDN but with improved validation and normalization.
 * 
 * MUTUAL EXCLUSIVITY:
 *   HAVE_IDN and HAVE_LIBIDN2 are mutually exclusive. Only one may be enabled.
 *   HAVE_LIBIDN2 is RECOMMENDED for all new deployments.
 * 
 * IMPACT:
 *   + Modern IDN standard with better security
 *   + Preferred over HAVE_IDN for new installations
 *   - Similar resource impact to HAVE_IDN
 * 
 * DEPENDENCIES: None (mutually exclusive with HAVE_IDN)
 * EXTERNAL LIBRARIES: libidn2
 * BINARY SIZE IMPACT: ~5KB (plus libidn2 ~100-150KB)
 * DEFAULT: Disabled (requires explicit enable and libidn2)
 */

/* ============================================================================
 * FIREWALL INTEGRATION
 * ============================================================================ */

/**
 * HAVE_CONNTRACK
 * 
 * FEATURE: Linux connection tracking (conntrack) mark propagation
 * 
 * PURPOSE:
 *   Integrates with Linux netfilter connection tracking to propagate conntrack marks
 *   from incoming DNS queries to corresponding upstream queries. Enables advanced
 *   routing policies and QoS based on DNS query source.
 * 
 * AFFECTED MODULES:
 *   - src/conntrack.c: libnetfilter_conntrack integration
 *   - src/forward.c: Conntrack mark preservation during query forwarding
 * 
 * OPERATION:
 *   1. Extract conntrack mark from incoming DNS query connection
 *   2. Apply same mark to upstream DNS query connection
 *   3. Enables policy-based routing using iptables/nftables rules based on marks
 * 
 * USE CASES:
 *   - Policy-based routing: Route DNS queries through specific interfaces based on source
 *   - QoS: Prioritize DNS traffic from certain sources
 *   - VPN split tunneling: Send DNS queries for specific clients through VPN
 *   - Traffic accounting: Track DNS query volume per client/mark
 * 
 * REQUIREMENTS:
 *   - Linux kernel with CONFIG_NETFILTER_CONNTRACK enabled
 *   - iptables/nftables rules to set initial conntrack marks
 *   - Requires CAP_NET_ADMIN capability or root privileges
 * 
 * IMPACT:
 *   + Advanced routing and QoS capabilities
 *   + Integrates with existing netfilter/iptables infrastructure
 *   - Linux-specific (not portable to BSD/other Unix)
 *   - Adds ~5-10KB to binary size
 *   - libnetfilter_conntrack dependency (~50-100KB)
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: libnetfilter_conntrack
 * BINARY SIZE IMPACT: ~5-10KB (plus libnetfilter_conntrack ~50-100KB)
 * DEFAULT: Disabled (Linux-specific advanced feature)
 */

/**
 * HAVE_IPSET
 * 
 * FEATURE: Linux ipset integration for dynamic firewall rules
 * 
 * PURPOSE:
 *   Adds resolved IP addresses to named ipset collections, enabling dynamic firewall
 *   rule application based on DNS resolution. Supports domain-based filtering and
 *   security policies that automatically adapt as IP addresses change.
 * 
 * AFFECTED MODULES:
 *   - src/ipset.c: ipset netlink API and legacy API integration
 *   - src/forward.c: IP address addition on successful DNS resolution
 *   - src/cache.c: ipset population from cache lookups
 * 
 * OPERATION:
 *   1. DNS query resolved (e.g., "ads.example.com" → 192.0.2.50)
 *   2. Resolved IP added to configured ipset (e.g., "adblock" set)
 *   3. iptables rules match ipset to block/allow/route traffic
 * 
 * IPSET API SUPPORT:
 *   - Legacy ipset API: Direct kernel interface
 *   - Modern netlink API: Kernel netlink socket interface
 *   - Automatic detection and fallback between APIs
 * 
 * USE CASES:
 *   - Content filtering: Block advertising/malware domains by populating block ipsets
 *   - Access control: Allow/deny traffic to resolved IPs based on domain category
 *   - Policy routing: Route traffic to specific domains through particular interfaces
 *   - Traffic accounting: Track bandwidth usage to domain categories
 * 
 * CONFIGURATION EXAMPLE:
 *   ipset=/example.com/myset      # Add IPs for example.com to "myset"
 *   ipset=/.ads.example.com/adblock # Add advertising subdomain IPs to "adblock"
 * 
 * REQUIREMENTS:
 *   - ipset kernel module loaded
 *   - ipset must exist before dnsmasq starts (created via "ipset create")
 *   - Requires CAP_NET_ADMIN capability or root privileges
 * 
 * IMPACT:
 *   + Domain-based firewall rules that adapt to IP changes
 *   + No manual IP address tracking required
 *   + Integrates with existing iptables infrastructure
 *   - Linux-specific (not portable)
 *   - Adds ~5-10KB to binary size
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None (uses kernel interfaces directly)
 * BINARY SIZE IMPACT: ~5-10KB
 * DEFAULT: Enabled (Linux-specific feature, no external library required)
 */

/**
 * HAVE_NFTSET
 * 
 * FEATURE: Linux nftables set integration
 * 
 * PURPOSE:
 *   Modern successor to HAVE_IPSET using nftables infrastructure. Adds resolved IP
 *   addresses to nftables sets, enabling domain-based packet filtering with the
 *   newer nftables firewall framework.
 * 
 * AFFECTED MODULES:
 *   - src/nftset.c: libnftables integration
 *   - src/forward.c: IP address addition on DNS resolution
 * 
 * OPERATION:
 *   Similar to HAVE_IPSET but uses nftables sets instead of ipsets.
 *   1. DNS query resolved → IP obtained
 *   2. IP added to configured nftables set
 *   3. nftables rules match set membership for policy enforcement
 * 
 * ADVANTAGES OVER IPSET:
 *   - Modern nftables infrastructure (successor to iptables)
 *   - Better performance for large rule sets
 *   - More flexible rule matching
 *   - Unified IPv4/IPv6 handling
 * 
 * USE CASES:
 *   Same as HAVE_IPSET: content filtering, access control, policy routing
 * 
 * CONFIGURATION EXAMPLE:
 *   nftset=/example.com/4#inet#filter#myset   # IPv4 addresses to inet/filter/myset
 *   nftset=/example.com/6#inet#filter#myset6  # IPv6 addresses to separate set
 * 
 * REQUIREMENTS:
 *   - Kernel with nftables support (Linux 3.13+)
 *   - nftables sets must exist before dnsmasq starts
 *   - Requires CAP_NET_ADMIN capability or root privileges
 * 
 * IMPACT:
 *   + Modern firewall integration (nftables is future of Linux firewalling)
 *   + Better performance than legacy iptables for large configurations
 *   - Requires libnftables library (~200-300KB)
 *   - Linux-specific (not portable)
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: libnftables
 * BINARY SIZE IMPACT: ~10-15KB (plus libnftables ~200-300KB)
 * DEFAULT: Disabled (requires explicit enable and libnftables)
 */

/* ============================================================================
 * ADVANCED DNS FEATURES
 * ============================================================================ */

/**
 * HAVE_AUTH
 * 
 * FEATURE: Authoritative DNS server mode
 * 
 * PURPOSE:
 *   Enables dnsmasq to act as authoritative nameserver for designated zones,
 *   responding authoritatively to queries within configured zones and supporting
 *   zone transfers (AXFR) to secondary nameservers. Complements forwarding mode
 *   for hosting local DNS zones.
 * 
 * AFFECTED MODULES:
 *   - src/auth.c: Complete authoritative DNS implementation
 *   - src/forward.c: Integration with forwarding path (auth zones bypass forwarding)
 *   - src/cache.c: Authoritative zone data integration
 * 
 * CAPABILITIES:
 *   - Primary authoritative server for configured zones
 *   - SOA record generation with configurable parameters
 *   - Zone transfer (AXFR) to secondary nameservers
 *   - Per-zone subnet filtering for split-horizon DNS
 *   - Support for A, AAAA, PTR, CNAME, MX, SRV, TXT, NAPTR records
 * 
 * SOA PARAMETERS (from constants above):
 *   - Default TTL: AUTH_TTL=600 seconds
 *   - Refresh: SOA_REFRESH=1200 seconds
 *   - Retry: SOA_RETRY=180 seconds
 *   - Expiry: SOA_EXPIRY=1209600 seconds (14 days)
 * 
 * USE CASES:
 *   - Hosting small internal DNS zones without separate authoritative server
 *   - Split-horizon DNS: different responses for internal vs. external queries
 *   - Local network zones (e.g., ".local", ".lan", ".internal")
 *   - Reverse DNS zones for private networks
 * 
 * CONFIGURATION EXAMPLE:
 *   auth-zone=example.com,192.168.1.0/24     # Authoritative for example.com
 *   auth-server=ns1.example.com,eth0         # NS record and serving interface
 * 
 * IMPACT:
 *   + Eliminates need for separate authoritative DNS server
 *   + Simplified internal DNS zone management
 *   - Adds ~15-20KB to binary size
 *   - Not suitable for high-volume public authoritative service
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: ~15-20KB
 * DEFAULT: Enabled
 */

/**
 * HAVE_DNSSEC
 * 
 * FEATURE: DNSSEC validation (DNS Security Extensions)
 * 
 * PURPOSE:
 *   Implements complete DNSSEC validation chain to cryptographically verify DNS
 *   responses, protecting against cache poisoning, man-in-the-middle attacks, and
 *   domain hijacking. Validates RRSIG signatures, DNSKEY records, DS records, and
 *   processes NSEC/NSEC3 denial-of-existence proofs.
 * 
 * AFFECTED MODULES:
 *   - src/dnssec.c: Complete DNSSEC validation implementation
 *   - src/crypto.c: Cryptographic operations wrapper (Nettle library interface)
 *   - src/forward.c: DNSSEC-aware query forwarding (DO bit, CD bit handling)
 *   - src/cache.c: DNSKEY and DS record caching, validation state storage
 * 
 * VALIDATION PROCESS:
 *   1. Verify RRSIG signatures on RRsets
 *   2. Validate DNSKEY records against DS records in parent zone
 *   3. Traverse trust chain from root zone to target domain
 *   4. Validate against trust anchors (trust-anchors.conf)
 *   5. Process NSEC/NSEC3 proofs for non-existent names
 * 
 * VALIDATION STATES:
 *   - SECURE: Valid signatures, complete trust chain to trust anchor
 *   - INSECURE: Unsigned zone (not an error, zone not DNSSEC-enabled)
 *   - BOGUS: Invalid signatures or broken trust chain (return SERVFAIL)
 * 
 * DOS PROTECTION LIMITS (from constants above):
 *   - Max queries per validation: DNSSEC_LIMIT_WORK=40
 *   - Max signature failures: DNSSEC_LIMIT_SIG_FAIL=20
 *   - Max crypto operations: DNSSEC_LIMIT_CRYPTO=200
 *   - Max NSEC3 iterations: DNSSEC_LIMIT_NSEC3_ITERS=150
 * 
 * CRYPTOGRAPHIC ALGORITHMS SUPPORTED (via Nettle):
 *   - RSA/SHA-1, RSA/SHA-256, RSA/SHA-512
 *   - ECDSA/SHA-256, ECDSA/SHA-384
 *   - EdDSA (Ed25519, Ed448)
 * 
 * TRUST ANCHOR MANAGEMENT:
 *   - Trust anchors stored in trust-anchors.conf (root zone KSK)
 *   - Manual updates required on root KSK rollover (monitor IANA announcements)
 *   - RFC 5011 automated trust anchor update not currently implemented
 * 
 * IMPACT:
 *   + Protection against DNS-based attacks (cache poisoning, spoofing)
 *   + Cryptographic integrity and authenticity verification
 *   + Compliance with security-conscious network policies
 *   - Significant binary size increase (~30-40KB)
 *   - Nettle cryptography library dependency (300-500KB)
 *   - Increased query latency for validated responses (typically 50-200ms)
 *   - Higher CPU usage for signature verification
 * 
 * DEPENDENCIES: None (optional NO_GMP to use Nettle's mini-gmp)
 * EXTERNAL LIBRARIES: nettle, hogweed; optional: libgmp (can use mini-gmp with NO_GMP)
 * BINARY SIZE IMPACT: ~30-40KB (plus Nettle ~300-500KB)
 * DEFAULT: Disabled (requires explicit enable and Nettle library)
 */

/* ============================================================================
 * DEBUGGING AND MONITORING
 * ============================================================================ */

/**
 * HAVE_DUMPFILE
 * 
 * FEATURE: Packet capture to libpcap format for debugging
 * 
 * PURPOSE:
 *   Enables packet dumping to libpcap-format files for detailed protocol analysis
 *   and troubleshooting. Captures DNS queries and responses in format compatible
 *   with Wireshark and tcpdump for offline analysis.
 * 
 * AFFECTED MODULES:
 *   - src/dump.c: libpcap file format writer
 *   - src/forward.c: Packet capture hook points
 *   - src/dhcp.c: DHCP packet capture (if enabled)
 * 
 * OPERATION:
 *   Configured via --dumpfile=<path> option. Captures all DNS and DHCP packets
 *   (queries and responses) to specified file in pcap format.
 * 
 * USE CASES:
 *   - Debugging DNS resolution issues
 *   - Analyzing query patterns and response times
 *   - Troubleshooting DNSSEC validation failures
 *   - Protocol conformance testing
 *   - Performance analysis
 * 
 * ANALYSIS TOOLS:
 *   - Wireshark: GUI packet analyzer
 *   - tcpdump: Command-line packet analyzer
 *   - tshark: Command-line Wireshark
 * 
 * IMPACT:
 *   + Detailed protocol-level troubleshooting capability
 *   + Compatible with standard analysis tools
 *   - File I/O overhead during packet processing
 *   - Disk space consumption (can be substantial under load)
 *   - Should NOT be enabled in production (performance and disk impact)
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None (implements libpcap format directly)
 * BINARY SIZE IMPACT: ~5-10KB
 * DEFAULT: Enabled (disabled via NO_DUMPFILE if needed)
 */

/**
 * HAVE_LOOP
 * 
 * FEATURE: DNS forwarding loop detection and prevention
 * 
 * PURPOSE:
 *   Detects and breaks DNS forwarding loops that can occur in complex network
 *   topologies where multiple DNS forwarders might create circular query paths.
 *   Prevents infinite query loops and associated resource exhaustion.
 * 
 * AFFECTED MODULES:
 *   - src/loop.c: Loop detection probe mechanism
 *   - src/forward.c: Loop detection integration in forwarding path
 * 
 * DETECTION MECHANISM:
 *   Periodically sends probe queries to special test domain (LOOP_TEST_DOMAIN="test",
 *   reserved by RFC 2606) with unique identifiers. If probe returns to originating
 *   dnsmasq instance, a loop is detected and upstream server is disabled.
 * 
 * LOOP SCENARIOS:
 *   - Network topology changes causing circular forwarding
 *   - Misconfigured upstream servers pointing back to dnsmasq
 *   - VPN configuration errors creating routing loops
 * 
 * REMEDIATION:
 *   - Detected loop causes upstream server to be temporarily disabled
 *   - Periodic retry to detect when loop condition resolves
 *   - Logging alerts administrator to configuration issue
 * 
 * IMPACT:
 *   + Prevents resource exhaustion from infinite query loops
 *   + Automatic detection and mitigation
 *   - Adds ~5KB to binary size
 *   - Minor overhead from periodic probe queries
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None
 * BINARY SIZE IMPACT: ~5KB
 * DEFAULT: Enabled
 */

/**
 * HAVE_INOTIFY
 * 
 * FEATURE: Linux inotify for efficient configuration file monitoring
 * 
 * PURPOSE:
 *   Uses Linux inotify facility to efficiently monitor configuration files,
 *   /etc/hosts, /etc/resolv.conf, and DHCP host files for changes. Enables
 *   automatic reload without manual SIGHUP signal or polling overhead.
 * 
 * AFFECTED MODULES:
 *   - src/inotify.c: inotify integration and event handling
 *   - src/dnsmasq.c: Configuration reload triggered by inotify events
 *   - src/option.c: File change detection integration
 * 
 * MONITORED FILES:
 *   - Configuration file: /etc/dnsmasq.conf (or configured path)
 *   - Hosts file: /etc/hosts
 *   - Resolv file: /etc/resolv.conf (for upstream server discovery)
 *   - DHCP hosts directories: Dynamically monitored per configuration
 * 
 * OPERATION:
 *   1. inotify watches established on monitored files and directories
 *   2. File modification triggers inotify event
 *   3. Event processed in main event loop
 *   4. Automatic configuration reload (equivalent to SIGHUP)
 * 
 * ADVANTAGES OVER POLLING:
 *   - Zero CPU usage when files unchanged (vs. periodic polling)
 *   - Immediate reload on file change (vs. polling interval delay)
 *   - Scales to many monitored files without overhead
 * 
 * IMPACT:
 *   + Efficient configuration change detection
 *   + Automatic reload without manual intervention
 *   + No polling overhead
 *   - Linux-specific (not portable to BSD/other Unix)
 *   - Adds ~5KB to binary size
 * 
 * DEPENDENCIES: None
 * EXTERNAL LIBRARIES: None (uses Linux kernel inotify interface)
 * BINARY SIZE IMPACT: ~5KB
 * DEFAULT: Disabled (can be enabled via NO_INOTIFY=0, Linux-specific)
 */

/* ============================================================================
 * FEATURE DISABLE FLAGS
 * ============================================================================ */

/**
 * NO_ID
 * 
 * PURPOSE: Disable CHAOS query responses for version.bind and other *.bind queries.
 *          Instead of responding locally with version information, forward these
 *          queries upstream.
 * 
 * SECURITY RATIONALE:
 *   Prevents information disclosure of dnsmasq version to potential attackers
 *   via CHAOS TXT queries (e.g., "dig version.bind chaos txt").
 * 
 * DEFAULT BEHAVIOR (without NO_ID):
 *   Queries to version.bind, authors.bind, copyright.bind, etc. return local
 *   information about dnsmasq version and build configuration.
 * 
 * IMPACT: Minimal (~1KB code removal if enabled)
 */

/**
 * NO_TFTP, NO_DHCP, NO_DHCP6, NO_SCRIPT, NO_AUTH, NO_DUMPFILE, NO_LOOP, NO_INOTIFY, NO_IPSET
 * 
 * PURPOSE: Explicitly disable features that would otherwise be enabled by default
 *          or through automatic detection.
 * 
 * USAGE:
 *   Build with: make COPTS=-DNO_<FEATURE>
 *   Example: make COPTS="-DNO_TFTP -DNO_SCRIPT"
 * 
 * RATIONALE:
 *   - Minimize binary size for embedded systems with strict storage constraints
 *   - Disable unneeded functionality for security hardening
 *   - Create specialized builds (e.g., DNS-only, no DHCP)
 * 
 * DEFAULT STATE:
 *   Without NO_* flags, the following are enabled by default:
 *   HAVE_DHCP, HAVE_DHCP6, HAVE_TFTP, HAVE_SCRIPT, HAVE_AUTH, HAVE_IPSET,
 *   HAVE_LOOP, HAVE_DUMPFILE
 */

/**
 * NO_LARGEFILE
 * 
 * PURPOSE: Disable large file support (64-bit file offsets) on 32-bit systems.
 * 
 * IMPACT:
 *   Without large file support, files >2GB cannot be accessed. Relevant only for
 *   lease file and TFTP file serving on systems with extremely large lease databases
 *   or boot images. Not typically needed, as lease files are small (<1MB typically).
 */

/**
 * NO_GMP
 * 
 * PURPOSE: Build DNSSEC support (HAVE_DNSSEC) without linking against libgmp
 *          (GNU Multi-Precision arithmetic library).
 * 
 * RATIONALE:
 *   The Nettle cryptography library can be built with --enable-mini-gmp to use
 *   an embedded minimal GMP implementation instead of full libgmp. This reduces
 *   external dependencies at the cost of slightly reduced crypto performance.
 * 
 * REQUIREMENTS:
 *   - Nettle must be built with --enable-mini-gmp
 *   - Only affects DNSSEC builds (HAVE_DNSSEC)
 * 
 * IMPACT:
 *   - Removes libgmp dependency (~500KB library)
 *   - Slightly slower DNSSEC crypto operations (usually negligible)
 */

/* ============================================================================
 * FILE PATH CONFIGURATION
 * ============================================================================ */

/**
 * LEASEFILE, CONFFILE, RESOLVFILE, RUNFILE
 * 
 * PURPOSE:
 *   Default file paths for core dnsmasq configuration and runtime files.
 *   Paths are platform-specific (defined in later section based on OS detection).
 *   Can be overridden at build time via COPTS or at runtime via command-line options.
 * 
 * FILES:
 *   - LEASEFILE: DHCP lease database persistence
 *   - CONFFILE: Main configuration file
 *   - RESOLVFILE: System resolver configuration (upstream DNS servers)
 *   - RUNFILE: PID file for daemon process management
 * 
 * OVERRIDE METHODS:
 *   Build-time: make COPTS=-DLEASEFILE=\"/custom/path/leases\"
 *   Runtime: Command-line options (--leasefile-ro, --conf-file, --resolv-file, --pid-file)
 * 
 * Platform-specific defaults are defined below based on __linux__, __ANDROID__,
 * __FreeBSD__, __OpenBSD__, __DragonFly__, __FreeBSD_kernel__, __NetBSD__, __sun.
 */

/* Defining this builds a binary which handles time differently and works better on a system without a 
   stable RTC (it uses uptime, not epoch time) and writes the DHCP leases file less often to avoid flash wear. 
*/

/* #define HAVE_BROKEN_RTC */

/* The default set of options to build. Built with these options, dnsmasq
   has no library dependencies other than libc */

#define HAVE_DHCP
#define HAVE_DHCP6 
#define HAVE_TFTP
#define HAVE_SCRIPT
#define HAVE_AUTH
#define HAVE_IPSET 
#define HAVE_LOOP
#define HAVE_DUMPFILE

/* Build options which require external libraries.
   
   Defining HAVE_<opt>_STATIC as _well_ as HAVE_<opt> will link the library statically.

   You can use "make COPTS=-DHAVE_<opt>" instead of editing these.
*/

/* #define HAVE_LUASCRIPT */
/* #define HAVE_DBUS */
/* #define HAVE_IDN */
/* #define HAVE_LIBIDN2 */
/* #define HAVE_CONNTRACK */
/* #define HAVE_DNSSEC */
/* #define HAVE_NFTSET */

/* ============================================================================
 * PLATFORM-SPECIFIC FILE PATHS
 * ============================================================================
 * 
 * This section defines default filesystem locations for dnsmasq's persistent
 * and runtime files. Paths vary by operating system to conform to platform-
 * specific filesystem hierarchy standards (FHS on Linux, BSD conventions, etc.).
 * 
 * PATH OVERRIDE MECHANISMS:
 *   1. Build-time: make COPTS=-DLEASEFILE=\"/custom/path/leases\"
 *   2. Runtime: Command-line options (--leasefile-ro, --conf-file, --resolv-file, --pid-file)
 *   3. Preprocessor: Define macros before including this header
 * 
 * PLATFORM DETECTION:
 *   Platform identification uses compiler predefined macros:
 *   - __FreeBSD__, __OpenBSD__, __DragonFly__, __NetBSD__: BSD variants
 *   - __sun__, __sun: Solaris and OpenSolaris
 *   - __ANDROID__: Android Open Source Project (AOSP)
 *   - __uClinux__: Embedded Linux without MMU (memory management unit)
 *   - Default: Standard Linux/POSIX paths
 */

/**
 * LEASEFILE - DHCP Lease Database Location
 * 
 * PURPOSE:
 *   Persistent storage for DHCP lease assignments. Contains lease records with
 *   MAC address, assigned IP address, hostname, lease expiration (or duration
 *   if HAVE_BROKEN_RTC), and client identifier.
 * 
 * FILE FORMAT:
 *   Text file, one lease per line:
 *   <expiry_time> <mac_address> <ip_address> <hostname> <client_id>
 * 
 * PERSISTENCE BEHAVIOR:
 *   - Normal mode: Written on every lease renewal for up-to-date state
 *   - HAVE_BROKEN_RTC mode: Written only on create/destroy (flash-friendly)
 * 
 * PLATFORM-SPECIFIC PATHS:
 *   - BSD (FreeBSD, OpenBSD, DragonFly, NetBSD): /var/db/dnsmasq.leases
 *     Rationale: BSD convention for application databases in /var/db
 *   
 *   - Solaris/OpenSolaris: /var/cache/dnsmasq.leases
 *     Rationale: Solaris places cached data in /var/cache
 *   
 *   - Android (AOSP): /data/misc/dhcp/dnsmasq.leases
 *     Rationale: Android security model isolates app data in /data partition;
 *                /data/misc/dhcp is standard location for DHCP daemon data
 *   
 *   - Linux/Default: /var/lib/misc/dnsmasq.leases
 *     Rationale: Follows Filesystem Hierarchy Standard (FHS) for variable
 *                application state data in /var/lib
 * 
 * FILE PERMISSIONS:
 *   - Should be readable/writable by dnsmasq daemon user (typically nobody)
 *   - Parent directory must exist and be writable
 *   - On error, retry writes every LEASE_RETRY=60 seconds
 * 
 * OVERRIDE EXAMPLE:
 *   make COPTS=-DLEASEFILE=\"/tmp/dnsmasq.leases\"
 *   OR: --leasefile-ro=/custom/path  (runtime option)
 */
#ifndef LEASEFILE
#   if defined(__FreeBSD__) || defined (__OpenBSD__) || defined(__DragonFly__) || defined(__NetBSD__)
#      define LEASEFILE "/var/db/dnsmasq.leases"
#   elif defined(__sun__) || defined (__sun)
#      define LEASEFILE "/var/cache/dnsmasq.leases"
#   elif defined(__ANDROID__)
#      define LEASEFILE "/data/misc/dhcp/dnsmasq.leases"
#   else
#      define LEASEFILE "/var/lib/misc/dnsmasq.leases"
#   endif
#endif

/**
 * CONFFILE - Main Configuration File Location
 * 
 * PURPOSE:
 *   Primary configuration file containing all dnsmasq directives and options.
 *   Parsed at daemon startup and on SIGHUP reload. Supports extensive configuration
 *   vocabulary (350+ directives documented in dnsmasq.conf.example).
 * 
 * CONFIGURATION SYNTAX:
 *   - One directive per line
 *   - Comments start with #
 *   - Long option format: option=value (e.g., cache-size=1000)
 *   - Include files: conf-file=/path/to/additional.conf
 *   - Include directories: conf-dir=/etc/dnsmasq.d/,*.conf
 * 
 * PLATFORM-SPECIFIC PATHS:
 *   - FreeBSD: /usr/local/etc/dnsmasq.conf
 *     Rationale: FreeBSD ports/packages install to /usr/local by convention;
 *                configuration files go in /usr/local/etc to avoid conflicts
 *                with base system /etc
 *   
 *   - All other platforms: /etc/dnsmasq.conf
 *     Rationale: Standard Unix/Linux configuration directory
 * 
 * FILE PERMISSIONS:
 *   - Should be readable by root (daemon starts as root before privilege drop)
 *   - Recommended permissions: 644 (world-readable, root-writable)
 *   - May contain sensitive data (upstream server credentials, domain filtering rules)
 * 
 * RELOAD BEHAVIOR:
 *   - Send SIGHUP to daemon PID to reload configuration
 *   - DNS cache cleared on reload
 *   - DHCP leases preserved across reload
 *   - Active connections complete correctly
 * 
 * OVERRIDE EXAMPLE:
 *   make COPTS=-DCONFFILE=\"/opt/dnsmasq/dnsmasq.conf\"
 *   OR: --conf-file=/custom/path.conf  (runtime option)
 *   OR: -C /custom/path.conf  (short form runtime option)
 */
#ifndef CONFFILE
#   if defined(__FreeBSD__)
#      define CONFFILE "/usr/local/etc/dnsmasq.conf"
#   else
#      define CONFFILE "/etc/dnsmasq.conf"
#   endif
#endif

/**
 * RESOLVFILE - System Resolver Configuration File
 * 
 * PURPOSE:
 *   System's upstream DNS server configuration. Dnsmasq reads this file to
 *   discover which recursive DNS servers to forward queries to. Automatically
 *   monitored for changes (via inotify on Linux with HAVE_INOTIFY, or periodic
 *   polling otherwise).
 * 
 * FILE FORMAT (standard resolv.conf):
 *   nameserver 8.8.8.8
 *   nameserver 8.8.4.4
 *   search example.com
 *   domain example.com
 * 
 * DNSMASQ BEHAVIOR:
 *   - Reads nameserver lines to populate upstream server list
 *   - Ignores local loopback addresses (127.0.0.1, ::1) to prevent forwarding loops
 *   - Automatically reloads on file change (if HAVE_INOTIFY enabled)
 *   - Can be disabled via --no-resolv option (use explicit --server= instead)
 * 
 * PLATFORM-SPECIFIC PATHS:
 *   - uClinux (Embedded Linux without MMU): /etc/config/resolv.conf
 *     Rationale: Embedded systems often use /etc/config for configuration
 *                files to separate from read-only root filesystem
 *   
 *   - All other platforms: /etc/resolv.conf
 *     Rationale: Standard Unix/Linux resolver configuration location per
 *                resolver(5) man page
 * 
 * DYNAMIC UPDATE SCENARIOS:
 *   - DHCP client: Network manager or dhclient updates resolv.conf on IP acquisition
 *   - VPN connection: VPN client updates resolv.conf with VPN DNS servers
 *   - NetworkManager: Dynamically manages resolv.conf based on active connections
 * 
 * FILE PERMISSIONS:
 *   - Standard: 644 (world-readable, root-writable)
 *   - Dnsmasq needs read access only
 * 
 * OVERRIDE EXAMPLE:
 *   make COPTS=-DRESOLVFILE=\"/tmp/resolv.conf\"
 *   OR: --resolv-file=/custom/resolv.conf  (runtime option)
 *   OR: -r /custom/resolv.conf  (short form runtime option)
 */
#ifndef RESOLVFILE
#   if defined(__uClinux__)
#      define RESOLVFILE "/etc/config/resolv.conf"
#   else
#      define RESOLVFILE "/etc/resolv.conf"
#   endif
#endif

/**
 * RUNFILE - Process ID (PID) File Location
 * 
 * PURPOSE:
 *   Stores daemon process ID (PID) for process management, signal delivery,
 *   and preventing multiple daemon instances. Written immediately after daemon
 *   fork() and successful initialization.
 * 
 * FILE FORMAT:
 *   Single line containing ASCII decimal PID:
 *   12345\n
 * 
 * USAGE PATTERNS:
 *   - Init scripts: Read PID for daemon control (start, stop, restart, reload)
 *   - Signal delivery: kill -HUP $(cat /var/run/dnsmasq.pid)  # Reload config
 *   - Process monitoring: Check if PID from file exists and is dnsmasq
 *   - Multiple instances: Different --pid-file per instance to avoid conflicts
 * 
 * PLATFORM-SPECIFIC PATHS:
 *   - Android (AOSP): /data/dnsmasq.pid
 *     Rationale: Android restricts /var/run access; /data partition is
 *                writable and suitable for runtime daemon data
 *   
 *   - All other platforms: /var/run/dnsmasq.pid
 *     Rationale: Standard FHS location for runtime process data
 *                (on systemd systems, /var/run is symlink to /run)
 * 
 * FILE PERMISSIONS:
 *   - Created as: 644 (world-readable, daemon-writable)
 *   - Parent directory: /var/run typically root-owned, mode 755
 *   - File removed on clean daemon shutdown
 * 
 * STALE PID HANDLING:
 *   - Daemon checks if PID file exists at startup
 *   - If exists and process is running: Exit with error (already running)
 *   - If exists and process is dead: Remove stale file and continue
 *   - If cannot remove: Exit with permission error
 * 
 * OVERRIDE EXAMPLE:
 *   make COPTS=-DRUNFILE=\"/tmp/dnsmasq.pid\"
 *   OR: --pid-file=/custom/path.pid  (runtime option)
 *   OR: -x /custom/path.pid  (short form runtime option)
 */
#ifndef RUNFILE
#   if defined(__ANDROID__)
#      define RUNFILE "/data/dnsmasq.pid"
#    else
#      define RUNFILE "/var/run/dnsmasq.pid"
#    endif
#endif

/* ============================================================================
 * AUTOMATIC PLATFORM DETECTION AND NETWORK API SELECTION
 * ============================================================================
 * 
 * PURPOSE:
 *   Automatically detect the target platform and configure network API usage,
 *   command-line parsing capabilities, and socket structure compatibility.
 *   This abstraction layer enables a single codebase to compile correctly
 *   across diverse Unix-like operating systems with different networking APIs.
 * 
 * DETECTION MECHANISM:
 *   Platform identification uses compiler predefined macros that are automatically
 *   set by the compiler toolchain based on the target system:
 *   
 *   - __UCLIBC__: uClibc C library (embedded Linux)
 *   - __linux__: Linux with glibc
 *   - __FreeBSD__, __OpenBSD__, __DragonFly__, __FreeBSD_kernel__: BSD variants
 *   - __APPLE__: macOS / Mac OS X / Darwin
 *   - __NetBSD__: NetBSD
 *   - __sun, __sun__: Solaris and OpenSolaris
 * 
 * NETWORK ABSTRACTION LAYER MACROS:
 *   Exactly ONE of these is defined to select platform networking implementation:
 *   
 *   HAVE_LINUX_NETWORK:
 *     - Linux-specific networking APIs including netlink sockets for interface
 *       monitoring, inotify for file change detection, Linux DHCP packet filter
 *     - Implementation files: src/netlink.c, src/inotify.c
 *     - Kernel features: netlink, inotify, Linux-specific socket options
 *   
 *   HAVE_BSD_NETWORK:
 *     - BSD-specific networking including Berkeley Packet Filter (BPF) for DHCP,
 *       routing socket for interface monitoring, BSD socket API variants
 *     - Implementation files: src/bpf.c
 *     - Kernel features: BPF device (/dev/bpf*), routing sockets, BSD socket API
 *   
 *   HAVE_SOLARIS_NETWORK:
 *     - Solaris-specific networking including STREAMS-based interface monitoring,
 *       Solaris DHCP packet handling, Solaris socket extensions
 *     - Kernel features: STREAMS, Solaris routing sockets, Solaris DLPI
 * 
 * PORTABLE API DETECTION:
 *   
 *   HAVE_GETOPT_LONG:
 *     - Indicates availability of GNU-style getopt_long() for parsing long
 *       command-line options like --cache-size=1000 (versus short -c 1000)
 *     - Availability: glibc, modern BSDs, macOS
 *     - Missing: Old BSD systems, minimal embedded environments
 *     - Fallback: If undefined, dnsmasq uses only short option parsing
 *   
 *   HAVE_SOCKADDR_SA_LEN:
 *     - Indicates struct sockaddr includes sa_len field specifying structure length
 *     - Present: BSD variants (4.4BSD heritage), macOS
 *     - Absent: Linux, Solaris (use separate length parameter instead)
 *     - Impact: Socket address structure handling in network code
 */

/**
 * PLATFORM: uClibc (Embedded Linux)
 * 
 * uClibc is a compact C library designed for embedded Linux systems with limited
 * resources. Often found in routers, NAS devices, and consumer electronics.
 * 
 * DETECTION: __UCLIBC__ macro defined by uClibc compiler
 * 
 * CONFIGURATION:
 *   - Network API: Linux (netlink, inotify) via HAVE_LINUX_NETWORK
 *   - getopt_long: Conditional based on uClibc feature detection
 *     * __UCLIBC_HAS_GNU_GETOPT__: uClibc built with GNU getopt
 *     * uClibc 0.9.x < 0.9.21: Early versions had getopt_long
 *   - sockaddr.sa_len: Not present (Linux convention)
 *   - IPv6 socket option: Define IPV6_V6ONLY=26 if uClibc IPv6 enabled
 * 
 * RATIONALE:
 *   uClibc's modular configuration allows features to be compiled in or out.
 *   We detect available features at compile time and adapt accordingly.
 */
#if defined(__UCLIBC__)
#define HAVE_LINUX_NETWORK
#if defined(__UCLIBC_HAS_GNU_GETOPT__) || \
   ((__UCLIBC_MAJOR__==0) && (__UCLIBC_MINOR__==9) && (__UCLIBC_SUBLEVEL__<21))
#    define HAVE_GETOPT_LONG
#endif
#undef HAVE_SOCKADDR_SA_LEN
#if defined(__UCLIBC_HAS_IPV6__)
#  ifndef IPV6_V6ONLY
#    define IPV6_V6ONLY 26
#  endif
#endif

/**
 * PLATFORM: Linux with glibc 2.x
 * 
 * Standard Linux distributions (Debian, Ubuntu, Red Hat, Fedora, etc.) using
 * the GNU C Library (glibc) version 2.x as the system C library.
 * 
 * DETECTION: __linux__ macro defined by GCC/Clang on Linux targets
 * 
 * CONFIGURATION:
 *   - Network API: Linux (netlink, inotify) via HAVE_LINUX_NETWORK
 *   - getopt_long: Always available (glibc provides GNU getopt)
 *   - sockaddr.sa_len: Not present (Linux uses separate length parameter)
 * 
 * NETWORK FEATURES ENABLED:
 *   - Netlink sockets: Real-time interface monitoring in src/netlink.c
 *   - inotify: File change detection for config/resolv.conf in src/inotify.c
 *   - Linux-specific DHCP: Raw socket DHCP with packet filters
 *   - ipset integration: Firewall set population (HAVE_IPSET)
 *   - nftables integration: Nftables set population (HAVE_NFTSET)
 *   - Connection tracking: Netfilter conntrack marks (HAVE_CONNTRACK)
 * 
 * RATIONALE:
 *   Linux provides the most feature-rich networking stack with netlink for
 *   efficient interface monitoring and extensive firewall integration options.
 */
/* This is for glibc 2.x */
#elif defined(__linux__)
#define HAVE_LINUX_NETWORK
#define HAVE_GETOPT_LONG
#undef HAVE_SOCKADDR_SA_LEN

/**
 * PLATFORM: FreeBSD, OpenBSD, DragonFly BSD, GNU/kFreeBSD
 * 
 * BSD operating system family sharing 4.4BSD networking heritage. Includes:
 *   - FreeBSD: General-purpose BSD (servers, desktops, embedded)
 *   - OpenBSD: Security-focused BSD
 *   - DragonFly BSD: FreeBSD 4.x derivative with new SMP architecture
 *   - GNU/kFreeBSD: Debian GNU userland with FreeBSD kernel
 * 
 * DETECTION: __FreeBSD__, __OpenBSD__, __DragonFly__, __FreeBSD_kernel__ macros
 * 
 * CONFIGURATION:
 *   - Network API: BSD (BPF, routing sockets) via HAVE_BSD_NETWORK
 *   - getopt_long: Conditional detection via optional_argument/required_argument
 *     * Modern FreeBSD (5.0+): Has getopt_long
 *     * OpenBSD: Has getopt_long since 3.3 (2003)
 *     * Detection: Check for getopt.h constants that indicate GNU getopt
 *   - sockaddr.sa_len: Present (4.4BSD socket API includes length field)
 * 
 * NETWORK FEATURES:
 *   - BPF (Berkeley Packet Filter): DHCP packet capture in src/bpf.c
 *   - Routing sockets: Interface monitoring via PF_ROUTE sockets
 *   - BSD packet filter (pf): Firewall table integration in src/tables.c
 * 
 * RATIONALE:
 *   BSD networking uses BPF for packet capture (DHCP) and routing sockets
 *   for interface state changes. The sa_len field simplifies socket address
 *   handling by embedding the structure length directly.
 */
#elif defined(__FreeBSD__) || \
      defined(__OpenBSD__) || \
      defined(__DragonFly__) || \
      defined(__FreeBSD_kernel__)
#define HAVE_BSD_NETWORK
/* Later versions of FreeBSD have getopt_long() */
#if defined(optional_argument) && defined(required_argument)
#   define HAVE_GETOPT_LONG
#endif
#define HAVE_SOCKADDR_SA_LEN

/**
 * PLATFORM: macOS / Mac OS X / Darwin
 * 
 * Apple's Unix-based operating system built on Darwin kernel (BSD heritage).
 * Supports both desktop/laptop Macs and older Mac OS X Server systems.
 * 
 * DETECTION: __APPLE__ macro defined by Apple's compiler toolchain
 * 
 * CONFIGURATION:
 *   - Network API: BSD (BPF, routing sockets) via HAVE_BSD_NETWORK
 *   - getopt_long: Always available (macOS includes GNU getopt_long)
 *   - sockaddr.sa_len: Present (BSD socket API)
 *   - ipset: Disabled via NO_IPSET (Linux-specific feature)
 * 
 * APPLE-SPECIFIC WORKAROUNDS:
 *   
 *   _BSD_SOCKLEN_T_:
 *     - Must be defined before including <sys/socket.h>
 *     - Ensures socklen_t typedef is available
 *     - Prevents compilation errors in socket function prototypes
 *   
 *   __APPLE_USE_RFC_3542:
 *     - Must be defined before including <netinet6/in6.h>
 *     - Selects RFC 3542 version of IPv6 advanced socket API
 *     - Provides IPV6_PKTINFO, IPV6_RECVPKTINFO, etc.
 *     - Rationale: macOS supports both old (RFC 2292) and new (RFC 3542) APIs;
 *                  we select the standardized RFC 3542 version
 *   
 *   SOL_TCP definition:
 *     - macOS Mojave (10.14) and later removed SOL_TCP constant
 *     - Workaround: Define SOL_TCP as IPPROTO_TCP if not present
 *     - Used for TCP socket options like TCP_NODELAY
 *     - Source: /usr/include/netinet/tcp.h on Mojave
 * 
 * INTEGRATION:
 *   - Launch daemon: Service management via launchd (contrib/MacOSX-launchd/)
 *   - Default paths: Modified for macOS conventions (not /var/run, etc.)
 * 
 * RATIONALE:
 *   macOS networking follows BSD model but requires version-specific workarounds
 *   for API compatibility across OS X 10.6+ through modern macOS versions.
 */
#elif defined(__APPLE__)
#define HAVE_BSD_NETWORK
#define HAVE_GETOPT_LONG
#define HAVE_SOCKADDR_SA_LEN
#define NO_IPSET
/* Define before sys/socket.h is included so we get socklen_t */
#define _BSD_SOCKLEN_T_
/* Select the RFC_3542 version of the IPv6 socket API. 
   Define before netinet6/in6.h is included. */
#define __APPLE_USE_RFC_3542
/* Required for Mojave. */
#ifndef SOL_TCP
#  define SOL_TCP IPPROTO_TCP
#endif

/**
 * PLATFORM: NetBSD
 * 
 * NetBSD is a BSD operating system emphasizing portability across diverse
 * hardware platforms (runs on 50+ CPU architectures). Known for clean code
 * and adherence to standards.
 * 
 * DETECTION: __NetBSD__ macro defined by NetBSD compiler
 * 
 * CONFIGURATION:
 *   - Network API: BSD (BPF, routing sockets) via HAVE_BSD_NETWORK
 *   - getopt_long: Always available (NetBSD includes GNU getopt_long)
 *   - sockaddr.sa_len: Present (4.4BSD socket API)
 * 
 * NETWORK FEATURES:
 *   - BPF: DHCP packet capture using /dev/bpf
 *   - Routing sockets: Interface monitoring
 *   - BSD socket API: Full 4.4BSD compatibility
 * 
 * RATIONALE:
 *   NetBSD follows standard BSD networking conventions with no special
 *   workarounds required. Clean, standards-compliant implementation.
 */
#elif defined(__NetBSD__)
#define HAVE_BSD_NETWORK
#define HAVE_GETOPT_LONG
#define HAVE_SOCKADDR_SA_LEN

/**
 * PLATFORM: Solaris and OpenSolaris
 * 
 * Oracle Solaris (commercial Unix) and OpenSolaris (open-source derivative).
 * Enterprise Unix system with STREAMS networking architecture.
 * 
 * DETECTION: __sun or __sun__ macro defined by Solaris compiler
 * 
 * CONFIGURATION:
 *   - Network API: Solaris-specific via HAVE_SOLARIS_NETWORK
 *   - getopt_long: Available (Solaris includes GNU-compatible getopt_long)
 *   - sockaddr.sa_len: Not present (Solaris follows System V conventions)
 *   - ETHER_ADDR_LEN: Must be defined manually (not in system headers)
 * 
 * SOLARIS-SPECIFIC FEATURES:
 *   
 *   STREAMS Networking:
 *     - Solaris uses STREAMS-based network stack (not BSD sockets exclusively)
 *     - Interface monitoring via different mechanisms than Linux/BSD
 *     - DLPI (Data Link Provider Interface) for link-layer access
 *   
 *   ETHER_ADDR_LEN Definition:
 *     - Standard value: 6 bytes (Ethernet MAC address length)
 *     - Defined here because Solaris headers don't provide this constant
 *     - Used in: ARP handling, DHCP MAC address operations
 * 
 * INTEGRATION:
 *   - Service management: SMF (Service Management Facility) in contrib/Solaris10/
 *   - Init scripts: svccfg/svcadm for service control
 *   - Platform paths: /var/cache for lease file (Solaris FHS variant)
 * 
 * RATIONALE:
 *   Solaris networking differs significantly from Linux/BSD due to STREAMS
 *   architecture and System V heritage. Requires dedicated implementation
 *   for interface monitoring and packet handling.
 */
#elif defined(__sun) || defined(__sun__)
#define HAVE_SOLARIS_NETWORK
#define HAVE_GETOPT_LONG
#undef HAVE_SOCKADDR_SA_LEN
#define ETHER_ADDR_LEN 6 
 
#endif

/* ============================================================================
 * FEATURE DEPENDENCY RESOLUTION AND COMPILE-TIME FEATURE DISABLING
 * ============================================================================
 * 
 * PURPOSE:
 *   This section implements two critical build configuration mechanisms:
 *   
 *   1. FEATURE DEPENDENCIES: Automatically enable prerequisite features when
 *      dependent features are enabled (e.g., HAVE_DHCP6 implies HAVE_DHCP).
 *   
 *   2. EXPLICIT FEATURE DISABLING: Process NO_XXX flags to disable features
 *      even if HAVE_XXX is defined, allowing forced exclusion for minimal builds.
 * 
 * EXECUTION ORDER:
 *   This logic executes AFTER platform detection and AFTER any HAVE_XXX macros
 *   are defined by the build system (via COPTS). The processing order ensures:
 *   
 *   Step 1: Platform detection defines HAVE_LINUX_NETWORK, HAVE_BSD_NETWORK, etc.
 *   Step 2: Build system may define HAVE_DHCP, HAVE_TFTP, etc. via make COPTS
 *   Step 3: Build system may define NO_DHCP, NO_TFTP, etc. to force disable
 *   Step 4: THIS SECTION processes dependencies and NO_XXX overrides
 *   Step 5: Compilation proceeds with final HAVE_XXX configuration
 * 
 * USAGE PATTERNS:
 *   
 *   Minimal Build (DNS only):
 *     make COPTS="-DNO_DHCP -DNO_TFTP -DNO_AUTH"
 *     Result: Smallest binary, DNS forwarding/caching only
 *   
 *   Custom Build (DNS + DHCPv4, no IPv6):
 *     make COPTS="-DHAVE_DHCP -DNO_DHCP6 -DNO_TFTP"
 *     Result: IPv4 DNS and DHCP, no DHCPv6, no TFTP
 *   
 *   Platform-Specific Build (Disable unavailable features):
 *     make COPTS="-DNO_INOTIFY -DNO_SCRIPT"
 *     Result: Disable features not available on target platform
 * 
 * RATIONALE:
 *   Embedded systems require fine-grained control over binary size and feature
 *   inclusion. This mechanism supports minimal builds for resource-constrained
 *   devices while maintaining automatic dependency satisfaction to prevent
 *   broken configurations.
 */

/**
 * FEATURE DISABLING: TFTP Server
 * 
 * TRIGGER: NO_TFTP defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_TFTP to completely exclude TFTP server code.
 * 
 * AFFECTED CODE:
 *   - src/tftp.c: Entire file excluded from compilation
 *   - src/option.c: TFTP-related configuration options disabled
 *   - Network boot: PXE boot still available (uses DHCP), but no file serving
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 15-20KB from stripped binary (TFTP protocol handler,
 *   option negotiation, file transfer state machine, connection management).
 * 
 * USE CASE:
 *   Deployments not using network boot or where TFTP service is provided by
 *   separate daemon (e.g., tftpd-hpa, atftpd).
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_TFTP"
 */
#ifdef NO_TFTP
#undef HAVE_TFTP
#endif

/**
 * FEATURE DISABLING: DHCP (DHCPv4 and DHCPv6)
 * 
 * TRIGGER: NO_DHCP defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_DHCP and HAVE_DHCP6 to exclude all DHCP server functionality.
 *   This is the most impactful feature disable, removing entire protocol stacks.
 * 
 * AFFECTED CODE:
 *   - src/dhcp.c, src/rfc2131.c: DHCPv4 implementation excluded
 *   - src/dhcp6.c, src/rfc3315.c: DHCPv6 implementation excluded
 *   - src/lease.c: Lease database management excluded
 *   - src/radv.c: Router Advertisement excluded (depends on DHCP6)
 *   - src/slaac.c: SLAAC confirmation excluded
 *   - src/helper.c: Lease-change script execution excluded
 *   - DNS integration: Automatic DHCP hostname registration disabled
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 60-80KB from stripped binary (largest feature exclusion).
 *   This creates a DNS-only build suitable for pure DNS forwarding/caching scenarios.
 * 
 * FEATURE DEPENDENCY:
 *   Disabling HAVE_DHCP automatically disables HAVE_DHCP6 because DHCPv6
 *   requires DHCPv4 infrastructure (shared lease database, option parsing, etc.).
 * 
 * USE CASE:
 *   Pure DNS forwarder deployments where DHCP is handled by separate infrastructure
 *   (ISC DHCP Server, Kea, Windows DHCP Server, router DHCP, etc.).
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_DHCP"  # DNS-only build
 */
#ifdef NO_DHCP
#undef HAVE_DHCP
#undef HAVE_DHCP6
#endif

/**
 * FEATURE DISABLING: DHCPv6 Only (Keep DHCPv4)
 * 
 * TRIGGER: NO_DHCP6 defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_DHCP6 to exclude DHCPv6 while keeping DHCPv4.
 * 
 * AFFECTED CODE:
 *   - src/dhcp6.c, src/rfc3315.c: DHCPv6 excluded
 *   - src/radv.c: Router Advertisement excluded
 *   - src/slaac.c: SLAAC confirmation excluded
 *   - DHCPv4 remains: src/dhcp.c, src/rfc2131.c functional
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 25-30KB (DHCPv6 protocol stack and IPv6 RA).
 * 
 * USE CASE:
 *   IPv4-only networks where IPv6 is disabled or not required.
 *   Common in legacy environments or networks with IPv4-only clients.
 * 
 * EXAMPLE:
 *   make COPTS="-DHAVE_DHCP -DNO_DHCP6"  # IPv4 DHCP only
 */
#if defined(NO_DHCP6)
#undef HAVE_DHCP6
#endif

/**
 * FEATURE DEPENDENCY: DHCPv6 Requires DHCPv4
 * 
 * AUTOMATIC DEPENDENCY RESOLUTION:
 *   If HAVE_DHCP6 is defined, automatically define HAVE_DHCP.
 * 
 * RATIONALE:
 *   DHCPv6 implementation shares significant infrastructure with DHCPv4:
 *   
 *   - Lease database: src/lease.c stores both DHCPv4 and DHCPv6 leases
 *   - Common utilities: src/dhcp-common.c provides shared DHCP functions
 *   - Option parsing: Similar option handling frameworks
 *   - DNS integration: Both protocols register hostnames in DNS cache
 *   - Script execution: Lease-change scripts handle both protocols
 * 
 *   Attempting to build DHCPv6 without DHCPv4 would require extracting and
 *   duplicating substantial code, increasing maintenance burden. The dependency
 *   ensures DHCPv4 infrastructure is always present when DHCPv6 is enabled.
 * 
 * BUILD SYSTEM INTERACTION:
 *   Build system may specify "make COPTS=-DHAVE_DHCP6" without explicitly
 *   defining HAVE_DHCP. This rule ensures HAVE_DHCP is automatically defined.
 * 
 * OVERRIDE:
 *   Cannot override this dependency. To exclude DHCPv4, use NO_DHCP which
 *   disables both protocols (see above).
 */
/* DHCP6 needs DHCP too */
#ifdef HAVE_DHCP6
#define HAVE_DHCP
#endif

/**
 * FEATURE DISABLING: Script Execution (External and Lua)
 * 
 * TRIGGER: NO_SCRIPT defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_SCRIPT and HAVE_LUASCRIPT to exclude all script execution.
 * 
 * AFFECTED CODE:
 *   - src/helper.c: Fork-based script executor excluded
 *   - Lease-change scripts: No script invocation on add/old/del events
 *   - Lua scripting: Embedded Lua interpreter excluded
 *   - External integration: Script-based automation disabled
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 5-10KB (helper process management, script execution).
 *   If HAVE_LUASCRIPT was enabled, also removes Lua library linkage (50-200KB).
 * 
 * SECURITY IMPACT:
 *   Eliminates attack surface from script execution. On security-critical
 *   systems, disabling script execution prevents potential privilege escalation
 *   through malicious scripts or script injection vulnerabilities.
 * 
 * FEATURE DEPENDENCY:
 *   Disabling HAVE_SCRIPT automatically disables HAVE_LUASCRIPT because Lua
 *   scripting is an alternative implementation of script execution functionality.
 * 
 * USE CASE:
 *   - Security-hardened deployments
 *   - Minimal embedded systems without scripting requirements
 *   - Environments where external integration is handled through D-Bus/UBus
 *   - Android builds (scripts disabled by security policy)
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_SCRIPT"  # Disable external integration scripts
 */
#if defined(NO_SCRIPT)
#undef HAVE_SCRIPT
#undef HAVE_LUASCRIPT
#endif

/**
 * FEATURE DEPENDENCY: Lua Scripting Requires Base Script Support
 * 
 * AUTOMATIC DEPENDENCY RESOLUTION:
 *   If HAVE_LUASCRIPT is defined, automatically define HAVE_SCRIPT.
 * 
 * RATIONALE:
 *   Lua scripting (HAVE_LUASCRIPT) is an alternative implementation of script
 *   execution that reduces process overhead by embedding a Lua interpreter
 *   instead of fork/exec for each event. However, it shares:
 *   
 *   - Script trigger points: Same DHCP lease events (add/old/del)
 *   - Event infrastructure: Common event queue and dispatch mechanism
 *   - Configuration options: Same --dhcp-script and --dhcp-luascript directives
 *   - Helper coordination: Uses src/helper.c infrastructure
 * 
 *   HAVE_SCRIPT provides the foundation event infrastructure that HAVE_LUASCRIPT
 *   builds upon. The distinction is in execution method:
 *   
 *   - HAVE_SCRIPT only: Fork external executable for each event
 *   - HAVE_LUASCRIPT: Invoke Lua function in embedded interpreter
 * 
 * BUILD SYSTEM INTERACTION:
 *   Build system may specify "make COPTS=-DHAVE_LUASCRIPT" without explicitly
 *   defining HAVE_SCRIPT. This rule ensures base script infrastructure is enabled.
 * 
 * OVERRIDE:
 *   Cannot override this dependency. To exclude Lua scripting, use NO_SCRIPT
 *   which disables both external and Lua scripting (see above).
 */
/* Must HAVE_SCRIPT to HAVE_LUASCRIPT */
#ifdef HAVE_LUASCRIPT
#define HAVE_SCRIPT
#endif

/**
 * FEATURE DISABLING: Authoritative DNS
 * 
 * TRIGGER: NO_AUTH defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_AUTH to exclude authoritative DNS server functionality.
 * 
 * AFFECTED CODE:
 *   - src/auth.c: Entire authoritative DNS module excluded
 *   - Zone serving: Cannot serve as primary nameserver for local zones
 *   - Zone transfer: AXFR to secondary nameservers disabled
 *   - SOA generation: Automatic SOA record creation excluded
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 10-15KB (authoritative response generation, zone
 *   transfer protocol, SOA record management).
 * 
 * FUNCTIONAL IMPACT:
 *   Dnsmasq operates ONLY as forwarding resolver. Cannot serve as authoritative
 *   nameserver for designated zones. All queries either served from cache,
 *   /etc/hosts, or forwarded to upstream servers.
 * 
 * USE CASE:
 *   Deployments using dnsmasq purely for DNS caching and forwarding without
 *   need to host local zones authoritatively. Most small network deployments
 *   do not require authoritative DNS capability.
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_AUTH"  # Pure forwarding resolver
 */
#ifdef NO_AUTH
#undef HAVE_AUTH
#endif

/**
 * PLATFORM RESTRICTION: nftables Sets (Linux Only)
 * 
 * AUTOMATIC PLATFORM ENFORCEMENT:
 *   If HAVE_LINUX_NETWORK is not defined, undefine HAVE_NFTSET.
 * 
 * RATIONALE:
 *   nftables (netfilter tables) is a Linux-specific packet filtering framework
 *   that replaced iptables starting with Linux 3.13 (2014). The nftables set
 *   integration (src/nftset.c) uses Linux-specific libnftables API and netlink
 *   communication that is not available on BSD or Solaris platforms.
 * 
 *   BSD platforms use PF (Packet Filter) via src/tables.c instead.
 *   Solaris platforms have different firewall mechanisms.
 * 
 * DEPENDENCY:
 *   - Requires: HAVE_LINUX_NETWORK (Linux kernel and netlink)
 *   - External library: libnftables for set manipulation API
 *   - Kernel: Linux 3.13+ with nftables support
 * 
 * FEATURE SCOPE:
 *   Allows dnsmasq to populate nftables sets with resolved IP addresses,
 *   enabling dynamic firewall rules based on DNS resolution (domain-based
 *   firewall policies, content filtering, split-tunneling).
 * 
 * CROSS-PLATFORM ALTERNATIVE:
 *   - Linux (legacy): HAVE_IPSET for iptables ipset integration
 *   - BSD: HAVE_BSD_NETWORK enables PF table integration (src/tables.c)
 *   - Solaris: No equivalent firewall integration
 */
#if !defined(HAVE_LINUX_NETWORK)
#undef HAVE_NFTSET
#endif

/**
 * FEATURE DISABLING: ipset Integration
 * 
 * TRIGGER: NO_IPSET defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_IPSET to exclude ipset firewall integration.
 * 
 * AFFECTED CODE:
 *   - src/ipset.c: ipset manipulation code excluded
 *   - Firewall integration: Cannot populate ipset collections with resolved IPs
 *   - Dynamic firewall rules: Domain-based firewall policies disabled
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 5-8KB (ipset netlink communication, set management).
 * 
 * PLATFORM SCOPE:
 *   ipset is available on both Linux and BSD (different implementations):
 *   - Linux: netlink-based ipset via netfilter
 *   - BSD: ipfw table integration
 * 
 * USE CASE:
 *   Deployments not using firewall integration or where firewall rules are
 *   statically configured. Common in simple NAT routers or environments where
 *   packet filtering is handled separately.
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_IPSET"  # Disable ipset integration
 */
#if defined(NO_IPSET)
#undef HAVE_IPSET
#endif

/**
 * PLATFORM-SPECIFIC ipset IMPLEMENTATION SELECTION
 * 
 * CONDITIONAL COMPILATION:
 *   If HAVE_IPSET is enabled, select platform-specific implementation:
 *   
 *   - HAVE_LINUX_IPSET: Linux netlink-based ipset (netfilter framework)
 *   - HAVE_BSD_IPSET: BSD ipfw table integration
 *   - No platform: Undefine HAVE_IPSET (unsupported platform)
 * 
 * IMPLEMENTATION DIFFERENCES:
 *   
 *   Linux ipset (HAVE_LINUX_IPSET):
 *     - Uses netlink sockets to communicate with kernel netfilter
 *     - API: libipset or direct netlink messages
 *     - Kernel module: xt_set, ip_set
 *     - Features: Hash sets, bitmap sets, list sets with extensive options
 *     - Performance: Highly optimized for large sets (millions of entries)
 *   
 *   BSD ipfw tables (HAVE_BSD_IPSET):
 *     - Uses setsockopt() with IP_FW_TABLE_ADD, IP_FW_TABLE_DEL
 *     - API: ipfw kernel interface via socket options
 *     - Kernel: ipfw packet filter built into BSD kernel
 *     - Features: Simple address tables (IP addresses and networks)
 *     - Performance: Optimized for moderate set sizes (thousands of entries)
 * 
 * AUTOMATIC PLATFORM DETECTION:
 *   The logic examines previously defined HAVE_LINUX_NETWORK or HAVE_BSD_NETWORK
 *   macros (from platform detection section above) to determine available
 *   implementation. If neither is defined (e.g., Solaris), HAVE_IPSET is
 *   undefined because no platform-specific implementation exists.
 * 
 * RATIONALE:
 *   ipset functionality requires platform-specific kernel interfaces. The
 *   abstraction here allows src/ipset.c to be compiled with appropriate
 *   platform-specific code paths via conditional compilation on
 *   HAVE_LINUX_IPSET vs HAVE_BSD_IPSET.
 * 
 * SOURCE CODE ORGANIZATION:
 *   - src/ipset.c contains both implementations with #ifdef HAVE_LINUX_IPSET
 *     and #ifdef HAVE_BSD_IPSET sections
 *   - Common interface: ipset_init(), ipset_add_domain()
 *   - Platform-specific internals: netlink vs setsockopt implementations
 */
#if defined(HAVE_IPSET)
#  if defined(HAVE_LINUX_NETWORK)
#    define HAVE_LINUX_IPSET
#  elif defined(HAVE_BSD_NETWORK)
#    define HAVE_BSD_IPSET
#  else
#    undef HAVE_IPSET
#  endif
#endif

/**
 * FEATURE DISABLING: DNS Forwarding Loop Detection
 * 
 * TRIGGER: NO_LOOP defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_LOOP to exclude loop detection mechanism.
 * 
 * AFFECTED CODE:
 *   - src/loop.c: Loop detection probe mechanism excluded
 *   - Startup checks: Forwarding loop detection disabled
 *   - Configuration validation: Cannot detect circular upstream server config
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 2-3KB (minimal feature, small code footprint).
 * 
 * MECHANISM:
 *   Loop detection works by sending probe queries to upstream servers for a
 *   reserved test domain (test.test.test, RFC 2606 reserved) and checking if
 *   those queries are received back on the listening socket, indicating a
 *   forwarding loop where dnsmasq is configured as its own upstream server.
 * 
 * RISK OF DISABLING:
 *   Misconfigured upstream servers pointing back to dnsmasq itself will create
 *   infinite query loops, exhausting file descriptors and CPU. However, proper
 *   configuration management eliminates this risk.
 * 
 * USE CASE:
 *   Minimal embedded builds where configuration is known to be correct and
 *   loop detection overhead (startup probes, periodic checks) is unnecessary.
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_LOOP"  # Disable loop detection
 */
#ifdef NO_LOOP
#undef HAVE_LOOP
#endif

/**
 * FEATURE DISABLING: Packet Capture (libpcap format)
 * 
 * TRIGGER: NO_DUMPFILE defined via build system
 * 
 * ACTION:
 *   Undefine HAVE_DUMPFILE to exclude packet capture functionality.
 * 
 * AFFECTED CODE:
 *   - src/dump.c: Packet dump to libpcap format excluded
 *   - Debugging capability: Cannot capture DNS packets for troubleshooting
 *   - Configuration option: --dumpfile disabled
 * 
 * BINARY SIZE IMPACT:
 *   Removes approximately 2-3KB (packet capture formatting, file I/O).
 * 
 * FEATURE SCOPE:
 *   The packet dump feature writes DNS queries and responses to a file in
 *   libpcap format (tcpdump/Wireshark compatible) for debugging and analysis.
 *   Not the same as query logging (which logs to syslog); this captures raw
 *   binary packet data for protocol analysis.
 * 
 * USE CASE:
 *   Production deployments where packet capture is not needed. Debugging is
 *   typically performed in development/testing environments, not production.
 *   Disabling saves minimal space but eliminates a troubleshooting tool.
 * 
 * ALTERNATIVE:
 *   External packet capture tools (tcpdump, Wireshark) can capture dnsmasq
 *   traffic without built-in support. Disabling does not eliminate debugging
 *   capability, just built-in convenience feature.
 * 
 * EXAMPLE:
 *   make COPTS="-DNO_DUMPFILE"  # Disable packet capture
 */
#ifdef NO_DUMPFILE
#undef HAVE_DUMPFILE
#endif

/**
 * FEATURE AUTO-ENABLE: Linux inotify File Change Detection
 * 
 * AUTOMATIC PLATFORM ENABLEMENT:
 *   If HAVE_LINUX_NETWORK is defined AND NO_INOTIFY is not defined,
 *   automatically enable HAVE_INOTIFY.
 * 
 * MECHANISM:
 *   inotify is a Linux kernel subsystem for monitoring filesystem events
 *   (file creation, modification, deletion). Dnsmasq uses inotify to watch:
 *   
 *   - /etc/resolv.conf: Upstream DNS server changes (e.g., DHCP client updates)
 *   - Configuration directory: Configuration file changes for hot reload
 *   - DHCP hosts directory: Dynamic DHCP host file additions/removals
 * 
 * AFFECTED CODE:
 *   - src/inotify.c: inotify event processing and file watching
 *   - Automatic reload: Configuration changes trigger SIGHUP internally
 *   - Dynamic upstream: resolv.conf changes update upstream server list
 * 
 * PLATFORM AVAILABILITY:
 *   - Linux 2.6.13+ (2005): inotify API available in kernel
 *   - Not available: BSD (uses kqueue), Solaris (uses port file events)
 * 
 * RATIONALE FOR AUTO-ENABLE:
 *   inotify provides efficient file monitoring without polling. On Linux
 *   systems, this feature should be enabled by default unless explicitly
 *   disabled via NO_INOTIFY. Automatic enablement ensures Linux builds get
 *   optimal file change detection without manual configuration.
 * 
 * OVERRIDE:
 *   Define NO_INOTIFY to disable even on Linux:
 *   
 *   make COPTS="-DNO_INOTIFY"  # Disable inotify on Linux
 *   
 *   Use case: Embedded systems with stripped kernels lacking inotify support,
 *   or security-hardened systems where filesystem monitoring is disabled.
 * 
 * BINARY SIZE IMPACT:
 *   Adds approximately 3-5KB when enabled (inotify system call wrappers,
 *   event processing, file descriptor management).
 */
#if defined (HAVE_LINUX_NETWORK) && !defined(NO_INOTIFY)
#define HAVE_INOTIFY
#endif

/**
 * BUILD FINGERPRINTING: Compile-Time Options String
 * 
 * PURPOSE:
 *   Embed compile-time configuration as static string in binary for build
 *   identification and troubleshooting. This string is NOT used at runtime
 *   by dnsmasq code; it exists solely for the build system and binary analysis.
 * 
 * MECHANISM:
 *   If DNSMASQ_COMPILE_FLAGS macro is defined by the build system, declare
 *   a static string variable containing the flags. The Makefile defines this
 *   macro with a string representation of all active HAVE_* macros.
 * 
 * MAKEFILE INTEGRATION:
 *   The Makefile uses preprocessor to extract defined macros and constructs
 *   a string like: "HAVE_DHCP HAVE_DHCP6 HAVE_TFTP HAVE_DNSSEC ..."
 *   
 *   This string is embedded in the binary and can be extracted with:
 *   
 *   strings dnsmasq | grep HAVE_
 *   
 *   Or accessed via binary metadata tools to identify which features were
 *   compiled into a particular dnsmasq binary.
 * 
 * USE CASES:
 *   
 *   - Deployment verification: Confirm production binary has required features
 *   - Troubleshooting: Identify missing features in user-reported bug binaries
 *   - Distribution packaging: Verify package build matches specification
 *   - Binary comparison: Differentiate minimal vs full-featured builds
 * 
 * EXAMPLE OUTPUT:
 *   Full build: "HAVE_DHCP HAVE_DHCP6 HAVE_TFTP HAVE_DNSSEC HAVE_DBUS ..."
 *   Minimal build: "HAVE_LINUX_NETWORK HAVE_GETOPT_LONG"
 * 
 * CODE GENERATION:
 *   This code never compiles into actual executable instructions. The static
 *   string is placed in the read-only data section (.rodata) but never
 *   referenced by runtime code. Optimizing compilers may remove it, but build
 *   systems typically preserve for fingerprinting purposes.
 * 
 * NOTE:
 *   The #ifdef DNSMASQ_COMPILE_FLAGS condition ensures this only compiles when
 *   the build system explicitly provides the flags string. Direct source
 *   compilation without Makefile will not define DNSMASQ_COMPILE_FLAGS and
 *   this section is skipped.
 */
/* This never compiles code, it's only used by the makefile to fingerprint builds. */
#ifdef DNSMASQ_COMPILE_FLAGS
static char *compile_flags = DNSMASQ_COMPILE_FLAGS;
#endif

/* Define a string indicating which options are in use.
   DNSMASQ_COMPILE_OPTS is only defined in dnsmasq.c */

#ifdef DNSMASQ_COMPILE_OPTS

static char *compile_opts = 
"IPv6 "
#ifndef HAVE_GETOPT_LONG
"no-"
#endif
"GNU-getopt "
#ifdef HAVE_BROKEN_RTC
"no-RTC "
#endif
#ifndef HAVE_DBUS
"no-"
#endif
"DBus "
#ifndef HAVE_UBUS
"no-"
#endif
"UBus "
#ifndef LOCALEDIR
"no-"
#endif
"i18n "
#if defined(HAVE_LIBIDN2)
"IDN2 "
#else
 #if !defined(HAVE_IDN)
"no-"
 #endif 
"IDN " 
#endif
#ifndef HAVE_DHCP
"no-"
#endif
"DHCP "
#if defined(HAVE_DHCP)
#  if !defined (HAVE_DHCP6)
     "no-"
#  endif  
     "DHCPv6 "
#endif
#if !defined(HAVE_SCRIPT)
     "no-scripts "
#else
#  if !defined(HAVE_LUASCRIPT)
     "no-"
#  endif
     "Lua "
#endif
#ifndef HAVE_TFTP
"no-"
#endif
"TFTP "
#ifndef HAVE_CONNTRACK
"no-"
#endif
"conntrack "
#ifndef HAVE_IPSET
"no-"
#endif
"ipset "
#ifndef HAVE_NFTSET
"no-"
#endif
"nftset "
#ifndef HAVE_AUTH
"no-"
#endif
"auth "
#ifndef HAVE_DNSSEC
"no-"
#endif
"DNSSEC "
#ifdef NO_ID
"no-ID "
#endif
#ifndef HAVE_LOOP
"no-"
#endif
"loop-detect "
#ifndef HAVE_INOTIFY
"no-"
#endif
"inotify "
#ifndef HAVE_DUMPFILE
"no-"
#endif
"dumpfile";

#endif /* defined(DNSMASQ_COMPILE_OPTS) */
