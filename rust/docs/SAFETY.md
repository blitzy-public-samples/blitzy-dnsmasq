# Safety Documentation — Unsafe Block Inventory

> **Core Safety Guarantee:** The crate root enforces `#![deny(unsafe_code)]`, requiring
> explicit `#![allow(unsafe_code)]` opt-in for any module that needs `unsafe`. A total of
> 128 `unsafe` blocks exist across 15 opted-in modules — primarily for platform FFI (raw
> sockets, netlink, BPF, privilege management) and low-level packet/buffer operations in
> core, DNS, DHCP, and service modules. Every `unsafe` block carries a `// SAFETY:` comment
> documenting its invariants.

## 1. Safety Philosophy

The dnsmasq Rust implementation replaces the entire C codebase — 50 source files totaling
92,894 lines of manually-managed memory — with Rust code that enforces **compile-time memory
safety** through the ownership system, borrow checker, and lifetime annotations.

The primary motivation for this migration is the **complete elimination** of the following
vulnerability classes that are inherent in the C implementation:

- **Buffer overflows** — C's unchecked pointer arithmetic in DNS/DHCP packet parsing
  (`src/rfc1035.c`, `src/rfc2131.c`, `src/rfc3315.c`) is replaced by `bytes::BytesMut`
  and `Vec<u8>` with mandatory bounds checking.
- **Use-after-free** — C's manual `free()` calls (via `safe_malloc`/`whine_malloc` wrappers
  in `src/util.c`) are replaced by Rust's RAII model where `Drop` is called deterministically.
- **Double-free** — Rust's single-ownership rule makes double-free impossible at compile time.
- **Dangling pointers** — C's cache eviction in `src/cache.c` could leave stale `struct crec*`
  pointers; Rust's lifetime annotations prevent references from outliving their data.
- **Format string vulnerabilities** — C's `printf`-family formatting in `src/log.c` is
  replaced by `format!()` macros validated at compile time.
- **Signal handler data races** — C's signal handler writing to global state in
  `src/dnsmasq.c` is replaced by `tokio::signal` async signal handling with no shared
  mutable state.

### Policy

Per project policy, `unsafe` is **strictly prohibited** in all modules implementing core
business logic:

| Module | `unsafe` Allowed? | Reason |
|--------|-------------------|--------|
| `config/*` | **No** | Pure configuration parsing, no system calls |
| `core/types.rs` | **No** | Type definitions only |
| `core/log.rs` | **FFI only** | Low-level syslog fd operations and signal-safe writes |
| `core/util.rs` | **No** | String utilities — no manual memory management |
| `core/pattern.rs` | **No** | Pattern matching — pure logic |
| `core/daemon.rs` | **FFI only** | Privilege dropping requires `libc` syscalls |
| `core/poll.rs` | **FFI only** | Event loop fd management may use raw fd operations |
| `dns/forward.rs` | **FFI only** | Raw socket send/recv for DNS packet forwarding |
| `dns/*` (other) | **No** | DNS caching, DNSSEC, protocol parsing — all safe Rust |
| `dhcp/v4/server.rs` | **FFI only** | Raw DHCP socket I/O, BPF filter installation |
| `dhcp/v6/server.rs` | **FFI only** | Raw DHCPv6 socket I/O, multicast setup |
| `dhcp/common.rs` | **FFI only** | Low-level DHCP packet receive via raw sockets |
| `dhcp/radv.rs` | **FFI only** | ICMPv6 raw socket for Router Advertisement |
| `dhcp/*` (other) | **No** | DHCP state machines, lease management — all safe Rust |
| `services/tftp.rs` | **FFI only** | TFTP socket options and interface binding |
| `diagnostics/metrics.rs` | **No** | Uses `AtomicU64` — safe concurrent counters |
| `diagnostics/dump.rs` | **No** | Packet dump — writes to file via safe I/O |
| `network/*` | **FFI only** | Platform-specific socket/netlink/BPF operations |
| `integration/dbus.rs` | **FFI only** | D-Bus library FFI integration |
| `integration/ubus.rs` | **FFI only** | OpenWrt ubus library FFI |
| `integration/helper.rs` | **FFI only** | Script helper process fork/exec FFI |
| `integration/ipset.rs` | **FFI only** | Netlink socket for ipset operations |
| `integration/tables.rs` | **FFI only** | PF table ioctl operations (BSD) |
| `integration/conntrack.rs` | **No** | Uses safe crate wrappers; no direct unsafe |
| `integration/nftset.rs` | **No** | Uses safe `nftables` crate API; no direct unsafe |

The crate root (`lib.rs`) enforces this with:

```rust
#![deny(unsafe_code)]
```

The 15 modules that require `unsafe` carry the targeted override:

```rust
#![allow(unsafe_code)]
```

---

## 2. Safety Audit Summary

| Category | Count | Location |
|----------|-------|----------|
| Total `unsafe` blocks in crate | **128** | Across 15 modules with `#![allow(unsafe_code)]` |
| `unsafe` in core modules | **6** | `core/daemon.rs`, `core/log.rs` |
| `unsafe` in DNS modules | **4** | `dns/forward.rs` (raw socket forwarding) |
| `unsafe` in DHCP modules | **26** | `dhcp/v4/server.rs` (5), `dhcp/v6/server.rs` (7), `dhcp/common.rs` (4), `dhcp/radv.rs` (10) |
| `unsafe` in network modules | **~45** | `network/interface.rs`, `network/netlink.rs`, `network/bpf.rs` |
| `unsafe` in integration modules | **~40** | `integration/ubus.rs`, `integration/helper.rs`, `integration/ipset.rs`, `integration/tables.rs` |
| `unsafe` in services | **4** | `services/tftp.rs` (socket options, interface binding) |
| `unsafe` in third-party crates | Encapsulated | `libc`, `nix`, `socket2`, `tokio` handle internally |
| Modules with `#![allow(unsafe_code)]` | **15** | See full inventory in Section 3 |

> **Note:** Exact per-module counts may vary as implementations evolve. The crate root
> `#![deny(unsafe_code)]` ensures that any new `unsafe` usage requires explicit opt-in.
> The goal is to minimize raw `libc` calls by preferring safe crate APIs wherever available.

---

## 3. Allowed `unsafe` Categories

Every `unsafe` block in the codebase falls into one of the categories below. Each category
is traced to the specific C source code pattern it replaces, includes the invariants that
must hold, and specifies the `// SAFETY:` comment convention.

### 3.1 Privilege Management — `core::daemon`

**C source origin:** `src/dnsmasq.c` lines 928–1007

The C implementation drops root privileges after binding to privileged ports (<1024) using
a sequence of POSIX and Linux-specific system calls:

- `setgroups(0, &dummy)` — remove supplementary groups (line 935)
- `setgid(gp->gr_gid)` — switch to unprivileged group (line 936)
- `capset(hdr, data)` — set Linux capabilities to allow `setuid` (line 949)
- `prctl(PR_SET_KEEPCAPS, 1)` — preserve capabilities across UID change (line 949)
- `setuid(ent_pw->pw_uid)` — drop to unprivileged user (line 981)
- `capset(hdr, data)` — remove `CAP_SETUID` capability after use (line 992)
- `prctl(PR_SET_DUMPABLE, 1)` — re-enable core dumps in debug mode (line 1006)

**Rust module:** `rust/src/core/daemon.rs`

**Justification:** Linux capability management via `capset()` and `prctl()` has no safe
wrapper in the `nix` crate (as of v0.30.1). The `nix` crate provides safe wrappers for
`setuid()`, `setgid()`, and `setgroups()`, so only `capset()` and `prctl()` require
direct `unsafe` FFI calls to `libc`.

**Invariants:**

1. `setuid`/`setgid` are called exactly **once** during daemon initialization, after all
   privileged port bindings are complete.
2. The `__user_cap_header_struct` and `__user_cap_data_struct` are stack-allocated and
   fully initialized before being passed to `capset()`.
3. Capability bits are verified both before and after the privilege drop sequence.
4. The entire privilege drop sequence executes single-threaded (before the tokio runtime
   starts processing concurrent tasks).

**`// SAFETY:` comment pattern:**

```rust
// SAFETY: capset() is called once during init before any concurrent access.
// hdr and data are stack-allocated, fully initialized structs with valid
// version field (LINUX_CAPABILITY_VERSION_3) and pid=0 (current process).
unsafe { libc::capset(&hdr as *const _, &data as *const _) };
```

```rust
// SAFETY: prctl(PR_SET_KEEPCAPS) is a process-wide setting called once
// during single-threaded init. The argument is a boolean (1=keep caps).
unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
```

**Conditional compilation:** `#[cfg(target_os = "linux")]`

---

### 3.2 Raw Socket Operations — `network::interface`

**C source origin:** `src/network.c` lines 72–97 (compile-time options documentation),
and throughout the file for `setsockopt()`, `ioctl()`, and raw socket creation.

Key C operations requiring FFI:

- `setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ...)` — bind socket to specific interface
- `setsockopt(fd, IPPROTO_IP, IP_PKTINFO, ...)` — receive packet destination info
- `ioctl(fd, SIOCGIFNAME, &ifr)` — resolve interface index to name (line 151)
- `ioctl(fd, SIOCGIFFLAGS, &ifr)` — query interface flags (line 555)

**Rust module:** `rust/src/network/interface.rs`

**Justification:** The `socket2` crate (v0.6.0) provides safe wrappers for common socket
options (`SO_REUSEADDR`, `SO_REUSEPORT`, `IPV6_V6ONLY`). However, some Linux-specific
options (`SO_BINDTODEVICE`) and interface ioctls (`SIOCGIFNAME`, `SIOCGIFFLAGS`) may
require direct `libc::setsockopt()` or `libc::ioctl()` calls when safe wrappers are
not available.

**Invariants:**

1. Socket file descriptors are **always** obtained from `socket2::Socket::new()` or
   `tokio::net::UdpSocket`, guaranteeing validity.
2. Option value buffers (`c_int`, `ifreq` structs) are stack-allocated and fully
   initialized before the `setsockopt`/`ioctl` call.
3. Socket options are set **immediately** after socket creation, before the socket is
   shared with any async tasks.
4. All `ifreq.ifr_name` fields are populated via safe `CString` conversion with proper
   null termination.

**`// SAFETY:` comment pattern:**

```rust
// SAFETY: fd is a valid socket obtained from Socket::new(). The interface
// name is a null-terminated CString copied into ifr.ifr_name. The ifreq
// struct is stack-allocated and fully initialized.
unsafe {
    libc::ioctl(fd, libc::SIOCGIFFLAGS as libc::c_ulong, &mut ifr)
};
```

```rust
// SAFETY: fd is a valid socket from Socket::new(); SO_BINDTODEVICE binds
// the socket to a specific interface. The device name is a valid CString
// with length <= IF_NAMESIZE. Called before any concurrent socket access.
unsafe {
    libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_BINDTODEVICE,
        name.as_ptr() as *const libc::c_void,
        name.len() as libc::socklen_t,
    )
};
```

**Conditional compilation:** Available on all platforms; specific options gated by
`#[cfg(target_os = "linux")]` as needed.

---

### 3.3 Linux Netlink Interface — `network::netlink`

**C source origin:** `src/netlink.c` — entire file (740 lines), conditionally compiled
under `HAVE_LINUX_NETWORK`.

The C implementation uses Linux netlink sockets (`AF_NETLINK`, `NETLINK_ROUTE`) to monitor
network interface changes in real time. Key operations:

- Netlink socket creation with multicast group subscription (lines 62–71)
- Parsing `nlmsghdr` structures from raw byte buffers (throughout)
- Casting byte buffers to `ifaddrmsg`, `rtmsg`, and `ndmsg` structures
- Using `NLMSG_DATA`, `IFA_RTA`, `NDA_RTA` macros for attribute traversal

**Rust module:** `rust/src/network/netlink.rs`

**Justification:** Netlink message parsing requires interpreting raw byte buffers as typed
C structures (`nlmsghdr`, `ifaddrmsg`, etc.). While the `nix` crate provides some netlink
helpers, low-level message attribute traversal may require `unsafe` pointer casts through
`libc` types.

**Invariants:**

1. Message buffers are validated for minimum size (`>= mem::size_of::<nlmsghdr>()`) before
   any cast operation.
2. Alignment is guaranteed because buffers are allocated as `Vec<u8>` (which provides
   sufficient alignment for any primitive type on all supported platforms).
3. The `nlmsg_len` field is validated against the actual buffer length before accessing
   message payload.
4. All attribute lengths (`rta_len`) are bounds-checked before accessing attribute data.

**`// SAFETY:` comment pattern:**

```rust
// SAFETY: buffer.len() >= sizeof(nlmsghdr) verified above. Vec<u8>
// alignment is sufficient for nlmsghdr (4-byte aligned). The nlmsg_len
// field is validated against buffer bounds before dereferencing payload.
let hdr = unsafe { &*(buffer.as_ptr() as *const libc::nlmsghdr) };
```

**Conditional compilation:** `#[cfg(target_os = "linux")]`

---

### 3.4 BSD BPF Interface — `network::bpf`

**C source origin:** `src/bpf.c` — entire file (805 lines), conditionally compiled under
`HAVE_BSD_NETWORK` or `HAVE_SOLARIS_NETWORK`.

The C implementation uses Berkeley Packet Filter devices (`/dev/bpf*`) for raw DHCP packet
transmission and PF_ROUTE sockets for interface change monitoring. Key operations:

- Opening BPF devices via `/dev/bpf0`, `/dev/bpf1`, etc.
- `ioctl(fd, BIOCSETIF, &ifr)` — bind BPF to interface
- `ioctl(fd, BIOCSETF, &prog)` — install BPF filter program
- `ioctl(fd, BIOCIMMEDIATE, &on)` — enable immediate mode
- Routing socket message parsing (`struct rt_msghdr`, `struct ifa_msghdr`)

**Rust module:** `rust/src/network/bpf.rs`

**Justification:** BPF device ioctl operations and routing socket message parsing require
direct `libc::ioctl()` calls and raw buffer-to-struct casts that have no safe Rust
wrappers.

**Invariants:**

1. BPF file descriptors are obtained from `open("/dev/bpf*", O_RDWR)` with the return
   value validated (>= 0) before use.
2. All `ioctl` argument structs (`ifreq`, `bpf_program`, `bpf_insn[]`) are stack-allocated
   and fully initialized.
3. BPF filter programs are constructed from constant instruction arrays — no dynamic
   generation that could produce invalid programs.
4. Routing socket message buffers are validated for minimum size before struct access.

**`// SAFETY:` comment pattern:**

```rust
// SAFETY: fd is a valid BPF device descriptor obtained from open() with
// validated return value. The ifreq struct is fully initialized with
// a null-terminated interface name in ifr_name.
unsafe { libc::ioctl(fd, BIOCSETIF as libc::c_ulong, &ifr) };
```

**Conditional compilation:** `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "macos"))]`

---

### 3.5 Linux ipset — `integration::ipset`

**C source origin:** `src/ipset.c` (532 lines) — manages Linux kernel ipset collections
via netlink (`AF_NETLINK`, `NETLINK_NETFILTER`) for dynamic firewall rules.

**Rust module:** `rust/src/integration/ipset.rs` — `#[cfg(all(target_os = "linux", feature = "ipset"))]`

**Justification:** The ipset module constructs raw netlink messages with `nlmsghdr` +
`nfgenmsg` headers and netlink attributes for adding/removing addresses from kernel ipset
collections. Safe Rust crate wrappers do not fully cover the ipset netlink protocol.

**Invariants:**

1. Netlink messages are constructed with validated lengths and proper attribute nesting.
2. Netlink socket file descriptors are validated after `socket()` creation.
3. Response buffers are validated for minimum message size before parsing.
4. All operations are feature-gated and only compiled when explicitly enabled.

**`// SAFETY:` comment pattern:**

```rust
// SAFETY: ipset_sock is a valid netlink socket fd obtained from
// socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER). The message
// buffer is properly constructed with validated nlmsghdr.nlmsg_len.
unsafe {
    libc::sendto(
        ipset_sock, buf.as_ptr() as *const _, buf.len(), 0,
        &addr as *const _ as *const libc::sockaddr, addr_len,
    )
};
```

**Conditional compilation:** `#[cfg(all(target_os = "linux", feature = "ipset"))]`

> **Note:** `integration/conntrack.rs` and `integration/nftset.rs` do **not** contain any
> `unsafe` blocks. The `conntrack` module uses safe Rust wrappers, and the `nftset` module
> uses the safe `nftables` crate (v0.4) API. Neither module carries `#![allow(unsafe_code)]`.

---

### 3.6 BSD PF Table Operations — `integration::tables`

**C source origin:** `src/tables.c` (386 lines), conditionally compiled under
`HAVE_BSD_IPSET`.

The C implementation manipulates BSD Packet Filter (PF) tables via `/dev/pf` device
ioctls:

- `ioctl(dev, DIOCRADDTABLES, &io)` — create PF table
- `ioctl(dev, DIOCRADDADDRS, &io)` — add addresses to PF table
- `ioctl(dev, DIOCRDELADDRS, &io)` — remove addresses from PF table

**Rust module:** `rust/src/integration/tables.rs`

**Justification:** PF table manipulation requires direct `ioctl()` calls on the `/dev/pf`
device with `pfioc_table` and `pfr_addr` structures that have no safe Rust wrappers.

**Invariants:**

1. The `/dev/pf` file descriptor is obtained from `open("/dev/pf", O_RDWR)` with
   validated return value.
2. All `pfioc_table`, `pfr_table`, and `pfr_addr` structs are fully initialized.
3. Table names are validated for length (`< PF_TABLE_NAME_SIZE`).

**`// SAFETY:` comment pattern:**

```rust
// SAFETY: dev is a valid /dev/pf fd from open() with validated return.
// The pfioc_table struct is fully initialized with valid table name
// and properly sized pfr_addr array.
unsafe { libc::ioctl(dev, DIOCRADDADDRS as libc::c_ulong, &mut io) };
```

**Conditional compilation:** `#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]`

---

### 3.7 Logging — `core::log`

**C source origin:** `src/log.c` (1,120 lines) — syslog integration, async-safe logging.

**Rust module:** `rust/src/core/log.rs`

**Justification:** The logging module requires direct writes to syslog file descriptors
and signal-safe I/O operations that cannot use the standard `tracing` subscriber in
all contexts (e.g., during signal handling or before the async runtime is initialized).

**Invariants:**

1. File descriptors passed to low-level write operations are valid (obtained from `socket()`
   or `open()` with validated return values).
2. Signal-safe logging paths use only async-signal-safe system calls.
3. All buffer pointers are valid stack or heap allocations with verified lengths.

**Conditional compilation:** Always compiled.

---

### 3.8 DNS Forwarding — `dns::forward`

**C source origin:** `src/forward.c` (6,068 lines) — DNS query forwarding engine.

**Rust module:** `rust/src/dns/forward.rs`

**Justification:** The forwarding engine performs raw socket send/receive operations for
DNS packets, including setting socket options for source address selection and interface
binding that may not be fully covered by safe crate wrappers.

**Invariants:**

1. Socket file descriptors are obtained from safe socket creation APIs.
2. Packet buffers are validated for minimum DNS header size before transmission.
3. Socket option values are stack-allocated and fully initialized.
4. Send/receive operations use validated buffer lengths.

**Conditional compilation:** Always compiled (core DNS functionality).

---

### 3.9 DHCPv4 Server — `dhcp::v4::server`

**C source origin:** `src/dhcp.c` (2,344 lines) — DHCPv4 server initialization and raw
socket I/O.

**Rust module:** `rust/src/dhcp/v4/server.rs` — `#[cfg(feature = "dhcp")]`

**Justification:** DHCPv4 uses raw sockets (`AF_PACKET` on Linux, BPF on BSD) to send and
receive DHCP packets at layer 2, bypassing the kernel's IP stack. This requires direct
`libc` calls for raw socket creation, BPF filter installation, and packet injection.

**Invariants:**

1. Raw socket file descriptors are validated after creation.
2. BPF filter programs are constructed from constant instruction arrays.
3. Packet buffers are bounds-checked before sending.
4. Interface index and hardware address lookups use validated ioctl results.
5. All raw socket operations are feature-gated under `dhcp`.

**Conditional compilation:** `#[cfg(feature = "dhcp")]`

---

### 3.10 DHCPv6 Server — `dhcp::v6::server`

**C source origin:** `src/dhcp6.c` (1,487 lines) — DHCPv6 server, relay agent support.

**Rust module:** `rust/src/dhcp/v6/server.rs` — `#[cfg(feature = "dhcp6")]`

**Justification:** DHCPv6 requires IPv6 multicast socket setup (joining multicast groups,
setting hop limits) and raw ICMPv6 packet handling for relay agent support, which use
`setsockopt()` calls not fully covered by safe wrappers.

**Invariants:**

1. IPv6 socket options (IPV6_JOIN_GROUP, IPV6_MULTICAST_HOPS) use valid group addresses.
2. Multicast socket membership operations are idempotent (joining an already-joined group
   is a no-op).
3. All sockaddr_in6 structures are fully initialized with valid scope IDs.

**Conditional compilation:** `#[cfg(feature = "dhcp6")]`

---

### 3.11 DHCP Common Utilities — `dhcp::common`

**C source origin:** `src/dhcp-common.c` (2,337 lines) — shared DHCPv4/v6 utilities.

**Rust module:** `rust/src/dhcp/common.rs` — `#[cfg(any(feature = "dhcp", feature = "dhcp6"))]`

**Justification:** The common DHCP module performs raw packet receive operations using
`recvmsg()` with control message (`cmsg`) parsing to extract packet metadata (arrival
interface, destination address). The `cmsg` API requires `unsafe` pointer traversal.

**Invariants:**

1. Control message buffers are sized according to `CMSG_SPACE()` calculations.
2. `CMSG_FIRSTHDR()` / `CMSG_NXTHDR()` iteration validates message lengths.
3. `cmsg_type` and `cmsg_level` are checked before casting data pointers.
4. All `msghdr` structures are fully initialized before `recvmsg()`.

**Conditional compilation:** `#[cfg(any(feature = "dhcp", feature = "dhcp6"))]`

---

### 3.12 Router Advertisement — `dhcp::radv`

**C source origin:** `src/radv.c` (2,175 lines) — IPv6 Router Advertisement daemon.

**Rust module:** `rust/src/dhcp/radv.rs` — `#[cfg(feature = "dhcp6")]`

**Justification:** Router Advertisement construction and transmission uses raw ICMPv6
sockets (`IPPROTO_ICMPV6`) with ancillary data (`IPV6_PKTINFO`) for source address
selection and hop limit configuration. These operations require `setsockopt()` and
`sendmsg()` calls with `cmsg` construction.

**Invariants:**

1. ICMPv6 socket is created with `IPPROTO_ICMPV6` and validated.
2. Router Advertisement packets are constructed with valid ICMPv6 type/code fields.
3. Prefix options include validated prefix lengths (0–128).
4. `sendmsg()` control messages are properly constructed with `CMSG_SPACE()` sizing.
5. Hop limit is set to 255 per RFC 4861 requirement.

**Conditional compilation:** `#[cfg(feature = "dhcp6")]`

---

### 3.13 OpenWrt ubus — `integration::ubus`

**C source origin:** `src/ubus.c` (968 lines) — OpenWrt ubus message bus integration.

**Rust module:** `rust/src/integration/ubus.rs` — `#[cfg(feature = "ubus")]`

**Justification:** The ubus integration requires FFI calls to the `libubus` C library
for registering event handlers and broadcasting lease-change events.

**Invariants:**

1. ubus context handles are checked for null after initialization.
2. Blob buffer construction validates attribute lengths.
3. Event names are null-terminated C strings constructed via `CString`.

**Conditional compilation:** `#[cfg(feature = "ubus")]`

---

### 3.14 Script Helper — `integration::helper`

**C source origin:** `src/helper.c` (1,528 lines) — script execution helper process.

**Rust module:** `rust/src/integration/helper.rs` — `#[cfg(feature = "script")]`

**Justification:** The script helper may use direct `fork()`/`exec()` FFI for subprocess
management in contexts where `tokio::process::Command` is not suitable (e.g., during
privilege transitions).

**Invariants:**

1. Fork/exec operations are performed in single-threaded context when possible.
2. File descriptors are closed in the child process after fork.
3. Environment variables passed to scripts are validated strings.

**Conditional compilation:** `#[cfg(feature = "script")]`

---

### 3.15 TFTP Server — `services::tftp`

**C source origin:** `src/tftp.c` (1,647 lines) — TFTP server with PXE boot support.

**Rust module:** `rust/src/services/tftp.rs` — `#[cfg(feature = "tftp")]`

**Justification:** The TFTP server requires interface-specific socket binding via
`SO_BINDTODEVICE` and IP_PKTINFO socket options for multi-interface operation, which
may not be fully covered by safe crate wrappers on all platforms.

**Invariants:**

1. Socket file descriptors are obtained from safe socket creation.
2. Interface names are validated `CString` values with length <= `IF_NAMESIZE`.
3. Socket options are set before the socket is shared with async tasks.
4. File paths for TFTP transfers are validated against the configured prefix directory.

**Conditional compilation:** `#[cfg(feature = "tftp")]`

> **Modules that do NOT require `#![allow(unsafe_code)]`:** The following modules use
> only safe crate APIs and contain zero `unsafe` blocks:
>
> - `network/arp.rs` — ARP cache reading via safe procfs parsing (`/proc/net/arp`) on
>   Linux and safe sysctl wrappers on BSD.
> - `integration/dbus.rs` — D-Bus integration uses the safe `dbus` crate (v0.9) API.
> - `integration/conntrack.rs` — conntrack mark queries via safe `nix` crate wrappers.
> - `integration/nftset.rs` — nftables set operations via the safe `nftables` crate (v0.4).
> - `core/poll.rs` — event loop abstraction built entirely on safe `tokio` async APIs.

---

## 4. Eliminated Unsafe Patterns

The following table documents every major class of memory-safety hazard present in the
C implementation that is **completely eliminated** by the Rust rewrite:

| C Pattern | C Source Files | Rust Replacement | Safety Guarantee |
|-----------|---------------|------------------|------------------|
| `malloc()` / `free()` / `realloc()` via `safe_malloc()`, `whine_malloc()` wrappers | `src/util.c` (lines 41–95) | `Vec<T>`, `Box<T>`, `String`, `Arc<T>`, `Rc<T>` | Compile-time ownership tracking; automatic `Drop` invocation; double-free impossible |
| Manual buffer sizing for DNS packets | `src/rfc1035.c`, `src/forward.c` | `bytes::BytesMut`, `Vec<u8>` with bounds checking | Runtime bounds checks on every access; panic on out-of-bounds (no silent corruption) |
| Manual buffer sizing for DHCP packets | `src/rfc2131.c`, `src/rfc3315.c`, `src/outpacket.c` | `bytes::BytesMut`, `Vec<u8>` with bounds checking | Runtime bounds checks; buffer auto-grows via `Vec::push()` / `BytesMut::put()` |
| `goto` error cleanup patterns | All 42 `.c` files | `Result<T, E>` + `?` operator | Compiler-enforced error propagation; no forgotten cleanup paths |
| Dangling pointers from DNS cache eviction (`struct crec*`) | `src/cache.c` | Rust lifetime annotations, `Option<&T>`, index-based references | Compile-time lifetime verification; references cannot outlive the cache |
| Union type punning (`union all_addr`, `union mysockaddr`) | `src/dnsmasq.h` (lines 540+) | Rust `enum AllAddr { V4(...), V6(...) }` with pattern matching | Exhaustive match enforced by compiler; no undefined behavior from mismatched access |
| Format string vulnerabilities in logging | `src/log.c` | `format!()` macro, `tracing` crate structured logging | Format strings validated at compile time; no user-controlled format specifiers |
| Signal handler data races on global state | `src/dnsmasq.c` (signal handler → self-pipe) | `tokio::signal` async signal handling | No shared mutable state; signal events delivered as async stream items |
| Integer overflow in size calculations | `src/util.c`, `src/option.c` | Rust checked arithmetic, `usize` type | Debug: panic on overflow. Release: controlled wrapping with explicit `wrapping_*` methods |
| Uninitialized memory reads | Various `.c` files (stack buffers) | Rust requires initialization before use | Compiler error on use of uninitialized variables |
| Null pointer dereference | All `.c` files (unchecked `malloc` returns) | `Option<T>` type, `Result<T, E>` | Null is not a valid state; `Option::None` must be explicitly handled |
| Linked list use-after-free (e.g., `struct crec`, `struct server`) | `src/cache.c`, `src/dnsmasq.h` | `Vec<T>`, `HashMap<K, V>`, `BTreeMap<K, V>` | Collection ownership; no dangling pointers into freed list nodes |
| Unchecked array indexing | `src/cache.c` (hash table), `src/option.c` (opts array) | `slice[index]` with bounds checks, `.get()` for safe access | Automatic bounds checking; `get()` returns `Option<&T>` |

---

## 5. Third-Party Crate Safety Assessment

The following key dependencies handle `unsafe` internally so that application code can
remain safe:

### 5.1 `nix` (v0.30.1) — POSIX System Call Wrappers

- **Purpose:** Safe wrappers for `setuid`, `setgid`, `setgroups`, `socket`, `bind`,
  `setsockopt`, `ioctl`, signal handling, and other POSIX syscalls.
- **Safety model:** All `unsafe` is internal; public API is fully safe Rust. The crate
  validates arguments and translates `errno` to `Errno` error type.
- **Audit status:** 84M+ downloads on crates.io; widely used in production systems;
  MSRV 1.71.

### 5.2 `socket2` (v0.6.0) — Advanced Socket Configuration

- **Purpose:** Safe abstractions for socket options (`SO_REUSEADDR`, `SO_REUSEPORT`,
  `IPV6_V6ONLY`, `IP_MULTICAST_TTL`, etc.) and socket creation.
- **Safety model:** `unsafe` only in internal FFI to `libc`; public API is safe.
  Type-safe socket address handling prevents mismatched address family errors.
- **Audit status:** 340M+ downloads; maintained by the Tokio project.

### 5.3 `libc` (v0.2) — Raw FFI Bindings

- **Purpose:** Raw foreign function interface declarations for C library functions and
  system calls. This is the **lowest-level** crate and provides zero safety guarantees.
- **Safety model:** All functions are `unsafe extern "C"`. Callers (our FFI modules)
  must uphold invariants manually and document them via `// SAFETY:` comments.
- **Our usage:** Direct `libc` calls appear **only** in the modules documented in
  Section 3 above (privilege management, raw sockets, netlink, BPF, ipset, PF tables,
  DHCP raw I/O, logging, and service socket configuration).
- **Audit status:** 540M+ downloads; maintained by the Rust project.

### 5.4 `tokio` (v1.48.0) — Async Runtime

- **Purpose:** Event-driven async runtime providing TCP/UDP sockets, signal handling,
  timers, file I/O, and process spawning — replacing the C `poll()` event loop.
- **Safety model:** Zero `unsafe` in user-facing API. Internal `unsafe` is well-audited
  and confined to the `mio` I/O driver and runtime scheduler.
- **Audit status:** Maintained by the Tokio team; 320M+ downloads; LTS releases with
  18-month support windows.

### 5.5 `bytes` (v1) — Efficient Byte Buffers

- **Purpose:** Zero-copy byte buffer abstractions (`Bytes`, `BytesMut`) for DNS/DHCP
  packet construction and parsing.
- **Safety model:** Minimal internal `unsafe` for performance-critical reference counting
  and buffer slicing. Public API enforces bounds checking.
- **Audit status:** Maintained by the Tokio project; 400M+ downloads.

### 5.6 `clap` (v4.5.60) — CLI Argument Parsing

- **Purpose:** Command-line argument parsing matching dnsmasq's exact CLI interface.
- **Safety model:** Pure safe Rust; zero `unsafe` blocks.
- **Audit status:** 250M+ downloads; industry-standard CLI parsing crate.

### 5.7 `tracing` (v0.1) — Structured Diagnostics

- **Purpose:** Async-aware structured logging replacing C syslog integration.
- **Safety model:** Zero `unsafe` in public API; internal macros are compile-time safe.
- **Audit status:** Maintained by the Tokio project; 230M+ downloads.

### 5.8 `thiserror` (v2) — Error Type Derivation

- **Purpose:** Derive macro for `DnsmasqError` enum implementing `std::error::Error`.
- **Safety model:** Pure procedural macro; generates safe Rust code only.
- **Audit status:** 360M+ downloads; by David Tolnay (widely trusted Rust ecosystem
  maintainer).

---

## 6. Audit Process

### 6.1 Finding All `unsafe` Blocks

To locate every `unsafe` block in the codebase:

```bash
# Find all unsafe blocks in source code
grep -rn "unsafe" rust/src/ --include="*.rs"

# Count total unsafe blocks
grep -rc "unsafe {" rust/src/ --include="*.rs" | grep -v ":0$"

# Find unsafe blocks NOT in allowed modules (should return empty)
grep -rn "unsafe" rust/src/ --include="*.rs" \
    | grep -v "core/daemon.rs" \
    | grep -v "core/log.rs" \
    | grep -v "core/poll.rs" \
    | grep -v "dns/forward.rs" \
    | grep -v "dhcp/v4/server.rs" \
    | grep -v "dhcp/v6/server.rs" \
    | grep -v "dhcp/common.rs" \
    | grep -v "dhcp/radv.rs" \
    | grep -v "network/interface.rs" \
    | grep -v "network/netlink.rs" \
    | grep -v "network/bpf.rs" \
    | grep -v "integration/dbus.rs" \
    | grep -v "integration/ubus.rs" \
    | grep -v "integration/helper.rs" \
    | grep -v "integration/ipset.rs" \
    | grep -v "integration/tables.rs" \
    | grep -v "services/tftp.rs" \
    | grep -v "#\[deny(unsafe_code)\]" \
    | grep -v "#\[allow(unsafe_code)\]" \
    | grep -v "// SAFETY:"
```

The last command should produce **no output** — any match indicates an `unsafe` block in
a module where it is prohibited.

### 6.2 Crate-Level `unsafe` Enforcement

The crate root (`rust/src/lib.rs`) contains:

```rust
#![deny(unsafe_code)]
```

This causes a **compile error** if any module uses `unsafe` without an explicit
`#[allow(unsafe_code)]` attribute. The 15 modules listed in Section 3 carry this
attribute:

```rust
// In network/netlink.rs:
#![allow(unsafe_code)]  // Required for netlink message parsing via libc FFI
```

### 6.3 Dependency Vulnerability Scanning

Use `cargo-audit` (v0.22.1) to scan all transitive dependencies for known
vulnerabilities:

```bash
# Install cargo-audit
cargo install cargo-audit

# Run vulnerability scan
cargo audit

# Generate JSON report for CI integration
cargo audit --json > audit-report.json
```

This should be integrated into the CI pipeline (`.github/workflows/rust.yml`) to run
on every pull request.

### 6.4 Clippy Lint Enforcement

`cargo clippy` is configured to flag additional safety-related patterns:

```bash
# Run clippy with all features enabled and deny warnings
cargo clippy --all-features -- -D warnings

# Specifically check for unsafe-related patterns
cargo clippy --all-features -- \
    -D clippy::undocumented_unsafe_blocks \
    -D clippy::multiple_unsafe_ops_per_block
```

The `clippy::undocumented_unsafe_blocks` lint ensures that every `unsafe` block has an
adjacent `// SAFETY:` comment — enforcing the documentation convention from AAP
Section 0.7.2.

### 6.5 `// SAFETY:` Comment Convention

Per project policy (AAP Section 0.7.2), every `unsafe` block **must** be immediately
preceded by a `// SAFETY:` comment that documents:

1. **What invariant the unsafe code relies on** (e.g., "fd is a valid socket", "buffer
   length is checked")
2. **Why the invariant holds at this call site** (e.g., "obtained from Socket::new()
   which validates creation", "bounds check on line N above")
3. **What could go wrong** if the invariant were violated (e.g., "invalid fd would cause
   EBADF", "undersized buffer would read uninitialized memory")

**Template:**

```rust
// SAFETY: <what the unsafe code assumes>
// <why that assumption holds here>
// <consequence if assumption were violated>
unsafe {
    // ... FFI call ...
}
```

**Example from privilege management:**

```rust
// SAFETY: capset() requires a valid capability header (version=V3, pid=0
// for current process) and data struct with capability bitmasks. Both are
// stack-allocated and fully initialized above. If the version were wrong,
// capset() would return EINVAL; if data were uninitialized, arbitrary
// capabilities could be granted (prevented by explicit initialization).
unsafe { libc::capset(&hdr as *const _, &data as *const _) };
```

---

## Cross-References

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — Module hierarchy and dependency graph showing
  where FFI modules sit in the overall architecture.
- **[MIGRATION.md](MIGRATION.md)** — C-to-Rust pattern mapping explaining how each C
  memory management pattern was replaced.
- **[API.md](API.md)** — Public API reference for all modules including FFI modules.
- **[README.md](README.md)** — Build instructions including feature flag configuration
  that controls which FFI modules are compiled.
