# =============================================================================
# Multi-stage Alpine Linux build for dnsmasq (Rust implementation)
#
# Produces a minimal runtime container with a statically-linked dnsmasq binary.
# Supports Alpine Linux versions 3.19.9, 3.20.8, 3.21.5, and 3.22.2 via the
# ALPINE_VERSION build argument.
#
# Build context: the rust/ directory (repository root for the Rust project)
#
# Usage examples:
#   docker build -f deploy/Dockerfile -t dnsmasq-rust .
#   docker build -f deploy/Dockerfile --build-arg ALPINE_VERSION=3.21 -t dnsmasq-rust .
#   docker build -f deploy/Dockerfile --build-arg FEATURES="--all-features" -t dnsmasq-rust .
#
# Runtime examples:
#   docker run -d --name dnsmasq -p 53:53/udp -p 53:53/tcp dnsmasq-rust
#   docker run -d --name dnsmasq -p 53:53/udp -p 67:67/udp \
#     -v /etc/dnsmasq.conf:/etc/dnsmasq.conf:ro dnsmasq-rust
#   docker run -d --cap-add NET_ADMIN --cap-add NET_RAW \
#     -v /etc/dnsmasq.d:/etc/dnsmasq.d:ro dnsmasq-rust --conf-dir=/etc/dnsmasq.d
#
# Drop-in replacement: This container behaves identically to a C dnsmasq
# container. The same configuration files, CLI flags, and network behavior
# apply without modification.
#
# License: GPL-2.0-or-later (same as dnsmasq)
# =============================================================================

# Configurable Alpine Linux base version.
# Tested with: 3.19.9, 3.20.8, 3.21.5, 3.22.2
# Default: 3.22 (latest supported release series)
ARG ALPINE_VERSION=3.22

# =============================================================================
# Stage 1: Builder — compile the Rust dnsmasq binary
# =============================================================================
FROM alpine:${ALPINE_VERSION} AS builder

# Optional build argument to pass additional cargo flags.
# Examples:
#   --build-arg FEATURES=""                (default features only)
#   --build-arg FEATURES="--all-features"  (enable all optional features)
#   --build-arg FEATURES="--features dnssec,dbus"  (specific optional features)
ARG FEATURES=""

# Install build-time system dependencies.
# - build-base: GCC toolchain, make, musl-dev (required by Rust cc crate for
#   native code compilation in dependency crates like ring, nix, libc)
# - musl-dev: musl libc development headers for x86_64-unknown-linux-musl target
# - pkgconfig: dependency detection for optional system libraries (nettle, dbus)
# - curl: required for downloading the rustup installer
# - perl: required by some crate build scripts (e.g., openssl-sys)
#
# Note: Package versions are intentionally unpinned because ALPINE_VERSION is
# configurable (3.19–3.22) and package versions differ between Alpine releases.
# Pinning would break cross-version build compatibility.
# hadolint ignore=DL3018
RUN apk add --no-cache \
    build-base \
    musl-dev \
    pkgconfig \
    curl \
    perl

# Install Rust 1.91.0 via rustup.
# Alpine Linux package repositories ship Rust ~1.87, which is insufficient.
# The project requires Rust 1.91.0 as pinned in rust-toolchain.toml.
# The x86_64-unknown-linux-musl target produces fully statically-linked
# binaries suitable for the minimal Alpine runtime image.
#
# Note: The curl|sh pipe is the official rustup installation method.
# Alpine ash does not support the pipefail shell option.
# hadolint ignore=DL4006
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y \
        --default-toolchain 1.91.0 \
        --target x86_64-unknown-linux-musl \
        --profile minimal \
    && /root/.cargo/bin/rustup component add rustfmt clippy

# Add cargo and rustc to PATH for all subsequent RUN instructions.
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory for the Rust project.
# The Docker build context is the rust/ directory, so all COPY paths are
# relative to that root.
WORKDIR /app

# --- Docker layer caching optimization ---
# Copy dependency manifests and build configuration first, before source code.
# This allows Docker to cache the expensive dependency compilation layer.
# When only Rust source files change, dependencies are not recompiled.
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY .cargo/ .cargo/

# Pre-compile dependencies using stub source files.
# This creates a cached layer containing all compiled dependency crates.
# The stub files satisfy Cargo's requirement for a valid crate structure
# without including any actual project source code.
RUN mkdir -p src && \
    echo 'fn main() { println!("dependency-cache-stub"); }' > src/main.rs && \
    echo '// dependency cache stub' > src/lib.rs && \
    cargo build --release --target x86_64-unknown-linux-musl ${FEATURES} 2>/dev/null || true && \
    rm -rf src/

# Copy the full Rust source tree.
# This invalidates the layer cache only when source files change,
# not when dependencies change (those are cached above).
COPY src/ src/

# Build the release binary targeting musl libc for static linking.
# Default Cargo features enabled (from Cargo.toml [features].default):
#   dhcp, dhcp6, tftp, script, auth, ipset, loop-detect, dumpfile, inotify
# The output binary is at: target/x86_64-unknown-linux-musl/release/dnsmasq
RUN cargo build --release --target x86_64-unknown-linux-musl ${FEATURES}

# Strip debug symbols from the release binary to minimize image size.
# The Cargo.toml [profile.release] already sets strip = true and lto = true,
# but an explicit strip ensures minimal binary size regardless of profile.
RUN strip target/x86_64-unknown-linux-musl/release/dnsmasq 2>/dev/null || true

# =============================================================================
# Stage 2: Runtime — minimal Alpine image with only the dnsmasq binary
# =============================================================================
FROM alpine:${ALPINE_VERSION}

# OCI Image Specification labels (https://github.com/opencontainers/image-spec)
# These provide standard metadata for container registries and tooling.
LABEL maintainer="dnsmasq contributors"
LABEL description="Memory-safe Rust implementation of dnsmasq v2.92"
LABEL version="2.92-rust"
LABEL org.opencontainers.image.title="dnsmasq"
LABEL org.opencontainers.image.description="Memory-safe Rust implementation of dnsmasq - DNS forwarder, DHCP server, and network boot daemon"
LABEL org.opencontainers.image.version="2.92-rust"
LABEL org.opencontainers.image.source="https://thekelleys.org.uk/dnsmasq/doc.html"
LABEL org.opencontainers.image.licenses="GPL-2.0-or-later"
LABEL org.opencontainers.image.vendor="dnsmasq contributors"

# Install minimal runtime dependencies.
# The musl-static binary has zero dynamic library dependencies, but these
# packages provide essential runtime data:
# - ca-certificates: Root CA trust store for DNSSEC trust anchor validation
#   and any TLS operations (DNS-over-TLS upstream connections)
# - tzdata: Timezone database for DHCP lease time calculations and log
#   timestamps. Required for correct lease expiry behavior.
#
# Note: Package versions intentionally unpinned for cross-Alpine-version
# compatibility (ALPINE_VERSION supports 3.19–3.22).
# hadolint ignore=DL3018
RUN apk add --no-cache \
    ca-certificates \
    tzdata

# Create a dedicated system user and group for privilege separation.
#
# dnsmasq privilege separation lifecycle (from src/dnsmasq.c):
#   1. Container starts as root (UID 0) — required by Docker
#   2. dnsmasq binds privileged ports: DNS (53), DHCP (67), TFTP (69)
#   3. dnsmasq initializes all subsystems, network listeners, and file handles
#   4. dnsmasq drops privileges to the 'dnsmasq' user (via --user flag or default)
#   5. On Linux, retains capabilities: CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE
#   6. All subsequent packet processing runs as the unprivileged dnsmasq user
#
# Flags:
#   -S : System account (no password aging)
#   -G : Primary group
#   -H : No home directory
#   -D : No password
#   -s : Login shell (nologin for security)
RUN addgroup -S dnsmasq && \
    adduser -S -G dnsmasq -H -D -s /sbin/nologin dnsmasq

# Create required runtime directories with appropriate ownership.
#
# /etc/dnsmasq.d/     — Configuration fragment directory.
#                       Users mount additional .conf files here and reference
#                       them via the 'conf-dir=/etc/dnsmasq.d' directive.
#
# /var/run/dnsmasq/   — PID file directory.
#                       The 'pid-file=/var/run/dnsmasq/dnsmasq.pid' directive
#                       writes the daemon PID here for service management.
#
# /var/lib/dnsmasq/   — Persistent state directory.
#                       DHCP lease database is stored here via the
#                       'dhcp-leasefile=/var/lib/dnsmasq/dnsmasq.leases' directive.
#                       Must be writable by the dnsmasq user and should be backed
#                       by a Docker volume for lease persistence across restarts.
RUN mkdir -p /etc/dnsmasq.d /var/run/dnsmasq /var/lib/dnsmasq && \
    chown dnsmasq:dnsmasq /var/run/dnsmasq /var/lib/dnsmasq

# Copy the statically-linked dnsmasq binary from the builder stage.
# Installation path follows the C Makefile convention:
#   PREFIX  = /usr/local       (Makefile line 21)
#   BINDIR  = $(PREFIX)/sbin   (Makefile line 22)
# This ensures the Rust binary is a drop-in replacement at the same path.
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/dnsmasq \
    /usr/local/sbin/dnsmasq
RUN chmod 755 /usr/local/sbin/dnsmasq

# Expose standard dnsmasq network service ports.
#
# 53/udp  — DNS queries (primary protocol, RFC 1035)
# 53/tcp  — DNS queries over TCP (large responses >512 bytes, zone transfers)
# 67/udp  — DHCPv4 server (DISCOVER/OFFER/REQUEST/ACK, RFC 2131)
# 69/udp  — TFTP server (PXE network boot, firmware downloads, RFC 1350)
#
# Note: DHCPv6 uses port 547/udp but is typically handled via link-local
# multicast and does not require explicit port mapping in most deployments.
EXPOSE 53/udp 53/tcp 67/udp 69/udp

# Health check: verify dnsmasq configuration is parseable.
# The --test flag causes dnsmasq to parse its configuration, report any errors,
# and exit with status 0 (success) or 1 (failure) without starting the daemon.
# This validates that mounted configuration files are syntactically correct.
#
# Parameters:
#   --interval=30s  : Check every 30 seconds
#   --timeout=5s    : Config parsing should complete within 5 seconds
#   --retries=3     : Mark unhealthy after 3 consecutive failures
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["/usr/local/sbin/dnsmasq", "--test"]

# Default signal for container stop. SIGTERM triggers graceful shutdown
# in dnsmasq (registered in src/dnsmasq.c signal handler setup).
# SIGHUP is reserved for configuration reload (not termination).
STOPSIGNAL SIGTERM

# Container execution configuration.
#
# ENTRYPOINT: The dnsmasq binary at its standard installation path.
#   Using exec form (JSON array) to ensure dnsmasq runs as PID 1 and
#   receives signals directly from Docker (SIGTERM for stop, SIGHUP for reload).
#
# CMD: Default arguments for container operation.
#   -k              : Keep in foreground — prevents daemonization so the
#                     container process stays in the foreground. Required for
#                     Docker to track the process lifecycle correctly.
#   --log-facility=- : Direct all log output to stderr instead of syslog.
#                     This enables Docker log collection via 'docker logs'.
#
# Users can override CMD to pass additional dnsmasq configuration:
#   docker run dnsmasq-rust -k --conf-file=/etc/dnsmasq.d/custom.conf
#   docker run dnsmasq-rust -k --no-daemon --log-queries
ENTRYPOINT ["/usr/local/sbin/dnsmasq"]
CMD ["-k", "--log-facility=-"]
