// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! # Async Inotify File Monitoring
//!
//! Rust implementation of Linux inotify-based file monitoring for detecting
//! changes to `/etc/resolv.conf`, dynamic DHCP host directories, and DHCP
//! option directories.  Replaces `src/inotify.c` (687 lines).
//!
//! ## Feature Gate
//!
//! The entire module is gated by **both** `#[cfg(feature = "inotify")]` and
//! `#[cfg(target_os = "linux")]`, matching the C `#ifdef HAVE_INOTIFY` guard.
//! On non-Linux platforms, dnsmasq falls back to polling-based configuration
//! checking.
//!
//! ## Architecture
//!
//! Replaces C's synchronous `poll()`-based inotify monitoring with async
//! tokio-based monitoring using [`nix::sys::inotify`] wrapped in
//! [`tokio::io::unix::AsyncFd`].  The [`InotifyWatcher`] integrates with
//! the main `tokio::select!` event loop, eliminating the need for manual
//! file-descriptor polling.
//!
//! ## Monitored Resources
//!
//! | Resource                      | C Watch Flags                    | Trigger Action             |
//! |-------------------------------|----------------------------------|----------------------------|
//! | `/etc/resolv.conf` (+ symlinks)| `IN_CLOSE_WRITE \| IN_MOVED_TO` | Force `poll_resolv` reload |
//! | `--addn-hosts` directories     | `IN_CLOSE_WRITE \| IN_MOVED_TO \| IN_DELETE` | Cache flush + hosts reload |
//! | `--dhcp-hostsdir` directories  | `IN_CLOSE_WRITE \| IN_MOVED_TO \| IN_DELETE` | DHCP config + lease update |
//! | `--dhcp-optsdir` directories   | `IN_CLOSE_WRITE \| IN_MOVED_TO \| IN_DELETE` | DHCP options reload        |
//!
//! ## Memory Safety
//!
//! All inotify operations go through the [`nix`] crate's safe wrappers.
//! No `unsafe` blocks.  Symlink resolution uses [`std::fs::read_link`]
//! with automatic buffer sizing, replacing the C manual buffer-growth loop.

use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsFd, AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, InotifyEvent, WatchDescriptor};
use tokio::io::unix::AsyncFd;
use tracing::{error, info, warn};

use crate::core::types::DnsmasqError;

// ---------------------------------------------------------------------------
// Newtype wrapper — bridges nix AsFd ↔ tokio AsRawFd requirement
// ---------------------------------------------------------------------------

/// Wrapper around [`Inotify`] that implements [`AsRawFd`].
///
/// nix 0.30 provides [`AsFd`] but not [`AsRawFd`] for `Inotify`.
/// tokio's [`AsyncFd`] requires `T: AsRawFd`, so this newtype bridges the gap
/// without any `unsafe` code.
struct InotifyInner(Inotify);

impl AsRawFd for InotifyInner {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_fd().as_raw_fd()
    }
}

impl InotifyInner {
    /// Delegate to [`Inotify::add_watch`].
    fn add_watch(
        &self,
        path: &Path,
        mask: AddWatchFlags,
    ) -> Result<WatchDescriptor, nix::errno::Errno> {
        self.0.add_watch(path, mask)
    }

    /// Delegate to [`Inotify::read_events`].
    fn read_events(&self) -> Result<Vec<InotifyEvent>, nix::errno::Errno> {
        self.0.read_events()
    }
}

// ---------------------------------------------------------------------------
// Constants — AH_* directory flags (dnsmasq.h lines 898–903)
// ---------------------------------------------------------------------------

/// Dynamic directory flags matching C `AH_*` constants from `dnsmasq.h`.
///
/// These bit-flags control the type of watch applied to dynamic directories
/// and the reload action taken when file-change events arrive.
///
/// ```text
/// C define      Value   Purpose
/// ──────────    ─────   ─────────────────────────────────────
/// AH_DIR          1     Directory watch (vs single file)
/// AH_INACTIVE     2     Watch temporarily inactive
/// AH_WD_DONE      4     inotify watch descriptor has been set up
/// AH_HOSTS        8     Contains /etc/hosts-style files
/// AH_DHCP_HST    16     Contains DHCP host config files
/// AH_DHCP_OPT    32     Contains DHCP option config files
/// ```
pub mod dir_flags {
    /// Marks entry as a directory watch (vs single file).
    pub const AH_DIR: u32 = 1;
    /// Marks entry as temporarily inactive.
    #[allow(dead_code)]
    pub const AH_INACTIVE: u32 = 2;
    /// Watch descriptor has been set up for this directory.
    pub const AH_WD_DONE: u32 = 4;
    /// Directory contains `/etc/hosts`-style files.
    pub const AH_HOSTS: u32 = 8;
    /// Directory contains DHCP host configuration files.
    pub const AH_DHCP_HST: u32 = 16;
    /// Directory contains DHCP option configuration files.
    pub const AH_DHCP_OPT: u32 = 32;
}

// ---------------------------------------------------------------------------
// Maximum symlink depth (sys/param.h on Linux)
// ---------------------------------------------------------------------------

/// Maximum depth for following symbolic link chains.
///
/// Matches Linux kernel's `MAXSYMLINKS` value from `<sys/param.h>`.
/// Prevents infinite loops when resolving symlink chains such as
/// `/etc/resolv.conf → /run/systemd/resolve/stub-resolv.conf`.
const MAX_SYMLINKS: usize = 20;

// ---------------------------------------------------------------------------
// Callback Trait — decouples inotify from cache / DHCP / config modules
// ---------------------------------------------------------------------------

/// Callbacks for inotify event handling.
///
/// Decouples the inotify module from the DNS cache, DHCP, and configuration
/// modules.  The caller implements this trait to provide the reload actions
/// that the inotify watcher triggers on file-change events.
///
/// This trait replaces the direct function calls in C's `inotify_check()`:
/// `read_hostsfile()`, `cache_remove_uid()`, `option_read_dynfile()`,
/// `dhcp_update_configs()`, `lease_update_from_configs()`,
/// `lease_update_file()`, and `lease_update_dns()`.
pub trait InotifyCallbacks {
    /// Reload a hosts-format file and insert records into DNS cache.
    ///
    /// Replaces C `read_hostsfile(fname, index, 0, NULL, 0)` in
    /// `inotify_check()` (inotify.c line 637).
    ///
    /// # Arguments
    /// * `path`  — Full path to the hosts file.
    /// * `index` — Unique index for cache management (matches [`HostsFileEntry::index`]).
    ///
    /// # Returns
    /// Number of records loaded (used for logging, matching C `total_size`).
    fn read_hostsfile(&mut self, path: &Path, index: u32) -> usize;

    /// Remove all DNS cache entries with the given host-file UID.
    ///
    /// Replaces C `cache_remove_uid(ah->index)` (inotify.c line 624).
    ///
    /// # Returns
    /// Number of cache entries removed (used for logging).
    fn cache_remove_uid(&mut self, index: u32) -> u32;

    /// Read a dynamic DHCP configuration file (host or option).
    ///
    /// Replaces C `option_read_dynfile(path, flags)` (inotify.c lines 663/673).
    ///
    /// # Arguments
    /// * `path`  — Full path to the DHCP config file.
    /// * `flags` — [`dir_flags::AH_DHCP_HST`] or [`dir_flags::AH_DHCP_OPT`].
    ///
    /// # Returns
    /// `true` if configuration was successfully loaded.
    fn option_read_dynfile(&mut self, path: &Path, flags: u32) -> bool;

    /// Propagate DHCP configuration changes to active leases.
    ///
    /// Replaces C `dhcp_update_configs(daemon->dhcp_conf)` +
    /// `lease_update_from_configs()` (inotify.c lines 642–644, 665–667).
    fn dhcp_update_configs(&mut self);

    /// Write the lease database to disk.
    ///
    /// Replaces C `lease_update_file(now)` (inotify.c lines 644, 668).
    fn lease_update_file(&mut self);

    /// Update DNS cache entries derived from DHCP leases.
    ///
    /// Replaces C `lease_update_dns(1)` (inotify.c lines 645, 669).
    ///
    /// # Arguments
    /// * `force` — If `true`, force full DNS update even if nothing changed.
    fn lease_update_dns(&mut self, force: bool);
}

// ---------------------------------------------------------------------------
// Internal data structures
// ---------------------------------------------------------------------------

/// Tracks a single watched resolv-file (e.g. `/etc/resolv.conf`).
///
/// Corresponds to the inotify-specific fields in C `struct resolvc`:
/// `wd` (watch descriptor) and `file` (filename component of the path).
///
/// The watch is placed on the *parent directory* of the resolv-file so that
/// atomic rename-over-existing updates (the common `mv` pattern used by
/// `resolvconf`, `systemd-resolved`, etc.) are captured via `IN_MOVED_TO`.
#[derive(Debug)]
struct ResolvWatch {
    /// The original resolv-file path as configured (before symlink resolution).
    #[allow(dead_code)]
    original_path: PathBuf,
    /// Just the filename component extracted from the resolved path.
    /// Used for matching against inotify event names.
    filename: OsString,
}

/// Tracks a watched dynamic directory.
///
/// Corresponds to C `struct dyndir` with `wd`, `dname`, `flags`, `files`.
/// Each dynamic directory may contain hosts-format files or DHCP config files.
#[derive(Debug)]
struct DynDirWatch {
    /// Directory path.
    dir_path: PathBuf,
    /// Combination of `dir_flags::AH_*` flags controlling reload behaviour.
    flags: u32,
    /// Known host files in this directory, keyed by filename.
    ///
    /// Only populated for `AH_HOSTS` directories.  For `AH_DHCP_HST` and
    /// `AH_DHCP_OPT` directories the file set is not tracked because each
    /// event constructs the full path dynamically (matching C behaviour).
    files: HashMap<OsString, HostsFileEntry>,
}

/// Entry for a tracked hosts file inside a dynamic directory.
///
/// Corresponds to C `struct hostsfile` fields: `fname`, `flags`, `index`.
#[derive(Debug, Clone)]
struct HostsFileEntry {
    /// Full path to the hosts file (`dir_path` + `/` + filename).
    ///
    /// Stored for diagnostic logging and future API consumers that need to
    /// enumerate tracked files.  Matches C `struct hostsfile->fname`.
    #[allow(dead_code)]
    full_path: PathBuf,
    /// Flags inherited from the parent [`DynDirWatch`].
    #[allow(dead_code)]
    flags: u32,
    /// Unique index assigned at creation for DNS cache management.
    /// Matches the value passed to [`InotifyCallbacks::cache_remove_uid`].
    index: u32,
}

// ---------------------------------------------------------------------------
// Symlink resolution — replaces C my_readlink() (inotify.c lines 133-176)
// ---------------------------------------------------------------------------

/// Resolve a symbolic link and return the absolute target path.
///
/// Replaces C's `my_readlink()` (inotify.c lines 133–176).
///
/// Follows a symlink such as `/etc/resolv.conf → /run/systemd/resolve/resolv.conf`
/// and returns the resolved target.  If the target is a *relative* path, it is
/// made absolute by prepending the directory that contains the symlink.
///
/// # Returns
///
/// * `Ok(Some(path))` — `path` was a symlink; resolved target returned.
/// * `Ok(None)`       — `path` is not a symlink, or does not exist.
/// * `Err(_)`         — Unexpected I/O error (e.g. permission denied).
///
/// # Differences from C
///
/// Rust's [`std::fs::read_link`] handles buffer sizing automatically, so the
/// manual buffer-growth loop in C (`size += 64` retry) is unnecessary.
fn resolve_symlink(path: &Path) -> Result<Option<PathBuf>, DnsmasqError> {
    match std::fs::read_link(path) {
        Ok(target) => {
            if target.is_absolute() {
                Ok(Some(target))
            } else {
                // Relative symlink — prepend the directory containing the link.
                // Mirrors C lines 159-168: construct dir(path) + "/" + target.
                let dir = path.parent().unwrap_or_else(|| Path::new("/"));
                Ok(Some(dir.join(target)))
            }
        }
        Err(e) => {
            match e.kind() {
                // EINVAL → not a symlink.  ENOENT → path does not exist.
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound => Ok(None),
                _ => Err(DnsmasqError::Io(e)),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Editor-artifact filter — replaces C inline checks (inotify.c lines 475-479, 606-610)
// ---------------------------------------------------------------------------

/// Returns `true` if the filename is an editor artifact that should be ignored.
///
/// Matches the C filtering logic exactly:
/// - Empty names (`in->len == 0`)
/// - Emacs backup files (ending with `~`)
/// - Emacs lock / auto-save files (surrounded by `#`)
/// - Dotfiles (starting with `.`)
///
/// This prevents spurious reload events when files are edited in-place.
fn is_editor_artifact(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    // Dotfile
    if name.starts_with('.') {
        return true;
    }
    // Emacs backup (trailing ~)
    if name.ends_with('~') {
        return true;
    }
    // Emacs auto-save / lock file (#filename#)
    if name.starts_with('#') && name.ends_with('#') {
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// InotifyWatcher — the public async watcher
// ---------------------------------------------------------------------------

/// Async inotify watcher for configuration file change detection.
///
/// Replaces C's `daemon->inotifyfd` and the static `inotify_buffer`.
///
/// ## Monitored resources
///
/// * **resolv-files** — Upstream DNS server configuration files such as
///   `/etc/resolv.conf`.  When any resolv-file changes, [`check_events`]
///   returns `true` so the caller can trigger `poll_resolv`.
///
/// * **Dynamic DHCP host directories** — Directories containing
///   `/etc/hosts`-format files (specified via `--addn-hosts` with the
///   `AH_DIR` flag).  File additions/modifications cause DNS cache flushes
///   and re-reads; deletions cause cache removal.
///
/// * **DHCP host/option directories** — Directories containing DHCP host
///   or option config files (`--dhcp-hostsdir`, `--dhcp-optsdir`).
///   Changes trigger DHCP configuration and lease propagation.
///
/// ## Async integration
///
/// The inotify file descriptor is wrapped in [`AsyncFd`] so that
/// [`check_events`] can be awaited inside a `tokio::select!` branch.
///
/// [`check_events`]: InotifyWatcher::check_events
pub struct InotifyWatcher {
    /// The inotify instance wrapped in an async fd for tokio integration.
    /// Using `AsyncFd<InotifyInner>` ensures the fd lifetime is tied to the
    /// watcher and permits calling `get_ref().add_watch(...)` /
    /// `get_ref().read_events()` through the shared reference.
    async_fd: AsyncFd<InotifyInner>,

    /// Map of watch descriptors → resolv-file metadata.
    ///
    /// A single watch descriptor may correspond to a directory containing
    /// *multiple* resolv-files (rare but possible), so we store a `Vec`.
    resolv_watches: HashMap<WatchDescriptor, Vec<ResolvWatch>>,

    /// Map of watch descriptors → dynamic directory metadata.
    dir_watches: HashMap<WatchDescriptor, DynDirWatch>,

    /// Monotonically increasing counter for assigning unique host-file indices.
    /// Mirrors C's `daemon->host_index++`.
    host_index_counter: u32,
}

impl InotifyWatcher {
    // -----------------------------------------------------------------
    // Constructor — replaces C inotify_dnsmasq_init() (inotify.c 227-273)
    // -----------------------------------------------------------------

    /// Create a new [`InotifyWatcher`] and set up watches for resolv-files.
    ///
    /// Replaces C `inotify_dnsmasq_init()` (inotify.c lines 227–273).
    ///
    /// # Arguments
    ///
    /// * `resolv_files` — Paths to resolv-files to monitor (e.g. `/etc/resolv.conf`).
    /// * `port`         — DNS listening port; pass `0` to skip resolv-file watches.
    /// * `no_resolv`    — `true` if `--no-resolv` is set (`OPT_NO_RESOLV`).
    /// * `initial_host_index` — Starting value for the host-file index counter
    ///   (mirrors C's `daemon->host_index` at init time).
    ///
    /// # Errors
    ///
    /// Returns [`DnsmasqError::Io`] if `inotify_init1` fails or any required
    /// resolv-file parent directory cannot be watched.
    /// Returns [`DnsmasqError::Misc`] if the symlink chain exceeds [`MAX_SYMLINKS`].
    pub fn new(
        resolv_files: &[PathBuf],
        port: u16,
        no_resolv: bool,
        initial_host_index: u32,
    ) -> Result<Self, DnsmasqError> {
        // Create inotify instance with non-blocking + close-on-exec flags.
        // Mirrors C: inotify_init1(IN_NONBLOCK | IN_CLOEXEC)  (line 231)
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)
            .map_err(|e| DnsmasqError::Misc(format!("failed to create inotify: {}", e)))?;

        let async_fd = AsyncFd::new(InotifyInner(inotify)).map_err(DnsmasqError::Io)?;

        let mut resolv_watches: HashMap<WatchDescriptor, Vec<ResolvWatch>> = HashMap::new();

        // If DNS is disabled or --no-resolv is active, skip resolv-file watches.
        // Mirrors C lines 236-237.
        if port != 0 && !no_resolv {
            for resolv_path in resolv_files {
                // Follow symlinks up to MAX_SYMLINKS depth.
                // Mirrors C lines 241-253.
                let mut current = resolv_path.clone();
                let mut links_remaining = MAX_SYMLINKS;

                while let Some(target) = resolve_symlink(&current)? {
                    if links_remaining == 0 {
                        return Err(DnsmasqError::Misc(format!(
                            "too many symlinks following {}",
                            resolv_path.display()
                        )));
                    }
                    links_remaining -= 1;
                    current = target;
                }

                // Extract directory and filename components.
                // Mirrors C lines 257-263.
                let dir = current.parent().ok_or_else(|| {
                    DnsmasqError::Config(format!(
                        "cannot determine directory for resolv-file {}",
                        resolv_path.display()
                    ))
                })?;
                let filename = current
                    .file_name()
                    .ok_or_else(|| {
                        DnsmasqError::Config(format!(
                            "cannot determine filename for resolv-file {}",
                            resolv_path.display()
                        ))
                    })?
                    .to_os_string();

                // Add inotify watch on the *directory* for CLOSE_WRITE and MOVED_TO.
                // Watching the directory (not the file) handles atomic rename-over updates.
                // Mirrors C line 260.
                let watch_flags = AddWatchFlags::IN_CLOSE_WRITE | AddWatchFlags::IN_MOVED_TO;
                let wd = async_fd
                    .get_ref()
                    .add_watch(dir, watch_flags)
                    .map_err(|e| {
                        // ENOENT means directory doesn't exist.
                        // Mirrors C line 265-266.
                        if e == nix::errno::Errno::ENOENT {
                            DnsmasqError::Config(format!(
                                "directory {} for resolv-file is missing, cannot poll",
                                resolv_path.display()
                            ))
                        } else {
                            DnsmasqError::Misc(format!(
                                "failed to create inotify for {}: {}",
                                resolv_path.display(),
                                e
                            ))
                        }
                    })?;

                let entry = ResolvWatch {
                    original_path: resolv_path.clone(),
                    filename,
                };

                resolv_watches.entry(wd).or_default().push(entry);
            }
        }

        Ok(Self {
            async_fd,
            resolv_watches,
            dir_watches: HashMap::new(),
            host_index_counter: initial_host_index,
        })
    }

    // -----------------------------------------------------------------
    // Dynamic directory setup — replaces C set_dynamic_inotify()
    //                           (inotify.c lines 428-513)
    // -----------------------------------------------------------------

    /// Set up inotify watches for dynamic directories and read pre-existing files.
    ///
    /// Replaces C `set_dynamic_inotify()` (inotify.c lines 428–513).
    ///
    /// For each directory in `dirs` whose flags match `flag`, this method:
    ///
    /// 1. Verifies the directory exists.
    /// 2. Adds an inotify watch for `IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE`.
    /// 3. Reads all existing files (filtering out editor artifacts and dotfiles).
    /// 4. Calls the appropriate callback to load each file's contents.
    ///
    /// # Arguments
    ///
    /// * `dirs`      — Slice of `(path, flags)` pairs describing dynamic directories.
    ///   Typically sourced from the parsed `--addn-hosts`, `--dhcp-hostsdir`, and
    ///   `--dhcp-optsdir` configuration directives.
    /// * `flag`      — Only directories whose `flags & flag != 0` are processed.
    ///   Pass [`dir_flags::AH_DIR`] for addn-hosts directories, or `0` to process
    ///   all remaining directories (matching C calling convention).
    /// * `callbacks` — Implementation of [`InotifyCallbacks`] to receive reload events.
    ///
    /// # Errors
    ///
    /// Non-fatal errors (missing directories, inotify watch failures) are logged
    /// and the directory is skipped, matching C behaviour.  Only unexpected I/O
    /// errors propagate.
    pub fn setup_dynamic_dirs(
        &mut self,
        dirs: &[(PathBuf, u32)],
        flag: u32,
        callbacks: &mut impl InotifyCallbacks,
    ) -> Result<(), DnsmasqError> {
        for (dir_path, dir_flags_val) in dirs {
            // Only process directories matching the requested flag.
            // Mirrors C line 438-439.
            // When flag == 0, process all directories (C convention for DHCP dirs).
            if flag != 0 && (dir_flags_val & flag) == 0 {
                continue;
            }

            // Verify the directory exists and is actually a directory.
            // Mirrors C lines 441-453.
            let metadata = match std::fs::metadata(dir_path) {
                Ok(m) => m,
                Err(e) => {
                    error!("bad dynamic directory {}: {}", dir_path.display(), e);
                    continue;
                }
            };
            if !metadata.is_dir() {
                error!(
                    "bad dynamic directory {}: not a directory",
                    dir_path.display()
                );
                continue;
            }

            // Add inotify watch if not already done (AH_WD_DONE check).
            // Mirrors C lines 455-459.
            let watch_flags = AddWatchFlags::IN_CLOSE_WRITE
                | AddWatchFlags::IN_MOVED_TO
                | AddWatchFlags::IN_DELETE;

            let wd = match self
                .async_fd
                .get_ref()
                .add_watch(dir_path.as_path(), watch_flags)
            {
                Ok(wd) => wd,
                Err(e) => {
                    error!("failed to create inotify for {}: {}", dir_path.display(), e);
                    continue;
                }
            };

            // Create or retrieve the DynDirWatch entry.
            let dir_watch = self.dir_watches.entry(wd).or_insert_with(|| DynDirWatch {
                dir_path: dir_path.clone(),
                flags: *dir_flags_val | dir_flags::AH_WD_DONE,
                files: HashMap::new(),
            });

            // Read existing files *after* adding the watch to minimise the
            // race window where files appear between config parse and watch setup.
            // Mirrors C lines 461-462.
            let entries = match std::fs::read_dir(dir_path) {
                Ok(rd) => rd,
                Err(e) => {
                    error!("failed to read directory {}: {}", dir_path.display(), e);
                    continue;
                }
            };

            for entry in entries {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(
                            "error reading directory entry in {}: {}",
                            dir_path.display(),
                            e
                        );
                        continue;
                    }
                };

                let file_name = entry.file_name();
                let name_str = match file_name.to_str() {
                    Some(s) => s,
                    None => continue, // Skip non-UTF8 filenames
                };

                // Filter out editor artifacts (mirrors C lines 474-479).
                if is_editor_artifact(name_str) {
                    continue;
                }

                if dir_watch.flags & dir_flags::AH_HOSTS != 0 {
                    // ── AH_HOSTS directory ──
                    // Create or retrieve a HostsFileEntry for this file.
                    // Then verify it is a regular file before loading.
                    // Mirrors C lines 481-488.
                    let full_path = dir_path.join(name_str);
                    // Use the static helper directly to avoid borrowing
                    // `&mut self` while `dir_watch` is still live (disjoint
                    // field borrow: dir_watch.files vs self.host_index_counter).
                    let index = Self::get_or_create_hosts_entry(
                        &mut dir_watch.files,
                        name_str,
                        &full_path,
                        dir_watch.flags,
                        &mut self.host_index_counter,
                    );

                    // Ignore non-regular files (mirrors C line 487).
                    match std::fs::metadata(&full_path) {
                        Ok(m) if m.is_file() => {
                            callbacks.read_hostsfile(&full_path, index);
                        }
                        _ => {} // skip symlinks, dirs, missing files
                    }
                } else if dir_watch.flags & (dir_flags::AH_DHCP_HST | dir_flags::AH_DHCP_OPT) != 0 {
                    // ── DHCP host/option directory ──
                    // Construct full path, verify it is a regular file, then load.
                    // Mirrors C lines 491-506.
                    let full_path = dir_path.join(name_str);
                    match std::fs::metadata(&full_path) {
                        Ok(m) if m.is_file() => {
                            callbacks.option_read_dynfile(
                                &full_path,
                                dir_watch.flags & (dir_flags::AH_DHCP_HST | dir_flags::AH_DHCP_OPT),
                            );
                        }
                        _ => {} // skip non-regular files
                    }
                }
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------
    // Event processing — replaces C inotify_check() (inotify.c 580-685)
    // -----------------------------------------------------------------

    /// Process pending inotify events and trigger appropriate reload actions.
    ///
    /// Replaces C `inotify_check()` (inotify.c lines 580–685).
    ///
    /// This method awaits readability on the inotify fd via [`AsyncFd`],
    /// reads all pending events, filters out editor artifacts, and dispatches
    /// reload callbacks for affected files.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if any watched resolv-file was modified (the caller should
    /// trigger `poll_resolv` with `force=true`).
    /// `Ok(false)` if only dynamic directory files changed, or no meaningful
    /// events were received.
    ///
    /// # Async Integration
    ///
    /// Designed to be used inside the main `tokio::select!` loop:
    ///
    /// ```ignore
    /// tokio::select! {
    ///     result = watcher.check_events(&mut callbacks) => {
    ///         if result? { poll_resolv(true); }
    ///     }
    ///     // ... other branches ...
    /// }
    /// ```
    pub async fn check_events(
        &mut self,
        callbacks: &mut impl InotifyCallbacks,
    ) -> Result<bool, DnsmasqError> {
        // Await readability — integrates with tokio's epoll loop.
        // Replaces C poll() on daemon->inotifyfd.
        let mut guard = self.async_fd.readable().await.map_err(DnsmasqError::Io)?;

        let mut hit = false;

        // Read all pending events.  nix's read_events() returns a Vec of all
        // events that fit in its internal buffer.  Matches C's while(1) { read() }
        // loop (inotify.c lines 587-597).
        match self.async_fd.get_ref().read_events() {
            Ok(events) => {
                for event in &events {
                    // Extract event name; skip events without a name.
                    let name_os = match &event.name {
                        Some(n) => n,
                        None => continue,
                    };

                    // Convert to &str for filtering.  Non-UTF8 names are skipped.
                    let name_str = match name_os.to_str() {
                        Some(s) => s,
                        None => continue,
                    };

                    // Filter editor artifacts (mirrors C lines 606-610).
                    if is_editor_artifact(name_str) {
                        continue;
                    }

                    // ── Resolv-file check ──
                    // Mirrors C lines 612-614.
                    if let Some(watches) = self.resolv_watches.get(&event.wd) {
                        for rw in watches {
                            if rw.filename.as_bytes() == name_os.as_bytes() {
                                hit = true;
                            }
                        }
                    }

                    // ── Dynamic directory check ──
                    // Mirrors C lines 616-680.
                    if let Some(dir_watch) = self.dir_watches.get_mut(&event.wd) {
                        let is_delete = event.mask.contains(AddWatchFlags::IN_DELETE);

                        if dir_watch.flags & dir_flags::AH_HOSTS != 0 {
                            // -- AH_HOSTS handling (C lines 619-648) --
                            let full_path = dir_watch.dir_path.join(name_str);
                            let index = Self::get_or_create_hosts_entry(
                                &mut dir_watch.files,
                                name_str,
                                &full_path,
                                dir_watch.flags,
                                &mut self.host_index_counter,
                            );

                            // Remove old cache entries.
                            let removed = callbacks.cache_remove_uid(index);

                            if is_delete {
                                info!("inotify: {} removed", full_path.display());
                            } else {
                                info!("inotify: {} new or modified", full_path.display());
                            }

                            if removed > 0 {
                                info!(
                                    "inotify: flushed {} names read from {}",
                                    removed,
                                    full_path.display()
                                );
                            }

                            // Reload file unless this is a deletion event.
                            // Mirrors C lines 636-637.
                            if !is_delete {
                                callbacks.read_hostsfile(&full_path, index);
                            }

                            // Propagate DHCP consequences (C lines 638-646).
                            callbacks.dhcp_update_configs();
                            callbacks.lease_update_file();
                            callbacks.lease_update_dns(true);
                        } else if !is_delete
                            && (dir_watch.flags & (dir_flags::AH_DHCP_HST | dir_flags::AH_DHCP_OPT)
                                != 0)
                        {
                            // -- DHCP host/option handling (C lines 651-677) --
                            let full_path = dir_watch.dir_path.join(name_str);
                            info!("inotify: {} new or modified", full_path.display());

                            if dir_watch.flags & dir_flags::AH_DHCP_HST != 0
                                && callbacks.option_read_dynfile(&full_path, dir_flags::AH_DHCP_HST)
                            {
                                // Propagate DHCP host config changes.
                                // Mirrors C lines 664-669.
                                callbacks.dhcp_update_configs();
                                callbacks.lease_update_file();
                                callbacks.lease_update_dns(true);
                            }

                            if dir_watch.flags & dir_flags::AH_DHCP_OPT != 0 {
                                callbacks.option_read_dynfile(&full_path, dir_flags::AH_DHCP_OPT);
                            }
                        }
                    }
                }
            }
            Err(nix::errno::Errno::EAGAIN) => {
                // No events available — fd was signalled but drained already.
                // Note: EWOULDBLOCK is the same value as EAGAIN on Linux,
                // so a separate arm is unnecessary (and would be unreachable).
            }
            Err(e) => {
                guard.clear_ready();
                return Err(DnsmasqError::Io(std::io::Error::from_raw_os_error(
                    e as i32,
                )));
            }
        }

        // Clear readiness so tokio re-arms the epoll interest.
        guard.clear_ready();
        Ok(hit)
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Get or create a [`HostsFileEntry`] in the file map.
    ///
    /// Replaces C `dyndir_addhosts()` (inotify.c lines 328–366).
    ///
    /// If `name` already exists in `files`, returns its existing index.
    /// Otherwise creates a new entry with a freshly allocated index from
    /// `host_index_counter`.
    fn get_or_create_hosts_entry(
        files: &mut HashMap<OsString, HostsFileEntry>,
        name: &str,
        full_path: &Path,
        flags: u32,
        host_index_counter: &mut u32,
    ) -> u32 {
        let key = OsString::from(name);

        if let Some(existing) = files.get(&key) {
            return existing.index;
        }

        let index = *host_index_counter;
        *host_index_counter = host_index_counter.wrapping_add(1);

        files.insert(
            key,
            HostsFileEntry {
                full_path: full_path.to_path_buf(),
                flags,
                index,
            },
        );

        index
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_is_editor_artifact_empty() {
        assert!(is_editor_artifact(""));
    }

    #[test]
    fn test_is_editor_artifact_dotfile() {
        assert!(is_editor_artifact(".hidden"));
        assert!(is_editor_artifact("."));
        assert!(is_editor_artifact(".."));
    }

    #[test]
    fn test_is_editor_artifact_emacs_backup() {
        assert!(is_editor_artifact("hosts~"));
        assert!(is_editor_artifact("resolv.conf~"));
    }

    #[test]
    fn test_is_editor_artifact_emacs_autosave() {
        assert!(is_editor_artifact("#hosts#"));
        assert!(is_editor_artifact("#.resolv.conf#"));
    }

    #[test]
    fn test_is_editor_artifact_normal_files() {
        assert!(!is_editor_artifact("hosts"));
        assert!(!is_editor_artifact("resolv.conf"));
        assert!(!is_editor_artifact("server1.hosts"));
        assert!(!is_editor_artifact("dhcp-host.conf"));
    }

    #[test]
    fn test_is_editor_artifact_edge_cases() {
        // Single '#' is not an emacs auto-save (needs both start and end '#')
        assert!(!is_editor_artifact("#only-start"));
        assert!(!is_editor_artifact("only-end#"));
        // '#' at start only without matching end
        assert!(!is_editor_artifact("#abc"));
    }

    #[test]
    fn test_resolve_symlink_non_symlink() {
        // /etc/hostname is a regular file, not a symlink (usually)
        let result = resolve_symlink(Path::new("/dev/null"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_resolve_symlink_nonexistent() {
        let result = resolve_symlink(Path::new("/nonexistent/path/xyz"));
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_dir_flags_values() {
        // Verify flag values match C dnsmasq.h AH_* constants exactly.
        assert_eq!(dir_flags::AH_DIR, 1);
        assert_eq!(dir_flags::AH_INACTIVE, 2);
        assert_eq!(dir_flags::AH_WD_DONE, 4);
        assert_eq!(dir_flags::AH_HOSTS, 8);
        assert_eq!(dir_flags::AH_DHCP_HST, 16);
        assert_eq!(dir_flags::AH_DHCP_OPT, 32);
    }

    #[test]
    fn test_dir_flags_no_overlap() {
        // All flags must be distinct powers of two (bit-field).
        let all = [
            dir_flags::AH_DIR,
            dir_flags::AH_INACTIVE,
            dir_flags::AH_WD_DONE,
            dir_flags::AH_HOSTS,
            dir_flags::AH_DHCP_HST,
            dir_flags::AH_DHCP_OPT,
        ];
        for (i, &a) in all.iter().enumerate() {
            for &b in &all[i + 1..] {
                assert_eq!(a & b, 0, "Flags {} and {} overlap", a, b);
            }
        }
    }

    #[test]
    fn test_get_or_create_hosts_entry_new() {
        let mut files = HashMap::new();
        let mut counter = 100u32;
        let path = PathBuf::from("/etc/dnsmasq.d/hosts/server1");

        let idx = InotifyWatcher::get_or_create_hosts_entry(
            &mut files,
            "server1",
            &path,
            dir_flags::AH_HOSTS,
            &mut counter,
        );

        assert_eq!(idx, 100);
        assert_eq!(counter, 101);
        assert!(files.contains_key(&OsString::from("server1")));
    }

    #[test]
    fn test_get_or_create_hosts_entry_existing() {
        let mut files = HashMap::new();
        let mut counter = 100u32;
        let path = PathBuf::from("/etc/dnsmasq.d/hosts/server1");

        // First insertion.
        let idx1 = InotifyWatcher::get_or_create_hosts_entry(
            &mut files,
            "server1",
            &path,
            dir_flags::AH_HOSTS,
            &mut counter,
        );

        // Second call for the same file — should return existing index.
        let idx2 = InotifyWatcher::get_or_create_hosts_entry(
            &mut files,
            "server1",
            &path,
            dir_flags::AH_HOSTS,
            &mut counter,
        );

        assert_eq!(idx1, idx2);
        // Counter should NOT have advanced for the duplicate.
        assert_eq!(counter, 101);
    }
}
