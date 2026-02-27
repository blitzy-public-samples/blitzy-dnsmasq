//! Linux inotify file-change monitoring for dnsmasq configuration hot-reload.
//!
//! This module implements efficient filesystem monitoring using the Linux `inotify(7)` API
//! to detect configuration file changes without polling. It is the Rust replacement for
//! `src/inotify.c` (687 lines of C).
//!
//! # What's Monitored
//!
//! - **Resolv-files:** Upstream DNS server configuration (e.g., `/etc/resolv.conf`).
//!   Watches the *parent directory* for `IN_CLOSE_WRITE` and `IN_MOVED_TO` events,
//!   since files are typically updated atomically via rename.
//! - **Dynamic hosts directories:** Directories specified via `--addn-hosts` with the
//!   `AH_DIR` flag, monitored for `IN_CLOSE_WRITE`, `IN_MOVED_TO`, and `IN_DELETE`.
//! - **DHCP configuration directories:** `--dhcp-hostsdir` and `--dhcp-optsdir` directories,
//!   also monitored for write/move/delete events (feature-gated with `dhcp`).
//!
//! # Linux Requirements
//!
//! Requires kernel 2.6.13+ with inotify support. When the `inotify_monitor` feature is
//! disabled, dnsmasq falls back to polling-based configuration checking.
//!
//! # Architecture
//!
//! The [`InotifyManager`] struct encapsulates all state (replacing C static globals).
//! Its file descriptor is exposed via [`fd()`](InotifyManager::fd) for integration with
//! the `mio::Poll` event loop. Event processing is triggered by calling
//! [`check_events()`](InotifyManager::check_events) when the fd becomes readable.
//!
//! # Events Watched
//!
//! | Target | Events | Reason |
//! |--------|--------|--------|
//! | Resolv-file directories | `IN_CLOSE_WRITE`, `IN_MOVED_TO` | Detect atomic file replacement |
//! | Dynamic host directories | `IN_CLOSE_WRITE`, `IN_MOVED_TO`, `IN_DELETE` | Full CRUD monitoring |
//! | DHCP config directories | `IN_CLOSE_WRITE`, `IN_MOVED_TO`, `IN_DELETE` | Full CRUD monitoring |
//!
//! # Feature Gate
//!
//! This module is compiled only when the `inotify_monitor` Cargo feature is enabled,
//! replacing the C `#ifdef HAVE_INOTIFY` guard.

use std::fs;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};
use log::{debug, info, warn};
use thiserror::Error;

use crate::config::options::DaemonConfig;
use crate::core::daemon::OPT_NO_RESOLV;
use crate::types::dns::HostsFileFlags;

// ===========================================================================
// Constants
// ===========================================================================

/// Maximum number of symbolic links to follow when resolving resolv-file paths.
///
/// Mirrors the POSIX `MAXSYMLINKS` constant from `<sys/param.h>` (typically 20 on Linux).
/// Prevents infinite loops when circular symlinks are encountered.
const MAXSYMLINKS: usize = 20;

/// Size of the buffer used for reading inotify events.
///
/// Each inotify event is `sizeof(struct inotify_event) + name_len`, where `name_len`
/// can be up to `NAME_MAX + 1` (256 bytes on Linux). A 4096-byte buffer can hold
/// multiple events per `read()` call.
///
/// Replaces C: `#define INOTIFY_SZ (sizeof(struct inotify_event) + NAME_MAX + 1)`
const INOTIFY_BUFFER_SIZE: usize = 4096;

// ===========================================================================
// InotifyError — replaces C die() calls with Result-based error propagation
// ===========================================================================

/// Errors that can occur during inotify operations.
///
/// Replaces the C pattern of calling `die()` with `EC_MISC` on inotify failures.
/// Each variant corresponds to a specific failure mode in the original C implementation,
/// enabling callers to handle errors gracefully or propagate them upward.
#[derive(Debug, Error)]
pub enum InotifyError {
    /// Failed to create the inotify instance via `inotify_init1()`.
    ///
    /// C equivalent: `die(_("failed to create inotify: %s"), NULL, EC_MISC)`
    #[error("Failed to create inotify instance: {0}")]
    InitFailed(io::Error),

    /// Failed to add an inotify watch on a directory.
    ///
    /// C equivalent: `die(_("failed to create inotify for %s: %s"), res->name, EC_MISC)`
    #[error("Failed to add inotify watch for {path}: {source}")]
    WatchFailed {
        /// Path that could not be watched.
        path: String,
        /// Underlying I/O error from `inotify_add_watch`.
        source: io::Error,
    },

    /// The directory containing a resolv-file does not exist.
    ///
    /// Inotify watches directories, not files. If the parent directory of a resolv-file
    /// is missing, monitoring cannot be set up.
    ///
    /// C equivalent: `die(_("directory %s for resolv-file is missing, cannot poll"), ...)`
    #[error("Directory {0} for resolv-file is missing, cannot poll")]
    DirectoryMissing(String),

    /// Exceeded the maximum symlink depth while resolving a resolv-file path.
    ///
    /// C equivalent: `die(_("too many symlinks following %s"), res->name, EC_MISC)`
    #[error("Too many symlinks following {0}")]
    TooManySymlinks(String),

    /// Permission denied or other access error when following symlinks.
    ///
    /// C equivalent: `die(_("cannot access path %s: %s"), path, EC_MISC)`
    #[error("Cannot access path {path}: {source}")]
    AccessDenied {
        /// Path that could not be accessed.
        path: String,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// A configured dynamic directory is invalid (missing or not a directory).
    ///
    /// Unlike resolv-file directory errors (which are fatal), dynamic directory errors
    /// are logged as warnings and the directory is skipped.
    ///
    /// C equivalent: `my_syslog(LOG_ERR, _("bad dynamic directory %s: %s"), ...)`
    #[error("Bad dynamic directory {path}: {reason}")]
    BadDynamicDir {
        /// Path to the invalid directory.
        path: String,
        /// Human-readable description of why the directory is invalid.
        reason: String,
    },

    /// Failed to read events from the inotify file descriptor.
    #[error("Failed to read inotify events: {0}")]
    ReadFailed(io::Error),
}

// ===========================================================================
// InotifyEventHandler — callback trait for event-triggered operations
// ===========================================================================

/// Callback trait for cache and configuration operations triggered by inotify events.
///
/// This trait decouples the inotify module from the DNS cache and DHCP configuration
/// internals. The main daemon implements this trait to handle file-change notifications
/// by flushing caches, reloading hosts files, and propagating DHCP configuration changes.
///
/// # Implementor Responsibilities
///
/// - [`cache_remove_uid`](Self::cache_remove_uid): Flush DNS cache entries for a hosts file.
/// - [`read_hostsfile`](Self::read_hostsfile): Parse a hosts-format file into the DNS cache.
/// - [`option_read_dynfile`](Self::option_read_dynfile): Parse a DHCP configuration file.
/// - [`dhcp_propagate_changes`](Self::dhcp_propagate_changes): Push DHCP config to active leases.
///
/// # C Equivalents
///
/// These methods replace direct function calls made from `inotify_check()` in the C code:
/// `cache_remove_uid()`, `read_hostsfile()`, `option_read_dynfile()`,
/// `dhcp_update_configs()`, `lease_update_from_configs()`, `lease_update_file()`,
/// `lease_update_dns()`.
pub trait InotifyEventHandler {
    /// Remove all DNS cache entries loaded from the hosts file with the given index.
    ///
    /// Returns the number of cache entries removed. Used to flush stale data before
    /// reloading a modified hosts file.
    ///
    /// C equivalent: `cache_remove_uid(ah->index)` in `cache.c`.
    fn cache_remove_uid(&mut self, index: u32) -> u32;

    /// Parse a hosts-format file and populate the DNS cache.
    ///
    /// Returns the total cache size after loading. Called after `cache_remove_uid` to
    /// reload the modified file's entries.
    ///
    /// C equivalent: `read_hostsfile(ah->fname, ah->index, ...)` in `cache.c`.
    fn read_hostsfile(&mut self, path: &str, index: u32) -> usize;

    /// Parse a dynamic DHCP configuration file (hosts or options).
    ///
    /// Returns `true` if the file was successfully parsed and configuration changed.
    /// The `flags` parameter indicates the file type (`AH_DHCP_HST` or `AH_DHCP_OPT`).
    ///
    /// C equivalent: `option_read_dynfile(path, flags)` in `option.c`.
    fn option_read_dynfile(&mut self, path: &str, flags: u32) -> bool;

    /// Propagate DHCP configuration changes to active leases.
    ///
    /// Called after loading new DHCP host definitions to update running lease state.
    /// This triggers the equivalent of `dhcp_update_configs()`,
    /// `lease_update_from_configs()`, `lease_update_file(now)`, and
    /// `lease_update_dns(1)` from the C codebase.
    ///
    /// # Arguments
    /// * `now` — Current timestamp in seconds since epoch, passed to lease file updates.
    fn dhcp_propagate_changes(&mut self, now: i64);
}

// ===========================================================================
// Internal types — replace C static variables and struct-embedded fields
// ===========================================================================

/// Tracks an inotify watch on the parent directory of a resolv-file.
///
/// When events fire on the watched directory, the filename from the event is compared
/// against [`filename`](ResolvWatch::filename) to determine if the specific resolv-file
/// was modified. This approach handles atomic file updates (write-to-temp-then-rename).
struct ResolvWatch {
    /// Inotify watch descriptor for the parent directory.
    wd: WatchDescriptor,
    /// Filename component (not full path) to match within the directory.
    /// For `/etc/resolv.conf`, this is `"resolv.conf"`.
    filename: String,
    /// Full original path to the resolv-file (for logging and diagnostics).
    full_path: String,
}

/// Tracks state for a dynamic directory being monitored via inotify.
///
/// Each `DynDirState` corresponds to a `--addn-hosts`, `--dhcp-hostsdir`, or
/// `--dhcp-optsdir` directory from the daemon configuration.
struct DynDirState {
    /// Inotify watch descriptor. `None` if watch setup failed or hasn't been attempted.
    wd: Option<WatchDescriptor>,
    /// Absolute path to the monitored directory.
    dir_path: String,
    /// Raw flags from the `DynDir` configuration (same numeric domain as `HostsFileFlags`).
    /// Tested with `HostsFileFlags::from_bits_truncate()` for type-safe flag checks.
    flags: i32,
    /// Files discovered and tracked within this directory.
    files: Vec<HostFileState>,
    /// Whether the inotify watch has been set up (prevents duplicate `add_watch` calls).
    /// Replaces the `AH_WD_DONE` flag bit in the C implementation.
    wd_done: bool,
}

/// Tracks a single file within a dynamic directory.
///
/// Replaces C `struct hostsfile` entries linked via `dd->files`. Each entry has a unique
/// `index` used by `cache_remove_uid()` to flush the DNS cache entries loaded from this file.
struct HostFileState {
    /// Full path to the file (e.g., `/etc/dnsmasq.d/hosts/myserver`).
    fname: String,
    /// Unique index for cache management, assigned monotonically from `host_index_counter`.
    index: u32,
}

// ===========================================================================
// InotifyManager — main public struct encapsulating all inotify state
// ===========================================================================

/// Manages Linux inotify watches for dnsmasq configuration file monitoring.
///
/// Encapsulates the inotify file descriptor, event buffer, and all watch state.
/// Replaces the C static globals (`inotify_buffer`, per-struct `wd` fields) with
/// a single owned struct that integrates with the `mio::Poll` event loop.
///
/// # Lifecycle
///
/// 1. **Construction:** [`InotifyManager::new()`] creates the inotify instance and sets
///    up watches for resolv-files.
/// 2. **Dynamic setup:** [`set_dynamic_watches()`](InotifyManager::set_dynamic_watches)
///    adds watches for `--addn-hosts` and `--dhcp-hostsdir` directories.
/// 3. **Event loop integration:** [`fd()`](InotifyManager::fd) returns the raw fd for
///    `mio::Poll` registration.
/// 4. **Event processing:** [`check_events()`](InotifyManager::check_events) is called
///    from the main event loop when the fd becomes readable.
///
/// # Thread Safety
///
/// Designed for single-threaded use within the dnsmasq event loop. Not `Send` or `Sync`
/// due to the `Inotify` file descriptor ownership model.
pub struct InotifyManager {
    /// The inotify instance owning the kernel file descriptor.
    /// Created with `IN_NONBLOCK | IN_CLOEXEC` flags.
    inotify: Inotify,

    /// Watches set up for resolv-file parent directories.
    /// Populated during [`new()`](InotifyManager::new).
    resolv_watches: Vec<ResolvWatch>,

    /// State for each dynamic directory from configuration.
    /// Populated during [`new()`](InotifyManager::new), watches added by
    /// [`set_dynamic_watches()`](InotifyManager::set_dynamic_watches).
    dynamic_dirs: Vec<DynDirState>,

    /// Monotonically increasing counter for assigning unique indices to new host files.
    /// Each hosts file tracked within dynamic directories gets a unique index used for
    /// DNS cache management via `cache_remove_uid()`.
    host_index_counter: u32,
}

// ===========================================================================
// Free helper functions
// ===========================================================================

/// Resolve symbolic links in a file path, following the chain up to `max_depth` levels.
///
/// This is the Rust equivalent of the C `my_readlink()` function (inotify.c lines 133-176).
/// It iteratively follows symbolic links using `std::fs::read_link()`, converting relative
/// symlink targets to absolute paths by prepending the symlink's parent directory.
///
/// # Arguments
/// * `path` — The initial path to resolve (may or may not be a symlink).
/// * `max_depth` — Maximum number of symlinks to follow before returning an error.
///
/// # Returns
/// * `Ok(PathBuf)` — The fully resolved path (no more symlinks).
/// * `Err(InotifyError::TooManySymlinks)` — Exceeded `max_depth` levels.
/// * `Err(InotifyError::AccessDenied)` — Permission or I/O error accessing the path.
///
/// # Behavior
/// - If the path is not a symlink (or doesn't exist), returns the original path unchanged.
/// - Relative symlink targets are resolved against the containing directory of the symlink.
/// - Absolute symlink targets are used as-is.
fn resolve_symlinks(path: &str, max_depth: usize) -> Result<PathBuf, InotifyError> {
    let mut current = PathBuf::from(path);
    let mut depth: usize = 0;

    loop {
        match fs::read_link(&current) {
            Ok(target) => {
                depth += 1;
                if depth > max_depth {
                    return Err(InotifyError::TooManySymlinks(path.to_string()));
                }

                // If the symlink target is relative, resolve it against the symlink's
                // parent directory. This matches the C logic at inotify.c lines 159-168:
                //   if (buf[0] != '/' && (d = strrchr(path, '/')))
                //     { /* prepend directory */ }
                if target.is_relative() {
                    if let Some(parent) = current.parent() {
                        current = parent.join(&target);
                    } else {
                        current = target;
                    }
                } else {
                    current = target;
                }
            }
            Err(e) => {
                // EINVAL means "not a symbolic link" — stop following, use current path.
                // ENOENT means "path doesn't exist" — also stop (file may appear later).
                // These match the C behavior at inotify.c lines 146-149.
                let raw_err = e.raw_os_error();
                if raw_err == Some(libc::EINVAL) || raw_err == Some(libc::ENOENT) {
                    return Ok(current);
                }
                // Any other error is fatal (e.g., EACCES, EIO).
                // C equivalent: die(_("cannot access path %s: %s"), path, EC_MISC)
                return Err(InotifyError::AccessDenied {
                    path: path.to_string(),
                    source: e,
                });
            }
        }
    }
}

/// Check whether a filename is an editor backup file that should be ignored.
///
/// Filters out files commonly created by text editors during save operations:
/// - Empty filenames
/// - Emacs backup files (ending with `~`)
/// - Emacs auto-save files (surrounded by `#`, e.g., `#file#`)
/// - Dotfiles (starting with `.`)
///
/// This matches the C filter at inotify.c lines 475-479 and 605-610:
/// ```text
/// if (lenfile == 0 ||
///     ent->d_name[lenfile - 1] == '~' ||
///     (ent->d_name[0] == '#' && ent->d_name[lenfile - 1] == '#') ||
///     ent->d_name[0] == '.')
///   continue;
/// ```
fn is_editor_backup(name: &str) -> bool {
    if name.is_empty() {
        return true;
    }
    // Emacs backup files end with '~'
    if name.ends_with('~') {
        return true;
    }
    // Emacs auto-save files: #filename#
    if name.starts_with('#') && name.ends_with('#') {
        return true;
    }
    // Dotfiles (hidden files, vim swap files like .file.swp)
    if name.starts_with('.') {
        return true;
    }
    false
}

/// Find or create a hosts file entry within a dynamic directory's file list.
///
/// This is the Rust equivalent of `dyndir_addhosts()` (inotify.c lines 328-366).
/// It searches the existing file list for a match by comparing the filename suffix
/// (after the directory path and separator). If not found, creates a new entry with
/// a unique index and appends it to the list.
///
/// # Arguments
/// * `files` — Mutable reference to the directory's tracked file list.
/// * `dir_path` — Absolute path to the parent directory.
/// * `filename` — Bare filename (no path components) of the file within the directory.
/// * `host_index` — Counter for assigning unique indices; incremented for new entries.
///
/// # Returns
/// The index into `files` of the found or newly created entry.
fn dyndir_add_hosts_entry(
    files: &mut Vec<HostFileState>,
    dir_path: &str,
    filename: &str,
    host_index: &mut u32,
) -> usize {
    // Search for existing entry matching this filename.
    // C logic (inotify.c lines 334-338): compare ah->fname[dirlen+1..] with file.
    let dir_len = dir_path.len();
    for (i, f) in files.iter().enumerate() {
        if f.fname.len() > dir_len + 1
            && f.fname.as_bytes().get(dir_len) == Some(&b'/')
            && &f.fname[dir_len + 1..] == filename
        {
            return i;
        }
    }

    // Not found — create a new entry.
    // C logic (inotify.c lines 341-363): allocate hostsfile, build full path, assign index.
    let full_path = format!("{}/{}", dir_path, filename);
    let entry = HostFileState {
        fname: full_path,
        index: *host_index,
    };
    *host_index += 1;
    files.push(entry);
    files.len() - 1
}

// ===========================================================================
// InotifyManager implementation
// ===========================================================================

impl InotifyManager {
    /// Create a new `InotifyManager` and set up inotify watches for resolv-files.
    ///
    /// This is the Rust equivalent of `inotify_dnsmasq_init()` (inotify.c lines 227-273).
    ///
    /// # Initialization Steps
    ///
    /// 1. Creates an inotify instance with `IN_NONBLOCK | IN_CLOEXEC` flags.
    /// 2. Copies dynamic directory configuration for later use by
    ///    [`set_dynamic_watches()`](Self::set_dynamic_watches).
    /// 3. If DNS is enabled and resolv-file monitoring is not disabled:
    ///    - For each resolv-file, resolves symbolic links up to [`MAXSYMLINKS`] depth.
    ///    - Extracts the parent directory and filename.
    ///    - Adds an inotify watch on the directory for `IN_CLOSE_WRITE | IN_MOVED_TO`.
    ///
    /// # Arguments
    /// * `config` — Parsed daemon configuration providing resolv-file paths, dynamic
    ///   directory definitions, option flags, and DNS port number.
    ///
    /// # Errors
    /// * [`InotifyError::InitFailed`] — Failed to create the inotify instance.
    /// * [`InotifyError::TooManySymlinks`] — A resolv-file path has too many symlink levels.
    /// * [`InotifyError::DirectoryMissing`] — A resolv-file's parent directory doesn't exist.
    /// * [`InotifyError::WatchFailed`] — Failed to add a watch on a resolv-file directory.
    /// * [`InotifyError::AccessDenied`] — Cannot access a path during symlink resolution.
    pub fn new(config: &DaemonConfig) -> Result<Self, InotifyError> {
        // Create inotify instance. The inotify crate automatically sets
        // IN_NONBLOCK | IN_CLOEXEC, matching C: inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        let inotify = Inotify::init().map_err(InotifyError::InitFailed)?;

        // Copy dynamic directory data from configuration for later use.
        // We store our own state rather than mutating the config.
        let dynamic_dirs: Vec<DynDirState> = config
            .dns
            .dyn_dirs
            .iter()
            .map(|dd| DynDirState {
                wd: None,
                dir_path: dd.dname.clone(),
                flags: dd.flags,
                files: dd
                    .files
                    .iter()
                    .map(|f| HostFileState {
                        fname: f.fname.clone(),
                        index: f.index,
                    })
                    .collect(),
                wd_done: false,
            })
            .collect();

        // Determine the starting host_index counter: one past the maximum existing index
        // from both hosts_files and dynamic directory files.
        let max_hosts_idx = config
            .dns
            .hosts_files
            .iter()
            .map(|f| f.index)
            .max()
            .unwrap_or(0);
        let max_dyn_idx = config
            .dns
            .dyn_dirs
            .iter()
            .flat_map(|d| d.files.iter())
            .map(|f| f.index)
            .max()
            .unwrap_or(0);
        let host_index_counter = max_hosts_idx.max(max_dyn_idx).saturating_add(1);

        let mut manager = InotifyManager {
            inotify,
            resolv_watches: Vec::new(),
            dynamic_dirs,
            host_index_counter,
        };

        // Skip resolv-file watch setup if DNS is disabled or --no-resolv is set.
        // C equivalent (inotify.c lines 236-237):
        //   if (daemon->port == 0 || option_bool(OPT_NO_RESOLV)) return;
        if config.dns.port == 0 || config.options.get(OPT_NO_RESOLV) {
            debug!("inotify: skipping resolv-file watches (DNS disabled or --no-resolv)");
            return Ok(manager);
        }

        // Set up watches for each resolv-file.
        // C equivalent (inotify.c lines 239-272): loop over daemon->resolv_files.
        for resolv in &config.dns.resolv_files {
            // Follow symlink chain to find the actual file target.
            let resolved = resolve_symlinks(&resolv.name, MAXSYMLINKS)?;
            let resolved_str = resolved.to_string_lossy().to_string();

            // Split into directory and filename components.
            let resolved_path = Path::new(&resolved_str);
            let dir = resolved_path.parent().ok_or_else(|| {
                InotifyError::DirectoryMissing(resolv.name.clone())
            })?;
            let filename = resolved_path
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default();

            if filename.is_empty() {
                return Err(InotifyError::WatchFailed {
                    path: resolv.name.clone(),
                    source: io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "resolv-file path has no filename component",
                    ),
                });
            }

            let dir_str = dir.to_string_lossy().to_string();

            // Add inotify watch on the directory for CLOSE_WRITE and MOVED_TO events.
            // Watching the directory (not the file) handles atomic file replacements
            // where the file is written to a temp name and then renamed.
            // C equivalent (inotify.c line 260):
            //   res->wd = inotify_add_watch(daemon->inotifyfd, path,
            //                               IN_CLOSE_WRITE | IN_MOVED_TO);
            let wd = manager
                .inotify
                .watches()
                .add(&dir_str, WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO)
                .map_err(|e| {
                    // ENOENT means directory doesn't exist — special error message.
                    // C equivalent (inotify.c lines 265-266):
                    //   if (res->wd == -1 && errno == ENOENT)
                    //     die(_("directory %s for resolv-file is missing..."), ...)
                    if e.raw_os_error() == Some(libc::ENOENT) {
                        InotifyError::DirectoryMissing(resolv.name.clone())
                    } else {
                        InotifyError::WatchFailed {
                            path: resolv.name.clone(),
                            source: e,
                        }
                    }
                })?;

            debug!(
                "inotify: watching directory '{}' for resolv-file '{}' (filename: '{}')",
                dir_str, resolv.name, filename
            );

            manager.resolv_watches.push(ResolvWatch {
                wd,
                filename,
                full_path: resolv.name.clone(),
            });
        }

        Ok(manager)
    }

    /// Return the raw file descriptor for the inotify instance.
    ///
    /// This fd should be registered with `mio::Poll` for `READABLE` events.
    /// When the fd becomes readable, call [`check_events()`](Self::check_events)
    /// to process pending inotify notifications.
    ///
    /// C equivalent: `daemon->inotifyfd` exposed for the `poll()` event loop.
    #[inline]
    pub fn fd(&self) -> RawFd {
        self.inotify.as_raw_fd()
    }

    /// Set up inotify watches for dynamic directories and read pre-existing files.
    ///
    /// This is the Rust equivalent of `set_dynamic_inotify()` (inotify.c lines 428-513).
    ///
    /// For each dynamic directory whose flags match the given `flag` bitmask:
    /// 1. Validates that the directory exists and is a directory.
    /// 2. Adds an inotify watch for `IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE`.
    /// 3. Reads all existing files in the directory (filtering editor backups).
    /// 4. For `AH_HOSTS` directories: creates host file entries and calls
    ///    [`read_hostsfile()`](InotifyEventHandler::read_hostsfile).
    /// 5. For DHCP directories (feature-gated): calls
    ///    [`option_read_dynfile()`](InotifyEventHandler::option_read_dynfile).
    ///
    /// # Arguments
    /// * `flag` — Bitmask to select which directories to set up. Pass
    ///   `HostsFileFlags::HOSTS.bits() as u32` for addn-hosts directories, or
    ///   `(HostsFileFlags::DHCP_HST | HostsFileFlags::DHCP_OPT).bits() as u32`
    ///   for DHCP configuration directories.
    /// * `handler` — Callback trait object for cache and config operations.
    ///
    /// # Errors
    /// Returns `Ok(())` on success. Individual directory failures are logged as warnings
    /// and the directory is skipped (matching C behavior of `continue` on errors).
    pub fn set_dynamic_watches(
        &mut self,
        flag: u32,
        handler: &mut dyn InotifyEventHandler,
    ) -> Result<(), InotifyError> {
        let flag_hf = HostsFileFlags::from_bits_truncate(flag as i32);

        for dir_idx in 0..self.dynamic_dirs.len() {
            // Check if this directory's flags match the requested flag bitmask.
            // C equivalent (inotify.c lines 438-439): if (!(dd->flags & flag)) continue;
            let dir_flags = HostsFileFlags::from_bits_truncate(self.dynamic_dirs[dir_idx].flags);
            if !dir_flags.intersects(flag_hf) {
                continue;
            }

            let dir_path = self.dynamic_dirs[dir_idx].dir_path.clone();

            // Validate directory exists and is actually a directory.
            // C equivalent (inotify.c lines 441-453): stat() + S_ISDIR check.
            let metadata = match fs::metadata(&dir_path) {
                Ok(m) => m,
                Err(e) => {
                    warn!("bad dynamic directory {}: {}", dir_path, e);
                    continue;
                }
            };

            if !metadata.is_dir() {
                warn!("bad dynamic directory {}: not a directory", dir_path);
                continue;
            }

            // Add inotify watch if not already done (AH_WD_DONE check).
            // C equivalent (inotify.c lines 455-459):
            //   if (!(dd->flags & AH_WD_DONE)) {
            //     dd->wd = inotify_add_watch(..., IN_CLOSE_WRITE|IN_MOVED_TO|IN_DELETE);
            //     dd->flags |= AH_WD_DONE;
            //   }
            if !self.dynamic_dirs[dir_idx].wd_done {
                match self.inotify.watches().add(
                    &dir_path,
                    WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO | WatchMask::DELETE,
                ) {
                    Ok(wd) => {
                        self.dynamic_dirs[dir_idx].wd = Some(wd);
                        self.dynamic_dirs[dir_idx].wd_done = true;
                        debug!("inotify: added watch for dynamic directory '{}'", dir_path);
                    }
                    Err(e) => {
                        warn!("failed to create inotify for {}: {}", dir_path, e);
                        self.dynamic_dirs[dir_idx].wd_done = true; // prevent retry
                        continue;
                    }
                }
            }

            // Directory must have a valid watch to proceed.
            if self.dynamic_dirs[dir_idx].wd.is_none() {
                warn!(
                    "failed to create inotify for {}: no watch descriptor",
                    dir_path
                );
                continue;
            }

            // Read directory contents _after_ adding the watch to minimize race conditions.
            // C equivalent (inotify.c lines 461-512): opendir/readdir loop.
            let entries = match fs::read_dir(&dir_path) {
                Ok(e) => e,
                Err(e) => {
                    warn!("failed to read directory {}: {}", dir_path, e);
                    continue;
                }
            };

            for entry_result in entries {
                let entry = match entry_result {
                    Ok(e) => e,
                    Err(_) => continue,
                };

                let name = entry.file_name();
                let name_str = name.to_string_lossy().to_string();

                // Filter out editor backup files (emacs ~, #...#, dotfiles).
                // C equivalent (inotify.c lines 474-479).
                if is_editor_backup(&name_str) {
                    continue;
                }

                if dir_flags.contains(HostsFileFlags::HOSTS) {
                    // For HOSTS directories: create/find hosts file entry, then read if regular.
                    // C equivalent (inotify.c lines 481-488).
                    let file_idx = dyndir_add_hosts_entry(
                        &mut self.dynamic_dirs[dir_idx].files,
                        &dir_path,
                        &name_str,
                        &mut self.host_index_counter,
                    );

                    let fname = self.dynamic_dirs[dir_idx].files[file_idx].fname.clone();
                    let index = self.dynamic_dirs[dir_idx].files[file_idx].index;

                    // Only read regular files (ignore directories, symlinks, etc.).
                    if let Ok(m) = fs::metadata(&fname) {
                        if m.is_file() {
                            handler.read_hostsfile(&fname, index);
                        }
                    }
                } else if dir_flags.intersects(HostsFileFlags::DHCP_HST | HostsFileFlags::DHCP_OPT)
                {
                    // For DHCP directories: construct full path and read if regular.
                    // C equivalent (inotify.c lines 491-507), behind #ifdef HAVE_DHCP.
                    #[cfg(feature = "dhcp")]
                    {
                        let full_path = format!("{}/{}", dir_path, name_str);

                        if let Ok(m) = fs::metadata(&full_path) {
                            if m.is_file() {
                                handler.option_read_dynfile(
                                    &full_path,
                                    self.dynamic_dirs[dir_idx].flags as u32,
                                );
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Process pending inotify events and trigger appropriate reload actions.
    ///
    /// This is the Rust equivalent of `inotify_check()` (inotify.c lines 580-685).
    /// Called from the main event loop when the inotify fd becomes readable.
    ///
    /// # Event Processing
    ///
    /// 1. Reads all pending inotify events in a non-blocking loop.
    /// 2. For each event with a valid filename (filtering editor backups):
    ///    - **Resolv-file match:** Sets the return flag to `true` (caller should reload
    ///      upstream DNS configuration via `poll_resolv()`).
    ///    - **HOSTS directory match:** Flushes old cache entries via `cache_remove_uid()`,
    ///      logs the event, reloads the file via `read_hostsfile()` (unless DELETE),
    ///      and propagates DHCP changes if applicable.
    ///    - **DHCP directory match (non-DELETE):** Reads the configuration file via
    ///      `option_read_dynfile()` and propagates DHCP changes if applicable.
    ///
    /// # Arguments
    /// * `handler` — Callback trait object for cache and config operations.
    /// * `now` — Current timestamp in seconds since epoch, passed to DHCP propagation.
    ///
    /// # Returns
    /// * `Ok(true)` — At least one resolv-file was modified (caller should reload DNS).
    /// * `Ok(false)` — No resolv-files changed (only dynamic dirs or no events).
    ///
    /// # Errors
    /// * [`InotifyError::ReadFailed`] — Fatal error reading from the inotify fd.
    pub fn check_events(
        &mut self,
        handler: &mut dyn InotifyEventHandler,
        now: i64,
    ) -> Result<bool, InotifyError> {
        let mut hit = false;

        // Use a local buffer to avoid borrow conflicts between self.inotify and
        // self.dynamic_dirs during event processing.
        let mut buffer = vec![0u8; INOTIFY_BUFFER_SIZE];

        // Outer loop: keep reading events until WouldBlock (non-blocking fd).
        // C equivalent (inotify.c lines 587-682): while(1) { read(); for(events) ... }
        loop {
            // Read one batch of events and collect into owned data.
            // We must collect before processing because the Events iterator borrows
            // the buffer, but processing needs mutable access to self.dynamic_dirs.
            let collected: Vec<(WatchDescriptor, EventMask, Option<String>)> = {
                match self.inotify.read_events(&mut buffer) {
                    Ok(events) => events
                        .map(|e| {
                            let name = e.name.map(|n| n.to_string_lossy().into_owned());
                            (e.wd, e.mask, name)
                        })
                        .collect(),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(InotifyError::ReadFailed(e)),
                }
            };

            if collected.is_empty() {
                break;
            }

            // Process each event.
            // C equivalent (inotify.c lines 599-681): inner for loop over events.
            for (wd, mask, name_opt) in &collected {
                let name = match name_opt {
                    Some(n) if !n.is_empty() => n.as_str(),
                    _ => continue,
                };

                // Filter out editor backup files.
                // C equivalent (inotify.c lines 605-610).
                if is_editor_backup(name) {
                    continue;
                }

                // Log the event, noting if it refers to a directory (ISDIR flag).
                if mask.contains(EventMask::ISDIR) {
                    debug!(
                        "inotify: directory event on wd={:?} mask={:?} name='{}'",
                        wd, mask, name
                    );
                } else {
                    debug!(
                        "inotify: file event on wd={:?} mask={:?} name='{}'",
                        wd, mask, name
                    );
                }

                // Check resolv-file watches.
                // C equivalent (inotify.c lines 612-614):
                //   for (res = ...; res; res = res->next)
                //     if (res->wd == in->wd && strcmp(res->file, in->name) == 0)
                //       hit = 1;
                for rw in &self.resolv_watches {
                    if rw.wd == *wd && rw.filename == name {
                        hit = true;
                        info!("inotify: resolv-file {} changed", rw.full_path);
                    }
                }

                // Check dynamic directory watches.
                // C equivalent (inotify.c lines 616-680):
                //   for (dd = ...; dd; dd = dd->next) if (dd->wd == in->wd) { ... }
                for dir_idx in 0..self.dynamic_dirs.len() {
                    let dir_wd = match &self.dynamic_dirs[dir_idx].wd {
                        Some(w) => w,
                        None => continue,
                    };

                    if *dir_wd != *wd {
                        continue;
                    }

                    let dir_flags =
                        HostsFileFlags::from_bits_truncate(self.dynamic_dirs[dir_idx].flags);

                    if dir_flags.contains(HostsFileFlags::HOSTS) {
                        // HOSTS directory processing.
                        // C equivalent (inotify.c lines 619-648).

                        // Get or create the hosts file entry for this filename.
                        let dir_path = self.dynamic_dirs[dir_idx].dir_path.clone();
                        let file_idx = dyndir_add_hosts_entry(
                            &mut self.dynamic_dirs[dir_idx].files,
                            &dir_path,
                            name,
                            &mut self.host_index_counter,
                        );

                        let fname =
                            self.dynamic_dirs[dir_idx].files[file_idx].fname.clone();
                        let index = self.dynamic_dirs[dir_idx].files[file_idx].index;

                        // Flush old cache entries for this hosts file.
                        let removed = handler.cache_remove_uid(index);

                        // Log the event type.
                        if mask.contains(EventMask::DELETE) {
                            info!("inotify: {} removed", fname);
                        } else {
                            info!("inotify: {} new or modified", fname);
                        }

                        if removed > 0 {
                            info!(
                                "inotify: flushed {} names read from {}",
                                removed, fname
                            );
                        }

                        // Reload the file unless it was deleted.
                        // C equivalent (inotify.c lines 636-637):
                        //   if (!(in->mask & IN_DELETE))
                        //     read_hostsfile(ah->fname, ah->index, 0, NULL, 0);
                        if !mask.contains(EventMask::DELETE) {
                            handler.read_hostsfile(&fname, index);
                        }

                        // Propagate changes to DHCP if active.
                        // C equivalent (inotify.c lines 638-646), behind #ifdef HAVE_DHCP.
                        #[cfg(feature = "dhcp")]
                        {
                            handler.dhcp_propagate_changes(now);
                        }
                    } else if !mask.contains(EventMask::DELETE) {
                        // DHCP directory processing (non-DELETE events only).
                        // C equivalent (inotify.c lines 650-677), behind #ifdef HAVE_DHCP.
                        // This branch handles directories with AH_DHCP_HST or AH_DHCP_OPT flags
                        // but NOT AH_HOSTS (the `else` ensures mutual exclusivity).
                        #[cfg(feature = "dhcp")]
                        {
                            if dir_flags.intersects(
                                HostsFileFlags::DHCP_HST | HostsFileFlags::DHCP_OPT,
                            ) {
                                let dir_path =
                                    self.dynamic_dirs[dir_idx].dir_path.clone();
                                let full_path = format!("{}/{}", dir_path, name);

                                info!("inotify: {} new or modified", full_path);

                                // Read DHCP host file and propagate if changed.
                                // C equivalent (inotify.c lines 663-670).
                                if dir_flags.contains(HostsFileFlags::DHCP_HST)
                                    && handler.option_read_dynfile(
                                        &full_path,
                                        HostsFileFlags::DHCP_HST.bits() as u32,
                                    )
                                {
                                    handler.dhcp_propagate_changes(now);
                                }

                                // Read DHCP options file (no propagation needed).
                                // C equivalent (inotify.c lines 672-673).
                                if dir_flags.contains(HostsFileFlags::DHCP_OPT) {
                                    handler.option_read_dynfile(
                                        &full_path,
                                        HostsFileFlags::DHCP_OPT.bits() as u32,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(hit)
    }
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock handler for testing that records all callback invocations.
    struct MockHandler {
        removed_uids: Vec<u32>,
        read_hosts: Vec<(String, u32)>,
        read_dynfiles: Vec<(String, u32)>,
        propagated: Vec<i64>,
    }

    impl MockHandler {
        fn new() -> Self {
            MockHandler {
                removed_uids: Vec::new(),
                read_hosts: Vec::new(),
                read_dynfiles: Vec::new(),
                propagated: Vec::new(),
            }
        }
    }

    impl InotifyEventHandler for MockHandler {
        fn cache_remove_uid(&mut self, index: u32) -> u32 {
            self.removed_uids.push(index);
            0
        }

        fn read_hostsfile(&mut self, path: &str, index: u32) -> usize {
            self.read_hosts.push((path.to_string(), index));
            0
        }

        fn option_read_dynfile(&mut self, path: &str, flags: u32) -> bool {
            self.read_dynfiles.push((path.to_string(), flags));
            true
        }

        fn dhcp_propagate_changes(&mut self, now: i64) {
            self.propagated.push(now);
        }
    }

    #[test]
    fn test_is_editor_backup() {
        // Empty name
        assert!(is_editor_backup(""));
        // Emacs backup
        assert!(is_editor_backup("file.conf~"));
        // Emacs auto-save
        assert!(is_editor_backup("#file.conf#"));
        // Dotfiles
        assert!(is_editor_backup(".hidden"));
        assert!(is_editor_backup(".file.swp"));
        // Normal files should NOT be filtered
        assert!(!is_editor_backup("hosts"));
        assert!(!is_editor_backup("server1.conf"));
        assert!(!is_editor_backup("192.168.1.hosts"));
        // Edge cases
        assert!(!is_editor_backup("#partial"));
        assert!(!is_editor_backup("partial#"));
        assert!(is_editor_backup("#both#"));
    }

    #[test]
    fn test_resolve_symlinks_non_symlink() {
        // A path that is not a symlink should be returned unchanged.
        let result = resolve_symlinks("/etc/hosts", MAXSYMLINKS);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("/etc/hosts"));
    }

    #[test]
    fn test_resolve_symlinks_nonexistent() {
        // A nonexistent path should be returned unchanged (ENOENT → Ok).
        let result = resolve_symlinks("/nonexistent/path/file.conf", MAXSYMLINKS);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            PathBuf::from("/nonexistent/path/file.conf")
        );
    }

    #[test]
    fn test_resolve_symlinks_with_actual_symlink() {
        // Create a temporary directory with a symlink to test resolution.
        let tmp = std::env::temp_dir().join("dnsmasq_inotify_test_symlink");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let target = tmp.join("actual_file.conf");
        fs::write(&target, "test content").expect("write target");

        let link = tmp.join("link_file.conf");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let result = resolve_symlinks(link.to_str().unwrap(), MAXSYMLINKS);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), target);

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_resolve_symlinks_too_many() {
        // Create a circular symlink chain to trigger TooManySymlinks error.
        let tmp = std::env::temp_dir().join("dnsmasq_inotify_test_circular");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        let link_a = tmp.join("link_a");
        let link_b = tmp.join("link_b");
        std::os::unix::fs::symlink(&link_b, &link_a).expect("create symlink a->b");
        std::os::unix::fs::symlink(&link_a, &link_b).expect("create symlink b->a");

        let result = resolve_symlinks(link_a.to_str().unwrap(), MAXSYMLINKS);
        assert!(result.is_err());
        match result.unwrap_err() {
            InotifyError::TooManySymlinks(_) => {} // expected
            other => panic!("Expected TooManySymlinks, got: {:?}", other),
        }

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_dyndir_add_hosts_entry_new() {
        let mut files: Vec<HostFileState> = Vec::new();
        let mut counter: u32 = 1;

        let idx = dyndir_add_hosts_entry(&mut files, "/etc/hosts.d", "server1", &mut counter);

        assert_eq!(idx, 0);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].fname, "/etc/hosts.d/server1");
        assert_eq!(files[0].index, 1);
        assert_eq!(counter, 2);
    }

    #[test]
    fn test_dyndir_add_hosts_entry_existing() {
        let mut files = vec![HostFileState {
            fname: "/etc/hosts.d/server1".to_string(),
            index: 42,
        }];
        let mut counter: u32 = 100;

        let idx = dyndir_add_hosts_entry(&mut files, "/etc/hosts.d", "server1", &mut counter);

        // Should find existing entry, not create a new one.
        assert_eq!(idx, 0);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].index, 42);
        assert_eq!(counter, 100); // counter unchanged
    }

    #[test]
    fn test_dyndir_add_hosts_entry_multiple() {
        let mut files: Vec<HostFileState> = Vec::new();
        let mut counter: u32 = 10;

        let idx1 = dyndir_add_hosts_entry(&mut files, "/etc/hosts.d", "server1", &mut counter);
        let idx2 = dyndir_add_hosts_entry(&mut files, "/etc/hosts.d", "server2", &mut counter);
        let idx3 = dyndir_add_hosts_entry(&mut files, "/etc/hosts.d", "server1", &mut counter);

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // should find existing
        assert_eq!(files.len(), 2);
        assert_eq!(counter, 12); // only incremented twice
    }

    #[test]
    fn test_inotify_manager_new_no_dns() {
        // When DNS port is 0, no resolv watches should be set up.
        let mut config = DaemonConfig::default();
        config.dns.port = 0;

        let result = InotifyManager::new(&config);
        assert!(result.is_ok());
        let mgr = result.unwrap();
        assert!(mgr.resolv_watches.is_empty());
        assert!(mgr.fd() >= 0);
    }

    #[test]
    fn test_inotify_manager_new_no_resolv() {
        // When OPT_NO_RESOLV is set, no resolv watches should be set up.
        let mut config = DaemonConfig::default();
        config.options.set(OPT_NO_RESOLV);

        let result = InotifyManager::new(&config);
        assert!(result.is_ok());
        let mgr = result.unwrap();
        assert!(mgr.resolv_watches.is_empty());
    }

    #[test]
    fn test_inotify_manager_check_events_no_events() {
        // With no watches and no events, check_events should return Ok(false).
        let mut config = DaemonConfig::default();
        config.dns.port = 0; // disable DNS so no resolv watches

        let mut mgr = InotifyManager::new(&config).expect("create manager");
        let mut handler = MockHandler::new();

        let result = mgr.check_events(&mut handler, 0);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_inotify_manager_set_dynamic_watches_empty() {
        // With no dynamic directories, set_dynamic_watches should succeed with no-op.
        let mut config = DaemonConfig::default();
        config.dns.port = 0;

        let mut mgr = InotifyManager::new(&config).expect("create manager");
        let mut handler = MockHandler::new();

        let result =
            mgr.set_dynamic_watches(HostsFileFlags::HOSTS.bits() as u32, &mut handler);
        assert!(result.is_ok());
    }

    #[test]
    fn test_inotify_manager_dynamic_hosts_directory() {
        // Create a temporary directory with a hosts file and verify set_dynamic_watches
        // discovers and reads it.
        use crate::types::dns::DynDir;

        let tmp = std::env::temp_dir().join("dnsmasq_inotify_test_dyndir");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");

        // Create a test hosts file.
        let hosts_file = tmp.join("myhosts");
        fs::write(&hosts_file, "192.168.1.1 server1\n").expect("write hosts");

        let mut config = DaemonConfig::default();
        config.dns.port = 0; // disable DNS resolv watches

        let dyn_dir = DynDir {
            files: Vec::new(),
            flags: HostsFileFlags::HOSTS.bits() | HostsFileFlags::DIR.bits(),
            dname: tmp.to_string_lossy().to_string(),
            #[cfg(feature = "inotify_monitor")]
            wd: -1,
        };
        config.dns.dyn_dirs.push(dyn_dir);

        let mut mgr = InotifyManager::new(&config).expect("create manager");
        let mut handler = MockHandler::new();

        let result =
            mgr.set_dynamic_watches(HostsFileFlags::HOSTS.bits() as u32, &mut handler);
        assert!(result.is_ok());

        // The handler should have been called to read the hosts file.
        assert_eq!(handler.read_hosts.len(), 1);
        assert!(handler.read_hosts[0].0.contains("myhosts"));

        // Cleanup
        let _ = fs::remove_dir_all(&tmp);
    }
}
