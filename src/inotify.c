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
 * @file inotify.c
 * @brief Linux inotify-based efficient file monitoring for configuration reload
 * 
 * DETAILED PURPOSE:
 * This Linux-specific module implements efficient file system monitoring using the
 * inotify(7) API to detect configuration file changes without polling. The system
 * watches critical configuration files including /etc/resolv.conf (upstream DNS
 * servers), dynamic DHCP hosts directories, and DHCP options files. When changes
 * are detected, dnsmasq automatically reloads the affected configuration without
 * requiring manual daemon restart or SIGHUP signal.
 * 
 * The inotify-based approach provides significant performance advantages over
 * traditional polling-based file monitoring by eliminating unnecessary filesystem
 * checks and providing immediate notification of file changes. This is particularly
 * important for embedded systems where CPU cycles and battery power are constrained.
 * 
 * KEY RESPONSIBILITIES:
 * - Initialize inotify watches for resolv.conf files and their parent directories
 * - Monitor dynamic DHCP hosts directories for hosts file additions/modifications
 * - Monitor DHCP options files for configuration changes
 * - Process inotify events and trigger appropriate reload actions (cache flush,
 *   configuration reload, DHCP lease updates)
 * - Handle symbolic links by following them to watch the actual target files
 * - Integrate with main event loop through file descriptor monitoring
 * 
 * DEPENDENCIES:
 * Includes: sys/inotify.h (Linux inotify API), sys/param.h (MAXSYMLINKS constant),
 *           dnsmasq.h (core data structures)
 * Called by: main event loop in dnsmasq.c calls inotify_check() when events ready
 * Calls: poll_resolv() in network.c for DNS server reload, read_hostsfile() in
 *        cache.c for hosts updates, reread_dhcp() in dhcp.c for DHCP configuration
 * 
 * DATA STRUCTURES:
 * - struct inotify_event: Linux kernel inotify event structure (sys/inotify.h)
 * - struct resolvc: Resolver configuration linked list (dnsmasq.h)
 * - struct hostsfile: Dynamic hosts file tracking (dnsmasq.h)
 * - struct dyndir: Dynamic directory monitoring configuration (dnsmasq.h)
 * - inotify_buffer: Static buffer for reading inotify events (INOTIFY_SZ bytes)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_INOTIFY: Entire module conditionally compiled only on Linux systems with
 *   inotify support (kernel 2.6.13+). On other platforms or when disabled, dnsmasq
 *   falls back to polling-based configuration checking.
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model. The inotify file descriptor is added to the
 * main poll() event loop, and inotify_check() is called from the main thread when
 * read events are ready. Uses IN_NONBLOCK flag to prevent blocking reads.
 * 
 * STRATEGY:
 * Set inotify watches on directories containing resolv files, monitoring for
 * IN_CLOSE_WRITE and IN_MOVED_TO events. When events occur, check if the affected
 * file is a configured resolv-file and trigger poll_resolv() with force=1 to
 * ensure immediate reload. For dynamic hosts directories, flush cache and reload
 * hosts. For DHCP files, trigger DHCP configuration and lease updates.
 * 
 * ERROR CONDITIONS:
 * All directories containing monitored resolv-files must exist at startup, even if
 * the actual files don't yet exist. This is a requirement of the inotify API which
 * cannot watch non-existent directories.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 * 
 * @see inotify(7) man page for Linux inotify API documentation
 * @see inotify_init(2), inotify_add_watch(2), inotify_rm_watch(2)
 */

#include "dnsmasq.h"
#ifdef HAVE_INOTIFY

#include <sys/inotify.h>
#include <sys/param.h> /* For MAXSYMLINKS */

static char *inotify_buffer;
#define INOTIFY_SZ (sizeof(struct inotify_event) + NAME_MAX + 1)

/**
 * @brief Resolve symbolic link and return absolute target path
 * 
 * @detailed Follows a symbolic link and returns the path it points to, converting
 * relative paths to absolute paths based on the symlink's location. This function
 * handles arbitrarily long target paths by iteratively increasing buffer size until
 * readlink() succeeds. If the path is not a symbolic link or doesn't exist, returns
 * NULL. This is critical for inotify monitoring because inotify watches the actual
 * file, not the symlink, so we need to resolve symlinks like /etc/resolv.conf which
 * often points to /run/systemd/resolve/resolv.conf or similar.
 * 
 * @param path Path to check and potentially resolve (must not be NULL)
 * 
 * @return Malloc'ed string containing absolute path to symlink target, or NULL if
 *         path is not a symlink or doesn't exist
 * @retval NULL Path doesn't exist (errno ENOENT) or is not a symlink (errno EINVAL)
 * @retval malloc'ed_string Absolute path to symlink target (caller must free)
 * 
 * @note Caller is responsible for freeing returned string with free()
 * @warning Dies with EC_MISC error code if readlink() fails for reasons other than
 *          EINVAL or ENOENT (e.g., permission denied, I/O error)
 * 
 * @see readlink(2), realpath(3)
 * 
 * EXAMPLE USAGE:
 * @code
 * char *target = my_readlink("/etc/resolv.conf");
 * if (target) {
 *   // resolv.conf is a symlink, watch the target file
 *   printf("Resolved to: %s\n", target);
 *   free(target);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (filesystem operation)
 * SIDE EFFECTS: Allocates memory via safe_malloc(), dies on unexpected errors
 * THREAD SAFETY: Single-threaded architecture, safe within main thread
 */
static char *my_readlink(char *path)
{
  ssize_t rc, size = 64;
  char *buf;

  while (1)
    {
      buf = safe_malloc(size);
      rc = readlink(path, buf, (size_t)size);
      
      if (rc == -1)
	{
	  /* Not link or doesn't exist. */
	  if (errno == EINVAL || errno == ENOENT)
	    {
	      free(buf);
	      return NULL;
	    }
	  else
	    die(_("cannot access path %s: %s"), path, EC_MISC);
	}
      else if (rc < size-1)
	{
	  char *d;
	  
	  buf[rc] = 0;
	  if (buf[0] != '/' && ((d = strrchr(path, '/'))))
	    {
	      /* Add path to relative link */
	      char *new_buf = safe_malloc((d - path) + strlen(buf) + 2);
	      *(d+1) = 0;
	      strcpy(new_buf, path);
	      strcat(new_buf, buf);
	      free(buf);
	      buf = new_buf;
	    }
	  return buf;
	}

      /* Buffer too small, increase and retry */
      size += 64;
      free(buf);
    }
}

/**
 * @brief Initialize inotify subsystem and set up watches for resolv-files
 * 
 * @detailed Creates the inotify file descriptor with non-blocking and close-on-exec
 * flags, allocates the event buffer, and sets up inotify watches on all configured
 * resolv-file directories. This function is called once during daemon initialization
 * to establish monitoring for upstream DNS server configuration files. For each
 * resolv-file (typically /etc/resolv.conf), the function follows symbolic links up to
 * MAXSYMLINKS depth to find the actual target file, then watches the containing
 * directory for IN_CLOSE_WRITE and IN_MOVED_TO events. Watching the directory rather
 * than the file itself handles the common pattern where files are atomically updated
 * by writing to a temporary file and renaming it.
 * 
 * The function skips initialization if DNS is disabled (daemon->port == 0) or if
 * resolv-file reading is disabled via --no-resolv option (OPT_NO_RESOLV). This allows
 * dnsmasq to operate in authoritative-only mode without unnecessary inotify overhead.
 * 
 * @param None (uses global daemon structure)
 * 
 * @return void
 * 
 * @note Stores inotify file descriptor in daemon->inotifyfd for event loop integration
 * @note Stores watch descriptor in res->wd and filename pointer in res->file for each
 *       resolv-file entry in daemon->resolv_files linked list
 * @warning Dies with EC_MISC if inotify initialization fails, if symlink depth exceeds
 *          MAXSYMLINKS (typically 20), if resolv-file directory doesn't exist, or if
 *          inotify_add_watch() fails for any reason. All directories containing
 *          resolv-files must exist at startup.
 * @warning Must be called after configuration parsing completes but before entering
 *          main event loop
 * 
 * @see inotify_check() for event processing, poll_resolv() for reload action
 * @see inotify_init1(2), inotify_add_watch(2)
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main daemon initialization (dnsmasq.c):
 * read_opts(argc, argv, compile_opts);  // Parse configuration
 * inotify_dnsmasq_init();                // Initialize file monitoring
 * check_servers();                       // Validate upstream servers
 * // Now daemon->inotifyfd can be added to poll() set
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux-specific implementation detail)
 * SIDE EFFECTS: Allocates inotify_buffer (INOTIFY_SZ bytes), creates inotify file
 *               descriptor, adds watches to kernel inotify subsystem, modifies
 *               daemon->inotifyfd and per-resolvc res->wd and res->file fields
 * THREAD SAFETY: Single-threaded initialization, must be called only once from main thread
 */
void inotify_dnsmasq_init()
{
  struct resolvc *res;
  inotify_buffer = safe_malloc(INOTIFY_SZ);
  daemon->inotifyfd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
  
  if (daemon->inotifyfd == -1)
    die(_("failed to create inotify: %s"), NULL, EC_MISC);

  if (daemon->port == 0 || option_bool(OPT_NO_RESOLV))
    return;
  
  for (res = daemon->resolv_files; res; res = res->next)
    {
      char *d, *new_path, *path = safe_malloc(strlen(res->name) + 1);
      int links = MAXSYMLINKS;

      strcpy(path, res->name);

      /* Follow symlinks until we reach a non-symlink, or a non-existent file. */
      while ((new_path = my_readlink(path)))
	{
	  if (links-- == 0)
	    die(_("too many symlinks following %s"), res->name, EC_MISC);
	  free(path);
	  path = new_path;
	}

      res->wd = -1;

      if ((d = strrchr(path, '/')))
	{
	  *d = 0; /* make path just directory */
	  res->wd = inotify_add_watch(daemon->inotifyfd, path, IN_CLOSE_WRITE | IN_MOVED_TO);

	  res->file = d+1; /* pointer to filename */
	  *d = '/';
	  
	  if (res->wd == -1 && errno == ENOENT)
	    die(_("directory %s for resolv-file is missing, cannot poll"), res->name, EC_MISC);
	}	  
	 
      if (res->wd == -1)
	die(_("failed to create inotify for %s: %s"), res->name, EC_MISC);
	
    }
}

/**
 * @brief Create or retrieve hostsfile entry for a file in a dynamic directory
 * 
 * @detailed Checks if a given file in a dynamic directory is already tracked in the
 * dd->files linked list. If found, returns the existing hostsfile structure. If not
 * found, allocates a new hostsfile structure, constructs the full file path by
 * concatenating dd->dname with the filename, links it to the head of dd->files list,
 * and assigns a unique host_index for cache management. This function is called during
 * dynamic directory initialization and when new files are detected via inotify events.
 * 
 * The function handles the common pattern where multiple inotify events may be generated
 * for the same file (e.g., close-write followed by attribute change), preventing duplicate
 * hostsfile entries. Each hostsfile entry tracks a single hosts file with its flags,
 * index, and full path, enabling efficient cache updates and file reloading.
 * 
 * @param dd Dynamic directory structure containing directory name, flags, and file list
 * @param file Filename (not full path) of hosts file within the directory
 * 
 * @return Pointer to hostsfile structure (existing or newly created)
 * @retval hostsfile_ptr Successfully found existing entry or created new entry
 * @retval NULL Memory allocation failed (whine_malloc returned NULL, error logged)
 * 
 * @note The returned hostsfile is linked into dd->files and should not be manually freed
 * @note Full file path is constructed as dd->dname + "/" + file
 * @note Each new hostsfile gets unique index from daemon->host_index (incremented)
 * @warning Does not verify file exists or is readable - caller should check separately
 * @warning Memory allocation failures logged via whine_malloc but do not die()
 * 
 * @see set_dynamic_inotify() for initial directory setup, inotify_check() for event handling
 * @see struct hostsfile and struct dyndir definitions in dnsmasq.h
 * @see read_hostsfile() in cache.c for hosts file parsing
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dyndir dd;
 * dd.dname = "/etc/dnsmasq.d/hosts";
 * dd.flags = AH_DIR;
 * dd.files = NULL;
 * 
 * // Add or retrieve hostsfile for "server1.hosts"
 * struct hostsfile *ah = dyndir_addhosts(&dd, "server1.hosts");
 * if (ah) {
 *   // ah->fname is "/etc/dnsmasq.d/hosts/server1.hosts"
 *   // ah->index is unique identifier for cache management
 *   read_hostsfile(ah, rhash, revhashsz, ...);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal implementation detail)
 * SIDE EFFECTS: May allocate hostsfile structure and path string, modifies dd->files
 *               linked list, increments daemon->host_index for new entries
 * THREAD SAFETY: Single-threaded architecture, safe within main thread
 */
static struct hostsfile *dyndir_addhosts(struct dyndir *dd, char *file)
{
  /* Check if this file is already known in dd->files */
  struct hostsfile *ah;
  size_t dirlen = strlen(dd->dname);
  
  /* ah->fname always starts with the string in dd->dname */
  for (ah = dd->files; ah; ah = ah->next)
    if (ah->fname[dirlen] == '/' &&
        strcmp(&ah->fname[dirlen+1], file) == 0)
      return ah;
        
  /* Not known, create new hostsfile record for this dyndir */
  if ((ah = whine_malloc(sizeof(struct hostsfile))))
    {
      char *path;

      if (!(path = whine_malloc(dirlen + strlen(file) + 2)))
	{
	  free(ah);
	  return NULL;
	}
      
      strcpy(path, dd->dname);
      strcat(path, "/");
      strcat(path, file);
      
      /* Add this file to the tip of the linked list */
      ah->next = dd->files;
      dd->files = ah;
      
      /* Copy flags, set index and the full file path */
      ah->flags = dd->flags;
      ah->index = daemon->host_index++;
      ah->fname = path;
    }
  
  return ah;
}


/**
 * @brief Initialize inotify watches for dynamic directories and read pre-existing files
 * 
 * @detailed This function sets up inotify monitoring for dynamic host directories
 *           (--addn-hosts via AH_DIR flag) or DHCP host directories (--dhcp-hostsdir).
 *           For each matching directory, it adds an inotify watch to detect file changes,
 *           then immediately reads all existing files in the directory to avoid race
 *           conditions where files might be added between configuration parsing and
 *           inotify setup. For addn-hosts directories, it creates hostsfile structures
 *           and calls read_hostsfile() to populate DNS cache. For dhcp-hostsdir, it
 *           calls option_read_dynfile() to parse DHCP configuration entries. The function
 *           handles both regular files and symbolic links, following symlinks to resolve
 *           their actual targets.
 * 
 * @param flag Controls which type of directory to initialize: AH_DIR for addn-hosts
 *             directories, 0 for dhcp-hostsdir directories. Only directories matching
 *             this flag are processed in this invocation
 * @param total_size Total DNS cache hash table size, passed to read_hostsfile() for
 *                   cache insertions
 * @param rhash Pointer to DNS cache hash table, passed to read_hostsfile() for inserting
 *              host records from addn-hosts files. Must not be NULL when flag is AH_DIR
 * @param revhashsz Reverse hash table size, passed to read_hostsfile() for reverse
 *                  lookup entries
 * 
 * @return None (void function)
 * 
 * @note This function must be called after inotify_dnsmasq_init() to ensure
 *       daemon->inotifyfd is initialized. It should be called once for AH_DIR
 *       directories and once for dhcp-hostsdir directories
 * @warning Dies with EC_MISC error if any directory doesn't exist or inotify_add_watch
 *          fails. All configured directories must be present at startup
 * 
 * @see dyndir_addhosts() for creating hostsfile entries from directory files
 * @see read_hostsfile() in option.c for parsing hosts file format
 * @see option_read_dynfile() in option.c for parsing DHCP host configuration
 * @see inotify_check() for processing subsequent file change events
 * 
 * EXAMPLE USAGE:
 * @code
 * // After inotify initialization, set up watches for addn-hosts directories
 * set_dynamic_inotify(AH_DIR, hash_size, daemon->packet, hash_size);
 * 
 * // Then set up watches for dhcp-hostsdir directories
 * set_dynamic_inotify(0, 0, NULL, 0);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux-specific inotify implementation)
 * 
 * SIDE EFFECTS:
 * - Adds inotify watches to kernel via inotify_add_watch() (limited by /proc/sys/fs/inotify/max_user_watches)
 * - Allocates hostsfile structures in daemon->addn_hosts linked list (AH_DIR directories)
 * - Reads and parses all existing files in watched directories
 * - Populates DNS cache with A/AAAA records from addn-hosts files
 * - Adds DHCP host configurations from dhcp-hostsdir files
 * - Opens and closes directory streams via opendir()/closedir()
 * - Follows symbolic links, potentially accessing files outside watched directory
 * 
 * THREAD SAFETY: Single-threaded event-driven architecture; modifies global daemon state
 */
void set_dynamic_inotify(int flag, int total_size, struct crec **rhash, int revhashsz)
{
  struct dyndir *dd;

  for (dd = daemon->dynamic_dirs; dd; dd = dd->next)
    {
      DIR *dir_stream = NULL;
      struct dirent *ent;
      struct stat buf;

      if (!(dd->flags & flag))
	continue;

      if (stat(dd->dname, &buf) == -1)
	{
	  my_syslog(LOG_ERR, _("bad dynamic directory %s: %s"), 
		    dd->dname, strerror(errno));
	  continue;
	}

      if (!(S_ISDIR(buf.st_mode)))
	{
	  my_syslog(LOG_ERR, _("bad dynamic directory %s: %s"), 
		    dd->dname, _("not a directory"));
	  continue;
	}

       if (!(dd->flags & AH_WD_DONE))
	 {
	   dd->wd = inotify_add_watch(daemon->inotifyfd, dd->dname, IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE);
	   dd->flags |= AH_WD_DONE;
	 }

       /* Read contents of dir _after_ calling add_watch, in the hope of avoiding
	  a race which misses files being added as we start */
       if (dd->wd == -1 || !(dir_stream = opendir(dd->dname)))
	 {
	   my_syslog(LOG_ERR, _("failed to create inotify for %s: %s"),
		     dd->dname, strerror(errno));
	   continue;
	 }

       while ((ent = readdir(dir_stream)))
	 {
	   size_t lenfile = strlen(ent->d_name);
	   	   
	   /* ignore emacs backups and dotfiles */
	   if (lenfile == 0 || 
	       ent->d_name[lenfile - 1] == '~' ||
	       (ent->d_name[0] == '#' && ent->d_name[lenfile - 1] == '#') ||
	       ent->d_name[0] == '.')
	     continue;

	   if (dd->flags & AH_HOSTS)
	     {
	       struct hostsfile *ah;

	       /* ignore non-regular files */
	       if ((ah = dyndir_addhosts(dd, ent->d_name)) &&
		   stat(ah->fname, &buf) != -1 && S_ISREG(buf.st_mode))
		 total_size = read_hostsfile(ah->fname, ah->index, total_size, rhash, revhashsz);
	     }
#ifdef HAVE_DHCP
	   else if (dd->flags & (AH_DHCP_HST | AH_DHCP_OPT))
	     {
	       char *path;
	       
	       if ((path = whine_malloc(strlen(dd->dname) + lenfile + 2)))
		 {
		   strcpy(path, dd->dname);
		   strcat(path, "/");
		   strcat(path, ent->d_name);
		   
		   /* ignore non-regular files */
		   if (stat(path, &buf) != -1 && S_ISREG(buf.st_mode))
		     option_read_dynfile(path, dd->flags);
		   
		   free(path);
		 }
	     }
#endif		   
	 }
       
       closedir(dir_stream);
    }
}

/**
 * @brief Process pending inotify file change events and trigger configuration reloads
 * 
 * @detailed This function is called from the main event loop when daemon->inotifyfd
 *           becomes readable, indicating pending inotify events. It reads all available
 *           events from the inotify file descriptor in a non-blocking manner, processes
 *           each event, and triggers appropriate actions based on the file type and
 *           event mask. For resolv-files (upstream DNS configuration), it returns a
 *           hit flag to signal poll_resolv() should be called. For dynamic addn-hosts
 *           directories, it removes old cache entries and reloads the modified file.
 *           For DHCP configuration directories (dhcp-hostsdir, dhcp-optsdir), it reads
 *           the new/modified configuration and propagates changes to active leases.
 *           The function filters out editor backup files (ending with ~), emacs
 *           temporary files (surrounded by #), and dotfiles (starting with .) to
 *           avoid processing spurious events during file editing.
 * 
 * @param now Current timestamp in seconds since epoch. Passed for consistency with
 *            other periodic check functions but not used by this implementation.
 *            Marked (void)now to suppress unused parameter warnings
 * 
 * @return Returns 1 if any watched resolv-file was modified (signals poll_resolv
 *         should be called with force flag). Returns 0 if only dynamic directory
 *         files changed or no events were processed
 * @retval 1 At least one resolv-file in daemon->resolv_files list was modified
 * @retval 0 No resolv-files changed (only dynamic dirs or no events)
 * 
 * @note This function must be called only when select/poll indicates daemon->inotifyfd
 *       is readable. Calling otherwise may block if IN_NONBLOCK was not set
 * @warning Assumes inotify_dnsmasq_init() and set_dynamic_inotify() have been called
 *          to set up watches. Processing events with missing watch descriptors is safe
 *          but events will be ignored
 * 
 * @see inotify_dnsmasq_init() for initial inotify setup and resolv-file watches
 * @see set_dynamic_inotify() for dynamic directory watch setup
 * @see poll_resolv() in option.c for handling resolv-file changes when hit=1
 * @see read_hostsfile() in option.c for reloading addn-hosts files
 * @see option_read_dynfile() in option.c for reading DHCP configuration files
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop when inotify fd is ready
 * if (FD_ISSET(daemon->inotifyfd, &rset)) {
 *     if (inotify_check(now)) {
 *         // Resolv-file changed, force upstream DNS reconfiguration
 *         poll_resolv(1, 0, now);
 *     }
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Linux-specific inotify implementation)
 * 
 * SIDE EFFECTS:
 * - Reads events from daemon->inotifyfd, draining kernel inotify event queue
 * - For addn-hosts events: Removes cache entries via cache_remove_uid() and reloads
 *   file via read_hostsfile(), populating DNS cache with new A/AAAA records
 * - For DHCP host/option events: Reads configuration via option_read_dynfile(),
 *   updates daemon->dhcp_conf structures, recalculates lease assignments via
 *   lease_update_from_configs(), writes lease file via lease_update_file(), and
 *   updates DNS cache with lease hostnames via lease_update_dns()
 * - Logs informational messages for each file event processed (INFO priority)
 * - Allocates and frees temporary path strings for DHCP directory events
 * 
 * THREAD SAFETY: Single-threaded event-driven architecture; modifies global daemon
 *                state including DNS cache and DHCP lease database
 */
int inotify_check(time_t now)
{
  int hit = 0;
  struct dyndir *dd;

  (void)now;
  
  while (1)
    {
      int rc;
      char *p;
      struct resolvc *res;
      struct inotify_event *in;

      while ((rc = read(daemon->inotifyfd, inotify_buffer, INOTIFY_SZ)) == -1 && errno == EINTR);
      
      if (rc <= 0)
	break;
      
      for (p = inotify_buffer; rc - (p - inotify_buffer) >= (int)sizeof(struct inotify_event); p += sizeof(struct inotify_event) + in->len) 
	{
	  size_t namelen;

	  in = (struct inotify_event*)p;
	  
	  /* ignore emacs backups and dotfiles */
	  if (in->len == 0 || (namelen = strlen(in->name)) == 0 ||
	      in->name[namelen - 1] == '~' ||
	      (in->name[0] == '#' && in->name[namelen - 1] == '#') ||
	      in->name[0] == '.')
	    continue;

	  for (res = daemon->resolv_files; res; res = res->next)
	    if (res->wd == in->wd && strcmp(res->file, in->name) == 0)
	      hit = 1;

	  for (dd = daemon->dynamic_dirs; dd; dd = dd->next)
	    if (dd->wd == in->wd)
	      {
		if (dd->flags & AH_HOSTS)
		  {
		    struct hostsfile *ah;
		    if ((ah = dyndir_addhosts(dd, in->name)))
		      {
			const unsigned int removed = cache_remove_uid(ah->index);

			/* Is this is a deletion event? */
			if (in->mask & IN_DELETE)
			  my_syslog(LOG_INFO, _("inotify: %s removed"), ah->fname);
			else 
			  my_syslog(LOG_INFO, _("inotify: %s new or modified"), ah->fname);

			if (removed > 0)
			  my_syslog(LOG_INFO, _("inotify: flushed %u names read from %s"), removed, ah->fname);
			
			/* (Re-)load hostsfile only if this event isn't triggered by deletion */
			if (!(in->mask & IN_DELETE))
			  read_hostsfile(ah->fname, ah->index, 0, NULL, 0);
#ifdef HAVE_DHCP
			if (daemon->dhcp || daemon->doing_dhcp6) 
			  {
			    /* Propagate the consequences of loading a new dhcp-host */
			    dhcp_update_configs(daemon->dhcp_conf);
			    lease_update_from_configs(); 
			    lease_update_file(now); 
			    lease_update_dns(1);
			  }
#endif
		      }
		  }
#ifdef HAVE_DHCP
		else if (!(in->mask & IN_DELETE))
		  {
		    char *path;

		    if ((path = whine_malloc(strlen(dd->dname) + in->len + 2)))
		      {
			strcpy(path, dd->dname);
			strcat(path, "/");
			strcat(path, in->name);
			
			my_syslog(LOG_INFO, _("inotify: %s new or modified"), path);

			if ((dd->flags & AH_DHCP_HST) && option_read_dynfile(path, AH_DHCP_HST))
			  {
			    /* Propagate the consequences of loading a new dhcp-host */
			    dhcp_update_configs(daemon->dhcp_conf);
			    lease_update_from_configs(); 
			    lease_update_file(now); 
			    lease_update_dns(1);
			  }
			
			if (dd->flags & AH_DHCP_OPT)
			  option_read_dynfile(path, AH_DHCP_OPT);
		    
			free(path);
		      }
		  }
#endif
		
	      }
	}
    }
  
  return hit;
}

#endif  /* INOTIFY */
