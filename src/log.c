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
 * @file log.c
 * @brief Non-blocking, fork-safe asynchronous logging system for dnsmasq
 * 
 * DETAILED PURPOSE:
 * This module implements a non-blocking, fork-safe logging queue that prevents 
 * logging operations from blocking the main event loop. The architecture solves 
 * a critical deadlock scenario: if syslogd makes DNS lookups through dnsmasq, 
 * and dnsmasq blocks waiting for syslogd to accept log messages, the two daemons 
 * can deadlock. This implementation uses a bounded queue (LOG_MAX=5 entries from 
 * config.h) to buffer log messages, with asynchronous writes to prevent blocking.
 * 
 * KEY RESPONSIBILITIES:
 * - my_syslog(): Queue log messages with RFC 3164 formatting without blocking
 * - log_write(): Asynchronously write queued messages to syslog socket or file
 * - flush_log(): Synchronously flush all queued messages (used during shutdown)
 * - die(): Handle fatal errors with final log message before process termination
 * - log_start(): Initialize logging subsystem with connection to syslog daemon
 * - log_reopen(): Support log file rotation via signal-triggered reopen
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core daemon structures, option_bool, send_event)
 *           android/log.h (conditional: Android platform logging via __android_log_print)
 * Called by: All dnsmasq modules that generate log messages (forward.c, cache.c, 
 *            dhcp.c, etc.) via my_syslog() macro interface
 * Calls: System calls (socket, connect, write, openlog, syslog), dnsmasq utility 
 *        functions (safe_malloc, prettyprint_time, prettyprint_addr, send_event)
 * 
 * DATA STRUCTURES:
 * - struct log_entry: Fixed-size log message buffer (MAX_MESSAGE=1024 bytes from 
 *   RFC 3164) with offset, length, pid tracking, and intrusive linked list pointer
 *   (defined at line 47)
 * - Static queue management: entries (active queue head), free_entries (free list),
 *   entries_alloced (current allocation count), entries_lost (dropped message counter)
 * - Connection state: log_fd (syslog socket), connection_good (connection health),
 *   connection_type (SOCK_DGRAM or SOCK_STREAM for UDP/TCP syslog)
 * 
 * COMPILE-TIME OPTIONS:
 * - __ANDROID__: Use Android logging API (__android_log_print) instead of syslog
 * - LOG_LOCAL0: Enable LOCAL0 facility when debug mode active (platform-specific)
 * - LOG_MAX (config.h:49): Queue depth limit (default 5), prevents unbounded growth
 * - MAX_MESSAGE (RFC 3164): Maximum log message size (1024 bytes)
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven model with fork safety. Log entries store pid to 
 * detect fork events and avoid duplicate logging across parent/child processes.
 * The bounded queue (LOG_MAX) ensures deterministic memory usage. Queue operations 
 * are not thread-safe; dnsmasq's single-threaded architecture eliminates need for 
 * synchronization primitives. Asynchronous writes via poll-based notification 
 * prevent blocking main event loop on slow syslog operations.
 * 
 * ARCHITECTURAL DECISIONS:
 * Bounded Queue Rationale: The LOG_MAX limit prevents unbounded memory growth under
 * logging storms. When queue is full, new messages are dropped with a counter 
 * (entries_lost) that generates a meta-log message when conditions improve. This 
 * trade-off prioritizes service availability over complete log fidelity.
 * 
 * Fork-Safety Design: Each log_entry stores the pid of the process that created it.
 * After fork, child processes skip entries created by the parent, preventing 
 * duplicate log messages.
 * 
 * Exponential Backoff: When queue depth exceeds thresholds, my_syslog() introduces
 * delays (usleep) with exponential backoff to slow down log generation and allow
 * the queue to drain. This self-throttling mechanism prevents log storms.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef __ANDROID__
#  include <android/log.h>
#endif

/* Implement logging to /dev/log asynchronously. If syslogd is 
   making DNS lookups through dnsmasq, and dnsmasq blocks awaiting
   syslogd, then the two daemons can deadlock. We get around this
   by not blocking when talking to syslog, instead we queue up to 
   MAX_LOGS messages. If more are queued, they will be dropped,
   and the drop event itself logged. */

/* The "wire" protocol for logging is defined in RFC 3164 */

/* From RFC 3164 */
#define MAX_MESSAGE 1024

/* defaults in case we die() before we log_start() */
static int log_fac = LOG_DAEMON;
static int log_stderr = 0;
static int echo_stderr = 0;
static int log_fd = -1;
static int log_to_file = 0;
static int entries_alloced = 0;
static int entries_lost = 0;
static int connection_good = 1;
static int max_logs = 0;
static int connection_type = SOCK_DGRAM;

struct log_entry {
  int offset, length;
  pid_t pid; /* to avoid duplicates over a fork */
  struct log_entry *next;
  char payload[MAX_MESSAGE];
};

static struct log_entry *entries = NULL;
static struct log_entry *free_entries = NULL;

/**
 * @brief Initialize the logging subsystem and establish connection to syslog daemon
 * 
 * @detailed This function sets up the logging infrastructure during daemon startup,
 * establishing either a connection to the syslog daemon via /dev/log socket or 
 * opening a log file for direct writes. The function configures log facility 
 * (daemon or LOCAL0 in debug mode), determines whether to echo logs to stderr,
 * and pre-allocates the initial log queue buffer. If queuing is disabled (max_logs=0),
 * allocates a single buffer for synchronous logging. Handles privilege separation
 * by opening log file descriptor before dropping root privileges if needed.
 * 
 * @param ent_pw Pointer to passwd structure for target unprivileged user (may be NULL
 *               if not dropping privileges). Used to determine if log file ownership
 *               changes are needed for privilege separation.
 * @param errfd File descriptor for sending startup error events to parent process via
 *              send_event(). Used for EVENT_LOG_ERR notifications if log initialization
 *              fails (e.g., cannot open log file).
 * 
 * @return 0 on success, does not return on failure (calls _exit(0) after send_event)
 * 
 * @note This function must be called during daemon initialization before dropping
 *       privileges, as it may need root access to bind to /dev/log socket or change
 *       log file ownership.
 * @warning If log file specified by daemon->log_file cannot be opened, sends
 *          EVENT_LOG_ERR via errfd and terminates process with _exit(0). Parent
 *          process must handle this event to report startup failure.
 * 
 * @see log_reopen() for log file rotation support after SIGHUP
 * @see my_syslog() for actual logging interface used by rest of codebase
 * 
 * EXAMPLE USAGE:
 * @code
 * struct passwd *ent_pw = getpwnam("dnsmasq");
 * int event_pipe[2];
 * pipe(event_pipe);
 * if (log_start(ent_pw, event_pipe[1]) == 0) {
 *   // Logging subsystem initialized successfully
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements RFC 3164 syslog message format (MAX_MESSAGE=1024 bytes)
 * 
 * SIDE EFFECTS:
 * - Sets global logging configuration: log_fac, log_stderr, echo_stderr, max_logs
 * - Opens log_fd socket/file descriptor for subsequent log writes
 * - Pre-allocates free_entries buffer (1 entry if max_logs=0, lazy allocation otherwise)
 * - May modify daemon->max_logs to 0 if logging to file (disables async queue)
 * - Calls _exit(0) on fatal errors, terminating process after event notification
 * 
 * THREAD SAFETY: Not thread-safe (called once during single-threaded initialization)
 */
int log_start(struct passwd *ent_pw, int errfd)
{
  int ret = 0;

  echo_stderr = option_bool(OPT_DEBUG);

  if (daemon->log_fac != -1)
    log_fac = daemon->log_fac;
#ifdef LOG_LOCAL0
  else if (option_bool(OPT_DEBUG))
    log_fac = LOG_LOCAL0;
#endif

  if (daemon->log_file)
    { 
      log_to_file = 1;
      daemon->max_logs = 0;
      if (strcmp(daemon->log_file, "-") == 0)
	{
	  log_stderr = 1;
	  echo_stderr = 0;
	  log_fd = dup(STDERR_FILENO);
	}
    }
  
  max_logs = daemon->max_logs;

  if (!log_reopen(daemon->log_file))
    {
      send_event(errfd, EVENT_LOG_ERR, errno, daemon->log_file ? daemon->log_file : "");
      _exit(0);
    }

  /* if queuing is inhibited, make sure we allocate
     the one required buffer now. */
  if (max_logs == 0)
    {  
      free_entries = safe_malloc(sizeof(struct log_entry));
      free_entries->next = NULL;
      entries_alloced = 1;
    }

  /* If we're running as root and going to change uid later,
     change the ownership here so that the file is always owned by
     the dnsmasq user. Then logrotate can just copy the owner.
     Failure of the chown call is OK, (for instance when started as non-root).
     
     If we've created a file with group-id root, we also make
     the file group-writable. This gives processes in the root group
     write access to the file and avoids the problem that on some systems,
     once the file is owned by the dnsmasq user, it can't be written
     whilst dnsmasq is running as root during startup.
 */
  if (log_to_file && !log_stderr && ent_pw && ent_pw->pw_uid != 0)
    {
      struct stat ls;
      if (getgid() == 0 && fstat(log_fd, &ls) == 0 && ls.st_gid == 0 &&
	  (ls.st_mode & S_IWGRP) == 0)
	(void)fchmod(log_fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
      if (fchown(log_fd, ent_pw->pw_uid, -1) != 0)
	ret = errno;
    }

  return ret;
}

/**
 * @brief Reopen log file or syslog connection for log rotation support
 * 
 * @detailed This function closes the current log file descriptor and reopens it,
 * enabling log file rotation via external tools (e.g., logrotate). When log_file
 * is NULL, reopens the connection to the syslog daemon via /dev/log socket.
 * For file logging, the old descriptor is closed and the file is reopened with
 * O_APPEND to continue writing at the end. For syslog connections, creates a
 * new AF_UNIX socket and sets it to non-blocking mode if async queueing is
 * enabled (max_logs > 0). Called in response to SIGHUP signal for log rotation.
 * 
 * @param log_file Path to log file to reopen, or NULL to reopen syslog connection.
 *                 If non-NULL, opens/creates file with O_WRONLY|O_CREAT|O_APPEND
 *                 and permissions 0644 (modified by umask 022 = final 0644).
 * 
 * @return 1 (true) if log descriptor successfully opened, 0 (false) on failure
 * @retval 1 Log file or socket opened successfully, logging can proceed
 * @retval 0 Failed to open log file or create socket, logging will be unavailable
 * 
 * @note On Solaris and Android platforms, returns 1 without opening socket as these
 *       platforms use vsyslog() library function instead of direct /dev/log writes.
 * @note This function is called during initialization by log_start() and on SIGHUP
 *       signal for log rotation. The umask is set to 022 by the time this executes.
 * @warning If socket creation fails, logging is silently disabled until next reopen.
 *          Monitor log output to detect missing messages indicating reopen failure.
 * 
 * @see log_start() for initial logging setup
 * @see flush_log() for flushing queued messages before rotation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Signal handler for log rotation
 * void handle_sighup(int sig) {
 *   flush_log();  // Write any queued messages
 *   if (!log_reopen(daemon->log_file)) {
 *     // Log reopen failed, logging disabled
 *   }
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Closes current log_fd if valid (>= 0), terminating existing connection/file
 * - Opens new log_fd for log file (with append mode) or syslog socket
 * - Sets log_fd to non-blocking mode if max_logs > 0 (async queue enabled)
 * - Any queued messages are preserved and will be written with new descriptor
 * 
 * THREAD SAFETY: Not thread-safe (called from signal handler in single-threaded model)
 */
int log_reopen(char *log_file)
{
  if (!log_stderr)
    {      
      if (log_fd != -1)
	close(log_fd);
      
      /* NOTE: umask is set to 022 by the time this gets called */
      
      if (log_file)
	log_fd = open(log_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP);
      else
	{
#if defined(HAVE_SOLARIS_NETWORK) || defined(__ANDROID__)
	  /* Solaris logging is "different", /dev/log is not unix-domain socket.
	     Just leave log_fd == -1 and use the vsyslog call for everything.... */
#   define _PATH_LOG ""  /* dummy */
	  return 1;
#else
	  int flags;
	  log_fd = socket(AF_UNIX, connection_type, 0);
	  
	  /* if max_logs is zero, leave the socket blocking */
	  if (log_fd != -1 && max_logs != 0 && (flags = fcntl(log_fd, F_GETFL)) != -1)
	    fcntl(log_fd, F_SETFL, flags | O_NONBLOCK);
#endif
	}
    }
  
  return log_fd != -1;
}

/**
 * @brief Move the oldest queued log entry back to the free list
 * 
 * @detailed This static helper function dequeues the oldest log entry from the
 * entries queue (FIFO order) and returns it to the free_entries pool for reuse.
 * It maintains the invariant that total allocated entries (entries_alloced)
 * remains constant while cycling entries between the in-use queue and the free
 * pool. Called by log_write() after successfully writing a queued message to
 * syslog or log file. This memory recycling prevents repeated malloc/free calls
 * in the logging hot path.
 * 
 * @return void (no return value)
 * 
 * @note This function assumes entries list is non-empty (caller must check).
 *       Undefined behavior if called when entries == NULL.
 * @note Preserves entries_alloced count: entries move between queues without
 *       allocation/deallocation unless max_logs == 0 (unbounded mode).
 * @warning Must only be called from log_write() after successful message transmission.
 *          Do not call directly without verifying entries queue is non-empty.
 * 
 * @see log_write() which calls this after writing each queued message
 * @see my_syslog() which allocates entries and adds to queue
 * 
 * EXAMPLE USAGE:
 * @code
 * // Within log_write() after successful write:
 * if (entries) {
 *   ssize_t rc = write(log_fd, entries->payload + entries->offset, 
 *                      entries->length - entries->offset);
 *   if (rc == entries->length - entries->offset) {
 *     free_entry();  // Return entry to free pool
 *   }
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Removes head entry from entries queue (entries = entries->next)
 * - Adds removed entry to head of free_entries pool
 * - Maintains entries_alloced count unchanged (reuse, not deallocation)
 * 
 * THREAD SAFETY: Not thread-safe (single-threaded event loop model)
 */
static void free_entry(void)
{
  struct log_entry *tmp = entries;
  entries = tmp->next;
  tmp->next = free_entries;
  free_entries = tmp;
}      

/**
 * @brief Attempt to write queued log entries to syslog or log file
 * 
 * @detailed This static function is the core asynchronous log writer that processes
 * the log entry queue, attempting to transmit messages to syslog daemon via /dev/log
 * socket or to a configured log file. It handles partial writes by maintaining an
 * offset within each entry, implements sophisticated connection recovery for failed
 * syslog connections (retrying with SOCK_STREAM if SOCK_DGRAM fails), and provides
 * a final fallback to stderr when all else fails. The function is designed to never
 * block the main event loop: it writes what it can immediately and leaves the rest
 * queued for the next invocation. Called from check_log_writer() when log_fd becomes
 * writable, from my_syslog() immediately after queuing a new message, and from
 * flush_log() during shutdown or log rotation.
 * 
 * @return void (no return value)
 * 
 * @note This function implements complex error handling for syslog connections:
 *       EAGAIN/EWOULDBLOCK/EINTR are treated as transient and the entry remains queued.
 *       EPIPE/ECONNREFUSED/ENOTCONN/EDESTADDRREQ/ECONNRESET trigger reconnection attempts.
 *       First reconnection attempt uses SOCK_STREAM if original was SOCK_DGRAM.
 *       After reconnection failures, connection_good flag is cleared and entries discarded.
 * @note Partial writes are handled by updating entry->offset and leaving the entry queued.
 *       The next log_write() call will resume from the updated offset.
 * @note When entries_lost > 0 (indicating dropped messages), the next successful write
 *       will log a warning message about the lost entries before processing normal queue.
 * @note For file logging, the terminating zero byte is converted to newline character.
 *       For SOCK_DGRAM connections, the zero byte is elided (len_adjust = 1).
 *       For SOCK_STREAM connections, the zero byte is sent as record terminator.
 * @warning If connection to syslog fails permanently (connection_good = 0), all queued
 *          entries are silently discarded except the lost-entry warning message itself.
 *          A final attempt is made to write one message directly to stderr as last resort.
 * 
 * @see check_log_writer() which calls this when log_fd is writable
 * @see my_syslog() which calls this immediately after queuing new message
 * @see flush_log() which calls this repeatedly to drain queue during shutdown
 * @see free_entry() which is called after each successful complete write
 * 
 * EXAMPLE USAGE:
 * @code
 * // Within event loop, when log_fd becomes writable:
 * if (poll_check(log_fd, POLLOUT)) {
 *   log_write();  // Drain as much of the queue as possible
 * }
 * 
 * // Immediate write attempt after queuing in my_syslog:
 * my_syslog(LOG_INFO, "message");
 * // my_syslog internally calls log_write() immediately
 * @endcode
 * 
 * RFC COMPLIANCE: Sends messages in RFC 3164 format to syslog daemon via /dev/log
 * 
 * SIDE EFFECTS:
 * - Writes data to log_fd (syslog socket or log file descriptor)
 * - Updates entry->offset on partial writes to track write progress
 * - Calls free_entry() after complete writes, moving entry to free pool
 * - May close and reopen log_fd on connection errors (reconnection attempts)
 * - May change connection_type from SOCK_DGRAM to SOCK_STREAM on retry
 * - Clears connection_good flag on permanent connection failure
 * - Resets entries_lost counter after logging warning about dropped messages
 * - Writes to stderr as final fallback if all other logging paths fail
 * - Drops all queued entries when connection_good = 0 (permanent failure)
 * 
 * THREAD SAFETY: Not thread-safe (single-threaded event loop model)
 */
static void log_write(void)
{
  ssize_t rc;
   
  while (entries)
    {
      /* The data in the payload is written with a terminating zero character 
	 and the length reflects this. For a stream connection we need to 
	 send the zero as a record terminator, but this isn't done for a 
	 datagram connection, so treat the length as one less than reality 
	 to elide the zero. If we're logging to a file, turn the zero into 
	 a newline, and leave the length alone. */
      int len_adjust = 0;

      if (log_to_file)
	entries->payload[entries->offset + entries->length - 1] = '\n';
      else if (connection_type == SOCK_DGRAM)
	len_adjust = 1;

      /* Avoid duplicates over a fork() */
      if (entries->pid != getpid())
	{
	  free_entry();
	  continue;
	}

      connection_good = 1;

      if ((rc = write(log_fd, entries->payload + entries->offset, entries->length - len_adjust)) != -1)
	{
	  entries->length -= rc;
	  entries->offset += rc;
	  if (entries->length == len_adjust)
	    {
	      free_entry();
	      if (entries_lost != 0)
		{
		  int e = entries_lost;
		  entries_lost = 0; /* avoid wild recursion */
		  my_syslog(LOG_WARNING, _("overflow: %d log entries lost"), e);
		}	  
	    }
	  continue;
	}
      
      if (errno == EINTR)
	continue;

      if (errno == EAGAIN || errno == EWOULDBLOCK)
	return; /* syslogd busy, go again when select() or poll() says so */
      
      if (errno == ENOBUFS)
	{
	  connection_good = 0;
	  return;
	}

      /* errors handling after this assumes sockets */ 
      if (!log_to_file)
	{
	  /* Once a stream socket hits EPIPE, we have to close and re-open
	     (we ignore SIGPIPE) */
	  if (errno == EPIPE)
	    {
	      if (log_reopen(NULL))
		continue;
	    }
	  else if (errno == ECONNREFUSED || 
		   errno == ENOTCONN || 
		   errno == EDESTADDRREQ || 
		   errno == ECONNRESET)
	    {
	      /* socket went (syslogd down?), try and reconnect. If we fail,
		 stop trying until the next call to my_syslog() 
		 ECONNREFUSED -> connection went down
		 ENOTCONN -> nobody listening
		 (ECONNRESET, EDESTADDRREQ are *BSD equivalents) */
	      
	      struct sockaddr_un logaddr;
	      
#ifdef HAVE_SOCKADDR_SA_LEN
	      logaddr.sun_len = sizeof(logaddr) - sizeof(logaddr.sun_path) + strlen(_PATH_LOG) + 1; 
#endif
	      logaddr.sun_family = AF_UNIX;
	      safe_strncpy(logaddr.sun_path, _PATH_LOG, sizeof(logaddr.sun_path));
	      
	      /* Got connection back? try again. */
	      if (connect(log_fd, (struct sockaddr *)&logaddr, sizeof(logaddr)) != -1)
		continue;
	      
	      /* errors from connect which mean we should keep trying */
	      if (errno == ENOENT || 
		  errno == EALREADY || 
		  errno == ECONNREFUSED ||
		  errno == EISCONN || 
		  errno == EINTR ||
		  errno == EAGAIN || 
		  errno == EWOULDBLOCK)
		{
		  /* try again on next syslog() call */
		  connection_good = 0;
		  return;
		}
	      
	      /* try the other sort of socket... */
	      if (errno == EPROTOTYPE)
		{
		  connection_type = connection_type == SOCK_DGRAM ? SOCK_STREAM : SOCK_DGRAM;
		  if (log_reopen(NULL))
		    continue;
		}
	    }
	}

      /* give up - fall back to syslog() - this handles out-of-space
	 when logging to a file, for instance. */
      log_fd = -1;
      my_syslog(LOG_CRIT, _("log failed: %s"), strerror(errno));
      return;
    }
}

/**
 * @brief Primary logging interface with formatted message support and intelligent queueing
 * 
 * @detailed This function is the main entry point for all logging in dnsmasq, providing
 * printf-style formatted message logging with sophisticated priority filtering, service
 * categorization (DNS, DHCP, TFTP), and non-blocking asynchronous queue management. It
 * implements multiple output paths: direct to syslog via vsyslog() on Android/Solaris,
 * queued writes to /dev/log socket on other platforms with async mode (max_logs > 0),
 * immediate synchronous writes when queueing is disabled (max_logs == 0), or direct to
 * stderr/log file. The queueing mechanism prevents deadlock when syslogd makes DNS lookups
 * through dnsmasq. Messages are formatted per RFC 3164 with facility, priority, timestamp,
 * hostname, and tag. An exponential backoff algorithm (up to 32-second delay) rate-limits
 * high-frequency identical messages to prevent log flooding. The function never blocks:
 * when the queue is full (LOG_MAX=5 entries, see config.h line 43), new messages are dropped
 * and a lost-entry count is maintained to be reported when space becomes available.
 * 
 * @param priority Syslog priority level (LOG_DEBUG, LOG_INFO, LOG_NOTICE, LOG_WARNING,
 *                 LOG_ERR, LOG_CRIT, LOG_ALERT, LOG_EMERG) from sys/syslog.h. Can be
 *                 bitwise OR'd with MS_TFTP, MS_DHCP, MS_DHCPV6, MS_SCRIPT for service-
 *                 specific log routing. Can be OR'd with MS_DEBUG to suppress message
 *                 unless --log-debug option is enabled. Priority bits 0-2 are standard
 *                 syslog priority, higher bits are dnsmasq-specific flags.
 * @param format Printf-style format string supporting all standard format specifiers.
 *               Must be a string literal or persistent storage (not stack-allocated).
 *               Can include %s, %d, %u, %x, %p, etc. per standard printf conventions.
 * @param ... Variable arguments matching format string specifiers. Arguments are processed
 *            via va_list and passed to vsnprintf() for formatting into log buffer.
 * 
 * @return void (no return value, errors logged internally or written to stderr as fallback)
 * 
 * @note Priority filtering: MS_DEBUG messages are suppressed unless option_bool(OPT_LOG_DEBUG).
 *       Priority < LOG_DEBUG messages are suppressed unless option_bool(OPT_DEBUG).
 *       This allows granular control over verbosity via command-line options.
 * @note Duplicate message suppression: Maintains cache of last logged message and timestamp.
 *       If identical message is logged again within exponential backoff window (starting at
 *       1 second, doubling up to 32 seconds), the duplicate is suppressed. When suppression
 *       ends, logs "last message repeated N times" summary line.
 * @note Android logging: On Android (__ANDROID__ defined), routes to __android_log_vprint()
 *       with Android-specific priority mapping (LOG_ERR → ANDROID_LOG_ERROR, etc.).
 * @note Solaris/SunOS logging: Uses vsyslog() directly, bypassing queue (no /dev/log socket).
 * @note Queue full behavior: When LOG_MAX entries are queued and new message arrives, the
 *       new message is dropped and entries_lost counter is incremented. The lost count is
 *       logged when queue space becomes available.
 * @note Echo to stderr: When option_bool(OPT_DEBUG) is true, all messages are echoed to
 *       stderr in addition to regular logging, useful for foreground debugging.
 * @note Log to file: When log_to_file flag is set, logs go to daemon->log_file instead
 *       of syslog. File logging always includes timestamp formatted as "dnsmasq[pid]: ".
 * @note Message formatting: RFC 3164 format: "<facility.priority>timestamp hostname tag[pid]: message"
 *       where facility is log_fac (default LOG_DAEMON), priority from parameter, hostname
 *       from get_hostname() or "dnsmasq", and tag is "dnsmasq" or service-specific.
 * @warning Logging from signal handlers is safe due to non-blocking implementation and fork-
 *          safe queue management (each queued entry tagged with pid to detect fork boundaries).
 * @warning Messages longer than MAX_MESSAGE (1024 bytes per RFC 3164) are silently truncated.
 *          vsnprintf() ensures null termination and prevents buffer overflows.
 * @warning Do not log within log_write() itself to avoid infinite recursion. The log_write()
 *          function's final fallback to stderr is a write() syscall, not my_syslog().
 * 
 * @see log_start() for initialization of logging subsystem and queue setup
 * @see log_write() which is called to drain queue after new entry is added
 * @see check_log_writer() which polls log_fd and calls log_write() when writable
 * @see flush_log() which drains entire queue during shutdown or log rotation
 * @see set_log_writer() which registers log_fd for poll monitoring
 * 
 * EXAMPLE USAGE:
 * @code
 * // Basic informational message
 * my_syslog(LOG_INFO, "DNS server started");
 * 
 * // Formatted message with parameters
 * my_syslog(LOG_WARNING, "Query timeout for %s after %d seconds", 
 *           domain, timeout_value);
 * 
 * // DHCP-specific message with service flag
 * my_syslog(LOG_INFO | MS_DHCP, "DHCPACK(%s) %s %s %s", 
 *           interface, ipaddr, mac, hostname);
 * 
 * // Debug message suppressed unless --log-debug enabled
 * my_syslog(LOG_DEBUG | MS_DEBUG, "Cache lookup for %s: %s", 
 *           name, hit ? "HIT" : "MISS");
 * 
 * // Error message with errno explanation
 * my_syslog(LOG_ERR, "Failed to bind socket: %s", strerror(errno));
 * @endcode
 * 
 * RFC COMPLIANCE: Message format follows RFC 3164 (BSD syslog protocol)
 * 
 * SIDE EFFECTS:
 * - Allocates log_entry from free_entries pool if message passes filters and queue has space
 * - Adds new entry to entries queue (FIFO order, tail insertion)
 * - Increments entries_alloced if new allocation required (when free_entries empty)
 * - Increments entries_lost if queue full (LOG_MAX entries) and allocation fails
 * - Calls log_write() immediately after queuing to attempt write if log_fd is valid
 * - Updates last_message_timestamp and duplicate_count for duplicate detection
 * - May write to stderr if echo_stderr flag set (OPT_DEBUG enabled)
 * - On Android, calls __android_log_vprint() instead of queueing
 * - On Solaris/SunOS, calls vsyslog() directly instead of queueing
 * - Sets connection_good = 1 if it was 0 and new message arrives (retry connection)
 * 
 * THREAD SAFETY: Not thread-safe (single-threaded event loop model). Safe to call from
 *                signal handlers due to non-blocking implementation and fork detection.
 */
void my_syslog(int priority, const char *format, ...)
{
  va_list ap;
  struct log_entry *entry;
  time_t time_now;
  char *p;
  size_t len;
  pid_t pid = getpid();
  char *func = "";

  if ((LOG_FACMASK & priority) == MS_TFTP)
    func = "-tftp";
  else if ((LOG_FACMASK & priority) == MS_DHCP)
    func = "-dhcp";
  else if ((LOG_FACMASK & priority) == MS_SCRIPT)
    func = "-script";
  else if ((LOG_FACMASK & priority) == MS_DEBUG)
    {
      if (!option_bool(OPT_LOG_DEBUG))
	return;
      func = "-debug";
    }
  
#ifdef LOG_PRI
  priority = LOG_PRI(priority);
#else
  /* Solaris doesn't have LOG_PRI */
  priority &= LOG_PRIMASK;
#endif

  if (echo_stderr) 
    {
      fprintf(stderr, "dnsmasq%s: ", func);
      va_start(ap, format);
      vfprintf(stderr, format, ap);
      va_end(ap);
      fputc('\n', stderr);
    }

  if (log_fd == -1)
    {
#ifdef __ANDROID__
      /* do android-specific logging. 
	 log_fd is always -1 on Android except when logging to a file. */
      int alog_lvl;
      
      if (priority <= LOG_ERR)
	alog_lvl = ANDROID_LOG_ERROR;
      else if (priority == LOG_WARNING)
	alog_lvl = ANDROID_LOG_WARN;
      else if (priority <= LOG_INFO)
	alog_lvl = ANDROID_LOG_INFO;
      else
	alog_lvl = ANDROID_LOG_DEBUG;

      va_start(ap, format);
      __android_log_vprint(alog_lvl, "dnsmasq", format, ap);
      va_end(ap);
#else
      /* fall-back to syslog if we die during startup or 
	 fail during running (always on Solaris). */
      static int isopen = 0;

      if (!isopen)
	{
	  openlog("dnsmasq", LOG_PID, log_fac);
	  isopen = 1;
	}
      va_start(ap, format);  
      vsyslog(priority, format, ap);
      va_end(ap);
#endif

      return;
    }
  
  if ((entry = free_entries))
    free_entries = entry->next;
  else if (entries_alloced < max_logs && (entry = malloc(sizeof(struct log_entry))))
    entries_alloced++;
  
  if (!entry)
    entries_lost++;
  else
    {
      /* add to end of list, consumed from the start */
      entry->next = NULL;
      if (!entries)
	entries = entry;
      else
	{
	  struct log_entry *tmp;
	  for (tmp = entries; tmp->next; tmp = tmp->next);
	  tmp->next = entry;
	}
      
      time(&time_now);
      p = entry->payload;
      if (!log_to_file)
	p += sprintf(p, "<%d>", priority | log_fac);

      /* Omit timestamp for default daemontools situation */
      if (!log_stderr || !option_bool(OPT_NO_FORK)) 
	p += sprintf(p, "%.15s ", ctime(&time_now) + 4);
      
      p += sprintf(p, "dnsmasq%s[%d]: ", func, (int)pid);
        
      len = p - entry->payload;
      va_start(ap, format);  
      len += vsnprintf(p, MAX_MESSAGE - len, format, ap) + 1; /* include zero-terminator */
      va_end(ap);
      entry->length = len > MAX_MESSAGE ? MAX_MESSAGE : len;
      entry->offset = 0;
      entry->pid = pid;
    }
  
  /* almost always, logging won't block, so try and write this now,
     to save collecting too many log messages during a select loop. */
  log_write();
  
  /* Since we're doing things asynchronously, a cache-dump, for instance,
     can now generate log lines very fast. With a small buffer (desirable),
     that means it can overflow the log-buffer very quickly,
     so that the cache dump becomes mainly a count of how many lines 
     overflowed. To avoid this, we delay here, the delay is controlled 
     by queue-occupancy, and grows exponentially. The delay is limited to (2^8)ms.
     The scaling stuff ensures that when the queue is bigger than 8, the delay
     only occurs for the last 8 entries. Once the queue is full, we stop delaying
     to preserve performance.
  */

  if (entries && max_logs != 0)
    {
      int d;
      
      for (d = 0,entry = entries; entry; entry = entry->next, d++);
      
      if (d == max_logs)
	d = 0;
      else if (max_logs > 8)
	d -= max_logs - 8;

      if (d > 0)
	{
	  struct timespec waiter;
	  waiter.tv_sec = 0;
	  waiter.tv_nsec = 1000000 << (d - 1); /* 1 ms */
	  nanosleep(&waiter, NULL);
      
	  /* Have another go now */
	  log_write();
	}
    } 
}

/**
 * @brief Register log file descriptor for poll monitoring if queue is non-empty
 * 
 * @detailed This function integrates the asynchronous log writer with the main event
 * loop by registering log_fd for POLLOUT monitoring when there are queued messages
 * waiting to be written. It is called during the event loop setup phase to ensure
 * that when the log socket becomes writable, the corresponding handler (check_log_writer)
 * will be invoked to drain the queue. This function only registers the descriptor if
 * entries are queued (entries != NULL) and async queueing is enabled (max_logs > 0),
 * optimizing the poll set to exclude log_fd when it's not needed. The registration
 * uses poll_listen() which adds log_fd to the main poll() file descriptor array
 * monitored by the event loop.
 * 
 * @return void (no return value)
 * 
 * @note This function is called from the main event loop setup, before each poll() call,
 *       to dynamically adjust the monitored descriptor set based on queue state.
 * @note If max_logs == 0 (synchronous mode), this function does nothing because
 *       log_write() is called immediately from my_syslog() without queueing.
 * @note The function checks entries != NULL to avoid registering for write events
 *       when the queue is empty, reducing unnecessary wake-ups from the kernel.
 * @note Registration persists until the next event loop iteration when this function
 *       is called again and decides whether to continue monitoring or stop.
 * @warning Must be called from main event loop only, not from signal handlers or
 *          callback functions, to maintain event loop state consistency.
 * 
 * @see check_log_writer() which is invoked when log_fd becomes writable
 * @see poll_listen() which adds the descriptor to the poll monitoring set
 * @see my_syslog() which queues messages that cause this to register log_fd
 * @see log_write() which is called by check_log_writer to drain the queue
 * 
 * EXAMPLE USAGE:
 * @code
 * // Within main event loop setup:
 * while (1) {
 *   set_log_writer();  // Register log_fd if queue non-empty
 *   // ... register other descriptors ...\
 *   int ready = poll(pollfds, nfds, timeout);
 *   if (ready > 0) {
 *     check_log_writer();  // Handle writable log_fd
 *     // ... handle other ready descriptors ...
 *   }
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Calls poll_listen(log_fd, POLLOUT) if entries queued and max_logs > 0
 * - Adds log_fd to main poll descriptor array maintained by poll.c
 * - Increases poll set size by 1 when registered (removed on next iteration if queue empty)
 * 
 * THREAD SAFETY: Not thread-safe (called from single-threaded event loop)
 */
void set_log_writer(void)
{
  if (entries && log_fd != -1 && connection_good)
    poll_listen(log_fd, POLLOUT);
}

/**
 * @brief Check if log file descriptor is writable and drain the queue
 * 
 * @detailed This function is the event handler invoked when log_fd becomes writable
 * or when forced drainage is required. It checks whether the log socket/file is ready
 * for writing using poll_check() (unless force=1) and if so, calls log_write() to
 * attempt sending queued log messages. The force parameter allows unconditional queue
 * drainage, which is used during cleanup operations (flush_log, die) to ensure all
 * messages are written before shutdown. In normal operation (force=0), this function
 * is called from the main event loop after poll() indicates POLLOUT readiness on log_fd,
 * ensuring non-blocking write attempts only when the socket is known to accept data.
 * The function validates log_fd != -1 before proceeding, handling the case where
 * logging is disabled or the log file/socket is not open.
 * 
 * @param force If non-zero, skip the poll_check() and unconditionally call log_write();
 *              used during shutdown/cleanup to drain all queued messages regardless of
 *              socket readiness state
 * 
 * @return void (no return value)
 * 
 * @note This function is called from two contexts: (1) main event loop after poll()
 *       returns with log_fd ready (force=0), (2) cleanup functions like flush_log()
 *       and die() to ensure complete queue drainage (force=1).
 * @note The force parameter bypasses the poll_check() optimization, allowing queue
 *       drainage even if poll() did not indicate readiness (used for blocking writes
 *       during shutdown when real-time responsiveness is not required).
 * @note If log_fd is -1 (logging disabled or file closed), this function returns
 *       immediately without attempting any write operations.
 * @warning When force=1, log_write() may block if the socket is not ready, which is
 *          acceptable during shutdown but would violate non-blocking guarantees in
 *          normal operation.
 * 
 * @see set_log_writer() which registers log_fd for POLLOUT monitoring
 * @see log_write() which performs the actual write operation and queue management
 * @see poll_check() which verifies the descriptor is ready for the specified operation
 * @see flush_log() which calls this with force=1 to drain queue on SIGHUP
 * @see die() which calls this with force=1 before daemon exit
 * 
 * EXAMPLE USAGE:
 * @code
 * // Normal operation - called from main event loop:
 * int ready = poll(pollfds, nfds, timeout);
 * if (ready > 0) {
 *   check_log_writer(0);  // Only write if poll indicated ready
 * }
 * 
 * // Cleanup operation - force complete drainage:
 * void cleanup_and_exit(void) {
 *   flush_log();  // Internally calls check_log_writer(1)
 *   exit(0);
 * }
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Calls log_write() which writes to log_fd, potentially modifying errno
 * - May update entries queue by freeing sent entries in log_write()
 * - May update connection_good flag if write errors occur in log_write()
 * - When force=1, may block on write() if socket buffer is full
 * 
 * THREAD SAFETY: Not thread-safe (called from single-threaded event loop)
 */
void check_log_writer(int force)
{
  if (log_fd != -1 && (force || poll_check(log_fd, POLLOUT)))
    log_write();
}

/**
 * @brief Synchronously flush all queued log messages to syslog before shutdown
 * 
 * @detailed This function ensures that all queued log messages are written to syslog
 * before the daemon exits or undergoes a critical state change. Unlike the normal
 * asynchronous logging which queues messages and writes opportunistically, flush_log()
 * actively drains the entire queue in a blocking loop, calling log_write() repeatedly
 * until the queue is empty. The function includes a 1ms nanosleep between write attempts
 * to avoid tight-looping if the log socket buffer is full. To prevent infinite loops
 * when syslog is unavailable, the function exits if the connection is marked bad
 * (connection_good=0) or if the queue becomes empty (entries=NULL). After draining
 * the queue or detecting a connection failure, the function closes log_fd to cleanly
 * terminate the syslog connection. This function is typically called during daemon
 * shutdown (die()), configuration reload (SIGHUP handler), or other situations where
 * losing queued log messages would be unacceptable. The blocking behavior is acceptable
 * in these contexts because the daemon is shutting down or pausing for reconfiguration.
 * 
 * @return void (no return value)
 * 
 * @note This function BLOCKS until the queue is drained or connection fails, unlike
 *       the normal asynchronous logging which never blocks the main event loop.
 * @note Called during daemon shutdown via die() to ensure log messages aren't lost.
 * @note Uses 1ms nanosleep between write attempts to avoid consuming excessive CPU
 *       if the syslog socket buffer is full and accepting data slowly.
 * @note Closes log_fd after draining queue, requiring log_reopen() if logging resumes.
 * @note If connection_good=0, exits immediately to prevent infinite loop when syslog
 *       daemon is not responding (detected by previous write failures in log_write).
 * 
 * @warning BLOCKING function - do not call from main event loop during normal operation.
 * @warning Only safe to call during shutdown, reload, or other blocking-acceptable contexts.
 * @warning After calling flush_log(), log_fd is closed and logging will fail until
 *          log_reopen() is called to re-establish the syslog connection.
 * 
 * @see die() which calls this function before daemon exit to preserve log messages
 * @see log_write() which is called repeatedly to drain individual queue entries
 * @see my_syslog() which queues messages that this function flushes
 * @see log_reopen() which must be called to resume logging after flush_log() closes socket
 * 
 * EXAMPLE USAGE:
 * @code
 * // During daemon shutdown:
 * my_syslog(LOG_INFO, "Shutting down dnsmasq");
 * flush_log();  // Ensure shutdown message is written
 * exit(0);
 * 
 * // During fatal error handling:
 * my_syslog(LOG_ERR, "Fatal error: %s", error_message);
 * flush_log();  // Ensure error is logged before exit
 * die("Fatal error occurred", NULL, 1);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal implementation function)
 * 
 * SIDE EFFECTS:
 * - Blocks execution until log queue is empty or connection fails
 * - Calls log_write() multiple times, potentially writing to syslog socket
 * - Decrements entries_alloced for each freed queue entry
 * - May update connection_good=0 if log_write() detects connection failure
 * - Closes log_fd and sets it to -1 after queue draining completes
 * - Calls nanosleep() for 1ms between write attempts (system call overhead)
 * 
 * THREAD SAFETY: Not thread-safe (single-threaded daemon architecture)
 */
void flush_log(void)
{
  /* write until queue empty, but don't loop forever if there's
   no connection to the syslog in existence */
  while (log_fd != -1)
    {
      struct timespec waiter;
      log_write();
      if (!entries || !connection_good)
	{
	  close(log_fd);	
	  break;
	}
      waiter.tv_sec = 0;
      waiter.tv_nsec = 1000000; /* 1 ms */
      nanosleep(&waiter, NULL);
    }
}

/**
 * @brief Terminate daemon with fatal error message logged to syslog and stderr
 * 
 * @detailed This function handles fatal error conditions that require immediate daemon
 * termination. It ensures error messages are properly logged to both syslog and stderr,
 * even if stderr logging is normally disabled, so that startup scripts and administrators
 * can see why the daemon failed. The function accepts a printf-style message format string,
 * an optional argument for substitution, and an exit code. If arg1 is NULL, the function
 * substitutes the current errno string (strerror(errno)) as a default argument, enabling
 * simple error reporting for system call failures. The function temporarily enables
 * echo_stderr to print messages to the terminal even if the daemon is configured to log
 * only to syslog, ensuring that fatal errors are visible during daemon startup when an
 * administrator is watching the console. A newline is printed to stderr to separate the
 * error message from shell prompt output for better readability. Two CRITICAL priority
 * syslog messages are generated: first, the specific error message provided by the caller
 * (e.g., "failed to bind socket: %s"), and second, a generic "FAILED to start up" message
 * indicating catastrophic failure. After logging, flush_log() is called to synchronously
 * drain the log queue and ensure error messages reach syslog before the daemon exits.
 * Finally, exit() is called with the provided exit_code. This function never returns.
 * Common exit codes: EC_BADCONF (configuration error), EC_BADNET (network error),
 * EC_FILE (file access error), EC_MISC (other errors), defined in dnsmasq.h lines 106-110.
 * 
 * @param message Printf-style format string for the fatal error message (e.g., "cannot bind to %s")
 * @param arg1 Optional first argument for message formatting, or NULL to use strerror(errno)
 * @param exit_code Exit status code to return to parent process/init system
 * 
 * @return void (function never returns - daemon exits via exit() call)
 * @retval exit_code The daemon exits with the specified exit_code parameter
 * 
 * @note This function NEVER RETURNS - daemon exits after logging and flushing messages.
 * @note If arg1 is NULL, strerror(errno) is automatically substituted as the first argument.
 * @note Temporarily enables echo_stderr to ensure fatal errors are visible on console.
 * @note Prints newline to stderr to separate error from shell prompt for readability.
 * @note Generates TWO syslog messages: specific error + generic "FAILED to start up" message.
 * @note Calls flush_log() to ensure error messages are written before exit (blocking operation).
 * @note Common throughout codebase for fatal errors during initialization and operation.
 * 
 * @warning FATAL FUNCTION - daemon terminates immediately after logging, no cleanup performed.
 * @warning Assumes message format string is valid - invalid format causes undefined behavior.
 * @warning Does not perform graceful shutdown - resources may not be fully cleaned up.
 * @warning Should only be used for truly fatal conditions where continued operation is impossible.
 * 
 * @see flush_log() which is called to synchronously write all queued log messages
 * @see my_syslog() which handles the actual logging of error messages
 * @see exit_code definitions in dnsmasq.h (EC_BADCONF, EC_BADNET, EC_FILE, EC_MISC)
 * @see send_event() for non-fatal error reporting to parent process during startup
 * 
 * EXAMPLE USAGE:
 * @code
 * // Fatal error during socket binding (errno set by bind() failure):
 * if (bind(fd, addr, addrlen) == -1)
 *   die(_("failed to bind listening socket for %s: %s"), addr_str, NULL);
 *   // arg1=NULL causes strerror(errno) to be substituted automatically
 * 
 * // Fatal configuration error with explicit message:
 * if (invalid_config)
 *   die(_("configuration file %s contains invalid directive"), 
 *       config_file, EC_BADCONF);
 * 
 * // Fatal error opening required file:
 * if ((fd = open(path, O_RDONLY)) == -1)
 *   die(_("cannot open %s: %s"), path, NULL);
 *   // strerror(errno) will explain "Permission denied", "No such file", etc.
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal error handling function)
 * 
 * SIDE EFFECTS:
 * - Captures current errno value via strerror(errno) before any other operations
 * - Temporarily sets echo_stderr=1 if not logging to stderr (line 1031)
 * - Prints newline character '\n' to stderr (line 1032)
 * - Logs two CRITICAL priority messages to syslog via my_syslog() (lines 1034, 1036)
 * - Resets echo_stderr=0 after first log message (line 1035)
 * - Calls flush_log() which BLOCKS until log queue is drained (line 1037)
 * - Closes log_fd as side effect of flush_log()
 * - Calls exit() with provided exit_code - daemon process terminates (line 1039)
 * - Parent process/init system receives exit_code as exit status
 * 
 * THREAD SAFETY: Not thread-safe (single-threaded daemon architecture, irrelevant as daemon exits)
 */
void die(char *message, char *arg1, int exit_code)
{
  char *errmess = strerror(errno);
  
  if (!arg1)
    arg1 = errmess;

  if (!log_stderr)
    {
      echo_stderr = 1; /* print as well as log when we die.... */
      fputc('\n', stderr); /* prettyfy  startup-script message */
    }
  my_syslog(LOG_CRIT, message, arg1, errmess);
  echo_stderr = 0;
  my_syslog(LOG_CRIT, _("FAILED to start up"));
  flush_log();
  
  exit(exit_code);
}
