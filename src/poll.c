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
 * @file poll.c
 * @brief Poll-based I/O multiplexing event loop infrastructure for dnsmasq
 * 
 * DETAILED PURPOSE:
 * This module provides the core event-driven I/O multiplexing mechanism that enables dnsmasq's
 * single-threaded architecture to efficiently monitor and respond to events on dozens of file
 * descriptors simultaneously without blocking. The implementation wraps the POSIX poll() system
 * call with a managed container of struct pollfd entries, maintaining them in sorted order by
 * file descriptor for efficient binary search operations.
 * 
 * The poll-based approach is fundamental to dnsmasq's architecture, allowing the main event loop
 * to monitor multiple socket types concurrently:
 * - DNS query sockets (UDP port 53, TCP port 53)
 * - DHCP sockets (UDP port 67 for DHCPv4, UDP port 547 for DHCPv6)
 * - TFTP sockets (UDP port 69)
 * - Linux netlink sockets (for interface monitoring)
 * - D-Bus connections (for control interface)
 * - UBus connections (for OpenWrt integration)
 * - Signal handling pipes (for async event notifications)
 * 
 * KEY RESPONSIBILITIES:
 * - poll_reset(): Reset the pollfd array to empty state at the start of each event loop iteration
 * - poll_listen(): Register a file descriptor for monitoring with specified event mask (POLLIN, POLLOUT, POLLERR)
 * - do_poll(): Execute the poll() system call with the current pollfd array and timeout
 * - poll_check(): Check if a specific file descriptor has pending events after poll() returns
 * - fd_search(): Binary search helper to locate file descriptors in the sorted array
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (for global definitions, whine_realloc utility)
 * Called by: Main event loop in dnsmasq.c
 * Calls: poll() system call, whine_realloc() for dynamic array management, memmove() for array insertion
 * 
 * DATA STRUCTURES:
 * - struct pollfd *pollfds: Dynamically sized array of pollfd structures, kept in file descriptor order
 * - nfds_t nfds: Current number of active file descriptors being monitored
 * - nfds_t arrsize: Allocated capacity of the pollfds array
 * 
 * The pollfd array is maintained in sorted order by file descriptor value to enable O(log n) binary
 * search operations. When a new file descriptor is registered, it is inserted at the appropriate
 * position to maintain sort order, with existing entries shifted as needed.
 * 
 * COMPILE-TIME OPTIONS:
 * None - this is core functionality always enabled in dnsmasq builds.
 * 
 * THREADING/CONCURRENCY:
 * This module operates within dnsmasq's single-threaded event-driven architecture. The pollfd array
 * is rebuilt from scratch at the start of each event loop iteration (via poll_reset()), then populated
 * with active file descriptors (via poll_listen() calls), polled for events (via do_poll()), and
 * finally queried for specific events (via poll_check() calls). This pattern ensures thread-safe
 * operation without locking, as all operations occur sequentially within the single event loop thread.
 * 
 * PERFORMANCE CHARACTERISTICS:
 * - poll_reset(): O(1) - simply resets counter to zero
 * - poll_listen(): O(log n + m) - binary search is O(log n), array insertion is O(m) where m is entries shifted
 * - do_poll(): O(n) - kernel must scan all n file descriptors for events
 * - poll_check(): O(log n) - binary search to locate file descriptor
 * - Memory consumption: Grows dynamically, starting at 64 entries and doubling when capacity exceeded
 * 
 * SCALABILITY LIMITS:
 * The poll() system call scales to hundreds of file descriptors but becomes less efficient than
 * epoll/kqueue for thousands of concurrent connections. For typical dnsmasq deployments (small networks
 * with 100-250 clients), the number of monitored file descriptors rarely exceeds 50-100, making poll()
 * an appropriate and portable choice.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

/* Wrapper for poll(). Allocates and extends array of struct pollfds,
   keeps them in fd order so that we can set and test conditions on
   fd using a simple but efficient binary chop. */

/* poll_reset()
   poll_listen(fd, event)
   .
   .
   poll_listen(fd, event);

   hits = do_poll(timeout);

   if (poll_check(fd, event)
    .
    .

   if (poll_check(fd, event)
    .
    .

    event is OR of POLLIN, POLLOUT, POLLERR, etc
*/

static struct pollfd *pollfds = NULL;
static nfds_t nfds, arrsize = 0;

/**
 * @brief Perform binary search to locate a file descriptor in the sorted pollfd array
 * 
 * @detailed This function implements a binary search algorithm to locate a file descriptor within
 * the sorted pollfds array. The array is maintained in ascending order by file descriptor value,
 * enabling efficient O(log n) lookups. The function serves dual purposes:
 * 
 * 1. **Exact match**: If the file descriptor exists in the array, returns its index
 * 2. **Insertion point**: If the file descriptor does not exist, returns the index where it should
 *    be inserted to maintain sort order
 * 
 * The algorithm uses the standard binary search approach with left and right pointers that converge
 * until they are adjacent (right == left + 1), at which point the correct position has been found.
 * 
 * This function is called by both poll_listen() (to register/update file descriptors) and poll_check()
 * (to query event status after poll() returns).
 * 
 * @param fd The file descriptor to search for in the pollfds array
 * 
 * @return Index into the pollfds array with the following semantics:
 * @retval [0..nfds-1] If pollfds[index].fd == fd, exact match found at this index
 * @retval [0..nfds] If pollfds[index].fd != fd, this is the insertion point (entries at this index
 *                   and beyond should be shifted right to insert the new fd)
 * @retval nfds If the file descriptor should be appended to the end of the array
 * 
 * @note If the array is empty (nfds == 0), immediately returns 0
 * @note The returned index always satisfies: pollfds[index-1].fd < fd <= pollfds[index].fd (when valid)
 * 
 * @see poll_listen() in poll.c for usage in file descriptor registration
 * @see poll_check() in poll.c for usage in event status queries
 * 
 * EXAMPLE USAGE:
 * @code
 * // Search for fd 10 in an array containing [5, 8, 12, 15]
 * nfds_t idx = fd_search(10);
 * // Returns index 2 (insertion point between 8 and 12)
 * // pollfds[idx].fd would be 12
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility function)
 * SIDE EFFECTS: None - read-only operation on pollfds array
 * THREAD SAFETY: Safe within single-threaded event loop architecture
 */
static nfds_t fd_search(int fd)
{
  nfds_t left, right, mid;
  
  if ((right = nfds) == 0)
    return 0;
  
  left = 0;
  
  while (1)
    {
      if (right == left + 1)
	return (pollfds[left].fd >= fd) ? left : right;
      
      mid = (left + right)/2;
      
      if (pollfds[mid].fd > fd)
	right = mid;
      else 
	left = mid;
    }
}

/**
 * @brief Reset the pollfd array to empty state at the start of each event loop iteration
 * 
 * @detailed This function resets the pollfd array to empty by setting the active count (nfds) to zero.
 * It is called at the beginning of each iteration of the main event loop in dnsmasq.c, before the
 * loop populates the array with file descriptors that should be monitored for the current iteration.
 * 
 * The function does NOT deallocate the underlying pollfds array memory - it simply marks all entries
 * as inactive by resetting the count to zero. This approach avoids repeated allocation/deallocation
 * overhead across event loop iterations. The allocated array capacity (arrsize) remains unchanged
 * and is reused in subsequent iterations.
 * 
 * This design pattern allows dnsmasq to rebuild the set of monitored file descriptors from scratch
 * on each event loop iteration, accommodating dynamic changes such as:
 * - New listening sockets created when network interfaces come up
 * - TCP connections accepted and later closed
 * - Control interface connections established and terminated
 * - Conditional monitoring based on operational state (e.g., DHCP disabled temporarily)
 * 
 * @return void
 * 
 * @note This function must be called before any poll_listen() calls in each event loop iteration
 * @warning Calling do_poll() after poll_reset() but before poll_listen() will poll zero file descriptors
 * 
 * @see poll_listen() in poll.c for registering file descriptors after reset
 * @see dnsmasq.c main event loop for typical usage pattern
 * 
 * EXAMPLE USAGE:
 * @code
 * // Typical event loop iteration in dnsmasq.c
 * poll_reset();
 * poll_listen(dnsfd, POLLIN);
 * poll_listen(dhcpfd, POLLIN);
 * poll_listen(netlinkfd, POLLIN);
 * int ready = do_poll(timeout_ms);
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal infrastructure function)
 * SIDE EFFECTS: Resets global nfds counter to zero, marking all pollfd entries as inactive
 * THREAD SAFETY: Safe within single-threaded event loop architecture
 */
void poll_reset(void)
{
  nfds = 0;
}

/**
 * @brief Execute the poll() system call to wait for events on registered file descriptors
 * 
 * @detailed This function wraps the POSIX poll() system call, blocking until one or more registered
 * file descriptors become ready for I/O operations, or until the timeout expires. It is the core
 * blocking point in dnsmasq's event loop where the daemon waits for incoming network traffic,
 * control interface commands, or timeout-based periodic tasks.
 * 
 * The poll() system call monitors all file descriptors registered via poll_listen() calls, checking
 * for the requested events (POLLIN for readable data, POLLOUT for writable buffer space, POLLERR
 * for error conditions). When one or more file descriptors become ready, or when the timeout expires,
 * poll() returns and the event loop processes the ready file descriptors by calling poll_check()
 * for each monitored descriptor.
 * 
 * The timeout parameter controls the maximum blocking duration:
 * - Positive value: Maximum milliseconds to wait before returning (enables periodic tasks)
 * - Zero: Non-blocking poll (returns immediately with current status)
 * - Negative value (-1): Infinite wait (blocks until at least one event occurs)
 * 
 * In dnsmasq's typical operation, the timeout is calculated based on the earliest scheduled task:
 * - DHCP lease expiration checks
 * - DNS cache entry expiration
 * - TCP connection timeouts
 * - Router Advertisement transmission intervals
 * - Script execution completion monitoring
 * 
 * @param timeout Maximum time to wait in milliseconds (-1 for infinite, 0 for non-blocking, >0 for timed wait)
 * 
 * @return Number of file descriptors with events ready, or status code
 * @retval >0 Number of file descriptors that have events ready (successful poll with events)
 * @retval 0 Timeout expired with no file descriptors ready (timeout occurred)
 * @retval -1 Error occurred (check errno for details: EINTR for signal interruption, ENOMEM for allocation failure)
 * 
 * @note Return value -1 with errno==EINTR is common when signals arrive during poll() and should be handled gracefully
 * @warning Very large timeout values (>INT_MAX milliseconds) may cause integer overflow on some platforms
 * 
 * @see poll_check() in poll.c for querying which file descriptors have events after this returns
 * @see poll_listen() in poll.c for registering file descriptors before calling this function
 * @see poll(2) man page for detailed POSIX poll() semantics and error conditions
 * 
 * EXAMPLE USAGE:
 * @code
 * // Main event loop pattern
 * poll_reset();
 * poll_listen(dnsfd, POLLIN);
 * poll_listen(dhcpfd, POLLIN);
 * 
 * int ready = do_poll(1000); // Wait up to 1 second
 * if (ready > 0) {
 *   if (poll_check(dnsfd, POLLIN))
 *     handle_dns_query();
 *   if (poll_check(dhcpfd, POLLIN))
 *     handle_dhcp_request();
 * } else if (ready == 0) {
 *   // Timeout - perform periodic maintenance
 *   check_lease_expiration();
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (wraps POSIX poll() system call)
 * SIDE EFFECTS: Blocks execution until events occur or timeout expires; updates revents field in pollfd array
 * THREAD SAFETY: Safe within single-threaded event loop architecture; poll() is thread-safe per POSIX
 */
int do_poll(int timeout)
{
  return poll(pollfds, nfds, timeout);
}

/**
 * @brief Check if a specific file descriptor has pending events after poll() returns
 * 
 * @detailed This function checks whether a specific file descriptor has any of the requested events
 * ready after do_poll() has returned. It uses binary search (via fd_search()) to efficiently locate
 * the file descriptor in the sorted pollfds array, then performs a bitwise AND between the returned
 * events (revents field) and the requested event mask to determine if the descriptor is ready.
 * 
 * This function is typically called repeatedly in the event loop after do_poll() returns with a
 * positive value, checking each monitored file descriptor to determine which ones have pending
 * events that need processing. The event parameter allows selective checking - for example,
 * checking only for POLLIN (readable data) even if the descriptor might also have POLLOUT or
 * POLLERR set.
 * 
 * The function handles the case where a file descriptor is not found in the array (returns 0),
 * which can occur if poll_check() is called for a descriptor that was never registered via
 * poll_listen(), or if the index returned by fd_search() points to a different descriptor.
 * 
 * Common event flags checked:
 * - POLLIN: Data available for reading (most common for server sockets)
 * - POLLOUT: Buffer space available for writing (useful for non-blocking sends)
 * - POLLERR: Error condition occurred on the descriptor
 * - POLLHUP: Peer closed connection (for TCP sockets)
 * - POLLPRI: Out-of-band data available (rarely used in dnsmasq)
 * 
 * @param fd The file descriptor to check for pending events
 * @param event Event mask specifying which events to check (bitwise OR of POLLIN, POLLOUT, POLLERR, POLLHUP, etc.)
 * 
 * @return Non-zero if the specified events are ready, zero otherwise
 * @retval >0 Bitwise AND of revents and event (indicates which of the requested events are ready)
 * @retval 0 No requested events are ready, or file descriptor not found in pollfds array
 * 
 * @note Should only be called after do_poll() returns a positive value indicating ready descriptors
 * @note Return value may contain multiple event bits if more than one requested event is ready
 * @warning Checking events for a file descriptor not registered via poll_listen() returns 0 without error
 * 
 * @see do_poll() in poll.c which must be called before this function to update revents
 * @see poll_listen() in poll.c for registering file descriptors to monitor
 * @see fd_search() in poll.c for the binary search implementation used to locate the descriptor
 * 
 * EXAMPLE USAGE:
 * @code
 * // After do_poll() returns indicating ready descriptors
 * if (poll_check(dnsfd, POLLIN)) {
 *   // DNS query data is ready to read
 *   struct dns_header *header;
 *   int len = recv_dns_query(dnsfd, &header);
 *   process_dns_query(header, len);
 * }
 * 
 * if (poll_check(tcpfd, POLLOUT)) {
 *   // TCP socket ready for writing
 *   send_tcp_response(tcpfd);
 * }
 * 
 * if (poll_check(tcpfd, POLLERR | POLLHUP)) {
 *   // Error or peer disconnect on TCP connection
 *   close_tcp_connection(tcpfd);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal utility function wrapping poll() result query)
 * SIDE EFFECTS: None - read-only operation on pollfds array
 * THREAD SAFETY: Safe within single-threaded event loop architecture
 */
int poll_check(int fd, short event)
{
  nfds_t i = fd_search(fd);
  
  if (i < nfds && pollfds[i].fd == fd)
    return pollfds[i].revents & event;

  return 0;
}

/**
 * @brief Register a file descriptor for event monitoring with specified event mask
 * 
 * @detailed This function registers a file descriptor to be monitored by the next do_poll() call,
 * specifying which events should trigger a notification. If the file descriptor is already registered,
 * the new event mask is ORed with the existing mask, allowing multiple event types to be monitored
 * simultaneously (e.g., both POLLIN and POLLOUT).
 * 
 * The function maintains the pollfds array in sorted order by file descriptor value, enabling
 * efficient binary search operations in poll_check(). When a new file descriptor is registered,
 * it is inserted at the appropriate position (determined by fd_search()), with existing entries
 * shifted right using memmove() to maintain sort order.
 * 
 * The pollfds array is dynamically sized and automatically expanded when capacity is reached:
 * - Initial capacity: 64 entries (first allocation)
 * - Growth strategy: Double the capacity when full (64 -> 128 -> 256 -> ...)
 * - Allocation: Uses whine_realloc() which logs allocation failures and returns NULL on error
 * - Failure handling: If allocation fails, the function returns silently without registering the fd
 * 
 * This function is called repeatedly during each event loop iteration to build the set of file
 * descriptors that should be monitored for the current iteration. Typical usage involves calling
 * poll_reset() first, then multiple poll_listen() calls for each active descriptor, followed by
 * do_poll() to wait for events.
 * 
 * Common event flags registered:
 * - POLLIN: Monitor for data available to read (most common for listening sockets)
 * - POLLOUT: Monitor for buffer space available to write (for non-blocking sends)
 * - POLLERR: Automatically monitored by poll() regardless of mask (error conditions)
 * - POLLHUP: Automatically monitored by poll() regardless of mask (peer disconnect)
 * 
 * Performance characteristics:
 * - If fd already exists: O(log n) binary search + O(1) event mask update
 * - If fd is new: O(log n) search + O(m) insertion where m is number of entries shifted
 * - Array expansion (rare): O(n) realloc + copy, amortized to O(1) with doubling strategy
 * 
 * @param fd The file descriptor to register for monitoring (must be a valid open file descriptor)
 * @param event Event mask specifying which events to monitor (bitwise OR of POLLIN, POLLOUT, etc.)
 * 
 * @return void
 * 
 * @note If the file descriptor is already registered, the event mask is ORed with existing events
 * @note If memory allocation fails during array expansion, the file descriptor is not registered
 * @note Event flags POLLERR and POLLHUP are always monitored by poll() regardless of the event mask
 * @warning Registering an invalid or closed file descriptor will not be detected until poll() is called
 * @warning If whine_realloc() fails (out of memory), the fd is silently not registered
 * 
 * @see poll_reset() in poll.c which should be called before poll_listen() calls each iteration
 * @see do_poll() in poll.c which uses the registered file descriptors to wait for events
 * @see poll_check() in poll.c for checking which registered fds have events ready
 * @see fd_search() in poll.c for the binary search used to locate insertion point
 * @see whine_realloc() in util.c for the memory allocation function used for array expansion
 * 
 * EXAMPLE USAGE:
 * @code
 * // Typical event loop iteration registering multiple file descriptors
 * poll_reset();
 * 
 * // Register DNS listening socket for incoming queries
 * poll_listen(dnsfd_udp, POLLIN);
 * 
 * // Register DHCP socket for DHCP requests
 * poll_listen(dhcpfd, POLLIN);
 * 
 * // Register TCP listener for incoming connections
 * poll_listen(tcpfd_listener, POLLIN);
 * 
 * // Register active TCP connection for both read and write
 * poll_listen(active_tcp_conn, POLLIN | POLLOUT);
 * 
 * // Register netlink socket for interface changes (Linux)
 * poll_listen(netlinkfd, POLLIN);
 * 
 * // Register D-Bus connection for control interface
 * if (daemon->dbus)
 *   poll_listen(daemon->dbus->watch_fd, POLLIN);
 * 
 * // Now wait for events
 * int ready = do_poll(calculate_timeout());
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal infrastructure function)
 * SIDE EFFECTS: 
 * - Modifies global pollfds array (may reallocate and move in memory)
 * - Increments global nfds counter if new fd registered
 * - May allocate memory via whine_realloc() if array expansion needed
 * - Shifts existing array entries via memmove() when inserting new fd
 * THREAD SAFETY: Safe within single-threaded event loop architecture; not thread-safe if called concurrently
 */
void poll_listen(int fd, short event)
{
   nfds_t i = fd_search(fd);
  
   if (i < nfds && pollfds[i].fd == fd)
     pollfds[i].events |= event;
   else
     {
       if (arrsize == nfds)
	 {
	   /* Array too small. Extend. */
	   struct pollfd *new;

	   arrsize = (arrsize == 0) ? 64 : arrsize * 2;

	   if (!(new = whine_realloc(pollfds, arrsize * sizeof(struct pollfd))))
	     return;

	   pollfds = new;
	 }

       memmove(&pollfds[i+1], &pollfds[i], (nfds - i) * sizeof(struct pollfd));

       pollfds[i].fd = fd;
       pollfds[i].events = event;
       nfds++;
     }
}
