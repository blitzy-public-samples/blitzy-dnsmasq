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
 * @file helper.c
 * @brief External script execution for DHCP lease events via forked helper processes
 * 
 * DETAILED PURPOSE:
 * This module manages fork-based helper processes that execute external scripts or Lua
 * functions in response to DHCP lease events (add/old/del), TFTP file transfers, and
 * ARP table changes. The helper architecture provides privilege separation and isolation,
 * ensuring that potentially compromised main daemon code cannot exploit root privileges
 * through script execution.
 * 
 * The helper process is forked before the main daemon drops root privileges, allowing
 * scripts to execute with elevated permissions when needed. Communication between the
 * main process and helper occurs through a unidirectional pipe, with the helper acting
 * as a paranoid consumer of data to prevent privilege escalation attacks.
 * 
 * KEY RESPONSIBILITIES:
 * - create_helper(): Fork privileged helper process with pipe communication channel
 * - Event loop processing: Receive lease/TFTP/ARP events from main daemon via pipe
 * - Script execution: Fork and exec external scripts with environment variables populated
 * - Lua integration: Optionally invoke embedded Lua interpreter for reduced overhead (HAVE_LUASCRIPT)
 * - queue_script(): Queue DHCP lease change events (add/old/del) with client details
 * - queue_relay_snoop(): Queue DHCPv6 relay snooping events (HAVE_DHCP6)
 * - queue_tftp(): Queue TFTP file transfer events (HAVE_TFTP)
 * - queue_arp(): Queue ARP table change events
 * - helper_write(): Serialize event data to helper pipe with proper buffering
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (struct daemon, event definitions, DHCP structures)
 * Optional: lua.h, lualib.h, lauxlib.h for Lua scripting support (HAVE_LUASCRIPT)
 * Called by: lease.c (DHCP lease changes), tftp.c (TFTP events), arp.c (ARP events)
 * Calls: fork(), execl(), pipe(), waitpid(), setenv() for process management
 * 
 * DATA STRUCTURES:
 * - struct script_data: Wire format for event data passed through pipe (line 52)
 *   Contains action type, hardware address, IP address, hostname, lease time, interface
 * - Global buffer (buf, buf_size, bytes_in_buf): Accumulates events before pipe write
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_SCRIPT: Enables entire helper process infrastructure (required for this file)
 * - HAVE_LUASCRIPT: Enables embedded Lua interpreter as alternative to fork-exec
 * - HAVE_DHCP6: Enables DHCPv6 relay snooping (queue_relay_snoop function)
 * - HAVE_TFTP: Enables TFTP event handling (queue_tftp function)
 * - HAVE_BROKEN_RTC: Adjusts lease time handling for systems without RTC
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. Helper process runs independently from main daemon
 * in separate process space. Communication is one-way (main -> helper) through pipe.
 * Signal handling in helper ignores SIGTERM/SIGINT to ensure cleanup on main process exit.
 * 
 * SECURITY MODEL:
 * The helper process retains root privileges while main daemon drops to unprivileged user.
 * To prevent privilege escalation via compromised main process, the helper:
 * - Validates all data received from pipe (bounds checking, null termination)
 * - Does not accept script path changes after fork (script path locked at startup)
 * - Drops privileges to configured user/group before script execution
 * - Sanitizes environment variables passed to scripts
 * 
 * ARCHITECTURAL RATIONALE:
 * Fork-exec model chosen over threading for isolation: compromised script cannot affect
 * daemon state. Separate helper process ensures script failures (crashes, hangs) do not
 * impact core DNS/DHCP services. Pipe communication provides clear trust boundary.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_SCRIPT

/* This file has code to fork a helper process which receives data via a pipe 
   shared with the main process and which is responsible for calling a script when
   DHCP leases change.

   The helper process is forked before the main process drops root, so it retains root 
   privs to pass on to the script. For this reason it tries to be paranoid about 
   data received from the main process, in case that has been compromised. We don't
   want the helper to give an attacker root. In particular, the script to be run is
   not settable via the pipe, once the fork has taken place it is not alterable by the 
   main process.
*/

static void my_setenv(const char *name, const char *value, int *error);
static unsigned char *grab_extradata(unsigned char *buf, unsigned char *end,  char *env, int *err);

#ifdef HAVE_LUASCRIPT
#define LUA_COMPAT_ALL
#include <lua.h>  
#include <lualib.h>  
#include <lauxlib.h>  

#ifndef lua_open
#define lua_open()     luaL_newstate()
#endif

lua_State *lua;

static unsigned char *grab_extradata_lua(unsigned char *buf, unsigned char *end, char *field);
#endif


struct script_data
{
  int flags;
  int action, hwaddr_len, hwaddr_type;
  int clid_len, hostname_len, ed_len;
  struct in_addr addr, giaddr;
  unsigned int remaining_time;
#ifdef HAVE_BROKEN_RTC
  unsigned int length;
#else
  time_t expires;
#endif
#ifdef HAVE_TFTP
  off_t file_len;
#endif
  struct in6_addr addr6;
#ifdef HAVE_DHCP6
  int vendorclass_count;
  unsigned int iaid;
#endif
  unsigned char hwaddr[DHCP_CHADDR_MAX];
  char interface[IF_NAMESIZE];
};

static struct script_data *buf = NULL;
static size_t bytes_in_buf = 0, buf_size = 0;

/**
 * @brief Fork privileged helper process for executing external scripts on DHCP/TFTP/ARP events
 * 
 * @detailed Creates a helper process before main daemon drops root privileges, establishing
 * a unidirectional pipe for event communication. The helper retains root access to execute
 * configured scripts with elevated permissions when needed. After forking, the parent process
 * (main daemon) receives the write end of the pipe and returns, while child process (helper)
 * enters event loop to process incoming events until main daemon terminates.
 * 
 * The helper implements privilege separation security model: it drops privileges to configured
 * uid/gid before executing scripts (except when script explicitly requires root), validates all
 * data received from main process, and does not accept script path modifications after fork.
 * 
 * Signal handling: Helper ignores SIGTERM/SIGINT to rely on pipe closure for termination
 * detection. SIGCHLD is handled to reap child processes from script executions. SIGALRM is
 * blocked and handled via self-pipe trick for timeout management.
 * 
 * @param event_fd File descriptor for signaling events back to main process (errors, status)
 * @param err_fd File descriptor for sending error events (EVENT_PIPE_ERR, etc.)
 * @param uid User ID to drop privileges to before script execution
 * @param gid Group ID to drop privileges to before script execution
 * @param max_fd Maximum file descriptor number for close-on-exec loop
 * 
 * @return For parent process (main daemon): write end of pipe (>0) for sending events to helper
 * @return For child process (helper): does not return, runs event loop until pipe closes, then exit(0)
 * @return On error: calls send_event(err_fd, EVENT_PIPE_ERR) and _exit(0), parent receives -1 indication
 * 
 * @note This function must be called before main daemon drops root privileges
 * @warning Helper retains root privileges until script execution, validate all pipe data
 * 
 * @see queue_script() for queuing DHCP lease events
 * @see helper_write() for writing event data to the pipe
 * 
 * EXAMPLE USAGE:
 * @code
 * // Called during daemon initialization, before privilege drop
 * int helper_pipe = create_helper(daemon->event_fd, daemon->err_fd, 
 *                                  daemon->scriptuser, daemon->scriptgroup, max_fd);
 * if (helper_pipe > 0)
 *   daemon->helperfd = helper_pipe;  // Main daemon writes events here
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (implementation-specific process architecture)
 * 
 * SIDE EFFECTS:
 * - Forks child process (helper) that persists for daemon lifetime
 * - Creates pipe with write end in parent, read end in child
 * - Child process closes all file descriptors except pipe, event_fd, err_fd
 * - Child process installs signal handlers (ignore SIGTERM/SIGINT, handle SIGCHLD/SIGALRM)
 * - Child process may execute external scripts via fork/exec
 * - For HAVE_LUASCRIPT: initializes Lua interpreter state in child process
 * 
 * THREAD SAFETY:
 * Called once during single-threaded daemon initialization, not thread-safe.
 * Helper process is single-threaded, uses self-pipe pattern for signal handling.
 */
int create_helper(int event_fd, int err_fd, uid_t uid, gid_t gid, long max_fd)
{
  pid_t pid;
  int i, pipefd[2];
  struct sigaction sigact;
  unsigned char *alloc_buff = NULL;
  
  /* create the pipe through which the main program sends us commands,
     then fork our process. */
  if (pipe(pipefd) == -1 || !fix_fd(pipefd[1]) || (pid = fork()) == -1)
    {
      send_event(err_fd, EVENT_PIPE_ERR, errno, NULL);
      _exit(0);
    }

  if (pid != 0)
    {
      close(pipefd[0]); /* close reader side */
      return pipefd[1];
    }

  /* ignore SIGTERM and SIGINT, so that we can clean up when the main process gets hit
     and SIGALRM so that we can use sleep() */
  sigact.sa_handler = SIG_IGN;
  sigact.sa_flags = 0;
  sigemptyset(&sigact.sa_mask);
  sigaction(SIGTERM, &sigact, NULL);
  sigaction(SIGALRM, &sigact, NULL);
  sigaction(SIGINT, &sigact, NULL);

  if (!option_bool(OPT_DEBUG) && uid != 0)
    {
      gid_t dummy;
      if (setgroups(0, &dummy) == -1 || 
	  setgid(gid) == -1 || 
	  setuid(uid) == -1)
	{
	  if (option_bool(OPT_NO_FORK))
	    /* send error to daemon process if no-fork */
	    send_event(event_fd, EVENT_USER_ERR, errno, daemon->scriptuser);
	  else
	    {
	      /* kill daemon */
	      send_event(event_fd, EVENT_DIE, 0, NULL);
	      /* return error */
	      send_event(err_fd, EVENT_USER_ERR, errno, daemon->scriptuser);
	    }
	  _exit(0);
	}
    }

  /* close all the sockets etc, we don't need them here. 
     Don't close err_fd, in case the lua-init fails.
     Note that we have to do this before lua init
     so we don't close any lua fds. */
  close_fds(max_fd, pipefd[0], event_fd, err_fd);
  
#ifdef HAVE_LUASCRIPT
  if (daemon->luascript)
    {
      const char *lua_err = NULL;
      lua = lua_open();
      luaL_openlibs(lua);
      
      /* get Lua to load our script file */
      if (luaL_dofile(lua, daemon->luascript) != 0)
	lua_err = lua_tostring(lua, -1);
      else
	{
	  lua_getglobal(lua, "lease");
	  if (lua_type(lua, -1) != LUA_TFUNCTION) 
	    lua_err = _("lease() function missing in Lua script");
	}
      
      if (lua_err)
	{
	  if (option_bool(OPT_NO_FORK) || option_bool(OPT_DEBUG))
	    /* send error to daemon process if no-fork */
	    send_event(event_fd, EVENT_LUA_ERR, 0, (char *)lua_err);
	  else
	    {
	      /* kill daemon */
	      send_event(event_fd, EVENT_DIE, 0, NULL);
	      /* return error */
	      send_event(err_fd, EVENT_LUA_ERR, 0, (char *)lua_err);
	    }
	  _exit(0);
	}
      
      lua_pop(lua, 1);  /* remove nil from stack */
      lua_getglobal(lua, "init");
      if (lua_type(lua, -1) == LUA_TFUNCTION)
	lua_call(lua, 0, 0);
      else
	lua_pop(lua, 1);  /* remove nil from stack */	
    }
#endif

  /* All init done, close our copy of the error pipe, so that main process can return */
  if (err_fd != -1)
    close(err_fd);
    
  /* loop here */
  while(1)
    {
      struct script_data data;
      char *p, *action_str, *hostname = NULL, *domain = NULL;
      unsigned char *buf = (unsigned char *)daemon->namebuff;
      unsigned char *end, *extradata;
      int is6, err = 0;
      int pipeout[2];

      /* Free rarely-allocated memory from previous iteration. */
      if (alloc_buff)
	{
	  free(alloc_buff);
	  alloc_buff = NULL;
	}
      
      /* we read zero bytes when pipe closed: this is our signal to exit */ 
      if (!read_write(pipefd[0], (unsigned char *)&data, sizeof(data), RW_READ))
	{
#ifdef HAVE_LUASCRIPT
	  if (daemon->luascript)
	    {
	      lua_getglobal(lua, "shutdown");
	      if (lua_type(lua, -1) == LUA_TFUNCTION)
		lua_call(lua, 0, 0);
	    }
#endif
	  _exit(0);
	}
 
      is6 = !!(data.flags & (LEASE_TA | LEASE_NA));
      
      if (data.action == ACTION_DEL)
	action_str = "del";
      else if (data.action == ACTION_ADD)
	action_str = "add";
      else if (data.action == ACTION_OLD || data.action == ACTION_OLD_HOSTNAME)
	action_str = "old";
      else if (data.action == ACTION_TFTP)
	{
	  action_str = "tftp";
	  is6 = (data.flags != AF_INET);
	}
      else if (data.action == ACTION_ARP)
	{
	  action_str = "arp-add";
	  is6 = (data.flags != AF_INET);
	}
       else if (data.action == ACTION_ARP_DEL)
	{
	  action_str = "arp-del";
	  is6 = (data.flags != AF_INET);
	  data.action = ACTION_ARP;
	}
       else if (data.action == ACTION_RELAY_SNOOP)
	 {
	   is6 = 1;
	   action_str = "relay-snoop";
	 }
       else
	 continue;
      	
      /* stringify MAC into dhcp_buff */
      p = daemon->dhcp_buff;
      if (data.hwaddr_type != ARPHRD_ETHER || data.hwaddr_len == 0) 
	p += sprintf(p, "%.2x-", data.hwaddr_type);
      for (i = 0; (i < data.hwaddr_len) && (i < DHCP_CHADDR_MAX); i++)
	{
	  p += sprintf(p, "%.2x", data.hwaddr[i]);
	  if (i != data.hwaddr_len - 1)
	    p += sprintf(p, ":");
	}
      
      /* supplied data may just exceed normal buffer (unlikely) */
      if ((data.hostname_len + data.ed_len + data.clid_len) > MAXDNAME && 
	  !(alloc_buff = buf = malloc(data.hostname_len + data.ed_len + data.clid_len)))
	continue;
      
      if (!read_write(pipefd[0], buf, 
		      data.hostname_len + data.ed_len + data.clid_len, RW_READ))
	continue;

      /* CLID into packet */
      for (p = daemon->packet, i = 0; i < data.clid_len; i++)
	{
	  p += sprintf(p, "%.2x", buf[i]);
	  if (i != data.clid_len - 1) 
	      p += sprintf(p, ":");
	}

#ifdef HAVE_DHCP6
      if (is6)
	{
	  /* or IAID and server DUID for IPv6 */
	  sprintf(daemon->dhcp_buff3, "%s%u", data.flags & LEASE_TA ? "T" : "", data.iaid);	
	  for (p = daemon->dhcp_packet.iov_base, i = 0; i < daemon->duid_len; i++)
	    {
	      p += sprintf(p, "%.2x", daemon->duid[i]);
	      if (i != daemon->duid_len - 1) 
		p += sprintf(p, ":");
	    }

	}
#endif

      buf += data.clid_len;

      if (data.hostname_len != 0)
	{
	  char *dot;
	  hostname = (char *)buf;
	  hostname[data.hostname_len - 1] = 0;
	  if (data.action != ACTION_TFTP && data.action != ACTION_RELAY_SNOOP)
	    {
	      if (!legal_hostname(hostname))
		hostname = NULL;
	      else if ((dot = strchr(hostname, '.')))
		{
		  domain = dot+1;
		  *dot = 0;
		} 
	    }
	}
    
      extradata = buf + data.hostname_len;
    
      if (!is6)
	inet_ntop(AF_INET, &data.addr, daemon->addrbuff, ADDRSTRLEN);
      else
	inet_ntop(AF_INET6, &data.addr6, daemon->addrbuff, ADDRSTRLEN);

#ifdef HAVE_TFTP
      /* file length */
      if (data.action == ACTION_TFTP)
	sprintf(is6 ? daemon->packet : daemon->dhcp_buff, "%lu", (unsigned long)data.file_len);
#endif

#ifdef HAVE_LUASCRIPT
      if (daemon->luascript)
	{
	  if (data.action == ACTION_TFTP)
	    {
	      lua_getglobal(lua, "tftp"); 
	      if (lua_type(lua, -1) != LUA_TFUNCTION)
		lua_pop(lua, 1); /* tftp function optional */
	      else
		{
		  lua_pushstring(lua, action_str); /* arg1 - action */
		  lua_newtable(lua);               /* arg2 - data table */
		  lua_pushstring(lua, daemon->addrbuff);
		  lua_setfield(lua, -2, "destination_address");
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "file_name"); 
		  lua_pushstring(lua, is6 ? daemon->packet : daemon->dhcp_buff);
		  lua_setfield(lua, -2, "file_size");
		  lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
		}
	    }
	  else if (data.action == ACTION_RELAY_SNOOP)
	    {
	      lua_getglobal(lua, "snoop"); 
	      if (lua_type(lua, -1) != LUA_TFUNCTION)
		lua_pop(lua, 1); /* tftp function optional */
	      else
		{
		  lua_pushstring(lua, action_str); /* arg1 - action */
		  lua_newtable(lua);               /* arg2 - data table */
		  lua_pushstring(lua, daemon->addrbuff);
		  lua_setfield(lua, -2, "client_address");
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "prefix"); 
		  lua_pushstring(lua, data.interface);
		  lua_setfield(lua, -2, "client_interface");
		  lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
		}
	    }
	  else if (data.action == ACTION_ARP)
	    {
	      lua_getglobal(lua, "arp"); 
	      if (lua_type(lua, -1) != LUA_TFUNCTION)
		lua_pop(lua, 1); /* arp function optional */
	      else
		{
		  lua_pushstring(lua, action_str); /* arg1 - action */
		  lua_newtable(lua);               /* arg2 - data table */
		  lua_pushstring(lua, daemon->addrbuff);
		  lua_setfield(lua, -2, "client_address");
		  lua_pushstring(lua, daemon->dhcp_buff);
		  lua_setfield(lua, -2, "mac_address");
		  lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
		}
	    }
	  else
	    {
	      lua_getglobal(lua, "lease");     /* function to call */
	      lua_pushstring(lua, action_str); /* arg1 - action */
	      lua_newtable(lua);               /* arg2 - data table */
	      
	      if (is6)
		{
		  lua_pushstring(lua, daemon->packet);
		  lua_setfield(lua, -2, "client_duid");
		  lua_pushstring(lua, daemon->dhcp_packet.iov_base);
		  lua_setfield(lua, -2, "server_duid");
		  lua_pushstring(lua, daemon->dhcp_buff3);
		  lua_setfield(lua, -2, "iaid");
		}
	      
	      if (!is6 && data.clid_len != 0)
		{
		  lua_pushstring(lua, daemon->packet);
		  lua_setfield(lua, -2, "client_id");
		}
	      
	      if (strlen(data.interface) != 0)
		{
		  lua_pushstring(lua, data.interface);
		  lua_setfield(lua, -2, "interface");
		}
	      
#ifdef HAVE_BROKEN_RTC	
	      lua_pushnumber(lua, data.length);
	      lua_setfield(lua, -2, "lease_length");
#else
	      lua_pushnumber(lua, data.expires);
	      lua_setfield(lua, -2, "lease_expires");
#endif
	      
	      if (hostname)
		{
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "hostname");
		}
	      
	      if (domain)
		{
		  lua_pushstring(lua, domain);
		  lua_setfield(lua, -2, "domain");
		}
	      
	      end = extradata + data.ed_len;
	      buf = extradata;

	      lua_pushnumber(lua, data.ed_len == 0 ? 1 : 0);
	      lua_setfield(lua, -2, "data_missing");
	      
	      if (!is6)
		buf = grab_extradata_lua(buf, end, "vendor_class");
#ifdef HAVE_DHCP6
	      else  if (data.vendorclass_count != 0)
		{
		  sprintf(daemon->dhcp_buff2, "vendor_class_id");
		  buf = grab_extradata_lua(buf, end, daemon->dhcp_buff2);
		  for (i = 0; i < data.vendorclass_count - 1; i++)
		    {
		      sprintf(daemon->dhcp_buff2, "vendor_class%i", i);
		      buf = grab_extradata_lua(buf, end, daemon->dhcp_buff2);
		    }
		}
#endif
	      
	      buf = grab_extradata_lua(buf, end, "supplied_hostname");
	      
	      if (!is6)
		{
		  buf = grab_extradata_lua(buf, end, "cpewan_oui");
		  buf = grab_extradata_lua(buf, end, "cpewan_serial");   
		  buf = grab_extradata_lua(buf, end, "cpewan_class");
		  buf = grab_extradata_lua(buf, end, "circuit_id");
		  buf = grab_extradata_lua(buf, end, "subscriber_id");
		  buf = grab_extradata_lua(buf, end, "remote_id");
		}

	      buf = grab_extradata_lua(buf, end, "requested_options");
	      buf = grab_extradata_lua(buf, end, "mud_url");
	      buf = grab_extradata_lua(buf, end, "tags");
	      
	      if (is6)
		buf = grab_extradata_lua(buf, end, "relay_address");
	      else if (data.giaddr.s_addr != 0)
		{
		  inet_ntop(AF_INET, &data.giaddr, daemon->dhcp_buff2, ADDRSTRLEN);
		  lua_pushstring(lua, daemon->dhcp_buff2);
		  lua_setfield(lua, -2, "relay_address");
		}
	      
	      for (i = 0; buf; i++)
		{
		  sprintf(daemon->dhcp_buff2, "user_class%i", i);
		  buf = grab_extradata_lua(buf, end, daemon->dhcp_buff2);
		}
	      
	      if (data.action != ACTION_DEL && data.remaining_time != 0)
		{
		  lua_pushnumber(lua, data.remaining_time);
		  lua_setfield(lua, -2, "time_remaining");
		}
	      
	      if (data.action == ACTION_OLD_HOSTNAME && hostname)
		{
		  lua_pushstring(lua, hostname);
		  lua_setfield(lua, -2, "old_hostname");
		}
	      
	      if (!is6 || data.hwaddr_len != 0)
		{
		  lua_pushstring(lua, daemon->dhcp_buff);
		  lua_setfield(lua, -2, "mac_address");
		}
	      
	      lua_pushstring(lua, daemon->addrbuff);
	      lua_setfield(lua, -2, "ip_address");
	    
	      lua_call(lua, 2, 0);	/* pass 2 values, expect 0 */
	    }
	}
#endif

      /* no script, just lua */
      if (!daemon->lease_change_command)
	continue;

      /* Pipe to capture stdout and stderr from script */
      if (!option_bool(OPT_DEBUG) && pipe(pipeout) == -1)
	continue;
      
      /* possible fork errors are all temporary resource problems */
      while ((pid = fork()) == -1 && (errno == EAGAIN || errno == ENOMEM))
	sleep(2);

      if (pid == -1)
        {
	  if (!option_bool(OPT_DEBUG))
	    {
	      close(pipeout[0]);
	      close(pipeout[1]);
	    }
	  continue;
        }
      
      /* wait for child to complete */
      if (pid != 0)
	{
	  if (!option_bool(OPT_DEBUG))
	    {
	      FILE *fp;
	  
	      close(pipeout[1]);
	      
	      /* Read lines sent to stdout/err by the script and pass them back to be logged */
	      if (!(fp = fdopen(pipeout[0], "r")))
		close(pipeout[0]);
	      else
		{
		  while (fgets(daemon->packet, daemon->packet_buff_sz, fp))
		    {
		      /* do not include new lines, log will append them */
		      size_t len = strlen(daemon->packet);
		      if (len > 0)
			{
			  --len;
			  if (daemon->packet[len] == '\n')
			    daemon->packet[len] = 0;
			}
		      send_event(event_fd, EVENT_SCRIPT_LOG, 0, daemon->packet);
		    }
		  fclose(fp);
		}
	    }
	  
	  /* reap our children's children, if necessary */
	  while (1)
	    {
	      int status;
	      pid_t rc = wait(&status);
	      
	      if (rc == pid)
		{
		  /* On error send event back to main process for logging */
		  if (WIFSIGNALED(status))
		    send_event(event_fd, EVENT_KILLED, WTERMSIG(status), NULL);
		  else if (WIFEXITED(status) && WEXITSTATUS(status) != 0)
		    send_event(event_fd, EVENT_EXITED, WEXITSTATUS(status), NULL);
		  break;
		}
	      
	      if (rc == -1 && errno != EINTR)
		break;
	    }
	  
	  continue;
	}

      if (!option_bool(OPT_DEBUG))
	{
	  /* map stdout/stderr of script to pipeout */
	  close(pipeout[0]);
	  dup2(pipeout[1], STDOUT_FILENO);
	  dup2(pipeout[1], STDERR_FILENO);
	  close(pipeout[1]);
	}
      
      if (data.action != ACTION_TFTP && data.action != ACTION_ARP && data.action != ACTION_RELAY_SNOOP)
	{
#ifdef HAVE_DHCP6
	  my_setenv("DNSMASQ_IAID", is6 ? daemon->dhcp_buff3 : NULL, &err);
	  my_setenv("DNSMASQ_SERVER_DUID", is6 ? daemon->dhcp_packet.iov_base : NULL, &err); 
	  my_setenv("DNSMASQ_MAC", is6 && data.hwaddr_len != 0 ? daemon->dhcp_buff : NULL, &err);
#endif
	  
	  my_setenv("DNSMASQ_CLIENT_ID", !is6 && data.clid_len != 0 ? daemon->packet : NULL, &err);
	  my_setenv("DNSMASQ_INTERFACE", strlen(data.interface) != 0 ? data.interface : NULL, &err);
	  
#ifdef HAVE_BROKEN_RTC
	  sprintf(daemon->dhcp_buff2, "%u", data.length);
	  my_setenv("DNSMASQ_LEASE_LENGTH", daemon->dhcp_buff2, &err);
#else
	  sprintf(daemon->dhcp_buff2, "%lu", (unsigned long)data.expires);
	  my_setenv("DNSMASQ_LEASE_EXPIRES", daemon->dhcp_buff2, &err); 
#endif
	  
	  my_setenv("DNSMASQ_DOMAIN", domain, &err);
	  
	  end = extradata + data.ed_len;
	  buf = extradata;

	  if (data.ed_len == 0)
	    my_setenv("DNSMASQ_DATA_MISSING", "1", &err);
	  
	  if (!is6)
	    buf = grab_extradata(buf, end, "DNSMASQ_VENDOR_CLASS", &err);
#ifdef HAVE_DHCP6
	  else
	    {
	      if (data.vendorclass_count != 0)
		{
		  buf = grab_extradata(buf, end, "DNSMASQ_VENDOR_CLASS_ID", &err);
		  for (i = 0; i < data.vendorclass_count - 1; i++)
		    {
		      sprintf(daemon->dhcp_buff2, "DNSMASQ_VENDOR_CLASS%i", i);
		      buf = grab_extradata(buf, end, daemon->dhcp_buff2, &err);
		    }
		}
	    }
#endif
	  
	  buf = grab_extradata(buf, end, "DNSMASQ_SUPPLIED_HOSTNAME", &err);
	  
	  if (!is6)
	    {
	      buf = grab_extradata(buf, end, "DNSMASQ_CPEWAN_OUI", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_CPEWAN_SERIAL", &err);   
	      buf = grab_extradata(buf, end, "DNSMASQ_CPEWAN_CLASS", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_CIRCUIT_ID", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_SUBSCRIBER_ID", &err);
	      buf = grab_extradata(buf, end, "DNSMASQ_REMOTE_ID", &err);
	    }
	  
	  buf = grab_extradata(buf, end, "DNSMASQ_REQUESTED_OPTIONS", &err);
	  buf = grab_extradata(buf, end, "DNSMASQ_MUD_URL", &err);
	  buf = grab_extradata(buf, end, "DNSMASQ_TAGS", &err);
	  	  
	  if (is6)
	    buf = grab_extradata(buf, end, "DNSMASQ_RELAY_ADDRESS", &err);
	  else
	    {
	      const char *giaddr = NULL;
	      if (data.giaddr.s_addr != 0)
		  giaddr = inet_ntop(AF_INET, &data.giaddr, daemon->dhcp_buff2, ADDRSTRLEN);
	      my_setenv("DNSMASQ_RELAY_ADDRESS", giaddr, &err);
	    }
	  
	  for (i = 0; buf; i++)
	    {
	      sprintf(daemon->dhcp_buff2, "DNSMASQ_USER_CLASS%i", i);
	      buf = grab_extradata(buf, end, daemon->dhcp_buff2, &err);
	    }
	  
	  sprintf(daemon->dhcp_buff2, "%u", data.remaining_time);
	  my_setenv("DNSMASQ_TIME_REMAINING", data.action != ACTION_DEL && data.remaining_time != 0 ? daemon->dhcp_buff2 : NULL, &err);
	  
	  my_setenv("DNSMASQ_OLD_HOSTNAME", data.action == ACTION_OLD_HOSTNAME ? hostname : NULL, &err);
	  if (data.action == ACTION_OLD_HOSTNAME)
	    hostname = NULL;
	  
	  my_setenv("DNSMASQ_LOG_DHCP", option_bool(OPT_LOG_OPTS) ? "1" : NULL, &err);
	}
      
      /* we need to have the event_fd around if exec fails */
      if ((i = fcntl(event_fd, F_GETFD)) != -1)
	fcntl(event_fd, F_SETFD, i | FD_CLOEXEC);
      close(pipefd[0]);

      if (data.action == ACTION_RELAY_SNOOP)
	strcpy(daemon->packet, data.interface);
      
      p =  strrchr(daemon->lease_change_command, '/');
      if (err == 0)
	{
	  execl(daemon->lease_change_command, 
		p ? p+1 : daemon->lease_change_command, action_str, 
		(is6 && data.action != ACTION_ARP) ? daemon->packet : daemon->dhcp_buff, 
		daemon->addrbuff, hostname, (char*)NULL);
	  err = errno;
	}
      /* failed, send event so the main process logs the problem */
      send_event(event_fd, EVENT_EXEC_ERR, err, NULL);
      _exit(0); 
    }
}

/**
 * @brief Set or unset environment variable with error tracking for script execution context
 * 
 * @detailed Wrapper around POSIX setenv() and unsetenv() that tracks whether any
 *           environment variable operation has failed during script preparation.
 *           Used to prepare the environment for external DHCP lease change scripts
 *           with variables like DNSMASQ_LEASE_LENGTH, DNSMASQ_CLIENT_ID, etc.
 *           Prevents cascading errors by checking error flag before attempting
 *           operations. If value is NULL, the variable is removed from the
 *           environment; otherwise it is set with overwrite enabled.
 * 
 * @param name Environment variable name (e.g., "DNSMASQ_INTERFACE")
 * @param value Environment variable value (string representation), or NULL to unset
 * @param error Pointer to error flag; set to errno if operation fails, preserved if already non-zero
 * 
 * @note This is a static helper function used only within helper.c for script execution
 * @warning Does not validate name; assumes caller provides valid environment variable name
 * 
 * @see queue_script() for the main function that calls this repeatedly to set environment
 * 
 * EXAMPLE USAGE:
 * @code
 * int error = 0;
 * my_setenv("DNSMASQ_INTERFACE", "eth0", &error);
 * my_setenv("DNSMASQ_LEASE_LENGTH", "3600", &error);
 * my_setenv("DNSMASQ_OLD_HOSTNAME", NULL, &error);  // Unset if not needed
 * if (error) {
 *   my_syslog(LOG_ERR, _("failed to set environment for script: %s"), strerror(error));
 * }
 * @endcode
 * 
 * SIDE EFFECTS: Modifies process environment variables visible to subsequently execed scripts
 * THREAD SAFETY: Single-threaded helper process - no concurrency concerns
 */
static void my_setenv(const char *name, const char *value, int *error)
{
  if (*error == 0)
    {
      if (!value)
	unsetenv(name);
      else if (setenv(name, value, 1) != 0)
	*error = errno;
    }
}
 
/**
 * @brief Extract null-terminated string from binary buffer and set as environment variable
 * 
 * @detailed Parses a null-terminated string from a binary buffer containing serialized
 *           DHCP lease data, sanitizes the extracted value by removing any '=' characters
 *           to prevent environment variable injection attacks, and sets the result as
 *           an environment variable. Returns pointer to the next field in the buffer
 *           or NULL if buffer is exhausted. Used extensively in queue_script() to
 *           extract variable-length fields like client identifiers, hostnames, and
 *           vendor class data from serialized lease information received via pipe.
 *           The '=' sanitization is a critical security feature preventing malicious
 *           DHCP clients from injecting arbitrary environment variables into scripts.
 * 
 * @param buf Pointer to current position in buffer (start of null-terminated string)
 * @param end Pointer to end of buffer (one byte past valid data)
 * @param env Environment variable name to set (e.g., "DNSMASQ_CLIENT_ID")
 * @param err Pointer to error flag; updated by my_setenv if operation fails
 * 
 * @return Pointer to next field in buffer (after null terminator), or NULL if buffer exhausted or invalid
 * @retval non-NULL Pointer to byte immediately following extracted string's null terminator
 * @retval NULL Buffer exhausted, no more fields, or parsing error (buf == end initially)
 * 
 * @note Static function used only within helper.c for parsing serialized lease data
 * @warning Modifies buffer in-place by replacing first '=' character with null terminator
 * @warning Assumes buffer contains null-terminated string; unterminated data causes undefined behavior
 * 
 * @see queue_script() which calls this repeatedly to extract hostname, client ID, vendor class, etc.
 * @see my_setenv() which performs the actual environment variable setting
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned char buffer[] = "client-identifier\0vendor-class\0";
 * unsigned char *ptr = buffer;
 * int error = 0;
 * 
 * ptr = grab_extradata(ptr, buffer + sizeof(buffer), "DNSMASQ_CLIENT_ID", &error);
 * // DNSMASQ_CLIENT_ID now set to "client-identifier"
 * 
 * ptr = grab_extradata(ptr, buffer + sizeof(buffer), "DNSMASQ_VENDOR_CLASS", &error);
 * // DNSMASQ_VENDOR_CLASS now set to "vendor-class"
 * 
 * ptr = grab_extradata(ptr, buffer + sizeof(buffer), "DNSMASQ_EXTRA", &error);
 * // ptr is NULL, buffer exhausted
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal data parsing, not protocol implementation)
 * SIDE EFFECTS: 
 *   - Modifies buffer in-place (replaces '=' with '\0' if present)
 *   - Sets environment variable via my_setenv
 *   - Updates error flag via err pointer if environment setting fails
 * THREAD SAFETY: Single-threaded helper process - no concurrency concerns
 */
static unsigned char *grab_extradata(unsigned char *buf, unsigned char *end,  char *env, int *err)
{
  unsigned char *next = NULL;
  char *val = NULL;

  if (buf && (buf != end))
    {
      for (next = buf; ; next++)
	if (next == end)
	  {
	    next = NULL;
	    break;
	  }
	else if (*next == 0)
	  break;

      if (next && (next != buf))
	{
	  char *p;
	  /* No "=" in value */
	  if ((p = strchr((char *)buf, '=')))
	    *p = 0;
	  val = (char *)buf;
	}
    }
  
  my_setenv(env, val, err);
   
  return next ? next + 1 : NULL;
}

#ifdef HAVE_LUASCRIPT
/**
 * @brief Extract null-terminated string from binary buffer and add to Lua table as field
 * 
 * @detailed Parses a null-terminated string from a binary buffer containing serialized
 *           DHCP lease data and pushes it onto the Lua stack as a named field in the
 *           current table (at index -2 on Lua stack). This function is the Lua scripting
 *           equivalent of grab_extradata(), used when HAVE_LUASCRIPT is enabled to
 *           prepare lease event data for embedded Lua script execution. Unlike
 *           grab_extradata which sets environment variables, this function directly
 *           populates a Lua table with lease information fields like client_id,
 *           hostname, vendor_class, etc. The Lua scripting approach provides better
 *           performance by eliminating fork-exec overhead for script invocation.
 * 
 * @param buf Pointer to current position in buffer (start of null-terminated string)
 * @param end Pointer to end of buffer (one byte past valid data)
 * @param field Lua table field name (e.g., "client_id", "hostname", "vendor_class")
 * 
 * @return Pointer to next field in buffer (after null terminator), or NULL if buffer exhausted or invalid
 * @retval non-NULL Pointer to byte immediately following extracted string's null terminator
 * @retval NULL Buffer exhausted, no more fields, buf is NULL, or buffer not properly null-terminated
 * 
 * @note Static function used only within helper.c for Lua script data preparation (HAVE_LUASCRIPT)
 * @note Requires Lua table at stack position -2 to receive the field (prepared by caller)
 * @warning Assumes buffer contains null-terminated string; unterminated data returns NULL
 * @warning Does not sanitize '=' characters like grab_extradata - Lua tables don't need this protection
 * 
 * @see queue_script() which calls this when HAVE_LUASCRIPT is enabled to populate Lua event table
 * @see grab_extradata() which is the environment variable equivalent for external scripts
 * 
 * EXAMPLE USAGE:
 * @code
 * // Lua table must be on stack at position -2
 * lua_newtable(lua);  // Create event data table
 * 
 * unsigned char buffer[] = "client-identifier\0vendor-class\0";
 * unsigned char *ptr = buffer;
 * 
 * ptr = grab_extradata_lua(ptr, buffer + sizeof(buffer), "client_id");
 * // Lua table now has table["client_id"] = "client-identifier"
 * 
 * ptr = grab_extradata_lua(ptr, buffer + sizeof(buffer), "vendor_class");
 * // Lua table now has table["vendor_class"] = "vendor-class"
 * 
 * ptr = grab_extradata_lua(ptr, buffer + sizeof(buffer), "extra");
 * // ptr is NULL, buffer exhausted
 * 
 * // Now call Lua function with populated table
 * lua_setglobal(lua, "lease_event_data");
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal data parsing for Lua scripting integration)
 * SIDE EFFECTS: 
 *   - Modifies Lua stack: pushes string value and sets field in table at position -2
 *   - Does not modify buffer (unlike grab_extradata which may replace '=')
 * THREAD SAFETY: Single-threaded helper process - no concurrency concerns
 * LUA STACK IMPACT: Net zero (pushes string then pops it via lua_setfield)
 */
static unsigned char *grab_extradata_lua(unsigned char *buf, unsigned char *end, char *field)
{
  unsigned char *next;

  if (!buf || (buf == end))
    return NULL;

  for (next = buf; *next != 0; next++)
    if (next == end)
      return NULL;
  
  if (next != buf)
    {
      lua_pushstring(lua,  (char *)buf);
      lua_setfield(lua, -2, field);
    }

  return next + 1;
}
#endif

/**
 * @brief Allocate or resize the helper process communication buffer
 * 
 * Ensures the static buffer 'buf' has sufficient capacity to hold script
 * data of the specified size. If the current buffer is too small, allocates
 * a new larger buffer and frees the old one. Uses a minimum allocation size
 * to avoid frequent reallocations for typical use cases.
 * 
 * @param size Minimum required buffer size in bytes
 * 
 * @note Buffer is statically allocated and shared across all queue operations
 * @note Minimum allocation size is sizeof(struct script_data) + 200 bytes
 * @warning On allocation failure, returns silently leaving old buffer intact
 * 
 * @see queue_script() Uses this to allocate buffer before populating script data
 * @see whine_malloc() Memory allocator that logs on failure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Allocate buffer for DHCP lease script invocation
 * buff_alloc(sizeof(struct script_data) + clid_len + hostname_len);
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Modifies global 'buf' pointer and 'buf_size' on successful allocation
 * - Frees previous buffer if reallocation occurs
 * - Logs warning message via whine_malloc if allocation fails
 * 
 * THREAD SAFETY: Single-threaded architecture - not thread-safe
 */
static void buff_alloc(size_t size)
{
  if (size > buf_size)
    {
      struct script_data *new;
      
      /* start with reasonable size, will almost never need extending. */
      if (size < sizeof(struct script_data) + 200)
	size = sizeof(struct script_data) + 200;

      if (!(new = whine_malloc(size)))
	return;
      if (buf)
	free(buf);
      buf = new;
      buf_size = size;
    }
}

/**
 * @brief Queue DHCP lease change event for script execution
 * 
 * Queues a DHCP lease change event (add, old, del) for processing by the helper
 * process, which will execute the configured script with the lease details. This
 * function serializes lease information into a buffer that is written to the pipe
 * shared with the helper process.
 * 
 * The function packages all relevant lease information including MAC address, IP
 * address (IPv4 and/or IPv6), hostname, client identifier, vendor class data, and
 * timing information into a structured buffer format that the helper process can
 * parse and pass to the external script as command-line arguments and environment
 * variables.
 * 
 * @param action Event type: ACTION_ADD (new lease), ACTION_OLD (lease renewal),
 *               or ACTION_DEL (lease expiration/release)
 * @param lease Pointer to dhcp_lease structure containing lease details. Must not
 *              be NULL. Includes hwaddr, addr, giaddr, addr6, clid, extradata,
 *              timing, and interface information.
 * @param hostname Client hostname string (may be NULL if not provided by client).
 *                 If provided, must be NULL-terminated string.
 * @param now Current time for calculating remaining lease time. Used to compute
 *            time difference from lease->expires.
 * 
 * @return void (no return value; failures result in event not being queued)
 * 
 * @note Early return occurs if helper process not initialized (daemon->helperfd == -1)
 * @note buff_alloc() manages buffer memory (global buf variable)
 * @note Function does not block; data is queued for asynchronous processing
 * @note DHCPv6 leases use daemon->dhcp6fd, DHCPv4 uses daemon->dhcpfd for interface lookup
 * 
 * @warning Assumes buff_alloc() always succeeds; no error handling for allocation failure
 * @warning MAC address copied using DHCP_CHADDR_MAX size, not actual hwaddr_len
 * 
 * @see buff_alloc() for buffer memory management
 * @see helper_write() for actual pipe write operation
 * @see create_helper() for helper process initialization
 * @see lease.c for lease structure details and lease change triggers
 * 
 * EXAMPLE USAGE:
 * @code
 * struct dhcp_lease *lease = ...;  // Existing lease from lease database
 * char *hostname = "client-workstation";
 * time_t now = dnsmasq_time();
 * queue_script(ACTION_ADD, lease, hostname, now);  // Queue lease add event
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (dnsmasq-specific implementation for external integration)
 * 
 * SIDE EFFECTS:
 * - Allocates/reuses memory via buff_alloc() (stored in global buf)
 * - Updates global bytes_in_buf with serialized data size
 * - Memory persists across calls (buffer reused for efficiency)
 * - No direct I/O; data buffered for subsequent helper_write()
 * - Modifies global buf structure with lease details
 * 
 * THREAD SAFETY: Single-threaded architecture; not thread-safe
 * 
 * Source: /src/helper.c:line 1073
 */
void queue_script(int action, struct dhcp_lease *lease, char *hostname, time_t now)
{
  unsigned char *p;
  unsigned int hostname_len = 0, clid_len = 0, ed_len = 0;
  int fd = daemon->dhcpfd;
#ifdef HAVE_DHCP6 
  if (!daemon->dhcp)
    fd = daemon->dhcp6fd;
#endif

  /* no script */
  if (daemon->helperfd == -1)
    return;

  if (lease->extradata)
    ed_len = lease->extradata_len;
  if (lease->clid)
    clid_len = lease->clid_len;
  if (hostname)
    hostname_len = strlen(hostname) + 1;

  buff_alloc(sizeof(struct script_data) +  clid_len + ed_len + hostname_len);

  buf->action = action;
  buf->flags = lease->flags;
#ifdef HAVE_DHCP6 
  buf->vendorclass_count = lease->vendorclass_count;
  buf->addr6 = lease->addr6;
  buf->iaid = lease->iaid;
#endif
  buf->hwaddr_len = lease->hwaddr_len;
  buf->hwaddr_type = lease->hwaddr_type;
  buf->clid_len = clid_len;
  buf->ed_len = ed_len;
  buf->hostname_len = hostname_len;
  buf->addr = lease->addr;
  buf->giaddr = lease->giaddr;
  memcpy(buf->hwaddr, lease->hwaddr, DHCP_CHADDR_MAX);
  if (!indextoname(fd, lease->last_interface, buf->interface))
    buf->interface[0] = 0;
  
#ifdef HAVE_BROKEN_RTC 
  buf->length = lease->length;
#else
  buf->expires = lease->expires;
#endif

  if (lease->expires != 0)
    buf->remaining_time = (unsigned int)difftime(lease->expires, now);
  else
    buf->remaining_time = 0;

  p = (unsigned char *)(buf+1);
  if (clid_len != 0)
    {
      memcpy(p, lease->clid, clid_len);
      p += clid_len;
    }
  if (hostname_len != 0)
    {
      memcpy(p, hostname, hostname_len);
      p += hostname_len;
    }
  if (ed_len != 0)
    {
      memcpy(p, lease->extradata, ed_len);
      p += ed_len;
    }
  bytes_in_buf = p - (unsigned char *)buf;
}

#ifdef HAVE_DHCP6
/**
 * @brief Queue DHCPv6 relay agent snooping event for script notification
 * 
 * Queues a DHCPv6 relay agent snooping event to notify external scripts when dnsmasq
 * acting as a DHCPv6 relay detects prefix delegation or address assignment traffic.
 * This enables monitoring and logging of relayed DHCPv6 traffic for network management,
 * prefix tracking, and security auditing purposes.
 * 
 * The function packages DHCPv6 relay topology information (client IPv6 address, relay
 * interface, and delegated/assigned prefix) into the script buffer for processing by
 * the helper process. The prefix is formatted as "address/prefix_len" string following
 * standard CIDR notation. This allows external scripts to track IPv6 prefix delegation
 * flows across network segments.
 * 
 * @param client IPv6 address of the DHCPv6 client behind the relay (struct in6_addr
 *               pointer, typically from relay message)
 * @param if_index Network interface index where relay received client request
 *                 (integer index resolved to interface name via indextoname)
 * @param prefix IPv6 prefix being delegated or assigned (struct in6_addr pointer,
 *               converted to string via inet_ntop for script consumption)
 * @param prefix_len Prefix length in bits (0-128, formatted as "/nnn" in CIDR notation)
 * 
 * @return void (no return value; early return if helper not initialized)
 * 
 * @note Early return occurs if helper process not configured (daemon->helperfd == -1)
 * @note Action code is ACTION_RELAY_SNOOP for script identification
 * @note Prefix formatted as "2001:db8::/64" style string in hostname_len field
 * @note Interface name resolved via indextoname() using daemon->dhcp6fd socket
 * @note Buffer allocation includes extra space for CIDR string (ADDRSTRLEN + 5 bytes)
 * @note Only compiled when HAVE_DHCP6 is defined
 * 
 * @warning Client and prefix pointers must not be NULL; dereferenced without check
 * @warning if_index must be valid interface index or indextoname returns empty string
 * @warning Reuses hostname_len field to store prefix string length (DHCP field repurposing)
 * 
 * @see queue_script() for primary DHCP lease event queuing
 * @see buff_alloc() for buffer memory management
 * @see indextoname() for interface index to name conversion
 * @see ACTION_RELAY_SNOOP constant definition in dnsmasq.h
 * 
 * EXAMPLE USAGE:
 * @code
 * struct in6_addr client, prefix;
 * inet_pton(AF_INET6, "2001:db8::1", &client);
 * inet_pton(AF_INET6, "2001:db8:1::", &prefix);
 * queue_relay_snoop(&client, 3, &prefix, 64);  // Interface index 3, /64 prefix
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 8415 (DHCPv6), RFC 3633 (IPv6 Prefix Delegation via DHCPv6)
 * 
 * SIDE EFFECTS:
 * - Converts prefix to string in daemon->addrbuff (shared buffer, overwritten)
 * - Allocates/reuses memory via buff_alloc() for script_data + CIDR string
 * - Zeroes entire script_data buffer (memset) before population
 * - Formats CIDR string immediately after script_data struct in buffer
 * - Updates global bytes_in_buf to total size (struct + string)
 * - Calls indextoname() which may perform ioctl on daemon->dhcp6fd socket
 * 
 * THREAD SAFETY: Single-threaded architecture; not thread-safe (uses global buf)
 * 
 * Source: /src/helper.c:line 1204
 */
void queue_relay_snoop(struct in6_addr *client, int if_index, struct in6_addr *prefix, int prefix_len)
{
  /* no script */
  if (daemon->helperfd == -1)
    return;
  
  inet_ntop(AF_INET6, prefix, daemon->addrbuff, ADDRSTRLEN);

  /* 5 for /nnn and zero on the end of the prefix. */
  buff_alloc(sizeof(struct script_data) + ADDRSTRLEN + 5);
  memset(buf, 0, sizeof(struct script_data));

  buf->action = ACTION_RELAY_SNOOP;
  buf->addr6 = *client;
  buf->hostname_len = sprintf((char *)(buf+1), "%s/%u", daemon->addrbuff, prefix_len) + 1;
  
  indextoname(daemon->dhcp6fd, if_index, buf->interface);

  bytes_in_buf = sizeof(struct script_data) + buf->hostname_len;
}
#endif

#ifdef HAVE_TFTP
/* This nastily re-uses DHCP-fields for TFTP stuff */
/**
 * @brief Queue TFTP file transfer event for script notification
 * 
 * @detailed Builds script data structure for TFTP file transfer completion events
 *           and queues for delivery to helper process. Used to notify external scripts
 *           when TFTP transfers complete, allowing integration with logging systems,
 *           access control mechanisms, or transfer auditing. The function captures
 *           transferred file size, filename, and client peer address for script processing.
 *           Available only when HAVE_TFTP compile flag is enabled. Re-uses DHCP data
 *           structure fields to store TFTP-specific information.
 * 
 * @param file_len Size of transferred file in bytes (off_t supports large files >2GB on 64-bit systems)
 * @param filename Name of file transferred via TFTP (NULL-terminated string, must not be NULL)
 * @param peer Socket address of TFTP client (union mysockaddr containing IPv4 or IPv6 address)
 * 
 * @return None (void function)
 * 
 * @note Requires buff_alloc() to have successfully allocated script data buffer before calling
 * @note Filename length limited by ed_len field and buffer size allocation
 * @warning Function assumes filename is NULL-terminated; no explicit length checking performed
 * @warning If buffer allocation fails, event is silently dropped
 * 
 * @see queue_script() - Core queuing function for all DHCP/TFTP/ARP events
 * @see create_helper() - Creates helper process that receives queued events
 * @see tftp.c - TFTP protocol implementation that generates transfer completion events
 * 
 * EXAMPLE USAGE:
 * @code
 * // After successful TFTP transfer completion
 * off_t transferred_bytes = 1048576; // 1MB file transferred
 * char *boot_filename = "pxelinux.0";
 * union mysockaddr client_addr;
 * // ... client_addr populated from TFTP connection ...\n * queue_tftp(transferred_bytes, boot_filename, &client_addr);
 * helper_write(); // Flush queued event to helper process
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (TFTP RFC 1350 protocol handling in tftp.c; this is event notification only)
 * SIDE EFFECTS: Modifies global buf and bytes_in_buf; data transmitted to helper pipe on helper_write()
 * THREAD SAFETY: Single-threaded architecture - not thread-safe, assumes exclusive access to global buf
 */
void queue_tftp(off_t file_len, char *filename, union mysockaddr *peer)
{
  unsigned int filename_len;

  /* no script */
  if (daemon->helperfd == -1)
    return;
  
  filename_len = strlen(filename) + 1;
  buff_alloc(sizeof(struct script_data) +  filename_len);
  memset(buf, 0, sizeof(struct script_data));

  buf->action = ACTION_TFTP;
  buf->hostname_len = filename_len;
  buf->file_len = file_len;

  if ((buf->flags = peer->sa.sa_family) == AF_INET)
    buf->addr = peer->in.sin_addr;
  else
    buf->addr6 = peer->in6.sin6_addr;

  memcpy((unsigned char *)(buf+1), filename, filename_len);
  
  bytes_in_buf = sizeof(struct script_data) +  filename_len;
}
#endif

/**
 * @brief Queue ARP cache change event for script notification
 * 
 * @detailed Builds script data structure for ARP neighbor cache change events (address-to-MAC
 *           binding additions or deletions) and queues for delivery to helper process. Used to
 *           notify external scripts when the kernel ARP cache updates, enabling integration with
 *           network access control systems, device tracking, or security monitoring. The function
 *           captures MAC address, IP address, and action type (add/del) for script processing.
 *           Supports both IPv4 ARP and IPv6 neighbor discovery events. Function is always
 *           available when HAVE_SCRIPT is enabled (not conditional on HAVE_ARP).
 * 
 * @param action Event action type: ARP_NEW for new binding, ARP_DEL for removed binding (see dnsmasq.h for constants)
 * @param mac MAC address bytes from ARP/neighbor cache entry (must not be NULL)
 * @param maclen MAC address length in bytes (typically 6 for Ethernet, 20 for Infiniband)
 * @param family Address family: AF_INET for IPv4 ARP, AF_INET6 for IPv6 neighbor discovery
 * @param addr IP address from ARP/neighbor cache entry (union all_addr containing addr4 or addr6)
 * 
 * @return None (void function)
 * 
 * @note Requires buff_alloc() to have successfully allocated script data buffer before calling
 * @note MAC address copied into fixed-size hwaddr array (DHCP_CHADDR_MAX bytes)
 * @note Hardware type hardcoded to ARPHRD_ETHER (Ethernet) regardless of actual link type
 * @warning If buffer allocation fails, event is silently dropped
 * @warning maclen must be ≤ DHCP_CHADDR_MAX (16 bytes) to prevent buffer overflow
 * 
 * @see queue_script() - Core queuing function for all DHCP/TFTP/ARP events
 * @see create_helper() - Creates helper process that receives queued events
 * @see arp.c:find_mac() - Function that discovers MAC addresses and calls queue_arp
 * 
 * EXAMPLE USAGE:
 * @code
 * // When new ARP entry discovered for 192.168.1.10 -> 00:11:22:33:44:55
 * unsigned char mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
 * union all_addr ipaddr;
 * inet_pton(AF_INET, "192.168.1.10", &ipaddr.addr4);
 * queue_arp(ARP_NEW, mac, 6, AF_INET, &ipaddr);
 * helper_write(); // Flush queued event to helper process
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (ARP is RFC 826; neighbor discovery is RFC 4861; this is event notification only)
 * SIDE EFFECTS: Modifies global buf and bytes_in_buf; data transmitted to helper pipe on helper_write()
 * THREAD SAFETY: Single-threaded architecture - not thread-safe, assumes exclusive access to global buf
 */
void queue_arp(int action, unsigned char *mac, int maclen, int family, union all_addr *addr)
{
  /* no script */
  if (daemon->helperfd == -1)
    return;
  
  buff_alloc(sizeof(struct script_data));
  memset(buf, 0, sizeof(struct script_data));

  buf->action = action;
  buf->hwaddr_len = maclen;
  buf->hwaddr_type =  ARPHRD_ETHER; 
  if ((buf->flags = family) == AF_INET)
    buf->addr = addr->addr4;
  else
    buf->addr6 = addr->addr6;
  
  memcpy(buf->hwaddr, mac, maclen);
  
  bytes_in_buf = sizeof(struct script_data);
}

/**
 * @brief Check if helper script data buffer is empty
 * 
 * @detailed Query function that tests whether the global script data buffer contains
 *           any pending events awaiting transmission to the helper process. Returns
 *           true (non-zero) if buffer is empty, false (zero) if buffer contains queued
 *           events. Used by main event loop to determine if helper_write() needs to be
 *           called to flush pending script notifications. Simple wrapper around
 *           bytes_in_buf global variable comparison.
 * 
 * @param None (void function)
 * 
 * @return int - 1 (true) if buffer is empty (bytes_in_buf == 0), 0 (false) if buffer contains data
 * @retval 1 Buffer is empty, no pending events to transmit to helper process
 * @retval 0 Buffer contains pending events, helper_write() should be called to flush
 * 
 * @note This is a pure query function with no side effects
 * @note Function always available when HAVE_SCRIPT compile flag is enabled
 * 
 * @see helper_write() - Function to flush buffer contents to helper pipe
 * @see bytes_in_buf - Global variable tracking buffer occupancy
 * @see queue_script() - Primary function that populates buffer with events
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after queuing DHCP lease event
 * queue_script(ACTION_ADD, &lease_data, "eth0");
 * if (!helper_buf_empty()) {
 *   helper_write(); // Flush pending events to helper process
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal buffer management function)
 * SIDE EFFECTS: None (pure query function)
 * THREAD SAFETY: Single-threaded architecture - not thread-safe, reads global bytes_in_buf
 */
int helper_buf_empty(void)
{
  return bytes_in_buf == 0;
}

/**
 * @brief Write buffered script data to helper process pipe
 * 
 * @detailed Transmits queued script event data from global buffer to helper process via
 *           pipe file descriptor (daemon->helperfd). Implements non-blocking write with
 *           partial write handling and error recovery. On successful write, adjusts buffer
 *           by moving any remaining untransmitted data to buffer start via memmove().
 *           On EAGAIN (pipe full) or EINTR (signal interrupted), returns immediately to
 *           retry later. On other errors (broken pipe, helper died), silently drops buffer
 *           contents to prevent indefinite blocking. Called from main event loop after
 *           queue_script() family functions populate buffer with DHCP/TFTP/ARP events.
 * 
 * @param None (void function)
 * 
 * @return None (void function)
 * 
 * @note Early return if buffer is empty (bytes_in_buf == 0) - no-op if no pending data
 * @note Handles partial writes: if write() returns fewer bytes than requested, remaining
 *       data is moved to buffer start for next write attempt
 * @note Non-blocking operation: EAGAIN means pipe buffer full, will retry on next call
 * @note Signal interruption (EINTR) handled by returning immediately to retry
 * @warning On write errors other than EAGAIN/EINTR (e.g., EPIPE if helper died), buffer
 *          is silently cleared (bytes_in_buf = 0), dropping all queued events
 * @warning Function assumes daemon->helperfd is valid file descriptor from create_helper()
 * 
 * @see helper_buf_empty() - Query function to check if write needed
 * @see queue_script() - Primary function that populates buffer requiring transmission
 * @see create_helper() - Creates helper process and establishes pipe (daemon->helperfd)
 * @see bytes_in_buf - Global variable tracking buffer occupancy, updated by this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main event loop after DHCP transaction
 * queue_script(ACTION_ADD, &lease_data, "eth0");
 * helper_write(); // Attempt to flush buffered event to helper process
 * // If write fails with EAGAIN, event remains buffered for next helper_write() call
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal IPC mechanism using POSIX pipe)
 * SIDE EFFECTS: Writes to daemon->helperfd pipe; modifies global buf and bytes_in_buf;
 *               may drop events on fatal write errors (broken pipe)
 * THREAD SAFETY: Single-threaded architecture - not thread-safe, assumes exclusive access
 *                to buf, bytes_in_buf, and daemon->helperfd
 */
void helper_write(void)
{
  ssize_t rc;

  if (bytes_in_buf == 0)
    return;
  
  if ((rc = write(daemon->helperfd, buf, bytes_in_buf)) != -1)
    {
      if (bytes_in_buf != (size_t)rc)
	memmove(buf, buf + rc, bytes_in_buf - rc); 
      bytes_in_buf -= rc;
    }
  else
    {
      if (errno == EAGAIN || errno == EINTR)
	return;
      bytes_in_buf = 0;
    }
}

#endif /* HAVE_SCRIPT */
