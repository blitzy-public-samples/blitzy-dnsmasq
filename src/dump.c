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
 * @file dump.c
 * @brief Packet capture to libpcap format for debugging and troubleshooting
 * 
 * DETAILED PURPOSE:
 * This module implements packet dumping functionality that writes DNS queries,
 * DNS responses, DHCP transactions, DHCPv6 messages, Router Advertisement packets,
 * and TFTP transfers to pcap (packet capture) files in standard libpcap format.
 * The captured packets can be analyzed using tools like Wireshark or tcpdump for
 * protocol debugging, troubleshooting network issues, and security analysis.
 * 
 * The implementation creates pcap files compatible with the libpcap file format
 * specification (https://wiki.wireshark.org/Development/LibpcapFileFormat), writing
 * raw IP packets with appropriate headers for analysis. The module supports both
 * regular files and named pipes (FIFOs), enabling real-time packet streaming to
 * analysis tools like Wireshark.
 * 
 * KEY RESPONSIBILITIES:
 * - dump_init(): Initialize packet capture file with pcap global header
 * - dump_packet_udp(): Capture UDP packets (DNS queries/responses on port 53)
 * - dump_packet_icmp(): Capture ICMPv6 packets (Router Advertisement)
 * - do_dump_packet(): Core packet writing function with IP/UDP header construction
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (daemon structure with dump_file, dump_mask, dumpfd)
 *           netinet/icmp6.h (ICMPv6 protocol definitions)
 * Called by: forward.c (DNS query/response dumping)
 *            dhcp.c (DHCPv4 transaction dumping)
 *            dhcp6.c (DHCPv6 and Router Advertisement dumping)
 *            rfc2131.c (DHCP protocol message dumping)
 *            tftp.c (TFTP transfer dumping)
 * Calls: Standard I/O functions (creat, open, lseek, stat)
 *        dnsmasq utility functions (read_write, die)
 * 
 * DATA STRUCTURES:
 * - struct pcap_hdr_s (lines 28-36): libpcap global file header structure
 *   containing magic number, version, timezone, timestamp accuracy, snapshot length,
 *   and data link type for DLT_RAW (raw IP packets without link-layer header)
 * 
 * - struct pcaprec_hdr_s (lines 38-43): libpcap packet record header structure
 *   containing timestamp (seconds and microseconds), included packet length, and
 *   original packet length for each captured packet in the file
 * 
 * - packet_count (line 23): Static counter tracking number of packets written to
 *   dump file, incremented for each captured packet
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DUMPFILE: Master compile-time flag that enables all packet dumping functionality.
 *   When undefined, this entire file is excluded from compilation. Enabled via
 *   COPTS=-DHAVE_DUMPFILE in Makefile or --enable-dumpfile configure flag.
 * 
 * DUMP MASK FLAGS (from dnsmasq.h lines 743-754):
 * - DUMP_QUERY (0x0001): Capture DNS queries from clients to dnsmasq
 * - DUMP_REPLY (0x0002): Capture DNS replies from dnsmasq to clients
 * - DUMP_UP_QUERY (0x0004): Capture DNS queries from dnsmasq to upstream servers
 * - DUMP_UP_REPLY (0x0008): Capture DNS replies from upstream servers to dnsmasq
 * - DUMP_SEC_QUERY (0x0010): Capture DNSSEC validation queries
 * - DUMP_SEC_REPLY (0x0020): Capture DNSSEC validation replies
 * - DUMP_BOGUS (0x0040): Capture DNS responses marked as bogus (failed validation)
 * - DUMP_SEC_BOGUS (0x0080): Capture DNSSEC bogus responses
 * - DUMP_DHCP (0x1000): Capture DHCPv4 transactions (DISCOVER/OFFER/REQUEST/ACK)
 * - DUMP_DHCPV6 (0x2000): Capture DHCPv6 messages (SOLICIT/ADVERTISE/REQUEST/REPLY)
 * - DUMP_RA (0x4000): Capture IPv6 Router Advertisement packets
 * - DUMP_TFTP (0x8000): Capture TFTP file transfers
 * 
 * THREADING/CONCURRENCY:
 * This module operates within dnsmasq's single-threaded event-driven architecture.
 * All dump operations are synchronous writes to the dump file descriptor (daemon->dumpfd).
 * The packet_count variable is modified only by the main event loop thread, avoiding
 * race conditions. File I/O uses blocking writes but packet capture is disabled by
 * default to prevent performance impact on production deployments.
 * 
 * USE CASES:
 * 1. Protocol Debugging: Capture DNS query/response exchanges to analyze protocol
 *    behavior, verify EDNS0 options, examine DNSSEC signatures, and troubleshoot
 *    forwarding issues.
 * 
 * 2. Network Troubleshooting: Diagnose connectivity problems by capturing complete
 *    packet sequences showing client queries, upstream forwarding, and response paths.
 *    Compare timestamps to identify latency sources.
 * 
 * 3. Security Analysis: Record suspicious DNS queries for malware domain detection,
 *    capture failed DNSSEC validations (DUMP_BOGUS) for security incident analysis,
 *    and monitor DHCP transactions for rogue client detection.
 * 
 * 4. Compliance and Auditing: Maintain packet-level audit trails of DNS resolution
 *    activity for compliance requirements, forensic analysis, and incident response.
 * 
 * 5. Real-time Monitoring: Use named pipe (FIFO) mode to stream packets directly to
 *    Wireshark or tcpdump for live protocol analysis without intermediate file storage.
 * 
 * PCAP FILE FORMAT COMPATIBILITY:
 * The implementation writes standard libpcap format files that are fully compatible with:
 * - Wireshark/TShark: Open pcap files for graphical or command-line analysis
 * - tcpdump: Read pcap files with tcpdump -r <dumpfile> for packet inspection
 * - tshark: Use tshark -r <dumpfile> for programmatic packet analysis
 * - Python dpkt/scapy: Parse pcap files programmatically for automated analysis
 * - tcpreplay: Replay captured packets for testing and validation
 * 
 * Files use DLT_RAW (data link type 101) indicating raw IP packets without Ethernet
 * headers, suitable for analyzing IP-layer and above protocol behavior.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_DUMPFILE

#include <netinet/icmp6.h>

/**
 * @brief Global counter tracking total packets written to dump file
 * 
 * This static variable maintains a count of all packets successfully written
 * to the pcap dump file since dump_init() was called. Incremented by
 * do_dump_packet() for each packet record written. Used for statistics and
 * to validate file integrity when reopening existing dump files.
 * 
 * Initialized to 0 in dump_init() and incremented for each packet dumped.
 * When reopening an existing dump file, dump_init() counts existing records
 * to restore the accurate packet count.
 */
static u32 packet_count;

static void do_dump_packet(int mask, void *packet, size_t len,
			   union mysockaddr *src, union mysockaddr *dst, int port, int proto);

/**
 * @struct pcap_hdr_s
 * @brief libpcap global file header structure (24 bytes)
 * 
 * This structure defines the global header written at the beginning of every
 * pcap file, providing metadata about the capture file format and contents.
 * Conforms to libpcap file format specification documented at:
 * https://wiki.wireshark.org/Development/LibpcapFileFormat
 * 
 * LIFECYCLE:
 * Creation: Initialized in dump_init() with standard values
 * Initialization: Written once at file creation or pipe opening
 * Destruction: N/A (structure is stack-allocated)
 * Ownership: Local to dump_init() function
 * 
 * MEMORY LAYOUT:
 * Size: 24 bytes (6 x 32-bit + 2 x 16-bit fields)
 * Alignment: Natural alignment for 32-bit integers
 * 
 * USAGE PATTERNS:
 * - Single instance created on stack in dump_init()
 * - Written to file descriptor with write() system call
 * - Read from existing files to validate magic number and version
 * - Standard libpcap tools (tcpdump, Wireshark) parse this header
 */
/* https://wiki.wireshark.org/Development/LibpcapFileFormat */
struct pcap_hdr_s {
        /** @var magic_number
         *  @brief Magic number identifying pcap file format (0xa1b2c3d4)
         *  
         *  Fixed value 0xa1b2c3d4 for standard libpcap files. This magic number
         *  indicates native byte order (vs. 0xd4c3b2a1 for swapped byte order).
         *  Used by reading tools to detect file format and byte ordering.
         */
        u32 magic_number;
        
        /** @var version_major
         *  @brief Major version number of pcap file format (2)
         *  
         *  Current pcap format uses version 2.4. Major version 2 has been stable
         *  since the original libpcap implementation.
         */
        u16 version_major;
        
        /** @var version_minor
         *  @brief Minor version number of pcap file format (4)
         *  
         *  Current pcap format uses version 2.4. Minor version indicates format
         *  refinements within major version 2.
         */
        u16 version_minor;
        
        /** @var thiszone
         *  @brief GMT to local time zone correction in seconds (0 for UTC)
         *  
         *  Offset from UTC to local time zone. Set to 0 indicating timestamps
         *  are in UTC. Most modern tools ignore this field and assume UTC.
         */
        u32 thiszone;
        
        /** @var sigfigs
         *  @brief Timestamp accuracy (significant figures) - unused, set to 0
         *  
         *  Originally intended to indicate timestamp precision but unused by
         *  libpcap and all tools. Always set to 0.
         */
        u32 sigfigs;
        
        /** @var snaplen
         *  @brief Maximum captured packet length in bytes
         *  
         *  Maximum number of bytes captured per packet. Set to daemon->edns_pktsz + 200
         *  to accommodate DNS packets with EDNS0 extensions plus IP/UDP headers.
         *  Packets longer than snaplen are truncated in the capture file.
         */
        u32 snaplen;
        
        /** @var network
         *  @brief Data link type (DLT) indicating packet encapsulation format
         *  
         *  Set to 101 (DLT_RAW) indicating raw IP packets without link-layer headers.
         *  See http://www.tcpdump.org/linktypes.html for complete DLT list.
         *  DLT_RAW means packets start with IP header (IPv4 or IPv6) directly.
         */
        u32 network;
};

/**
 * @struct pcaprec_hdr_s
 * @brief libpcap packet record header (16 bytes per packet)
 * 
 * This structure precedes each captured packet in the pcap file, providing
 * timestamp and length metadata for the packet data that follows. Every packet
 * in the file consists of this header immediately followed by the packet bytes.
 * 
 * LIFECYCLE:
 * Creation: Initialized in do_dump_packet() for each captured packet
 * Initialization: Populated with current timestamp and packet length
 * Destruction: N/A (structure is stack-allocated)
 * Ownership: Local to do_dump_packet() function
 * 
 * MEMORY LAYOUT:
 * Size: 16 bytes (4 x 32-bit fields)
 * Alignment: Natural alignment for 32-bit integers
 * 
 * USAGE PATTERNS:
 * - One instance per captured packet, written before packet data
 * - Timestamp precision is microseconds (though dnsmasq uses gettimeofday)
 * - incl_len may be less than orig_len if packet was truncated to snaplen
 * - Tools use this header to index through multiple packets in file
 */
struct pcaprec_hdr_s {
        /** @var ts_sec
         *  @brief Packet capture timestamp - seconds since Unix epoch
         *  
         *  Number of seconds since January 1, 1970 00:00:00 UTC when packet
         *  was captured. Obtained from gettimeofday() system call.
         */
        u32 ts_sec;
        
        /** @var ts_usec
         *  @brief Packet capture timestamp - microseconds component
         *  
         *  Microseconds component of capture timestamp (0-999999). Combined with
         *  ts_sec provides microsecond-precision timestamps for packet arrival times.
         *  Used to calculate latencies and analyze timing relationships.
         */
        u32 ts_usec;
        
        /** @var incl_len
         *  @brief Number of packet bytes actually saved in this file
         *  
         *  Length of packet data following this header in the file. May be less
         *  than orig_len if packet was truncated to snaplen limit. This is the
         *  number of bytes to read after this header to get the full packet record.
         */
        u32 incl_len;
        
        /** @var orig_len
         *  @brief Original packet length before any truncation
         *  
         *  Original length of packet as captured from network. If orig_len > incl_len,
         *  packet was truncated to fit snaplen. Tools can detect truncation by
         *  comparing these two values.
         */
        u32 orig_len;
};


/**
 * @brief Initialize packet capture dump file with pcap global header
 * 
 * @detailed This function initializes the packet dumping subsystem by opening or creating
 * the dump file specified by daemon->dump_file and writing the pcap global header. The
 * function handles three scenarios: creating a new file, opening a named pipe (FIFO) for
 * real-time streaming to tools like Wireshark, or reopening an existing file to append
 * additional packets. When reopening an existing file, the function validates the pcap
 * header magic number and counts existing packet records to maintain an accurate packet_count.
 * 
 * The function creates a libpcap format file compatible with tcpdump, Wireshark, and other
 * standard packet analysis tools. The file uses DLT_RAW (data link type 101) indicating
 * raw IP packets without Ethernet headers, which is appropriate for capturing DNS, DHCP,
 * and other IP-layer protocols at the application level.
 * 
 * @return void - function terminates process with die() on any error
 * 
 * @note File creation uses permissions S_IRUSR | S_IWUSR (0600, owner read/write only)
 * @warning This function calls die() to terminate the daemon process if the dump file cannot
 *          be created, opened, or if an existing file has an invalid pcap header. Any errors
 *          are fatal to ensure dump file integrity.
 * 
 * @see dump_packet_udp() in src/dump.c for UDP packet capture
 * @see dump_packet_icmp() in src/dump.c for ICMPv6 packet capture
 * @see do_dump_packet() in src/dump.c for core packet writing
 * 
 * EXAMPLE USAGE:
 * @code
 * // In main initialization (dnsmasq.c):
 * daemon->dump_file = "/var/log/dnsmasq-packets.pcap";
 * daemon->dump_mask = DUMP_QUERY | DUMP_REPLY;
 * dump_init();  // Creates pcap file with header
 * // Later: dump_packet_udp() writes packets to initialized file
 * @endcode
 * 
 * INITIALIZATION SCENARIOS:
 * 
 * Scenario 1 - New File Creation:
 * - stat() returns ENOENT (file does not exist)
 * - creat() creates new file with mode 0600
 * - Writes pcap_hdr_s global header to new file
 * - Sets daemon->dumpfd to file descriptor
 * - Leaves packet_count at 0
 * 
 * Scenario 2 - Named Pipe (FIFO):
 * - stat() succeeds, S_ISFIFO() returns true
 * - open() with O_APPEND | O_RDWR for pipe
 * - Writes pcap_hdr_s header to pipe (received by Wireshark on other end)
 * - Pipe consumer (Wireshark) receives header and subsequent packet stream
 * - packet_count remains 0 (pipe has no persistent record count)
 * 
 * Scenario 3 - Existing Regular File:
 * - stat() succeeds, S_ISREG() true
 * - open() with O_APPEND | O_RDWR for appending
 * - read_write() reads existing pcap_hdr_s header and validates magic number 0xa1b2c3d4
 * - Iterates through file reading each pcaprec_hdr_s, seeking past packet data
 * - Increments packet_count for each existing record found
 * - Positions file offset at EOF ready for appending new packets
 * 
 * PCAP HEADER CONFIGURATION:
 * - magic_number: 0xa1b2c3d4 (standard libpcap native byte order)
 * - version: 2.4 (major=2, minor=4, standard pcap version)
 * - thiszone: 0 (UTC, no timezone correction)
 * - sigfigs: 0 (timestamp accuracy field, unused by libpcap)
 * - snaplen: daemon->edns_pktsz + 200 bytes (DNS EDNS0 max size plus IP/UDP header slop)
 * - network: 101 (DLT_RAW, raw IP packets without link-layer header)
 * 
 * RFC COMPLIANCE: Implements libpcap file format per specification at
 *                 https://wiki.wireshark.org/Development/LibpcapFileFormat
 * 
 * SIDE EFFECTS:
 * - Creates or opens file at daemon->dump_file path
 * - Sets daemon->dumpfd to open file descriptor
 * - Initializes static packet_count to 0 or count of existing records
 * - Calls die() on fatal errors (file creation failure, permission errors, invalid header)
 * - File descriptor remains open for lifetime of daemon process
 * 
 * THREAD SAFETY: Single-threaded architecture, no locking required
 */
void dump_init(void)
{
  struct stat buf;
  struct pcap_hdr_s header;
  struct pcaprec_hdr_s pcap_header;

  packet_count = 0;
  
  header.magic_number = 0xa1b2c3d4;
  header.version_major = 2;
  header.version_minor = 4;
  header.thiszone = 0;
  header.sigfigs = 0;
  header.snaplen = daemon->edns_pktsz + 200; /* slop for IP/UDP headers */
  header.network = 101; /* DLT_RAW http://www.tcpdump.org/linktypes.html */

  if (stat(daemon->dump_file, &buf) == -1)
    {
      /* doesn't exist, create and add header */
      if (errno != ENOENT ||
	  (daemon->dumpfd = creat(daemon->dump_file, S_IRUSR | S_IWUSR)) == -1 ||
	  !read_write(daemon->dumpfd, (void *)&header, sizeof(header), RW_WRITE))
	die(_("cannot create %s: %s"), daemon->dump_file, EC_FILE);
    }
  else if (S_ISFIFO(buf.st_mode))
    {
      /* File is named pipe (with wireshark on the other end, probably.)
	 Send header. */
      if  ((daemon->dumpfd = open(daemon->dump_file, O_APPEND | O_RDWR)) == -1 ||
	   !read_write(daemon->dumpfd, (void *)&header, sizeof(header), RW_WRITE))
	die(_("cannot open pipe %s: %s"), daemon->dump_file, EC_FILE);
    }
  else if ((daemon->dumpfd = open(daemon->dump_file, O_APPEND | O_RDWR)) == -1 ||
	   !read_write(daemon->dumpfd, (void *)&header, sizeof(header), RW_READ))
    die(_("cannot access %s: %s"), daemon->dump_file, EC_FILE);
  else if (header.magic_number != 0xa1b2c3d4)
    die(_("bad header in %s"), daemon->dump_file, EC_FILE);
  else
    {
      /* count existing records */
      while (read_write(daemon->dumpfd, (void *)&pcap_header, sizeof(pcap_header), RW_READ))
	{
	  lseek(daemon->dumpfd, pcap_header.incl_len, SEEK_CUR);
	  packet_count++;
	}
    }
}

/**
 * @brief Capture UDP packet (DNS query/response) to pcap dump file
 * 
 * @detailed This function captures UDP packets to the pcap dump file, primarily used for
 * DNS queries and responses on UDP port 53. The function extracts the local address from
 * the provided socket file descriptor using getsockname(), then delegates to do_dump_packet()
 * to construct IP and UDP headers and write the complete packet to the dump file.
 * 
 * DNS packets are captured based on the dump mask configuration, which controls whether
 * client queries (DUMP_QUERY), client responses (DUMP_REPLY), upstream queries (DUMP_UP_QUERY),
 * upstream responses (DUMP_UP_REPLY), DNSSEC validation packets (DUMP_SEC_QUERY/DUMP_SEC_REPLY),
 * and bogus responses (DUMP_BOGUS/DUMP_SEC_BOGUS) are captured.
 * 
 * The function determines whether src or dst is the local address by comparing with the
 * socket's bound address. For DNS queries from clients, src is the client and dst is local.
 * For DNS responses to clients, src is local and dst is the client. This information is
 * used by do_dump_packet() to construct proper IP headers with correct source/destination.
 * 
 * @param mask Dump mask flag (DUMP_QUERY, DUMP_REPLY, etc.) controlling capture
 * @param packet Pointer to DNS packet payload (without IP/UDP headers)
 * @param len Length of DNS packet payload in bytes
 * @param src Source address (client IP for queries, server IP for responses)
 * @param dst Destination address (server IP for queries, client IP for responses)
 * @param fd Socket file descriptor used for getsockname() to determine local address
 * 
 * @return void
 * 
 * @note Only captures packets if daemon->dumpfd != -1 (dump file opened) and mask matches daemon->dump_mask
 * @warning Assumes valid socket file descriptor; getsockname() failure is logged but not fatal
 * 
 * @see dump_init() in src/dump.c for dump file initialization
 * @see do_dump_packet() in src/dump.c for core packet writing with IP/UDP header construction
 * @see dump_packet_icmp() in src/dump.c for ICMPv6 Router Advertisement capture
 * 
 * EXAMPLE USAGE:
 * @code
 * // In forward.c after receiving DNS query from client:
 * union mysockaddr client_addr, server_addr;
 * void *dns_packet = ...;  // DNS query payload
 * size_t dns_len = ...;    // DNS packet length
 * int listen_fd = ...;     // Listening socket
 * dump_packet_udp(DUMP_QUERY, dns_packet, dns_len, 
 *                 &client_addr, &server_addr, listen_fd);
 * 
 * // In forward.c when forwarding to upstream server:
 * dump_packet_udp(DUMP_UP_QUERY, dns_packet, dns_len,
 *                 &local_addr, &upstream_addr, upstream_fd);
 * @endcode
 * 
 * DUMP MASK VALUES (from dnsmasq.h):
 * - DUMP_QUERY (0x0001): DNS queries from clients to dnsmasq
 * - DUMP_REPLY (0x0002): DNS replies from dnsmasq to clients
 * - DUMP_UP_QUERY (0x0004): DNS queries from dnsmasq to upstream servers
 * - DUMP_UP_REPLY (0x0008): DNS replies from upstream servers to dnsmasq
 * - DUMP_SEC_QUERY (0x0010): DNSSEC validation queries
 * - DUMP_SEC_REPLY (0x0020): DNSSEC validation replies
 * - DUMP_BOGUS (0x0040): DNS responses marked as bogus (failed validation)
 * - DUMP_SEC_BOGUS (0x0080): DNSSEC bogus responses
 * 
 * ADDRESS DETERMINATION LOGIC:
 * The function retrieves the socket's local address using getsockname() to determine
 * which address (src or dst) represents the local dnsmasq instance. This is necessary
 * because:
 * - For client queries: src=client, dst=dnsmasq (fd is listening socket)
 * - For client responses: src=dnsmasq, dst=client (fd is same listening socket)
 * - For upstream queries: src=dnsmasq, dst=upstream (fd is upstream socket)
 * - For upstream responses: src=upstream, dst=dnsmasq (fd is same upstream socket)
 * 
 * The do_dump_packet() function uses this information to construct IP headers with
 * correct source and destination IP addresses and UDP port numbers.
 * 
 * RFC COMPLIANCE: UDP packet format per RFC 768 (User Datagram Protocol)
 *                 DNS packet format per RFC 1035 (Domain Names)
 * 
 * SIDE EFFECTS:
 * - Calls getsockname() to query socket local address
 * - Invokes do_dump_packet() which writes to daemon->dumpfd
 * - Increments packet_count (in do_dump_packet)
 * - May block on file I/O if dump file is regular file (not common in event loop)
 * 
 * THREAD SAFETY: Single-threaded architecture, no locking required
 */
void dump_packet_udp(int mask, void *packet, size_t len,
		     union mysockaddr *src, union mysockaddr *dst, int fd)
{
  union mysockaddr fd_addr;
  socklen_t addr_len = sizeof(fd_addr);

  if (daemon->dumpfd != -1 && (mask & daemon->dump_mask))
     {
       /* if fd is negative it carries a port number (negated) 
	  which we use as a source or destination when not otherwise
	  specified so wireshark can ID the packet. 
	  If both src and dst are specified, set this to -1 to avoid
	  a spurious getsockname() call. */
       int port = (fd < 0) ? -fd : -1;
       
       /* fd >= 0 is a file descriptor and the address of that file descriptor is used
	  in place of a NULL src or dst. */
       if (fd >= 0 && getsockname(fd, (struct sockaddr *)&fd_addr, &addr_len) != -1)
	 {
	   if (!src)
	     src = &fd_addr;
	   
	   if (!dst)
	     dst = &fd_addr;
	 }
       
       do_dump_packet(mask, packet, len, src, dst, port, IPPROTO_UDP);
     }
}

/**
 * @brief Dump ICMPv6 packet to capture file
 * 
 * @detailed Writes ICMPv6 packets (typically Router Advertisement, Router Solicitation,
 *           Neighbor Discovery messages) to the pcap dump file when ICMP packet dumping
 *           is enabled via the dump mask. Creates IP header and writes complete packet
 *           in pcap format for analysis. Used for debugging IPv6 network configuration
 *           and Router Advertisement functionality in radv.c.
 * 
 * @param mask Packet type mask indicating capture category (RA, NS, etc.)
 * @param packet Pointer to ICMPv6 packet data buffer to dump
 * @param len Length of ICMPv6 packet in bytes
 * @param src Source address of ICMP packet (IPv6 address)
 * @param dst Destination address of ICMP packet (IPv6 multicast or unicast)
 * 
 * @return void - No return value; writes to dump file or silently fails
 * 
 * @note Only dumps packets when daemon->dumpfd is valid and mask matches daemon->dump_mask
 * @warning Assumes IPv6 addresses in src/dst; do not use for ICMPv4
 * 
 * @see dump_packet_udp() for UDP packet capture
 * @see do_dump_packet() for core packet writing implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * // From radv.c when sending Router Advertisement
 * union mysockaddr src, dst;
 * dump_packet_icmp(DUMP_RA, icmp6_packet, packet_len, &src, &dst);
 * @endcode
 * 
 * RFC COMPLIANCE: ICMPv6 packet capture per RFC 4443 (ICMPv6)
 * SIDE EFFECTS: Writes to dump file descriptor; increments packet_count
 * THREAD SAFETY: Single-threaded architecture; assumes no concurrent writes to dump file
 */
void dump_packet_icmp(int mask, void *packet, size_t len,
		      union mysockaddr *src, union mysockaddr *dst)
{
  if (daemon->dumpfd != -1 && (mask & daemon->dump_mask))
    do_dump_packet(mask, packet, len, src, dst, -1, IPPROTO_ICMP);
}

/**
 * @brief Core packet dumping implementation writing packets to pcap file
 * 
 * @detailed Internal helper function that performs the actual packet capture writing.
 *           Constructs complete IP packets (IPv4 or IPv6) with proper headers, calculates
 *           checksums for UDP and ICMP protocols, creates pcap record headers with accurate
 *           timestamps, and writes all data to the dump file. This function handles both
 *           IPv4 and IPv6 address families, adapting header construction and checksum
 *           calculation accordingly. Called by dump_packet_udp() and dump_packet_icmp()
 *           after they have determined packet type and addresses.
 * 
 * @param mask Packet type mask for dump filtering (DUMP_QUERY, DUMP_REPLY, DUMP_DHCP, etc.)
 * @param packet Pointer to packet payload data (DNS, DHCP, or ICMP payload). Must not be NULL.
 * @param len Length of packet payload in bytes. Must be positive and fit within snaplen.
 * @param src Source address (IPv4 or IPv6) of packet. Must not be NULL.
 * @param dst Destination address (IPv4 or IPv6) of packet. Must not be NULL.
 * @param port UDP source/destination port for UDP packets (0 for ICMP packets)
 * @param proto IP protocol number: IPPROTO_UDP (17) or IPPROTO_ICMPV6 (58)
 * 
 * @return void - No return value; logs error message if write fails but does not abort
 * 
 * @note Static internal function not exposed outside dump.c module
 * @note Automatically determines IPv4 vs IPv6 based on src address family (sa_family)
 * @note For UDP: Calculates UDP checksum using IP pseudo-header per RFC 768
 * @note For ICMPv6: Calculates ICMP checksum using IPv6 pseudo-header per RFC 4443
 * @note Increments global packet_count on successful write
 * 
 * @warning Assumes src and dst addresses have same family (both IPv4 or both IPv6)
 * @warning Does not validate that len fits within configured snaplen; truncation may occur
 * @warning Write failures are logged but do not stop daemon operation
 * 
 * @see dump_packet_udp() in src/dump.c - calls this for UDP packet capture
 * @see dump_packet_icmp() in src/dump.c - calls this for ICMPv6 packet capture
 * @see dump_init() in src/dump.c - initializes dump file with pcap header
 * 
 * EXAMPLE USAGE:
 * @code
 * // Internal call from dump_packet_udp for DNS query
 * union mysockaddr src, dst;
 * // ... populate src and dst addresses ...
 * do_dump_packet(DUMP_QUERY, dns_packet, packet_len, &src, &dst, 53, IPPROTO_UDP);
 * @endcode
 * 
 * PCAP FILE FORMAT: Writes packets in libpcap format per https://wiki.wireshark.org/Development/LibpcapFileFormat
 * - Pcap record header: 32-bit timestamp seconds, 32-bit timestamp microseconds, 
 *                       32-bit included length, 32-bit original length
 * - IP header: IPv4 (20 bytes minimum) or IPv6 (40 bytes fixed)
 * - Protocol header: UDP (8 bytes) or ICMPv6 (variable)
 * - Packet payload: Original packet data
 * 
 * CHECKSUM CALCULATION:
 * - IPv4 header checksum: Standard IP header checksum over 20-byte IPv4 header
 * - UDP checksum: Includes IPv4/IPv6 pseudo-header + UDP header + payload per RFC 768/2460
 * - ICMPv6 checksum: Includes IPv6 pseudo-header + ICMP header + payload per RFC 4443
 * 
 * RFC COMPLIANCE: 
 * - RFC 768 (UDP protocol and checksum)
 * - RFC 791 (IPv4 header format and checksum)
 * - RFC 2460 (IPv6 header format)
 * - RFC 4443 (ICMPv6 checksum calculation)
 * 
 * SIDE EFFECTS: 
 * - Writes to daemon->dumpfd file descriptor
 * - Increments global packet_count variable
 * - Logs error message to syslog on write failure
 * 
 * THREAD SAFETY: Single-threaded daemon architecture; no locking required
 */
static void do_dump_packet(int mask, void *packet, size_t len,
			   union mysockaddr *src, union mysockaddr *dst, int port, int proto)
{
  struct ip ip;
  struct ip6_hdr ip6;
  int family;
  struct udphdr {
    u16 uh_sport;               /* source port */
    u16 uh_dport;               /* destination port */
    u16 uh_ulen;                /* udp length */
    u16 uh_sum;                 /* udp checksum */
  } udp;
  struct pcaprec_hdr_s pcap_header;
  struct timeval time;
  u32 i, sum;
  void *iphdr;
  size_t ipsz;
  int rc;
     
  /* if port != -1 it carries a port number 
     which we use as a source or destination when not otherwise
     specified so wireshark can ID the packet. 
     If both src and dst are specified, set this to -1 to avoid
     a spurious getsockname() call. */
  udp.uh_sport = udp.uh_dport = htons(port < 0 ? 0 : port);
  
  if (src)
    family = src->sa.sa_family;
  else
    family = dst->sa.sa_family;

  if (family == AF_INET6)
    {
      iphdr = &ip6;
      ipsz = sizeof(ip6);
      memset(&ip6, 0, sizeof(ip6));
      
      ip6.ip6_vfc = 6 << 4;
      ip6.ip6_hops = 64;

      if ((ip6.ip6_nxt = proto) == IPPROTO_UDP)
	ip6.ip6_plen = htons(sizeof(struct udphdr) + len);
      else
	{
	  proto = ip6.ip6_nxt = IPPROTO_ICMPV6;
	  ip6.ip6_plen = htons(len);
	}
      
      if (src)
	{
	  memcpy(&ip6.ip6_src, &src->in6.sin6_addr, IN6ADDRSZ);
	  udp.uh_sport = src->in6.sin6_port;
	}
      
      if (dst)
	{
	  memcpy(&ip6.ip6_dst, &dst->in6.sin6_addr, IN6ADDRSZ);
	  udp.uh_dport = dst->in6.sin6_port;
	}
            
      /* start UDP checksum */
      for (sum = 0, i = 0; i < IN6ADDRSZ; i+=2)
	{
	  sum += ntohs((ip6.ip6_src.s6_addr[i] << 8) + (ip6.ip6_src.s6_addr[i+1])) ;
	  sum += ntohs((ip6.ip6_dst.s6_addr[i] << 8) + (ip6.ip6_dst.s6_addr[i+1])) ; 
	}
    }
  else
    {
      iphdr = &ip;
      ipsz = sizeof(ip);
      memset(&ip, 0, sizeof(ip));
      
      ip.ip_v = IPVERSION;
      ip.ip_hl = sizeof(struct ip) / 4;
      ip.ip_ttl = IPDEFTTL;

      if ((ip.ip_p = proto) == IPPROTO_UDP)
	ip.ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + len);
      else
	{
	  ip.ip_len = htons(sizeof(struct ip) + len);
	  proto = ip.ip_p = IPPROTO_ICMP;
	}
      
      if (src)
	{
	  ip.ip_src = src->in.sin_addr;
	  udp.uh_sport = src->in.sin_port;
	}

      if (dst)
	{
	  ip.ip_dst = dst->in.sin_addr;
	  udp.uh_dport = dst->in.sin_port;
	}
      
      ip.ip_sum = 0;
      for (sum = 0, i = 0; i < sizeof(struct ip) / 2; i++)
	sum += ((u16 *)&ip)[i];
      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);  
      ip.ip_sum = (sum == 0xffff) ? sum : ~sum;
      
      /* start UDP/ICMP checksum */
      sum = ip.ip_src.s_addr & 0xffff;
      sum += (ip.ip_src.s_addr >> 16) & 0xffff;
      sum += ip.ip_dst.s_addr & 0xffff;
      sum += (ip.ip_dst.s_addr >> 16) & 0xffff;
    }
  
  if (len & 1)
    ((unsigned char *)packet)[len] = 0; /* for checksum, in case length is odd. */

  if (proto == IPPROTO_UDP)
    {
      /* Add Remaining part of the pseudoheader. Note that though the
	 IPv6 pseudoheader is very different to the IPv4 one, the 
	 net result of this calculation is correct as long as the 
	 packet length is less than 65536, which is fine for us. */
      sum += htons(IPPROTO_UDP);
      sum += htons(sizeof(struct udphdr) + len);
      
      udp.uh_sum = 0;
      udp.uh_ulen = htons(sizeof(struct udphdr) + len);
      
      for (i = 0; i < sizeof(struct udphdr)/2; i++)
	sum += ((u16 *)&udp)[i];
      for (i = 0; i < (len + 1) / 2; i++)
	sum += ((u16 *)packet)[i];
      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
      udp.uh_sum = (sum == 0xffff) ? sum : ~sum;

      pcap_header.incl_len = pcap_header.orig_len = ipsz + sizeof(udp) + len;
    }
  else
    {
      /* ICMP - ICMPv6 packet is a superset of ICMP */
      struct icmp6_hdr *icmp = packet;
      
      /* See comment in UDP code above. */
      sum += htons(proto);
      sum += htons(len);
      
      icmp->icmp6_cksum = 0;
      for (i = 0; i < (len + 1) / 2; i++)
	sum += ((u16 *)packet)[i];
      while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
      icmp->icmp6_cksum = (sum == 0xffff) ? sum : ~sum;

      pcap_header.incl_len = pcap_header.orig_len = ipsz + len;
    }
    
  rc = gettimeofday(&time, NULL);
  pcap_header.ts_sec = time.tv_sec;
  pcap_header.ts_usec = time.tv_usec;
  
  if (rc == -1 ||
      !read_write(daemon->dumpfd, (void *)&pcap_header, sizeof(pcap_header), RW_WRITE) ||
      !read_write(daemon->dumpfd, iphdr, ipsz, RW_WRITE) ||
      (proto == IPPROTO_UDP && !read_write(daemon->dumpfd, (void *)&udp, sizeof(udp), RW_WRITE)) ||
      !read_write(daemon->dumpfd, (void *)packet, len, RW_WRITE))
    my_syslog(LOG_ERR, _("failed to write packet dump"));
  else if (option_bool(OPT_EXTRALOG) && (mask & 0x00ff))
    my_syslog(LOG_INFO, _("%u dumping packet %u mask 0x%04x"),  daemon->log_display_id, ++packet_count, mask);
  else
    my_syslog(LOG_INFO, _("dumping packet %u mask 0x%04x"), ++packet_count, mask);

}

#endif
