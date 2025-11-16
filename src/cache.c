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
 * @file cache.c
 * @brief DNS cache implementation with hash table, LRU eviction, and multi-source integration
 * 
 * DETAILED PURPOSE:
 * This module implements dnsmasq's core DNS caching subsystem, providing fast local resolution
 * for DNS queries through an in-memory hash table with least-recently-used (LRU) eviction.
 * The cache integrates DNS records from multiple sources: upstream DNS server responses,
 * /etc/hosts file entries, and DHCP lease hostname assignments, creating a unified namespace
 * for DNS resolution. The implementation supports caching of A (IPv4), AAAA (IPv6), CNAME,
 * PTR (reverse lookup), DNSKEY, and DS record types, with per-record TTL tracking and
 * automatic expiration.
 * 
 * KEY RESPONSIBILITIES:
 * - Hash table management: cache_init() initializes hash table and cache structures;
 *   cache_hash() computes hash values for domain names with collision handling via chaining
 * - Cache insertion: cache_start_insert() begins insertion transaction, cache_insert() adds
 *   individual records, really_insert() performs actual insertion with duplicate detection,
 *   cache_end_insert() commits transaction and populates interprocess cache pipe
 * - Cache lookup: cache_find_by_name() locates records by hostname and type,
 *   cache_find_by_addr() performs reverse lookup by IP address, cache_find_non_terminal()
 *   finds intermediate domain nodes for DNSSEC chain validation
 * - LRU eviction: Cache maintains doubly-linked list ordered by last access time; when cache
 *   reaches capacity (CACHESIZ default 150 entries, configurable), least recently used
 *   entries are evicted to make space for new records
 * - /etc/hosts integration: read_hostsfile() parses /etc/hosts and add_hosts_entry() creates
 *   cache records; cache_reload() refreshes cache when hosts file changes (via inotify)
 * - DHCP integration: cache_add_dhcp_entry() registers DHCP-assigned hostnames,
 *   cache_unhash_dhcp() removes expired DHCP entries, a_record_from_hosts() queries DHCP
 *   lease database for hostname-to-IP mappings
 * - Logging and statistics: log_query() generates syslog entries for DNS queries with
 *   configurable verbosity; dump_cache() outputs cache contents on SIGUSR1 signal;
 *   cache_make_stat() generates cache statistics for monitoring
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (core data structures including struct crec, struct daemon, all_addr union)
 * Called by: forward.c (cache_find_by_name, cache_find_by_addr for query resolution),
 *            dnsmasq.c (cache_init during daemon startup, dump_cache for statistics),
 *            lease.c (cache_add_dhcp_entry for DHCP hostname registration),
 *            option.c (cache_reload when configuration changes)
 * Calls: Network functions (inet_ntop for address formatting), utility functions
 *        (sanitise for name validation, prettyprint_addr for address display),
 *        IPC functions for multiprocess cache synchronization, syslog (my_syslog) for logging
 * 
 * DATA STRUCTURES:
 * - struct crec (defined in dnsmasq.h:491): Cache record structure representing a single DNS
 *   cache entry. Contains union for different record types (addr for A/AAAA, cname for CNAME
 *   chains, ds/key for DNSSEC records), TTL expiration time, flags indicating record type
 *   and source, and hash chain pointer for collision resolution. Lifecycle: allocated from
 *   static pool during cache_init(), inserted via really_insert(), accessed via cache_find_*(),
 *   evicted when TTL expires or LRU policy requires space, freed back to pool.
 * - cache_head, cache_tail: Global pointers to doubly-linked LRU list (most recent at head,
 *   least recent at tail). Updated on every cache access to maintain LRU ordering.
 * - hash_table: Global array of struct crec* pointers (size configurable, default 150 buckets).
 *   Hash collisions resolved via chaining through crec->hash_next pointer.
 * - new_chain: Temporary linked list for records added during cache_start_insert() transaction;
 *   committed to main cache and IPC pipe during cache_end_insert()
 * - dhcp_spare: Free list of cache records reserved for DHCP hostname entries (HAVE_DHCP only)
 * - big_free: Free list of union bigname structures for storing long domain names (>SMALLDNAME)
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DHCP: Enables DHCP hostname caching (cache_add_dhcp_entry, cache_unhash_dhcp,
 *   dhcp_spare allocation, a_record_from_hosts integration with lease database)
 * - HAVE_DNSSEC: Enables DNSSEC record caching (DNSKEY, DS record types), DNSSEC validation
 *   status logging (F_DNSSECOK flag), and DNSSEC-specific cache queries
 * - HAVE_AUTH: Enables authoritative DNS mode cache interactions
 * - HAVE_IPSET: Enables ipset firewall integration logging via log_query()
 * - HAVE_NFTSET: Enables nftables set integration logging via log_query()
 * - CACHESIZ: Default cache size (150 entries, defined in config.h:38), overridable via
 *   --cache-size command-line option; setting to 0 disables caching entirely
 * - SMALLDNAME: Short domain name threshold (50 characters, config.h:48); names longer than
 *   this use union bigname allocation from big_free pool to conserve memory
 * 
 * THREADING/CONCURRENCY:
 * Single-process event-driven architecture. Cache operations are not thread-safe but do not
 * require locking due to single-threaded execution model. Interprocess synchronization for
 * cache updates uses IPC pipe (cache_recv_insert sends records to helper processes handling
 * DNSSEC validation and script execution). Cache pipe operations (PIPE_OP_RESULT, PIPE_OP_STATS,
 * PIPE_OP_IPSET, PIPE_OP_NFTSET) coordinate cache visibility across process boundaries without
 * shared memory, preventing race conditions in multiprocess scenarios.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

static struct crec *cache_head = NULL, *cache_tail = NULL, **hash_table = NULL;
#ifdef HAVE_DHCP
static struct crec *dhcp_spare = NULL;
#endif
static struct crec *new_chain = NULL;
static int insert_error;
static union bigname *big_free = NULL;
static int bignames_left, hash_size;

static void make_non_terminals(struct crec *source);
static struct crec *really_insert(char *name, union all_addr *addr, unsigned short class,
				  time_t now,  unsigned long ttl, unsigned int flags);
static void dump_cache_entry(struct crec *cache, time_t now);
static char *querystr(char *desc, unsigned short type);

/* type->string mapping: this is also used by the name-hash function as a mixing table. */
/* taken from https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml */
static const struct {
  unsigned int type;
  const char * const name;
} typestr[] = {
  { 1,   "A" }, /* a host address [RFC1035] */
  { 2,   "NS" }, /* an authoritative name server [RFC1035] */
  { 3,   "MD" }, /* a mail destination (OBSOLETE - use MX) [RFC1035] */
  { 4,   "MF" }, /* a mail forwarder (OBSOLETE - use MX) [RFC1035] */
  { 5,   "CNAME" }, /* the canonical name for an alias [RFC1035] */
  { 6,   "SOA" }, /* marks the start of a zone of authority [RFC1035] */
  { 7,   "MB" }, /* a mailbox domain name (EXPERIMENTAL) [RFC1035] */
  { 8,   "MG" }, /* a mail group member (EXPERIMENTAL) [RFC1035] */
  { 9,   "MR" }, /* a mail rename domain name (EXPERIMENTAL) [RFC1035] */
  { 10,  "NULL" }, /* a null RR (EXPERIMENTAL) [RFC1035] */
  { 11,  "WKS" }, /* a well known service description [RFC1035] */
  { 12,  "PTR" }, /* a domain name pointer [RFC1035] */
  { 13,  "HINFO" }, /* host information [RFC1035] */
  { 14,  "MINFO" }, /* mailbox or mail list information [RFC1035] */
  { 15,  "MX" }, /* mail exchange [RFC1035] */
  { 16,  "TXT" }, /* text strings [RFC1035] */
  { 17,  "RP" }, /* for Responsible Person [RFC1183] */
  { 18,  "AFSDB" }, /* for AFS Data Base location [RFC1183][RFC5864] */
  { 19,  "X25" }, /* for X.25 PSDN address [RFC1183] */
  { 20,  "ISDN" }, /* for ISDN address [RFC1183] */
  { 21,  "RT" }, /* for Route Through [RFC1183] */
  { 22,  "NSAP" }, /* for NSAP address, NSAP style A record [RFC1706] */
  { 23,  "NSAP_PTR" }, /* for domain name pointer, NSAP style [RFC1348][RFC1637][RFC1706] */
  { 24,  "SIG" }, /* for security signature [RFC2535][RFC2536][RFC2537][RFC2931][RFC3008][RFC3110][RFC3755][RFC4034] */
  { 25,  "KEY" }, /* for security key [RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110][RFC3755][RFC4034] */
  { 26,  "PX" }, /* X.400 mail mapping information [RFC2163] */
  { 27,  "GPOS" }, /* Geographical Position [RFC1712] */
  { 28,  "AAAA" }, /* IP6 Address [RFC3596] */
  { 29,  "LOC" }, /* Location Information [RFC1876] */
  { 30,  "NXT" }, /* Next Domain (OBSOLETE) [RFC2535][RFC3755] */
  { 31,  "EID" }, /* Endpoint Identifier [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt] 1995-06*/
  { 32,  "NIMLOC" }, /* Nimrod Locator [1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt] 1995-06*/
  { 33,  "SRV" }, /* Server Selection [1][RFC2782] */
  { 34,  "ATMA" }, /* ATM Address [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.] */
  { 35,  "NAPTR" }, /* Naming Authority Pointer [RFC2168][RFC2915][RFC3403] */
  { 36,  "KX" }, /* Key Exchanger [RFC2230] */
  { 37,  "CERT" }, /* CERT [RFC4398] */
  { 38,  "A6" }, /* A6 (OBSOLETE - use AAAA) [RFC2874][RFC3226][RFC6563] */
  { 39,  "DNAME" }, /* DNAME [RFC6672] */
  { 40,  "SINK" }, /* SINK [Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink] 1997-11*/
  { 41,  "OPT" }, /* OPT [RFC3225][RFC6891] */
  { 42,  "APL" }, /* APL [RFC3123] */
  { 43,  "DS" }, /* Delegation Signer [RFC3658][RFC4034] */
  { 44,  "SSHFP" }, /* SSH Key Fingerprint [RFC4255] */
  { 45,  "IPSECKEY" }, /* IPSECKEY [RFC4025] */
  { 46,  "RRSIG" }, /* RRSIG [RFC3755][RFC4034] */
  { 47,  "NSEC" }, /* NSEC [RFC3755][RFC4034][RFC9077] */
  { 48,  "DNSKEY" }, /* DNSKEY [RFC3755][RFC4034] */
  { 49,  "DHCID" }, /* DHCID [RFC4701] */
  { 50,  "NSEC3" }, /* NSEC3 [RFC5155][RFC9077] */
  { 51,  "NSEC3PARAM" }, /* NSEC3PARAM [RFC5155] */
  { 52,  "TLSA" }, /* TLSA [RFC6698] */
  { 53,  "SMIMEA" }, /* S/MIME cert association [RFC8162] SMIMEA/smimea-completed-template 2015-12-01*/
  { 55,  "HIP" }, /* Host Identity Protocol [RFC8005] */
  { 56,  "NINFO" }, /* NINFO [Jim_Reid] NINFO/ninfo-completed-template 2008-01-21*/
  { 57,  "RKEY" }, /* RKEY [Jim_Reid] RKEY/rkey-completed-template 2008-01-21*/
  { 58,  "TALINK" }, /* Trust Anchor LINK [Wouter_Wijngaards] TALINK/talink-completed-template 2010-02-17*/
  { 59,  "CDS" }, /* Child DS [RFC7344] CDS/cds-completed-template 2011-06-06*/
  { 60,  "CDNSKEY" }, /* DNSKEY(s) the Child wants reflected in DS [RFC7344] 2014-06-16*/
  { 61,  "OPENPGPKEY" }, /* OpenPGP Key [RFC7929] OPENPGPKEY/openpgpkey-completed-template 2014-08-12*/
  { 62,  "CSYNC" }, /* Child-To-Parent Synchronization [RFC7477] 2015-01-27*/
  { 63,  "ZONEMD" }, /* Message Digest Over Zone Data [RFC8976] ZONEMD/zonemd-completed-template 2018-12-12*/
  { 64,  "SVCB" }, /* Service Binding [draft-ietf-dnsop-svcb-https-00] SVCB/svcb-completed-template 2020-06-30*/
  { 65,  "HTTPS" }, /* HTTPS Binding [draft-ietf-dnsop-svcb-https-00] HTTPS/https-completed-template 2020-06-30*/
  { 66,  "DSYNC" }, /* Endpoint discovery for delegation synchronization [draft-ietf-dnsop-generalized-notify-03] DSYNC/dsync-completed-template 2024-12-10 */
  { 67,  "HHIT" }, /* [draft-ietf-drip-registries-28] */
  { 68,  "BRID" }, /* [draft-ietf-drip-registries-28] */
  { 99,  "SPF" }, /* [RFC7208] */
  { 100, "UINFO" }, /* [IANA-Reserved] */
  { 101, "UID" }, /* [IANA-Reserved] */
  { 102, "GID" }, /* [IANA-Reserved] */
  { 103, "UNSPEC" }, /* [IANA-Reserved] */
  { 104, "NID" }, /* [RFC6742] ILNP/nid-completed-template */
  { 105, "L32" }, /* [RFC6742] ILNP/l32-completed-template */
  { 106, "L64" }, /* [RFC6742] ILNP/l64-completed-template */
  { 107, "LP" }, /* [RFC6742] ILNP/lp-completed-template */
  { 108, "EUI48" }, /* an EUI-48 address [RFC7043] EUI48/eui48-completed-template 2013-03-27*/
  { 109, "EUI64" }, /* an EUI-64 address [RFC7043] EUI64/eui64-completed-template 2013-03-27*/
  { 128, "NXNAME" }, /* NXDOMAIN indicator for Compact Denial of Existence https://www.iana.org/go/draft-ietf-dnsop-compact-denial-of-existence-04 */
  { 249, "TKEY" }, /* Transaction Key [RFC2930] */
  { 250, "TSIG" }, /* Transaction Signature [RFC8945] */
  { 251, "IXFR" }, /* incremental transfer [RFC1995] */
  { 252, "AXFR" }, /* transfer of an entire zone [RFC1035][RFC5936] */
  { 253, "MAILB" }, /* mailbox-related RRs (MB, MG or MR) [RFC1035] */
  { 254, "MAILA" }, /* mail agent RRs (OBSOLETE - see MX) [RFC1035] */
  { 255, "ANY" }, /* A request for some or all records the server has available [RFC1035][RFC6895][RFC8482] */
  { 256, "URI" }, /* URI [RFC7553] URI/uri-completed-template 2011-02-22*/
  { 257, "CAA" }, /* Certification Authority Restriction [RFC8659] CAA/caa-completed-template 2011-04-07*/
  { 258, "AVC" }, /* Application Visibility and Control [Wolfgang_Riedel] AVC/avc-completed-template 2016-02-26*/
  { 259, "DOA" }, /* Digital Object Architecture [draft-durand-doa-over-dns] DOA/doa-completed-template 2017-08-30*/
  { 260, "AMTRELAY" }, /* Automatic Multicast Tunneling Relay [RFC8777] AMTRELAY/amtrelay-completed-template 2019-02-06*/
  { 261, "RESINFO" }, /* Resolver Information as Key/Value Pairs https://datatracker.ietf.org/doc/draft-ietf-add-resolver-info/06/ */
  { 262, "WALLET" }, /* Public wallet address https://www.iana.org/assignments/dns-parameters/WALLET/wallet-completed-template */
  { 263, "CLA" }, /*  BP Convergence Layer Adapter https://www.iana.org/go/draft-johnson-dns-ipn-cla-07 */
  { 264, "IPN" }, /* BP Node Number https://www.iana.org/go/draft-johnson-dns-ipn-cla-07 */
  { 32768,  "TA" }, /* DNSSEC Trust Authorities [Sam_Weiler][http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.] 2005-12-13*/
  { 32769,  "DLV" }, /* DNSSEC Lookaside Validation (OBSOLETE) [RFC8749][RFC4431] */
};

static void cache_free(struct crec *crecp);
static void cache_unlink(struct crec *crecp);
static void cache_link(struct crec *crecp);
static void rehash(int size);
static void cache_hash(struct crec *crecp);

/**
 * @brief Convert DNS record type string to numeric type value
 * 
 * Performs case-insensitive lookup of DNS record type name in the typestr
 * mapping table and returns the corresponding numeric RR type code. This
 * function supports all IANA-registered DNS record types defined in the
 * typestr table (A, AAAA, CNAME, PTR, MX, SRV, TXT, etc.).
 * 
 * @param in DNS record type name as null-terminated string (e.g., "A", "aaaa", "CNAME")
 * 
 * @return Numeric DNS RR type code (1 for A, 28 for AAAA, etc.)
 * @retval 0 Record type name not found in mapping table
 * @retval >0 Valid DNS RR type code per IANA assignments
 * 
 * @note Case-insensitive comparison allows mixed-case input ("aaaa" == "AAAA")
 * @note Uses typestr[] static table as both mapping table and hash mixing source
 * 
 * @see typestr[] mapping table (lines 36-144)
 * @see querystr() for reverse mapping (type code to string)
 * 
 * EXAMPLE USAGE:
 * @code
 * unsigned short type = rrtype("AAAA");  // Returns 28
 * if (type == 0) {
 *   // Unknown record type
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: IANA DNS Parameters Registry
 * SIDE EFFECTS: None (read-only table lookup)
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
unsigned short rrtype(char *in)
{
  unsigned int i;
  
  for (i = 0; i < (sizeof(typestr)/sizeof(typestr[0])); i++)
    if (strcasecmp(in, typestr[i].name) == 0)
      return typestr[i].type;

  return 0;
}

/**
 * @brief Assign unique identifier to cache record
 * 
 * Assigns a monotonically increasing unique identifier to a cache record
 * if it does not already have one (uid == UID_NONE). UIDs are used for
 * cache record tracking and identification across cache operations. The
 * UID space wraps to avoid collision with the reserved value UID_NONE (0),
 * which indicates unassigned cache records.
 * 
 * @param crecp Cache record to assign UID (must not be NULL)
 * 
 * @note UID_NONE (0) is RESERVED to indicate unassigned cache records
 * @note UID wraps from UID_NONE-1 back to 1 to avoid reserved value
 * @note Only assigns UID if crecp->uid == UID_NONE (idempotent)
 * @warning crecp parameter must not be NULL
 * 
 * @see struct crec in dnsmasq.h - cache record structure with uid member
 * @see UID_NONE constant definition
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *cache_entry = safe_malloc(sizeof(struct crec));
 * cache_entry->uid = UID_NONE;  // Initialize to unassigned
 * next_uid(cache_entry);         // Assigns unique ID
 * @endcode
 * 
 * SIDE EFFECTS: Increments static uid counter, modifies crecp->uid
 * THREAD SAFETY: NOT thread-safe (static variable, single-threaded architecture)
 */
void next_uid(struct crec *crecp)
{
  static unsigned int uid = 0;

  if (crecp->uid == UID_NONE)
    {
      uid++;
  
      /* uid == 0 used to indicate CNAME to interface name. */
      if (uid == UID_NONE)
	uid++;
      
      crecp->uid = uid;
    }
}

/**
 * @brief Initialize DNS cache system at daemon startup
 * 
 * Allocates and initializes the main DNS cache structure including cache
 * record array and hash table. Creates daemon->cachesize cache records,
 * links them into the free list, and establishes the initial hash table.
 * Reserves 10% of cache size for "bigname" storage (long DNS names).
 * 
 * Cache records are allocated as a single contiguous array for memory
 * efficiency. Each record is initialized with flags=0 and uid=UID_NONE,
 * then linked into the cache free list via cache_link(). The hash table
 * is created with size based on cache capacity (power of 2, at least 64).
 * 
 * @note Must be called once at daemon startup before any cache operations
 * @note Cache size configured via --cache-size option (default CACHESIZ=150)
 * @note Bigname allocation: 10% of cache size reserved for long DNS names
 * @warning Calls safe_malloc() which terminates on allocation failure
 * 
 * @see daemon->cachesize configuration parameter
 * @see cache_link() to add record to free list
 * @see rehash() to create initial hash table
 * @see struct crec cache record structure
 * 
 * EXAMPLE USAGE:
 * @code
 * daemon->cachesize = 150;  // Configure cache size
 * cache_init();              // Initialize cache system
 * // Cache ready for cache_insert(), cache_find_by_name() operations
 * @endcode
 * 
 * SIDE EFFECTS: Allocates daemon->cachesize * sizeof(struct crec) memory
 * SIDE EFFECTS: Sets bignames_left global variable
 * SIDE EFFECTS: Creates hash table via rehash()
 * THREAD SAFETY: NOT thread-safe (modifies global cache state)
 */
void cache_init(void)
{
  struct crec *crecp;
  int i;
 
  bignames_left = daemon->cachesize/10;
  
  if (daemon->cachesize > 0)
    {
      crecp = safe_malloc(daemon->cachesize*sizeof(struct crec));
      
      for (i=0; i < daemon->cachesize; i++, crecp++)
	{
	  cache_link(crecp);
	  crecp->flags = 0;
	  crecp->uid = UID_NONE;
	}
    }
  
  /* create initial hash table*/
  rehash(daemon->cachesize);
}

/* In most cases, we create the hash table once here by calling this with (hash_table == NULL)
   but if the hosts file(s) are big (some people have 50000 ad-block entries), the table
   will be much too small, so the hosts reading code calls rehash every 1000 addresses, to
   expand the table. */

/**
 * @brief Expand DNS cache hash table to accommodate more entries
 * 
 * Creates a new hash table sized as a power of 2 (minimum 64, sized for
 * size/10 entries to provide overprovisioning) and rehashes all existing
 * cache entries from the old table into the new table. Called during
 * cache initialization and dynamically when hosts files contain thousands
 * of entries (every ENTRY_CHUNK=1000 hosts file entries).
 * 
 * The hash table is chained (linked list per bucket) so performance
 * degrades gracefully under high load, but larger tables improve lookup
 * efficiency. For ad-blocker configurations with 50000+ hosts entries,
 * the table expands dynamically to maintain performance.
 * 
 * @param size Desired cache capacity (table sized for size/10 entries)
 * 
 * @note Hash table size is always a power of 2 (64, 128, 256, 512, ...)
 * @note Minimum table size is 64 entries
 * @note First allocation uses safe_malloc() (terminates on failure)
 * @note Subsequent expansions use whine_malloc() (logs warning, non-fatal)
 * @note Only expands table (never shrinks) - returns silently if new_size <= hash_size
 * @warning First call must succeed or daemon terminates
 * 
 * @see hash_bucket() for hash function
 * @see cache_hash() to insert entry into hash table
 * @see ENTRY_CHUNK constant for hosts file batching
 * 
 * EXAMPLE USAGE:
 * @code
 * cache_init();           // Creates initial 64-entry table
 * rehash(1000);           // Expand to 128 entries (next power of 2 >= 1000/10)
 * rehash(10000);          // Expand to 1024 entries for large hosts file
 * @endcode
 * 
 * SIDE EFFECTS: Allocates new hash table, rehashes all entries, frees old table
 * SIDE EFFECTS: Updates global hash_table and hash_size variables
 * THREAD SAFETY: NOT thread-safe (modifies global hash table)
 */
static void rehash(int size)
{
  struct crec **new, **old, *p, *tmp;
  int i, new_size, old_size;

  /* hash_size is a power of two. */
  for (new_size = 64; new_size < size/10; new_size = new_size << 1);
  
  /* must succeed in getting first instance, failure later is non-fatal */
  if (!hash_table)
    new = safe_malloc(new_size * sizeof(struct crec *));
  else if (new_size <= hash_size || !(new = whine_malloc(new_size * sizeof(struct crec *))))
    return;

  for (i = 0; i < new_size; i++)
    new[i] = NULL;

  old = hash_table;
  old_size = hash_size;
  hash_table = new;
  hash_size = new_size;
  
  if (old)
    {
      for (i = 0; i < old_size; i++)
	for (p = old[i]; p ; p = tmp)
	  {
	    tmp = p->hash_next;
	    cache_hash(p);
	  }
      free(old);
    }
}
  
/**
 * @brief Compute hash bucket pointer for a domain name
 * 
 * Calculates hash value for a domain name using a case-insensitive hash
 * function with the typestr table as a mixing table. Returns pointer to
 * the hash bucket (linked list head) in the global hash_table array.
 * 
 * The hash function uses Barker code (017465 = 0x3F35) as initial value
 * for minimum self-correlation in cyclic shift. Each character is converted
 * to lowercase (manual ASCII conversion to avoid locale issues), mixed with
 * typestr table values, and combined using rotate-left-7 and XOR operations.
 * Final hash is folded with 16-bit XOR and masked to hash_size-1 (power of 2).
 * 
 * @param name Domain name to hash (null-terminated string)
 * 
 * @return Pointer to hash bucket (struct crec **) in hash_table array
 * 
 * @note Hash function is case-insensitive (converts A-Z to a-z)
 * @note Uses manual case conversion to avoid locale dependency
 * @note typestr table provides additional mixing beyond character values
 * @note Hash table size must be a power of 2 for efficient masking
 * @warning Name must not be NULL
 * 
 * @see rehash() to allocate/expand hash table
 * @see cache_hash() to insert entry into computed bucket
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec **bucket = hash_bucket("example.com");
 * // bucket now points to linked list head for this name's hash
 * @endcode
 * 
 * RFC COMPLIANCE: Case-insensitive DNS name comparison per RFC 1035 Section 3.1
 * SIDE EFFECTS: None (pure function)
 * THREAD SAFETY: Thread-safe (no global state modification)
 */
static struct crec **hash_bucket(char *name)
{
  unsigned int c, val = 017465; /* Barker code - minimum self-correlation in cyclic shift */
  const unsigned char *mix_tab = (const unsigned char*)typestr; 

  while((c = (unsigned char) *name++))
    {
      /* don't use tolower and friends here - they may be messed up by LOCALE */
      if (c >= 'A' && c <= 'Z')
	c += 'a' - 'A';
      val = ((val << 7) | (val >> (32 - 7))) + (mix_tab[(val + c) & 0x3F] ^ c);
    } 
  
  /* hash_size is a power of two */
  return hash_table + ((val ^ (val >> 16)) & (hash_size - 1));
}

/**
 * @brief Insert cache record into hash table with ordering invariants
 * 
 * Inserts a cache record into the hash chain while maintaining strict ordering
 * invariants: F_REVERSE entries at chain start, F_IMMORTAL entries at chain end.
 * This ordering enables optimized reverse searches and efficient garbage collection
 * by grouping entries with similar lifecycle characteristics. Preserves insertion
 * order for entries with identical names and flags.
 * 
 * @param crecp Cache record to insert into hash table (must not be NULL)
 * 
 * HASH CHAIN ORDERING INVARIANT:
 * 1. F_REVERSE entries (reverse lookup PTR records) at chain head
 * 2. Regular entries in middle
 * 3. F_IMMORTAL entries (from /etc/hosts) at chain tail
 * 
 * ORDERING BENEFITS:
 * - Reverse searches can stop at first non-F_REVERSE entry
 * - Garbage collection can skip F_IMMORTAL entries at chain end
 * - Same-name entries maintain insertion order within flag groups
 * 
 * SIDE EFFECTS:
 * - Modifies hash_table structure via hash_bucket pointer manipulation
 * - Sets crecp->hash_next to link into chain
 * 
 * THREAD SAFETY: Not thread-safe, assumes single-threaded event loop
 * 
 * Source: /src/cache.c:506
 */
/**
 * @brief Insert cache record into hash table with ordering invariants
 * 
 * Inserts a cache record into the appropriate hash bucket while maintaining critical
 * ordering invariants: all F_REVERSE entries at chain start, all non-reverse immortal
 * entries at chain end, and preservation of insertion order for same-name entries.
 * These invariants optimize reverse DNS lookups and garbage collection operations.
 * 
 * The hash chain ordering enables efficient operations:
 * - Reverse DNS searches can stop at the first non-F_REVERSE entry
 * - Garbage collection can skip immortal entries at the end of chains
 * - Multiple entries for the same name maintain insertion order
 * 
 * @param crecp Cache record to insert into hash table (must not be NULL)
 * 
 * @note This is a static function called by cache_insert(), cache_reload(), and other
 *       cache management operations after record creation
 * @warning Assumes crecp is properly initialized with valid name and flags
 * @warning Does not check for duplicate entries - caller must handle deduplication
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *new_rec = cache_insert(...);
 * cache_hash(new_rec);  // Insert into appropriate hash bucket
 * @endcode
 * 
 * HASH CHAIN INVARIANTS:
 * 1. All F_REVERSE entries appear first in chain (enables early-exit for forward lookups)
 * 2. Non-reverse F_IMMORTAL entries appear last (protects from garbage collection)
 * 3. Same-name entries with identical flags maintain insertion order (deterministic behavior)
 * 
 * SIDE EFFECTS: Modifies hash table structure by updating hash_next pointers
 * THREAD SAFETY: Not thread-safe - relies on single-threaded event loop architecture
 * 
 * Source: /src/cache.c:535
 */
static void cache_hash(struct crec *crecp)
{
  /* maintain an invariant that all entries with F_REVERSE set
     are at the start of the hash-chain  and all non-reverse
     immortal entries are at the end of the hash-chain.
     This allows reverse searches and garbage collection to be optimised */

  char *name = cache_get_name(crecp);
  struct crec **up = hash_bucket(name);
  unsigned int flags = crecp->flags & (F_IMMORTAL | F_REVERSE);
  
  if (!(flags & F_REVERSE))
    {
      while (*up && ((*up)->flags & F_REVERSE))
	up = &((*up)->hash_next); 
      
      if (flags & F_IMMORTAL)
	while (*up && !((*up)->flags & F_IMMORTAL))
	  up = &((*up)->hash_next);
    }

  /* Preserve order when inserting the same name multiple times.
     Do not mess up the flag invariants. */
  while (*up &&
	 hostname_isequal(cache_get_name(*up), name) &&
	 flags == ((*up)->flags & (F_IMMORTAL | F_REVERSE)))
    up = &((*up)->hash_next);
  
  crecp->hash_next = *up;
  *up = crecp;
}

/**
 * @brief Free blockdata storage associated with a cache record
 * 
 * Releases variable-length blockdata storage for DNS resource records that use
 * blockdata chains for efficient memory management. Handles different record types
 * including generic RR records with KEYTAG and DNSSEC-specific records (DNSKEY, DS).
 * Only processes positive cache entries; negative cache entries have no blockdata.
 * 
 * @param crecp Cache record whose blockdata should be freed (must not be NULL)
 * 
 * @note This is a static helper function called by cache_free() and cache cleaning operations
 * @warning Does not free the cache record itself, only associated blockdata storage
 * 
 * SIDE EFFECTS:
 * - Calls blockdata_free() which returns memory to blockdata pool
 * - Does not modify the cache record structure itself
 * 
 * THREAD SAFETY: Single-threaded architecture; assumes exclusive access to cache record
 */
static void cache_blockdata_free(struct crec *crecp)
{
  if (!(crecp->flags & F_NEG))
    {
      if ((crecp->flags & F_RR) && (crecp->flags & F_KEYTAG))
	blockdata_free(crecp->addr.rrblock.rrdata);
#ifdef HAVE_DNSSEC
      else if (crecp->flags & F_DNSKEY)
	blockdata_free(crecp->addr.key.keydata);
      else if (crecp->flags & F_DS)
	blockdata_free(crecp->addr.ds.keydata);
#endif
    }
}

/**
 * @brief Free a cache record and return it to the free list
 * 
 * Moves a cache record to the free list (tail of LRU chain) for reuse by future
 * cache insertions. Clears forward/reverse mapping flags, invalidates UID to break
 * CNAME chains pointing to this record, recovers bigname storage for reuse, and
 * frees associated blockdata storage. This implements the cache eviction mechanism
 * where least-recently-used entries are recycled rather than deallocated.
 * 
 * @param crecp Cache record to free (must not be NULL, must be valid cache entry)
 * 
 * @note This is a static helper function used by cache eviction and cleanup logic
 * @warning Does not remove record from hash table; caller must unhash before freeing
 * @see cache_blockdata_free() for blockdata cleanup details
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *old_entry = cache_find_by_name(...);
 * cache_unlink(old_entry);  // Remove from hash table
 * cache_free(old_entry);     // Return to free list
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Moves cache record to tail of LRU chain (free list)
 * - Clears F_FORWARD and F_REVERSE flags
 * - Sets UID to UID_NONE (invalidates CNAME references)
 * - Returns bigname storage to big_free pool if F_BIGNAME set
 * - Calls cache_blockdata_free() to release blockdata storage
 * 
 * THREAD SAFETY: Single-threaded architecture; modifies global cache_head and cache_tail
 */
static void cache_free(struct crec *crecp)
{
  crecp->flags &= ~F_FORWARD;
  crecp->flags &= ~F_REVERSE;
  crecp->uid = UID_NONE; /* invalidate CNAMES pointing to this. */

  if (cache_tail)
    cache_tail->next = crecp;
  else
    cache_head = crecp;
  crecp->prev = cache_tail;
  crecp->next = NULL;
  cache_tail = crecp;
  
  /* retrieve big name for further use. */
  if (crecp->flags & F_BIGNAME)
    {
      crecp->name.bname->next = big_free;
      big_free = crecp->name.bname;
      crecp->flags &= ~F_BIGNAME;
    }

  cache_blockdata_free(crecp);
}    

/* insert a new cache entry at the head of the list (youngest entry) */
/**
 * @brief Link a cache record to the head of the LRU chain
 * 
 * Inserts a cache record at the head of the doubly-linked LRU chain, marking it as
 * most-recently-used. This function maintains the LRU eviction policy where the head
 * contains the most recent entry and the tail contains the oldest entry. Called when
 * a cache entry is accessed or newly created to update its position in the LRU order.
 * 
 * @param crecp Cache record to link to head (must not be NULL)
 * 
 * @note This is a static helper function for LRU chain management
 * @warning Assumes crecp is not currently in the chain (caller must unlink first if reordering)
 * @see cache_unlink() for removing entries from the LRU chain
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *new_entry = cache_tail;  // Reuse oldest entry
 * cache_unlink(new_entry);              // Remove from current position
 * // ... populate entry with new data ...
 * cache_link(new_entry);                // Move to head as most-recently-used
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Updates cache_head to point to crecp
 * - Updates cache_tail if chain was previously empty
 * - Modifies prev pointer of previous cache_head
 * - Sets crecp->next and crecp->prev pointers
 * 
 * THREAD SAFETY: Single-threaded architecture; modifies global cache_head and cache_tail
 */
static void cache_link(struct crec *crecp)
{
  if (cache_head) /* check needed for init code */
    cache_head->prev = crecp;
  crecp->next = cache_head;
  crecp->prev = NULL;
  cache_head = crecp;
  if (!cache_tail)
    cache_tail = crecp;
}

/* remove an arbitrary cache entry for promotion */ 
/**
 * @brief Unlink a cache record from the LRU chain
 * 
 * Removes a cache record from the doubly-linked LRU chain by updating the prev/next
 * pointers of adjacent entries. This function is called before repositioning an entry
 * in the LRU order (e.g., moving accessed entry to head) or before freeing an entry.
 * Handles edge cases where entry is at head, tail, or both (single-entry chain).
 * 
 * @param crecp Cache record to unlink (must not be NULL, must be in LRU chain)
 * 
 * @note This is a static helper function for LRU chain management
 * @warning Does not free memory or clear entry data; only removes from chain
 * @see cache_link() for inserting entries into the LRU chain
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *entry = cache_find_by_name(...);
 * cache_unlink(entry);   // Remove from current position
 * cache_link(entry);     // Re-insert at head as most-recently-used
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Updates cache_head if crecp was at head
 * - Updates cache_tail if crecp was at tail
 * - Updates prev->next pointer of previous entry
 * - Updates next->prev pointer of next entry
 * - Does NOT modify crecp->prev or crecp->next pointers
 * 
 * THREAD SAFETY: Single-threaded architecture; modifies global cache_head and cache_tail
 */
static void cache_unlink (struct crec *crecp)
{
  if (crecp->prev)
    crecp->prev->next = crecp->next;
  else
    cache_head = crecp->next;

  if (crecp->next)
    crecp->next->prev = crecp->prev;
  else
    cache_tail = crecp->prev;
}

/**
 * @brief Get the hostname associated with a cache record
 * 
 * Retrieves the hostname string from a cache record, handling the three different
 * name storage mechanisms: big names (heap-allocated for long names), name pointer
 * (reference to external string), and short name (inline storage). The function
 * abstracts the storage details, always returning a pointer to the name string.
 * 
 * @param crecp Cache record containing name (must not be NULL)
 * 
 * @return Pointer to hostname string (never NULL for valid cache entries)
 * @retval name.bname->name If F_BIGNAME flag set (name exceeds SMALLDNAME bytes)
 * @retval name.namep If F_NAMEP flag set (name stored externally, e.g., from /etc/hosts)
 * @retval name.sname Default case (name stored inline in crec structure)
 * 
 * @note Returned pointer remains valid as long as cache entry exists
 * @warning Do not free returned pointer; memory managed by cache subsystem
 * @see cache_insert() for name storage allocation logic
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *entry = cache_find_by_name(...);
 * if (entry) {
 *   char *hostname = cache_get_name(entry);
 *   my_syslog(LOG_INFO, "Found cached entry for %s", hostname);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Name storage supports DNS name length limits (RFC 1035 Section 2.3.4: labels ≤63 bytes, total ≤255 bytes)
 * SIDE EFFECTS: None (read-only access to cache entry)
 * THREAD SAFETY: Single-threaded architecture; safe if cache entry not concurrently freed
 */
char *cache_get_name(struct crec *crecp)
{
  if (crecp->flags & F_BIGNAME)
    return crecp->name.bname->name;
  else if (crecp->flags & F_NAMEP) 
    return crecp->name.namep;
  
  return crecp->name.sname;
}

/**
 * @brief Get the target hostname for a CNAME cache record
 * 
 * Retrieves the canonical name target from a CNAME cache entry, handling both
 * direct name pointers (string stored in cache entry) and indirect cache pointers
 * (reference to another cache entry). This function is specific to CNAME records
 * where the addr.cname union stores the target domain name.
 * 
 * @param crecp CNAME cache record (must have F_CNAME flag set, must not be NULL)
 * 
 * @return Pointer to target hostname string
 * @retval addr.cname.target.name If is_name_ptr is true (target stored as string)
 * @retval Result of cache_get_name(target.cache) If is_name_ptr is false (target is cache entry reference)
 * 
 * @note Only valid for CNAME cache entries with F_CNAME flag set
 * @warning Caller must verify crecp is a CNAME record before calling
 * @see cache_get_name() for name extraction from cache entries
 * @see struct crec definition in dnsmasq.h for addr.cname union structure
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *cname_entry = cache_find_by_name(...);
 * if (cname_entry && (cname_entry->flags & F_CNAME)) {
 *   char *target = cache_get_cname_target(cname_entry);
 *   my_syslog(LOG_INFO, "CNAME points to %s", target);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Supports CNAME RR semantics (RFC 1035 Section 3.3.1)
 * SIDE EFFECTS: None (read-only access)
 * THREAD SAFETY: Single-threaded architecture; safe if cache entries not concurrently modified
 */
char *cache_get_cname_target(struct crec *crecp)
{
  if (crecp->addr.cname.is_name_ptr)
     return crecp->addr.cname.target.name;
  else
    return cache_get_name(crecp->addr.cname.target.cache);
}



/**
 * @brief Enumerate all cache entries using iterator pattern
 * 
 * Provides iteration over all cache entries in the hash table, using static state
 * to maintain position between calls. The function traverses each hash bucket
 * sequentially, following hash_next chains within each bucket. Caller must invoke
 * with init=1 to start iteration, then repeatedly with init=0 until NULL returned.
 * 
 * @param init Iterator control flag
 *             - 1: Initialize iteration (start from beginning)
 *             - 0: Continue iteration from previous position
 * 
 * @return Pointer to next cache entry, or NULL when iteration complete
 * @retval struct crec* Next cache entry in traversal order
 * @retval NULL All cache entries enumerated (no more entries in any bucket)
 * 
 * @note Uses static variables to maintain state between calls (not re-entrant)
 * @warning NOT thread-safe and NOT re-entrant; only one enumeration at a time
 * @warning Cache modifications during enumeration may cause skipped or duplicate entries
 * @see cache_hash() for hash table organization
 * @see dump_cache() for usage example with this iterator
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *crecp;
 * for (crecp = cache_enumerate(1); crecp; crecp = cache_enumerate(0))
 * {
 *   char *name = cache_get_name(crecp);
 *   my_syslog(LOG_INFO, "Cache entry: %s", name);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal cache traversal mechanism)
 * SIDE EFFECTS: Modifies static variables bucket and cache for iteration state
 * THREAD SAFETY: NOT thread-safe due to static state; single-threaded architecture only
 */
struct crec *cache_enumerate(int init)
{
  static int bucket;
  static struct crec *cache;

  if (init)
    {
      bucket = 0;
      cache = NULL;
    }
  else if (cache && cache->hash_next)
    cache = cache->hash_next;
  else
    {
       cache = NULL; 
       while (bucket < hash_size)
	 if ((cache = hash_table[bucket++]))
	   break;
    }
  
  return cache;
}

/**
 * @brief Check if a CNAME cache pointer reference is outdated
 * 
 * Validates whether a CNAME cache entry's target cache pointer is still valid.
 * CNAME records can reference other cache entries via pointers, but those targets
 * may be evicted and replaced with different records. This function uses unique
 * identifiers (uid) to detect when the target cache entry has been replaced,
 * indicating the CNAME pointer is stale and needs updating.
 * 
 * @param crecp Cache record to check (may be NULL, any cache entry type)
 * 
 * @return Validity status of CNAME target pointer
 * @retval 0 Pointer is valid (not CNAME, name pointer type, or uid matches target)
 * @retval 1 Pointer is outdated (target cache entry replaced, uid mismatch)
 * 
 * @note Only applies to CNAME entries with cache pointer targets (not name pointers)
 * @note Cache records can be reused: DS/DNSKEY reuse uid field differently
 * @warning Outdated pointers must be converted to name pointers to prevent dangling references
 * @see cache_scan_free() which uses this to detect and fix stale CNAME pointers
 * @see next_uid() for uid generation ensuring uniqueness after entry replacement
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec *cname_entry = ...;
 * if (is_outdated_cname_pointer(cname_entry))
 * {
 *   // Convert cache pointer to name pointer to prevent dangling reference
 *   convert_to_name_pointer(cname_entry);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal cache consistency mechanism)
 * SIDE EFFECTS: None (read-only check)
 * THREAD SAFETY: Single-threaded architecture; safe if cache not concurrently modified
 */
static int is_outdated_cname_pointer(struct crec *crecp)
{
  if (!(crecp->flags & F_CNAME) || crecp->addr.cname.is_name_ptr)
    return 0;
  
  /* NB. record may be reused as DS or DNSKEY, where uid is 
     overloaded for something completely different */
  if (crecp->addr.cname.target.cache && 
      !(crecp->addr.cname.target.cache->flags & (F_DNSKEY | F_DS)) &&
      crecp->addr.cname.uid == crecp->addr.cname.target.cache->uid)
    return 0;
  
  return 1;
}

/**
 * @brief Determine if a cache entry has expired and should be evicted
 * 
 * Evaluates whether a cache entry is expired based on its TTD (time-to-die) timestamp
 * and the configured cache expiry policy. The function implements approximate LRU behavior
 * by allowing expired entries to remain cached within a configured tolerance window,
 * reducing upstream query load. Special handling prevents serving expired DNSSEC records
 * (DS/DNSKEY) which must be fresh for security validation.
 * 
 * @param now Current time (seconds since epoch)
 * @param crecp Cache record to check (must not be NULL)
 * 
 * @return Expiration status
 * @retval 0 Entry is NOT expired (should be retained in cache)
 * @retval 1 Entry IS expired (eligible for eviction)
 * 
 * @note Expiration policy controlled by daemon->cache_max_expiry:
 *       -1: Serve cached content regardless of age (infinite tolerance)
 *        0: Strict expiration (expired content never served)
 *       >0: Tolerance window in seconds (serve if expired less than N seconds ago)
 * @note F_IMMORTAL entries never expire (static hosts, DHCP reservations)
 * @warning DNSSEC entries (DS, DNSKEY) always expire strictly (security requirement)
 * @see cache_scan_free() which uses this to identify eviction candidates
 * @see difftime() for TTD comparison (handles time_t arithmetic)
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * struct crec *entry = cache_find_by_name(...);
 * if (entry && is_expired(now, entry))
 * {
 *   // Entry expired, eligible for LRU eviction
 *   cache_scan_free(entry->name.sname, NULL, now, F_FORWARD, 0);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: TTL semantics per RFC 1035 Section 4.1.3 (TTL zero means no caching)
 * SIDE EFFECTS: None (read-only expiration check)
 * THREAD SAFETY: Single-threaded architecture; safe if cache not concurrently modified
 */
static int is_expired(time_t now, struct crec *crecp)
{
  /* Don't dump expired entries if they are within the accepted timeout range.
     The cache becomes approx. LRU. Never use expired DS or DNSKEY entries.
     Possible values for daemon->cache_max_expiry:
      -1  == serve cached content regardless how long ago it expired
       0  == the option is disabled, expired content isn't served
      <n> == serve cached content only if it expire less than <n> seconds
             ago (where n is a positive integer) */
  if (daemon->cache_max_expiry != 0 &&
      (daemon->cache_max_expiry == -1 ||
       difftime(now, crecp->ttd) < daemon->cache_max_expiry) &&
      !(crecp->flags & (F_DS | F_DNSKEY)))
    return 0;

  if (crecp->flags & F_IMMORTAL)
    return 0;

  if (difftime(now, crecp->ttd) < 0)
    return 0;
  
  return 1;
}

/* Remove entries with a given UID from the cache */
/**
 * @brief Remove all cache entries associated with a specific UID
 * 
 * Scans the entire cache hash table and removes all entries (HOSTS, DHCP, CONFIG)
 * that match the specified UID. This function is used when configuration sources
 * (such as dynamically managed host files) are updated or removed, requiring
 * cleanup of all associated cache entries. The function preserves hash table
 * integrity by properly unlinking entries from their hash chains.
 * 
 * @param uid Unique identifier for configuration source to remove (non-zero values)
 * 
 * @return Number of cache entries removed
 * 
 * @note Only removes entries with F_HOSTS, F_DHCP, or F_CONFIG flags
 * @note Iterates entire hash table (all hash_size buckets), O(n) operation
 * @note Freed entries are permanently removed (not moved to free list)
 * @warning Caller must ensure UID corresponds to inactive/removed configuration
 * @see next_uid() for UID allocation strategy
 * @see cache_scan_free() for alternative expiration-based cache cleanup
 * 
 * EXAMPLE USAGE:
 * @code
 * // Configuration file /etc/hosts.dynamic with UID 42 was removed
 * unsigned int count = cache_remove_uid(42);
 * my_syslog(LOG_INFO, "removed %u cache entries for UID %u", count, 42);
 * // All 'struct crec' entries with uid==42 are now freed
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal cache management, not protocol-visible)
 * SIDE EFFECTS: Frees memory for matching cache entries, modifies hash table structure
 * THREAD SAFETY: Single-threaded architecture; not safe for concurrent access
 */
unsigned int cache_remove_uid(const unsigned int uid)
{
  int i;
  unsigned int removed = 0;
  struct crec *crecp, *tmp, **up;

  for (i = 0; i < hash_size; i++)
    for (crecp = hash_table[i], up = &hash_table[i]; crecp; crecp = tmp)
      {
	tmp = crecp->hash_next;
	if ((crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) && crecp->uid == uid)
	  {
	    *up = tmp;
	    free(crecp);
	    removed++;
	  }
	else
	  up = &crecp->hash_next;
      }
  
  return removed;
}

/**
 * @brief Scan cache and remove entries matching criteria, preserving immortal entries
 * 
 * Performs selective cache entry removal based on flags, handling forward lookups (by name),
 * reverse lookups (by address), and general expiration cleanup. This function implements the
 * cache eviction policy while preserving permanent entries from hosts file, DHCP leases, and
 * configuration. Special handling preserves CNAME target integrity during removal operations.
 * 
 * @param name Hostname for forward lookup matching (used when flags & F_FORWARD)
 * @param addr IP address for reverse lookup matching (used when flags & F_REVERSE)
 * @param class DNS class for DNSSEC class-sensitive deletion (DS/DNSKEY records)
 * @param now Current timestamp for expiration checks
 * @param flags Operation mode flags controlling scan behavior:
 *              - F_FORWARD: Remove forward entries for name and expired entries in same hash bucket
 *              - F_REVERSE: Remove reverse entries for addr and all expired entries
 *              - 0: Remove only expired entries across entire cache
 *              - F_IPV4/F_IPV6: Address family for matching
 *              - F_NXDOMAIN: Match NXDOMAIN entries
 *              - F_CNAME: Match CNAME entries
 *              - F_RR: Match generic RR entries with type checking
 * @param target_crec Output parameter: If non-NULL and a CNAME target is freed, receives the crec pointer
 *                    for reuse with same name to preserve CNAME references
 * @param target_uid Output parameter: If non-NULL and a CNAME target is freed, receives the UID for
 *                   preserving CNAME target identity across re-insertion
 * 
 * @return Pointer to immortal cache entry (F_HOSTS/F_DHCP/F_CONFIG) if name exists in forward mode,
 *         NULL otherwise. Immortal entries are never deleted, only reported.
 * 
 * @note Hash chain ordering assumption: entries ordered as <reverse>, <other>, <immortal>
 *       allowing early termination when immortal non-reverse entry encountered
 * @note Freed entries are unlinked from LRU chain and hash bucket before deallocation
 * @note DNSSEC records (F_DNSKEY, F_DS) use class-sensitive deletion matching
 * 
 * ALGORITHM:
 * Forward mode (F_FORWARD):
 *   1. Scan only hash bucket for given name
 *   2. Remove matching entries for name with compatible flags (IP type, NXDOMAIN, CNAME)
 *   3. Remove expired or outdated CNAME pointer entries
 *   4. Preserve immortal entries (F_HOSTS, F_DHCP, F_CONFIG) and return first match
 *   5. Handle CNAME target preservation via target_crec/target_uid output parameters
 *   6. DNSSEC: Remove DS/DNSKEY only if class matches
 * 
 * Reverse mode (F_REVERSE):
 *   1. Scan all hash buckets (entire cache)
 *   2. Remove expired entries throughout cache
 *   3. Remove reverse entries matching address and address family
 *   4. Stop at immortal non-reverse entries per hash chain ordering
 * 
 * Expiration-only mode (flags == 0):
 *   1. Scan all hash buckets
 *   2. Remove only expired entries, preserving all active entries
 * 
 * SIDE EFFECTS:
 * - Modifies hash bucket chains by removing entries
 * - Modifies LRU chain via cache_unlink()
 * - Frees memory for removed non-immortal entries via cache_free()
 * - May populate target_crec and target_uid for CNAME target preservation
 * 
 * THREAD SAFETY: Single-threaded architecture, no synchronization required
 * 
 * RFC COMPLIANCE: Cache management per DNS caching requirements (RFC 1035)
 * 
 * @see cache_free() for entry deallocation
 * @see cache_unlink() for LRU chain removal
 * @see is_expired() for TTL-based expiration check
 * @see is_outdated_cname_pointer() for CNAME validity check
 * @see hash_bucket() for hash bucket selection
 */
static struct crec *cache_scan_free(char *name, union all_addr *addr, unsigned short class, time_t now,
				    unsigned int flags, struct crec **target_crec, unsigned int *target_uid)
{
  /* Scan and remove old entries.
     If (flags & F_FORWARD) then remove any forward entries for name and any expired
     entries but only in the same hash bucket as name.
     If (flags & F_REVERSE) then remove any reverse entries for addr and any expired
     entries in the whole cache.
     If (flags == 0) remove any expired entries in the whole cache. 

     In the flags & F_FORWARD case, the return code is valid, and returns a non-NULL pointer
     to a cache entry if the name exists in the cache as a HOSTS or DHCP entry (these are never deleted)

     We take advantage of the fact that hash chains have stuff in the order <reverse>,<other>,<immortal>
     so that when we hit an entry which isn't reverse and is immortal, we're done. 

     If we free a crec which is a CNAME target, return the entry and uid in target_crec and target_uid.
     This entry will get re-used with the same name, to preserve CNAMEs. */
 
  struct crec *crecp, **up;

  (void)class;
  
  if (flags & F_FORWARD)
    {
      for (up = hash_bucket(name), crecp = *up; crecp; crecp = crecp->hash_next)
	{
	  if ((crecp->flags & F_FORWARD) && hostname_isequal(cache_get_name(crecp), name))
	    {
	      int rrmatch = 0;
	      if (addr && (crecp->flags & flags & F_RR))
		{
		  unsigned short rrc = (crecp->flags & F_KEYTAG) ? crecp->addr.rrblock.rrtype : crecp->addr.rrdata.rrtype;
		  unsigned short rra = (flags & F_KEYTAG) ? addr->rrblock.rrtype : addr->rrdata.rrtype;

		  if (rrc == rra)
		    rrmatch = 1;
		}

	      /* Don't delete DNSSEC in favour of a CNAME, they can co-exist */
	      if ((flags & crecp->flags & (F_IPV4 | F_IPV6 | F_NXDOMAIN)) || 
		  (((crecp->flags | flags) & F_CNAME) && !(crecp->flags & (F_DNSKEY | F_DS))) ||
		  rrmatch)
		{
		  if (crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))
		    return crecp;
		  *up = crecp->hash_next;
		  /* If this record is for the name we're inserting and is the target
		     of a CNAME record. Make the new record for the same name, in the same
		     crec, with the same uid to avoid breaking the existing CNAME. */
		  if (crecp->uid != UID_NONE)
		    {
		      if (target_crec)
			*target_crec = crecp;
		      if (target_uid)
			*target_uid = crecp->uid;
		    }
		  cache_unlink(crecp);
		  cache_free(crecp);
		  continue;
		}
	      
#ifdef HAVE_DNSSEC
	      /* Deletion has to be class-sensitive for DS and DNSKEY */
	      if ((flags & crecp->flags & (F_DNSKEY | F_DS)) && crecp->uid == class)
		{
		  if (crecp->flags & F_CONFIG)
		    return crecp;
		  *up = crecp->hash_next;
		  cache_unlink(crecp);
		  cache_free(crecp);
		  continue;
		}
#endif
	    }

	  if (is_expired(now, crecp) || is_outdated_cname_pointer(crecp))
	    { 
	      *up = crecp->hash_next;
	      if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		{
		  cache_unlink(crecp);
		  cache_free(crecp);
		}
	      continue;
	    } 
	  
	  up = &crecp->hash_next;
	}
    }
  else
    {
      int i;
      int addrlen = (flags & F_IPV6) ? IN6ADDRSZ : INADDRSZ;

      for (i = 0; i < hash_size; i++)
	for (crecp = hash_table[i], up = &hash_table[i]; 
	     crecp && ((crecp->flags & F_REVERSE) || !(crecp->flags & F_IMMORTAL));
	     crecp = crecp->hash_next)
	  if (is_expired(now, crecp))
	    {
	      *up = crecp->hash_next;
	      if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		{ 
		  cache_unlink(crecp);
		  cache_free(crecp);
		}
	    }
	  else if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)) &&
		   (flags & crecp->flags & F_REVERSE) && 
		   (flags & crecp->flags & (F_IPV4 | F_IPV6)) &&
		   addr && memcmp(&crecp->addr, addr, addrlen) == 0)
	    {
	      *up = crecp->hash_next;
	      cache_unlink(crecp);
	      cache_free(crecp);
	    }
	  else
	    up = &crecp->hash_next;
    }
  
  return NULL;
}

/* Note: The normal calling sequence is
   cache_start_insert
   cache_insert * n
   cache_end_insert

   but an abort can cause the cache_end_insert to be missed 
   in which can the next cache_start_insert cleans things up. */

/**
 * @brief Initialize cache insertion transaction by cleaning up uncommitted entries
 * 
 * Prepares the cache for a new batch of insertions by freeing any entries that were
 * allocated but not successfully committed during the previous insertion operation.
 * This cleanup ensures the cache remains in a consistent state when prior insertions
 * encountered errors (e.g., memory allocation failures, validation errors). Must be
 * called before starting a new cache_insert()/cache_end_insert() transaction sequence.
 * 
 * @return void
 * 
 * @note Call this before beginning a sequence of cache_insert() calls
 * @note Automatically frees uncommitted entries from failed previous insertions
 * @note Resets insert_error flag to prepare for new transaction
 * 
 * TRANSACTION FLOW:
 * 1. cache_start_insert() - Initialize transaction (this function)
 * 2. cache_insert() - Insert one or more entries (may fail)
 * 3. cache_end_insert() - Commit all pending entries
 * 
 * ERROR RECOVERY:
 * - If previous cache_insert() failed (insert_error set), allocated but uncommitted
 *   entries remain in new_chain
 * - This function iterates through new_chain and frees all entries via cache_free()
 * - Clears new_chain to NULL and resets insert_error flag
 * 
 * EXAMPLE USAGE:
 * @code
 * cache_start_insert();
 * cache_insert("example.com", &addr, C_IN, now, 3600, F_IPV4 | F_FORWARD);
 * cache_insert("www.example.com", &addr2, C_IN, now, 3600, F_IPV4 | F_FORWARD);
 * cache_end_insert(now);
 * @endcode
 * 
 * SIDE EFFECTS:
 * - Frees memory for uncommitted entries in new_chain
 * - Sets new_chain to NULL
 * - Clears insert_error flag to 0
 * 
 * THREAD SAFETY: Single-threaded architecture, no synchronization required
 * 
 * @see cache_insert() for inserting entries into transaction
 * @see cache_end_insert() for committing transaction
 * @see cache_free() for entry deallocation
 */
void cache_start_insert(void)
{
  /* Free any entries which didn't get committed during the last
     insert due to error.
  */
  while (new_chain)
    {
      struct crec *tmp = new_chain->next;
      cache_free(new_chain);
      new_chain = tmp;
    }
  new_chain = NULL;
  insert_error = 0;
}

/**
 * @brief Insert DNS record into cache with TTL policy enforcement (transaction wrapper)
 * 
 * Validates and normalizes TTL values according to configured policies before inserting
 * a DNS record into the cache. This function is part of a multi-stage insertion transaction
 * initiated by cache_start_insert() and committed by cache_end_insert(). Enforces minimum
 * TTL for DNSSEC records to prevent validation failures from very short or zero TTLs, and
 * applies global min/max cache TTL policies for non-DNSSEC records. The actual insertion
 * is delegated to really_insert() after TTL adjustment.
 * 
 * @param name Domain name for the record (NULL-terminated string). NULL for reverse-only entries.
 * @param addr IP address (IPv4 in addr->addr4, IPv6 in addr->addr6) or NULL for name-only records
 * @param class DNS class (C_IN for internet class). Used for DNSSEC class-specific handling.
 * @param now Current timestamp (seconds since epoch) for expiration calculation
 * @param ttl Time-to-live in seconds from DNS response. Will be adjusted per policy before insertion.
 * @param flags Record type and attributes (F_IPV4, F_IPV6, F_CNAME, F_DNSKEY, F_DS, F_NXDOMAIN, etc.)
 * 
 * @return Pointer to inserted cache entry (struct crec *) if successful.
 *         NULL if insertion failed (memory allocation failure, validation error).
 *         On failure, insert_error flag is set (checked by cache_end_insert).
 * 
 * @note Must be called after cache_start_insert() and before cache_end_insert()
 * @note Multiple cache_insert() calls can be made in one transaction
 * @note Entries are not visible in cache until cache_end_insert() commits the transaction
 * @note Insertion failures set insert_error flag but do not abort transaction immediately
 * @warning Do not call this outside of cache_start_insert()/cache_end_insert() transaction
 * 
 * TTL POLICY ENFORCEMENT:
 * 
 * DNSSEC Records (F_DNSKEY | F_DS):
 *   - Minimum TTL: DNSSEC_MIN_TTL (hardcoded, typically 120 seconds)
 *   - Rationale: DNSSEC validation requires multiple queries; very short/zero TTLs cause
 *     premature expiration before validation completes, causing validation loops
 *   - If ttl < DNSSEC_MIN_TTL, force ttl = DNSSEC_MIN_TTL
 *   - Ignores daemon->min_cache_ttl and daemon->max_cache_ttl for DNSSEC
 * 
 * Non-DNSSEC Records:
 *   - Maximum TTL: daemon->max_cache_ttl (0 = unlimited, default from --max-cache-ttl)
 *   - Minimum TTL: daemon->min_cache_ttl (0 = no minimum, default from --min-cache-ttl)
 *   - If daemon->max_cache_ttl != 0 and ttl > max, force ttl = max
 *   - If daemon->min_cache_ttl != 0 and ttl < min, force ttl = min
 *   - Policies applied in order: max cap first, then min boost
 * 
 * EXAMPLE USAGE:
 * @code
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.0.2.1");
 * 
 * cache_start_insert();
 * struct crec *entry = cache_insert("example.com", &addr, C_IN, time(NULL), 3600,
 *                                     F_IPV4 | F_FORWARD);
 * if (entry == NULL) {
 *   my_syslog(LOG_ERR, "Cache insertion failed for example.com");
 * }
 * cache_end_insert(time(NULL));
 * @endcode
 * 
 * SIDE EFFECTS:
 * - May modify TTL value according to DNSSEC minimum or global min/max policies
 * - Calls really_insert() which allocates memory and modifies cache data structures
 * - On failure, sets insert_error flag preventing transaction commit
 * 
 * THREAD SAFETY: Single-threaded architecture, no synchronization required
 * 
 * RFC COMPLIANCE:
 * - RFC 1035: DNS caching with TTL-based expiration
 * - RFC 4033-4035: DNSSEC validation TTL requirements
 * 
 * @see cache_start_insert() for transaction initialization
 * @see cache_end_insert() for transaction commit
 * @see really_insert() for actual cache insertion logic
 */
struct crec *cache_insert(char *name, union all_addr *addr, unsigned short class,
			  time_t now,  unsigned long ttl, unsigned int flags)
{
#ifdef HAVE_DNSSEC
  if (flags & (F_DNSKEY | F_DS)) 
    {
      /* The DNSSEC validation process works by getting needed records into the
	 cache, then retrying the validation until they are all in place.
	 This can be messed up by very short TTLs, and _really_ messed up by
	 zero TTLs, so we force the TTL to be at least long enough to do a validation.
	 Ideally, we should use some kind of reference counting so that records are
	 locked until the validation that asks for them is complete, but this
	 is much easier, and just as effective. */
      if (ttl < DNSSEC_MIN_TTL)
	ttl = DNSSEC_MIN_TTL;
    }
  else
#endif
    {
      if (daemon->max_cache_ttl != 0 && daemon->max_cache_ttl < ttl)
	ttl = daemon->max_cache_ttl;
      if (daemon->min_cache_ttl != 0 && daemon->min_cache_ttl > ttl)
	ttl = daemon->min_cache_ttl;
    }	
  
  return really_insert(name, addr, class, now, ttl, flags);
}


/**
 * @brief Allocate and initialize a cache record for pending insertion
 * 
 * @detailed Creates a new cache record (struct crec) and populates it with the provided
 *           DNS record information. The record is added to the pending insertion chain
 *           (new_chain) but NOT yet committed to the active cache. Actual cache insertion
 *           occurs when cache_end_insert() is called, which hashes and links all pending
 *           records. This two-phase commit approach ensures transactional consistency when
 *           inserting multiple related records (e.g., CNAME chains).
 * 
 * @param name DNS name to cache (will be copied into allocated storage)
 * @param addr Pointer to IP address (IPv4/IPv6) or NULL for name-only records like CNAME
 * @param class DNS class (typically C_IN for Internet class, or DNSKEY uid for DNSSEC records)
 * @param now Current time (seconds since epoch) for TTL calculation
 * @param ttl Time-to-live in seconds (expiration time calculated as now + ttl)
 * @param flags Cache record type and status flags (F_IPV4, F_IPV6, F_CNAME, F_DNSKEY, etc.)
 * 
 * @return Pointer to newly allocated cache record on success, NULL on allocation failure
 * @retval non-NULL Successfully allocated and initialized cache record added to new_chain
 * @retval NULL Memory allocation failed (insert_error flag set to prevent partial commits)
 * 
 * @note This function does NOT insert the record into the active cache hash table.
 *       The record remains on new_chain until cache_end_insert() commits the transaction.
 * @warning Memory allocation failure sets insert_error flag, causing cache_end_insert()
 *          to abort the entire transaction and free all pending records.
 * 
 * @see cache_start_insert() - Begins cache insertion transaction
 * @see cache_end_insert() - Commits transaction by hashing and linking all pending records
 * @see cache_insert() - High-level wrapper for single-record insertion
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.0.2.1");
 * struct crec *new_rec = really_insert("example.com", &addr, C_IN, now, 3600, F_IPV4 | F_FORWARD);
 * if (new_rec) {
 *   // Record allocated and added to pending chain
 *   cache_end_insert(); // Commit transaction
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Supports RFC 1035 DNS record types and TTL semantics
 * SIDE EFFECTS: Allocates memory for cache record and name storage; modifies new_chain global
 * THREAD SAFETY: Not thread-safe (single-threaded event-driven architecture)
 */
static struct crec *really_insert(char *name, union all_addr *addr, unsigned short class,
				  time_t now,  unsigned long ttl, unsigned int flags)
{
  struct crec *new, *target_crec = NULL;
  union bigname *big_name = NULL;
  int freed_all = (flags & F_REVERSE);
  struct crec *free_avail = NULL;
  unsigned int target_uid;
  
  /* if previous insertion failed give up now. */
  if (insert_error)
    return NULL;

  /* we don't cache zero-TTL records unless we're doing stale-caching. */
  if (daemon->cache_max_expiry == 0 && ttl == 0)
    {
      insert_error = 1;
      return NULL;
    }
  
  /* First remove any expired entries and entries for the name/address we
     are currently inserting. */
  if ((new = cache_scan_free(name, addr, class, now, flags, &target_crec, &target_uid)))
    {
      /* We're trying to insert a record over one from 
	 /etc/hosts or DHCP, or other config. If the 
	 existing record is for an A or AAAA or CNAME and
	 the record we're trying to insert is the same, 
	 just drop the insert, but don't error the whole process. */
      if ((flags & (F_IPV4 | F_IPV6)) && (flags & F_FORWARD) && addr)
	{
	  if ((flags & F_IPV4) && (new->flags & F_IPV4) &&
	      new->addr.addr4.s_addr == addr->addr4.s_addr)
	    return new;
	  else if ((flags & F_IPV6) && (new->flags & F_IPV6) &&
		   IN6_ARE_ADDR_EQUAL(&new->addr.addr6, &addr->addr6))
	    return new;
	}

      insert_error = 1;
      return NULL;
    }
  
  /* Now get a cache entry from the end of the LRU list */
  if (!target_crec)
    while (1) {
      if (!(new = cache_tail)) /* no entries left - cache is too small, bail */
	{
	  insert_error = 1;
	  return NULL;
	}
      
      /* Free entry at end of LRU list, use it. */
      if (!(new->flags & (F_FORWARD | F_REVERSE)))
	break; 

      /* End of LRU list is still in use: if we didn't scan all the hash
	 chains for expired entries do that now. If we already tried that
	 then it's time to start spilling things. */
      
      /* If free_avail set, we believe that an entry has been freed.
	 Bugs have been known to make this not true, resulting in
	 a tight loop here. If that happens, abandon the
	 insert. Once in this state, all inserts will probably fail. */
      if (free_avail)
	{
	  my_syslog(LOG_ERR, _("Internal error in cache."));
	  /* Log the entry we tried to delete. */
	  dump_cache_entry(free_avail, now);
	  insert_error = 1;
	  return NULL;
	}
      
      if (freed_all)
	{
	  /* For DNSSEC records, uid holds class. */
	  free_avail = new; /* Must be free space now. */
	  
	  /* condition valid when stale-caching */
	  if (difftime(now, new->ttd) < 0)
	    daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]++;
	  
	  cache_scan_free(cache_get_name(new), &new->addr, new->uid, now, new->flags, NULL, NULL); 
	}
      else
	{
	  cache_scan_free(NULL, NULL, class, now, 0, NULL, NULL);
	  freed_all = 1;
	}
    }
      
  /* Check if we need to and can allocate extra memory for a long name.
     If that fails, give up now, always succeed for DNSSEC records. */
  if (name && (strlen(name) > SMALLDNAME-1))
    {
      if (big_free)
	{ 
	  big_name = big_free;
	  big_free = big_free->next;
	}
      else if ((bignames_left == 0 && !(flags & (F_DS | F_DNSKEY))) ||
	       !(big_name = (union bigname *)whine_malloc(sizeof(union bigname))))
	{
	  insert_error = 1;
	  return NULL;
	}
      else if (bignames_left != 0)
	bignames_left--;
      
    }

  /* If we freed a cache entry for our name which was a CNAME target, use that.
     and preserve the uid, so that existing CNAMES are not broken. */
  if (target_crec)
    {
      new = target_crec;
      new->uid = target_uid;
    }
  
  /* Got the rest: finally grab entry. */
  cache_unlink(new);
  
  new->flags = flags;
  if (big_name)
    {
      new->name.bname = big_name;
      new->flags |= F_BIGNAME;
    }

  if (name)
    strcpy(cache_get_name(new), name);
  else
    *cache_get_name(new) = 0;

#ifdef HAVE_DNSSEC
  if (flags & (F_DS | F_DNSKEY))
    new->uid = class;
#endif

  if (addr)
    new->addr = *addr;	

  new->ttd = now + (time_t)ttl;
  new->next = new_chain;
  new_chain = new;
  
  return new;
}

/**
 * @brief Commit pending cache insertion transaction by hashing and linking all new records
 * 
 * @detailed Completes a cache insertion transaction started by cache_start_insert() by processing
 *           all records on the new_chain. For each record: validates CNAME targets, computes hash
 *           values, inserts into hash table buckets, and links into the LRU chain. In multi-process
 *           mode (daemon->pipe_to_parent != -1), marshals each new record to the parent process
 *           via pipe for cache synchronization. If insert_error flag is set (indicating allocation
 *           failure during transaction), aborts without committing any records.
 * 
 * @return void (no return value)
 * 
 * @note MUST be called after cache_start_insert() and really_insert() to finalize cache changes.
 *       Records on new_chain remain uncommitted until this function executes.
 * @warning If insert_error flag is set, function returns immediately without committing, leaving
 *          new_chain records to be freed by subsequent cleanup or retry operations.
 * @warning In multi-process mode, pipe communication failures may cause cache desynchronization
 *          between child and parent processes.
 * 
 * @see cache_start_insert() - Begins cache insertion transaction
 * @see really_insert() - Allocates and adds records to pending chain
 * @see cache_hash() - Computes hash and inserts into hash table
 * @see cache_link() - Adds record to LRU chain
 * 
 * EXAMPLE USAGE:
 * @code
 * cache_start_insert();
 * // Insert multiple related records (e.g., A record + CNAME)
 * really_insert("www.example.com", &addr1, C_IN, now, 300, F_IPV4 | F_FORWARD);
 * really_insert("example.com", &addr2, C_IN, now, 300, F_IPV4 | F_FORWARD);
 * cache_end_insert(); // Commit transaction: hash and link all pending records
 * @endcode
 * 
 * RFC COMPLIANCE: Maintains RFC 1035 cache coherency requirements
 * SIDE EFFECTS: Modifies hash_table and LRU chain globals; sends pipe messages in multi-process mode
 * THREAD SAFETY: Not thread-safe (single-threaded event-driven architecture)
 */
/* after end of insertion, commit the new entries */
void cache_end_insert(void)
{
  if (insert_error)
    return;

  /* signal start of cache insert transaction to master process */
  if (daemon->pipe_to_parent != -1)
    {
      unsigned char op = PIPE_OP_INSERT;
      read_write(daemon->pipe_to_parent, &op, sizeof(op), RW_WRITE);
    }

  while (new_chain)
    { 
      struct crec *tmp = new_chain->next;
      /* drop CNAMEs which didn't find a target. */
      if (is_outdated_cname_pointer(new_chain))
	cache_free(new_chain);
      else
	{
	  cache_hash(new_chain);
	  cache_link(new_chain);
	  daemon->metrics[METRIC_DNS_CACHE_INSERTED]++;

	  /* If we're a child process, send this cache entry up the pipe to the master.
	     The marshalling process is rather nasty. */
	  if (daemon->pipe_to_parent != -1)
	    {
	      char *name = cache_get_name(new_chain);
	      ssize_t m = strlen(name);
	      unsigned int flags = new_chain->flags;
#ifdef HAVE_DNSSEC
	      u16 class = new_chain->uid;
#endif
	      
	      read_write(daemon->pipe_to_parent, (unsigned char *)&m, sizeof(m), RW_WRITE);
	      read_write(daemon->pipe_to_parent, (unsigned char *)name, m, RW_WRITE);
	      read_write(daemon->pipe_to_parent, (unsigned char *)&new_chain->ttd, sizeof(new_chain->ttd), RW_WRITE);
	      read_write(daemon->pipe_to_parent, (unsigned char *)&flags, sizeof(flags), RW_WRITE);
	      read_write(daemon->pipe_to_parent, (unsigned char *)&new_chain->addr, sizeof(new_chain->addr), RW_WRITE);
	      
	      if (flags & F_RR)
		{
		  /* A negative RR entry is possible and has no data, obviously. */
		  if (!(flags & F_NEG) && (flags & F_KEYTAG))
		    blockdata_write(new_chain->addr.rrblock.rrdata, new_chain->addr.rrblock.datalen, daemon->pipe_to_parent);
		}
#ifdef HAVE_DNSSEC
	      else if (flags & F_DNSKEY)
		{
		  read_write(daemon->pipe_to_parent, (unsigned char *)&class, sizeof(class), RW_WRITE);
		  blockdata_write(new_chain->addr.key.keydata, new_chain->addr.key.keylen, daemon->pipe_to_parent);
		}
	      else if (flags & F_DS)
		{
		  read_write(daemon->pipe_to_parent, (unsigned char *)&class, sizeof(class), RW_WRITE);
		  /* A negative DS entry is possible and has no data, obviously. */
		  if (!(flags & F_NEG))
		    blockdata_write(new_chain->addr.ds.keydata, new_chain->addr.ds.keylen, daemon->pipe_to_parent);
		}
#endif
	    }
	}
      
      new_chain = tmp;
    }

  /* signal end of cache insert in master process */
  if (daemon->pipe_to_parent != -1)
    {
      ssize_t m = -1;
      read_write(daemon->pipe_to_parent, (unsigned char *)&m, sizeof(m), RW_WRITE);
    }
}

#ifdef HAVE_DNSSEC
/**
 * @brief Send updated DNSSEC high water mark (HWM) metrics to parent process
 * 
 * @detailed Transmits DNSSEC validation resource usage metrics to the parent process via pipe
 *           for statistics aggregation. Sends PIPE_OP_STATS operation followed by three HWM
 *           metric values: METRIC_CRYPTO_HWM (cryptographic operations), METRIC_SIG_FAIL_HWM
 *           (signature validation failures), and METRIC_WORK_HWM (total validation work units).
 *           Only compiled when HAVE_DNSSEC is defined. Called by child processes after DNSSEC
 *           validation operations to report peak resource consumption to master process.
 * 
 * @return void (no return value)
 * 
 * @note Only available when compiled with HAVE_DNSSEC support
 * @note MUST be called from child process context with valid daemon->pipe_to_parent
 * @warning Assumes pipe communication is operational; no error handling for write failures
 * @warning Metrics sent represent current HWM values, not delta since last transmission
 * 
 * @see cache_end_insert() - Also uses pipe_to_parent for cache synchronization
 * @see dnssec.c - DNSSEC validation code that updates these metrics
 * 
 * EXAMPLE USAGE:
 * @code
 * // After completing DNSSEC validation in child process
 * if (dnssec_validation_complete && daemon->pipe_to_parent != -1)
 *   cache_update_hwm(); // Send HWM metrics to parent for aggregation
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (internal metrics reporting, not protocol-level)
 * SIDE EFFECTS: Writes to daemon->pipe_to_parent; blocks until pipe write completes
 * THREAD SAFETY: Not thread-safe (single-threaded event-driven architecture)
 */
void cache_update_hwm(void)
{
  /* Sneak out possibly updated crypto HWM values. */
  unsigned char op = PIPE_OP_STATS;

  read_write(daemon->pipe_to_parent, &op, sizeof(op), RW_WRITE);
  read_write(daemon->pipe_to_parent,
	     (unsigned char *)&daemon->metrics[METRIC_CRYPTO_HWM],
	     sizeof(daemon->metrics[METRIC_CRYPTO_HWM]), RW_WRITE);
  read_write(daemon->pipe_to_parent,
	     (unsigned char *)&daemon->metrics[METRIC_SIG_FAIL_HWM],
	     sizeof(daemon->metrics[METRIC_SIG_FAIL_HWM]), RW_WRITE);
  read_write(daemon->pipe_to_parent,
	     (unsigned char *)&daemon->metrics[METRIC_WORK_HWM],
	     sizeof(daemon->metrics[METRIC_WORK_HWM]), RW_WRITE);
}
#endif

#if defined(HAVE_IPSET) || defined(HAVE_NFTSET)
/**
 * @brief Send ipset/nftset firewall rule update to parent process for resolved IP address
 * 
 * @detailed Marshals ipset/nftset operation to parent process via pipe for firewall integration.
 *           Transmits operation code (ADD or DEL), ipset/nftset configuration pointer, address
 *           family flags (AF_INET/AF_INET6), and resolved IP address. Parent process receives
 *           these parameters and invokes actual ipset/nftset netlink operations to populate
 *           firewall sets with resolved IPs, enabling domain-based firewall rules. Only compiled
 *           when HAVE_IPSET or HAVE_NFTSET is defined. Called by cache insertion code when new
 *           DNS responses match ipset/nftset configuration rules (--ipset or --nftset options).
 * 
 * @param op Operation code (typically PIPE_OP_IPSET_ADD for adding resolved IP to set)
 * @param sets Pointer to ipsets configuration structure defining target ipset/nftset names
 * @param flags Address family and record type flags (F_IPV4, F_IPV6, F_FORWARD, etc.)
 * @param addr Pointer to union all_addr containing IPv4 or IPv6 address to add to firewall set
 * 
 * @return void (no return value)
 * 
 * @note Only available when compiled with HAVE_IPSET or HAVE_NFTSET support
 * @note MUST be called from child process context with valid daemon->pipe_to_parent
 * @warning Assumes pipe communication is operational; no error handling for write failures
 * @warning Sets pointer is sent as address (sizeof(sets)), not dereferenced structure
 * 
 * @see ipset.c - Linux ipset integration via netlink
 * @see nftset.c - Linux nftables set integration
 * @see cache_end_insert() - Calls this function when ipset/nftset rules match new records
 * 
 * EXAMPLE USAGE:
 * @code
 * // After DNS resolution for domain matching ipset rule
 * struct ipsets *target_sets = ...; // From --ipset=/ads.example.com/blocklist config
 * union all_addr resolved_ip;
 * resolved_ip.addr4.s_addr = inet_addr("192.0.2.1");
 * cache_send_ipset(PIPE_OP_IPSET_ADD, target_sets, F_IPV4 | F_FORWARD, &resolved_ip);
 * // Parent process adds 192.0.2.1 to "blocklist" ipset/nftset
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (firewall integration feature, not protocol-level)
 * SIDE EFFECTS: Writes to daemon->pipe_to_parent; blocks until pipe write completes
 * THREAD SAFETY: Not thread-safe (single-threaded event-driven architecture)
 */
void cache_send_ipset(unsigned char op, struct ipsets *sets, int flags, union all_addr *addr)
{
  read_write(daemon->pipe_to_parent, &op, sizeof(op), RW_WRITE);
  read_write(daemon->pipe_to_parent, (unsigned char *)&sets, sizeof(sets), RW_WRITE);
  read_write(daemon->pipe_to_parent, (unsigned char *)&flags, sizeof(flags), RW_WRITE);
  read_write(daemon->pipe_to_parent, (unsigned char *)addr, sizeof(*addr), RW_WRITE);
}
#endif

/**
 * @brief Receive and process cache insertion from child process via pipe in parent
 * 
 * @detailed Parent process receives serialized cache records from child processes via pipe
 *           and reconstructs them in the master cache. Reads operation code from pipe, and if
 *           PIPE_OP_INSERT, deserializes complete cache record including: flags, name, address,
 *           TTL, UID, and optional CNAME target. Reconstructs struct crec in parent cache,
 *           allocates bigname storage if needed, sets up CNAME linkage if present. Called by
 *           main event loop when child process has completed DNS resolution and committed new
 *           records via cache_end_insert(). Enables cache synchronization in multi-process
 *           architecture where child processes handle DNS queries and parent maintains
 *           authoritative cache. Returns 0 when pipe is closed by far end (child terminated).
 * 
 * @param now Current time (seconds since epoch) for TTL expiration calculations
 * @param fd File descriptor for pipe from child process (daemon->pipe_to_parent in child)
 * 
 * @return 1 on successful operation read and processing
 * @retval 0 when pipe is closed by far end (child process terminated or closed pipe)
 * @retval 1 after successfully processing PIPE_OP_INSERT, PIPE_OP_STATS, or PIPE_OP_IPSET_ADD
 * 
 * @note MUST be called from parent process context when pipe becomes readable
 * @note Counterpart to cache_end_insert() which sends records from child to parent
 * @warning Assumes well-formed data on pipe; no validation of received structure integrity
 * @warning Loops reading RRs to avoid poll() loop pollution during multi-record insertion
 * 
 * @see cache_end_insert() - Sends cache records from child to parent via pipe
 * @see really_insert() - Similar insertion logic but for local (non-pipe) operations
 * @see cache_link() - Links newly created record into LRU chain
 * 
 * EXAMPLE USAGE:
 * @code
 * // In parent process event loop when pipe from child becomes readable
 * if (poll_check(daemon->pipe_from_child, POLLIN)) {
 *   if (!cache_recv_insert(dnsmasq_time(), daemon->pipe_from_child))
 *     // Child process closed pipe (terminated), clean up child process resources
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Maintains RFC 1035 cache coherency in multi-process architecture
 * SIDE EFFECTS: Reads from pipe fd; allocates memory for cache records and name storage
 * THREAD SAFETY: Not thread-safe (single-threaded event-driven architecture)
 */
/* Retrieve and handle a result from child TCP-handler.
   Return 0 when pipe is closed by far end. */
int cache_recv_insert(time_t now, int fd)
{
  unsigned char op;
  
  if (!read_write(fd, &op, sizeof(op), RW_READ))
    return 0;
  
  switch (op)
    {
    case PIPE_OP_INSERT:
      {
	/* A marshalled set if cache entries arrives on fd, read, unmarshall and insert into cache of master process. */
	ssize_t m;
	union all_addr addr;
	unsigned long ttl;
	time_t ttd;
	unsigned int flags;
	struct crec *crecp = NULL;

	cache_start_insert();
	
	/* loop reading RRs, since we don't want to go back to the poll() loop
	   and start processing other queries which might pollute the insertion
	   chain. The child will never block between the first OP_RR and the
	   minus-one length marking the end. */
	while (1)
	  {
	    if (!read_write(fd, (unsigned char *)&m, sizeof(m), RW_READ))
	      return 0;
	    
	    if (m == -1)
	      {
		cache_end_insert();
		return 1;
	      }
	    
	    if (!read_write(fd, (unsigned char *)daemon->namebuff, m, RW_READ) ||
		!read_write(fd, (unsigned char *)&ttd, sizeof(ttd), RW_READ) ||
		!read_write(fd, (unsigned char *)&flags, sizeof(flags), RW_READ) ||
		!read_write(fd, (unsigned char *)&addr, sizeof(addr), RW_READ))
	      return 0;
	    
	    daemon->namebuff[m] = 0;
	    
	    ttl = difftime(ttd, now);
	    
	    if (flags & F_CNAME)
	      {
		struct crec *newc = really_insert(daemon->namebuff, NULL, C_IN, now, ttl, flags);
		/* This relies on the fact that the target of a CNAME immediately precedes
		   it because of the order of extraction in extract_addresses, and
		   the order reversal on the new_chain. */
		if (newc)
		  {
		    newc->addr.cname.is_name_ptr = 0;
		    newc->addr.cname.target.cache = crecp;
		    
		    if (crecp)
		      {
			next_uid(crecp);
			newc->addr.cname.uid = crecp->uid;
		      }
		    crecp = newc;
		  }
	      }
	    else
	      {
		unsigned short class = C_IN;
		struct blockdata *block = NULL;

		if ((flags & F_RR) && !(flags & F_NEG) && (flags & F_KEYTAG)
		    && !(block = addr.rrblock.rrdata = blockdata_read(fd, addr.rrblock.datalen)))
		  continue;
#ifdef HAVE_DNSSEC
		else if (flags & F_DNSKEY)
		  {
		    if (!read_write(fd, (unsigned char *)&class, sizeof(class), RW_READ))
		      return 0;
		    if (!(block = addr.key.keydata = blockdata_read(fd, addr.key.keylen)))
		      continue;
		  }
		else  if (flags & F_DS)
		  {
		    if (!read_write(fd, (unsigned char *)&class, sizeof(class), RW_READ))
		      return 0;
		    if (!(flags & F_NEG) && !(block = addr.ds.keydata = blockdata_read(fd, addr.ds.keylen)))
		      continue;
		  }
#endif
		if (!(crecp = really_insert(daemon->namebuff, &addr, class, now, ttl, flags)))
		  blockdata_free(block);
	      }
	  }
      }
      
#ifdef HAVE_DNSSEC
    case PIPE_OP_STATS:
      {
	/* Sneak in possibly updated crypto HWM. */
	unsigned int val;
	
	if (!read_write(fd, (unsigned char *)&val, sizeof(val), RW_READ))
	  return 0;
	if (val > daemon->metrics[METRIC_CRYPTO_HWM])
	  daemon->metrics[METRIC_CRYPTO_HWM] = val;
	if (!read_write(fd, (unsigned char *)&val, sizeof(val), RW_READ))
	  return 0;
	if (val > daemon->metrics[METRIC_SIG_FAIL_HWM])
	  daemon->metrics[METRIC_SIG_FAIL_HWM] = val;
	if (!read_write(fd, (unsigned char *)&val, sizeof(val), RW_READ))
	  return 0;
	if (val > daemon->metrics[METRIC_WORK_HWM])
	  daemon->metrics[METRIC_WORK_HWM] = val;
	return 1;
      }
      
    case PIPE_OP_RESULT:
      {
	/* UDP validation moved to TCP to avoid truncation. 
	   Restart UDP validation process with the returned result. */
	int status, uid, keycount, validatecount;
	int *keycountp, *validatecountp;
	size_t ret_len;
	
	struct frec *forward;
	
	if (!read_write(fd, (unsigned char *)&status, sizeof(status), RW_READ) ||
	    !read_write(fd, (unsigned char *)&ret_len, sizeof(ret_len), RW_READ) ||
	    !read_write(fd, (unsigned char *)daemon->packet, ret_len, RW_READ) ||
	    !read_write(fd, (unsigned char *)&forward, sizeof(forward), RW_READ) ||
	    !read_write(fd, (unsigned char *)&uid, sizeof(uid), RW_READ) ||
	    !read_write(fd, (unsigned char *)&keycount, sizeof(keycount), RW_READ) ||
	    !read_write(fd, (unsigned char *)&keycountp, sizeof(keycountp), RW_READ) ||
	    !read_write(fd, (unsigned char *)&validatecount, sizeof(validatecount), RW_READ) ||
	    !read_write(fd, (unsigned char *)&validatecountp, sizeof(validatecountp), RW_READ))
	  return 0;
	
	/* There's a tiny chance that the frec may have been freed 
	   and reused before the TCP process returns. Detect that with
	   the uid field which is unique modulo 2^32 for each use. */
	if (uid == forward->uid)
	  {
	    /* repatriate the work counters from the child process. */
	    *keycountp = keycount;
	    *validatecountp = validatecount;
	    
	    if (!forward->dependent)
	      return_reply(now, forward, (struct dns_header *)daemon->packet, ret_len, status);
	    else
	      pop_and_retry_query(forward, status, now);
	  }
	
	return 1;
      }
#endif
      
#if defined(HAVE_IPSET) || defined(HAVE_NFTSET)
    case PIPE_OP_IPSET:
    case PIPE_OP_NFTSET:
      {
	struct ipsets *sets;
	char **sets_cur;
	unsigned int flags;
	union all_addr addr;
	
	if (!read_write(fd, (unsigned char *)&sets, sizeof(sets), RW_READ) ||
	    !read_write(fd, (unsigned char *)&flags, sizeof(flags), RW_READ) ||
	    !read_write(fd, (unsigned char *)&addr, sizeof(addr), RW_READ))
	  return 0;
	
	for (sets_cur = sets->sets; *sets_cur; sets_cur++)
	  {
	    int rc = -1;
	    
#ifdef HAVE_IPSET
	    if (op == PIPE_OP_IPSET)
	      rc = add_to_ipset(*sets_cur, &addr, flags, 0);
#endif
	    
#ifdef HAVE_NFTSET		  
	    if (op == PIPE_OP_NFTSET)
	      rc = add_to_nftset(*sets_cur, &addr, flags, 0);
#endif
	    
	    if (rc == 0)
	      log_query((flags & (F_IPV4 | F_IPV6)) | F_IPSET, sets->domain, &addr, *sets_cur, op == PIPE_OP_IPSET);
	  }
	
	return 1;
      }
#endif
      
    }

  return 0;
}
	
/**
 * @brief Check if a non-terminal cache record exists for the given name
 * 
 * @detailed Searches the cache for any valid, non-expired forward record matching the given name
 *           that is not an NXDOMAIN and not an outdated CNAME pointer. This function is used to
 *           determine if there are any records under a given domain name, which is important for
 *           DNSSEC processing to distinguish between non-existent domains (NXDOMAIN) and domains
 *           that exist but have no records of the requested type (NODATA). Returns 1 if any
 *           qualifying record is found, 0 otherwise.
 * 
 * @param name Domain name to search for (null-terminated C string)
 * @param now Current time for expiration checking (seconds since epoch)
 * 
 * @return int 1 if non-terminal record exists, 0 if no matching record found
 * 
 * @note This function only checks for forward records (F_FORWARD flag set)
 * @note NXDOMAIN records are explicitly excluded from consideration
 * @warning name must not be NULL; no NULL pointer check performed
 * 
 * @see cache_find_by_name() - Main cache lookup function
 * @see is_outdated_cname_pointer() - CNAME staleness detection
 * @see is_expired() - TTL expiration checking
 * @see hash_bucket() - Hash table bucket lookup
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * if (cache_find_non_terminal("www.example.com", now))
 *   {
 *     // Domain exists in cache (has some records)
 *     // Return NODATA if specific type not found
 *   }
 * else
 *   {
 *     // Domain not in cache, may be NXDOMAIN
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: Supports RFC 4035 DNSSEC NXDOMAIN vs NODATA distinction
 * SIDE EFFECTS: None (read-only cache access)
 * THREAD SAFETY: Not thread-safe (single-threaded architecture)
 */
int cache_find_non_terminal(char *name, time_t now)
{
  struct crec *crecp;

  for (crecp = *hash_bucket(name); crecp; crecp = crecp->hash_next)
    if (!is_outdated_cname_pointer(crecp) &&
	!is_expired(now, crecp) &&
	(crecp->flags & F_FORWARD) &&
	!(crecp->flags & F_NXDOMAIN) && 
	hostname_isequal(name, cache_get_name(crecp)))
      return 1;

  return 0;
}

/**
 * @brief Find cache records matching domain name and protocol type with round-robin support
 * 
 * @detailed Primary cache lookup function for forward DNS queries (name → address). Searches hash
 *           table for records matching the given name and protocol flags (F_IPV4, F_IPV6, etc.).
 *           On first call (crecp == NULL), builds a result chain by scanning the hash bucket,
 *           freeing expired entries, and optionally implementing round-robin by reordering hash
 *           chain entries. Subsequent calls with non-NULL crecp iterate through the result chain.
 *           Records from /etc/hosts, DHCP, or config (F_HOSTS|F_DHCP|F_CONFIG) are linked into
 *           result chain but not moved in LRU. Dynamic records are promoted to cache head.
 *           Supports F_NO_RR flag to disable round-robin reordering.
 * 
 * @param crecp Previous result for iteration (NULL for first call)
 * @param name Domain name to search for (null-terminated C string)
 * @param now Current time for expiration checking (seconds since epoch)
 * @param prot Protocol/type flags (F_IPV4, F_IPV6, F_CNAME, etc.) with optional F_NO_RR
 * 
 * @return struct crec* Pointer to matching cache record, or NULL if no match found
 * @retval Non-NULL Matching cache record with F_FORWARD flag and matching name/protocol
 * @retval NULL No matching record found, or end of iteration chain reached
 * 
 * @note First call builds result chain and may reorder hash table for round-robin
 * @note Subsequent calls iterate through pre-built chain without hash table modification
 * @warning name must not be NULL; no NULL pointer check performed
 * @warning Modifies hash table and LRU chain on first call (crecp == NULL)
 * @warning F_NO_RR flag or OPT_NORR option disables round-robin reordering
 * 
 * @see cache_find_by_addr() - Reverse lookup (address → name)
 * @see hash_bucket() - Computes hash bucket for name
 * @see is_expired() - Checks TTL expiration
 * @see cache_unlink() - Removes from LRU chain
 * @see cache_link() - Adds to LRU head
 * @see cache_free() - Frees expired records
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * struct crec *cache_record = NULL;
 * // First call: build result chain
 * cache_record = cache_find_by_name(NULL, "www.example.com", now, F_IPV4);
 * while (cache_record)
 *   {
 *     // Process this A record
 *     struct in_addr *addr = &cache_record->addr.addr4;
 *     // Iterate to next matching record
 *     cache_record = cache_find_by_name(cache_record, "www.example.com", now, F_IPV4);
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements RFC 1035 name-to-address lookup with round-robin per RFC 1794
 * SIDE EFFECTS: Reorders hash table entries (round-robin), frees expired records, modifies LRU chain
 * THREAD SAFETY: Not thread-safe (single-threaded architecture)
 */
struct crec *cache_find_by_name(struct crec *crecp, char *name, time_t now, unsigned int prot)
{
  struct crec *ans;
  int no_rr = (prot & F_NO_RR) || option_bool(OPT_NORR);

  prot &= ~F_NO_RR;
  
  if (crecp) /* iterating */
    ans = crecp->next;
  else
    {
      /* first search, look for relevant entries and push to top of list
	 also free anything which has expired */
      struct crec *next, **up, **insert = NULL, **chainp = &ans;
      unsigned int ins_flags = 0;
      
      for (up = hash_bucket(name), crecp = *up; crecp; crecp = next)
	{
	  next = crecp->hash_next;
	  
	  if (!is_expired(now, crecp) && !is_outdated_cname_pointer(crecp))
	    {
	      if ((crecp->flags & F_FORWARD) && 
		  (crecp->flags & prot) &&
		  hostname_isequal(cache_get_name(crecp), name))
		{
		  if (crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))
		    {
		      *chainp = crecp;
		      chainp = &crecp->next;
		    }
		  else
		    {
		      cache_unlink(crecp);
		      cache_link(crecp);
		    }
	      	      
		  /* Move all but the first entry up the hash chain
		     this implements round-robin. 
		     Make sure that re-ordering doesn't break the hash-chain
		     order invariants. 
		  */
		  if (insert && (crecp->flags & (F_REVERSE | F_IMMORTAL)) == ins_flags)
		    {
		      *up = crecp->hash_next;
		      crecp->hash_next = *insert;
		      *insert = crecp;
		      insert = &crecp->hash_next;
		    }
		  else
		    {
		      if (!insert && !no_rr)
			{
			  insert = up;
			  ins_flags = crecp->flags & (F_REVERSE | F_IMMORTAL);
			}
		      up = &crecp->hash_next; 
		    }
		}
	      else
		/* case : not expired, incorrect entry. */
		up = &crecp->hash_next; 
	    }
	  else
	    {
	      /* expired entry, free it */
	      *up = crecp->hash_next;
	      if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		{ 
		  cache_unlink(crecp);
		  cache_free(crecp);
		}
	    }
	}
	  
      *chainp = cache_head;
    }

  if (ans && 
      (ans->flags & F_FORWARD) &&
      (ans->flags & prot) &&     
      hostname_isequal(cache_get_name(ans), name))
    return ans;
  
  return NULL;
}

/**
 * @brief Find cache records matching IP address for reverse DNS lookup (address → name)
 * 
 * @detailed Reverse DNS lookup function searching all hash buckets for PTR records matching
 *           the given IP address. On first call (crecp == NULL), scans entire hash table for
 *           F_REVERSE records matching the address and protocol (F_IPV4 or F_IPV6). Builds
 *           result chain by linking static records (F_HOSTS|F_DHCP|F_CONFIG) and promoting
 *           dynamic records to cache head. Frees expired reverse entries during scan. Reverse
 *           entries cluster at start of hash chains (optimization: stops scanning each bucket
 *           after first non-reverse entry). Subsequent calls (crecp != NULL) iterate through
 *           pre-built result chain without additional hash table scanning.
 * 
 * @param crecp Previous result for iteration (NULL for first call)
 * @param addr IP address to search for (IPv4 or IPv6 union)
 * @param now Current time for expiration checking (seconds since epoch)
 * @param prot Protocol flag (F_IPV4 or F_IPV6) determining address length and type
 * 
 * @return struct crec* Pointer to matching reverse cache record, or NULL if no match found
 * @retval Non-NULL Matching cache record with F_REVERSE flag and matching address/protocol
 * @retval NULL No matching record found, or end of iteration chain reached
 * 
 * @note First call scans all hash buckets (expensive), subsequent calls iterate chain (fast)
 * @note Address comparison uses memcmp with addrlen = INADDRSZ (4) for IPv4, IN6ADDRSZ (16) for IPv6
 * @warning addr must not be NULL; no NULL pointer check performed
 * @warning First call modifies hash table (frees expired) and LRU chain (promotes matches)
 * 
 * @see cache_find_by_name() - Forward lookup (name → address)
 * @see is_expired() - Checks TTL expiration
 * @see cache_unlink() - Removes from LRU chain
 * @see cache_link() - Adds to LRU head
 * @see cache_free() - Frees expired records
 * 
 * EXAMPLE USAGE:
 * @code
 * time_t now = dnsmasq_time();
 * union all_addr addr;
 * addr.addr4.s_addr = inet_addr("192.168.1.100");
 * struct crec *cache_record = NULL;
 * // First call: scan all hash buckets for reverse entries
 * cache_record = cache_find_by_addr(NULL, &addr, now, F_IPV4);
 * while (cache_record)
 *   {
 *     // Process this PTR record
 *     char *hostname = cache_get_name(cache_record);
 *     // Iterate to next matching record
 *     cache_record = cache_find_by_addr(cache_record, &addr, now, F_IPV4);
 *   }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements RFC 1035 reverse DNS (address-to-name) queries
 * SIDE EFFECTS: Scans all hash buckets, frees expired reverse entries, modifies LRU chain
 * THREAD SAFETY: Not thread-safe (single-threaded architecture)
 */
struct crec *cache_find_by_addr(struct crec *crecp, union all_addr *addr, 
				time_t now, unsigned int prot)
{
  struct crec *ans;
  int addrlen = (prot == F_IPV6) ? IN6ADDRSZ : INADDRSZ;
  
  if (crecp) /* iterating */
    ans = crecp->next;
  else
    {  
      /* first search, look for relevant entries and push to top of list
	 also free anything which has expired. All the reverse entries are at the
	 start of the hash chain, so we can give up when we find the first 
	 non-REVERSE one.  */
       int i;
       struct crec **up, **chainp = &ans;
       
       for (i=0; i<hash_size; i++)
	 for (crecp = hash_table[i], up = &hash_table[i]; 
	      crecp && (crecp->flags & F_REVERSE);
	      crecp = crecp->hash_next)
	   if (!is_expired(now, crecp))
	     {      
	       if ((crecp->flags & prot) &&
		   memcmp(&crecp->addr, addr, addrlen) == 0)
		 {	    
		   if (crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))
		     {
		       *chainp = crecp;
		       chainp = &crecp->next;
		     }
		   else
		     {
		       cache_unlink(crecp);
		       cache_link(crecp);
		     }
		 }
	       up = &crecp->hash_next;
	     }
	   else
	     {
	       *up = crecp->hash_next;
	       if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
		 {
		   cache_unlink(crecp);
		   cache_free(crecp);
		 }
	     }
       
       *chainp = cache_head;
    }
  
  if (ans && 
      (ans->flags & F_REVERSE) &&
      (ans->flags & prot) &&
      memcmp(&ans->addr, addr, addrlen) == 0)
    return ans;
  
  return NULL;
}

static void add_hosts_entry(struct crec *cache, union all_addr *addr, int addrlen, 
			    unsigned int index, struct crec **rhash, int hashsz)
{
  int i;
  unsigned int j; 
  struct crec *lookup = NULL;

  /* Remove duplicates in hosts files. */
  while ((lookup = cache_find_by_name(lookup, cache_get_name(cache), 0, cache->flags & (F_IPV4 | F_IPV6))))
    if ((lookup->flags & F_HOSTS) && memcmp(&lookup->addr, addr, addrlen) == 0)
      {
	free(cache);
	return;
      }
    
  /* Ensure there is only one address -> name mapping (first one trumps) 
     We do this by steam here, The entries are kept in hash chains, linked
     by ->next (which is unused at this point) held in hash buckets in
     the array rhash, hashed on address. Note that rhash and the values
     in ->next are only valid  whilst reading hosts files: the buckets are
     then freed, and the ->next pointer used for other things. 
     Only insert each unique address once into this hashing structure.

     This complexity avoids O(n^2) divergent CPU use whilst reading
     large (10000 entry) hosts files. 

     Note that we only do this process when bulk-reading hosts files, 
     for incremental reads, rhash is NULL, and we use cache lookups
     instead.
  */
  
  if (rhash)
    {
      /* hash address */
      for (j = 0, i = 0; i < addrlen; i++)
	j = (j*2 +((unsigned char *)addr)[i]) % hashsz;
      
      for (lookup = rhash[j]; lookup; lookup = lookup->next)
	if ((lookup->flags & cache->flags & (F_IPV4 | F_IPV6)) &&
	    memcmp(&lookup->addr, addr, addrlen) == 0)
	  {
	    cache->flags &= ~F_REVERSE;
	    break;
	  }
      
      /* maintain address hash chain, insert new unique address */
      if (!lookup)
	{
	  cache->next = rhash[j];
	  rhash[j] = cache;
	}
    }
  else
    {
      /* incremental read, lookup in cache */
      lookup = cache_find_by_addr(NULL, addr, 0, cache->flags & (F_IPV4 | F_IPV6));
      if (lookup && lookup->flags & F_HOSTS)
	cache->flags &= ~F_REVERSE;
    }

  cache->uid = index;
  memcpy(&cache->addr, addr, addrlen);  
  cache_hash(cache);
  make_non_terminals(cache);
}

/**
 * @brief Consume whitespace and comments from file stream, counting newlines
 * 
 * Reads and discards whitespace characters (spaces, tabs, newlines) and comments
 * from the given file stream until a non-whitespace, non-comment character is
 * encountered. Comments are defined as text from '#' to end of line. The first
 * non-whitespace character is pushed back onto the stream for subsequent reading.
 * 
 * This function is used during hosts file parsing to skip blank lines and comments
 * while tracking line numbers for error reporting.
 * 
 * @param f File stream positioned at any point in a hosts file
 * 
 * @return Number of newlines encountered (0 or more), or 1 if EOF reached
 * @retval 0+ Number of newline characters consumed before non-whitespace character
 * @retval 1 End of file reached without finding non-whitespace content
 * 
 * @note Leaves stream positioned at first non-whitespace character (pushed back via ungetc)
 * @note Comments extend from '#' character to end of line
 * 
 * SIDE EFFECTS: Modifies file stream position; pushes back one character if non-EOF/non-whitespace found
 * 
 * EXAMPLE USAGE:
 * @code
 * FILE *f = fopen("/etc/hosts", "r");
 * int lineno = 0;
 * lineno += eatspace(f);  // Skip leading whitespace/comments, track line numbers
 * // Stream now positioned at start of first hosts entry
 * @endcode
 */
static int eatspace(FILE *f)
{
  int c, nl = 0;

  while (1)
    {
      if ((c = getc(f)) == '#')
	while (c != '\n' && c != EOF)
	  c = getc(f);
      
      if (c == EOF)
	return 1;

      if (!isspace(c))
	{
	  ungetc(c, f);
	  return nl;
	}

      if (c == '\n')
	nl++;
    }
}
	 
/**
 * @brief Extract one whitespace-delimited token from file stream
 * 
 * Reads characters from the file stream and accumulates them into the provided
 * token buffer until whitespace, comment character '#', or EOF is encountered.
 * The token is null-terminated and the stream is positioned after any trailing
 * whitespace/comments via eatspace().
 * 
 * This function is the core tokenizer for hosts file parsing, extracting IP
 * addresses and hostnames as discrete tokens. It enforces a maximum token length
 * of MAXDNAME-1 characters (typically 1023 bytes), silently truncating longer
 * tokens to prevent buffer overflow.
 * 
 * @param f File stream positioned at start of a token in a hosts file
 * @param token Output buffer for extracted token (must be at least MAXDNAME bytes)
 * 
 * @return Status code indicating token extraction result and newline count
 * @retval -1 EOF reached with no token characters read (end of file)
 * @retval 0+ Number of newlines encountered after token (from eatspace)
 * @retval 1 EOF reached after token characters read but before delimiter
 * 
 * @note Token buffer must be at least MAXDNAME bytes to avoid truncation
 * @note Tokens longer than MAXDNAME-1 are silently truncated
 * @note Stream is positioned after trailing whitespace/comments via eatspace()
 * @warning Caller must provide buffer of adequate size (MAXDNAME bytes minimum)
 * 
 * @see eatspace() for whitespace/comment consumption after token
 * @see read_hostsfile() for usage context in hosts file parsing
 * 
 * SIDE EFFECTS: Modifies file stream position; writes to token buffer; null-terminates token
 * 
 * EXAMPLE USAGE:
 * @code
 * FILE *f = fopen("/etc/hosts", "r");
 * char token[MAXDNAME];
 * int result = gettok(f, token);
 * if (result == -1) {
 *     // End of file, no token
 * } else {
 *     // token contains IP address or hostname
 * }
 * @endcode
 */
static int gettok(FILE *f, char *token)
{
  int c, count = 0;
 
  while (1)
    {
      if ((c = getc(f)) == EOF)
	return (count == 0) ? -1 : 1;

      if (isspace(c) || c == '#')
	{
	  ungetc(c, f);
	  return eatspace(f);
	}
      
      if (count < (MAXDNAME - 1))
	{
	  token[count++] = c;
	  token[count] = 0;
	}
    }
}

/**
 * @brief Parse hosts file and populate DNS cache with static hostname-to-IP mappings
 * 
 * Reads a hosts file in /etc/hosts format (lines of "IP hostname [hostname...]") and
 * creates immortal cache entries for each hostname-to-IP mapping. Supports both IPv4
 * and IPv6 addresses, optional domain suffix expansion, and incremental rehashing for
 * large hosts files (rehash every 1000 names).
 * 
 * The function tokenizes each line to extract IP addresses and associated hostnames,
 * validates addresses using inet_pton(), canonicalizes hostnames, and creates cache
 * records marked as F_HOSTS (from hosts file) and F_IMMORTAL (never expires). If
 * OPT_EXPAND option is set and hostname is not FQDN, also creates entry with domain
 * suffix appended.
 * 
 * Integration with cache system: Entries are added via add_hosts_entry() which inserts
 * into both the hash table (for fast lookup) and the cache LRU list. Hosts file entries
 * have higher precedence than upstream DNS due to F_HOSTS flag.
 * 
 * @param filename Path to hosts file to parse (e.g., "/etc/hosts", "/etc/dnsmasq.d/custom.hosts")
 * @param index Source index for tracking which hosts file provided this entry (0=main /etc/hosts, 1+=additional)
 * @param cache_size Current cache entry count before parsing this file
 * @param rhash Pointer to hash table for inserting entries (NULL if no rehashing needed)
 * @param hashsz Hash table size for rehash operations
 * 
 * @return Updated cache entry count after adding names from this file
 * @retval cache_size File could not be opened, no entries added
 * @retval >cache_size Number of cache entries after parsing (includes newly added names)
 * 
 * @note File must be in /etc/hosts format: "IP_ADDRESS hostname [alias1 alias2 ...]"
 * @note IPv4 and IPv6 addresses both supported (auto-detected via inet_pton)
 * @note Blank lines and comments (# to end of line) are ignored
 * @note Malformed addresses log error and skip to next line
 * @note Rehashing occurs every 1000 names for large files to maintain lookup performance
 * @warning File open failures logged to syslog but do not abort daemon startup
 * 
 * @see eatspace() for whitespace/comment skipping during parsing
 * @see gettok() for token extraction from file stream
 * @see canonicalise() for hostname validation and lowercasing
 * @see add_hosts_entry() for cache entry insertion with F_HOSTS flag
 * @see rehash() for hash table resizing during large file loads
 * 
 * RFC COMPLIANCE: Hosts file format per /etc/hosts convention (not formally standardized)
 * 
 * SIDE EFFECTS: Opens and reads file; allocates memory for cache entries; modifies global
 * hash table and cache LRU list; logs to syslog on errors and completion
 * 
 * EXAMPLE USAGE:
 * @code
 * struct crec **hash_table = get_hash_table();
 * int cache_count = daemon->cachesize;
 * cache_count = read_hostsfile("/etc/hosts", 0, cache_count, hash_table, hash_size);
 * // cache_count now includes entries from /etc/hosts
 * @endcode
 */
int read_hostsfile(char *filename, unsigned int index, int cache_size, struct crec **rhash, int hashsz)
{  
  FILE *f = fopen(filename, "r");
  char *token = daemon->namebuff, *domain_suffix = NULL;
  int names_done = 0, name_count = cache_size, lineno = 1;
  unsigned int flags = 0;
  union all_addr addr;
  int atnl, addrlen = 0;

  if (!f)
    {
      my_syslog(LOG_ERR, _("failed to load names from %s: %s"), filename, strerror(errno));
      return cache_size;
    }
  
  lineno += eatspace(f);
  
  while ((atnl = gettok(f, token)) != -1)
    {
      if (inet_pton(AF_INET, token, &addr) > 0)
	{
	  flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4;
	  addrlen = INADDRSZ;
	  domain_suffix = get_domain(addr.addr4);
	}
      else if (inet_pton(AF_INET6, token, &addr) > 0)
	{
	  flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV6;
	  addrlen = IN6ADDRSZ;
	  domain_suffix = get_domain6(&addr.addr6);
	}
      else
	{
	  my_syslog(LOG_ERR, _("bad address at %s line %d"), filename, lineno); 
	  while (atnl == 0)
	    atnl = gettok(f, token);
	  lineno += atnl;
	  continue;
	}
      
      /* rehash every 1000 names. */
      if (rhash && ((name_count - cache_size) > 1000))
	{
	  rehash(name_count);
	  cache_size = name_count;
	} 
      
      while (atnl == 0)
	{
	  struct crec *cache;
	  int fqdn, nomem;
	  char *canon;
	  
	  if ((atnl = gettok(f, token)) == -1)
	    break;

	  fqdn = !!strchr(token, '.');

	  if ((canon = canonicalise(token, &nomem)))
	    {
	      /* If set, add a version of the name with a default domain appended */
	      if (option_bool(OPT_EXPAND) && domain_suffix && !fqdn && 
		  (cache = whine_malloc(SIZEOF_BARE_CREC + strlen(canon) + 2 + strlen(domain_suffix))))
		{
		  strcpy(cache->name.sname, canon);
		  strcat(cache->name.sname, ".");
		  strcat(cache->name.sname, domain_suffix);
		  cache->flags = flags;
		  cache->ttd = daemon->local_ttl;
		  add_hosts_entry(cache, &addr, addrlen, index, rhash, hashsz);
		  name_count++;
		  names_done++;
		}
	      if ((cache = whine_malloc(SIZEOF_BARE_CREC + strlen(canon) + 1)))
		{
		  strcpy(cache->name.sname, canon);
		  cache->flags = flags;
		  cache->ttd = daemon->local_ttl;
		  add_hosts_entry(cache, &addr, addrlen, index, rhash, hashsz);
		  name_count++;
		  names_done++;
		}
	      free(canon);
	      
	    }
	  else if (!nomem)
	    my_syslog(LOG_ERR, _("bad name at %s line %d"), filename, lineno); 
	}

      lineno += atnl;
    } 

  fclose(f);
  
  if (rhash)
    rehash(name_count); 
  
  my_syslog(LOG_INFO, _("read %s - %d names"), filename, names_done);
  
  return name_count;
}

/**
 * @brief Reload DNS cache from configuration sources, preserving DHCP entries
 * 
 * Clears all static cache entries (F_HOSTS | F_CONFIG flags) and repopulates the cache
 * from multiple configuration sources while preserving dynamically assigned DHCP hostnames.
 * The function rebuilds the cache from:
 * 1. Configured CNAME records (daemon->cnames)
 * 2. DNSSEC DS records (daemon->ds for trust anchors)
 * 3. Host records from configuration (daemon->host_records)
 * 4. System hosts file (/etc/hosts if not OPT_NO_HOSTS)
 * 5. Additional hosts files (daemon->addn_hosts list)
 * 6. Non-terminal records for TXT, NAPTR, MX, PTR, and interface names
 * 
 * The reload process uses a temporary reverse hash table (stored in daemon->packet buffer)
 * to efficiently rebuild the hash table structure. Entries with F_DHCP flag are preserved
 * across reload to maintain DHCP-assigned hostname resolution continuity. All F_HOSTS and
 * F_CONFIG entries are removed, their blockdata freed, and then repopulated from current
 * configuration state.
 * 
 * Cache metrics counters (METRIC_DNS_CACHE_INSERTED, METRIC_DNS_CACHE_LIVE_FREED) are reset
 * to baseline after clearing existing entries. The function coordinates with inotify file
 * monitoring (if HAVE_INOTIFY defined) to watch configuration files for changes.
 * 
 * Typical trigger: SIGHUP signal handler invokes this function to reload configuration
 * without daemon restart. Also called during initial daemon startup after configuration
 * parsing completes.
 * 
 * @param None - operates on global daemon state and cache structures
 * 
 * @return None (void function)
 * 
 * @note F_DHCP entries (DHCP-assigned hostnames) are PRESERVED across reload
 * @note F_HOSTS entries (from hosts files) and F_CONFIG entries (from config) are CLEARED
 * @note Uses daemon->packet buffer as temporary storage for reverse hash table
 * @note Reverse hash table size is daemon->cachesize / 16 to reduce memory usage
 * @note All blockdata associated with cleared entries is freed to prevent memory leaks
 * @note Hosts file parsing can trigger rehashing if >1000 names added from single file
 * @warning Function modifies global hash_table and daemon state; not thread-safe
 * @warning Temporary packet buffer usage means no DNS packet processing during reload
 * 
 * @see read_hostsfile() for /etc/hosts file parsing and cache population
 * @see rehash() for hash table resizing during large configuration loads
 * @see cache_unhash_dhcp() for F_DHCP entry preservation mechanism
 * @see cache_hash() for hash function used in hash table operations
 * @see cache_blockdata_free() for freeing variable-length record data
 * @see make_non_terminals() for creating non-terminal records for local RRs
 * 
 * RFC COMPLIANCE: Cache reload preserves DNS protocol semantics; configuration
 * changes take effect immediately without query interruption
 * 
 * SIDE EFFECTS:
 * - Clears all F_HOSTS and F_CONFIG entries from hash table and cache LRU list
 * - Frees blockdata memory for all cleared entries
 * - Resets metrics counters to baseline (subtract freed entry count)
 * - Rereads /etc/hosts and additional hosts files
 * - Repopulates cache with current configuration (CNAME, DS, host_records)
 * - Creates non-terminal cache records for locally defined RR types
 * - Sets daemon->srv_save to NULL (clears SRV record iteration state)
 * - Registers inotify watches on configuration files (Linux with HAVE_INOTIFY)
 * - Logs cache reload completion with entry counts to syslog
 * 
 * THREAD SAFETY: Single-threaded architecture; function not reentrant
 * 
 * EXAMPLE USAGE:
 * @code
 * // SIGHUP signal handler triggers configuration reload
 * void sig_handler(int sig) {
 *   if (sig == SIGHUP) {
 *     reread_config();  // Reparse configuration file
 *     cache_reload();   // Rebuild cache from new configuration
 *     my_syslog(LOG_INFO, "Configuration reloaded successfully");
 *   }
 * }
 * @endcode
 */	    
void cache_reload(void)
{
  struct crec *cache, **up, *tmp;
  int revhashsz, i, total_size = daemon->cachesize;
  struct hostsfile *ah;
  struct host_record *hr;
  struct name_list *nl;
  struct cname *a;
  struct crec lrec;
  struct mx_srv_record *mx;
  struct txt_record *txt;
  struct interface_name *intr;
  struct ptr_record *ptr;
  struct naptr *naptr;
#ifdef HAVE_DNSSEC
  struct ds_config *ds;
#endif

  daemon->metrics[METRIC_DNS_CACHE_INSERTED] = 0;
  daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED] = 0;
  
  for (i=0; i<hash_size; i++)
    for (cache = hash_table[i], up = &hash_table[i]; cache; cache = tmp)
      {
	cache_blockdata_free(cache);

	tmp = cache->hash_next;
	if (cache->flags & (F_HOSTS | F_CONFIG))
	  {
	    *up = cache->hash_next;
	    free(cache);
	  }
	else if (!(cache->flags & F_DHCP))
	  {
	    *up = cache->hash_next;
	    if (cache->flags & F_BIGNAME)
	      {
		cache->name.bname->next = big_free;
		big_free = cache->name.bname;
	      }
	    cache->flags = 0;
	  }
	else
	  up = &cache->hash_next;
      }
  
  /* Add locally-configured CNAMEs to the cache */
  for (a = daemon->cnames; a; a = a->next)
    if (a->alias[1] != '*' &&
	((cache = whine_malloc(SIZEOF_POINTER_CREC))))
      {
	cache->flags = F_FORWARD | F_NAMEP | F_CNAME | F_IMMORTAL | F_CONFIG;
	cache->ttd = a->ttl;
	cache->name.namep = a->alias;
	cache->addr.cname.target.name = a->target;
	cache->addr.cname.is_name_ptr = 1;
	cache->uid = UID_NONE;
	cache_hash(cache);
	make_non_terminals(cache);
      }
  
#ifdef HAVE_DNSSEC
  for (ds = daemon->ds; ds; ds = ds->next)
    if ((cache = whine_malloc(SIZEOF_POINTER_CREC)) &&
	(cache->addr.ds.keydata = blockdata_alloc(ds->digest, ds->digestlen)))
      {
	cache->flags = F_FORWARD | F_IMMORTAL | F_DS | F_CONFIG | F_NAMEP;
	cache->ttd = daemon->local_ttl;
	cache->name.namep = ds->name;
	cache->uid = ds->class;
	if (ds->digestlen != 0)
	  {
	    cache->addr.ds.keylen = ds->digestlen;
	    cache->addr.ds.algo = ds->algo;
	    cache->addr.ds.keytag = ds->keytag;
	    cache->addr.ds.digest = ds->digest_type;
	  }
	else
	  cache->flags |= F_NEG | F_DNSSECOK | F_NO_RR;
	
	cache_hash(cache);
	make_non_terminals(cache);
      }
#endif
  
  /* borrow the packet buffer for a temporary by-address hash */
  memset(daemon->packet, 0, daemon->packet_buff_sz);
  revhashsz = daemon->packet_buff_sz / sizeof(struct crec *);
  /* we overwrote the buffer... */
  daemon->srv_save = NULL;

  /* Do host_records in config. */
  for (hr = daemon->host_records; hr; hr = hr->next)
    for (nl = hr->names; nl; nl = nl->next)
      {
	if ((hr->flags & HR_4) &&
	    (cache = whine_malloc(SIZEOF_POINTER_CREC)))
	  {
	    cache->name.namep = nl->name;
	    cache->ttd = hr->ttl;
	    cache->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV4 | F_NAMEP | F_CONFIG;
	    add_hosts_entry(cache, (union all_addr *)&hr->addr, INADDRSZ, SRC_CONFIG, (struct crec **)daemon->packet, revhashsz);
	  }

	if ((hr->flags & HR_6) &&
	    (cache = whine_malloc(SIZEOF_POINTER_CREC)))
	  {
	    cache->name.namep = nl->name;
	    cache->ttd = hr->ttl;
	    cache->flags = F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_IPV6 | F_NAMEP | F_CONFIG;
	    add_hosts_entry(cache, (union all_addr *)&hr->addr6, IN6ADDRSZ, SRC_CONFIG, (struct crec **)daemon->packet, revhashsz);
	  }
      }
	
  if (option_bool(OPT_NO_HOSTS) && !daemon->addn_hosts)
    {
      if (daemon->cachesize > 0)
	my_syslog(LOG_INFO, _("cleared cache"));
    }
  else
    {
      if (!option_bool(OPT_NO_HOSTS))
	total_size = read_hostsfile(HOSTSFILE, SRC_HOSTS, total_size, (struct crec **)daemon->packet, revhashsz);
      
      daemon->addn_hosts = expand_filelist(daemon->addn_hosts);
      for (ah = daemon->addn_hosts; ah; ah = ah->next)
	if (!(ah->flags & AH_INACTIVE))
	  total_size = read_hostsfile(ah->fname, ah->index, total_size, (struct crec **)daemon->packet, revhashsz);
    }
  
  /* Make non-terminal records for all locally-define RRs */
  lrec.flags = F_FORWARD | F_CONFIG | F_NAMEP | F_IMMORTAL;
  
  for (txt = daemon->txt; txt; txt = txt->next)
    {
      lrec.name.namep = txt->name;
      make_non_terminals(&lrec);
    }

  for (naptr = daemon->naptr; naptr; naptr = naptr->next)
    {
      lrec.name.namep = naptr->name;
      make_non_terminals(&lrec);
    }

  for (mx = daemon->mxnames; mx; mx = mx->next)
    {
      lrec.name.namep = mx->name;
      make_non_terminals(&lrec);
    }

  for (intr = daemon->int_names; intr; intr = intr->next)
    {
      lrec.name.namep = intr->name;
      make_non_terminals(&lrec);
    }
  
  for (ptr = daemon->ptr; ptr; ptr = ptr->next)
    {
      lrec.name.namep = ptr->name;
      make_non_terminals(&lrec);
    }
  
#ifdef HAVE_INOTIFY
  set_dynamic_inotify(AH_HOSTS, total_size, (struct crec **)daemon->packet, revhashsz);
#endif
  
} 

#ifdef HAVE_DHCP
/**
 * @brief Retrieve IPv4 address for hostname from hosts file cache entries
 * 
 * Searches the DNS cache for IPv4 address records (A records) matching the specified
 * hostname, restricting results to entries from hosts files (F_HOSTS flag). Returns
 * the first matching IPv4 address found, or 0.0.0.0 if no matching entry exists.
 * 
 * This function is primarily used by the DHCP subsystem to resolve hostnames configured
 * in static DHCP reservations to IPv4 addresses from /etc/hosts or additional hosts files.
 * Only hosts file entries are returned; upstream DNS results and dynamically assigned DHCP
 * addresses are excluded from consideration.
 * 
 * If DNS service is disabled (daemon->port == 0), indicating cache is not initialized,
 * the function immediately returns 0.0.0.0 without attempting cache lookup. This prevents
 * crashes when DHCP service runs without DNS service.
 * 
 * Integration: Called from DHCP reservation processing (dhcp.c) when static host definitions
 * reference hostnames instead of explicit IP addresses. Allows hosts file to serve as
 * central hostname-to-IP mapping for both DNS and DHCP services.
 * 
 * @param name Hostname to look up (null-terminated string, case-insensitive)
 * @param now Current time in seconds since epoch for TTL expiration checks
 * 
 * @return struct in_addr containing IPv4 address from hosts file, or 0.0.0.0 if not found
 * @retval addr4 First matching IPv4 address from hosts file entry
 * @retval 0.0.0.0 (ret.s_addr = 0) No matching hosts file entry found, or DNS service disabled
 * 
 * @note Only returns addresses from hosts files (F_HOSTS flag); excludes upstream DNS results
 * @note Returns first match only; if multiple A records exist, only first is returned
 * @note DNS service must be enabled (daemon->port != 0) for cache to be initialized
 * @note Name comparison is case-insensitive per DNS protocol
 * @warning Logs warning to syslog if no address found (may generate log volume for misconfigured hosts)
 * @warning Returns 0.0.0.0 as sentinel value; caller must check for this error condition
 * 
 * @see cache_find_by_name() for cache search implementation
 * @see read_hostsfile() for hosts file parsing that creates F_HOSTS entries
 * @see cache_add_dhcp_entry() for DHCP dynamic hostname registration (excluded from results)
 * 
 * RFC COMPLIANCE: Hosts file format follows /etc/hosts convention (no formal RFC)
 * 
 * SIDE EFFECTS: Logs warning message to syslog (MS_DHCP | LOG_WARNING facility) if no address found
 * 
 * THREAD SAFETY: Single-threaded architecture; cache_find_by_name() not reentrant
 * 
 * EXAMPLE USAGE:
 * @code
 * // DHCP static reservation: "dhcp-host=server1,192.168.1.100"
 * // If "server1" is in /etc/hosts, use that address instead of configured address
 * struct in_addr host_addr = a_record_from_hosts("server1", time(NULL));
 * if (host_addr.s_addr != 0) {
 *   // Found in hosts file, use this address for DHCP reservation
 *   memcpy(&reservation_addr, &host_addr, sizeof(struct in_addr));
 * }
 * @endcode
 */
struct in_addr a_record_from_hosts(char *name, time_t now)
{
  struct crec *crecp = NULL;
  struct in_addr ret;
  
  /* If no DNS service, cache not initialised. */
  if (daemon->port != 0)
    while ((crecp = cache_find_by_name(crecp, name, now, F_IPV4)))
      if (crecp->flags & F_HOSTS)
	return crecp->addr.addr4;
  
  my_syslog(MS_DHCP | LOG_WARNING, _("No IPv4 address found for %s"), name);
  
  ret.s_addr = 0;
  return ret;
}

/**
 * @brief Remove all DHCP-originated cache entries from hash table and recycle to spare pool
 * 
 * Traverses the entire DNS cache hash table and removes all entries with the F_DHCP flag,
 * indicating they originated from DHCP lease assignments. Removed entries are not freed;
 * instead they are added to the dhcp_spare linked list for future reuse, optimizing memory
 * allocation performance for DHCP lease churn.
 * 
 * This function is called when DHCP-DNS integration state changes, such as when DHCP service
 * is disabled, when configuration reload requires clearing DHCP-originated names, or when
 * lease database is reset. It ensures that DNS cache contains only non-DHCP entries
 * (hosts file entries, upstream DNS results, authoritative records) after invocation.
 * 
 * The unhashing operation modifies the hash_table structure in place, carefully maintaining
 * hash chain integrity by adjusting the "up" pointer to skip over removed entries. This
 * ensures that hash chains remain valid for concurrent cache lookups (though single-threaded
 * architecture prevents true concurrency).
 * 
 * Memory Management: Removed cache records (struct crec) are transferred to dhcp_spare list
 * for reuse by future cache_add_dhcp_entry() calls, avoiding repeated malloc/free cycles.
 * This recycling strategy is critical for performance when DHCP lease churn is high.
 * 
 * Integration: Called from configuration reload (cache_reload()) when DHCP service state
 * changes, from DHCP subsystem (dhcp.c) during lease database cleanup, and potentially
 * from signal handlers (SIGHUP configuration reload).
 * 
 * @note Iterates entire hash table (hash_size buckets); O(n) where n = total cache entries
 * @note Removed entries retain their data but are removed from hash lookup paths
 * @note dhcp_spare list grows with number of removed entries; no limit enforced
 * @note Only entries with F_DHCP flag are removed; F_HOSTS, F_FORWARD, F_REVERSE preserved
 * @warning Must not be called during active DHCP lease assignment (race condition risk)
 * @warning After invocation, DHCP hostnames are no longer resolvable until re-registered
 * 
 * @see cache_add_dhcp_entry() for DHCP entry creation that consumes dhcp_spare entries
 * @see cache_reload() for configuration reload that calls this function
 * @see dhcp_spare for spare entry pool that receives unlinked entries
 * 
 * RFC COMPLIANCE: Not protocol-specific; internal cache management operation
 * 
 * SIDE EFFECTS: 
 * - Modifies hash_table structure by removing F_DHCP entries from hash chains
 * - Grows dhcp_spare linked list with all removed entries
 * - Breaks DNS resolution for DHCP-assigned hostnames until re-registration
 * 
 * THREAD SAFETY: Single-threaded architecture; not reentrant; must not call during cache lookup
 * 
 * EXAMPLE USAGE:
 * @code
 * // Configuration reload disables DHCP service
 * if (daemon->dhcp_disable_changed) {
 *   cache_unhash_dhcp();  // Remove all DHCP entries from DNS cache
 *   my_syslog(LOG_INFO, "DHCP cache entries cleared");
 * }
 * // Later, DHCP leases will re-register if DHCP re-enabled
 * @endcode
 */
void cache_unhash_dhcp(void)
{
  struct crec *cache, **up;
  int i;

  for (i=0; i<hash_size; i++)
    for (cache = hash_table[i], up = &hash_table[i]; cache; cache = cache->hash_next)
      if (cache->flags & F_DHCP)
	{
	  *up = cache->hash_next;
	  cache->next = dhcp_spare;
	  dhcp_spare = cache;
	}
      else
	up = &cache->hash_next;
}

/**
 * @brief Register DHCP lease hostname in DNS cache for immediate name resolution
 * 
 * Adds a DHCP-originated hostname-to-IP mapping to the DNS cache, enabling clients to
 * resolve DHCP-assigned hostnames immediately after lease assignment without requiring
 * external DNS server configuration. This function implements the DNS-DHCP integration
 * that allows DHCP clients to be addressed by name within the local network.
 * 
 * The function performs comprehensive conflict detection to prevent DHCP from overriding
 * statically configured hosts file entries. If the hostname exists in /etc/hosts or
 * additional hosts files with a matching address, the DHCP entry is redundant and
 * skipped. If the hostname exists with a different address, the DHCP registration is
 * rejected with a syslog warning to alert the administrator of the naming conflict.
 * 
 * Integration with DNS Cache:
 * - Hostname becomes immediately resolvable via DNS queries from all clients
 * - Forward lookup (hostname → IP) and reverse lookup (IP → hostname) both configured
 * - Cache entry expires automatically when DHCP lease expires (ttd timestamp)
 * - Entries persist across daemon restart if lease database is preserved
 * 
 * Memory Management Optimization:
 * The function first attempts to reuse a cache entry from the dhcp_spare pool (populated
 * by cache_unhash_dhcp()). This recycling strategy avoids repeated malloc/free cycles
 * during DHCP lease churn, critical for performance in networks with frequent lease
 * renewals or short lease times. Only if dhcp_spare is empty does the function allocate
 * a new cache record via whine_malloc().
 * 
 * Conflict Detection Algorithm:
 * 1. Search cache for existing entries with same hostname
 * 2. If hostname exists in hosts file (F_HOSTS | F_CONFIG):
 *    - If CNAME: Log warning, reject DHCP entry (CNAME cannot coexist with A/AAAA)
 *    - If address matches: Return early (hosts file entry sufficient, no DHCP entry needed)
 *    - If address differs: Log conflict warning, reject DHCP entry (hosts file takes precedence)
 * 3. If hostname exists as non-DHCP dynamic entry: Clear it to allow DHCP override
 * 4. If reverse lookup (IP → name) exists as negative cache: Clear negative entry
 * 
 * Flags Configuration:
 * - F_IPV4 or F_IPV6: Protocol family (determined by prot parameter)
 * - F_NAMEP: Hostname stored as pointer (not inline in struct crec)
 * - F_DHCP: Marks entry as DHCP-originated (distinguishes from hosts file entries)
 * - F_FORWARD: Enables forward lookup (hostname → IP)
 * - F_REVERSE: Enables reverse lookup (IP → hostname) if no existing entry
 * - F_IMMORTAL: Set if ttd == 0 (infinite lease time; rare in practice)
 * 
 * Integration with DHCP Subsystem:
 * - Called from dhcp.c:dhcp_reply() when DHCP ACK/REPLY message is sent
 * - Called from lease.c when lease database is reloaded on daemon restart
 * - Coordinates with cache_unhash_dhcp() which removes all DHCP entries
 * 
 * @param host_name Hostname from DHCP client or static configuration (null-terminated)
 * @param prot Address family: AF_INET (IPv4) or AF_INET6 (IPv6)
 * @param host_address IP address assigned to hostname (union all_addr contains in_addr or in6_addr)
 * @param ttd Time to die: lease expiration timestamp (seconds since epoch), or 0 for immortal
 * 
 * @note Returns without adding entry if hostname conflicts with hosts file entry
 * @note Hostname must not contain wildcard characters (* ?) - validation done by caller
 * @note Function is conditional on HAVE_DHCP compile flag (not compiled without DHCP support)
 * @note Cache entry automatically expires at ttd; no manual removal needed for normal lease expiration
 * @note If malloc fails, entry silently not added (whine_malloc logs error)
 * 
 * @warning Logs syslog warnings for naming conflicts (may generate log volume for misconfigurations)
 * @warning Silently does nothing if DNS service is disabled (daemon->port == 0) - cache not initialized
 * @warning host_name pointer must remain valid for lifetime of cache entry (F_NAMEP flag)
 * @warning Does not validate hostname RFC compliance - caller must ensure valid DNS name
 * 
 * @see cache_unhash_dhcp() for removing all DHCP entries during configuration changes
 * @see cache_find_by_name() for hostname conflict detection
 * @see cache_find_by_addr() for reverse lookup conflict detection
 * @see cache_scan_free() for clearing existing non-DHCP entries
 * @see cache_hash() for inserting entry into hash table
 * @see make_non_terminals() for creating parent domain cache entries
 * @see dhcp_spare for recycled cache entry pool (populated by cache_unhash_dhcp)
 * 
 * RFC COMPLIANCE: Implements local DNS service per DHCP/DNS integration best practices
 * 
 * SIDE EFFECTS:
 * - Adds entry to DNS cache hash table (cache_hash modifies hash_table structure)
 * - Creates parent domain entries via make_non_terminals() (converts NXDOMAIN to NODATA)
 * - Logs warnings to syslog for conflicts (MS_DHCP | LOG_WARNING facility)
 * - Clears existing negative cache entries for same IP address
 * - Consumes entry from dhcp_spare pool if available, or allocates new memory
 * - Hostname becomes immediately resolvable for DNS queries from all clients
 * 
 * THREAD SAFETY: Single-threaded architecture; not reentrant; must not call during cache operations
 * 
 * EXAMPLE USAGE:
 * @code
 * // DHCP server assigns lease to client with hostname "laptop"
 * struct in_addr lease_addr;
 * inet_pton(AF_INET, "192.168.1.100", &lease_addr);
 * time_t expiry = time(NULL) + 86400;  // 24-hour lease
 * 
 * cache_add_dhcp_entry("laptop", AF_INET, (union all_addr *)&lease_addr, expiry);
 * // Now "laptop" resolves to 192.168.1.100 via DNS queries
 * // Reverse lookup of 192.168.1.100 returns "laptop"
 * // Entry expires automatically after 24 hours
 * @endcode
 */
void cache_add_dhcp_entry(char *host_name, int prot,
			  union all_addr *host_address, time_t ttd) 
{
  struct crec *crec = NULL, *fail_crec = NULL;
  unsigned int flags = F_IPV4;
  int in_hosts = 0;
  size_t addrlen = sizeof(struct in_addr);

  if (prot == AF_INET6)
    {
      flags = F_IPV6;
      addrlen = sizeof(struct in6_addr);
    }
  
  inet_ntop(prot, host_address, daemon->addrbuff, ADDRSTRLEN);
  
  while ((crec = cache_find_by_name(crec, host_name, 0, flags | F_CNAME)))
    {
      /* check all addresses associated with name */
      if (crec->flags & (F_HOSTS | F_CONFIG))
	{
	  if (crec->flags & F_CNAME)
	    my_syslog(MS_DHCP | LOG_WARNING, 
		      _("%s is a CNAME, not giving it to the DHCP lease of %s"),
		      host_name, daemon->addrbuff);
	  else if (memcmp(&crec->addr, host_address, addrlen) == 0)
	    in_hosts = 1;
	  else
	    fail_crec = crec;
	}
      else if (!(crec->flags & F_DHCP))
	{
	  cache_scan_free(host_name, NULL, C_IN, 0, crec->flags & (flags | F_CNAME | F_FORWARD), NULL, NULL);
	  /* scan_free deletes all addresses associated with name */
	  break;
	}
    }
  
  /* if in hosts, don't need DHCP record */
  if (in_hosts)
    return;
  
  /* Name in hosts, address doesn't match */
  if (fail_crec)
    {
      inet_ntop(prot, &fail_crec->addr, daemon->namebuff, MAXDNAME);
      my_syslog(MS_DHCP | LOG_WARNING, 
		_("not giving name %s to the DHCP lease of %s because "
		  "the name exists in %s with address %s"), 
		host_name, daemon->addrbuff,
		record_source(fail_crec->uid), daemon->namebuff);
      return;
    }	  
  
  if ((crec = cache_find_by_addr(NULL, (union all_addr *)host_address, 0, flags)))
    {
      if (crec->flags & F_NEG)
	{
	  flags |= F_REVERSE;
	  cache_scan_free(NULL, (union all_addr *)host_address, C_IN, 0, flags, NULL, NULL);
	}
    }
  else
    flags |= F_REVERSE;
  
  if ((crec = dhcp_spare))
    dhcp_spare = dhcp_spare->next;
  else /* need new one */
    crec = whine_malloc(SIZEOF_POINTER_CREC);
  
  if (crec) /* malloc may fail */
    {
      crec->flags = flags | F_NAMEP | F_DHCP | F_FORWARD;
      if (ttd == 0)
	crec->flags |= F_IMMORTAL;
      else
	crec->ttd = ttd;
      crec->addr = *host_address;
      crec->name.namep = host_name;
      crec->uid = UID_NONE;
      cache_hash(crec);
      make_non_terminals(crec);
    }
}
#endif

/* Called when we put a local or DHCP name into the cache.
   Creates empty cache entries for subnames (ie,
   for three.two.one, for two.one and one), without
   F_IPV4 or F_IPV6 or F_CNAME set. These convert
   NXDOMAIN answers to NoData ones. */
static void make_non_terminals(struct crec *source)
{
  char *name = cache_get_name(source);
  struct crec *crecp, *tmp, **up;
  int type = F_HOSTS | F_CONFIG;
#ifdef HAVE_DHCP
  if (source->flags & F_DHCP)
    type = F_DHCP;
#endif
  
  /* First delete any empty entries for our new real name. Note that
     we only delete empty entries deriving from DHCP for a new DHCP-derived
     entry and vice-versa for HOSTS and CONFIG. This ensures that 
     non-terminals from DHCP go when we reload DHCP and 
     for HOSTS/CONFIG when we re-read. */
  for (up = hash_bucket(name), crecp = *up; crecp; crecp = tmp)
    {
      tmp = crecp->hash_next;

      if (!is_outdated_cname_pointer(crecp) &&
	  (crecp->flags & F_FORWARD) &&
	  (crecp->flags & type) &&
	  !(crecp->flags & (F_IPV4 | F_IPV6 | F_CNAME | F_DNSKEY | F_DS | F_RR)) && 
	  hostname_isequal(name, cache_get_name(crecp)))
	{
	  *up = crecp->hash_next;
#ifdef HAVE_DHCP
	  if (type & F_DHCP)
	    {
	      crecp->next = dhcp_spare;
	      dhcp_spare = crecp;
	    }
	  else
#endif
	    free(crecp);
	  break;
	}
      else
	 up = &crecp->hash_next;
    }
     
  while ((name = strchr(name, '.')))
    {
      name++;

      /* Look for one existing, don't need another */
      for (crecp = *hash_bucket(name); crecp; crecp = crecp->hash_next)
	if (!is_outdated_cname_pointer(crecp) &&
	    (crecp->flags & F_FORWARD) &&
	    (crecp->flags & type) &&
	    hostname_isequal(name, cache_get_name(crecp)))
	  break;
      
      if (crecp)
	{
	  /* If the new name expires later, transfer that time to
	     empty non-terminal entry. */
	  if (!(crecp->flags & F_IMMORTAL))
	    {
	      if (source->flags & F_IMMORTAL)
		crecp->flags |= F_IMMORTAL;
	      else if (difftime(crecp->ttd, source->ttd) < 0)
		crecp->ttd = source->ttd;
	    }
	  continue;
	}
      
#ifdef HAVE_DHCP
      if ((source->flags & F_DHCP) && dhcp_spare)
	{
	  crecp = dhcp_spare;
	  dhcp_spare = dhcp_spare->next;
	}
      else
#endif
	crecp = whine_malloc(SIZEOF_POINTER_CREC);

      if (crecp)
	{
	  crecp->flags = (source->flags | F_NAMEP) & ~(F_IPV4 | F_IPV6 | F_CNAME | F_RR | F_DNSKEY | F_DS | F_REVERSE);
	  if (!(crecp->flags & F_IMMORTAL))
	    crecp->ttd = source->ttd;
	  crecp->name.namep = name;
	  
	  cache_hash(crecp);
	}
    }
}

#ifndef NO_ID
/**
 * @brief Generate cache statistics as TXT record data for monitoring and diagnostics
 * 
 * Produces formatted cache statistics for DNS TXT record queries enabling remote monitoring
 * of dnsmasq cache performance and upstream server health without requiring shell access.
 * Clients can query special TXT records (e.g., "cachesize.bind") to retrieve real-time
 * statistics including cache size, hit rates, server query counts, and other metrics.
 * 
 * This function is called from the DNS query processing path when a TXT query matches
 * a configured statistics record. It populates the txt_record structure with formatted
 * statistics data that will be returned to the client as a TXT resource record.
 * 
 * Supported Statistics Types (determined by t->stat parameter):
 * 
 * - **TXT_STAT_CACHESIZE**: Configured maximum cache size (daemon->cachesize)
 * - **TXT_STAT_INSERTS**: Total cache insertions since daemon start (METRIC_DNS_CACHE_INSERTED)
 * - **TXT_STAT_EVICTIONS**: Total cache evictions due to LRU (METRIC_DNS_CACHE_LIVE_FREED)
 * - **TXT_STAT_MISSES**: Cache misses requiring upstream forwarding (METRIC_DNS_QUERIES_FORWARDED)
 * - **TXT_STAT_HITS**: Cache hits answered locally (METRIC_DNS_LOCAL_ANSWERED)
 * - **TXT_STAT_AUTH**: Authoritative answers (METRIC_DNS_AUTH_ANSWERED, HAVE_AUTH only)
 * - **TXT_STAT_SERVERS**: Per-upstream-server statistics with query/failure counts
 * 
 * TXT_STAT_SERVERS Complex Processing:
 * This case generates a multi-part TXT record with statistics for each unique upstream
 * server, aggregating query counts across multiple server records with the same IP address
 * and port. The algorithm marks processed servers to avoid double-counting, sums query
 * and failure counters across duplicate server definitions, and formats output as:
 *   "<server_ip>#<port> <total_queries> <failed_queries>"
 * Each server entry is length-prefixed per DNS TXT record format (RFC 1035).
 * 
 * Memory Management Strategy:
 * Uses static buffer (initially 60 bytes) with dynamic expansion on demand. Buffer persists
 * across function calls to avoid repeated allocations. For TXT_STAT_SERVERS case, buffer
 * grows as needed to accommodate all server statistics entries. If realloc fails, function
 * returns 0 (error), preventing incomplete statistics transmission.
 * 
 * Output Format:
 * - Simple statistics (non-SERVERS): Length-prefixed string "<length><value>"
 * - Server statistics: Concatenated length-prefixed strings, one per server
 * - Length byte precedes each string segment per DNS TXT record encoding
 * 
 * Integration with Monitoring Tools:
 * Clients can query "cachesize.bind TXT" or similar special names to retrieve statistics
 * via standard DNS queries. This enables monitoring systems (Nagios, Prometheus exporters,
 * custom scripts) to collect dnsmasq metrics without requiring authenticated shell access
 * or D-Bus/UBus interfaces. Configuration directive: "--txt-record=<name>,<stat_type>".
 * 
 * Metrics Source:
 * Statistics counters are maintained in daemon->metrics[] array (metrics.c), updated
 * throughout DNS/DHCP processing. Cache size from daemon->cachesize configuration.
 * Server query counters from daemon->servers linked list (forward.c maintains counts).
 * 
 * @param t Pointer to txt_record structure specifying statistic type and receiving output
 *          - Input: t->stat identifies which statistic to generate
 *          - Output: t->txt set to formatted data, t->len set to data length
 * 
 * @return Success status for statistics generation
 * @retval 1 Statistics successfully generated and populated in t->txt/t->len
 * @retval 0 Memory allocation failure (whine_malloc or whine_realloc failed)
 * 
 * @note Function maintains static buffer across calls; not thread-safe
 * @note Buffer initially 60 bytes, expands dynamically for TXT_STAT_SERVERS case
 * @note Caller must not free t->txt (points to static buffer owned by this function)
 * @note For TXT_STAT_SERVERS, iterates all daemon->servers entries (O(n²) worst case)
 * @note Server records with identical addresses are aggregated (query counts summed)
 * @note SERV_MARK flag temporarily used during aggregation, cleared before return
 * @note TXT_STAT_AUTH conditional on HAVE_AUTH compile flag (authoritative DNS feature)
 * 
 * @warning Static buffer means concurrent calls would corrupt data (not issue in single-threaded model)
 * @warning Buffer never freed (persists for daemon lifetime); acceptable for single static allocation
 * @warning Returns 0 on allocation failure; caller must handle gracefully (no statistics sent)
 * @warning TXT_STAT_SERVERS case may allocate significant memory for large server lists
 * 
 * @see metrics.c for METRIC_* counter definitions and update logic
 * @see forward.c for server query counter maintenance (serv->queries, serv->failed_queries)
 * @see option.c for "--txt-record" configuration directive parsing
 * @see rfc1035.c for TXT record encoding and transmission
 * 
 * RFC COMPLIANCE: TXT record format per RFC 1035 Section 3.3.14 (length-prefixed strings)
 * 
 * SIDE EFFECTS:
 * - Allocates/expands static buffer on first call or when insufficient space
 * - Temporarily modifies SERV_MARK flags in daemon->servers list (restored before return)
 * - Sets t->txt pointer to internal static buffer
 * - Updates t->len with formatted data length
 * 
 * THREAD SAFETY: Not thread-safe due to static buffer; single-threaded architecture only
 * 
 * EXAMPLE USAGE:
 * @code
 * // Client queries "cachesize.bind TXT" configured with "--txt-record=cachesize.bind,cachesize"
 * struct txt_record stat_record;
 * stat_record.stat = TXT_STAT_CACHESIZE;
 * 
 * if (cache_make_stat(&stat_record)) {
 *   // stat_record.txt contains: "\x03150" (length=3, value="150")
 *   // Send as TXT RR in DNS response
 *   add_resource_record(header, limit, NULL, rec_ttl, NULL, 
 *                       T_TXT, C_IN, "txt", stat_record.txt, stat_record.len);
 * } else {
 *   // Allocation failure, send SERVFAIL
 * }
 * @endcode
 */
int cache_make_stat(struct txt_record *t)
{ 
  static char *buff = NULL;
  static int bufflen = 60;
  int len;
  struct server *serv, *serv1;
  char *p;

  if (!buff && !(buff = whine_malloc(60)))
    return 0;

  p = buff;
  
  switch (t->stat)
    {
    case TXT_STAT_CACHESIZE:
      sprintf(buff+1, "%d", daemon->cachesize);
      break;

    case TXT_STAT_INSERTS:
      sprintf(buff+1, "%d", daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
      break;

    case TXT_STAT_EVICTIONS:
      sprintf(buff+1, "%d", daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED]);
      break;

    case TXT_STAT_MISSES:
      sprintf(buff+1, "%u", daemon->metrics[METRIC_DNS_QUERIES_FORWARDED]);
      break;

    case TXT_STAT_HITS:
      sprintf(buff+1, "%u", daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]);
      break;

#ifdef HAVE_AUTH
    case TXT_STAT_AUTH:
      sprintf(buff+1, "%u", daemon->metrics[METRIC_DNS_AUTH_ANSWERED]);
      break;
#endif

    case TXT_STAT_SERVERS:
      /* sum counts from different records for same server */
      for (serv = daemon->servers; serv; serv = serv->next)
	serv->flags &= ~SERV_MARK;
      
      for (serv = daemon->servers; serv; serv = serv->next)
	if (!(serv->flags & SERV_MARK))
	  {
	    char *new, *lenp;
	    int port, newlen, bytes_avail, bytes_needed;
	    unsigned int queries = 0, failed_queries = 0;
	    for (serv1 = serv; serv1; serv1 = serv1->next)
	      if (!(serv1->flags & SERV_MARK) && sockaddr_isequal(&serv->addr, &serv1->addr))
		{
		  serv1->flags |= SERV_MARK;
		  queries += serv1->queries;
		  failed_queries += serv1->failed_queries;
		}
	    port = prettyprint_addr(&serv->addr, daemon->addrbuff);
	    lenp = p++; /* length */
	    bytes_avail = bufflen - (p - buff );
	    bytes_needed = snprintf(p, bytes_avail, "%s#%d %u %u", daemon->addrbuff, port, queries, failed_queries);
	    if (bytes_needed >= bytes_avail)
	      {
		/* expand buffer if necessary */
		newlen = bytes_needed + 1 + bufflen - bytes_avail;
		if (!(new = whine_realloc(buff, newlen)))
		  return 0;
		p = new + (p - buff);
		lenp = p - 1;
		buff = new;
		bufflen = newlen;
		bytes_avail =  bufflen - (p - buff );
		bytes_needed = snprintf(p, bytes_avail, "%s#%d %u %u", daemon->addrbuff, port, queries, failed_queries);
	      }
	    *lenp = bytes_needed;
	    p += bytes_needed;
	  }
      t->txt = (unsigned char *)buff;
      t->len = p - buff;

      return 1;
    }
  
  len = strlen(buff+1);
  t->txt = (unsigned char *)buff;
  t->len = len + 1;
  *buff = len;
  return 1;
}
#endif

/* There can be names in the cache containing control chars, don't 
   mess up logging or open security holes. Also convert to all-LC
   so that 0x20-encoding doesn't make logs look like ransom notes
   made out of letters cut from a newspaper.
   Overwrites daemon->workspacename */
static char *sanitise(char *name)
{
  unsigned char *r = (unsigned char *)name;
  
  if (name)
    {
      char *d = name = daemon->workspacename;
      
      for (; *r; r++, d++)
	if (!isprint((int)*r))
	  return "<name unprintable>";
	else
	  {
	    unsigned char c = *r;
	    
	    *d = (char)((c >= 'A' && c <= 'Z') ? c + 'a' - 'A' : c);
	  }
      
      *d = 0;
    }
  
  return name;
}

static void dump_cache_entry(struct crec *cache, time_t now)
{
  (void)now;
  static char *buff = NULL;
  
  char *p, *t = " ";
  char *a = daemon->addrbuff, *n = cache_get_name(cache);

  /* String length is limited below */
  if (!buff && !(buff = whine_malloc(150)))
    return;
  
  p = buff;
  
  *a = 0;

  if (cache->flags & F_REVERSE)
    {
      if ((cache->flags & F_NEG))
	n = "";
    }
  else
    {
      if (strlen(n) == 0)
	n = "<Root>";
    }
  
  p += sprintf(p, "%-30.30s ", sanitise(n));
  if ((cache->flags & F_CNAME) && !is_outdated_cname_pointer(cache))
    a = sanitise(cache_get_cname_target(cache));
  else if (cache->flags & F_RR)
    {
      if (cache->flags & F_KEYTAG)
	sprintf(a, "%s", querystr(NULL, cache->addr.rrblock.rrtype));
      else
	sprintf(a, "%s", querystr(NULL, cache->addr.rrdata.rrtype));
    }
#ifdef HAVE_DNSSEC
  else if (cache->flags & F_DS)
    {
      if (!(cache->flags & F_NEG))
	sprintf(a, "%5u %3u %3u", cache->addr.ds.keytag,
		cache->addr.ds.algo, cache->addr.ds.digest);
    }
  else if (cache->flags & F_DNSKEY)
    sprintf(a, "%5u %3u %3u", cache->addr.key.keytag,
	    cache->addr.key.algo, cache->addr.key.flags);
#endif
  else if (!(cache->flags & F_NEG) || !(cache->flags & F_FORWARD))
    { 
      a = daemon->addrbuff;
      if (cache->flags & F_IPV4)
	inet_ntop(AF_INET, &cache->addr, a, ADDRSTRLEN);
      else if (cache->flags & F_IPV6)
	inet_ntop(AF_INET6, &cache->addr, a, ADDRSTRLEN);
    }
  
  if (cache->flags & F_IPV4)
    t = "4";
  else if (cache->flags & F_IPV6)
    t = "6";
  else if (cache->flags & F_CNAME)
    t = "C";
  else if (cache->flags & F_RR)
    t = "T";
#ifdef HAVE_DNSSEC
  else if (cache->flags & F_DS)
    t = "S";
  else if (cache->flags & F_DNSKEY)
    t = "K";
#endif
  else if (!(cache->flags & F_NXDOMAIN)) /* non-terminal */
    t = "!";
  
  p += sprintf(p, "%-40.40s %s%s%s%s%s%s%s%s%s%s ", a, t,
	       cache->flags & F_FORWARD ? "F" : " ",
	       cache->flags & F_REVERSE ? "R" : " ",
	       cache->flags & F_IMMORTAL ? "I" : " ",
	       cache->flags & F_DHCP ? "D" : " ",
	       cache->flags & F_NEG ? "N" : " ",
	       cache->flags & F_NXDOMAIN ? "X" : " ",
	       cache->flags & F_HOSTS ? "H" : " ",
	       cache->flags & F_CONFIG ? "C" : " ",
	       cache->flags & F_DNSSECOK ? "V" : " ");
#ifdef HAVE_BROKEN_RTC
  p += sprintf(p, "%-24lu", cache->flags & F_IMMORTAL ? 0: (unsigned long)(cache->ttd - now));
#else
  p += sprintf(p, "%-24.24s", cache->flags & F_IMMORTAL ? "" : ctime(&(cache->ttd)));
#endif
  if(cache->flags & (F_HOSTS | F_CONFIG) && cache->uid > 0)
    p += sprintf(p, " %-40.40s", record_source(cache->uid));
  
  my_syslog(LOG_INFO, "%s", buff);
}

void dump_cache(time_t now)
{
  struct server *serv, *serv1;

  my_syslog(LOG_INFO, _("time %lu"), (unsigned long)now);
  my_syslog(LOG_INFO, _("cache size %d, %d/%d cache insertions re-used unexpired cache entries."), 
	    daemon->cachesize, daemon->metrics[METRIC_DNS_CACHE_LIVE_FREED], daemon->metrics[METRIC_DNS_CACHE_INSERTED]);
  my_syslog(LOG_INFO, _("queries forwarded %u, queries answered locally %u"), 
	    daemon->metrics[METRIC_DNS_QUERIES_FORWARDED], daemon->metrics[METRIC_DNS_LOCAL_ANSWERED]);
  if (daemon->cache_max_expiry != 0)
    my_syslog(LOG_INFO, _("queries answered from stale cache %u"), daemon->metrics[METRIC_DNS_STALE_ANSWERED]);
#ifdef HAVE_AUTH
  my_syslog(LOG_INFO, _("queries for authoritative zones %u"), daemon->metrics[METRIC_DNS_AUTH_ANSWERED]);
#endif
#ifdef HAVE_DNSSEC
  my_syslog(LOG_INFO, _("DNSSEC per-query subqueries HWM %u"), daemon->metrics[METRIC_WORK_HWM]);
  my_syslog(LOG_INFO, _("DNSSEC per-query crypto work HWM %u"), daemon->metrics[METRIC_CRYPTO_HWM]);
  my_syslog(LOG_INFO, _("DNSSEC per-RRSet signature fails HWM %u"), daemon->metrics[METRIC_SIG_FAIL_HWM]);
#endif

  blockdata_report();
  my_syslog(LOG_INFO, _("child processes for TCP requests: in use %zu, highest since last SIGUSR1 %zu, max allowed %zu."),
	    daemon->metrics[METRIC_TCP_CONNECTIONS],
	    daemon->max_procs_used,
	    daemon->max_procs);
  daemon->max_procs_used = daemon->metrics[METRIC_TCP_CONNECTIONS];
  
  /* sum counts from different records for same server */
  for (serv = daemon->servers; serv; serv = serv->next)
    serv->flags &= ~SERV_MARK;
  
  for (serv = daemon->servers; serv; serv = serv->next)
    if (!(serv->flags & SERV_MARK))
      {
	int port;
	unsigned int queries = 0, failed_queries = 0, nxdomain_replies = 0, retrys = 0;
	unsigned int sigma_latency = 0, count_latency = 0;

	for (serv1 = serv; serv1; serv1 = serv1->next)
	  if (!(serv1->flags & SERV_MARK) && sockaddr_isequal(&serv->addr, &serv1->addr))
	    {
	      serv1->flags |= SERV_MARK;
	      queries += serv1->queries;
	      failed_queries += serv1->failed_queries;
	      nxdomain_replies += serv1->nxdomain_replies;
	      retrys += serv1->retrys;
	      sigma_latency += serv1->query_latency;
	      count_latency++;
	    }
	port = prettyprint_addr(&serv->addr, daemon->addrbuff);
	my_syslog(LOG_INFO, _("server %s#%d: queries sent %u, retried %u, failed %u, nxdomain replies %u, avg. latency %ums"),
		  daemon->addrbuff, port, queries, retrys, failed_queries, nxdomain_replies, sigma_latency/count_latency);
      }

  if (option_bool(OPT_DEBUG) || option_bool(OPT_LOG))
    {
      struct crec *cache;
      int i;
      my_syslog(LOG_INFO, "Host                           Address                                  Flags      Expires                  Source");
      my_syslog(LOG_INFO, "------------------------------ ---------------------------------------- ---------- ------------------------ ------------");
    
      for (i=0; i<hash_size; i++)
	for (cache = hash_table[i]; cache; cache = cache->hash_next)
	  dump_cache_entry(cache, now);
    }
}

char *record_source(unsigned int index)
{
  struct hostsfile *ah;
#ifdef HAVE_INOTIFY
  struct dyndir *dd;
#endif
  
  if (index == SRC_CONFIG)
    return "config";
  else if (index == SRC_HOSTS)
    return HOSTSFILE;

  for (ah = daemon->addn_hosts; ah; ah = ah->next)
    if (ah->index == index)
      return ah->fname;

#ifdef HAVE_INOTIFY
  /* Dynamic directories contain multiple files */
  for (dd = daemon->dynamic_dirs; dd; dd = dd->next)
    for (ah = dd->files; ah; ah = ah->next)
      if (ah->index == index)
	return ah->fname;
#endif

  return "<unknown>";
}

static char *querystr(char *desc, unsigned short type)
{
  unsigned int i;
  int len = 10; /* strlen("type=xxxxx") */
  const char *types = NULL;
  static char *buff = NULL;
  static int bufflen = 0;

  for (i = 0; i < (sizeof(typestr)/sizeof(typestr[0])); i++)
    if (typestr[i].type == type)
      {
	types = typestr[i].name;
	len = strlen(types);
	break;
      }

  if (desc)
    {
       len += 2; /* braces */
       len += strlen(desc);
    }
  len++; /* terminator */
  
  if (!buff || bufflen < len)
    {
      if (buff)
	free(buff);
      else if (len < 20)
	len = 20;
      
      buff = whine_malloc(len);
      bufflen = len;
    }

  if (buff)
    {
      if (desc)
	{
	  if (types)
	    sprintf(buff, "%s[%s]", desc, types);
	  else
	    sprintf(buff, "%s[type=%d]", desc, type);
	}
      else
	{
	  if (types)
	    sprintf(buff, "<%s>", types);
	  else
	    sprintf(buff, "<type=%d>", type);
	}
    }
  
  return buff ? buff : "";
}

static char *edestr(int ede)
{
  switch (ede)
    {
    case EDE_OTHER:                       return "other";
    case EDE_USUPDNSKEY:                  return "unsupported DNSKEY algorithm";
    case EDE_USUPDS:                      return "unsupported DS digest";
    case EDE_STALE:                       return "stale answer";
    case EDE_FORGED:                      return "forged";
    case EDE_DNSSEC_IND:                  return "DNSSEC indeterminate";
    case EDE_DNSSEC_BOGUS:                return "DNSSEC bogus";
    case EDE_SIG_EXP:                     return "DNSSEC signature expired";
    case EDE_SIG_NYV:                     return "DNSSEC sig not yet valid";
    case EDE_NO_DNSKEY:                   return "DNSKEY missing";
    case EDE_NO_RRSIG:                    return "RRSIG missing";
    case EDE_NO_ZONEKEY:                  return "no zone key bit set";
    case EDE_NO_NSEC:                     return "NSEC(3) missing";
    case EDE_CACHED_ERR:                  return "cached error";
    case EDE_NOT_READY:                   return "not ready";
    case EDE_BLOCKED:                     return "blocked";
    case EDE_CENSORED:                    return "censored";
    case EDE_FILTERED:                    return "filtered";
    case EDE_PROHIBITED:                  return "prohibited";
    case EDE_STALE_NXD:                   return "stale NXDOMAIN";
    case EDE_NOT_AUTH:                    return "not authoritative";
    case EDE_NOT_SUP:                     return "not supported";
    case EDE_NO_AUTH:                     return "no reachable authority";
    case EDE_NETERR:                      return "network error";
    case EDE_INVALID_DATA:                return "invalid data";
    case EDE_SIG_E_B_V:                   return "signature expired before valid";
    case EDE_TOO_EARLY:                   return "too early";
    case EDE_UNS_NS3_ITER:                return "unsupported NSEC3 iterations value";
    case EDE_UNABLE_POLICY:               return "uanble to conform to policy";
    case EDE_SYNTHESIZED:                 return "synthesized";
    default:                              return "unknown";
    }
}

void log_query(unsigned int flags, char *name, union all_addr *addr, char *arg, unsigned short type)
{
  char *source, *dest;
  char *verb = "is";
  char *extra = "";
  char *gap = " ";
  char portstring[7]; /* space for #<portnum> */
  char opcodestring[3]; /* maximum is 15 */

  if (!option_bool(OPT_LOG))
    return;

  /* F_NOERR is reused here to indicate logs arrising from auth queries */ 
  if (!(flags & F_NOERR) && option_bool(OPT_AUTH_LOG))
    return;

  /* build query type string if requested */
  if (!(flags & (F_SERVER | F_IPSET | F_QUERY)) && type > 0)
    arg = querystr(arg, type);

  dest = arg;

#ifdef HAVE_DNSSEC
  if ((flags & F_DNSSECOK) && option_bool(OPT_EXTRALOG))
    extra = " (DNSSEC signed)";
#endif

  name = sanitise(name);

  if (addr)
    {
      dest = daemon->addrbuff;

       if (flags & F_RR)
	 {
	   if (flags & F_KEYTAG)
	     dest = querystr(NULL, addr->rrblock.rrtype);
	   else
	     dest = querystr(NULL, addr->rrdata.rrtype);
	 }
       else if (flags & F_KEYTAG)
	sprintf(daemon->addrbuff, arg, addr->log.keytag, addr->log.algo, addr->log.digest);
      else if (flags & F_RCODE)
	{
	  unsigned int rcode = addr->log.rcode;

	  if (rcode == SERVFAIL)
	    dest = "SERVFAIL";
	  else if (rcode == REFUSED)
	    dest = "REFUSED";
	  else if (rcode == FORMERR)
	    dest = "FORMERR";
	  else if (rcode == NOTIMP)
	    dest = "not implemented";
	  else
	    sprintf(daemon->addrbuff, "%u", rcode);

	  if (addr->log.ede != EDE_UNSET)
	    {
	      extra = daemon->addrbuff;
	      sprintf(extra, " (EDE: %s)", edestr(addr->log.ede));
	    }
	}
      else if (flags & (F_IPV4 | F_IPV6))
	{
	  inet_ntop(flags & F_IPV4 ? AF_INET : AF_INET6,
		    addr, daemon->addrbuff, ADDRSTRLEN);
	  if ((flags & F_SERVER) && type != NAMESERVER_PORT)
	    {
	      extra = portstring;
	      sprintf(portstring, "#%u", type);
	    }
	}
      else
	dest = arg;
    }

  if (flags & F_REVERSE)
    {
      dest = name;
      name = daemon->addrbuff;
    }
  
  if (flags & F_NEG)
    {
      if (flags & F_NXDOMAIN)
	dest = "NXDOMAIN";
      else
	{      
	  if (flags & F_IPV4)
	    dest = "NODATA-IPv4";
	  else if (flags & F_IPV6)
	    dest = "NODATA-IPv6";
	  else
	    dest = "NODATA";
	}
    }
  else if (flags & F_CNAME)
    dest = "<CNAME>";
  else if (flags & F_RRNAME)
    dest = arg;
    
  if (flags & F_CONFIG)
    source = "config";
  else if (flags & F_DHCP)
    source = "DHCP";
  else if (flags & F_HOSTS)
    source = arg;
  else if (flags & F_UPSTREAM)
    source = "reply";
  else if (flags & F_AUTH)
    source = "auth";
  else if (flags & F_QUERY)
    source = "query";
  else if (flags & F_SECSTAT)
    {
      if (addr && addr->log.ede != EDE_UNSET && option_bool(OPT_EXTRALOG))
	{
	  extra = daemon->addrbuff;
	  sprintf(extra, " (EDE: %s)", edestr(addr->log.ede));
	}
      source = "validation";
      dest = arg;
    }
  else if (flags & F_DNSSEC)
    {
      source = arg;
      verb = "to";
    }
  else if (flags & F_SERVER)
    {
      source = "forwarded";
      verb = "to";
    }
  else if (flags & F_IPSET)
    {
      source = type ? "ipset add" : "nftset add";
      dest = name;
      name = arg;
      verb = daemon->addrbuff;
    }
  else if (flags & F_STALE)
    source = "cached-stale";
  else
    source = "cached";

  if (flags & F_QUERY)
    {
      if (flags & F_CONFIG)
	{
	  sprintf(opcodestring, "%u", type & 0xf);
	  source = "non-query opcode";
	  name = opcodestring;
	}
      else if (type > 0)
	source = querystr(source, type);
      
      verb = "from";
    }

  if (!name)
    gap = name = "";
  else if (!name[0])
    name = ".";
  
  if (option_bool(OPT_EXTRALOG))
    {
      int display_id = daemon->log_display_id;
      char *proto = "";

      if (option_bool(OPT_LOG_PROTO))
	proto = (display_id < 0) ? "TCP " : "UDP ";
      
      if (display_id < 0)
	display_id = -display_id;
      
      if (flags & F_NOEXTRA || !daemon->log_source_addr)
	my_syslog(LOG_INFO, "%s%u %s %s%s%s %s%s", proto, display_id, source, name, gap, verb, dest, extra);
      else
	{
	   int port = prettyprint_addr(daemon->log_source_addr, daemon->addrbuff2);
	   my_syslog(LOG_INFO, "%s%u %s/%u %s %s%s%s %s%s", proto, display_id, daemon->addrbuff2, port, source, name, gap, verb, dest, extra);
	}
    }
  else
    my_syslog(LOG_INFO, "%s %s%s%s %s%s", source, name, gap, verb, dest, extra);
}
