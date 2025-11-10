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
 * @file crypto.c
 * @brief Cryptographic wrapper for DNSSEC signature verification using Nettle library
 * 
 * DETAILED PURPOSE:
 * This module provides a thin abstraction layer over the Nettle cryptography library,
 * enabling DNSSEC signature validation in dnsmasq. It implements algorithm-to-digest
 * mapping, signature verification functions for multiple cryptographic algorithms
 * (RSA, ECDSA, EdDSA, GOST), and hash function selection. The module isolates all
 * cryptographic operations from the core DNSSEC validation logic in dnssec.c, providing
 * a clean interface for signature verification while handling algorithm-specific details
 * and Nettle library version compatibility.
 * 
 * KEY RESPONSIBILITIES:
 * - Provide verify() function for DNSSEC RRSIG signature validation (line 419)
 * - Implement algorithm-specific verification functions for RSA (line 140), ECDSA (line 215),
 *   EdDSA (line 341), and GOST (line 289)
 * - Map IANA DNSSEC algorithm numbers to digest algorithm names via algo_digest_name() (line 434)
 * - Map DS record digest types to hash names via ds_digest_name() (line 471)
 * - Map NSEC3 digest types to hash names via nsec3_digest_name() (line 486)
 * - Select appropriate hash function implementation via hash_find() (line 495)
 * - Provide null_hash "hash function" for EdDSA which operates on complete messages (line 65)
 * - Handle Nettle library version compatibility across versions 2.x through 3.x
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (global definitions, types, utility functions)
 * Called by: dnssec.c (DNSSEC validation module uses verify() for RRSIG validation)
 * Calls: Nettle library functions (rsa_sha256_verify_digest, ecdsa_verify, ed25519_sha512_verify, etc.)
 * 
 * DATA STRUCTURES:
 * - null_hash_ctx: Context for EdDSA null hash function tracking message length (line 56)
 * - null_hash_digest: Digest structure for EdDSA containing message buffer (line 50)
 * - Uses Nettle library structures: rsa_public_key, dsa_signature, ecc_point, etc.
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_DNSSEC: Must be defined to compile this module (line 19)
 * - Nettle version detection via NETTLE_VERSION_MAJOR/MINOR macros (line 26)
 * - MIN_VERSION macro controls feature availability (EdDSA requires 3.1+, GOST requires 3.6+)
 * 
 * THREADING/CONCURRENCY:
 * Single-threaded event-driven model. All cryptographic operations execute synchronously
 * within the main event loop. Static null_hash_buff is not thread-safe but acceptable
 * in single-threaded architecture.
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#if defined(HAVE_DNSSEC)

/* Minimal version of nettle */

/* bignum.h includes version.h and works on
   earlier releases of nettle which don't have version.h */
#include <nettle/bignum.h>
#if !defined(NETTLE_VERSION_MAJOR)
#  define NETTLE_VERSION_MAJOR 2
#  define NETTLE_VERSION_MINOR 0
#endif
#define MIN_VERSION(major, minor) ((NETTLE_VERSION_MAJOR == (major) && NETTLE_VERSION_MINOR >= (minor)) || \
				   (NETTLE_VERSION_MAJOR > (major)))

#include <nettle/rsa.h>
#include <nettle/ecdsa.h>
#include <nettle/ecc-curve.h>
#if MIN_VERSION(3, 1)
#include <nettle/eddsa.h>
#endif
#if MIN_VERSION(3, 6)
#  include <nettle/gostdsa.h>
#endif

#if MIN_VERSION(3, 1)
/* Implement a "hash-function" to the nettle API, which simply returns
   the input data, concatenated into a single, statically maintained, buffer.

   Used for the EdDSA sigs, which operate on the whole message, rather 
   than a digest. */

struct null_hash_digest
{
  uint8_t *buff;
  size_t len;
};

struct null_hash_ctx
{
  size_t len;
};

static size_t null_hash_buff_sz = 0;
static uint8_t *null_hash_buff = NULL;
#define BUFF_INCR 128

/**
 * @brief Initialize null hash context for EdDSA message buffering
 * 
 * @detailed Resets the null hash context to prepare for accumulating a new message.
 * EdDSA algorithms (Ed25519, Ed448) operate on the complete message rather than
 * a message digest, so this "hash function" simply buffers the entire input.
 * Initialization sets the accumulated message length to zero.
 * 
 * @param ctx Pointer to null_hash_ctx structure to initialize (cast from void*)
 * 
 * @note This function is part of the Nettle hash API compatibility layer
 * @see null_hash_update() for message data accumulation
 * @see null_hash_digest() for final message buffer retrieval
 * 
 * EXAMPLE USAGE:
 * @code
 * struct null_hash_ctx ctx;
 * null_hash_init(&ctx);
 * @endcode
 * 
 * RFC COMPLIANCE: Supports EdDSA signature verification per RFC 8032
 * SIDE EFFECTS: Modifies ctx->len field
 * THREAD SAFETY: Not thread-safe, assumes single-threaded event-driven architecture
 */
static void null_hash_init(void *ctx)
{
  ((struct null_hash_ctx *)ctx)->len = 0;
}

/**
 * @brief Accumulate message data into null hash buffer for EdDSA verification
 * 
 * @detailed Appends input data to the statically maintained message buffer used by
 * EdDSA signature verification. Unlike traditional hash functions that produce fixed-size
 * digests, EdDSA operates on complete messages, so this function simply concatenates
 * all input data. The buffer grows dynamically in BUFF_INCR (128 byte) increments as
 * needed. Memory allocation failures are handled gracefully via whine_malloc().
 * 
 * @param ctxv Pointer to null_hash_ctx structure (cast from void* for API compatibility)
 * @param length Number of bytes to append from src
 * @param src Source buffer containing message data to accumulate
 * 
 * @note Buffer growth uses whine_malloc which logs allocation failures
 * @warning Buffer is statically allocated, not thread-safe (acceptable for single-threaded dnsmasq)
 * @see null_hash_init() for context initialization
 * @see null_hash_digest() for final buffer retrieval
 * 
 * EXAMPLE USAGE:
 * @code
 * struct null_hash_ctx ctx;
 * null_hash_init(&ctx);
 * null_hash_update(&ctx, 10, (uint8_t*)"message123");
 * @endcode
 * 
 * RFC COMPLIANCE: Supports EdDSA message accumulation per RFC 8032
 * SIDE EFFECTS: Modifies static null_hash_buff and null_hash_buff_sz, updates ctx->len
 * THREAD SAFETY: Not thread-safe due to static buffer usage
 */
static void null_hash_update(void *ctxv, size_t length, const uint8_t *src)
{
  struct null_hash_ctx *ctx = ctxv;
  size_t new_len = ctx->len + length;
  
  if (new_len > null_hash_buff_sz)
    {
      uint8_t *new;
      
      if (!(new = whine_malloc(new_len + BUFF_INCR)))
	return;

      if (null_hash_buff)
	{
	  if (ctx->len != 0)
	    memcpy(new, null_hash_buff, ctx->len);
	  free(null_hash_buff);
	}
      
      null_hash_buff_sz = new_len + BUFF_INCR;
      null_hash_buff = new;
    }

  memcpy(null_hash_buff + ctx->len, src, length);
  ctx->len += length;
}
 
/**
 * @brief Finalize null hash and return message buffer pointer for EdDSA verification
 * 
 * @detailed Completes the null hash operation by populating the destination structure
 * with a pointer to the accumulated message buffer and its length. Unlike traditional
 * hash digest functions that copy computed digest bytes, this function simply returns
 * references to the statically maintained buffer containing the complete message.
 * The length parameter is ignored as the digest "size" is variable (the complete message).
 * 
 * @param ctx Pointer to null_hash_ctx structure containing accumulated message length
 * @param length Digest length parameter (ignored, present for API compatibility)
 * @param dst Pointer to null_hash_digest structure to populate with buffer reference
 * 
 * @note The returned buffer pointer in dst->buff points to static memory
 * @warning Buffer contents are only valid until next null_hash_init call
 * @see null_hash_init() for context initialization
 * @see null_hash_update() for message accumulation
 * 
 * EXAMPLE USAGE:
 * @code
 * struct null_hash_ctx ctx;
 * struct null_hash_digest digest;
 * null_hash_init(&ctx);
 * null_hash_update(&ctx, 10, (uint8_t*)"message123");
 * null_hash_digest(&ctx, 0, (uint8_t*)&digest);
 * // digest.buff points to "message123", digest.len == 10
 * @endcode
 * 
 * RFC COMPLIANCE: Supports EdDSA message finalization per RFC 8032
 * SIDE EFFECTS: Populates dst structure with pointers to static buffer
 * THREAD SAFETY: Not thread-safe due to static buffer usage
 */
static void null_hash_digest(void *ctx, size_t length, uint8_t *dst)
{
  (void)length;
  
  ((struct null_hash_digest *)dst)->buff = null_hash_buff;
  ((struct null_hash_digest *)dst)->len = ((struct null_hash_ctx *)ctx)->len;
}

/**
 * @brief Nettle hash API structure for EdDSA null hash implementation
 * 
 * @detailed Defines a pseudo-hash-function conforming to Nettle's hash API that
 * simply buffers complete messages for EdDSA signature verification. This structure
 * allows EdDSA algorithms to use the standard Nettle hash interface while operating
 * on complete messages rather than message digests. Fields specify context size,
 * digest size, block size (0 for non-blocked), and function pointers for init,
 * update, and digest operations.
 * 
 * Structure fields:
 * - name: "null_hash" identifier string
 * - context_size: sizeof(struct null_hash_ctx) for context allocation
 * - digest_size: sizeof(struct null_hash_digest) for result structure
 * - block_size: 0 (no block-based processing)
 * - init: null_hash_init function pointer
 * - update: null_hash_update function pointer
 * - digest: null_hash_digest function pointer
 * 
 * @note Used exclusively for EdDSA signature verification (Ed25519, Ed448)
 * @see null_hash_init(), null_hash_update(), null_hash_digest()
 * @see hash_find() which returns pointer to this structure for "null_hash" lookups
 */
static struct nettle_hash null_hash = {
  "null_hash",
  sizeof(struct null_hash_ctx),
  sizeof(struct null_hash_digest),
  0,
  (nettle_hash_init_func *) null_hash_init,
  (nettle_hash_update_func *) null_hash_update,
  (nettle_hash_digest_func *) null_hash_digest
};

#endif /* MIN_VERSION(3, 1) */

/**
 * @brief Initialize hash context and digest buffers with dynamic memory management
 * 
 * @detailed Manages memory allocation for hash context and digest buffers using
 * statically maintained pointers that grow as needed to accommodate different hash
 * algorithms. This approach avoids repeated malloc/free cycles for same-sized or
 * smaller hash operations, improving performance for repeated DNSSEC validation
 * operations. When a hash algorithm requires larger buffers than currently allocated,
 * the function reallocates with the new larger size. Returns pointers to the allocated
 * buffers via output parameters and calls the hash algorithm's init function to
 * prepare the context for use.
 * 
 * Memory management strategy:
 * - Static context and digest buffers persist across calls
 * - Buffers grow but never shrink (optimized for maximum-size requirements)
 * - Allocation only occurs when larger size needed than currently allocated
 * - Old buffers freed before allocating new larger buffers
 * 
 * @param hash Pointer to nettle_hash structure defining algorithm requirements
 * @param ctxp Output pointer to receive address of hash context buffer
 * @param digestp Output pointer to receive address of digest buffer
 * 
 * @return 1 on success (buffers allocated and hash initialized)
 * @retval 1 Hash context initialized successfully, output pointers populated
 * @retval 0 Memory allocation failed (whine_malloc returned NULL)
 * 
 * @note Static buffers not thread-safe - function must be called serially
 * @warning Returned pointers reference static memory valid until next hash_init call
 * @see hash_find() to obtain nettle_hash structure for algorithm name
 * @see verify() for usage example in signature verification flow
 * 
 * EXAMPLE USAGE:
 * @code
 * const struct nettle_hash *hash = hash_find("sha256");
 * void *ctx;
 * unsigned char *digest;
 * if (hash_init(hash, &ctx, &digest)) {
 *   hash->update(ctx, data_len, data);
 *   hash->digest(ctx, hash->digest_size, digest);
 *   // digest now contains SHA-256 hash of data
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Supports all hash algorithms required for DNSSEC per RFC 8624
 * SIDE EFFECTS: May allocate memory (persistent static buffers), calls hash->init
 * THREAD SAFETY: Not thread-safe due to static buffer usage
 */
int hash_init(const struct nettle_hash *hash, void **ctxp, unsigned char **digestp)
{
  static void *ctx = NULL;
  static unsigned char *digest = NULL;
  static unsigned int ctx_sz = 0;
  static unsigned int digest_sz = 0;

  void *new;

  if (ctx_sz < hash->context_size)
    {
      if (!(new = whine_malloc(hash->context_size)))
	return 0;
      if (ctx)
	free(ctx);
      ctx = new;
      ctx_sz = hash->context_size;
    }
  
  if (digest_sz < hash->digest_size)
    {
      if (!(new = whine_malloc(hash->digest_size)))
	return 0;
      if (digest)
	free(digest);
      digest = new;
      digest_sz = hash->digest_size;
    }

  *ctxp = ctx;
  *digestp = digest;

  hash->init(ctx);

  return 1;
}

/**
 * @brief Verify RSA signature using DNSSEC DNSKEY public key and message digest
 * 
 * @detailed Implements RSA signature verification for DNSSEC RRSIG validation supporting
 * RSASHA1 (algorithms 5 and 7), RSASHA256 (algorithm 8), and RSASHA512 (algorithm 10).
 * The function parses the RSA public key from DNSSEC wire format (exponent length followed
 * by exponent bytes followed by modulus bytes), imports both key and signature into GMP
 * multi-precision integers, and invokes the appropriate Nettle RSA verification function
 * based on the DNSSEC algorithm number. Uses static memory for key and signature structures
 * to avoid repeated allocation overhead during multiple DNSSEC validations.
 * 
 * RSA public key wire format (per RFC 3110):
 * - If first byte is non-zero: it specifies exponent length (1-255 bytes)
 * - If first byte is zero: next 2 bytes specify exponent length (big-endian)
 * - Remaining bytes: exponent bytes followed by modulus bytes
 * 
 * Algorithm mappings:
 * - Algorithm 5 (RSASHA1): Uses SHA-1 digest (legacy, deprecated)
 * - Algorithm 7 (RSASHA1-NSEC3-SHA1): Uses SHA-1 digest (NSEC3 variant)
 * - Algorithm 8 (RSASHA256): Uses SHA-256 digest (recommended)
 * - Algorithm 10 (RSASHA512): Uses SHA-512 digest (recommended for large keys)
 * 
 * @param key_data Blockdata structure containing RSA public key in DNSSEC wire format
 * @param key_len Length of key data in bytes (must be >= 3)
 * @param sig Pointer to RSA signature bytes (PKCS#1 v1.5 padded)
 * @param sig_len Length of signature in bytes (typically 128, 256, or 512 bytes)
 * @param digest Pointer to message digest computed by caller (SHA-1/256/512)
 * @param digest_len Length of digest in bytes (ignored, determined by algorithm)
 * @param algo DNSSEC algorithm number (5, 7, 8, or 10)
 * 
 * @return Signature verification result
 * @retval 1 Signature is valid (RSA verification succeeded)
 * @retval 0 Signature is invalid, key parsing failed, or memory allocation failed
 * 
 * @note Uses static memory for key and signature - not thread-safe
 * @warning Static key structure overwritten on each call - keys not preserved
 * @see verify() for high-level signature verification dispatch
 * @see algo_digest_name() for algorithm-to-digest mapping
 * 
 * EXAMPLE USAGE:
 * @code
 * struct blockdata *key = ...; // DNSKEY RDATA from DNS
 * unsigned char sig[256];      // RRSIG signature bytes
 * unsigned char digest[32];    // SHA-256 digest of signed data
 * int result = dnsmasq_rsa_verify(key, key_len, sig, 256, digest, 32, 8);
 * if (result == 1) {
 *   // Signature valid - RRSIG authenticates the RRset
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 3110 (RSA key format), RFC 4034 (DNSSEC RRSIG), RFC 8624 (algorithm status)
 * SIDE EFFECTS: Overwrites static key and sig_mpz structures, allocates on first call
 * THREAD SAFETY: Not thread-safe due to static memory reuse
 */
static int dnsmasq_rsa_verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
			      unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
  size_t exp_len;
  
  static struct rsa_public_key *key = NULL;
  static mpz_t sig_mpz;

  (void)digest_len;
  
  if (key == NULL)
    {
      if (!(key = whine_malloc(sizeof(struct rsa_public_key))))
	return 0;
      
      nettle_rsa_public_key_init(key);
      mpz_init(sig_mpz);
    }
  
  if ((key_len < 3) || !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  key_len--;
  if ((exp_len = *p++) == 0)
    {
      GETSHORT(exp_len, p);
      key_len -= 2;
    }
  
  if (exp_len >= key_len)
    return 0;
  
  key->size =  key_len - exp_len;
  mpz_import(key->e, exp_len, 1, 1, 0, 0, p);
  mpz_import(key->n, key->size, 1, 1, 0, 0, p + exp_len);

  mpz_import(sig_mpz, sig_len, 1, 1, 0, 0, sig);
  
  switch (algo)
    {
    case 5: case 7:
      return nettle_rsa_sha1_verify_digest(key, digest, sig_mpz);
    case 8:
      return nettle_rsa_sha256_verify_digest(key, digest, sig_mpz);
    case 10:
      return nettle_rsa_sha512_verify_digest(key, digest, sig_mpz);
    }

  return 0;
}  
/**
 * @brief Verify ECDSA signature using Nettle library for DNSSEC algorithms 13 and 14
 * 
 * @detailed Implements Elliptic Curve Digital Signature Algorithm (ECDSA) verification
 * for DNSSEC signing algorithms 13 (ECDSAP256SHA256) and 14 (ECDSAP384SHA384). The
 * function maintains static ECC point structures for the two supported curves (NIST P-256
 * and P-384) to avoid repeated allocation overhead. Key and signature data are imported
 * from wire format (big-endian byte arrays) into multi-precision integers (mpz_t), then
 * used to construct ECC points and DSA signature structures for Nettle's verification.
 * 
 * Algorithm 13 uses NIST P-256 curve (secp256r1) with 32-byte coordinates.
 * Algorithm 14 uses NIST P-384 curve (secp384r1) with 48-byte coordinates.
 * 
 * Wire format structure:
 * - Public key: X coordinate (t bytes) || Y coordinate (t bytes)
 * - Signature: R value (t bytes) || S value (t bytes)
 * where t = 32 for P-256, t = 48 for P-384
 * 
 * @param key_data Blockdata structure containing ECDSA public key in wire format
 * @param key_len Length of public key in bytes (must be 2*t: 64 for P-256, 96 for P-384)
 * @param sig ECDSA signature in wire format (R || S)
 * @param sig_len Length of signature in bytes (must be 2*t)
 * @param digest Message digest to verify against
 * @param digest_len Length of message digest in bytes
 * @param algo DNSSEC algorithm number (13=ECDSAP256SHA256, 14=ECDSAP384SHA384)
 * 
 * @return 1 if signature verifies correctly, 0 on verification failure or error
 * @retval 1 ECDSA signature is valid for given digest and public key
 * @retval 0 Signature invalid, unsupported algorithm, length mismatch, or allocation failure
 * 
 * @note Static ECC point structures persist across calls for performance
 * @note Nettle 3.4+ uses nettle_get_secp_256r1() accessor, earlier versions use direct struct access
 * @warning Not thread-safe due to static variable usage
 * @see dnsmasq_rsa_verify() for RSA signature verification
 * @see verify() for signature verification dispatcher calling this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Verify ECDSA P-256 signature from DNSSEC RRSIG record
 * unsigned char digest[32]; // SHA-256 hash of signed data
 * struct blockdata *pubkey = ...; // Public key from DNSKEY record
 * unsigned char *signature = ...; // Signature from RRSIG record
 * if (dnsmasq_ecdsa_verify(pubkey, 64, signature, 64, digest, 32, 13)) {
 *   // Signature valid
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements ECDSA for DNSSEC per RFC 6605 (algorithm 13, 14)
 * RFC COMPLIANCE: Algorithm recommendations per RFC 8624 (RECOMMENDED status)
 * SIDE EFFECTS: Allocates static ECC point structures on first use
 * THREAD SAFETY: Not thread-safe due to static curve point and signature structure reuse
 */
static int dnsmasq_ecdsa_verify(struct blockdata *key_data, unsigned int key_len, 
				unsigned char *sig, size_t sig_len,
				unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
  unsigned int t;
  struct ecc_point *key;

  static struct ecc_point *key_256 = NULL, *key_384 = NULL;
  static mpz_t x, y;
  static struct dsa_signature *sig_struct;
#if !MIN_VERSION(3, 4)
#define nettle_get_secp_256r1() (&nettle_secp_256r1)
#define nettle_get_secp_384r1() (&nettle_secp_384r1)
#endif
  
  if (!sig_struct)
    {
      if (!(sig_struct = whine_malloc(sizeof(struct dsa_signature))))
	return 0;
      
      nettle_dsa_signature_init(sig_struct);
      mpz_init(x);
      mpz_init(y);
    }
  
  switch (algo)
    {
    case 13:
      if (!key_256)
	{
	  if (!(key_256 = whine_malloc(sizeof(struct ecc_point))))
	    return 0;
	  
	  nettle_ecc_point_init(key_256, nettle_get_secp_256r1());
	}
      
      key = key_256;
      t = 32;
      break;
      
    case 14:
      if (!key_384)
	{
	  if (!(key_384 = whine_malloc(sizeof(struct ecc_point))))
	    return 0;
	  
	  nettle_ecc_point_init(key_384, nettle_get_secp_384r1());
	}
      
      key = key_384;
      t = 48;
      break;
        
    default:
      return 0;
    }
  
  if (sig_len != 2*t || key_len != 2*t ||
      !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  mpz_import(x, t , 1, 1, 0, 0, p);
  mpz_import(y, t , 1, 1, 0, 0, p + t);

  if (!ecc_point_set(key, x, y))
    return 0;
  
  mpz_import(sig_struct->r, t, 1, 1, 0, 0, sig);
  mpz_import(sig_struct->s, t, 1, 1, 0, 0, sig + t);
  
  return nettle_ecdsa_verify(key, digest_len, digest, sig_struct);
}

#if MIN_VERSION(3, 6)
/**
 * @brief Verify GOST R 34.10-2012 signature using Nettle library for DNSSEC algorithm 12
 * 
 * @detailed Implements GOST (Russian cryptographic standard) Digital Signature Algorithm
 * verification for DNSSEC signing algorithm 12 (ECC-GOST). The function maintains static
 * ECC point structures for the GOST GC 256B elliptic curve to avoid repeated allocation
 * overhead. Key and signature data are imported from wire format with careful attention
 * to byte ordering: public key coordinates use little-endian format (GOST convention),
 * while signature components use big-endian format (standard DSA convention). The GOST
 * curve (GC 256B) is specifically defined in Russian cryptographic standards and differs
 * from Western NIST curves.
 * 
 * Algorithm 12 uses GOST GC 256B curve with 32-byte coordinates (256-bit curve).
 * 
 * Wire format structure:
 * - Public key: X coordinate (32 bytes, little-endian) || Y coordinate (32 bytes, little-endian)
 * - Signature: S value (32 bytes, big-endian) || R value (32 bytes, big-endian)
 * 
 * Byte ordering details:
 * - mpz_import(..., -1, ...) indicates little-endian (GOST key format)
 * - mpz_import(..., 1, ...) indicates big-endian (DSA signature format)
 * 
 * @param key_data Blockdata structure containing GOST public key in wire format
 * @param key_len Length of public key in bytes (must be exactly 64 bytes)
 * @param sig GOST DSA signature in wire format (S || R)
 * @param sig_len Length of signature in bytes (must be exactly 64 bytes)
 * @param digest Message digest to verify against
 * @param digest_len Length of message digest in bytes
 * @param algo DNSSEC algorithm number (must be 12 for ECC-GOST)
 * 
 * @return 1 if signature verifies correctly, 0 on verification failure or error
 * @retval 1 GOST DSA signature is valid for given digest and public key
 * @retval 0 Signature invalid, unsupported algorithm (!= 12), length mismatch, or allocation failure
 * 
 * @note Static ECC point structure persists across calls for performance
 * @note Requires Nettle 3.6+ for GOST DSA support (MIN_VERSION(3, 6) guard)
 * @warning Not thread-safe due to static variable usage
 * @warning GOST algorithm uses different byte ordering conventions than Western standards
 * @see dnsmasq_ecdsa_verify() for ECDSA signature verification
 * @see verify() for signature verification dispatcher calling this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Verify GOST DSA signature from DNSSEC RRSIG record
 * unsigned char digest[32]; // GOST hash of signed data
 * struct blockdata *pubkey = ...; // Public key from DNSKEY record
 * unsigned char *signature = ...; // Signature from RRSIG record
 * if (dnsmasq_gostdsa_verify(pubkey, 64, signature, 64, digest, 32, 12)) {
 *   // Signature valid
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements GOST for DNSSEC per RFC 5933 (algorithm 12)
 * RFC COMPLIANCE: Algorithm recommendations per RFC 8624 (MAY status)
 * SIDE EFFECTS: Allocates static ECC point structures on first use
 * THREAD SAFETY: Not thread-safe due to static curve point and signature structure reuse
 */
static int dnsmasq_gostdsa_verify(struct blockdata *key_data, unsigned int key_len, 
				  unsigned char *sig, size_t sig_len,
				  unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
  
  static struct ecc_point *gost_key = NULL;
  static mpz_t x, y;
  static struct dsa_signature *sig_struct;

  if (algo != 12 ||
      sig_len != 64 || key_len != 64 ||
      !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  if (!sig_struct)
    {
      if (!(sig_struct = whine_malloc(sizeof(struct dsa_signature))) ||
	  !(gost_key = whine_malloc(sizeof(struct ecc_point))))
	return 0;
      
      nettle_dsa_signature_init(sig_struct);
      nettle_ecc_point_init(gost_key, nettle_get_gost_gc256b());
      mpz_init(x);
      mpz_init(y);
    }
    
  mpz_import(x, 32, -1, 1, 0, 0, p);
  mpz_import(y, 32, -1, 1, 0, 0, p + 32);

  if (!ecc_point_set(gost_key, x, y))
    return 0; 
  
  mpz_import(sig_struct->s, 32, 1, 1, 0, 0, sig);
  mpz_import(sig_struct->r, 32, 1, 1, 0, 0, sig + 32);
  
  return nettle_gostdsa_verify(gost_key, digest_len, digest, sig_struct);
}
#endif

#if MIN_VERSION(3, 1)
/**
 * @brief Verify EdDSA (Edwards-curve Digital Signature Algorithm) signatures for DNSSEC algorithms 15 and 16
 * 
 * @detailed Implements EdDSA signature verification for Ed25519 (algorithm 15) and Ed448 
 * (algorithm 16) using Nettle library cryptographic primitives. EdDSA algorithms operate on 
 * complete messages rather than message digests, which is why this function receives a 
 * null_hash_digest structure containing the full message buffer rather than a traditional hash.
 * 
 * The function performs direct signature verification without the "modified verification" approach
 * mentioned in RFC 8032 Section 8.4, as the security analysis demonstrates that an attacker capable
 * of creating collisions preserving both hash and signature would already have broken SHA-256/512,
 * which would indicate a far more fundamental cryptographic failure than DNSSEC signature forgery.
 * 
 * Algorithm characteristics:
 * - Algorithm 15 (Ed25519): 32-byte public keys, 64-byte signatures, SHA-512 based
 * - Algorithm 16 (Ed448): 57-byte public keys, 114-byte signatures, SHAKE256 based
 * 
 * EdDSA advantages for DNSSEC:
 * - Deterministic signatures (same message always produces same signature)
 * - Smaller key and signature sizes compared to RSA
 * - Constant-time operations resistant to timing attacks
 * - No requirement for high-quality randomness during signing
 * 
 * Security note from RFC 8032 Section 8.4:
 * Modified verification (re-signing to detect malicious data modifications) is not performed
 * because any attacker capable of creating a collision preserving both the hash and signature
 * would require finding arbitrary SHA-256/512 collisions in the (2^256 or 2^512)-1 space of
 * non-matching hashes, which implies a complete break of the underlying hash function.
 * 
 * @param key_data Blockdata structure containing EdDSA public key in wire format
 * @param key_len Length of public key (must be ED25519_KEY_SIZE=32 or ED448_KEY_SIZE=57)
 * @param sig EdDSA signature in wire format
 * @param sig_len Length of signature (must be ED25519_SIGNATURE_SIZE=64 or ED448_SIGNATURE_SIZE=114)
 * @param digest Pointer to null_hash_digest structure containing complete message buffer
 * @param digest_len Length of null_hash_digest structure (must be sizeof(struct null_hash_digest))
 * @param algo DNSSEC algorithm number (15 for Ed25519, 16 for Ed448)
 * 
 * @return 1 if signature verifies correctly, 0 on verification failure or error
 * @retval 1 EdDSA signature is valid for given message and public key
 * @retval 0 Signature invalid, unsupported algorithm, length mismatch, digest_len incorrect, or key retrieval failure
 * 
 * @note Ed448 support (algorithm 16) requires Nettle 3.6+ (MIN_VERSION(3, 6))
 * @note EdDSA operates on complete messages, not digests - digest parameter is null_hash_digest
 * @note Deterministic signatures prevent timing attacks and eliminate random number generator requirements
 * @warning Key and signature sizes are algorithm-specific and strictly validated
 * @warning digest_len must equal sizeof(struct null_hash_digest) for proper null_hash_digest casting
 * @see dnsmasq_ecdsa_verify() for ECDSA signature verification (works on digests)
 * @see null_hash_digest structure for EdDSA message buffering approach
 * @see verify() for signature verification dispatcher calling this function
 * 
 * EXAMPLE USAGE:
 * @code
 * // Verify Ed25519 signature from DNSSEC RRSIG record
 * struct null_hash_digest msg_digest; // Contains complete message via null_hash
 * struct blockdata *pubkey = ...; // Ed25519 public key from DNSKEY (32 bytes)
 * unsigned char *signature = ...; // Ed25519 signature from RRSIG (64 bytes)
 * if (dnsmasq_eddsa_verify(pubkey, 32, signature, 64, 
 *                          (unsigned char*)&msg_digest, sizeof(msg_digest), 15)) {
 *   // Signature valid - message authentic
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements Ed25519 per RFC 8032 (algorithm 15 in DNSSEC)
 * RFC COMPLIANCE: Implements Ed448 per RFC 8032 (algorithm 16 in DNSSEC)
 * RFC COMPLIANCE: Algorithm recommendations per RFC 8624 (RECOMMENDED status for Ed25519)
 * SIDE EFFECTS: Calls Nettle ed25519_sha512_verify or ed448_shake256_verify
 * THREAD SAFETY: Thread-safe (no static variables, read-only operations on input data)
 */
static int dnsmasq_eddsa_verify(struct blockdata *key_data, unsigned int key_len, 
				unsigned char *sig, size_t sig_len,
				unsigned char *digest, size_t digest_len, int algo)
{
  unsigned char *p;
   
  if (digest_len != sizeof(struct null_hash_digest) ||
      !(p = blockdata_retrieve(key_data, key_len, NULL)))
    return 0;
  
  /* The "digest" returned by the null_hash function is simply a struct null_hash_digest
     which has a pointer to the actual data and a length, because the buffer
     may need to be extended during "hashing". */
  
  switch (algo)
    {
    case 15:
      if (key_len != ED25519_KEY_SIZE ||
	  sig_len != ED25519_SIGNATURE_SIZE)
	return 0;

      return ed25519_sha512_verify(p,
				   ((struct null_hash_digest *)digest)->len,
				   ((struct null_hash_digest *)digest)->buff,
				   sig);
      
#if MIN_VERSION(3, 6)
    case 16:
      if (key_len != ED448_KEY_SIZE ||
	  sig_len != ED448_SIGNATURE_SIZE)
	return 0;

      return ed448_shake256_verify(p,
				   ((struct null_hash_digest *)digest)->len,
				   ((struct null_hash_digest *)digest)->buff,
				   sig);
#endif

    }

  return 0;
}
#endif

/**
 * @brief Return function pointer for signature verification function matching DNSSEC algorithm
 * 
 * @detailed Dispatches to the appropriate cryptographic signature verification function based
 * on the DNSSEC algorithm number from a DNSKEY or RRSIG record. This dispatcher serves as the
 * central routing mechanism for all DNSSEC signature verification, ensuring that each algorithm
 * type (RSA, ECDSA, GOST R 34.10-2001, EdDSA) is handled by its specialized verification
 * implementation.
 * 
 * The function first validates runtime hash algorithm support via hash_find(), ensuring that
 * the required digest algorithm is available from the Nettle library before returning the
 * verification function pointer. This prevents cryptographic operations with unavailable
 * algorithms that would fail during signature verification.
 * 
 * DNSSEC algorithm mapping (from RFC 8624):
 * - Algorithms 5, 7, 8, 10: RSA variants (RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256, RSASHA512)
 * - Algorithm 12: GOST R 34.10-2001 (requires Nettle 3.6+, limited deployment)
 * - Algorithms 13, 14: ECDSA variants (ECDSAP256SHA256, ECDSAP384SHA384)
 * - Algorithm 15: Ed25519 (requires Nettle 3.1+, RECOMMENDED in RFC 8624)
 * - Algorithm 16: Ed448 (requires Nettle 3.6+)
 * 
 * The switch statement explicitly defines supported algorithms rather than attempting runtime
 * introspection of Nettle library capabilities, providing compile-time and runtime clarity
 * about which algorithms are available in the current build.
 * 
 * @param algo DNSSEC algorithm number from DNSKEY or RRSIG record (1-255, defined in RFC 8624)
 * 
 * @return Function pointer to appropriate verification function, or NULL if algorithm unsupported
 * @retval dnsmasq_rsa_verify For RSA-based algorithms (5, 7, 8, 10)
 * @retval dnsmasq_gostdsa_verify For GOST R 34.10-2001 algorithm 12 (Nettle 3.6+)
 * @retval dnsmasq_ecdsa_verify For ECDSA algorithms (13, 14)
 * @retval dnsmasq_eddsa_verify For Ed25519 algorithm 15 (Nettle 3.1+) and Ed448 algorithm 16 (Nettle 3.6+)
 * @retval NULL Algorithm not supported, hash algorithm unavailable, or unsupported by this build
 * 
 * @note Function returns NULL rather than calling the verification function, allowing verify() to handle the call
 * @note Hash algorithm support checked via hash_find(algo_digest_name(algo)) before returning function pointer
 * @warning Unsupported algorithms return NULL - caller must check before dereferencing
 * @warning Algorithm availability depends on Nettle version (compile-time MIN_VERSION checks)
 * @see verify() for the wrapper that calls the returned function pointer
 * @see dnsmasq_rsa_verify() for RSA signature verification implementation
 * @see dnsmasq_ecdsa_verify() for ECDSA signature verification implementation
 * @see dnsmasq_gostdsa_verify() for GOST signature verification implementation
 * @see dnsmasq_eddsa_verify() for EdDSA signature verification implementation
 * @see hash_find() for hash algorithm availability checking
 * @see algo_digest_name() for algorithm-to-digest-name mapping
 * 
 * EXAMPLE USAGE:
 * @code
 * // Get verification function for DNSSEC algorithm 8 (RSASHA256)
 * int (*verify_fn)(struct blockdata*, unsigned int, unsigned char*, size_t,
 *                  unsigned char*, size_t, int);
 * verify_fn = verify_func(8);
 * if (verify_fn) {
 *   int result = (*verify_fn)(key_data, key_len, sig, sig_len, digest, digest_len, 8);
 *   // result == 1 if signature valid
 * } else {
 *   // Algorithm 8 not supported or hash unavailable
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Algorithm numbers per RFC 8624 (DNSSEC algorithm recommendations)
 * RFC COMPLIANCE: RSA algorithms per RFC 3110, RFC 5702 (algorithms 5, 7, 8, 10)
 * RFC COMPLIANCE: ECDSA algorithms per RFC 6605 (algorithms 13, 14)
 * RFC COMPLIANCE: GOST algorithm per RFC 5933 (algorithm 12)
 * RFC COMPLIANCE: EdDSA algorithms per RFC 8080 (algorithms 15, 16)
 * SIDE EFFECTS: Calls hash_find() to check digest algorithm availability
 * THREAD SAFETY: Thread-safe (no static state modified, returns const function pointers)
 */
static int (*verify_func(int algo))(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
			     unsigned char *digest, size_t digest_len, int algo)
{
    
  /* Ensure at runtime that we have support for this digest */
  if (!hash_find(algo_digest_name(algo)))
    return NULL;
  
  /* This switch defines which sig algorithms we support, can't introspect Nettle for that. */
  switch (algo)
    {
    case 5: case 7: case 8: case 10:
      return dnsmasq_rsa_verify;

#if MIN_VERSION(3, 6)
    case 12:
      return dnsmasq_gostdsa_verify;
#endif
      
    case 13: case 14:
      return dnsmasq_ecdsa_verify;
      
#if MIN_VERSION(3, 1)
    case 15:
      return dnsmasq_eddsa_verify;
#endif

#if MIN_VERSION(3, 6)
    case 16:
      return dnsmasq_eddsa_verify;
#endif
    }
  
  return NULL;
}

/**
 * @brief Verify DNSSEC signature using appropriate algorithm-specific verification function
 * 
 * @detailed This is the primary external entry point for DNSSEC signature verification in dnsmasq.
 * It acts as a convenience wrapper around verify_func(), selecting the appropriate algorithm-specific
 * verification function based on the DNSSEC algorithm number, then invoking it to validate the
 * signature against the provided digest and public key.
 * 
 * The function delegates to algorithm-specific verification implementations:
 * - Algorithms 5, 7, 8, 10: dnsmasq_rsa_verify() for RSA signatures
 * - Algorithm 12: dnsmasq_gostdsa_verify() for GOST R 34.10-2001 (Nettle 3.6+)
 * - Algorithms 13, 14: dnsmasq_ecdsa_verify() for ECDSA P-256/P-384 signatures
 * - Algorithm 15: dnsmasq_eddsa_verify() for Ed25519 (Nettle 3.1+)
 * - Algorithm 16: dnsmasq_eddsa_verify() for Ed448 (Nettle 3.6+)
 * 
 * The function returns 0 (failure) if:
 * - The algorithm number is unsupported
 * - The required hash/digest function is unavailable at runtime
 * - The signature verification fails cryptographically
 * 
 * This wrapper simplifies calling code in dnssec.c by providing a single uniform interface
 * for all signature verification operations, hiding the complexity of algorithm selection
 * and function pointer management.
 * 
 * @param key_data Blockdata structure containing public key in DNSKEY wire format
 * @param key_len Length of public key in bytes (algorithm-dependent)
 * @param sig Signature data from RRSIG record in wire format
 * @param sig_len Length of signature in bytes (algorithm-dependent)
 * @param digest Message digest or null_hash_digest structure (EdDSA uses full message)
 * @param digest_len Length of digest (algorithm-dependent, EdDSA uses sizeof(null_hash_digest))
 * @param algo DNSSEC algorithm number from RRSIG record (5-16 supported)
 * 
 * @return 1 if signature verifies correctly, 0 on failure
 * @retval 1 Signature is cryptographically valid for given digest and public key
 * @retval 0 Unsupported algorithm, hash unavailable, or signature verification failure
 * 
 * @note Called from dnssec.c during DNSSEC validation chain processing
 * @note For EdDSA algorithms (15, 16), digest parameter is struct null_hash_digest, not hash digest
 * @note Algorithm support depends on Nettle version (GOST, Ed448 require Nettle 3.6+)
 * @warning Returns 0 for unsupported algorithms - caller must distinguish from verification failure
 * 
 * @see verify_func() for algorithm-to-function-pointer mapping logic
 * @see dnsmasq_rsa_verify() for RSA signature verification implementation
 * @see dnsmasq_ecdsa_verify() for ECDSA signature verification implementation
 * @see dnsmasq_eddsa_verify() for EdDSA signature verification implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Verify RSA-SHA256 signature (algorithm 8) from dnssec.c
 * struct blockdata *pubkey = ...; // From DNSKEY record
 * unsigned char *signature = ...; // From RRSIG record
 * unsigned char digest[SHA256_DIGEST_SIZE]; // Computed hash of RRset
 * 
 * if (verify(pubkey, pubkey_len, signature, sig_len, 
 *            digest, sizeof(digest), 8)) {
 *   // Signature valid - RRset authenticated
 * } else {
 *   // Signature invalid or algorithm unsupported
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: Implements signature verification per RFC 4034 (DNSSEC resource records)
 * RFC COMPLIANCE: Algorithm support per RFC 8624 (DNSSEC algorithm recommendations)
 * SIDE EFFECTS: Calls verify_func() which checks hash availability via hash_find()
 * SIDE EFFECTS: Invokes algorithm-specific Nettle cryptographic verification functions
 * THREAD SAFETY: Thread-safe (no mutable static state, delegates to thread-safe verify functions)
 */
int verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
	   unsigned char *digest, size_t digest_len, int algo)
{

  int (*func)(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len,
	      unsigned char *digest, size_t digest_len, int algo);
  
  func = verify_func(algo);
  
  if (!func)
    return 0;

  return (*func)(key_data, key_len, sig, sig_len, digest, digest_len, algo);
}

/* Note the ds_digest_name(), algo_digest_name() and nsec3_digest_name()
   define which algo numbers we support. If algo_digest_name() returns
   non-NULL for an algorithm number, we assume that algorithm is 
   supported by verify(). */

/**
 * @brief Map DS (Delegation Signer) digest algorithm number to Nettle hash function name
 * 
 * @detailed Maps DNSSEC DS record digest algorithm numbers to the corresponding Nettle library
 * hash function name strings. DS records in the parent zone authenticate child zone DNSKEY records
 * by containing a hash (digest) of the child's public key. This function translates the numeric
 * digest algorithm identifier from the DS record's wire format into the string name required
 * by Nettle's hash_find() function for hash algorithm lookup.
 * 
 * Supported DS digest algorithms per IANA registry:
 * - Algorithm 1 (SHA-1): MUST NOT use per RFC 8624 (collision attacks demonstrated)
 * - Algorithm 2 (SHA-256): MUST implement per RFC 8624 (current standard)
 * - Algorithm 3 (GOST R 34.11-94): Regional algorithm, requires Nettle 3.6+
 * - Algorithm 4 (SHA-384): RECOMMENDED per RFC 8624 (stronger security margin)
 * 
 * Security considerations:
 * - SHA-1 (digest 1) is deprecated for DNSSEC due to demonstrated collision attacks
 * - SHA-256 (digest 2) provides 128-bit security level (2^128 collision resistance)
 * - SHA-384 (digest 4) provides 192-bit security level (2^192 collision resistance)
 * - GOST (digest 3) is primarily used in regional deployments (Russia/CIS)
 * 
 * The function returns NULL for unsupported or reserved digest algorithm numbers,
 * which will cause hash_find() to fail and the DS record validation to fail.
 * 
 * @param digest DS digest algorithm number from DS record (1-4 defined in IANA registry)
 * 
 * @return Nettle hash function name string for hash_find(), or NULL if unsupported
 * @retval "sha1" Digest algorithm 1 (SHA-1, deprecated, collision-vulnerable)
 * @retval "sha256" Digest algorithm 2 (SHA-256, MUST implement per RFC 8624)
 * @retval "gosthash94cp" Digest algorithm 3 (GOST R 34.11-94, Nettle 3.6+ only)
 * @retval "sha384" Digest algorithm 4 (SHA-384, RECOMMENDED per RFC 8624)
 * @retval NULL Unsupported or reserved digest algorithm number
 * 
 * @note Called from dnssec.c during DS record validation to select hash algorithm
 * @note Returned string is static constant - do not free or modify
 * @note SHA-1 support maintained for compatibility but deprecated per RFC 8624 Section 3.3
 * @note GOST support requires Nettle 3.6+ (MIN_VERSION(3, 6))
 * @warning Returns NULL for unsupported digest types - caller must handle validation failure
 * @warning SHA-1 is vulnerable to collision attacks - use SHA-256 or SHA-384 for new deployments
 * 
 * @see hash_find() for Nettle hash function lookup using returned name
 * @see algo_digest_name() for DNSKEY algorithm to digest name mapping
 * @see DS record format in RFC 4034 Section 5 (digest type field)
 * 
 * EXAMPLE USAGE:
 * @code
 * // Validate DS record digest (algorithm 2 = SHA-256)
 * int ds_digest_type = 2; // From DS record wire format
 * char *hash_name = ds_digest_name(ds_digest_type);
 * if (hash_name) {
 *   const struct nettle_hash *hash = hash_find(hash_name);
 *   // Use hash to compute digest of DNSKEY for comparison with DS digest
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: DS digest algorithms per RFC 4034 Section 5.1.3
 * RFC COMPLIANCE: Algorithm security recommendations per RFC 8624 Section 3.3
 * IANA REFERENCE: http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
 * SIDE EFFECTS: None (pure function, returns static string)
 * THREAD SAFETY: Thread-safe (returns static constant strings, no mutable state)
 */
/* http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml */
char *ds_digest_name(int digest)
{
  switch (digest)
    {
    case 1: return "sha1";
    case 2: return "sha256";
#if MIN_VERSION(3, 6)
    case 3: return "gosthash94cp";
#endif
    case 4: return "sha384";
    default: return NULL;
    }
}
 
/**
 * @brief Map DNSKEY algorithm number to corresponding hash digest name for signature verification
 * 
 * @detailed Converts DNSSEC algorithm identifiers from DNSKEY records into the hash digest
 *           algorithm names expected by the Nettle cryptography library. This mapping is
 *           critical for RRSIG signature verification, as the digest algorithm must match
 *           the algorithm used to create the signature. Returns NULL for deprecated algorithms
 *           (RSA/MD5, DSA/SHA1) that must not be implemented per RFC 8624, for algorithms
 *           not requiring explicit digests (EdDSA uses "null_hash" to process the entire
 *           message), and for unrecognized algorithm numbers.
 * 
 * @param algo DNSKEY algorithm number from DNSKEY record (IANA DNSSEC algorithm numbers)
 * 
 * @return String name of hash digest algorithm for Nettle library ("sha1", "sha256", "sha384",
 *         "sha512", "gosthash94cp", "null_hash"), or NULL if algorithm is deprecated, unsupported,
 *         or does not require explicit digest computation
 * @retval "sha1" Algorithm 5 (RSA/SHA1) or 7 (RSASHA1-NSEC3-SHA1)
 * @retval "sha256" Algorithm 8 (RSA/SHA-256) or 13 (ECDSAP256SHA256)
 * @retval "sha384" Algorithm 14 (ECDSAP384SHA384)
 * @retval "sha512" Algorithm 10 (RSA/SHA-512)
 * @retval "gosthash94cp" Algorithm 12 (ECC-GOST) - requires Nettle 3.6+
 * @retval "null_hash" Algorithm 15 (ED25519) or 16 (ED448) - EdDSA uses entire message, not digest
 * @retval NULL Deprecated algorithms (1=RSA/MD5, 3=DSA/SHA1, 6=DSA-NSEC3-SHA1) or unknown algorithms
 * 
 * @note Algorithm 1 (RSA/MD5) deprecated per RFC 6944 para 2.3 - must not implement
 * @note Algorithm 3 (DSA/SHA1) and 6 (DSA-NSEC3-SHA1) deprecated per RFC 8624 section 3.1
 * @note EdDSA algorithms (15, 16) return "null_hash" because EdDSA operates on entire message
 * @note GOST algorithm (12) only available with Nettle 3.6 or later
 * @note ED448 algorithm (16) only available with Nettle 3.6 or later
 * 
 * @warning Returning NULL for deprecated algorithms prevents their use in DNSSEC validation,
 *          enforcing security policy against weak cryptographic algorithms
 * 
 * @see verify() for usage in algorithm selection during RRSIG verification
 * @see hash_find() for converting digest name string to Nettle hash function structure
 * 
 * EXAMPLE USAGE:
 * @code
 * // Select hash algorithm for DNSSEC signature verification
 * int dnskey_algo = 8;  // RSA/SHA-256
 * char *digest_name = algo_digest_name(dnskey_algo);
 * if (digest_name) {
 *   const struct nettle_hash *hash = hash_find(digest_name);
 *   // Use hash for RRSIG verification
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: IANA DNSSEC Algorithm Numbers registry
 *                 RFC 8624 (DNSSEC algorithm implementation recommendations)
 *                 RFC 6944 (RSA/MD5 deprecation)
 * SIDE EFFECTS: None - pure lookup function
 * THREAD SAFETY: Thread-safe (returns pointer to static string literals)
 * 
 * SOURCE: http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
 */
/* http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml */
char *algo_digest_name(int algo)
{
  switch (algo)
    {
    case 1: return NULL;          /* RSA/MD5 - Must Not Implement.  RFC 6944 para 2.3. */
    case 2: return NULL;          /* Diffie-Hellman */
    case 3: return NULL; ;        /* DSA/SHA1 - Must Not Implement. RFC 8624 section 3.1 */ 
    case 5: return "sha1";        /* RSA/SHA1 */
    case 6: return NULL;          /* DSA-NSEC3-SHA1 - Must Not Implement. RFC 8624 section 3.1 */
    case 7: return "sha1";        /* RSASHA1-NSEC3-SHA1 */
    case 8: return "sha256";      /* RSA/SHA-256 */
    case 10: return "sha512";     /* RSA/SHA-512 */
#if MIN_VERSION(3, 6)
    case 12: return "gosthash94cp"; /* ECC-GOST */ 
#endif
    case 13: return "sha256";     /* ECDSAP256SHA256 */
    case 14: return "sha384";     /* ECDSAP384SHA384 */ 	
#if MIN_VERSION(3, 1)
    case 15: return "null_hash";  /* ED25519 */
#  if MIN_VERSION(3, 6)
    case 16: return "null_hash";  /* ED448 */
#  endif
#endif
    default: return NULL;
    }
}
  
/**
 * @brief Map NSEC3 hash algorithm number to corresponding digest name for NSEC3 hash computation
 * 
 * @detailed Converts NSEC3 hash algorithm identifiers from NSEC3 records into hash digest
 *           algorithm names expected by the Nettle cryptography library. NSEC3 provides
 *           authenticated denial of existence in DNSSEC by hashing owner names before
 *           including them in the zone. This function maps the hash algorithm field from
 *           NSEC3 records to the corresponding Nettle hash function name. Currently, only
 *           SHA-1 (algorithm 1) is defined in the IANA registry and supported by this
 *           implementation. Returns NULL for unrecognized or unsupported algorithm numbers.
 * 
 * @param digest NSEC3 hash algorithm number from NSEC3 record (IANA DNSSEC NSEC3 hash algorithm)
 * 
 * @return String name of hash digest algorithm for Nettle library ("sha1"), or NULL if
 *         algorithm is unrecognized or unsupported
 * @retval "sha1" Algorithm 1 (SHA-1) - currently the only defined NSEC3 hash algorithm
 * @retval NULL Any algorithm other than 1 (unsupported or unrecognized)
 * 
 * @note SHA-1 is currently the only IANA-assigned NSEC3 hash algorithm despite being
 *       deprecated for signature verification - NSEC3 hash collisions have different
 *       security implications than signature collisions
 * @note NSEC3 iteration count limits (DNSSEC_LIMIT_NSEC3_ITERS in config.h) provide
 *       additional protection against computational DoS attacks
 * 
 * @warning Future NSEC3 hash algorithms require code updates to this function to support
 *          them in NSEC3 validation
 * 
 * @see hash_find() for converting digest name string to Nettle hash function structure
 * @see dnssec.c NSEC3 validation functions for usage context
 * 
 * EXAMPLE USAGE:
 * @code
 * // Select hash algorithm for NSEC3 hash computation
 * int nsec3_algo = 1;  // SHA-1
 * char *digest_name = nsec3_digest_name(nsec3_algo);
 * if (digest_name) {
 *   const struct nettle_hash *hash = hash_find(digest_name);
 *   // Use hash for NSEC3 owner name hashing
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: IANA DNSSEC NSEC3 Hash Algorithms registry
 *                 RFC 5155 (NSEC3 specification)
 * SIDE EFFECTS: None - pure lookup function
 * THREAD SAFETY: Thread-safe (returns pointer to static string literals)
 * 
 * SOURCE: http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml
 */
/* http://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml */
char *nsec3_digest_name(int digest)
{
  switch (digest)
    {
    case 1: return "sha1";
    default: return NULL;
    }
}

/**
 * @brief Find Nettle hash function structure by algorithm name
 * 
 * @detailed Looks up and returns a pointer to the Nettle library hash function structure
 *           corresponding to the specified algorithm name. This function serves as the
 *           bridge between dnsmasq's string-based hash algorithm names (returned by
 *           algo_digest_name(), ds_digest_name(), and nsec3_digest_name()) and the
 *           Nettle library's hash function implementations. The function handles three
 *           lookup scenarios: (1) the special "null_hash" for EdDSA algorithms that
 *           operate on entire messages rather than digests, (2) Nettle 3.4+ using the
 *           nettle_lookup_hash() API which avoids ABI incompatibilities, and (3) older
 *           Nettle versions using direct iteration over the nettle_hashes[] array. The
 *           returned structure contains function pointers for hash initialization,
 *           update, and digest operations used throughout DNSSEC validation.
 * 
 * @param name String name of hash algorithm ("sha1", "sha256", "sha384", "sha512",
 *             "gosthash94cp", "null_hash"), or NULL
 * 
 * @return Pointer to Nettle hash function structure, or NULL if algorithm name is NULL,
 *         unrecognized, or not supported by the linked Nettle library version
 * @retval &null_hash For "null_hash" algorithm (EdDSA message processing) - Nettle 3.1+
 * @retval struct_nettle_hash* For recognized hash algorithms supported by Nettle library
 * @retval NULL If name is NULL, algorithm unrecognized, or not supported by Nettle version
 * 
 * @note Nettle 3.4+ uses nettle_lookup_hash() API to avoid ABI incompatibilities when
 *       sizeof(nettle_hashes) changes between library versions
 * @note Nettle 3.1-3.3 uses direct iteration over nettle_hashes[] array for lookup
 * @note "null_hash" is a dnsmasq-provided pseudo-hash for EdDSA that returns input data
 *       as digest without transformation
 * 
 * @warning NULL name parameter returns NULL immediately without error - callers should
 *          validate algo_digest_name() return values before calling hash_find()
 * @warning Hash function availability depends on Nettle library version and compile-time
 *          configuration - some algorithms may not be available on all systems
 * 
 * @see algo_digest_name() for DNSSEC algorithm to hash name mapping
 * @see ds_digest_name() for DS digest algorithm to hash name mapping
 * @see nsec3_digest_name() for NSEC3 hash algorithm to hash name mapping
 * @see null_hash_init() for EdDSA null hash implementation
 * 
 * EXAMPLE USAGE:
 * @code
 * // Lookup hash function for DNSSEC signature verification
 * char *digest_name = algo_digest_name(8);  // RSA/SHA-256
 * const struct nettle_hash *hash = hash_find(digest_name);
 * if (hash) {
 *   void *hash_ctx = safe_malloc(hash->context_size);
 *   hash->init(hash_ctx);
 *   hash->update(hash_ctx, data_len, data);
 *   hash->digest(hash_ctx, hash->digest_size, digest_buffer);
 *   free(hash_ctx);
 * }
 * @endcode
 * 
 * RFC COMPLIANCE: N/A (Nettle library interface function)
 * SIDE EFFECTS: None - pure lookup function
 * THREAD SAFETY: Thread-safe (read-only access to static hash function structures)
 */
/* Find pointer to correct hash function in nettle library */
const struct nettle_hash *hash_find(char *name)
{
  if (!name)
    return NULL;
  
#if MIN_VERSION(3,1) && defined(HAVE_DNSSEC)
  /* We provide a "null" hash which returns the input data as digest. */
  if (strcmp(null_hash.name, name) == 0)
    return &null_hash;
#endif
  
  /* libnettle >= 3.4 provides nettle_lookup_hash() which avoids nasty ABI
     incompatibilities if sizeof(nettle_hashes) changes between library
     versions. */
#if MIN_VERSION(3, 4)
  return nettle_lookup_hash(name);
#else
  {
    int i;

    for (i = 0; nettle_hashes[i]; i++)
      if (strcmp(nettle_hashes[i]->name, name) == 0)
	return nettle_hashes[i];
  }
  
  return NULL;
#endif
}

#endif /* defined(HAVE_DNSSEC) */
