# DNSSEC Validation in dnsmasq

## Table of Contents

1. [Overview](#overview)
2. [DNSSEC Architecture](#dnssec-architecture)
3. [Trust Chain Validation](#trust-chain-validation)
4. [RRset Canonicalization](#rrset-canonicalization)
5. [Signature Verification](#signature-verification)
6. [NSEC Proof Validation](#nsec-proof-validation)
7. [NSEC3 Proof Validation](#nsec3-proof-validation)
8. [Trust Anchor Management](#trust-anchor-management)
9. [Validation Limits and DoS Protection](#validation-limits-and-dos-protection)
10. [Validation States](#validation-states)
11. [Cryptographic Library Integration](#cryptographic-library-integration)
12. [Configuration and Integration](#configuration-and-integration)
13. [See Also](#see-also)

## Overview

DNSSEC (Domain Name System Security Extensions) validation in dnsmasq provides cryptographic authentication of DNS responses to protect against cache poisoning, man-in-the-middle attacks, and DNS spoofing. The implementation conforms to RFC 4033 (DNSSEC Introduction), RFC 4034 (Resource Records), and RFC 4035 (Protocol Modifications).

**Purpose**: Verify the authenticity and integrity of DNS responses using digital signatures, ensuring that DNS data has not been tampered with during transit and originates from the authoritative source.

**Key Capabilities**:
- Complete DNSSEC validation chain from root zone to target domain
- Support for RRSIG signature verification using RSA, ECDSA, EdDSA, and GOST algorithms
- NSEC and NSEC3 authenticated denial-of-existence proof validation
- Trust anchor management with root zone KSK validation
- DoS protection through configurable validation limits
- Integration with Nettle cryptography library for signature operations

**Implementation Location**: The DNSSEC validation logic is implemented primarily in `src/dnssec.c` (cryptographic validation) and `src/crypto.c` (cryptographic primitives using Nettle library).

## DNSSEC Architecture

### High-Level Validation Flow

The DNSSEC validation process in dnsmasq follows a hierarchical trust chain from the DNS root zone down to the target domain:

```mermaid
flowchart TD
    Start[Receive DNS Response] --> CheckDO{DO bit set<br/>in query?}
    CheckDO -->|No| NoValidation[Skip DNSSEC<br/>validation]
    CheckDO -->|Yes| CheckRRSIG{RRSIG present<br/>in response?}
    
    CheckRRSIG -->|No| CheckUnsigned{Unsigned zone<br/>expected?}
    CheckUnsigned -->|Yes| Insecure[Return INSECURE]
    CheckUnsigned -->|No| Bogus[Return BOGUS<br/>SERVFAIL to client]
    
    CheckRRSIG -->|Yes| ValidateRRset[Validate RRset<br/>validate_rrset]
    
    ValidateRRset --> Canonicalize[Canonicalize RRset<br/>Sort and normalize]
    Canonicalize --> ComputeDigest[Compute digest<br/>of canonical form]
    ComputeDigest --> GetDNSKEY[Retrieve cached<br/>DNSKEY]
    
    GetDNSKEY --> CheckDNSKEY{DNSKEY<br/>trusted?}
    CheckDNSKEY -->|No| ValidateDNSKEY[Validate DNSKEY<br/>against DS]
    ValidateDNSKEY --> CheckDS{DS record<br/>exists?}
    
    CheckDS -->|No| CheckTrustAnchor{Trust anchor<br/>for zone?}
    CheckTrustAnchor -->|Yes| Secure[Return SECURE]
    CheckTrustAnchor -->|No| Insecure2[Return INSECURE]
    
    CheckDS -->|Yes| ValidateDS[Compute DS digest<br/>Compare with cached DS]
    ValidateDS --> DSMatch{DS digest<br/>matches?}
    DSMatch -->|No| Bogus2[Return BOGUS]
    DSMatch -->|Yes| CacheDNSKEY[Cache trusted<br/>DNSKEY]
    
    CheckDNSKEY -->|Yes| VerifySignature[Verify RRSIG<br/>using DNSKEY]
    CacheDNSKEY --> VerifySignature
    
    VerifySignature --> SigValid{Signature<br/>valid?}
    SigValid -->|No| Bogus3[Return BOGUS]
    SigValid -->|Yes| CheckExpiry{RRSIG within<br/>validity period?}
    
    CheckExpiry -->|No| Bogus4[Return BOGUS]
    CheckExpiry -->|Yes| Secure2[Return SECURE<br/>Cache validated data]
    
    style Start fill:#e1f5ff
    style Secure fill:#90EE90
    style Secure2 fill:#90EE90
    style Insecure fill:#FFD700
    style Insecure2 fill:#FFD700
    style Bogus fill:#FF6B6B
    style Bogus2 fill:#FF6B6B
    style Bogus3 fill:#FF6B6B
    style Bogus4 fill:#FF6B6B
```

### Validation Entry Point

The main entry point for DNSSEC validation is `dnssec_validate_reply()` in `src/dnssec.c`. This function is invoked for every DNS response when DNSSEC validation is enabled (compile-time flag `HAVE_DNSSEC` and runtime option `--dnssec`).

**Function**: `dnssec_validate_reply(time_t now, struct dns_header *header, size_t plen, char *name, ...)`
**Source**: `src/dnssec.c` (primary validation orchestrator)
**Purpose**: Validate all RRsets in a DNS response, verify signatures, and determine the security status of the response (SECURE, INSECURE, or BOGUS).

**Validation Workflow**:
1. Check if DNSSEC is requested (DO bit set in original query)
2. Extract all RRsets and associated RRSIGs from the response
3. For each RRset, invoke `validate_rrset()` to verify signatures
4. Validate DNSKEY records against DS records in parent zones
5. Follow the chain of trust to root zone trust anchors
6. Handle NSEC/NSEC3 proofs for non-existent names or types
7. Return validation status and cache validated data

## Trust Chain Validation

### DNSKEY → DS → RRSIG Verification Process

DNSSEC establishes a chain of trust from the root zone (whose trust anchors are pre-configured) down to the target domain through a series of cryptographic validations:

```mermaid
graph TB
    subgraph "Root Zone (.)"
        RootTrustAnchor[Trust Anchor<br/>DS records in<br/>trust-anchors.conf]
        RootDNSKEY[Root Zone DNSKEY]
    end
    
    subgraph "TLD Zone (.com)"
        TLD_DS[.com DS record]
        TLD_DNSKEY[.com DNSKEY]
        TLD_RRSIG[RRSIG over .com DS]
    end
    
    subgraph "Second-Level Domain (example.com)"
        SLD_DS[example.com DS record]
        SLD_DNSKEY[example.com DNSKEY]
        SLD_RRSIG[RRSIG over example.com DS]
    end
    
    subgraph "Target Domain (www.example.com)"
        Target_A[www.example.com A record]
        Target_RRSIG[RRSIG over A record]
    end
    
    RootTrustAnchor -.->|Validates| RootDNSKEY
    RootDNSKEY -->|Signs| TLD_RRSIG
    TLD_RRSIG -.->|Verifies| TLD_DS
    TLD_DS -.->|Validates| TLD_DNSKEY
    
    TLD_DNSKEY -->|Signs| SLD_RRSIG
    SLD_RRSIG -.->|Verifies| SLD_DS
    SLD_DS -.->|Validates| SLD_DNSKEY
    
    SLD_DNSKEY -->|Signs| Target_RRSIG
    Target_RRSIG -.->|Verifies| Target_A
    
    style RootTrustAnchor fill:#90EE90
    style RootDNSKEY fill:#FFD700
    style TLD_DS fill:#87CEEB
    style TLD_DNSKEY fill:#FFD700
    style SLD_DS fill:#87CEEB
    style SLD_DNSKEY fill:#FFD700
    style Target_A fill:#FFA07A
```

### Trust Chain Components

**1. Trust Anchors (Root of Trust)**

Trust anchors are the starting point of DNSSEC validation. Dnsmasq uses pre-configured DS records for the DNS root zone (`.`) stored in `trust-anchors.conf`.

**File**: `trust-anchors.conf`
**Current Trust Anchors** (as of July 2024):
```
. DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
```

This DS record represents the Key Signing Key (KSK) for the root zone. The fields are:
- **20326**: Key tag (identifier for the DNSKEY)
- **8**: Algorithm (8 = RSA/SHA-256)
- **2**: Digest type (2 = SHA-256)
- **E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D**: Digest of the root zone DNSKEY

**2. DNSKEY Records**

DNSKEY records contain public keys used to verify RRSIG signatures. There are two types:
- **Zone Signing Key (ZSK)**: Used to sign zone data (A, AAAA, CNAME, etc.)
- **Key Signing Key (KSK)**: Used to sign the DNSKEY RRset itself (represented by DS in parent zone)

**3. DS Records (Delegation Signer)**

DS records in the parent zone contain a hash of the child zone's DNSKEY. This creates the cryptographic link between parent and child zones in the trust chain.

**Validation Process** in `src/dnssec.c`:
```c
// Validate DNSKEY against DS record (simplified)
// Source: src/dnssec.c, validate_rrset() function

1. Retrieve cached DS record from parent zone
2. Compute digest of child zone DNSKEY using specified hash algorithm
3. Compare computed digest with DS record digest
4. If match: DNSKEY is trusted, cache it for future validations
5. If mismatch: Return BOGUS status
```

**4. RRSIG Records (Resource Record Signature)**

RRSIG records contain digital signatures over RRsets (sets of resource records with the same name and type). Each RRSIG includes:
- **Type Covered**: RR type being signed (e.g., A, AAAA)
- **Algorithm**: Cryptographic algorithm used (RSA, ECDSA, EdDSA)
- **Labels**: Number of labels in the original owner name
- **Original TTL**: TTL of the signed RRset
- **Signature Expiration**: Validity end time
- **Signature Inception**: Validity start time
- **Key Tag**: Identifier of the DNSKEY that created the signature
- **Signer's Name**: Domain name of the zone that created the signature
- **Signature**: The actual cryptographic signature

### Validation Sequence

The validation sequence follows this pattern for each domain level:

```mermaid
sequenceDiagram
    participant Client as DNS Client
    participant Dnsmasq as dnsmasq
    participant Cache as DNS Cache
    participant Upstream as Upstream DNS
    participant Crypto as Nettle Crypto
    
    Client->>Dnsmasq: Query www.example.com A (DO bit set)
    Dnsmasq->>Cache: Check for cached validated A record
    Cache-->>Dnsmasq: Cache miss
    
    Dnsmasq->>Upstream: Forward query with DO bit
    Upstream-->>Dnsmasq: Response with A, RRSIG, DNSKEY, DS records
    
    Note over Dnsmasq: Start DNSSEC validation
    
    Dnsmasq->>Dnsmasq: Extract www.example.com A RRset + RRSIG
    Dnsmasq->>Cache: Get example.com DNSKEY
    
    alt DNSKEY not trusted
        Dnsmasq->>Cache: Get example.com DS from .com
        Dnsmasq->>Dnsmasq: Compute digest of DNSKEY
        Dnsmasq->>Dnsmasq: Compare digest with DS
        
        alt DS matches
            Dnsmasq->>Dnsmasq: Validate .com DNSKEY against root DS
            Dnsmasq->>Cache: Get root DNSKEY
            Dnsmasq->>Dnsmasq: Compare root DNSKEY with trust anchor
            
            alt Trust anchor validates
                Note over Dnsmasq: Trust chain complete
            else Trust anchor fails
                Dnsmasq->>Client: SERVFAIL (BOGUS)
            end
        else DS mismatch
            Dnsmasq->>Client: SERVFAIL (BOGUS)
        end
    end
    
    Dnsmasq->>Dnsmasq: Canonicalize A RRset
    Dnsmasq->>Dnsmasq: Compute digest of canonical form
    Dnsmasq->>Crypto: Verify RRSIG signature
    Crypto-->>Dnsmasq: Signature valid
    
    Dnsmasq->>Dnsmasq: Check RRSIG validity period
    
    alt Valid signature and time
        Dnsmasq->>Cache: Cache validated A record (SECURE)
        Dnsmasq->>Client: Return A record (authenticated)
    else Invalid signature
        Dnsmasq->>Client: SERVFAIL (BOGUS)
    end
```

## RRset Canonicalization

Before signature verification, the RRset (Resource Record Set) must be converted to a canonical form exactly as it was when the signature was created. This ensures that signature verification works correctly regardless of case variations or record ordering.

**Source**: `src/dnssec.c`, `validate_rrset()` function (canonicalization logic integrated into validation)

### Canonicalization Steps

**1. Name Canonicalization**
- Convert all domain names to lowercase
- Preserve wire format (no textual conversion)
- Example: `Example.COM` → `example.com`

**2. RRset Sorting**
- Sort resource records within the RRset in canonical order
- Sorting is based on wire-format RDATA (resource data) comparison
- Required by RFC 4034 Section 6.3

**3. RDATA Normalization**
- Ensure consistent field ordering for multi-field records
- Normalize domain names within RDATA (e.g., CNAME targets, MX hostnames)

**4. Canonical RR Form Construction**
```
RRSIG_RDATA = {
    Type Covered (2 octets)
    Algorithm (1 octet)
    Labels (1 octet)
    Original TTL (4 octets)
    Signature Expiration (4 octets)
    Signature Inception (4 octets)
    Key Tag (2 octets)
    Signer's Name (variable)
}

For each RR in RRset (sorted order):
    RR_WIRE_FORMAT = {
        Owner Name (canonical, wire format)
        Type (2 octets)
        Class (2 octets)
        TTL (Original TTL from RRSIG, not current TTL)
        RDLENGTH (2 octets)
        RDATA (canonical form)
    }

CANONICAL_FORM = RRSIG_RDATA || RR_WIRE_FORMAT[0] || RR_WIRE_FORMAT[1] || ...
```

**5. Digest Computation**
- Compute cryptographic hash (SHA-1, SHA-256, SHA-384, SHA-512) of canonical form
- Hash algorithm determined by RRSIG algorithm field
- Example: RSA/SHA-256 (algorithm 8) uses SHA-256 hash

### Canonicalization Example

**Original RRset**:
```
WWW.EXAMPLE.COM.  300  IN  A  192.0.2.1
www.Example.com.  300  IN  A  192.0.2.2
```

**Canonical Form**:
```
www.example.com.  3600  IN  A  192.0.2.1
www.example.com.  3600  IN  A  192.0.2.2
```
(Note: Owner names lowercased, records sorted, Original TTL from RRSIG used)

**Implementation Detail** (from `src/dnssec.c`):

The canonicalization process is integrated into `validate_rrset()`:

```c
// Simplified canonicalization logic
// Source: src/dnssec.c, validate_rrset()

// 1. Extract RRSIG fields (type covered, algorithm, original TTL, etc.)
// 2. Build canonical RRset by sorting records
// 3. For each record:
//    - Convert owner name to lowercase wire format
//    - Use original TTL from RRSIG (not current TTL)
//    - Append RDATA in canonical form
// 4. Compute digest of concatenated canonical form
// 5. Pass digest and signature to verify() function
```

## Signature Verification

Signature verification is the cryptographic heart of DNSSEC validation, confirming that RRset data has not been modified and was signed by the legitimate zone operator.

**Source**: `src/crypto.c` (cryptographic operations using Nettle library)

### Verification Flow

```mermaid
flowchart LR
    A[Canonical RRset] --> B[Compute Digest]
    B --> C[Hash Algorithm<br/>SHA-1/SHA-256/SHA-384/SHA-512]
    C --> D[Digest]
    
    E[RRSIG Signature] --> F[Extract Algorithm]
    F --> G{Algorithm Type}
    
    H[DNSKEY Public Key] --> G
    D --> G
    
    G -->|RSA| I[RSA Verify<br/>dnsmasq_rsa_verify]
    G -->|ECDSA| J[ECDSA Verify<br/>dnsmasq_ecdsa_verify]
    G -->|EdDSA| K[EdDSA Verify<br/>dnsmasq_eddsa_verify]
    G -->|GOST| L[GOST Verify<br/>dnsmasq_gostdsa_verify]
    
    I --> M{Signature Valid?}
    J --> M
    K --> M
    L --> M
    
    M -->|Yes| N[Validation Success]
    M -->|No| O[Validation Failure<br/>BOGUS]
    
    style N fill:#90EE90
    style O fill:#FF6B6B
```

### Supported Algorithms

Dnsmasq supports the following DNSSEC algorithms through the Nettle cryptography library:

| Algorithm Number | Algorithm Name | Hash Function | Implementation |
|-----------------|----------------|---------------|----------------|
| 5 | RSA/SHA-1 | SHA-1 | `dnsmasq_rsa_verify` |
| 7 | RSASHA1-NSEC3-SHA1 | SHA-1 | `dnsmasq_rsa_verify` |
| 8 | RSA/SHA-256 | SHA-256 | `dnsmasq_rsa_verify` |
| 10 | RSA/SHA-512 | SHA-512 | `dnsmasq_rsa_verify` |
| 13 | ECDSA P-256/SHA-256 | SHA-256 | `dnsmasq_ecdsa_verify` |
| 14 | ECDSA P-384/SHA-384 | SHA-384 | `dnsmasq_ecdsa_verify` |
| 15 | Ed25519 | SHA-512 | `dnsmasq_eddsa_verify` |
| 16 | Ed448 | SHAKE256 | `dnsmasq_eddsa_verify` |
| 12 | GOST R 34.10-2012 | GOST R 34.11-2012 | `dnsmasq_gostdsa_verify` |

### Verification Implementation

**Main Verification Entry Point**: `verify(int algo, char *key, int keylen, unsigned char *sig, int siglen, unsigned char *digest, size_t digest_len, int algo_digest_len)`

**Source**: `src/crypto.c`, lines 400-550

**Purpose**: Dispatcher function that selects the appropriate algorithm-specific verification function and performs signature validation.

**Algorithm Selection**:
```c
// Source: src/crypto.c, verify_func()
// Returns function pointer to algorithm-specific verifier

static int (*verify_func(int algo))(struct blockdata *key_data, ...)
{
  switch (algo)
    {
    case 5: case 7: case 8: case 10:
      return dnsmasq_rsa_verify;    // RSA variants
    case 12:
      return dnsmasq_gostdsa_verify; // GOST
    case 13: case 14:
      return dnsmasq_ecdsa_verify;   // ECDSA variants
    case 15: case 16:
      return dnsmasq_eddsa_verify;   // EdDSA variants
    default:
      return NULL;                    // Unsupported algorithm
    }
}
```

### RSA Verification

**Function**: `dnsmasq_rsa_verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len, unsigned char *digest, size_t digest_len, int algo)`

**Source**: `src/crypto.c`, lines 100-150

**Supported Variants**:
- **Algorithm 5**: RSA/SHA-1 (legacy, being phased out)
- **Algorithm 8**: RSA/SHA-256 (most common)
- **Algorithm 10**: RSA/SHA-512 (high security)

**Implementation Details**:
```c
// Simplified RSA verification logic
// Source: src/crypto.c, dnsmasq_rsa_verify()

1. Parse RSA public key from DNSKEY RDATA
   - Extract public exponent (e)
   - Extract modulus (n)
   
2. Initialize Nettle RSA public key structure
   rsa_public_key_init(&key);
   
3. Import public key components
   mpz_import(key.e, ...);  // Import exponent
   mpz_import(key.n, ...);  // Import modulus
   
4. Select hash algorithm based on RRSIG algorithm field
   - Algorithm 5/7: SHA-1
   - Algorithm 8: SHA-256
   - Algorithm 10: SHA-512
   
5. Verify signature
   result = rsa_<hash>_verify_digest(&key, digest, sig);
   
6. Clean up
   rsa_public_key_clear(&key);
   
7. Return result (1 = valid, 0 = invalid)
```

### ECDSA Verification

**Function**: `dnsmasq_ecdsa_verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len, unsigned char *digest, int algo)`

**Source**: `src/crypto.c`, lines 150-250

**Supported Curves**:
- **Algorithm 13**: ECDSA P-256 with SHA-256
- **Algorithm 14**: ECDSA P-384 with SHA-384

**Implementation Details**:
```c
// Simplified ECDSA verification logic
// Source: src/crypto.c, dnsmasq_ecdsa_verify()

1. Select elliptic curve based on algorithm
   if (algo == 13)
     ecc_curve = nettle_get_secp_256r1();  // P-256
   else if (algo == 14)
     ecc_curve = nettle_get_secp_384r1();  // P-384
   
2. Parse public key point (X, Y coordinates) from DNSKEY
   
3. Initialize ECC point structure
   ecc_point_init(&key_point, ecc_curve);
   
4. Import public key coordinates
   ecc_point_set(&key_point, X, Y);
   
5. Parse signature (R, S components)
   
6. Verify signature
   result = ecdsa_verify(&key_point, digest_len, digest, &signature);
   
7. Clean up
   ecc_point_clear(&key_point);
   
8. Return result
```

### EdDSA Verification

**Function**: `dnsmasq_eddsa_verify(struct blockdata *key_data, unsigned int key_len, unsigned char *sig, size_t sig_len, unsigned char *digest, size_t digest_len, int algo)`

**Source**: `src/crypto.c`, lines 250-350

**Supported Algorithms**:
- **Algorithm 15**: Ed25519 (32-byte keys, 64-byte signatures)
- **Algorithm 16**: Ed448 (57-byte keys, 114-byte signatures)

**Implementation Details**:
```c
// Simplified EdDSA verification logic
// Source: src/crypto.c, dnsmasq_eddsa_verify()

1. Select EdDSA variant
   if (algo == 15)
     // Ed25519: 32-byte key, 64-byte signature
   else if (algo == 16)
     // Ed448: 57-byte key, 114-byte signature
   
2. Extract public key from DNSKEY RDATA
   
3. Verify signature using Nettle EdDSA functions
   if (algo == 15)
     result = ed25519_sha512_verify(key, digest_len, digest, sig);
   else
     result = ed448_shake256_verify(key, digest_len, digest, sig);
   
4. Return result
```

### Signature Validity Period Check

In addition to cryptographic verification, DNSSEC requires time-based validity checks:

```c
// Source: src/dnssec.c, validate_rrset()
// Check RRSIG inception and expiration times

// RRSIG fields (from wire format):
// - signature_inception: Start of validity period (Unix timestamp)
// - signature_expiration: End of validity period (Unix timestamp)

current_time = time(NULL);

if (current_time < signature_inception)
  return STAT_BOGUS;  // Signature not yet valid

if (current_time >= signature_expiration)
  return STAT_BOGUS;  // Signature expired

// Proceed with cryptographic verification
```

## NSEC Proof Validation

NSEC (Next Secure) records provide authenticated denial of existence for DNS names and record types. When a query returns NXDOMAIN or NODATA, NSEC records prove that no data exists at the queried name.

**Source**: `src/dnssec.c`, `prove_non_existence()` orchestrator and NSEC-specific handlers

### NSEC Record Structure

NSEC records have two key components:
1. **Next Domain Name**: The next existing domain name in canonical order
2. **Type Bitmap**: A bit array indicating which record types exist at this name

**Example NSEC Record**:
```
example.com. 3600 IN NSEC f.example.com. A MX RRSIG NSEC DNSKEY
```

This NSEC proves:
- No domain names exist between `example.com` and `f.example.com`
- `example.com` has A, MX, RRSIG, NSEC, and DNSKEY records
- `example.com` does NOT have AAAA, TXT, or other types

### NSEC Proof Types

**1. Name Non-Existence Proof (NXDOMAIN)**

Proves that a queried name does not exist:

```
Query: nonexistent.example.com

NSEC records in response:
example.com.           NSEC f.example.com. A MX RRSIG NSEC
f.example.com.         NSEC z.example.com. A AAAA RRSIG NSEC
```

**Validation Logic**:
- `nonexistent.example.com` falls alphabetically between `f.example.com` and `z.example.com`
- The NSEC for `f.example.com` proves no names exist between `f` and `z`
- Therefore, `nonexistent.example.com` does not exist → NXDOMAIN validated

**2. Type Non-Existence Proof (NODATA)**

Proves that a name exists but does not have the requested record type:

```
Query: www.example.com AAAA

NSEC record in response:
www.example.com.       NSEC z.example.com. A MX RRSIG NSEC
```

**Validation Logic**:
- The NSEC type bitmap for `www.example.com` includes A, MX, RRSIG, NSEC
- The type bitmap does NOT include AAAA
- Therefore, `www.example.com` has no AAAA record → NODATA validated

**3. Wildcard Non-Existence Proof**

Proves that a wildcard match did not occur:

```
Query: foo.example.com

NSEC records:
*.example.com.         NSEC a.example.com. A AAAA RRSIG NSEC
foo.example.com.       NSEC z.example.com. A AAAA RRSIG NSEC
```

**Validation Logic**:
- The NSEC proves that `foo.example.com` explicitly exists (not a wildcard match)
- Or, if no exact match NSEC, proves that wildcard does not cover this name

### NSEC Validation Implementation

**Function**: `prove_non_existence()` orchestrator in `src/dnssec.c`

**Purpose**: Determine if NSEC records in a response properly authenticate denial of existence.

**Validation Steps**:

```c
// Simplified NSEC validation logic
// Source: src/dnssec.c, prove_non_existence()

int prove_non_existence(struct dns_header *header, size_t plen, 
                        char *name, int type, ...)
{
  // 1. Extract all NSEC records from response
  nsec_records = extract_nsec_records(header, plen);
  
  // 2. Verify NSEC RRSIGs (signatures over NSEC records)
  for (each nsec in nsec_records)
    {
      if (!validate_rrset(nsec, nsec_rrsig, DNSKEY))
        return STAT_BOGUS;  // NSEC signature invalid
    }
  
  // 3. Check NSEC coverage for queried name
  if (type == NXDOMAIN)
    {
      // Find NSEC that spans queried name
      // Verify: nsec_owner < queried_name < nsec_next
      if (found_spanning_nsec)
        return STAT_SECURE;  // NXDOMAIN authenticated
      else
        return STAT_BOGUS;   // No NSEC covers name
    }
  else if (type == NODATA)
    {
      // Find NSEC for exact name match
      nsec = find_nsec_for_name(name);
      
      // Check type bitmap
      if (nsec && !type_in_bitmap(nsec, requested_type))
        return STAT_SECURE;  // Type absence authenticated
      else
        return STAT_BOGUS;   // NSEC doesn't prove absence
    }
  
  // 4. Handle wildcard cases (additional logic)
  // ...
  
  return STAT_BOGUS;  // Could not prove non-existence
}
```

### NSEC Chain Walking

NSEC records form a circular linked list covering the entire zone namespace:

```
example.com → a.example.com → f.example.com → z.example.com → example.com
```

**Validation Requirement**: To prove name non-existence, must find NSEC where:
```
canonical_sort(nsec_owner) < canonical_sort(query_name) < canonical_sort(nsec_next)
```

**Implementation Detail**: Canonical name sorting follows DNS wire-format byte-by-byte comparison with labels sorted right-to-left.

## NSEC3 Proof Validation

NSEC3 (Next Secure version 3) provides authenticated denial of existence while preventing zone enumeration by using cryptographic hashes of domain names instead of plaintext names.

**Source**: `src/dnssec.c`, NSEC3-specific validation logic integrated into `prove_non_existence()`

### NSEC3 vs. NSEC Comparison

| Feature | NSEC | NSEC3 |
|---------|------|-------|
| **Name Representation** | Plaintext domain names | Hashed domain names (Base32-encoded SHA-1) |
| **Zone Enumeration** | Possible (reveals all names) | Prevented (hashes hide names) |
| **Opt-Out Support** | No | Yes (for unsigned delegations) |
| **Complexity** | Simple | More complex (hashing, salt, iterations) |
| **Performance** | Fast | Slower (hash computation) |

### NSEC3 Record Structure

NSEC3 records contain:
1. **Hash Algorithm**: Algorithm used to hash names (currently only SHA-1, algorithm 1)
2. **Flags**: Opt-out flag for unsigned delegations
3. **Iterations**: Number of additional hash iterations (DoS protection limit)
4. **Salt**: Random value mixed into hash computation (prevents pre-computation attacks)
5. **Next Hashed Owner Name**: Hash of the next existing name in canonical order
6. **Type Bitmap**: Record types present at the hashed name

**Example NSEC3 Record**:
```
15BG9L6359F5CH23E34DDUA6N1RIHL9H.example.com. 3600 IN NSEC3 1 0 10 AABBCCDD 15BG9L6359F5CH23E34DDUA6N1RIHL9I A RRSIG
```

**Fields**:
- **15BG9L6359F5CH23E34DDUA6N1RIHL9H**: Base32-encoded hash of owner name
- **1**: Hash algorithm (SHA-1)
- **0**: Flags (0 = no opt-out)
- **10**: Iterations (10 additional hash rounds)
- **AABBCCDD**: Salt (hexadecimal)
- **15BG9L6359F5CH23E34DDUA6N1RIHL9I**: Next hashed owner name
- **A RRSIG**: Type bitmap

### NSEC3 Hash Computation

The NSEC3 hash is computed as follows:

```
Hash(owner_name, salt, iterations) {
    hash = SHA-1(owner_name || salt)
    
    for (i = 0; i < iterations; i++) {
        hash = SHA-1(hash || salt)
    }
    
    return Base32-Hex-Encode(hash)
}
```

**Example**:
```
Owner Name: www.example.com.
Salt: AABBCCDD
Iterations: 10

Step 1: hash = SHA-1("www.example.com.\x00" || AABBCCDD)
Step 2-11: hash = SHA-1(hash || AABBCCDD)  [repeat 10 times]
Step 12: result = Base32-Hex-Encode(hash)
        = "15BG9L6359F5CH23E34DDUA6N1RIHL9H"
```

### NSEC3 Iteration Limit

To prevent denial-of-service attacks through computationally expensive hash iterations, dnsmasq enforces a strict iteration limit:

**Limit**: `DNSSEC_LIMIT_NSEC3_ITERS = 150`
**Source**: `src/config.h`, line 29

**Validation Behavior**:
- If NSEC3 record specifies iterations > 150: Validation FAILS (BOGUS)
- Rationale: Excessive iterations can cause CPU exhaustion during validation
- Current recommendations (RFC 9276): Maximum 100 iterations for 1024-bit keys, 150 for 2048-bit keys

```c
// Source: src/dnssec.c, NSEC3 iteration check
#define NSEC3_MAX_ITERATIONS 150

if (nsec3_iterations > NSEC3_MAX_ITERATIONS)
  {
    // Iteration count exceeds limit
    return STAT_BOGUS;  // Reject validation
  }
```

### NSEC3 Proof Validation

**NSEC3 Name Non-Existence Proof (NXDOMAIN)**:

```
Query: nonexistent.example.com

Step 1: Compute hash of queried name
    query_hash = Hash("nonexistent.example.com.", salt, iterations)
               = "1AVVXTR5LT74BHFPH0Q055TRM8K7NSEC"

Step 2: Find NSEC3 records spanning query_hash
    NSEC3: 15BG9L6359F5CH23E34DDUA6N1RIHL9H → 1BBBAAAA...
    NSEC3: 1BBBAAAA...                     → 2CCCCCCC...

Step 3: Check if query_hash falls within NSEC3 coverage
    15BG9... < 1AVVXTR5... < 1BBBAAAA...  ✓ (covered)

Step 4: Verify NSEC3 RRSIG
    Validate signature over NSEC3 record

Step 5: Conclusion
    Name "nonexistent.example.com" does not exist → NXDOMAIN authenticated
```

**NSEC3 Type Non-Existence Proof (NODATA)**:

```
Query: www.example.com AAAA

Step 1: Compute hash of queried name
    query_hash = Hash("www.example.com.", salt, iterations)
               = "15BG9L6359F5CH23E34DDUA6N1RIHL9H"

Step 2: Find NSEC3 record matching query_hash
    NSEC3: 15BG9L6359F5CH23E34DDUA6N1RIHL9H A RRSIG
           (type bitmap includes A and RRSIG, but NOT AAAA)

Step 3: Check type bitmap
    AAAA not in bitmap ✓

Step 4: Verify NSEC3 RRSIG

Step 5: Conclusion
    www.example.com exists but has no AAAA record → NODATA authenticated
```

### NSEC3 Opt-Out

NSEC3 supports "opt-out" for unsigned delegations (child zones that don't use DNSSEC):

**Opt-Out Flag**: Bit in NSEC3 flags field
**Purpose**: Allow insecure delegations without providing denial-of-existence proofs
**Security Tradeoff**: Enables zone signing without signing all delegations, but weakens security for opted-out names

**Validation Behavior**:
- If NSEC3 has opt-out flag set: Insecure delegations are allowed
- If queried name falls in opt-out range: Return INSECURE (not BOGUS)
- If query is for DS record in opt-out range: Must have explicit proof (no opt-out for DS)

### NSEC3 Validation Implementation

```c
// Simplified NSEC3 validation logic
// Source: src/dnssec.c, prove_non_existence() with NSEC3 handling

int validate_nsec3_proof(char *query_name, int query_type,
                         struct nsec3_record *nsec3_records)
{
  // 1. Extract NSEC3 parameters (salt, iterations, algorithm)
  salt = nsec3_records[0].salt;
  iterations = nsec3_records[0].iterations;
  
  // 2. Enforce iteration limit
  if (iterations > DNSSEC_LIMIT_NSEC3_ITERS)
    return STAT_BOGUS;  // Too many iterations
  
  // 3. Compute hash of queried name
  query_hash = nsec3_hash(query_name, salt, iterations);
  
  // 4. Find NSEC3 record covering query_hash
  covering_nsec3 = find_covering_nsec3(query_hash, nsec3_records);
  
  if (!covering_nsec3)
    return STAT_BOGUS;  // No NSEC3 covers query
  
  // 5. Verify NSEC3 RRSIG
  if (!validate_rrset(covering_nsec3, nsec3_rrsig, DNSKEY))
    return STAT_BOGUS;  // NSEC3 signature invalid
  
  // 6. Check proof type
  if (query_type == NXDOMAIN)
    {
      // Verify query_hash falls between nsec3_owner and nsec3_next
      if (nsec3_covers_name(covering_nsec3, query_hash))
        return STAT_SECURE;  // NXDOMAIN authenticated
    }
  else if (query_type == NODATA)
    {
      // Find exact match NSEC3
      exact_nsec3 = find_exact_nsec3(query_hash, nsec3_records);
      
      // Check type bitmap
      if (exact_nsec3 && !type_in_bitmap(exact_nsec3, query_type))
        return STAT_SECURE;  // Type absence authenticated
    }
  
  // 7. Handle opt-out cases
  if (covering_nsec3->flags & NSEC3_OPT_OUT)
    return STAT_INSECURE;  // Opt-out delegation
  
  return STAT_BOGUS;  // Could not prove non-existence
}
```

## Trust Anchor Management

Trust anchors are the foundation of DNSSEC validation, representing pre-configured public keys or DS records that are explicitly trusted without further validation.

**Source**: `trust-anchors.conf` (trust anchor storage), `src/dnssec.c` (trust anchor validation logic)

### Root Zone Trust Anchors

Dnsmasq uses DS records for the DNS root zone (`.`) as trust anchors. These are maintained by IANA and updated during Key Signing Key (KSK) rollovers.

**Current Root Trust Anchor** (as of July 2024):

**File**: `trust-anchors.conf`
```
. DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
```

**DS Record Fields**:
- **. (root zone)**: Zone name
- **DS**: Record type (Delegation Signer)
- **20326**: Key tag (identifier for the corresponding DNSKEY)
- **8**: Algorithm (8 = RSA/SHA-256)
- **2**: Digest type (2 = SHA-256)
- **E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D**: SHA-256 digest of the root zone KSK

### Trust Anchor Validation

When validating a DNSKEY for the root zone, dnsmasq performs the following:

```c
// Simplified trust anchor validation
// Source: src/dnssec.c, validate_rrset() for root zone

// 1. Retrieve root zone DNSKEY from DNS response
root_dnskey = extract_dnskey(response, ".");

// 2. Compute digest of DNSKEY
computed_digest = compute_ds_digest(root_dnskey, SHA256);

// 3. Compare with trust anchor DS digest
trust_anchor_digest = lookup_trust_anchor(".");

if (computed_digest == trust_anchor_digest)
  {
    // Trust anchor matches
    cache_dnskey(root_dnskey, STAT_SECURE);
    return STAT_SECURE;
  }
else
  {
    // Trust anchor mismatch
    return STAT_BOGUS;
  }
```

### Trust Anchor Updates

**KSK Rollover Process**:

When IANA performs a root zone KSK rollover (Key Signing Key replacement), the trust anchor must be updated:

1. **Pre-Rollover**: Old KSK active, new KSK published but not used
2. **Rollover**: New KSK becomes active, old KSK still published
3. **Post-Rollover**: Old KSK removed, only new KSK remains

**Manual Update Process**:
1. Obtain new root zone trust anchor from IANA (https://www.iana.org/dnssec/)
2. Update `trust-anchors.conf` with new DS record
3. Restart dnsmasq or send SIGHUP signal to reload configuration
4. Verify DNSSEC validation continues to work with test queries

**Historical Trust Anchors**:
- **2010-2017**: Key tag 19036 (RSA/SHA-256, first root KSK)
- **2017-present**: Key tag 20326 (RSA/SHA-256, current KSK after 2017 rollover)

**Automatic Trust Anchor Update** (RFC 5011):
- Dnsmasq does NOT currently implement RFC 5011 automatic trust anchor updates
- Trust anchor updates require manual configuration file changes
- Future enhancement: Implement RFC 5011 for automated KSK rollover tracking

### Trust Anchor Security

**Protection Against Trust Anchor Attacks**:

1. **Secure Distribution**: Trust anchors distributed via OS packages and verified against IANA authoritative sources
2. **Integrity Verification**: Package managers verify cryptographic signatures on dnsmasq packages
3. **File Permissions**: `trust-anchors.conf` should be owned by root with restrictive permissions (644 or 600)
4. **Configuration Validation**: Dnsmasq validates trust anchor format at startup

**Trust Anchor Verification**:
```bash
# Verify current root zone KSK matches trust anchor
dig . DNSKEY +dnssec @a.root-servers.net | grep "257 3 8"

# Compare key tag and algorithm with trust-anchors.conf
# Key tag should be 20326, algorithm should be 8 (RSA/SHA-256)
```

### Additional Trust Anchors

While the root zone trust anchor is sufficient for validating the entire DNS namespace, administrators can configure additional trust anchors for specific zones:

**Use Cases**:
- **Internal TLDs**: Private top-level domains not delegated from root (e.g., `.internal`)
- **Testing Zones**: DNSSEC test zones with known keys
- **Split-Horizon DNS**: Different trust anchors for internal vs. external views

**Configuration**:
```
# trust-anchors.conf example with additional zone
. DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
internal. DS 12345 8 2 ABCD1234...
```

## Validation Limits and DoS Protection

DNSSEC validation can be computationally expensive, creating opportunities for denial-of-service attacks. Dnsmasq implements strict resource limits to prevent validation-based DoS.

**Source**: `src/config.h` (limit definitions), `src/dnssec.c` (limit enforcement)

### Configured Limits

| Limit Name | Value | Config Constant | Purpose |
|-----------|-------|----------------|---------|
| **Maximum Queries per Validation** | 40 | `DNSSEC_LIMIT_WORK` | Limits upstream queries during trust chain traversal |
| **Maximum Signature Failures** | 20 | `DNSSEC_LIMIT_SIG_FAIL` | Limits failed signature verification attempts |
| **Maximum Crypto Operations** | 200 | `DNSSEC_LIMIT_CRYPTO` | Limits total cryptographic operations per validation |
| **Maximum NSEC3 Iterations** | 150 | `DNSSEC_LIMIT_NSEC3_ITERS` | Limits NSEC3 hash iteration count |

**Definition Location**: `src/config.h`, lines 25-29

```c
// Source: src/config.h, lines 25-29
#define DNSSEC_LIMIT_WORK 40          /* Maximum queries during validation */
#define DNSSEC_LIMIT_SIG_FAIL 20      /* Maximum signature failures */
#define DNSSEC_LIMIT_CRYPTO 200       /* Maximum crypto operations */
#define DNSSEC_LIMIT_NSEC3_ITERS 150  /* Maximum NSEC3 iterations */
```

### Limit Enforcement

**1. Query Limit (DNSSEC_LIMIT_WORK)**

**Purpose**: Prevent infinite loops or excessively deep trust chains requiring many upstream queries.

**Attack Scenario**: Malicious zone creates circular DNSKEY dependencies forcing validator to make hundreds of queries.

**Enforcement**:
```c
// Source: src/dnssec.c, dnssec_validate_reply()
static unsigned int queries_outstanding = 0;

int dnssec_validate_reply(...)
{
  queries_outstanding++;
  
  if (queries_outstanding > DNSSEC_LIMIT_WORK)
    {
      // Too many queries during validation
      return STAT_BOGUS;
    }
  
  // Perform validation...
  
  queries_outstanding--;
  return validation_status;
}
```

**Impact**: If trust chain validation requires more than 40 upstream queries, validation aborts with BOGUS status.

**2. Signature Failure Limit (DNSSEC_LIMIT_SIG_FAIL)**

**Purpose**: Prevent attackers from exhausting CPU with repeated signature verification failures.

**Attack Scenario**: Response contains hundreds of invalid RRSIGs forcing validator to attempt verification for each.

**Enforcement**:
```c
// Source: src/dnssec.c, validate_rrset()
static unsigned int sig_fail_count = 0;

int validate_rrset(...)
{
  for (each RRSIG in response)
    {
      if (!verify_signature(rrsig, dnskey, rrset))
        {
          sig_fail_count++;
          
          if (sig_fail_count > DNSSEC_LIMIT_SIG_FAIL)
            {
              // Too many signature failures
              return STAT_BOGUS;
            }
          
          continue;  // Try next RRSIG
        }
      
      // Signature valid
      sig_fail_count = 0;  // Reset on success
      return STAT_SECURE;
    }
  
  return STAT_BOGUS;  // All signatures failed
}
```

**Impact**: If more than 20 signature verifications fail during validation, abort with BOGUS status.

**3. Cryptographic Operation Limit (DNSSEC_LIMIT_CRYPTO)**

**Purpose**: Limit total number of expensive cryptographic operations (signature verifications, digest computations).

**Attack Scenario**: Response designed to trigger maximum crypto work (large RRsets, many RRSIGs, complex algorithms).

**Enforcement**:
```c
// Source: src/crypto.c, verify()
static unsigned int crypto_ops = 0;

int verify(int algo, char *key, ...)
{
  crypto_ops++;
  
  if (crypto_ops > DNSSEC_LIMIT_CRYPTO)
    {
      // Too many cryptographic operations
      return 0;  // Verification failed
    }
  
  // Perform signature verification
  result = algorithm_specific_verify(...);
  
  return result;
}
```

**Impact**: If more than 200 cryptographic operations are performed during validation, additional operations fail.

**4. NSEC3 Iteration Limit (DNSSEC_LIMIT_NSEC3_ITERS)**

**Purpose**: Prevent CPU exhaustion through excessive NSEC3 hash iterations.

**Attack Scenario**: Zone configures NSEC3 with thousands of iterations forcing validator to perform expensive repeated hashing.

**Enforcement**:
```c
// Source: src/dnssec.c, NSEC3 validation
int validate_nsec3(struct nsec3_record *nsec3)
{
  if (nsec3->iterations > DNSSEC_LIMIT_NSEC3_ITERS)
    {
      // Iteration count exceeds limit
      return STAT_BOGUS;
    }
  
  // Compute NSEC3 hash with allowed iterations
  hash = nsec3_hash(name, salt, nsec3->iterations);
  
  // Validate proof...
}
```

**Impact**: NSEC3 records with iteration counts > 150 are rejected, validation returns BOGUS.

### Rationale for Limit Values

**DNSSEC_LIMIT_WORK (40 queries)**:
- Typical trust chain depth: 3-4 levels (root → TLD → SLD → target)
- Each level requires ~2-5 queries (DS, DNSKEY, RRSIG)
- Total: 8-20 queries for normal validation
- Limit of 40 provides comfortable margin while preventing abuse

**DNSSEC_LIMIT_SIG_FAIL (20 failures)**:
- Normal validation: 0-2 signature failures (wrong key, expired signature)
- Limit of 20 allows multiple failure attempts while preventing exhaustive search

**DNSSEC_LIMIT_CRYPTO (200 operations)**:
- Each RRset validation: 1-5 crypto operations (canonicalization, digest, verify)
- Typical validation: 20-50 operations
- Limit of 200 accommodates complex responses with multiple RRsets

**DNSSEC_LIMIT_NSEC3_ITERS (150 iterations)**:
- RFC 9276 recommendation: 100 iterations for 2048-bit RSA keys
- Limit of 150 provides security margin while remaining performant
- Higher iteration counts (500+) used by some zones are intentionally rejected

### Performance Impact

**Resource Consumption Under Limits**:

| Scenario | Queries | Crypto Ops | CPU Time | Result |
|----------|---------|------------|----------|--------|
| Simple validation (cached keys) | 1-2 | 5-10 | <10ms | SECURE |
| Full trust chain (root to target) | 10-15 | 30-50 | 50-100ms | SECURE |
| Limit exceeded (attack) | 40+ | 200+ | Aborted | BOGUS |
| NSEC3 excessive iterations | 1 | N/A | Rejected | BOGUS |

**Tuning Considerations**:

The limits are compile-time constants defined in `src/config.h`. To adjust for specific deployment requirements:

1. **Edit** `src/config.h`:
   ```c
   #define DNSSEC_LIMIT_WORK 80  // Double query limit
   ```

2. **Recompile** dnsmasq:
   ```bash
   make COPTS="-DHAVE_DNSSEC"
   ```

3. **Test** with DNSSEC validation:
   ```bash
   dig @localhost example.com +dnssec
   ```

**Warning**: Increasing limits may expose validator to DoS attacks. Only adjust if experiencing legitimate validation failures due to complex trust chains.

## Validation States

DNSSEC validation results in one of three security states for each DNS response:

**Source**: `src/dnssec.c` (validation state determination), `src/dnsmasq.h` (state constants)

### State Definitions

| State | Meaning | Client Response | Caching Behavior |
|-------|---------|----------------|------------------|
| **SECURE** | Cryptographically validated | Return data with AD bit set | Cache validated data |
| **INSECURE** | Unsigned zone or delegation | Return data without AD bit | Cache unsigned data |
| **BOGUS** | Validation failed | SERVFAIL error | Do not cache |

### SECURE State

**Condition**: All DNSSEC validation checks passed successfully.

**Requirements**:
1. Valid RRSIG present and covers queried RRset
2. RRSIG signature verifies correctly with trusted DNSKEY
3. DNSKEY validates against DS in parent zone
4. Trust chain complete to root zone trust anchor
5. RRSIG within validity period (inception ≤ now < expiration)
6. All resource limits respected (queries, crypto ops, etc.)

**Implementation**:
```c
// Source: src/dnssec.c, validation success path
#define STAT_SECURE 1

int dnssec_validate_reply(...)
{
  // Perform all validation checks
  
  if (all_checks_passed)
    {
      // Mark response as validated
      header->ad = 1;  // Set Authenticated Data bit
      
      // Cache validated data
      cache_insert(name, rrset, ttl, STAT_SECURE);
      
      return STAT_SECURE;
    }
}
```

**Client Behavior**:
- Receive DNS response with AD (Authenticated Data) bit set in header
- Trust that data has not been tampered with
- Example: `dig example.com +dnssec` shows `;; flags: qr rd ra ad;` (ad flag present)

### INSECURE State

**Condition**: Zone is intentionally unsigned or uses opt-out delegation.

**Scenarios**:
1. **Unsigned Zone**: Zone does not have DNSSEC records (no DS in parent, no DNSKEY/RRSIG in zone)
2. **Insecure Delegation**: Parent zone has no DS record for child zone
3. **NSEC3 Opt-Out**: NSEC3 record with opt-out flag covers unsigned delegation

**Implementation**:
```c
// Source: src/dnssec.c, insecure zone detection
#define STAT_INSECURE 2

int validate_rrset(...)
{
  // Check for DS record in parent zone
  ds_record = find_ds(parent_zone, child_zone);
  
  if (!ds_record)
    {
      // No DS record → zone is insecure
      return STAT_INSECURE;
    }
  
  // Check for NSEC3 opt-out
  if (nsec3_opt_out_covers(query_name))
    {
      return STAT_INSECURE;
    }
  
  // Continue validation...
}
```

**Client Behavior**:
- Receive DNS response without AD bit set
- Data not validated, but not flagged as bogus
- Accept data but without cryptographic guarantees
- Example: `dig unsigned-example.com +dnssec` shows `;; flags: qr rd ra;` (no ad flag)

**Rationale**: Many zones remain unsigned. Returning INSECURE allows these zones to work normally while still providing validation for DNSSEC-enabled zones.

### BOGUS State

**Condition**: DNSSEC validation failed, indicating potential tampering or misconfiguration.

**Failure Scenarios**:
1. **Signature Verification Failed**: RRSIG does not verify with DNSKEY
2. **DNSKEY Validation Failed**: DNSKEY does not match DS in parent zone
3. **Trust Chain Broken**: Cannot validate DNSKEY chain to root trust anchor
4. **Expired Signature**: Current time outside RRSIG validity period
5. **Missing RRSIG**: DNSSEC expected but no signature present
6. **NSEC/NSEC3 Proof Invalid**: Denial-of-existence proof does not cover queried name
7. **Resource Limits Exceeded**: Validation hit query, crypto, or iteration limits
8. **Algorithm Unsupported**: RRSIG uses unsupported algorithm

**Implementation**:
```c
// Source: src/dnssec.c, validation failure path
#define STAT_BOGUS 0

int dnssec_validate_reply(...)
{
  // Attempt validation
  
  if (signature_invalid || chain_broken || expired || ...)
    {
      // Validation failed
      
      // Log failure reason
      my_syslog(LOG_WARNING, "DNSSEC validation failed: %s", reason);
      
      // Do NOT cache bogus data
      
      // Return SERVFAIL to client
      header->rcode = SERVFAIL;
      
      return STAT_BOGUS;
    }
}
```

**Client Behavior**:
- Receive SERVFAIL response (RCODE 2)
- Application fails to resolve name
- Example: `dig bogus-example.com +dnssec` returns SERVFAIL

**Rationale**: BOGUS status indicates potential security issue (tampering, misconfiguration, or attack). Returning SERVFAIL forces application to fail safely rather than accepting potentially malicious data.

### Validation State Transitions

```mermaid
stateDiagram-v2
    [*] --> Start: DNS Query<br/>with DO bit
    
    Start --> CheckDNSSEC: Extract RRsets
    
    CheckDNSSEC --> CheckSignature: DNSSEC<br/>expected?
    
    CheckSignature --> ValidateChain: RRSIG<br/>present?
    CheckSignature --> CheckDS: No RRSIG
    
    CheckDS --> INSECURE: No DS<br/>in parent
    CheckDS --> BOGUS: DS present<br/>but no RRSIG
    
    ValidateChain --> VerifySignature: Retrieve<br/>DNSKEY
    
    VerifySignature --> CheckTime: Signature<br/>valid?
    VerifySignature --> BOGUS: Signature<br/>invalid
    
    CheckTime --> CheckLimits: Within<br/>validity?
    CheckTime --> BOGUS: Expired or<br/>not yet valid
    
    CheckLimits --> SECURE: All limits<br/>OK
    CheckLimits --> BOGUS: Limit<br/>exceeded
    
    SECURE --> [*]: Return data<br/>with AD bit
    INSECURE --> [*]: Return data<br/>without AD bit
    BOGUS --> [*]: Return<br/>SERVFAIL
    
    style SECURE fill:#90EE90
    style INSECURE fill:#FFD700
    style BOGUS fill:#FF6B6B
```

### Configuration Options Affecting Validation States

**Enable DNSSEC Validation**:
```bash
# dnsmasq.conf or command-line
dnssec
# or
--dnssec
```

**Check Unsigned Zones**:
```bash
# Treat unsigned zones as BOGUS (strict mode)
dnssec-check-unsigned
# or
--dnssec-check-unsigned
```

**Impact of dnssec-check-unsigned**:
- **Disabled** (default): Unsigned zones return INSECURE
- **Enabled**: Unsigned zones return BOGUS (SERVFAIL to client)
- **Use Case**: Enforce DNSSEC for all queries in high-security environments

**Query Logging**:
```bash
# Log DNSSEC validation results
log-queries
```

**Example Log Output**:
```
dnssec-query[A] example.com from 192.168.1.10
validation result: SECURE
validation result: INSECURE (unsigned zone)
validation result: BOGUS (signature verification failed)
```

## Cryptographic Library Integration

Dnsmasq relies on the Nettle cryptography library for all DNSSEC cryptographic operations. Nettle provides low-level cryptographic primitives optimized for performance and security.

**Source**: `src/crypto.c` (Nettle integration layer)

### Nettle Library Overview

**Nettle** is a low-level cryptographic library providing:
- Cryptographic hash functions (SHA-1, SHA-256, SHA-384, SHA-512, SHAKE)
- Public-key cryptography (RSA, ECDSA, EdDSA, GOST)
- Big integer arithmetic (via GMP - GNU Multiple Precision Arithmetic Library)

**Why Nettle**:
- **Lightweight**: Minimal dependencies, suitable for embedded systems
- **Portable**: Runs on all dnsmasq target platforms
- **Well-Maintained**: Actively developed and security-audited
- **DNSSEC-Focused**: Comprehensive support for all DNSSEC algorithms

**Library Dependencies**:
- **libnettle**: Core cryptographic algorithms
- **libhogweed**: Public-key cryptography (RSA, DSA, ECDSA, EdDSA)
- **libgmp**: Multi-precision arithmetic (optional, improves RSA performance)

**Compile-Time Detection**:
```makefile
# Makefile, lines 58-71
LIBS = $(shell pkg-config --libs nettle)
CFLAGS += $(shell pkg-config --cflags nettle)
```

**Build Requirement**:
```bash
# Install Nettle development libraries (Debian/Ubuntu)
sudo apt-get install libnettle-dev

# Compile dnsmasq with DNSSEC support
make COPTS="-DHAVE_DNSSEC"
```

### Cryptographic Primitive Mapping

| DNSSEC Algorithm | Nettle Function | Hash Function | Key Size |
|-----------------|----------------|---------------|----------|
| RSA/SHA-1 (5) | `rsa_sha1_verify_digest` | SHA-1 | 512-4096 bits |
| RSA/SHA-256 (8) | `rsa_sha256_verify_digest` | SHA-256 | 1024-4096 bits |
| RSA/SHA-512 (10) | `rsa_sha512_verify_digest` | SHA-512 | 1024-4096 bits |
| ECDSA P-256 (13) | `ecdsa_verify` | SHA-256 | 256 bits |
| ECDSA P-384 (14) | `ecdsa_verify` | SHA-384 | 384 bits |
| Ed25519 (15) | `ed25519_sha512_verify` | SHA-512 | 256 bits |
| Ed448 (16) | `ed448_shake256_verify` | SHAKE256 | 456 bits |
| GOST (12) | `gost_dsa_verify` | GOST R 34.11-2012 | 512 bits |

### Nettle API Usage Examples

**RSA Signature Verification**:
```c
// Source: src/crypto.c, dnsmasq_rsa_verify()
#include <nettle/rsa.h>
#include <nettle/bignum.h>

int dnsmasq_rsa_verify(unsigned char *key, size_t key_len,
                       unsigned char *sig, size_t sig_len,
                       unsigned char *digest, size_t digest_len)
{
  struct rsa_public_key rsa_key;
  mpz_t signature;
  
  // Initialize RSA public key structure
  rsa_public_key_init(&rsa_key);
  mpz_init(signature);
  
  // Parse public key from DNSKEY RDATA
  // DNSKEY format: exponent_length || exponent || modulus
  mpz_import(rsa_key.e, exponent_len, 1, 1, 0, 0, exponent);
  mpz_import(rsa_key.n, modulus_len, 1, 1, 0, 0, modulus);
  
  // Import signature
  mpz_import(signature, sig_len, 1, 1, 0, 0, sig);
  
  // Verify signature based on algorithm
  int result;
  if (algorithm == 5 || algorithm == 7)  // RSA/SHA-1
    result = rsa_sha1_verify_digest(&rsa_key, digest, signature);
  else if (algorithm == 8)  // RSA/SHA-256
    result = rsa_sha256_verify_digest(&rsa_key, digest, signature);
  else if (algorithm == 10)  // RSA/SHA-512
    result = rsa_sha512_verify_digest(&rsa_key, digest, signature);
  
  // Cleanup
  mpz_clear(signature);
  rsa_public_key_clear(&rsa_key);
  
  return result;  // 1 = valid, 0 = invalid
}
```

**ECDSA Signature Verification**:
```c
// Source: src/crypto.c, dnsmasq_ecdsa_verify()
#include <nettle/ecdsa.h>
#include <nettle/ecc-curve.h>

int dnsmasq_ecdsa_verify(unsigned char *key, size_t key_len,
                         unsigned char *sig, size_t sig_len,
                         unsigned char *digest, size_t digest_len,
                         int algorithm)
{
  struct ecc_point public_key;
  struct dsa_signature signature;
  const struct ecc_curve *curve;
  
  // Select curve based on algorithm
  if (algorithm == 13)  // ECDSA P-256
    curve = nettle_get_secp_256r1();
  else if (algorithm == 14)  // ECDSA P-384
    curve = nettle_get_secp_384r1();
  
  // Initialize point and signature
  ecc_point_init(&public_key, curve);
  dsa_signature_init(&signature);
  
  // Parse public key (X and Y coordinates)
  // DNSKEY format: X || Y (raw bytes, big-endian)
  mpz_import(X, curve->p.size, 1, 1, 0, 0, key);
  mpz_import(Y, curve->p.size, 1, 1, 0, 0, key + curve->p.size);
  ecc_point_set(&public_key, X, Y);
  
  // Parse signature (R and S components)
  mpz_import(signature.r, sig_len / 2, 1, 1, 0, 0, sig);
  mpz_import(signature.s, sig_len / 2, 1, 1, 0, 0, sig + sig_len / 2);
  
  // Verify signature
  int result = ecdsa_verify(&public_key, digest_len, digest, &signature);
  
  // Cleanup
  ecc_point_clear(&public_key);
  dsa_signature_clear(&signature);
  
  return result;
}
```

**EdDSA Signature Verification**:
```c
// Source: src/crypto.c, dnsmasq_eddsa_verify()
#include <nettle/eddsa.h>

int dnsmasq_eddsa_verify(unsigned char *key, size_t key_len,
                         unsigned char *sig, size_t sig_len,
                         unsigned char *digest, size_t digest_len,
                         int algorithm)
{
  int result;
  
  if (algorithm == 15)  // Ed25519
    {
      // Ed25519: 32-byte key, 64-byte signature
      result = ed25519_sha512_verify(key,           // 32-byte public key
                                      digest_len,    // Message length
                                      digest,        // Message
                                      sig);          // 64-byte signature
    }
  else if (algorithm == 16)  // Ed448
    {
      // Ed448: 57-byte key, 114-byte signature
      result = ed448_shake256_verify(key,           // 57-byte public key
                                      digest_len,    // Message length
                                      digest,        // Message
                                      sig);          // 114-byte signature
    }
  
  return result;
}
```

### Performance Characteristics

| Algorithm | Key Size | Signature Size | Verification Time | Security Level |
|-----------|----------|----------------|-------------------|----------------|
| RSA/SHA-256 | 2048 bits | 256 bytes | ~1-2 ms | 112-bit |
| RSA/SHA-512 | 4096 bits | 512 bytes | ~5-10 ms | 128-bit |
| ECDSA P-256 | 256 bits | 64 bytes | ~0.5-1 ms | 128-bit |
| ECDSA P-384 | 384 bits | 96 bytes | ~1-2 ms | 192-bit |
| Ed25519 | 256 bits | 64 bytes | ~0.2-0.5 ms | 128-bit |
| Ed448 | 456 bits | 114 bytes | ~0.5-1 ms | 224-bit |

**Performance Observations**:
- **EdDSA** (Ed25519, Ed448): Fastest verification, smallest keys
- **ECDSA**: Fast verification, moderate key sizes
- **RSA**: Slowest verification, largest keys and signatures

**Recommendation**: Modern DNSSEC deployments prefer EdDSA (especially Ed25519) for optimal performance and security.

### Error Handling

**Nettle Function Return Values**:
- **1**: Signature verification successful
- **0**: Signature verification failed

**Dnsmasq Error Propagation**:
```c
// Source: src/crypto.c, verify()
int verify(int algo, char *key, int keylen, unsigned char *sig, ...)
{
  int (*verify_func_ptr)(struct blockdata *, ...) = verify_func(algo);
  
  if (!verify_func_ptr)
    {
      // Unsupported algorithm
      return 0;
    }
  
  int result = verify_func_ptr(key_data, ...);
  
  if (result == 0)
    {
      // Verification failed
      // Increment sig_fail_count in dnssec.c
      // Try next RRSIG or return BOGUS
    }
  
  return result;
}
```

**Common Failure Scenarios**:
1. **Invalid Key Format**: DNSKEY parsing fails (malformed key data)
2. **Signature Mismatch**: Cryptographic verification returns 0
3. **Algorithm Mismatch**: Signature algorithm doesn't match DNSKEY algorithm
4. **Unsupported Algorithm**: Algorithm number not implemented

## Configuration and Integration

### Runtime Configuration

**Enable DNSSEC Validation**:
```bash
# /etc/dnsmasq.conf
dnssec

# Trust anchor file location (default)
trust-anchor=/usr/share/dnsmasq/trust-anchors.conf
```

**Command-Line Options**:
```bash
dnsmasq --dnssec \
        --trust-anchor=/etc/dnsmasq/trust-anchors.conf \
        --dnssec-check-unsigned \
        --log-queries
```

**Configuration File Example**:
```
# Enable DNSSEC validation
dnssec

# Trust anchor file (optional, default location used if not specified)
trust-anchor=/usr/share/dnsmasq/trust-anchors.conf

# Treat unsigned zones as BOGUS (strict mode)
# dnssec-check-unsigned

# Log DNSSEC validation results
log-queries
```

**Source**: `dnsmasq.conf.example`, lines 1-150 (DNSSEC-related options documented)

### Compile-Time Configuration

**Build with DNSSEC Support**:
```bash
# Install Nettle library
sudo apt-get install libnettle-dev

# Compile with DNSSEC enabled
make COPTS="-DHAVE_DNSSEC"

# Install
sudo make install
```

**Verify DNSSEC Support**:
```bash
# Check if DNSSEC is compiled in
dnsmasq --version

# Output should include:
# Compile time options: DNSSEC ...
```

### Integration with Upstream DNS Servers

**Upstream Server Requirements**:
- **MUST support EDNS0**: Required for DO (DNSSEC OK) bit
- **MUST return DNSSEC records**: RRSIG, DNSKEY, DS, NSEC/NSEC3
- **SHOULD support large UDP responses**: Or fallback to TCP for large responses

**Configuration**:
```bash
# /etc/dnsmasq.conf

# Use upstream DNS servers that support DNSSEC
server=8.8.8.8        # Google Public DNS (supports DNSSEC)
server=1.1.1.1        # Cloudflare DNS (supports DNSSEC)
server=9.9.9.9        # Quad9 (supports DNSSEC)

# Or use resolv.conf
resolv-file=/etc/resolv.conf
```

**Upstream Query Behavior**:
- Dnsmasq sets DO (DNSSEC OK) bit in queries to upstream servers
- Upstream servers include DNSSEC records in responses
- Dnsmasq performs validation on received responses

### Testing DNSSEC Validation

**Test with Known Good Domain**:
```bash
# Query DNSSEC-signed domain
dig @localhost example.com A +dnssec

# Expected output:
# ;; flags: qr rd ra ad;  ← AD (Authenticated Data) bit set
# ;; ANSWER SECTION:
# example.com.  3600  IN  A  93.184.215.14
# example.com.  3600  IN  RRSIG  A 13 2 3600 ...
```

**Test with Known Bogus Domain**:
```bash
# Query dnssec-failed.org (intentionally broken DNSSEC)
dig @localhost dnssec-failed.org A +dnssec

# Expected output:
# ;; Got answer:
# ;; status: SERVFAIL  ← Validation failed
```

**Test with Unsigned Domain**:
```bash
# Query unsigned domain
dig @localhost unsigned-example.com A +dnssec

# Expected output:
# ;; flags: qr rd ra;  ← NO AD bit (INSECURE)
# ;; ANSWER SECTION:
# unsigned-example.com.  3600  IN  A  192.0.2.1
```

### Troubleshooting

**Enable Query Logging**:
```bash
# /etc/dnsmasq.conf
log-queries

# Restart dnsmasq
sudo systemctl restart dnsmasq

# View logs
sudo journalctl -u dnsmasq -f
```

**Common Issues**:

**1. SERVFAIL for All DNSSEC Queries**:
- **Cause**: Trust anchor mismatch or outdated `trust-anchors.conf`
- **Solution**: Update trust anchor file from IANA

**2. Validation Failures for Specific Domains**:
- **Cause**: Zone misconfiguration (expired RRSIG, incorrect DS)
- **Solution**: Contact zone operator

**3. Performance Degradation**:
- **Cause**: Hitting validation limits (too many queries/crypto ops)
- **Solution**: Investigate zone causing excessive work, adjust limits if legitimate

**4. Nettle Library Missing**:
- **Cause**: Nettle not installed or not detected at compile time
- **Solution**: Install libnettle-dev and recompile

### Security Considerations

**1. Trust Anchor Security**:
- Protect `trust-anchors.conf` with restrictive permissions (600 or 644)
- Verify trust anchor integrity after system updates
- Monitor IANA announcements for KSK rollovers

**2. Upstream Server Trust**:
- Use reputable upstream DNS servers that support DNSSEC
- Prefer encrypted transport (DNS-over-TLS/HTTPS) for upstream queries (requires external proxy)

**3. Cache Poisoning Protection**:
- DNSSEC validation prevents cache poisoning attacks
- BOGUS responses not cached, preventing contamination

**4. Resource Exhaustion**:
- Validation limits protect against DoS attacks
- Monitor logs for excessive BOGUS responses (potential attack indicator)

**5. Algorithm Deprecation**:
- RSA/SHA-1 (algorithm 5) is deprecated, avoid if possible
- Prefer modern algorithms: Ed25519 (15), ECDSA P-256 (13)

## See Also

- [DNS Forwarding and Caching](DNS_FORWARDING.md) - DNS query forwarding and cache integration
- [Architecture Overview](ARCHITECTURE.md) - System architecture and component relationships
- [Configuration Guide](CONFIGURATION.md) - Complete configuration options including DNSSEC settings
- [Building Guide](BUILDING.md) - Compilation instructions with Nettle library dependencies

**External Resources**:
- [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033.html) - DNSSEC Introduction and Requirements
- [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034.html) - DNSSEC Resource Records
- [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035.html) - DNSSEC Protocol Modifications
- [RFC 9276](https://www.rfc-editor.org/rfc/rfc9276.html) - NSEC3 Parameter Settings
- [IANA DNSSEC Resources](https://www.iana.org/dnssec/) - Root zone trust anchors and KSK information
- [Nettle Cryptography Library](https://www.lysator.liu.se/~nisse/nettle/) - Cryptographic library documentation

---

**Document Version**: 1.0  
**Last Updated**: Based on dnsmasq version 2.92  
**Trust Anchor Current As Of**: July 2024  
**Source Code References**: `src/dnssec.c`, `src/crypto.c`, `src/config.h`, `trust-anchors.conf`
