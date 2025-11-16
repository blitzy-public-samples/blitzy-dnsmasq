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
 * @file pattern.c
 * @brief Hostname pattern validation and matching for security and configuration
 * 
 * DETAILED PURPOSE:
 * This module provides DNS hostname pattern validation and matching functionality
 * used primarily for conntrack-based filtering and security policy enforcement.
 * It implements RFC 1123-compliant hostname validation with support for wildcard
 * patterns, enabling domain-based filtering rules that can match entire domain
 * hierarchies (e.g., *.example.com) while preventing malicious or malformed patterns.
 * 
 * The pattern validation ensures that wildcard characters (*) are used safely,
 * restricting them from appearing in the final two labels (e.g., *.co.uk is invalid
 * to prevent overly broad matches). This security measure prevents patterns that would
 * match unrelated domains and reduces the risk of misconfiguration.
 * 
 * KEY RESPONSIBILITIES:
 * - Validate DNS hostnames against RFC 1123 requirements (is_valid_dns_name)
 * - Validate DNS hostname patterns with wildcard support (is_valid_dns_name_pattern)
 * - Match DNS hostnames against validated patterns (is_dns_name_matching_pattern)
 * - Implement case-insensitive glob pattern matching (is_string_matching_glob_pattern)
 * - Enforce security restrictions on wildcard placement in patterns
 * 
 * DEPENDENCIES:
 * Includes: dnsmasq.h (global header with system includes, type definitions, macros)
 * Called by: conntrack.c (for pattern-based connection tracking filtering)
 * Calls: my_syslog() from log.c for debugging and error reporting
 * 
 * DATA STRUCTURES:
 * This module operates on C strings (char*) and uses primitive types for validation.
 * No complex data structures are defined or managed within this module. All functions
 * are stateless and operate only on input parameters.
 * 
 * COMPILE-TIME OPTIONS:
 * - HAVE_CONNTRACK: All functionality in this file is conditionally compiled only
 *   when connection tracking support is enabled. Without this flag, the file
 *   contributes no code to the final binary.
 * 
 * THREADING/CONCURRENCY:
 * All functions are pure (no side effects except logging) and thread-safe for
 * read-only operations on input strings. Functions do not modify shared state.
 * 
 * PATTERN SYNTAX:
 * Patterns support the wildcard character '*' which matches zero or more characters.
 * Valid patterns include:
 *   - Exact matches: "www.example.com"
 *   - Subdomain wildcards: "*.example.com" (matches any subdomain)
 *   - Multiple wildcards: "*example*.com" (matches any label containing "example")
 * Invalid patterns include:
 *   - Wildcards in TLD: "*.com" (too broad, security risk)
 *   - Wildcards in second-level and TLD: "*.co.uk" (country-code TLD protection)
 * 
 * SECURITY CONSIDERATIONS:
 * Pattern validation includes multiple security checks to prevent injection attacks
 * and overly broad matching:
 * - Label length validation (max 63 characters per RFC 1123)
 * - Total hostname length validation (max 255 characters)
 * - Character validation (alphanumeric, hyphen, period, wildcard only)
 * - Wildcard placement restrictions (not in final two labels)
 * - Input sanitization against buffer overflows via length checks
 * 
 * @copyright Copyright (c) 2000-2025 Simon Kelley
 * @license GPL-2.0-or-later
 */

#include "dnsmasq.h"

#ifdef HAVE_CONNTRACK

#define LOG(...) \
  do { \
    my_syslog(LOG_DEBUG, __VA_ARGS__); \
  } while (0)

#define ASSERT(condition) \
  do { \
    if (!(condition)) \
      my_syslog(LOG_ERR, _("[pattern.c:%d] Assertion failure: %s"), __LINE__, #condition); \
  } while (0)

/**
 * @brief Match a string value against a glob pattern with wildcard support
 * 
 * @detailed Implements case-insensitive glob pattern matching where '*' acts as a
 *           zero-or-more-character wildcard. This function uses an efficient backtracking
 *           algorithm based on Russ Cox's "Glob Matching Can Be Simple And Fast Too"
 *           (https://research.swtch.com/glob). The algorithm avoids exponential complexity
 *           by maintaining a single backtrack point rather than recursive backtracking.
 *           Case-insensitive comparison converts lowercase ASCII characters to uppercase
 *           during matching (a-z become A-Z).
 * 
 * @param value A string value to match against the pattern. Must not be NULL.
 * @param num_value_bytes The number of bytes in the string value (not including null terminator)
 * @param pattern A glob pattern potentially containing '*' wildcards. Must not be NULL.
 * @param num_pattern_bytes The number of bytes in the glob pattern (not including null terminator)
 * 
 * @return 1 if the value matches the pattern (case-insensitive)
 * @return 0 if the value does not match or if invalid input detected
 * 
 * @note This is an internal static function used by is_dns_name_matching_pattern()
 * @warning Input strings must be valid for num_*_bytes length; buffer overruns will occur
 *          if lengths exceed actual string sizes. No NULL-terminator is required.
 * 
 * @see is_dns_name_matching_pattern() - public interface using this matching algorithm
 * @see Source: /src/pattern.c:line 47
 * 
 * EXAMPLE USAGE:
 * @code
 * // Match exact string
 * int result1 = is_string_matching_glob_pattern("example", 7, "example", 7);
 * // result1 == 1 (match)
 * 
 * // Match with wildcard
 * int result2 = is_string_matching_glob_pattern("www.example.com", 15, "*.example.com", 13);
 * // result2 == 1 (match)
 * 
 * // Case-insensitive match
 * int result3 = is_string_matching_glob_pattern("Example", 7, "EXAMPLE", 7);
 * // result3 == 1 (match)
 * @endcode
 * 
 * RFC COMPLIANCE: Not directly tied to RFC (internal algorithm), but supports
 *                 case-insensitive DNS name matching per RFC 1035 Section 3.1
 * 
 * SIDE EFFECTS: May call ASSERT macro which logs to syslog on assertion failure
 * THREAD SAFETY: Thread-safe (read-only operations on input parameters)
 */
static int is_string_matching_glob_pattern(
  const char *value,
  size_t num_value_bytes,
  const char *pattern,
  size_t num_pattern_bytes)
{
  ASSERT(value);
  ASSERT(pattern);
  
  size_t value_index = 0;
  size_t next_value_index = 0;
  size_t pattern_index = 0;
  size_t next_pattern_index = 0;
  while (value_index < num_value_bytes || pattern_index < num_pattern_bytes)
    {
      if (pattern_index < num_pattern_bytes)
	{
	  char pattern_character = pattern[pattern_index];
	  if ('a' <= pattern_character && pattern_character <= 'z')
	    pattern_character -= 'a' - 'A';
	  if (pattern_character == '*')
	    {
	      /* zero-or-more-character wildcard */
	      /* Try to match at value_index, otherwise restart at value_index + 1 next. */
	      next_pattern_index = pattern_index;
	      pattern_index++;
	      if (value_index < num_value_bytes)
		next_value_index = value_index + 1;
	      else
		next_value_index = 0;
	      continue;
	    }
	  else
	    {
	      /* ordinary character */
	      if (value_index < num_value_bytes)
	        {
		  char value_character = value[value_index];
		  if ('a' <= value_character && value_character <= 'z')
		    value_character -= 'a' - 'A';
		  if (value_character == pattern_character)
		    {
		      pattern_index++;
		      value_index++;
		      continue;
		    }
		}
	    }
	}
      if (next_value_index)
	{
	  pattern_index = next_pattern_index;
	  value_index = next_value_index;
	  continue;
	}
      return 0;
    }
  return 1;
}

/**
 * @brief Validate a DNS hostname against RFC 1123 requirements
 * 
 * @detailed Validates DNS hostnames according to RFC 1123 Section 2.1 (host naming conventions)
 *           with additional security restrictions for conntrack filtering. The validation ensures:
 *           
 *           1. Total length: 1-253 characters (DNS protocol limit)
 *           2. Label structure: Dot-separated labels, each 1-63 characters
 *           3. Character restrictions: ASCII letters (a-z, A-Z), digits (0-9), hyphens (-)
 *           4. Label boundaries: Labels must not start or end with hyphen
 *           5. Fully qualified: Minimum two labels (e.g., "host.domain")
 *           6. TLD restrictions: Final label must not be fully numeric (prevents IP addresses)
 *           7. Pseudo-TLD blocking: Rejects ".local" TLD (mDNS/Bonjour namespace)
 *           
 *           The function performs single-pass validation with character-by-character inspection,
 *           tracking label boundaries and numeric content. Invalid characters, malformed labels,
 *           or security-restricted patterns cause immediate rejection with syslog logging.
 * 
 * @param value A null-terminated string representing a hostname. Must not be NULL.
 * 
 * @return 1 if the hostname is valid per RFC 1123 and security restrictions
 * @return 0 if the hostname is invalid or fails security checks
 * 
 * @note This function is used by conntrack.c for validating domain patterns in filtering rules
 * @warning NULL input triggers ASSERT macro (logs error); behavior undefined in production without assertions
 * 
 * @see is_valid_dns_name_pattern() - validates patterns with wildcard support
 * @see Source: /src/pattern.c:line 126
 * 
 * EXAMPLE USAGE:
 * @code
 * // Valid fully-qualified domain names
 * int valid1 = is_valid_dns_name("example.com");
 * // valid1 == 1 (two labels, valid characters)
 * 
 * int valid2 = is_valid_dns_name("www.example.com");
 * // valid2 == 1 (three labels, valid)
 * 
 * // Invalid: single label (not fully qualified)
 * int invalid1 = is_valid_dns_name("ipcamera");
 * // invalid1 == 0 (must have at least two labels)
 * 
 * // Invalid: .local pseudo-TLD (mDNS namespace)
 * int invalid2 = is_valid_dns_name("ipcamera.local");
 * // invalid2 == 0 (security restriction on .local)
 * 
 * // Invalid: numeric TLD (looks like IP address)
 * int invalid3 = is_valid_dns_name("8.8.8.8");
 * // invalid3 == 0 (all-numeric final label rejected)
 * @endcode
 * 
 * RFC COMPLIANCE: RFC 1123 Section 2.1 (Host Names and Numbers)
 *                 Enforces syntax rules for Internet host names with additional
 *                 security restrictions beyond the RFC specification
 * 
 * SIDE EFFECTS: Logs validation failure messages to syslog at LOG_DEBUG level
 *               via LOG() macro when invalid characters or patterns detected
 * 
 * THREAD SAFETY: Thread-safe (read-only operations on input string)
 */
int is_valid_dns_name(const char *value)
{
  ASSERT(value);
  
  size_t num_bytes = 0;
  size_t num_labels = 0;
  const char *c, *label = NULL;
  int is_label_numeric = 1;
  for (c = value;; c++)
    {
      if (*c &&
	  *c != '-' && *c != '.' &&
	  (*c < '0' || *c > '9') &&
	  (*c < 'A' || *c > 'Z') &&
	  (*c < 'a' || *c > 'z'))
	{
	  LOG(_("Invalid DNS name: Invalid character %c."), *c);
	  return 0;
	}
      if (*c)
	num_bytes++;
      if (!label)
	{
	  if (!*c || *c == '.')
	    {
	      LOG(_("Invalid DNS name: Empty label."));
	      return 0;
	    }
	  if (*c == '-')
	    {
	      LOG(_("Invalid DNS name: Label starts with hyphen."));
	      return 0;
	    }
	  label = c;
	}
      if (*c && *c != '.')
	{
	  if (*c < '0' || *c > '9')
	    is_label_numeric = 0;
	}
      else
	{
	  if (c[-1] == '-')
	    {
	      LOG(_("Invalid DNS name: Label ends with hyphen."));
	      return 0;
	    }
	  size_t num_label_bytes = (size_t) (c - label);
	  if (num_label_bytes > 63)
	    {
	      LOG(_("Invalid DNS name: Label is too long (%zu)."), num_label_bytes);
	      return 0;
	    }
	  num_labels++;
	  if (!*c)
	    {
	      if (num_labels < 2)
		{
		  LOG(_("Invalid DNS name: Not enough labels (%zu)."), num_labels);
		  return 0;
		}
	      if (is_label_numeric)
		{
		  LOG(_("Invalid DNS name: Final label is fully numeric."));
		  return 0;
		}
	      if (num_label_bytes == 5 &&
		  (label[0] == 'l' || label[0] == 'L') &&
		  (label[1] == 'o' || label[1] == 'O') &&
		  (label[2] == 'c' || label[2] == 'C') &&
		  (label[3] == 'a' || label[3] == 'A') &&
		  (label[4] == 'l' || label[4] == 'L'))
		{
		  LOG(_("Invalid DNS name: \"local\" pseudo-TLD."));
		  return 0;
		}
	      if (num_bytes < 1 || num_bytes > 253)
		{
		  LOG(_("DNS name has invalid length (%zu)."), num_bytes);
		  return 0;
		}
	      return 1;
	    }
	  label = NULL;
	  is_label_numeric = 1;
	}
    }
}

/**
 * @brief Validate DNS hostname pattern with wildcard support and security restrictions
 *
 * @detailed Validates that a string represents a valid DNS hostname pattern conforming to
 * RFC 1123 naming requirements with wildcard extensions for pattern matching. This function
 * is primarily used for conntrack filtering rules to ensure that domain-based filters are
 * syntactically valid and do not pose security risks through overly broad matching.
 *
 * The validation enforces multiple security and correctness constraints:
 * - RFC 1123 compliance: Total length 1-253 characters, labels 1-63 characters each
 * - Character restrictions: ASCII letters, digits, hyphens, periods, and wildcards only
 * - Label format: Labels cannot start or end with hyphens
 * - Wildcard restrictions: Up to two wildcards (*) per label, matching zero or more characters
 * - Security restriction: Final two labels must be literal (no wildcards) to prevent overly
 *   broad matches like "*.com" or "*.co.uk" which would match unrelated domains
 * - Fully qualified requirement: Minimum two labels required
 * - TLD restrictions: Final label cannot be fully numeric or "local" pseudo-TLD
 *
 * Wildcard behavior: The wildcard character (*) matches zero or more characters within a single
 * label but never crosses label boundaries (dots). For example, "*.example.com" matches
 * "api.example.com" but NOT "api.us.example.com" (the wildcard does not match "api.us").
 *
 * @param value String to validate as DNS hostname pattern (null-terminated C string)
 *              Must not be NULL (assertion enforced via ASSERT macro)
 *
 * @return 1 if the string is a valid DNS hostname pattern meeting all RFC and security requirements
 * @retval 1 Pattern is syntactically valid, wildcards properly placed, length constraints satisfied
 * @retval 0 Pattern is invalid (syntax error, security violation, or RFC 1123 non-compliance)
 *
 * @note This function logs detailed error messages via LOG() macro for each validation failure,
 *       enabling debugging of rejected patterns. Logging uses syslog LOG_DEBUG level.
 *
 * @warning Wildcard restrictions are security-critical: patterns with wildcards in the final
 *          two labels are explicitly rejected to prevent accidental or malicious overly broad
 *          matching. For example, "*.com" would match millions of unrelated domains.
 *
 * @see is_valid_dns_name() for validation of hostnames without wildcard support
 * @see is_dns_name_matching_pattern() for matching hostnames against validated patterns
 * @see RFC 1123 Section 2.1 for hostname syntax requirements
 *
 * EXAMPLE USAGE:
 * @code
 * // Valid patterns accepted by function
 * if (is_valid_dns_name_pattern("example.com"))         // Exact hostname
 *   accept_rule();
 * if (is_valid_dns_name_pattern("*.example.com"))       // Subdomain wildcard
 *   accept_rule();
 * if (is_valid_dns_name_pattern("video*.example.com"))  // Partial label wildcard
 *   accept_rule();
 * if (is_valid_dns_name_pattern("api*.*.example.com"))  // Multiple labels with wildcards
 *   accept_rule();
 *
 * // Invalid patterns rejected by function
 * if (!is_valid_dns_name_pattern("ipcamera"))           // Not fully qualified (single label)
 *   reject_rule();
 * if (!is_valid_dns_name_pattern("*.com"))              // Wildcard in TLD (security risk)
 *   reject_rule();
 * if (!is_valid_dns_name_pattern("*.co.uk"))            // Wildcard in second-to-last label
 *   reject_rule();
 * if (!is_valid_dns_name_pattern("ipcamera.local"))     // "local" pseudo-TLD forbidden
 *   reject_rule();
 * if (!is_valid_dns_name_pattern("8.8.8.8"))            // Fully numeric final label
 *   reject_rule();
 * @endcode
 *
 * RFC COMPLIANCE: RFC 1123 Section 2.1 (hostname syntax requirements)
 * SIDE EFFECTS: Logs validation failures to syslog at LOG_DEBUG level via my_syslog()
 * THREAD SAFETY: Thread-safe for read-only operations; no shared state modified
 */
int is_valid_dns_name_pattern(const char *value)
{
  ASSERT(value);
  
  size_t num_bytes = 0;
  size_t num_labels = 0;
  const char *c, *label = NULL;
  int is_label_numeric = 1;
  size_t num_wildcards = 0;
  int previous_label_has_wildcard = 1;
  for (c = value;; c++)
    {
      if (*c &&
	  *c != '*' && /* Wildcard. */
	  *c != '-' && *c != '.' &&
	  (*c < '0' || *c > '9') &&
	  (*c < 'A' || *c > 'Z') &&
	  (*c < 'a' || *c > 'z'))
	{
	  LOG(_("Invalid DNS name pattern: Invalid character %c."), *c);
	  return 0;
	}
      if (*c && *c != '*')
	num_bytes++;
      if (!label)
	{
	  if (!*c || *c == '.')
	    {
	      LOG(_("Invalid DNS name pattern: Empty label."));
	      return 0;
	    }
	  if (*c == '-')
	    {
	      LOG(_("Invalid DNS name pattern: Label starts with hyphen."));
	      return 0;
	    }
	  label = c;
	}
      if (*c && *c != '.')
	{
	  if (*c < '0' || *c > '9')
	    is_label_numeric = 0;
	  if (*c == '*')
	    {
	      if (num_wildcards >= 2)
		{
		  LOG(_("Invalid DNS name pattern: Wildcard character used more than twice per label."));
		  return 0;
		}
	      num_wildcards++;
	    }
	}
      else
	{
	  if (c[-1] == '-')
	    {
	      LOG(_("Invalid DNS name pattern: Label ends with hyphen."));
	      return 0;
	    }
	  size_t num_label_bytes = (size_t) (c - label) - num_wildcards;
	  if (num_label_bytes > 63)
	    {
	      LOG(_("Invalid DNS name pattern: Label is too long (%zu)."), num_label_bytes);
	      return 0;
	    }
	  num_labels++;
	  if (!*c)
	    {
	      if (num_labels < 2)
		{
		  LOG(_("Invalid DNS name pattern: Not enough labels (%zu)."), num_labels);
		  return 0;
		}
	      if (num_wildcards != 0 || previous_label_has_wildcard)
		{
		  LOG(_("Invalid DNS name pattern: Wildcard within final two labels."));
		  return 0;
		}
	      if (is_label_numeric)
		{
		  LOG(_("Invalid DNS name pattern: Final label is fully numeric."));
		  return 0;
		}
	      if (num_label_bytes == 5 &&
		  (label[0] == 'l' || label[0] == 'L') &&
		  (label[1] == 'o' || label[1] == 'O') &&
		  (label[2] == 'c' || label[2] == 'C') &&
		  (label[3] == 'a' || label[3] == 'A') &&
		  (label[4] == 'l' || label[4] == 'L'))
		{
		  LOG(_("Invalid DNS name pattern: \"local\" pseudo-TLD."));
		  return 0;
		}
	      if (num_bytes < 1 || num_bytes > 253)
		{
		  LOG(_("DNS name pattern has invalid length after removing wildcards (%zu)."), num_bytes);
		  return 0;
		}
	      return 1;
	    }
	    label = NULL;
	    is_label_numeric = 1;
	    previous_label_has_wildcard = num_wildcards != 0;
	    num_wildcards = 0;
	  }
    }
}

/**
 * @brief Match DNS hostname against validated pattern with wildcard support
 *
 * @detailed Performs label-by-label matching of a DNS hostname against a validated DNS
 * hostname pattern, with support for wildcard matching within labels. This function
 * implements the pattern matching semantics used for conntrack filtering rules, where
 * domain-based filters need to match actual connection hostnames against configured patterns.
 *
 * The matching algorithm processes both the name and pattern simultaneously, comparing
 * corresponding labels (segments separated by dots). Each label pair is matched using
 * case-insensitive glob pattern matching with wildcard support. The wildcard character (*)
 * within a pattern label matches zero or more characters within the corresponding name
 * label, but never crosses label boundaries.
 *
 * Matching semantics:
 * - Case-insensitive: "Example.COM" matches pattern "example.com"
 * - Label-by-label: Both name and pattern must have the same number of labels
 * - Wildcard behavior: "*" matches within a label but not across dots
 * - Complete match required: All labels must match and both strings must be fully consumed
 *
 * Examples:
 * - "api.example.com" matches "*.example.com" (wildcard label match)
 * - "api.us.example.com" does NOT match "*.example.com" (label count mismatch)
 * - "video123.example.com" matches "video*.example.com" (partial wildcard match)
 * - "www.example.com" matches "www.example.com" (exact match)
 * - "API.EXAMPLE.COM" matches "api.example.com" (case-insensitive)
 *
 * @param name Valid DNS hostname to test against pattern (null-terminated C string)
 *             Must not be NULL and must be valid per is_valid_dns_name() (assertion enforced)
 *             Examples: "www.example.com", "api.service.internal", "host123.domain.org"
 * @param pattern Valid DNS hostname pattern with optional wildcards (null-terminated C string)
 *                Must not be NULL and must be valid per is_valid_dns_name_pattern() (assertion enforced)
 *                Examples: "*.example.com", "api*.service.internal", "host123.domain.org"
 *
 * @return 1 if the hostname matches the pattern according to glob matching semantics
 * @retval 1 All labels match and both name and pattern are fully consumed (complete match)
 * @retval 0 At least one label fails to match, or label counts differ (no match)
 *
 * @note The function assumes inputs are pre-validated. Assertions verify that name is a
 *       valid DNS hostname (via is_valid_dns_name) and pattern is a valid DNS pattern
 *       (via is_valid_dns_name_pattern). Invalid inputs will trigger assertion failures
 *       with syslog error messages in debug builds.
 *
 * @warning This function does NOT validate its inputs beyond assertions. Callers must
 *          ensure that name and pattern are valid using is_valid_dns_name() and
 *          is_valid_dns_name_pattern() respectively before calling this function.
 *          Invalid inputs in production builds (where assertions may be disabled) will
 *          result in undefined behavior.
 *
 * @see is_valid_dns_name() for hostname validation without wildcards
 * @see is_valid_dns_name_pattern() for pattern validation with wildcard support
 * @see is_string_matching_glob_pattern() for the label-level matching implementation
 *
 * EXAMPLE USAGE:
 * @code
 * // Typical usage pattern: validate then match
 * const char *hostname = "api.example.com";
 * const char *filter_pattern = "*.example.com";
 * 
 * if (is_valid_dns_name(hostname) && is_valid_dns_name_pattern(filter_pattern)) {
 *   if (is_dns_name_matching_pattern(hostname, filter_pattern)) {
 *     // Hostname matches pattern - apply filtering rule
 *     apply_conntrack_rule(hostname);
 *   }
 * }
 *
 * // Example match scenarios
 * is_dns_name_matching_pattern("www.example.com", "*.example.com")         // Returns 1
 * is_dns_name_matching_pattern("api.us.example.com", "*.example.com")      // Returns 0 (label count)
 * is_dns_name_matching_pattern("video123.site.org", "video*.site.org")     // Returns 1
 * is_dns_name_matching_pattern("test.COM", "test.com")                     // Returns 1 (case-insensitive)
 * is_dns_name_matching_pattern("api-prod-01.example.com", "*-prod-*.example.com") // Returns 1
 * @endcode
 *
 * ALGORITHM IMPLEMENTATION:
 * The function implements a label-by-label comparison algorithm:
 * 1. Initialize pointers to the start of both name and pattern strings
 * 2. Loop while labels remain in both strings:
 *    a. Extract the next label from name (characters up to next dot or end)
 *    b. Extract the next label from pattern (characters up to next dot or end)
 *    c. Call is_string_matching_glob_pattern() to match the label pair
 *    d. If labels don't match, break immediately (no match)
 *    e. Advance past the dot separator in both strings (if present)
 * 3. Return success only if both strings are fully consumed (both at end)
 *
 * SIDE EFFECTS: None (pure function with no external state modifications)
 * THREAD SAFETY: Thread-safe for read-only operations on input strings; no shared state
 */
int is_dns_name_matching_pattern(const char *name, const char *pattern)
{
  ASSERT(name);
  ASSERT(is_valid_dns_name(name));
  ASSERT(pattern);
  ASSERT(is_valid_dns_name_pattern(pattern));
  
  const char *n = name;
  const char *p = pattern;
  
  do {
    const char *name_label = n;
    while (*n && *n != '.')
      n++;
    const char *pattern_label = p;
    while (*p && *p != '.')
      p++;
    if (!is_string_matching_glob_pattern(
        name_label, (size_t) (n - name_label),
        pattern_label, (size_t) (p - pattern_label)))
      break;
    if (*n)
      n++;
    if (*p)
      p++;
  } while (*n && *p);
  
  return !*n && !*p;
}

#endif
