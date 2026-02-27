//! Domain pattern matching and server selection with O(log n) binary search.
//!
//! Stub — will be replaced by the code generation agent with the complete
//! implementation derived from `src/domain-match.c`.

/// Sorted server array supporting O(log n) domain-to-server lookup with
/// longest-suffix-wins matching semantics.
///
/// Replaces the C sorted pointer array + qsort approach with a Rust `Vec<usize>`
/// of indices into the daemon's server list.
pub struct ServerArray {
    /// Sorted indices into the server list, ordered by domain length (longest first).
    indices: Vec<usize>,
    /// Whether any server has the SERV_WILDCARD flag set.
    has_wildcard: bool,
}

impl ServerArray {
    /// Create a new empty server array.
    pub fn new() -> Self {
        Self {
            indices: Vec::new(),
            has_wildcard: false,
        }
    }
}

impl Default for ServerArray {
    fn default() -> Self {
        Self::new()
    }
}
