//! DNS forwarding engine: query lifecycle state machine.
//!
//! Stub — will be replaced by the code generation agent with the complete
//! implementation derived from `src/forward.c`.

use std::collections::HashMap;

/// DNS forwarding engine managing the query lifecycle from client receipt
/// through upstream dispatch to response delivery.
///
/// Replaces the C `struct frec` singly-linked list with a `HashMap<u16, ()>`
/// keyed by randomized transaction ID for O(1) lookup.
pub struct ForwardingEngine {
    /// Outstanding forward records keyed by new_id.
    forward_table: HashMap<u16, ()>,
    /// Maximum forward table size (FTABSIZ = 150 default).
    max_forwards: usize,
}

impl ForwardingEngine {
    /// Create a new forwarding engine with the specified forward table capacity.
    pub fn new(max_forwards: usize) -> Self {
        Self {
            forward_table: HashMap::with_capacity(max_forwards),
            max_forwards,
        }
    }
}
