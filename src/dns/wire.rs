//! DNS wire-format codec derived from `src/rfc1035.c`.
//!
//! Stub — will be replaced by the code generation agent with the complete
//! implementation including name compression, packet construction, and
//! answer_request().

/// DNS wire-format errors encountered during packet parsing or construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Packet is shorter than expected at the given offset.
    TruncatedPacket,
    /// DNS name contains invalid label encoding.
    InvalidName,
    /// Compression pointer creates an infinite loop.
    CompressionLoop,
    /// Compression pointer references an offset beyond packet bounds.
    InvalidOffset,
    /// DNS name exceeds the maximum length (MAXDNAME = 1025).
    NameTooLong,
    /// Single label exceeds the maximum length of 63 bytes.
    LabelTooLong,
    /// Writing would exceed the available buffer space.
    BufferOverflow,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedPacket => write!(f, "packet truncated"),
            Self::InvalidName => write!(f, "invalid DNS name"),
            Self::CompressionLoop => write!(f, "compression pointer loop detected"),
            Self::InvalidOffset => write!(f, "invalid compression pointer offset"),
            Self::NameTooLong => write!(f, "DNS name too long"),
            Self::LabelTooLong => write!(f, "DNS label too long"),
            Self::BufferOverflow => write!(f, "buffer overflow"),
        }
    }
}

impl std::error::Error for WireError {}
