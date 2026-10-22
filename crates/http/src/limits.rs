//! Size bounds on messages read from a peer.

/// Bounds on one message read from an untrusted peer.
///
/// Each bound caps the memory one message can claim.
/// Time is bounded separately, by the client's and server's timeouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes in the start line and header fields, terminator included.
    pub max_head_bytes: usize,

    /// Most header fields.
    pub max_headers: usize,

    /// Most bytes in the decoded body.
    pub max_body_bytes: usize,
}

impl Limits {
    /// Bounds that suit API traffic.
    ///
    /// - 16 KiB of head is twice what common servers accept by default.
    /// - 64 fields is far beyond what an RPC peer sends.
    /// - 32 MiB of body holds a hex-encoded block with a full set of blobs.
    pub const DEFAULT: Self = Self {
        max_head_bytes: 16 << 10,
        max_headers: 64,
        max_body_bytes: 32 << 20,
    };
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
