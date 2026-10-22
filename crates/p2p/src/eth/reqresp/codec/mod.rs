//! The ssz_snappy wire format of requests and response chunks.
//!
//! # Overview
//!
//! ```text
//! request         = [ varint ssz_len ][ snappy frames ]
//! response chunk  = [ result: 1 byte ][ context: 4 bytes, success only ][ varint ssz_len ][ snappy frames ]
//!
//! snappy frames   = [ ff 06 00 00 "sNaPpY" ][ chunk ][ chunk ] ...   at most 64 KiB per chunk
//! ```
//!
//! The varint is the uncompressed SSZ length, checked against the type's bounds before any read.
//! A reader takes at most max_compressed_len(n) framed bytes for n SSZ bytes.
//! Requests and responses share one incremental payload decoder.
//! See `specs/phase0/p2p-interface.md`, SSZ-snappy encoding strategy.

mod payload;
mod request;
mod response;

use axiom_types::ForkDigest;
pub(super) use payload::Payload;
pub use request::RequestDecoder;
pub use response::ResponseDecoder;

/// Longest error message, the ErrorMessage list bound.
pub const MAX_ERROR_MESSAGE_LEN: usize = 256;

/// The result byte opening every response chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResponseCode {
    /// A payload of the expected type follows.
    Success,
    /// The request was malformed or semantically invalid.
    InvalidRequest,
    /// The responder failed while processing.
    ServerError,
    /// The responder does not have the requested resource.
    ResourceUnavailable,
    /// A code in 4..=127, reserved and to be treated as an error.
    Reserved(u8),
    /// A code in 128..=255, a client-specific error.
    ClientSpecific(u8),
}

impl ResponseCode {
    /// The wire byte.
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::InvalidRequest => 1,
            Self::ServerError => 2,
            Self::ResourceUnavailable => 3,
            Self::Reserved(code) | Self::ClientSpecific(code) => code,
        }
    }

    /// The code a wire byte names.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::Success,
            1 => Self::InvalidRequest,
            2 => Self::ServerError,
            3 => Self::ResourceUnavailable,
            4..=127 => Self::Reserved(byte),
            _ => Self::ClientSpecific(byte),
        }
    }
}

/// One decoded or to-be-encoded response chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseChunk {
    /// The result code.
    pub code: ResponseCode,
    /// The fork digest of the payload, for methods with ForkDigest-context.
    pub context: Option<ForkDigest>,
    /// The SSZ payload, or the error message bytes for an error code.
    pub payload: Vec<u8>,
}

impl ResponseChunk {
    /// Appends the wire form of this chunk.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(self.code.to_byte());
        // Context bytes accompany success chunks only; error chunks never carry them.
        if self.code == ResponseCode::Success
            && let Some(digest) = self.context
        {
            out.extend_from_slice(digest.as_bytes());
        }
        Payload(&self.payload).encode_to(out);
    }

    /// A success chunk.
    #[must_use]
    pub const fn success(context: Option<ForkDigest>, payload: Vec<u8>) -> Self {
        Self {
            code: ResponseCode::Success,
            context,
            payload,
        }
    }

    /// An error chunk with a message, truncated to 256 bytes.
    #[must_use]
    pub fn error(code: ResponseCode, message: &str) -> Self {
        let mut payload = message.as_bytes().to_vec();
        payload.truncate(MAX_ERROR_MESSAGE_LEN);
        Self {
            code,
            context: None,
            payload,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_codes() {
        for byte in 0..=255u8 {
            assert_eq!(ResponseCode::from_byte(byte).to_byte(), byte);
        }
        assert_eq!(ResponseCode::from_byte(4), ResponseCode::Reserved(4));
        assert_eq!(
            ResponseCode::from_byte(128),
            ResponseCode::ClientSpecific(128)
        );
    }

    #[test]
    fn error_messages_are_truncated() {
        // A 300-byte message keeps its first 256 bytes, and no context.
        let chunk = ResponseChunk::error(ResponseCode::ServerError, &"x".repeat(300));
        assert_eq!(chunk.payload, vec![b'x'; 256]);
        assert_eq!(chunk.context, None);
    }
}
