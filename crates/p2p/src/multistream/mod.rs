//! multistream-select 1.0: agreeing on the protocol a fresh byte stream speaks.
//!
//! # Overview
//!
//! Each message is a varint length, then UTF-8 text ending in a newline.
//! Both sides open with the protocol header, then the dialer proposes and the listener answers.
//!
//! 1. The dialer sends "/multistream/1.0.0\n".
//! 2. The listener answers "/multistream/1.0.0\n".
//! 3. The dialer proposes "/mplex/6.7.0\n", which the listener does not support.
//! 4. The listener answers "na\n".
//! 5. The dialer proposes "/yamux/1.0.0\n", which the listener supports.
//! 6. The listener echoes "/yamux/1.0.0\n", and both sides agree.
//!
//! ```text
//! wire form of "na\n":  [0x03, b'n', b'a', b'\n']
//! ```
//!
//! The dialer may also send `ls`, and the listener answers with every protocol it supports.
//! Bytes that arrive after agreement belong to the negotiated protocol and are handed back.
//!
//! See `multiformats/multistream-select` and `libp2p/specs/connections`.

mod dialer;
mod listener;
mod message;

pub use dialer::{Dialer, Lister};
pub use listener::Listener;
use thiserror::Error;

use crate::protobuf::ProtobufError;

/// The header both sides send first.
pub const PROTOCOL_HEADER: &str = "/multistream/1.0.0";

/// The listener's refusal of a proposal.
const NOT_AVAILABLE: &str = "na";

/// The dialer's request for the listener's protocol list.
const LIST: &str = "ls";

/// Longest message accepted.
///
/// Protocol names are short; only an `ls` answer needs room for many of them.
const MAX_MESSAGE_LEN: usize = 64 * 1024;

/// Most proposals a listener answers before giving up on a dialer.
const MAX_PROPOSALS: usize = 32;

/// The outcome of a successful negotiation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The agreed protocol name.
    pub protocol: String,
    /// Bytes received after agreement, which belong to that protocol.
    pub remainder: Vec<u8>,
}

/// A stream that broke the negotiation rules.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NegotiationError {
    /// A length prefix is malformed or above the message bound.
    #[error("malformed message frame: {0}")]
    Framing(#[from] ProtobufError),

    /// A message does not end with a newline.
    #[error("message of {len} bytes lacks its trailing newline")]
    MissingNewline {
        /// Length of the message, in bytes.
        len: usize,
    },

    /// A message is not UTF-8.
    #[error("message is not UTF-8 after byte {valid_up_to}")]
    InvalidUtf8 {
        /// Length of the longest valid UTF-8 prefix.
        valid_up_to: usize,
    },

    /// The peer opened with something other than the protocol header.
    #[error("unexpected header {0:?}")]
    InvalidHeader(String),

    /// The listener refused every proposal.
    #[error("listener refused all {refused} proposals, the last {last:?}")]
    NoCommonProtocol {
        /// Number of proposals refused.
        refused: usize,
        /// The last protocol proposed.
        last: String,
    },

    /// The listener answered a proposal with neither an echo nor a refusal.
    #[error("unexpected response {response:?} to proposal {proposed:?}")]
    UnexpectedResponse {
        /// The protocol proposed.
        proposed: String,
        /// The answer received.
        response: String,
    },

    /// The dialer kept proposing past the listener's patience.
    #[error("dialer sent more than {max} unsupported proposals, the last {last:?}")]
    TooManyProposals {
        /// Most unsupported proposals the listener answers.
        max: usize,
        /// The proposal that crossed the bound.
        last: String,
    },

    /// The dialer was given no protocol to propose.
    #[error("no protocol to propose")]
    NothingToPropose,
}
