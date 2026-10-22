//! multistream-select 1.0: agreeing on the protocol a fresh byte stream speaks.
//!
//! # Overview
//!
//! Each message is a varint length, then UTF-8 text ending in a newline.
//! Both sides open with the protocol header, then the dialer proposes and the listener answers.
//!
//! ```text
//! dialer                                        listener
//!   ── "/multistream/1.0.0\n" ──────────────────▶
//!   ◀───────────────────── "/multistream/1.0.0\n" ──
//!   ── "/mplex/6.7.0\n" ────────────────────────▶   unsupported
//!   ◀───────────────────────────────────── "na\n" ──
//!   ── "/yamux/1.0.0\n" ────────────────────────▶   supported
//!   ◀─────────────────────────── "/yamux/1.0.0\n" ──  echo: agreed
//!
//! wire form of "na\n":  [0x03, b'n', b'a', b'\n']
//! ```
//!
//! The dialer may also send `ls`, and the listener answers with every protocol it supports.
//! Bytes that arrive after agreement belong to the negotiated protocol and are handed back.
//!
//! See `multiformats/multistream-select` and `libp2p/specs/connections`.

mod dialer;
mod listener;

use std::{error::Error, fmt, str};

pub use dialer::{Dialer, Lister};
pub use listener::Listener;

use crate::{
    protobuf::{ProtobufError, split_length_prefixed},
    varint,
};

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

/// Appends one message: a varint length, the text, and a newline.
fn encode_message(text: &str, out: &mut Vec<u8>) {
    encode_raw_message(text.as_bytes(), out);
}

/// Appends one message whose body may be arbitrary bytes.
fn encode_raw_message(body: &[u8], out: &mut Vec<u8>) {
    // The length counts the trailing newline.
    varint::encode(body.len() as u64 + 1, out);
    out.extend_from_slice(body);
    out.push(b'\n');
}

/// Splits one message off the front of a buffer.
///
/// # Returns
///
/// - The text without its newline, and the bytes the message took.
/// - Nothing while the message is incomplete.
fn decode_message(buffer: &[u8]) -> Result<Option<(&str, usize)>, NegotiationError> {
    let Some((body, consumed)) = decode_raw_message(buffer)? else {
        return Ok(None);
    };
    let text = str::from_utf8(body).map_err(|_| NegotiationError::InvalidUtf8)?;
    Ok(Some((text, consumed)))
}

/// Splits one message off the front of a buffer, keeping its body as bytes.
fn decode_raw_message(buffer: &[u8]) -> Result<Option<(&[u8], usize)>, NegotiationError> {
    let Some((body, consumed)) = split_length_prefixed(buffer, MAX_MESSAGE_LEN)? else {
        return Ok(None);
    };
    // Every message ends with a newline, which is not part of the body.
    let body = body
        .strip_suffix(b"\n")
        .ok_or(NegotiationError::MissingNewline)?;
    Ok(Some((body, consumed)))
}

/// Encodes the body of an `ls` answer: one nested message per protocol.
///
/// ```text
/// outer body = [ len "/a\n" ][ len "/b\n" ] ...
/// ```
fn encode_list<'a>(protocols: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
    let mut body = Vec::new();
    for protocol in protocols {
        encode_message(protocol, &mut body);
    }
    body
}

/// Decodes the body of an `ls` answer back into protocol names.
fn decode_list(mut body: &[u8]) -> Result<Vec<String>, NegotiationError> {
    let mut protocols = Vec::new();
    // Peel nested messages until the body is used up.
    while !body.is_empty() {
        let (name, consumed) =
            decode_message(body)?.ok_or(NegotiationError::Framing(ProtobufError::Truncated))?;
        protocols.push(name.to_owned());
        body = &body[consumed..];
    }
    Ok(protocols)
}

/// A stream that broke the negotiation rules.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NegotiationError {
    /// A length prefix is malformed or above the message bound.
    Framing(ProtobufError),

    /// A message does not end with a newline.
    MissingNewline,

    /// A message is not UTF-8.
    InvalidUtf8,

    /// The peer opened with something other than the protocol header.
    InvalidHeader(String),

    /// The listener refused every proposal.
    NoCommonProtocol,

    /// The listener answered a proposal with neither an echo nor a refusal.
    UnexpectedResponse(String),

    /// The dialer kept proposing past the listener's patience.
    TooManyProposals,

    /// The dialer was given no protocol to propose.
    NothingToPropose,
}

impl From<ProtobufError> for NegotiationError {
    fn from(error: ProtobufError) -> Self {
        Self::Framing(error)
    }
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Framing(error) => write!(f, "malformed message frame: {error}"),
            Self::MissingNewline => f.write_str("message lacks its trailing newline"),
            Self::InvalidUtf8 => f.write_str("message is not UTF-8"),
            Self::InvalidHeader(header) => write!(f, "unexpected header {header:?}"),
            Self::NoCommonProtocol => f.write_str("no protocol in common"),
            Self::UnexpectedResponse(text) => write!(f, "unexpected response {text:?}"),
            Self::TooManyProposals => f.write_str("too many proposals"),
            Self::NothingToPropose => f.write_str("no protocol to propose"),
        }
    }
}

impl Error for NegotiationError {}
