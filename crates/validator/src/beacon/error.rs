//! Why a beacon node request failed.

use axiom_http::{HttpError, StatusCode};
use axiom_json::ParseError;
use axiom_ssz::DecodeError;
use thiserror::Error;

use crate::json::JsonError;

/// A beacon node request that did not produce its answer.
#[derive(Debug, Error)]
pub enum BeaconError {
    /// The node could not be reached, or the exchange broke.
    #[error("beacon node unreachable: {0}")]
    Http(#[from] HttpError),
    /// The node answered with an error status.
    #[error("beacon node answered {status}: {message}")]
    Status {
        /// The HTTP status.
        status: StatusCode,
        /// The node's message, or the raw body.
        message: String,
    },
    /// The answer is not JSON.
    #[error("beacon node answer is not JSON: {0}")]
    Parse(#[from] ParseError),
    /// The answer is JSON of the wrong shape.
    #[error("beacon node answer is malformed: {0}")]
    Json(#[from] JsonError),
    /// The answer is not the SSZ value expected.
    #[error("beacon node answer is not valid SSZ: {0}")]
    Ssz(#[from] DecodeError),
    /// A response header the answer needs is missing or malformed.
    #[error("beacon node answer lacks a valid {0} header")]
    Header(&'static str),
    /// The answer is of another fork than the slot it is for.
    #[error("beacon node answered for fork {found}, expected {expected}")]
    WrongFork {
        /// The fork the slot is in.
        expected: String,
        /// The fork the answer claims.
        found: String,
    },
    /// The node has nothing to answer, such as no block yet for a payload vote.
    #[error("beacon node has no content for this request")]
    NoContent,
    /// The node produced a blinded block, which this client cannot sign.
    #[error("beacon node produced a blinded block, which this client does not sign")]
    Blinded,
    /// A duty names a committee seat outside its committee.
    #[error("committee seat {seat} is outside a committee of {length}")]
    Seat {
        /// The seat.
        seat: u64,
        /// Members of the committee.
        length: u64,
    },
    /// A duty names a committee larger than an attestation's bits.
    #[error("committee of {length} exceeds the {max} members an attestation holds")]
    CommitteeTooLarge {
        /// Members of the committee.
        length: u64,
        /// Most members allowed.
        max: u64,
    },
    /// No beacon node is configured.
    #[error("no beacon node configured")]
    NoNodes,
}
