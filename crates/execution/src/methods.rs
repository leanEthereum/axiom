//! The engine API methods each fork calls.
//!
//! # Overview
//!
//! Each consensus fork pairs with one execution fork, and that pair fixes every method version.
//! The table below is the only place a version is chosen.
//!
//! ```text
//!     fork       execution  newPayload  forkchoiceUpdated  getPayload  getBlobs
//!     Bellatrix  Paris      V1          V1                 V1          none
//!     Capella    Shanghai   V2          V2                 V2          none
//!     Deneb      Cancun     V3          V3                 V3          V1
//!     Electra    Prague     V4          V3                 V4          V1
//!     Fulu       Osaka      V4          V3                 V5          V2
//!     Gloas      Amsterdam  V5          V4                 V6          V2
//! ```
//!
//! Phase0 and Altair predate the merge, so they call no engine method.
//! Each version is defined in `src/engine/` of `ethereum/execution-apis`, in the file of its fork.
//!
//! Gloas keeps getBlobsV2.
//! Amsterdam leaves it valid, and its blobs carry the cell proofs that data columns need.
//! The partial variants, getBlobsV3 and getBlobsV4, are optional and not called.

use std::{fmt, time::Duration};

use axiom_types::ForkName;

/// Timeout of engine_newPayload and engine_forkchoiceUpdated, from `src/engine/paris.md`.
///
/// Both may execute a block, so the engine gets eight seconds, more than half a slot.
pub const EXECUTION_TIMEOUT: Duration = Duration::from_secs(8);

/// Timeout of engine_newPayloadV5, which `src/engine/amsterdam.md` shortens to six seconds.
const AMSTERDAM_NEW_PAYLOAD_TIMEOUT: Duration = Duration::from_secs(6);

/// Engine methods this client calls whatever the fork, as announced to the engine.
///
/// See `src/engine/shanghai.md` and `src/engine/identification.md`.
pub const FORK_INDEPENDENT: &[&str] = &[
    "engine_getPayloadBodiesByHashV1",
    "engine_getPayloadBodiesByRangeV1",
    "engine_getClientVersionV1",
];

/// Engine methods this client calls, as announced to the engine.
///
/// It is the union of the table's methods, in family and version order, then the fork-independent ones.
pub const CAPABILITIES: &[&str] = &[
    "engine_newPayloadV1",
    "engine_newPayloadV2",
    "engine_newPayloadV3",
    "engine_newPayloadV4",
    "engine_newPayloadV5",
    "engine_forkchoiceUpdatedV1",
    "engine_forkchoiceUpdatedV2",
    "engine_forkchoiceUpdatedV3",
    "engine_forkchoiceUpdatedV4",
    "engine_getPayloadV1",
    "engine_getPayloadV2",
    "engine_getPayloadV3",
    "engine_getPayloadV4",
    "engine_getPayloadV5",
    "engine_getPayloadV6",
    "engine_getBlobsV1",
    "engine_getBlobsV2",
    "engine_getPayloadBodiesByHashV1",
    "engine_getPayloadBodiesByRangeV1",
    "engine_getClientVersionV1",
];

/// The versions of every engine method one fork calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EngineMethods {
    /// Hands a payload to the engine for judgement.
    pub new_payload: NewPayloadVersion,

    /// Moves the engine's head, and optionally starts a build.
    pub forkchoice_updated: ForkchoiceVersion,

    /// Fetches a payload the engine built.
    pub get_payload: GetPayloadVersion,

    /// Fetches blobs from the engine's pool, from Deneb on.
    pub get_blobs: Option<GetBlobsVersion>,
}

impl EngineMethods {
    /// The methods a fork calls, or nothing before the merge.
    #[must_use]
    pub const fn of(fork: ForkName) -> Option<Self> {
        let (new_payload, forkchoice_updated, get_payload, get_blobs) = match fork {
            ForkName::Phase0 | ForkName::Altair => return None,
            ForkName::Bellatrix => (
                NewPayloadVersion::V1,
                ForkchoiceVersion::V1,
                GetPayloadVersion::V1,
                None,
            ),
            ForkName::Capella => (
                NewPayloadVersion::V2,
                ForkchoiceVersion::V2,
                GetPayloadVersion::V2,
                None,
            ),
            ForkName::Deneb => (
                NewPayloadVersion::V3,
                ForkchoiceVersion::V3,
                GetPayloadVersion::V3,
                Some(GetBlobsVersion::V1),
            ),
            ForkName::Electra => (
                NewPayloadVersion::V4,
                ForkchoiceVersion::V3,
                GetPayloadVersion::V4,
                Some(GetBlobsVersion::V1),
            ),
            ForkName::Fulu => (
                NewPayloadVersion::V4,
                ForkchoiceVersion::V3,
                GetPayloadVersion::V5,
                Some(GetBlobsVersion::V2),
            ),
            ForkName::Gloas => (
                NewPayloadVersion::V5,
                ForkchoiceVersion::V4,
                GetPayloadVersion::V6,
                Some(GetBlobsVersion::V2),
            ),
        };
        Some(Self {
            new_payload,
            forkchoice_updated,
            get_payload,
            get_blobs,
        })
    }
}

/// A version of engine_newPayload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NewPayloadVersion {
    /// The payload alone, see `src/engine/paris.md`.
    V1,
    /// A payload with withdrawals, see `src/engine/shanghai.md`.
    V2,
    /// Adds blob versioned hashes and the parent beacon block root, see `src/engine/cancun.md`.
    V3,
    /// Adds the execution requests, see `src/engine/prague.md`.
    V4,
    /// A payload with a block access list and a slot number, see `src/engine/amsterdam.md`.
    V5,
}

impl NewPayloadVersion {
    /// The JSON-RPC method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::V1 => "engine_newPayloadV1",
            Self::V2 => "engine_newPayloadV2",
            Self::V3 => "engine_newPayloadV3",
            Self::V4 => "engine_newPayloadV4",
            Self::V5 => "engine_newPayloadV5",
        }
    }

    /// How long the engine may take to answer.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        match self {
            Self::V1 | Self::V2 | Self::V3 | Self::V4 => EXECUTION_TIMEOUT,
            Self::V5 => AMSTERDAM_NEW_PAYLOAD_TIMEOUT,
        }
    }
}

impl fmt::Display for NewPayloadVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.method())
    }
}

/// A version of engine_forkchoiceUpdated, which fixes the payload attributes version too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ForkchoiceVersion {
    /// Attributes without withdrawals, see `src/engine/paris.md`.
    V1,
    /// Attributes with withdrawals, see `src/engine/shanghai.md`.
    V2,
    /// Attributes with the parent beacon block root, see `src/engine/cancun.md`.
    V3,
    /// Attributes with a slot number and a target gas limit, see `src/engine/amsterdam.md`.
    V4,
}

impl ForkchoiceVersion {
    /// The JSON-RPC method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::V1 => "engine_forkchoiceUpdatedV1",
            Self::V2 => "engine_forkchoiceUpdatedV2",
            Self::V3 => "engine_forkchoiceUpdatedV3",
            Self::V4 => "engine_forkchoiceUpdatedV4",
        }
    }
}

impl fmt::Display for ForkchoiceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.method())
    }
}

/// A version of engine_getPayload, which fixes the shape of the reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GetPayloadVersion {
    /// The payload alone, see `src/engine/paris.md`.
    V1,
    /// Adds the block value, see `src/engine/shanghai.md`.
    V2,
    /// Adds blobs with one proof each, see `src/engine/cancun.md`.
    V3,
    /// Adds the execution requests, see `src/engine/prague.md`.
    V4,
    /// Blobs carry cell proofs, see `src/engine/osaka.md`.
    V5,
    /// The payload gains a block access list and a slot number, see `src/engine/amsterdam.md`.
    V6,
}

impl GetPayloadVersion {
    /// The JSON-RPC method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::V1 => "engine_getPayloadV1",
            Self::V2 => "engine_getPayloadV2",
            Self::V3 => "engine_getPayloadV3",
            Self::V4 => "engine_getPayloadV4",
            Self::V5 => "engine_getPayloadV5",
            Self::V6 => "engine_getPayloadV6",
        }
    }
}

impl fmt::Display for GetPayloadVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.method())
    }
}

/// A version of engine_getBlobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GetBlobsVersion {
    /// One proof per blob, a null per missing blob, see `src/engine/cancun.md`.
    V1,
    /// Cell proofs per blob, all or nothing, see `src/engine/osaka.md`.
    V2,
}

impl GetBlobsVersion {
    /// The JSON-RPC method name.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::V1 => "engine_getBlobsV1",
            Self::V2 => "engine_getBlobsV2",
        }
    }
}

impl fmt::Display for GetBlobsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.method())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One row of the table, spelled out.
    const fn row(
        new_payload: NewPayloadVersion,
        forkchoice_updated: ForkchoiceVersion,
        get_payload: GetPayloadVersion,
        get_blobs: Option<GetBlobsVersion>,
    ) -> EngineMethods {
        EngineMethods {
            new_payload,
            forkchoice_updated,
            get_payload,
            get_blobs,
        }
    }

    #[test]
    fn every_fork_calls_the_versions_its_execution_fork_defines() {
        // The table of the module docs, row by row, phase0 to Gloas.
        let expected = [
            None,
            None,
            Some(row(
                NewPayloadVersion::V1,
                ForkchoiceVersion::V1,
                GetPayloadVersion::V1,
                None,
            )),
            Some(row(
                NewPayloadVersion::V2,
                ForkchoiceVersion::V2,
                GetPayloadVersion::V2,
                None,
            )),
            Some(row(
                NewPayloadVersion::V3,
                ForkchoiceVersion::V3,
                GetPayloadVersion::V3,
                Some(GetBlobsVersion::V1),
            )),
            Some(row(
                NewPayloadVersion::V4,
                ForkchoiceVersion::V3,
                GetPayloadVersion::V4,
                Some(GetBlobsVersion::V1),
            )),
            Some(row(
                NewPayloadVersion::V4,
                ForkchoiceVersion::V3,
                GetPayloadVersion::V5,
                Some(GetBlobsVersion::V2),
            )),
            Some(row(
                NewPayloadVersion::V5,
                ForkchoiceVersion::V4,
                GetPayloadVersion::V6,
                Some(GetBlobsVersion::V2),
            )),
        ];
        let actual = ForkName::ALL.map(EngineMethods::of);
        assert_eq!(actual, expected);
    }

    #[test]
    fn capabilities_are_the_union_of_the_table() {
        // Collect each method once, grouped by family as the announced list is.
        let rows = ForkName::ALL
            .into_iter()
            .filter_map(EngineMethods::of)
            .collect::<Vec<_>>();
        let new_payload = rows.iter().map(|methods| methods.new_payload.method());
        let forkchoice = rows
            .iter()
            .map(|methods| methods.forkchoice_updated.method());
        let get_payload = rows.iter().map(|methods| methods.get_payload.method());
        let get_blobs = rows
            .iter()
            .filter_map(|methods| methods.get_blobs.map(GetBlobsVersion::method));
        let mut union = Vec::new();
        for method in new_payload
            .chain(forkchoice)
            .chain(get_payload)
            .chain(get_blobs)
            .chain(FORK_INDEPENDENT.iter().copied())
        {
            if !union.contains(&method) {
                union.push(method);
            }
        }

        // Each method version of the table appears once.
        assert_eq!(union, CAPABILITIES);
        assert_eq!(CAPABILITIES.len(), 20);
    }

    #[test]
    fn only_amsterdam_shortens_the_new_payload_timeout() {
        // Paris through Prague allow 8 seconds; Amsterdam allows 6.
        let timeouts = [
            NewPayloadVersion::V1,
            NewPayloadVersion::V2,
            NewPayloadVersion::V3,
            NewPayloadVersion::V4,
            NewPayloadVersion::V5,
        ]
        .map(|version| version.timeout().as_secs());
        assert_eq!(timeouts, [8, 8, 8, 8, 6]);
    }
}
