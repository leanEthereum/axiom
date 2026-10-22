//! The versioned envelope the builder API wraps its fork-dependent responses in.

use axiom_json::{Json, Limits};
use axiom_types::ForkName;

use crate::BuilderError;

/// A response body of the form `{"version": "<fork>", "data": ...}`.
///
/// The bid and the revealed payload travel this way.
/// See the getHeader and submitBlindedBlock responses of the builder API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Versioned {
    /// The fork the data belongs to.
    pub(crate) fork: ForkName,
    /// The fork's container, still as JSON.
    pub(crate) data: Json,
}

impl Versioned {
    /// Most bytes accepted in one response.
    ///
    /// A Fulu reveal carries its blobs hex-encoded, 256 KiB of text each, plus 128 proofs per blob.
    /// 64 MiB holds well over a hundred blobs with a full block of transactions.
    pub(crate) const MAX_BYTES: usize = 64 << 20;

    /// Nesting allowed in a response; a revealed payload nests at most five levels.
    const MAX_DEPTH: usize = 32;

    /// Reads the envelope and checks that it answers a request of the given fork.
    ///
    /// # Errors
    ///
    /// Fails when the body is not JSON, lacks a member, names an unknown fork, or another fork.
    pub(crate) fn parse(body: &[u8], expected: ForkName) -> Result<Self, BuilderError> {
        let limits = Limits {
            max_depth: Self::MAX_DEPTH,
            max_bytes: Self::MAX_BYTES,
        };
        let mut json = Json::parse_with(body, limits).map_err(BuilderError::Json)?;
        let version = json
            .get("version")
            .and_then(Json::as_str)
            .ok_or(BuilderError::MissingMember { member: "version" })?;
        let fork = ForkName::from_name(version).ok_or_else(|| BuilderError::UnknownVersion {
            version: version.to_owned(),
        })?;
        if fork != expected {
            return Err(BuilderError::Version {
                expected,
                actual: fork,
            });
        }
        let data = match &mut json {
            Json::Object(object) => object.remove("data"),
            _ => None,
        }
        .ok_or(BuilderError::MissingMember { member: "data" })?;
        Ok(Self { fork, data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses a body against a Deneb request and renders the outcome for whole-value comparison.
    fn parse(body: &str) -> Result<Versioned, String> {
        Versioned::parse(body.as_bytes(), ForkName::Deneb).map_err(|error| error.to_string())
    }

    #[test]
    fn a_matching_envelope_yields_its_data() {
        assert_eq!(
            parse(r#"{"version":"deneb","data":{"a":"1"}}"#),
            Ok(Versioned {
                fork: ForkName::Deneb,
                data: Json::parse(r#"{"a":"1"}"#).unwrap(),
            })
        );
    }

    #[test]
    fn a_broken_envelope_is_refused() {
        // Each case names the member or the fork at fault.
        assert_eq!(
            parse(r#"{"data":{}}"#),
            Err("relay response lacks the version member".to_owned())
        );
        assert_eq!(
            parse(r#"{"version":"deneb"}"#),
            Err("relay response lacks the data member".to_owned())
        );
        assert_eq!(
            parse(r#"{"version":"verge","data":{}}"#),
            Err("relay response names unknown version \"verge\"".to_owned())
        );
        assert_eq!(
            parse(r#"{"version":"capella","data":{}}"#),
            Err("relay answered with a capella response to a deneb request".to_owned())
        );
    }
}
