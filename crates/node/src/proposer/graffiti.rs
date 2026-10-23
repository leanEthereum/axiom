//! Block graffiti: the validator's text, the operator's, or the client versions that built the block.

use std::str::FromStr;

use axiom_execution::ClientVersion;
use axiom_types::Bytes32;

use crate::client_version::{CLIENT_CODE, COMMIT, VERSION};

/// Bytes of graffiti a block carries.
const GRAFFITI_BYTES: usize = 32;

/// What a validator client asks of the graffiti it names.
///
/// The query parameter is an extension of the block production routes, not part of beacon-APIs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GraffitiPolicy {
    /// Use the validator's graffiti as given.
    PreserveUserGraffiti,
    /// Append the execution and consensus client versions, as room allows.
    #[default]
    AppendClientVersions,
}

impl FromStr for GraffitiPolicy {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "PreserveUserGraffiti" => Ok(Self::PreserveUserGraffiti),
            "AppendClientVersions" => Ok(Self::AppendClientVersions),
            other => Err(format!("unknown graffiti policy {other}")),
        }
    }
}

/// The graffiti of a block, from the validator's request, the operator, and the engine.
///
/// # Overview
///
/// Client versions in graffiti let anyone measure client diversity from the chain itself.
/// The suffix names both clients by code and commit, shrinking as the validator's text grows:
///
/// ```text
///     text length   suffix              example
///     0             GEfa4fAX0000        no text: the suffix alone
///     1 to 19       " GEfa4fAX0000"     two code letters and four commit digits each
///     20 to 23      " GEfaAX00"         two commit digits each
///     24 to 27      " GEAX"             codes only
///     28 to 29      " GE"               the execution client's code only
///     30 to 32      none                the text alone
/// ```
///
/// The validator's text comes first; the operator's graffiti serves requests that name none.
/// A validator may keep its text untouched.
/// Without an engine identity, a validator's text stays as it is.
/// A block with no text from anyone then carries the client version.
/// See the client version specification in `src/engine/identification.md` of the engine API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GraffitiChoice<'a> {
    /// The operator's graffiti, for requests that name none.
    pub(crate) operator: Option<Bytes32>,
    /// The validator's graffiti, when its request names one.
    pub(crate) validator: Option<Bytes32>,
    /// What the validator asks of its graffiti.
    pub(crate) policy: GraffitiPolicy,
    /// The execution client's identity, when the engine gave exactly one.
    pub(crate) engine: Option<&'a ClientVersion>,
}

impl GraffitiChoice<'_> {
    /// Whether the decision needs the engine's identity, so a caller can skip asking for it.
    pub(crate) const fn reads_engine(
        operator: Option<Bytes32>,
        validator: Option<Bytes32>,
        policy: GraffitiPolicy,
    ) -> bool {
        match validator {
            Some(_) => matches!(policy, GraffitiPolicy::AppendClientVersions),
            None => operator.is_none(),
        }
    }

    /// The graffiti the block carries.
    pub(crate) fn graffiti(self) -> Bytes32 {
        match (self.validator, self.policy) {
            (Some(validator), GraffitiPolicy::PreserveUserGraffiti) => return validator,
            (None, _) => {
                if let Some(operator) = self.operator {
                    return operator;
                }
            }
            (Some(_), GraffitiPolicy::AppendClientVersions) => {}
        }
        let Some(engine) = self.engine else {
            return self.validator.unwrap_or_else(|| Self::padded(VERSION));
        };
        let ours = COMMIT.strip_prefix("0x").unwrap_or(COMMIT).to_lowercase();
        let theirs = engine.commit_prefix();
        let code = engine.code.as_str();
        let full = format!("{code}{theirs:.4}{CLIENT_CODE}{ours:.4}");
        let Some(validator) = self.validator else {
            return Self::padded(&full);
        };
        let text = Self::text(validator);
        let suffix = match text.len() {
            0..20 => full,
            20..24 => format!("{code}{theirs:.2}{CLIENT_CODE}{ours:.2}"),
            24..28 => format!("{code}{CLIENT_CODE}"),
            28..30 => code.to_owned(),
            _ => return validator,
        };
        Self::padded(&format!("{text} {suffix}"))
    }

    /// The readable text of graffiti: its bytes as UTF-8, without control characters such as padding.
    fn text(graffiti: Bytes32) -> String {
        String::from_utf8_lossy(&graffiti.0)
            .chars()
            .filter(|character| !character.is_control())
            .collect()
    }

    /// Text as graffiti: its first 32 bytes, padded with zeros.
    fn padded(text: &str) -> Bytes32 {
        let mut bytes = [0; GRAFFITI_BYTES];
        let length = text.len().min(GRAFFITI_BYTES);
        bytes[..length].copy_from_slice(&text.as_bytes()[..length]);
        Bytes32(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The engine of the identification spec's example.
    fn geth() -> ClientVersion {
        ClientVersion {
            code: "GE".to_owned(),
            name: "go-ethereum".to_owned(),
            version: "v1.14.0".to_owned(),
            commit: [0xfa, 0x4f, 0xf9, 0x22],
        }
    }

    /// The graffiti a validator text gets with the engine above and no operator graffiti.
    fn appended(text: &str) -> Bytes32 {
        let engine = geth();
        GraffitiChoice {
            operator: None,
            validator: Some(GraffitiChoice::padded(text)),
            policy: GraffitiPolicy::AppendClientVersions,
            engine: Some(&engine),
        }
        .graffiti()
    }

    #[test]
    fn the_suffix_shrinks_as_the_text_grows() {
        // Builds without a commit report zeros: the consensus part is AX0000.
        assert_eq!(COMMIT, "0x00000000");

        // 19 bytes of text leave room for the whole suffix, 32 bytes in all.
        let nineteen = "a".repeat(19);
        assert_eq!(
            appended(&nineteen),
            GraffitiChoice::padded(&format!("{nineteen} GEfa4fAX0000"))
        );

        // 20 to 23 bytes keep two commit digits each.
        let twenty = "a".repeat(20);
        assert_eq!(
            appended(&twenty),
            GraffitiChoice::padded(&format!("{twenty} GEfaAX00"))
        );

        // 24 to 27 bytes keep the codes alone; 28 and 29 the engine's code alone.
        let twenty_four = "a".repeat(24);
        assert_eq!(
            appended(&twenty_four),
            GraffitiChoice::padded(&format!("{twenty_four} GEAX"))
        );
        let twenty_nine = "a".repeat(29);
        assert_eq!(
            appended(&twenty_nine),
            GraffitiChoice::padded(&format!("{twenty_nine} GE"))
        );

        // 30 bytes leave no room for a space and a code.
        let thirty = "a".repeat(30);
        assert_eq!(appended(&thirty), GraffitiChoice::padded(&thirty));
    }

    #[test]
    fn the_validator_text_comes_first_and_no_engine_keeps_it() {
        let engine = geth();
        let validator = Some(GraffitiChoice::padded("hello"));
        let operator = Some(GraffitiChoice::padded("operator"));
        let choice = |operator, validator, policy, engine| {
            GraffitiChoice {
                operator,
                validator,
                policy,
                engine,
            }
            .graffiti()
        };

        // A validator that preserves its text gets it untouched, whatever the operator set.
        assert_eq!(
            choice(
                operator,
                validator,
                GraffitiPolicy::PreserveUserGraffiti,
                Some(&engine)
            ),
            GraffitiChoice::padded("hello")
        );
        // Appending keeps the validator's text over the operator's.
        assert_eq!(
            choice(
                operator,
                validator,
                GraffitiPolicy::AppendClientVersions,
                Some(&engine)
            ),
            GraffitiChoice::padded("hello GEfa4fAX0000")
        );
        // A request without text takes the operator's graffiti as it is.
        assert_eq!(
            choice(
                operator,
                None,
                GraffitiPolicy::AppendClientVersions,
                Some(&engine)
            ),
            GraffitiChoice::padded("operator")
        );
        // The engine is asked only when its identity can matter.
        assert!(!GraffitiChoice::reads_engine(
            operator,
            None,
            GraffitiPolicy::AppendClientVersions
        ));
        assert!(!GraffitiChoice::reads_engine(
            None,
            validator,
            GraffitiPolicy::PreserveUserGraffiti
        ));
        assert!(GraffitiChoice::reads_engine(
            operator,
            validator,
            GraffitiPolicy::AppendClientVersions
        ));
        // No request text and an engine identity: the suffix alone.
        assert_eq!(
            choice(
                None,
                None,
                GraffitiPolicy::AppendClientVersions,
                Some(&engine)
            ),
            GraffitiChoice::padded("GEfa4fAX0000")
        );
        // No engine identity: the text unchanged, or the client version without one.
        assert_eq!(
            choice(None, validator, GraffitiPolicy::AppendClientVersions, None),
            GraffitiChoice::padded("hello")
        );
        assert_eq!(
            choice(None, None, GraffitiPolicy::AppendClientVersions, None),
            GraffitiChoice::padded(VERSION)
        );
    }

    #[test]
    fn policies_parse_by_their_names() {
        assert_eq!(
            "PreserveUserGraffiti".parse(),
            Ok(GraffitiPolicy::PreserveUserGraffiti)
        );
        assert_eq!(
            "AppendClientVersions".parse(),
            Ok(GraffitiPolicy::AppendClientVersions)
        );
        assert!("Preserve".parse::<GraffitiPolicy>().is_err());
    }
}
