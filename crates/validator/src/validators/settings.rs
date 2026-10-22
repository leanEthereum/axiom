//! Proposal settings: the client's defaults, each validator's overrides, and their resolution.

use axiom_types::ExecutionAddress;

use crate::validators::{BuilderConfig, Graffiti};

/// Gas limit a proposer asks for when none is configured.
///
/// It matches the execution layer's default target at the time of writing.
pub const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

/// The boost factor that weighs a builder's bid and the local payload equally.
///
/// See `produceBlockV3` in the beacon API: the factor is a percentage.
pub const NEUTRAL_BOOST_FACTOR: u64 = 100;

/// Proposal settings that apply to every validator unless overridden.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProposerDefaults {
    /// Where execution fees go.
    pub fee_recipient: ExecutionAddress,
    /// The gas limit to ask builders and the engine for.
    pub gas_limit: u64,
    /// Bytes written into each block.
    pub graffiti: Graffiti,
    /// Whether validators register with external builders and accept their bids.
    pub builder: bool,
    /// The boost factor sent with block requests.
    pub builder_boost_factor: Option<u64>,
    /// Whether a builder's bid always wins over the local payload.
    pub prefer_builder_proposals: bool,
}

/// One validator's overrides of the client's defaults, each absent until set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidatorSettings {
    /// Where execution fees go.
    pub fee_recipient: Option<ExecutionAddress>,
    /// The gas limit to ask for.
    pub gas_limit: Option<u64>,
    /// Bytes written into each block.
    pub graffiti: Option<Graffiti>,
    /// Whether the validator registers with external builders and accepts their bids.
    pub builder_proposals: Option<bool>,
    /// The boost factor sent with block requests.
    pub builder_boost_factor: Option<u64>,
    /// Whether a builder's bid always wins over the local payload.
    pub prefer_builder_proposals: Option<bool>,
    /// The builders a Gloas proposal asks for bids, through the keymanager API.
    pub builder_config: Option<BuilderConfig>,
}

/// What a validator's proposals use, after overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposerSettings {
    /// Where execution fees go.
    pub fee_recipient: ExecutionAddress,
    /// The gas limit to ask for.
    pub gas_limit: u64,
    /// Whether the validator registers with external builders.
    pub builder: bool,
    /// The boost factor to send with block requests, absent for the neutral one.
    pub builder_boost_factor: Option<u64>,
}

impl ProposerSettings {
    /// Resolves a validator's overrides against the client's defaults.
    ///
    /// # Algorithm
    ///
    /// The boost factor follows the first rule that applies:
    ///
    /// 1. The validator prefers builders: the largest factor, so any bid wins.
    /// 2. The validator sets a factor: that factor.
    /// 3. The validator turns builders off: zero, so the local payload wins.
    /// 4. The client prefers builders: the largest factor.
    /// 5. The client sets a factor: that factor.
    /// 6. The client turns builders off: zero, even for a validator that turns them on.
    ///
    /// The neutral factor of 100 is sent as no factor, which the beacon API treats alike.
    #[must_use]
    pub fn resolve(defaults: &ProposerDefaults, overrides: &ValidatorSettings) -> Self {
        let builder = overrides.builder_proposals.unwrap_or(defaults.builder);
        let own = if overrides.prefer_builder_proposals == Some(true) {
            Some(u64::MAX)
        } else {
            overrides
                .builder_boost_factor
                .or_else(|| (overrides.builder_proposals == Some(false)).then_some(0))
        };
        let client = if defaults.prefer_builder_proposals {
            Some(u64::MAX)
        } else {
            defaults
                .builder_boost_factor
                .or_else(|| (!defaults.builder).then_some(0))
        };
        Self {
            fee_recipient: overrides.fee_recipient.unwrap_or(defaults.fee_recipient),
            gas_limit: overrides.gas_limit.unwrap_or(defaults.gas_limit),
            builder,
            builder_boost_factor: own
                .or(client)
                .filter(|factor| *factor != NEUTRAL_BOOST_FACTOR),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Client defaults with builders on or off, and a factor.
    fn defaults(builder: bool, factor: Option<u64>, prefer: bool) -> ProposerDefaults {
        ProposerDefaults {
            builder,
            builder_boost_factor: factor,
            prefer_builder_proposals: prefer,
            ..ProposerDefaults::default()
        }
    }

    /// The factor a validator's overrides resolve to under client defaults.
    fn factor(defaults: &ProposerDefaults, overrides: &ValidatorSettings) -> Option<u64> {
        ProposerSettings::resolve(defaults, overrides).builder_boost_factor
    }

    #[test]
    fn each_boost_rule_wins_in_turn() {
        let none = ValidatorSettings::default();
        let with = |prefer, factor, proposals| ValidatorSettings {
            prefer_builder_proposals: prefer,
            builder_boost_factor: factor,
            builder_proposals: proposals,
            ..ValidatorSettings::default()
        };
        let client = defaults(true, Some(50), true);

        // Rule 1 beats a factor of 7 the validator also sets.
        assert_eq!(
            factor(&client, &with(Some(true), Some(7), None)),
            Some(u64::MAX)
        );
        // Rule 2 beats the validator turning builders off.
        assert_eq!(factor(&client, &with(None, Some(7), Some(false))), Some(7));
        // Rule 3 beats every client rule.
        assert_eq!(factor(&client, &with(None, None, Some(false))), Some(0));
        // Rule 4 beats the client's factor of 50.
        assert_eq!(factor(&client, &none), Some(u64::MAX));
        // Rule 5 beats the client turning builders off.
        assert_eq!(factor(&defaults(false, Some(50), false), &none), Some(50));
        // Rule 6 is the last word, and builders on with no factor leave the node to choose.
        assert_eq!(factor(&defaults(false, None, false), &none), Some(0));
        assert_eq!(factor(&defaults(true, None, false), &none), None);
    }

    #[test]
    fn the_neutral_factor_is_sent_as_none() {
        // 100 weighs bid and local payload alike, which no factor also means.
        let overrides = ValidatorSettings {
            builder_boost_factor: Some(NEUTRAL_BOOST_FACTOR),
            ..ValidatorSettings::default()
        };
        assert_eq!(factor(&defaults(false, None, false), &overrides), None);
    }

    #[test]
    fn overrides_replace_each_default() {
        let client = ProposerDefaults {
            fee_recipient: ExecutionAddress([1; 20]),
            gas_limit: DEFAULT_GAS_LIMIT,
            builder: false,
            ..ProposerDefaults::default()
        };
        let overrides = ValidatorSettings {
            fee_recipient: Some(ExecutionAddress([7; 20])),
            gas_limit: Some(30_000_000),
            builder_proposals: Some(true),
            ..ValidatorSettings::default()
        };
        // The validator registers with builders, but the client's builders-off rule still sends 0.
        assert_eq!(
            ProposerSettings::resolve(&client, &overrides),
            ProposerSettings {
                fee_recipient: ExecutionAddress([7; 20]),
                gas_limit: 30_000_000,
                builder: true,
                builder_boost_factor: Some(0),
            }
        );
    }
}
