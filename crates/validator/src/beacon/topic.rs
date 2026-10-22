//! Kinds of publication, each sent to every beacon node or to the healthiest one alone.

use std::{collections::BTreeSet, fmt, str::FromStr};

use crate::beacon::BeaconError;

/// A kind of message the client publishes through beacon nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ApiTopic {
    /// Votes, aggregates, and payload timeliness votes.
    Attestations,
    /// Signed blocks and payload envelopes.
    Blocks,
    /// Subnet subscriptions, proposer preparations, registrations, and preferences.
    Subscriptions,
    /// Sync committee messages and contributions.
    SyncCommittee,
}

impl ApiTopic {
    /// Every topic, in the order operators name them.
    pub const ALL: [Self; 4] = [
        Self::Attestations,
        Self::Blocks,
        Self::Subscriptions,
        Self::SyncCommittee,
    ];

    /// The topic's name on the command line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attestations => "attestations",
            Self::Blocks => "blocks",
            Self::Subscriptions => "subscriptions",
            Self::SyncCommittee => "sync-committee",
        }
    }

    /// The topics broadcast when an operator names none: subscriptions only.
    ///
    /// Every node then serves the subnets duties need, while each message is sent once.
    #[must_use]
    pub fn defaults() -> BTreeSet<Self> {
        BTreeSet::from([Self::Subscriptions])
    }

    /// Reads a comma-separated list, in which the word none names no topic.
    ///
    /// # Errors
    ///
    /// Fails on a name that is no topic.
    pub fn parse_list(text: &str) -> Result<BTreeSet<Self>, BeaconError> {
        let mut topics = BTreeSet::new();
        for name in text.split(',').map(str::trim) {
            if name == "none" {
                continue;
            }
            topics.insert(name.parse()?);
        }
        Ok(topics)
    }
}

impl FromStr for ApiTopic {
    type Err = BeaconError;

    fn from_str(name: &str) -> Result<Self, BeaconError> {
        Self::ALL
            .into_iter()
            .find(|topic| topic.as_str() == name)
            .ok_or_else(|| BeaconError::UnknownTopic(name.to_owned()))
    }
}

impl fmt::Display for ApiTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_parse_by_name_and_none_names_nothing() {
        assert_eq!(
            ApiTopic::parse_list("blocks, sync-committee").unwrap(),
            BTreeSet::from([ApiTopic::Blocks, ApiTopic::SyncCommittee])
        );
        assert_eq!(ApiTopic::parse_list("none").unwrap(), BTreeSet::new());
        for topic in ApiTopic::ALL {
            assert_eq!(topic.as_str().parse::<ApiTopic>().unwrap(), topic);
        }
        assert_eq!(
            ApiTopic::parse_list("blocks,votes")
                .unwrap_err()
                .to_string(),
            "unknown broadcast topic \"votes\""
        );
    }
}
