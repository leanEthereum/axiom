//! Names of the beacon chain forks.

use std::fmt;

/// A beacon chain fork, in activation order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ForkName {
    /// The launch of the beacon chain.
    Phase0,
    /// Sync committees and participation flags.
    Altair,
    /// The merge with the execution layer.
    Bellatrix,
    /// Withdrawals.
    Capella,
    /// Blobs, see EIP-4844.
    Deneb,
    /// Larger validators and execution requests, see EIP-7251 and EIP-7685.
    Electra,
    /// Peer data availability sampling, see EIP-7594.
    Fulu,
    /// Enshrined proposer-builder separation, see EIP-7732.
    Gloas,
}

impl ForkName {
    /// Every fork, in activation order.
    pub const ALL: [Self; 8] = [
        Self::Phase0,
        Self::Altair,
        Self::Bellatrix,
        Self::Capella,
        Self::Deneb,
        Self::Electra,
        Self::Fulu,
        Self::Gloas,
    ];

    /// The fork's name in lowercase, as the spec's test vectors spell it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phase0 => "phase0",
            Self::Altair => "altair",
            Self::Bellatrix => "bellatrix",
            Self::Capella => "capella",
            Self::Deneb => "deneb",
            Self::Electra => "electra",
            Self::Fulu => "fulu",
            Self::Gloas => "gloas",
        }
    }

    /// The fork with the given lowercase name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|fork| fork.as_str() == name)
    }

    /// The fork right before this one.
    #[must_use]
    pub const fn previous(self) -> Option<Self> {
        match self {
            Self::Phase0 => None,
            Self::Altair => Some(Self::Phase0),
            Self::Bellatrix => Some(Self::Altair),
            Self::Capella => Some(Self::Bellatrix),
            Self::Deneb => Some(Self::Capella),
            Self::Electra => Some(Self::Deneb),
            Self::Fulu => Some(Self::Electra),
            Self::Gloas => Some(Self::Fulu),
        }
    }
}

impl fmt::Display for ForkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
