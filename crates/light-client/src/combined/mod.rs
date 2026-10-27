//! Light client data and stores of any format, one enum per container.
//!
//! # Overview
//!
//! Light client data travels in the format of the fork it describes, tagged by a fork digest.
//! A store keeps one format, and upgrades data of earlier formats before using it.
//! These enums carry one variant per format and the few methods that move between them.
//!
//! Dispatch happens once, at that boundary.
//! Below it, the store's rules run on one concrete format.

mod bootstrap;
mod header;
mod store;
mod update;

use std::fmt;

use axiom_types::ForkName;
pub use bootstrap::LightClientBootstrap;
pub use header::LightClientHeader;
pub use store::LightClientStore;
pub use update::{LightClientFinalityUpdate, LightClientOptimisticUpdate, LightClientUpdate};

use crate::LightClientError;

/// A light client data format, named after the fork that introduced it.
///
/// Bellatrix keeps Altair's format and Fulu keeps Electra's.
/// See the per-fork type tables of the Gloas light client networking spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Format {
    /// Beacon headers alone.
    Altair,
    /// Headers with the Capella payload header.
    Capella,
    /// Headers with the Deneb payload header.
    Deneb,
    /// Deneb headers, with longer state branches.
    Electra,
    /// Headers with the execution block hash alone.
    Gloas,
}

impl Format {
    /// The format of a fork's light client data.
    ///
    /// # Errors
    ///
    /// Fails for phase0, which has no sync committees.
    pub const fn of(fork: ForkName) -> Result<Self, LightClientError> {
        match fork {
            ForkName::Phase0 => Err(LightClientError::NoLightClientData(fork)),
            ForkName::Altair | ForkName::Bellatrix => Ok(Self::Altair),
            ForkName::Capella => Ok(Self::Capella),
            ForkName::Deneb => Ok(Self::Deneb),
            ForkName::Electra | ForkName::Fulu => Ok(Self::Electra),
            // Hstar keeps Gloas's headers and indices, so its data is in Gloas's format.
            ForkName::Gloas | ForkName::Hstar => Ok(Self::Gloas),
        }
    }

    /// The fork that introduced the format.
    #[must_use]
    pub const fn fork(self) -> ForkName {
        match self {
            Self::Altair => ForkName::Altair,
            Self::Capella => ForkName::Capella,
            Self::Deneb => ForkName::Deneb,
            Self::Electra => ForkName::Electra,
            Self::Gloas => ForkName::Gloas,
        }
    }

    /// Checks that data of this format can be upgraded into another format.
    ///
    /// # Errors
    ///
    /// Fails when the other format is earlier: upgrades only move forward.
    pub fn upgradable_to(self, target: Self) -> Result<(), LightClientError> {
        if self > target {
            return Err(LightClientError::LaterData {
                data: self.fork(),
                store: target.fork(),
            });
        }
        Ok(())
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.fork(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bellatrix_and_fulu_keep_the_format_before_them() {
        assert_eq!(Format::of(ForkName::Bellatrix), Ok(Format::Altair));
        assert_eq!(Format::of(ForkName::Fulu), Ok(Format::Electra));
        assert_eq!(Format::of(ForkName::Gloas), Ok(Format::Gloas));
        assert_eq!(
            Format::of(ForkName::Phase0),
            Err(LightClientError::NoLightClientData(ForkName::Phase0))
        );
    }

    #[test]
    fn upgrades_only_move_forward() {
        // Capella data upgrades into a Deneb store, and stays as it is in a Capella store.
        assert_eq!(Format::Capella.upgradable_to(Format::Deneb), Ok(()));
        assert_eq!(Format::Capella.upgradable_to(Format::Capella), Ok(()));

        // Gloas data cannot enter an Electra store.
        assert_eq!(
            Format::Gloas.upgradable_to(Format::Electra),
            Err(LightClientError::LaterData {
                data: ForkName::Gloas,
                store: ForkName::Electra,
            })
        );
    }
}
