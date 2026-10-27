//! A data column sidecar of any fork that has columns.

use axiom_ssz::{DecodeError, Root, Ssz};

use crate::{ColumnIndex, ForkName, Preset, Slot, fulu, gloas};

/// A data column sidecar of whichever fork it belongs to.
///
/// Fulu columns carry their block's header and prove their commitments against it.
/// Gloas columns name their block, whose bid holds the commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "the Fulu header and proof are inline; holders keep columns behind a shared pointer"
)]
pub enum DataColumnSidecar<P: Preset> {
    /// A Fulu column.
    Fulu(fulu::DataColumnSidecar<P>),
    /// A Gloas column.
    Gloas(gloas::DataColumnSidecar<P>),
}

impl<P: Preset> DataColumnSidecar<P> {
    /// The fork whose format the column has.
    #[must_use]
    pub const fn fork_name(&self) -> ForkName {
        match self {
            Self::Fulu(_) => ForkName::Fulu,
            Self::Gloas(_) => ForkName::Gloas,
        }
    }

    /// Position of the column in the extended matrix.
    #[must_use]
    pub const fn index(&self) -> ColumnIndex {
        match self {
            Self::Fulu(sidecar) => sidecar.index,
            Self::Gloas(sidecar) => sidecar.index,
        }
    }

    /// Slot of the column's block.
    #[must_use]
    pub const fn slot(&self) -> Slot {
        match self {
            Self::Fulu(sidecar) => sidecar.signed_block_header.message.slot,
            Self::Gloas(sidecar) => sidecar.slot,
        }
    }

    /// Root of the column's block.
    #[must_use]
    pub fn block_root(&self) -> Root {
        match self {
            Self::Fulu(sidecar) => sidecar.signed_block_header.message.hash_tree_root(),
            Self::Gloas(sidecar) => sidecar.beacon_block_root,
        }
    }

    /// The column's cells, one per blob of its block, in blob order.
    #[must_use]
    pub fn cells(&self) -> &[fulu::Cell<P>] {
        match self {
            Self::Fulu(sidecar) => &sidecar.column,
            Self::Gloas(sidecar) => &sidecar.column,
        }
    }

    /// The column's SSZ encoding, which does not record the fork.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Fulu(sidecar) => sidecar.encode(),
            Self::Gloas(sidecar) => sidecar.encode(),
        }
    }

    /// Decodes a column of the fork in force at its block's slot.
    ///
    /// Hstar kept the Gloas column, so its bytes are read in that format.
    /// Forks before Fulu have no columns, so their bytes are read in the first column format.
    /// Callers check the fork's blob data first and never get there.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are not the encoding of that fork's column.
    pub fn decode(bytes: &[u8], fork: ForkName) -> Result<Self, DecodeError> {
        Ok(match fork {
            ForkName::Gloas | ForkName::Hstar => Self::Gloas(Ssz::decode(bytes)?),
            ForkName::Phase0
            | ForkName::Altair
            | ForkName::Bellatrix
            | ForkName::Capella
            | ForkName::Deneb
            | ForkName::Electra
            | ForkName::Fulu => Self::Fulu(Ssz::decode(bytes)?),
        })
    }
}

impl<P: Preset> From<fulu::DataColumnSidecar<P>> for DataColumnSidecar<P> {
    fn from(sidecar: fulu::DataColumnSidecar<P>) -> Self {
        Self::Fulu(sidecar)
    }
}

impl<P: Preset> From<gloas::DataColumnSidecar<P>> for DataColumnSidecar<P> {
    fn from(sidecar: gloas::DataColumnSidecar<P>) -> Self {
        Self::Gloas(sidecar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Minimal;

    #[test]
    fn each_format_reads_its_own_slot_and_root() {
        // Fixture state: a Fulu column of a block at slot 9, and a Gloas column naming root 0x07.
        let mut fulu = fulu::DataColumnSidecar::<Minimal> {
            index: ColumnIndex(3),
            ..Default::default()
        };
        fulu.signed_block_header.message.slot = Slot(9);
        let gloas = gloas::DataColumnSidecar::<Minimal> {
            index: ColumnIndex(4),
            slot: Slot(10),
            beacon_block_root: Root([7; 32]),
            ..Default::default()
        };

        let fulu_column = DataColumnSidecar::from(fulu.clone());
        assert_eq!(fulu_column.slot(), Slot(9));
        assert_eq!(fulu_column.index(), ColumnIndex(3));
        assert_eq!(
            fulu_column.block_root(),
            fulu.signed_block_header.message.hash_tree_root()
        );
        let gloas_column = DataColumnSidecar::from(gloas);
        assert_eq!(gloas_column.slot(), Slot(10));
        assert_eq!(gloas_column.block_root(), Root([7; 32]));
    }

    #[test]
    fn decoding_follows_the_fork() {
        let gloas = DataColumnSidecar::<Minimal>::Gloas(gloas::DataColumnSidecar::default());
        let fulu = DataColumnSidecar::<Minimal>::Fulu(fulu::DataColumnSidecar::default());

        assert_eq!(
            DataColumnSidecar::decode(&gloas.encode(), ForkName::Gloas),
            Ok(gloas)
        );
        assert_eq!(
            DataColumnSidecar::decode(&fulu.encode(), ForkName::Fulu),
            Ok(fulu)
        );
    }
}
