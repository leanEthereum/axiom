//! Request bodies of the req/resp methods that fetch blocks and columns.

use axiom_ssz::{Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};
use axiom_types::{ColumnIndex, Preset, Root, Slot, fulu::DataColumnsByRootIdentifier};

/// Most blocks one request may ask for: MAX_REQUEST_BLOCKS_DENEB.
///
/// The spec sets it in the network configuration, yet uses it as a list bound.
/// It is 128 on every network, so it is fixed in the type here.
pub(crate) type MaxRequestBlocks = Const<128>;

/// Block roots, for blocks by root.
pub(crate) type BlocksByRootRequest = List<Root, MaxRequestBlocks>;

/// Blocks and the columns wanted of each, for columns by root.
pub(crate) type ColumnsByRootRequest<P> = List<DataColumnsByRootIdentifier<P>, MaxRequestBlocks>;

/// Blocks in a slot range.
///
/// See `BeaconBlocksByRange v2` in the Altair p2p spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BlocksByRangeRequest {
    /// First slot of the range.
    pub start_slot: Slot,
    /// Slots in the range.
    pub count: u64,
    /// Deprecated, always one.
    pub step: u64,
}

impl Container for BlocksByRangeRequest {
    const FIELDS: &'static [Option<usize>] = &[Slot::FIXED_SIZE, u64::FIXED_SIZE, u64::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.start_slot);
        visitor.field(&self.count);
        visitor.field(&self.step);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            start_slot: fields.field()?,
            count: fields.field()?,
            step: fields.field()?,
        })
    }
}

/// Blocks along the ancestry of a root, newest first.
///
/// See `BeaconBlocksByHead v1` in the Fulu p2p spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BlocksByHeadRequest {
    /// The newest block wanted.
    pub beacon_root: Root,
    /// Blocks wanted, walking back from it.
    pub count: u64,
}

impl Container for BlocksByHeadRequest {
    const FIELDS: &'static [Option<usize>] = &[Root::FIXED_SIZE, u64::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.beacon_root);
        visitor.field(&self.count);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            beacon_root: fields.field()?,
            count: fields.field()?,
        })
    }
}

/// Some columns of every block in a slot range.
///
/// See `DataColumnSidecarsByRange v1` in the Fulu p2p spec.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ColumnsByRangeRequest<P: Preset> {
    /// First slot of the range.
    pub start_slot: Slot,
    /// Slots in the range.
    pub count: u64,
    /// Columns wanted of each block.
    pub columns: List<ColumnIndex, P::NumberOfColumns>,
}

impl<P: Preset> Container for ColumnsByRangeRequest<P> {
    const FIELDS: &'static [Option<usize>] = &[
        Slot::FIXED_SIZE,
        u64::FIXED_SIZE,
        <List<ColumnIndex, P::NumberOfColumns>>::FIXED_SIZE,
    ];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.start_slot);
        visitor.field(&self.count);
        visitor.field(&self.columns);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            start_slot: fields.field()?,
            count: fields.field()?,
            columns: fields.field()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn a_range_request_is_three_little_endian_words() {
        // Fixture state: slots 64 to 127, step one.
        //
        //     start_slot 64   count 64   step 1
        //     40 00..00       40 00..00  01 00..00
        let request = BlocksByRangeRequest {
            start_slot: Slot(64),
            count: 64,
            step: 1,
        };

        let mut expected = vec![0; 24];
        expected[0] = 64;
        expected[8] = 64;
        expected[16] = 1;
        assert_eq!(request.encode(), expected);
    }

    proptest! {
        #[test]
        fn column_range_requests_round_trip(
            start in any::<u64>(),
            count in any::<u64>(),
            columns in proptest::collection::vec(0..128_u64, 0..=128),
        ) {
            let request = ColumnsByRangeRequest::<Minimal> {
                start_slot: Slot(start),
                count,
                columns: List::try_from(columns.into_iter().map(ColumnIndex).collect::<Vec<_>>()).unwrap(),
            };

            prop_assert_eq!(ColumnsByRangeRequest::decode(&request.encode()), Ok(request));
        }
    }
}
