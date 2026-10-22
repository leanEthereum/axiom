//! Request bodies of the req/resp methods that fetch blocks, their data, and light client data.

use axiom_ssz::{Const, Container, DecodeError, FieldDecoder, FieldVisitor, List, Ssz};
use axiom_types::{
    ColumnIndex, Preset, Root, Slot, deneb::BlobIdentifier, fulu::DataColumnsByRootIdentifier,
};

/// Most blocks one request may ask for: MAX_REQUEST_BLOCKS_DENEB.
///
/// The spec sets it in the network configuration, yet uses it as a list bound.
/// It is 128 on every network, so it is fixed in the type here.
pub(crate) type MaxRequestBlocks = Const<128>;

/// Block roots, for blocks by root.
pub(crate) type BlocksByRootRequest = List<Root, MaxRequestBlocks>;

/// Blocks and the columns wanted of each, for columns by root.
pub(crate) type ColumnsByRootRequest<P> = List<DataColumnsByRootIdentifier<P>, MaxRequestBlocks>;

/// Most blob sidecars one request may ask for: MAX_REQUEST_BLOB_SIDECARS_ELECTRA.
///
/// Deneb's bound is lower; the larger one decodes requests of both forks.
pub(crate) type MaxRequestBlobSidecars = Const<1152>;

/// Blobs by block root and index, for blobs by root.
pub(crate) type BlobsByRootRequest = List<BlobIdentifier, MaxRequestBlobSidecars>;

/// Most payload envelopes one request may ask for: MAX_REQUEST_PAYLOADS.
///
/// See the Gloas p2p spec.
pub(crate) type MaxRequestPayloads = Const<128>;

/// Block roots whose envelopes are wanted, for envelopes by root.
pub(crate) type EnvelopesByRootRequest = List<Root, MaxRequestPayloads>;

/// Items of every block in a slot range, for blobs and envelopes by range.
///
/// See `BlobSidecarsByRange v1` in the Deneb p2p spec and its Gloas envelope twin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SlotRangeRequest {
    /// First slot of the range.
    pub start_slot: Slot,
    /// Slots in the range.
    pub count: u64,
}

impl Container for SlotRangeRequest {
    const FIELDS: &'static [Option<usize>] = &[Slot::FIXED_SIZE, u64::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.start_slot);
        visitor.field(&self.count);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            start_slot: fields.field()?,
            count: fields.field()?,
        })
    }
}

/// Light client updates of a range of sync committee periods.
///
/// See `LightClientUpdatesByRange` in the Altair light client p2p spec.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UpdatesByRangeRequest {
    /// First period of the range.
    pub start_period: u64,
    /// Periods in the range.
    pub count: u64,
}

impl Container for UpdatesByRangeRequest {
    const FIELDS: &'static [Option<usize>] = &[u64::FIXED_SIZE, u64::FIXED_SIZE];

    fn visit_fields<V: FieldVisitor>(&self, visitor: &mut V) {
        visitor.field(&self.start_period);
        visitor.field(&self.count);
    }

    fn decode_fields(fields: &mut FieldDecoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            start_period: fields.field()?,
            count: fields.field()?,
        })
    }
}

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
