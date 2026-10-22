//! The latest execution payload header, from Bellatrix through Fulu.

use axiom_ssz::Ssz;

use crate::accessors::CoreState;

/// The header of the latest execution payload the chain accepted.
///
/// Bellatrix, Capella, and Deneb each define their own header, so the type is associated.
/// Gloas drops the header for the builder's bid, so its state does not implement this.
/// See the Bellatrix beacon chain spec.
pub trait ExecutionHeaderState: CoreState {
    /// The fork's execution payload header.
    type ExecutionPayloadHeader: Ssz + Clone;

    /// Header of the latest execution payload.
    fn latest_execution_payload_header(&self) -> &Self::ExecutionPayloadHeader;

    /// Header of the latest execution payload, for payload processing.
    fn latest_execution_payload_header_mut(&mut self) -> &mut Self::ExecutionPayloadHeader;
}
