//! Hstar's execution payload envelopes, checked by Gloas's rule.

use axiom_ssz::Ssz;
use axiom_types::{
    Domain, Preset, Root,
    gloas::VersionedHashes,
    hstar::{BeaconState, NewPayloadRequest, SignedExecutionPayloadEnvelope},
    phase0::SigningData,
};

use crate::gloas::{EnvelopeParts, RevealedPayload};

impl<P: Preset> RevealedPayload for SignedExecutionPayloadEnvelope<P> {
    type State = BeaconState<P>;
    type Request = NewPayloadRequest<P>;

    fn parts(&self) -> EnvelopeParts<'_, P> {
        let envelope = &self.message;
        EnvelopeParts {
            payload: &envelope.payload,
            requests_root: envelope.execution_requests.hash_tree_root(),
            builder_index: envelope.builder_index,
            beacon_block_root: envelope.beacon_block_root,
            parent_beacon_block_root: envelope.parent_beacon_block_root,
            signature: &self.signature,
        }
    }

    fn signing_root(&self, domain: Domain) -> Root {
        SigningData::signing_root(&self.message, domain)
    }

    fn new_payload_request(&self, versioned_hashes: VersionedHashes<P>) -> NewPayloadRequest<P> {
        let envelope = &self.message;
        NewPayloadRequest {
            execution_payload: envelope.payload.clone(),
            versioned_hashes,
            parent_beacon_block_root: envelope.parent_beacon_block_root,
            execution_requests: envelope.execution_requests.clone(),
        }
    }
}
