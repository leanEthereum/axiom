//! The boundary between consensus and the execution engine.

use axiom_types::{Preset, fulu::NewPayloadRequest};

/// The execution engine's verdict on a payload.
///
/// Execution is outside the consensus layer.
/// The node asks its engine over the engine API, then hands the verdict in here.
/// The transition itself stays a pure function.
///
/// See `verify_and_notify_new_payload` in the Electra beacon chain spec.
pub trait ExecutionEngine<P: Preset> {
    /// Whether the payload's block hash, versioned hashes, and execution are valid.
    fn verify_and_notify_new_payload(&self, request: &NewPayloadRequest<P>) -> bool;
}

/// An engine whose verdict is fixed in advance.
///
/// Spec vectors supply the verdict in their execution file.
/// A node uses it for a payload its engine already judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownVerdict(pub bool);

impl<P: Preset> ExecutionEngine<P> for KnownVerdict {
    fn verify_and_notify_new_payload(&self, _request: &NewPayloadRequest<P>) -> bool {
        self.0
    }
}
