//! The boundary between consensus and the execution engine.

use axiom_types::{Preset, bellatrix, capella, deneb, electra, gloas};

/// The execution engine's verdict on one fork's new payload request.
///
/// Execution is outside the consensus layer.
/// The node asks its engine over the engine API, then hands the verdict in here.
/// The transition itself stays a pure function.
///
/// See `verify_and_notify_new_payload` in the Bellatrix through Gloas beacon chain specs.
pub trait ExecutionEngine<R> {
    /// Whether the payload's block hash, versioned hashes, and execution are valid.
    fn verify_and_notify_new_payload(&self, request: &R) -> bool;
}

/// An engine that judges the payload requests of every fork.
///
/// Each fork that changed the request type adds one bound here.
pub trait PayloadEngine<P: Preset>:
    ExecutionEngine<bellatrix::NewPayloadRequest<P>>
    + ExecutionEngine<capella::NewPayloadRequest<P>>
    + ExecutionEngine<deneb::NewPayloadRequest<P>>
    + ExecutionEngine<electra::NewPayloadRequest<P>>
    + ExecutionEngine<gloas::NewPayloadRequest<P>>
{
}

impl<P: Preset, E> PayloadEngine<P> for E where
    E: ExecutionEngine<bellatrix::NewPayloadRequest<P>>
        + ExecutionEngine<capella::NewPayloadRequest<P>>
        + ExecutionEngine<deneb::NewPayloadRequest<P>>
        + ExecutionEngine<electra::NewPayloadRequest<P>>
        + ExecutionEngine<gloas::NewPayloadRequest<P>>
{
}

/// An engine whose verdict is fixed in advance.
///
/// Spec vectors supply the verdict in their execution file.
/// A node uses it for a payload its engine already judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownVerdict(pub bool);

impl<R> ExecutionEngine<R> for KnownVerdict {
    fn verify_and_notify_new_payload(&self, _request: &R) -> bool {
        self.0
    }
}
