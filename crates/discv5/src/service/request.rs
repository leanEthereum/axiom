//! Why the service sent a request, and what has come back so far.

use super::LookupId;
use crate::{enr::Enr, message::RequestId};

/// Most NODES messages accepted for one FINDNODE.
///
/// 16 records of at most 300 bytes fit in 5 packets of 1280 bytes.
pub(crate) const MAX_NODES_MESSAGES: u64 = 5;

/// The reason behind a request, which decides where its answer goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// An application PING.
    Ping,
    /// An application FINDNODE.
    FindNode,
    /// An application TALKREQ.
    Talk,
    /// A liveness check of a table entry.
    Liveness,
    /// A fetch of a peer's newer record.
    RecordRefresh,
    /// A step of a lookup.
    Lookup(LookupId),
}

/// A request the service awaits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestState {
    /// The request id.
    pub(crate) request_id: RequestId,
    /// The reason it was sent.
    pub(crate) purpose: Purpose,
    /// Records gathered from NODES messages so far.
    pub(crate) enrs: Vec<Enr>,
    /// NODES messages received so far.
    pub(crate) responses: u64,
}

impl RequestState {
    /// A request just sent.
    pub(crate) const fn new(purpose: Purpose, request_id: RequestId) -> Self {
        Self {
            request_id,
            purpose,
            enrs: Vec::new(),
            responses: 0,
        }
    }
}
