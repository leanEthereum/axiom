//! The parts of a received handshake its checks need.

use axiom_crypto::secp256k1::PublicKey;

use crate::{enr::Enr, node_id::NodeId, session::IdSignature};

/// A handshake's authdata, unpacked for verification.
#[derive(Debug)]
pub(crate) struct ReceivedHandshake {
    /// The initiator's id.
    pub(crate) src_id: NodeId,
    /// The initiator's identity proof.
    pub(crate) id_signature: IdSignature,
    /// The initiator's ephemeral key.
    pub(crate) ephemeral_key: PublicKey,
    /// The initiator's record, when sent.
    pub(crate) record: Option<Enr>,
}
