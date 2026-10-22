//! The random values that make every packet and every challenge unique.

use std::array;

use axiom_crypto::aes::Aes128Ctr;

use crate::NodeId;

/// The 96-bit nonce of a message packet, also its AES-GCM nonce.
///
/// A WHOAREYOU packet carries the nonce of the packet it answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nonce(pub [u8; 12]);

/// The 128-bit initial counter that masks a packet header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MaskingIv(pub [u8; 16]);

impl MaskingIv {
    /// The masking cipher: AES-128-CTR keyed by the first half of the destination id.
    ///
    /// Only the destination can unmask, so packets look random to observers.
    #[must_use]
    pub fn cipher(&self, dest: &NodeId) -> Aes128Ctr {
        // The key is the first 16 of the 32 id bytes.
        let key: [u8; 16] = array::from_fn(|i| dest.0[i]);
        Aes128Ctr::new(&key, &self.0)
    }
}

/// The 128-bit random value a WHOAREYOU challenge asks the peer to sign over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IdNonce(pub [u8; 16]);
