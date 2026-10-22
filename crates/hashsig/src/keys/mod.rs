//! Public keys, secret keys, and signatures.

mod public_key;
mod secret_key;
mod signature;

pub use public_key::PublicKey;
pub use secret_key::SecretKey;
pub use signature::Signature;

/// An epoch of a synchronized key: the index of the one-time key that signs in it.
///
/// A key signs at most once per epoch, and verifiers learn the epoch from the message's time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeafEpoch(pub u32);
