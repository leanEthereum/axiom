//! The random values that make every packet and every challenge unique.

/// The 96-bit nonce of a message packet, also its AES-GCM nonce.
///
/// A WHOAREYOU packet carries the nonce of the packet it answers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Nonce(pub [u8; 12]);

/// The 128-bit initial counter that masks a packet header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MaskingIv(pub [u8; 16]);

/// The 128-bit random value a WHOAREYOU challenge asks the peer to sign over.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IdNonce(pub [u8; 16]);
