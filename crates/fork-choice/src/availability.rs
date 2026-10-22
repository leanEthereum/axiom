//! The data availability verdict a block arrives with.

/// Whether a block's blobs were shown to be available.
///
/// The check samples data column sidecars and verifies their proofs.
/// It needs the network and KZG, so the caller performs it and passes the verdict in.
///
/// See `is_data_available` in the Fulu fork choice spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataAvailability {
    /// Every sampled column arrived and verified.
    Available,
    /// Some sampled column is missing or invalid.
    Unavailable,
}
