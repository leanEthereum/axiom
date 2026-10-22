//! Bellatrix: the merge of the beacon chain with the proof-of-work chain.
//!
//! The only fork choice rule Bellatrix adds checks the first block that carries a payload.
//! See the Bellatrix fork choice spec and EIP-3675.

mod pow_chain;

pub use pow_chain::{PowChain, SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY};
