//! Why an operation of the scheme failed.

use thiserror::Error;

/// Why bytes are not a valid key or signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// The input ends before a field does.
    #[error("needed {needed} more bytes, {available} left")]
    Truncated {
        /// Bytes the field needs.
        needed: usize,
        /// Bytes left in the input.
        available: usize,
    },
    /// A field element's word is not below p, so it would have a second encoding.
    #[error("field element word {value} is not below the field order")]
    NonCanonical {
        /// The word read.
        value: u32,
    },
    /// An SSZ offset does not point where the variable part starts.
    #[error("offset {actual}, expected {expected}")]
    Offset {
        /// The only valid offset.
        expected: usize,
        /// The offset read.
        actual: usize,
    },
    /// A list's bytes do not split into whole items.
    #[error("list of {len} bytes is not a multiple of its {item}-byte items")]
    PartialItem {
        /// Bytes of the list.
        len: usize,
        /// Bytes per item.
        item: usize,
    },
    /// Bytes remain after the last field.
    #[error("{bytes} trailing bytes")]
    Trailing {
        /// Bytes left over.
        bytes: usize,
    },
    /// A list does not hold the number of items the instantiation fixes.
    #[error("{list} holds {actual} items, the instantiation needs {expected}")]
    Count {
        /// Which list.
        list: &'static str,
        /// Items the instantiation needs.
        expected: usize,
        /// Items found.
        actual: usize,
    },
    /// A secret key's activation interval is not made of whole bottom trees inside the lifetime.
    #[error("activation of {len} epochs from {start} does not fit whole bottom trees")]
    Activation {
        /// First active epoch.
        start: u64,
        /// Number of active epochs.
        len: u64,
    },
    /// A stored tree layer does not have the shape its position implies.
    #[error("tree layer {layer} starts at {start} with {len} nodes, which its level forbids")]
    Layer {
        /// The layer's index from the lowest stored level.
        layer: usize,
        /// The layer's first node index.
        start: u64,
        /// The layer's node count.
        len: usize,
    },
}

/// Why a message could not be encoded into a codeword.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum EncodingError {
    /// A hash element fell in the rejected range of the aborting hypercube hash.
    #[error("hash element {index} fell in the rejected range")]
    Aborted {
        /// The element's position in the hash output.
        index: usize,
    },
    /// The codeword's chunks do not sum to the target.
    #[error("codeword sums to {actual}, the target is {expected}")]
    SumMismatch {
        /// The target sum.
        expected: usize,
        /// The codeword's sum.
        actual: usize,
    },
}

/// Why a key pair could not be generated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum KeyGenError {
    /// The key would be active for no epoch.
    #[error("a key must be active for at least one epoch")]
    Empty,
    /// The requested epochs run past the lifetime.
    #[error("{count} epochs from {start} run past the lifetime of {lifetime}")]
    BeyondLifetime {
        /// First requested epoch.
        start: u64,
        /// Number of requested epochs.
        count: u64,
        /// Epochs in the lifetime.
        lifetime: u64,
    },
}

/// Why a secret key refused to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum SignError {
    /// The key is not active at the epoch.
    #[error("epoch {epoch} is outside the key's activation [{start}, {end})")]
    Inactive {
        /// The requested epoch.
        epoch: u64,
        /// First active epoch.
        start: u64,
        /// End of activation, exclusive.
        end: u64,
    },
    /// The key's prepared window does not cover the epoch yet.
    #[error("epoch {epoch} is outside the prepared window [{start}, {end})")]
    NotPrepared {
        /// The requested epoch.
        epoch: u64,
        /// First prepared epoch.
        start: u64,
        /// End of the window, exclusive.
        end: u64,
    },
    /// No randomness within the try budget encoded the message.
    #[error("no codeword after {attempts} attempts")]
    EncodingExhausted {
        /// Attempts made.
        attempts: u64,
    },
}

/// Why a signature does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// The epoch lies past the lifetime.
    #[error("epoch {epoch} is past the lifetime of {lifetime}")]
    BeyondLifetime {
        /// The claimed epoch.
        epoch: u64,
        /// Epochs in the lifetime.
        lifetime: u64,
    },
    /// The signature or key has the shape of another instantiation.
    #[error("{part} has {actual} elements, the instantiation needs {expected}")]
    Shape {
        /// Which part.
        part: &'static str,
        /// Elements the instantiation needs.
        expected: usize,
        /// Elements found.
        actual: usize,
    },
    /// The randomness does not encode the message under the key and epoch.
    #[error("encoding failed: {0}")]
    Encoding(#[from] EncodingError),
    /// The recomputed root differs from the public key's.
    #[error("the authentication path does not lead to the public root")]
    RootMismatch,
}

/// Why the next bottom tree cannot be installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrepareError {
    /// The prepared window already reaches the end of activation.
    #[error("the prepared window already ends at the activation end {end}")]
    Exhausted {
        /// End of activation, exclusive.
        end: u64,
    },
    /// The tree is not the one after the prepared window.
    #[error("bottom tree {actual} offered, the window needs {expected}")]
    WrongTree {
        /// The bottom tree the window needs next.
        expected: u64,
        /// The bottom tree offered.
        actual: u64,
    },
}
