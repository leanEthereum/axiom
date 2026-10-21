//! Lengths carried in the type system.

use std::{fmt::Debug, hash::Hash};

/// A length known at compile time.
///
/// A vector's length and a list's limit are part of its SSZ type.
/// The limit fixes the depth of the hash tree, so two lists with different limits hash differently.
///
/// Carrying lengths as types lets a preset choose them.
/// A mainnet state and a minimal state are then distinct types, checked by the compiler.
pub trait Length: Copy + Debug + Default + Eq + Hash + Send + Sync + 'static {
    /// The length itself.
    const LEN: usize;
}

/// A length written as a literal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Const<const N: usize>;

impl<const N: usize> Length for Const<N> {
    const LEN: usize = N;
}
