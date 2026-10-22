//! The secret key: the PRF key, the top tree, and a window of two prepared bottom trees.
//!
//! # Overview
//!
//! The key signs any epoch of its two bottom trees, the prepared window [a, a + 2c).
//! Once signing has moved into the second tree, the window slides one tree right:
//!
//! ```text
//! before : [left = tree i | right = tree i + 1]
//! after  : [left = tree i + 1 | right = tree i + 2]
//! ```
//!
//! Building tree i + 2 is the expensive step, and needs only the PRF key.
//! So it runs as a detached preparation, and the key installs the result in a cheap swap.
//! Signing the first epoch of the right tree leaves a whole tree's duration to finish it.

use std::ops::Range;

use crate::{
    codec::{OFFSET_BYTES, Reader, Writer},
    encoding::MESSAGE_LEN,
    error::{DecodeError, PrepareError, SignError},
    field::KoalaBear,
    keys::{LeafEpoch, PublicKey, Signature},
    merkle::Subtree,
    one_time::{BottomTree, OneTimeKeys, Preparation},
    prf::{PRF_KEY_LEN, PrfKey},
    scheme::{MAX_ENCODING_ATTEMPTS, Scheme},
    words::{PARAMETER_LEN, PublicParameter},
};

/// Bytes of the fixed part of an encoded secret key.
///
/// ```text
/// PRF key 32, parameter 20, activation start 8, activation length 8,
/// top offset 4, left index 8, left offset 4, right offset 4
/// ```
const FIXED_LEN: usize =
    PRF_KEY_LEN + PARAMETER_LEN * 4 + 8 + 8 + OFFSET_BYTES + 8 + 2 * OFFSET_BYTES;

/// A secret key.
///
/// # Invariants
///
/// The activation is whole bottom trees, at least two, inside the lifetime.
/// The left and right trees are consecutive and inside the activation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey {
    /// The derivation of every one-time key.
    keys: OneTimeKeys,
    /// The bottom trees the key spans.
    trees: Range<u64>,
    /// The levels above the bottom trees.
    top: Subtree,
    /// The first tree of the prepared window.
    left: Subtree,
    /// The second tree of the prepared window.
    right: Subtree,
}

impl SecretKey {
    /// A key from its parts.
    pub(crate) fn new(
        keys: OneTimeKeys,
        trees: Range<u64>,
        top: Subtree,
        left: BottomTree,
        right: BottomTree,
    ) -> Self {
        Self {
            keys,
            trees,
            top,
            left: left.0,
            right: right.0,
        }
    }

    /// The instantiation.
    #[must_use]
    pub const fn scheme(&self) -> &Scheme {
        self.keys.scheme()
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            root: self.top.root(),
            parameter: *self.keys.hash().parameter(),
        }
    }

    /// The epochs the key may ever sign in.
    #[must_use]
    pub const fn activation(&self) -> Range<u64> {
        let c = self.scheme().leaves_per_bottom_tree();
        self.trees.start * c..self.trees.end * c
    }

    /// The epochs the key can sign in now: its two prepared bottom trees.
    #[must_use]
    pub fn prepared(&self) -> Range<u64> {
        let c = self.scheme().leaves_per_bottom_tree();
        let start = self.left.index() * c;
        start..start + 2 * c
    }

    /// The work of building the tree after the window, or none when the window ends the activation.
    #[must_use]
    pub fn preparation(&self) -> Option<Preparation> {
        let next = self.left.index() + 2;
        (next < self.trees.end).then(|| Preparation::new(self.keys.clone(), next))
    }

    /// Slides the window one tree right, onto a freshly built tree.
    ///
    /// # Errors
    ///
    /// Fails when the window already ends the activation, or the tree is not the next one.
    pub fn install(&mut self, tree: BottomTree) -> Result<(), PrepareError> {
        let expected = self.left.index() + 2;
        if expected >= self.trees.end {
            return Err(PrepareError::Exhausted {
                end: self.activation().end,
            });
        }
        if tree.index() != expected {
            return Err(PrepareError::WrongTree {
                expected,
                actual: tree.index(),
            });
        }
        self.left = std::mem::replace(&mut self.right, tree.0);
        Ok(())
    }

    /// Prepares and installs the next tree on this thread; false when the window cannot move.
    pub fn advance(&mut self) -> bool {
        let Some(preparation) = self.preparation() else {
            return false;
        };
        // Invariant: the preparation builds exactly the tree install expects.
        self.install(preparation.build())
            .expect("a preparation builds the next tree");
        true
    }

    /// Signs a message at an epoch.
    ///
    /// The caller must never sign two messages at one epoch: that reveals enough to forge.
    /// Signing one message twice is harmless, since the signature is deterministic.
    ///
    /// # Errors
    ///
    /// Fails outside the activation, outside the prepared window, or when no codeword is found.
    pub fn sign(
        &self,
        epoch: LeafEpoch,
        message: &[u8; MESSAGE_LEN],
    ) -> Result<Signature, SignError> {
        let at = u64::from(epoch.0);
        let (activation, prepared) = (self.activation(), self.prepared());
        if !activation.contains(&at) {
            return Err(SignError::Inactive {
                epoch: at,
                start: activation.start,
                end: activation.end,
            });
        }
        if !prepared.contains(&at) {
            return Err(SignError::NotPrepared {
                epoch: at,
                start: prepared.start,
                end: prepared.end,
            });
        }

        // The path: siblings in the bottom tree, then in the top tree above it.
        let c = self.scheme().leaves_per_bottom_tree();
        let bottom = if at < prepared.start + c {
            &self.left
        } else {
            &self.right
        };
        let mut path = Vec::with_capacity(self.scheme().log_lifetime as usize);
        bottom.path(at, &mut path);
        self.top.path(bottom.index(), &mut path);

        let (randomness, codeword) = self
            .scheme()
            .find_codeword(&self.keys, epoch.0, message)
            .ok_or(SignError::EncodingExhausted {
                attempts: MAX_ENCODING_ATTEMPTS,
            })?;

        // Chain i reveals its value at position x_i: x_i steps from the secret start.
        let chain_values = codeword
            .iter()
            .enumerate()
            .map(|(chain, &position)| {
                let start = self.keys.chain_start(epoch.0, chain);
                self.keys
                    .hash()
                    .walk(epoch.0, chain as u8, 0, usize::from(position), &start)
            })
            .collect();
        Ok(Signature {
            path,
            randomness,
            chain_values,
        })
    }

    /// The encoding: the PRF key, the parameter, the activation, then the three trees.
    ///
    /// The bytes hold the PRF key: whoever reads them can sign.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let h = self.scheme().hash_len;
        let activation = self.activation();
        let top_offset = FIXED_LEN;
        let left_offset = top_offset + self.top.encoded_len(h);
        let right_offset = left_offset + self.left.encoded_len(h);

        let mut writer = Writer::with_capacity(right_offset + self.right.encoded_len(h));
        writer.bytes(self.keys.prf().as_bytes());
        writer.elements(&self.keys.hash().parameter().0);
        writer.u64(activation.start);
        writer.u64(activation.end - activation.start);
        writer.offset(top_offset);
        writer.u64(self.left.index());
        writer.offset(left_offset);
        writer.offset(right_offset);
        self.top.encode(&mut writer, h);
        self.left.encode(&mut writer, h);
        self.right.encode(&mut writer, h);
        writer.finish()
    }

    /// Decodes a key and checks every tree has the shape its activation implies.
    pub(crate) fn decode(scheme: Scheme, bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let prf = PrfKey::from_bytes(reader.array()?);
        let mut parameter = [KoalaBear::ZERO; PARAMETER_LEN];
        for element in &mut parameter {
            *element = reader.element()?;
        }
        let start = reader.u64()?;
        let len = reader.u64()?;
        reader.offset(FIXED_LEN)?;
        let left_index = reader.u64()?;
        let left_offset = reader.u32()? as usize;
        let right_offset = reader.u32()? as usize;

        // The activation must be whole bottom trees, at least two, inside the lifetime.
        let c = scheme.leaves_per_bottom_tree();
        let trees = start / c..start.saturating_add(len) / c;
        let whole = start % c == 0 && len % c == 0 && len >= 2 * c;
        if !whole || start.saturating_add(len) > scheme.lifetime() {
            return Err(DecodeError::Activation { start, len });
        }
        if left_index < trees.start || left_index + 2 > trees.end {
            return Err(DecodeError::Activation { start, len });
        }
        if left_offset < FIXED_LEN || left_offset > right_offset || right_offset > bytes.len() {
            return Err(DecodeError::Offset {
                expected: left_offset.max(FIXED_LEN),
                actual: right_offset,
            });
        }

        let h = scheme.hash_len;
        let roots = (trees.end - trees.start) as usize;
        let top = Subtree::decode(
            &bytes[FIXED_LEN..left_offset],
            h,
            &Subtree::shape_of_top(scheme.log_lifetime, trees.start, roots),
        )?;
        let left = Subtree::decode(
            &bytes[left_offset..right_offset],
            h,
            &Subtree::shape_of_bottom(scheme.log_lifetime, left_index),
        )?;
        let right = Subtree::decode(
            &bytes[right_offset..],
            h,
            &Subtree::shape_of_bottom(scheme.log_lifetime, left_index + 1),
        )?;
        let parameter = PublicParameter(parameter);
        Ok(Self {
            keys: OneTimeKeys::new(scheme, prf, scheme.tweak_hash(parameter)),
            trees,
            top,
            left,
            right,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use proptest::prelude::*;

    use super::*;
    use crate::{
        entropy::SeedStream,
        instantiation::{HypercubeLifetime, Instantiation},
    };

    /// The test lifetime: 2^8 epochs in 16 bottom trees of 16, 4 chains of length 8.
    fn scheme() -> Scheme {
        Instantiation::Hypercube(HypercubeLifetime::TestOnly8).scheme()
    }

    /// One key over epochs 16 to 63, bottom trees 1 to 3, generated once.
    fn key() -> &'static (PublicKey, SecretKey) {
        static KEY: OnceLock<(PublicKey, SecretKey)> = OnceLock::new();
        KEY.get_or_init(|| {
            scheme()
                .generate(&mut SeedStream::new(b"properties"), 16..64)
                .unwrap()
        })
    }

    #[test]
    fn signing_outside_the_window_is_refused() {
        // Fixture state: activation [16, 64), prepared window [16, 48).
        let (_, secret) = key();
        assert_eq!(
            secret.sign(LeafEpoch(15), &[0; 32]),
            Err(SignError::Inactive {
                epoch: 15,
                start: 16,
                end: 64
            })
        );
        assert_eq!(
            secret.sign(LeafEpoch(48), &[0; 32]),
            Err(SignError::NotPrepared {
                epoch: 48,
                start: 16,
                end: 48
            })
        );
    }

    #[test]
    fn the_window_slides_once_then_stops() {
        // Fixture state: trees 1 to 3, so one slide reaches the last window [32, 64).
        let (public, mut secret) = key().clone();
        let preparation = secret.preparation().unwrap();
        assert_eq!(preparation.index(), 3);

        // A tree other than the next one is refused, then the right one is installed.
        let stale = Preparation::new(secret.keys.clone(), 2).build();
        assert_eq!(
            secret.install(stale),
            Err(PrepareError::WrongTree {
                expected: 3,
                actual: 2
            })
        );
        let tree = preparation.build();
        secret.install(tree.clone()).unwrap();
        assert_eq!(secret.prepared(), 32..64);

        // Epoch 63 now signs, and the key cannot slide further.
        let signature = secret.sign(LeafEpoch(63), &[7; 32]).unwrap();
        assert_eq!(
            scheme().verify(&public, LeafEpoch(63), &[7; 32], &signature),
            Ok(())
        );
        assert!(secret.preparation().is_none());
        assert!(!secret.advance());
        assert_eq!(
            secret.install(tree),
            Err(PrepareError::Exhausted { end: 64 })
        );
    }

    #[test]
    fn secret_key_decoding_checks_the_activation() {
        let (_, secret) = key();
        let bytes = secret.to_bytes();

        // Activation length 47 is not whole bottom trees of 16.
        let mut broken = bytes.clone();
        broken[60..68].copy_from_slice(&47_u64.to_le_bytes());
        assert_eq!(
            scheme().decode_secret_key(&broken),
            Err(DecodeError::Activation { start: 16, len: 47 })
        );

        // A truncated key fails inside the last tree.
        assert!(
            scheme()
                .decode_secret_key(&bytes[..bytes.len() - 1])
                .is_err()
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn signatures_verify_only_at_their_epoch_and_message(
            epoch in 16_u32..48,
            other_epoch in 0_u32..256,
            message: [u8; 32],
            other_message: [u8; 32],
        ) {
            let (public, secret) = key();
            let scheme = scheme();
            let signature = secret.sign(LeafEpoch(epoch), &message).unwrap();

            // Round trip through bytes, then verification.
            let decoded = scheme.decode_signature(&signature.to_bytes()).unwrap();
            prop_assert_eq!(&decoded, &signature);
            prop_assert_eq!(scheme.verify(public, LeafEpoch(epoch), &message, &signature), Ok(()));

            // Never under another epoch, nor for another message.
            if other_epoch != epoch {
                prop_assert!(scheme.verify(public, LeafEpoch(other_epoch), &message, &signature).is_err());
            }
            if other_message != message {
                prop_assert!(scheme.verify(public, LeafEpoch(epoch), &other_message, &signature).is_err());
            }
        }

        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
            let scheme = scheme();
            let _ = scheme.decode_signature(&bytes);
            let _ = scheme.decode_public_key(&bytes);
            let _ = scheme.decode_secret_key(&bytes);
        }
    }
}
