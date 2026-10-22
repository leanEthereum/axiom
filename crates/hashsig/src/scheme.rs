//! An instantiation's parameters, with key generation and verification.

use std::ops::Range;

pub(crate) use crate::encoding::MessageHash;
use crate::{
    codec::{ELEMENT_BYTES, OFFSET_BYTES, Reader},
    encoding::{MESSAGE_LEN, Shape},
    entropy::Entropy,
    error::{DecodeError, EncodingError, KeyGenError, VerifyError},
    field::KoalaBear,
    keys::{LeafEpoch, PublicKey, SecretKey, Signature},
    merkle::{Subtree, root_from_path},
    one_time::OneTimeKeys,
    prf::PrfKey,
    tweak_hash::{TWEAK_LEN, TweakHash},
    words::{Digest, PARAMETER_LEN, PublicParameter, Randomness, Words},
};

/// The parameters of one instantiation of generalized XMSS.
///
/// # Invariants
///
/// Every instance comes from the instantiation table, which checks its parameters at compile time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Scheme {
    /// Base-2 logarithm h of the lifetime: keys sign in epochs [0, 2^h).
    pub(crate) log_lifetime: u32,
    /// Number of chains v, one per codeword chunk.
    pub(crate) dimension: usize,
    /// Chain length w, the codeword base.
    pub(crate) base: usize,
    /// The codeword sum T.
    pub(crate) target_sum: usize,
    /// Field elements per digest.
    pub(crate) hash_len: usize,
    /// Field elements of encoding randomness.
    pub(crate) rand_len: usize,
    /// How the message hash becomes chunks.
    pub(crate) message_hash: MessageHash,
}

/// Encoding attempts before signing gives up.
///
/// The worst instantiation, eight-bit chunks at the expected sum, hits with probability about 1/150.
/// So a failure after this many tries has probability below 2^-900.
pub(crate) const MAX_ENCODING_ATTEMPTS: u64 = 100_000;

impl Scheme {
    /// Checks the parameters, at compile time when called in a constant.
    ///
    /// # Panics
    ///
    /// Panics on parameters the hash layouts or the tweak encoding cannot hold.
    pub(crate) const fn checked(self) -> Self {
        let h = self.hash_len;
        // Hash layouts: a chain step fills at most 16 words, a node and the message hash 24.
        assert!(h >= 1 && h <= 8 && self.rand_len >= 1 && self.rand_len <= 7);
        assert!(h + PARAMETER_LEN + TWEAK_LEN <= 16);
        assert!(PARAMETER_LEN + TWEAK_LEN + 2 * h <= 24);
        assert!(9 + PARAMETER_LEN + TWEAK_LEN + self.rand_len <= 24);
        // Tweaks hold the chain index and the chain position in one byte each.
        assert!(self.dimension >= 1 && self.dimension <= 256);
        assert!(self.base >= 2 && self.base <= 256);
        // A codeword of v chunks below w sums to at most v * (w - 1).
        assert!(self.target_sum <= self.dimension * (self.base - 1));
        // The tree splits evenly at half depth, and epochs fit 32 bits.
        assert!(
            self.log_lifetime >= 2
                && self.log_lifetime <= 32
                && self.log_lifetime.is_multiple_of(2)
        );
        match self.message_hash {
            MessageHash::BaseP { output_len } => {
                // Power-of-two bases make digits bit fields.
                // The digits cover the integer: 30 * l bits below p^l fit in v * log2(w) bits.
                assert!(self.base.is_power_of_two());
                assert!(30 * output_len <= self.dimension * self.base.trailing_zeros() as usize);
                assert!(output_len <= 5);
            }
            MessageHash::Aborting {
                output_len,
                digits_per_element,
                quotient,
            } => {
                // Enough elements for v digits, and Q * w^z inside the field.
                assert!(output_len * digits_per_element >= self.dimension);
                assert!(output_len <= 24);
                let mut bound = quotient as u64;
                let mut digit = 0;
                while digit < digits_per_element {
                    bound *= self.base as u64;
                    digit += 1;
                }
                assert!(bound <= KoalaBear::ORDER as u64);
            }
        }
        self
    }

    /// Epochs in the lifetime, 2^h.
    #[must_use]
    pub const fn lifetime(&self) -> u64 {
        1 << self.log_lifetime
    }

    /// Base-2 logarithm h of the lifetime.
    #[must_use]
    pub const fn log_lifetime(&self) -> u32 {
        self.log_lifetime
    }

    /// Number of hash chains v.
    #[must_use]
    pub const fn dimension(&self) -> usize {
        self.dimension
    }

    /// Chain length w.
    #[must_use]
    pub const fn base(&self) -> usize {
        self.base
    }

    /// The codeword sum T.
    #[must_use]
    pub const fn target_sum(&self) -> usize {
        self.target_sum
    }

    /// Epochs per bottom tree, 2^(h/2).
    #[must_use]
    pub const fn leaves_per_bottom_tree(&self) -> u64 {
        1 << (self.log_lifetime / 2)
    }

    /// Bytes of an encoded public key: the root, then the parameter.
    #[must_use]
    pub const fn public_key_len(&self) -> usize {
        (self.hash_len + PARAMETER_LEN) * ELEMENT_BYTES
    }

    /// Bytes of an encoded signature.
    ///
    /// ```text
    /// offset, randomness, offset, (offset, h siblings), v chain values
    /// ```
    #[must_use]
    pub const fn signature_len(&self) -> usize {
        let digest = self.hash_len * ELEMENT_BYTES;
        3 * OFFSET_BYTES
            + self.rand_len * ELEMENT_BYTES
            + self.log_lifetime as usize * digest
            + self.dimension * digest
    }

    /// The codeword shape.
    pub(crate) const fn shape(&self) -> Shape {
        Shape {
            dimension: self.dimension,
            base: self.base,
            target_sum: self.target_sum,
        }
    }

    /// The codeword of a message, or why the randomness does not encode it.
    pub(crate) fn encode(
        &self,
        parameter: &PublicParameter,
        epoch: u32,
        randomness: &Randomness,
        message: &[u8; MESSAGE_LEN],
    ) -> Result<Vec<u8>, EncodingError> {
        let chunks =
            self.message_hash
                .chunks(self.shape(), parameter, epoch, randomness, message)?;
        self.shape().filter(chunks)
    }

    /// The tweakable hash of a key pair.
    pub(crate) fn tweak_hash(&self, parameter: PublicParameter) -> TweakHash {
        TweakHash::new(parameter, self.hash_len, self.dimension)
    }

    /// The randomness of an encoding attempt, and its codeword when it hits.
    pub(crate) fn find_codeword(
        &self,
        keys: &OneTimeKeys,
        epoch: u32,
        message: &[u8; MESSAGE_LEN],
    ) -> Option<(Randomness, Vec<u8>)> {
        // The randomness derives from the message, so signing it again finds the same codeword.
        (0..MAX_ENCODING_ATTEMPTS).find_map(|attempt| {
            let randomness = keys
                .prf()
                .randomness(epoch, message, attempt, self.rand_len);
            let codeword = self
                .encode(keys.hash().parameter(), epoch, &randomness, message)
                .ok()?;
            Some((randomness, codeword))
        })
    }

    /// Generates a key pair active over at least the given epochs.
    ///
    /// # Overview
    ///
    /// The activation widens to whole bottom trees, at least two, inside the lifetime.
    /// Every bottom tree is built once, for its root; the first two are kept for signing.
    /// The entropy supplies, in order, the parameter, the PRF key, and the top tree's padding.
    ///
    /// # Performance
    ///
    /// Key generation hashes v * (w - 1) chain steps per active epoch, the bulk of its cost.
    /// A full 2^32 lifetime is out of reach; keys activate for the epochs they will sign in.
    ///
    /// # Errors
    ///
    /// Fails for an empty activation, or one past the lifetime.
    pub fn generate(
        &self,
        entropy: &mut impl Entropy,
        activation: Range<u64>,
    ) -> Result<(PublicKey, SecretKey), KeyGenError> {
        if activation.is_empty() {
            return Err(KeyGenError::Empty);
        }
        if activation.end > self.lifetime() {
            return Err(KeyGenError::BeyondLifetime {
                start: activation.start,
                count: activation.end.saturating_sub(activation.start),
                lifetime: self.lifetime(),
            });
        }
        let trees = self.expand(activation);

        let parameter = PublicParameter::sample(entropy);
        let keys = OneTimeKeys::new(*self, PrfKey::sample(entropy), self.tweak_hash(parameter));

        // Every bottom tree's root feeds the top tree; only the first two trees stay whole.
        let left = keys.bottom_tree(trees.start);
        let right = keys.bottom_tree(trees.start + 1);
        let mut roots = vec![left.0.root(), right.0.root()];
        roots.extend((trees.start + 2..trees.end).map(|index| keys.bottom_tree(index).0.root()));
        let top = Subtree::top(keys.hash(), self.log_lifetime, trees.start, roots, || {
            Words::sample(self.hash_len, entropy)
        });

        let secret = SecretKey::new(keys, trees, top, left, right);
        Ok((secret.public_key(), secret))
    }

    /// The bottom trees covering an activation: whole trees, at least two, inside the lifetime.
    ///
    /// ```text
    /// c     = 2^(h/2), epochs per bottom tree
    /// start = start rounded down to a multiple of c
    /// end   = end rounded up to a multiple of c, and at least start + 2c
    /// ```
    ///
    /// An interval that would end past the lifetime slides left to end at it.
    pub(crate) fn expand(&self, activation: Range<u64>) -> Range<u64> {
        let c = self.leaves_per_bottom_tree();
        let lifetime = self.lifetime();
        let mut start = activation.start / c * c;
        let mut end = activation.end.div_ceil(c) * c;
        end = end.max(start + 2 * c);
        if end > lifetime {
            let duration = end - start;
            end = lifetime;
            start = lifetime.saturating_sub(duration) / c * c;
        }
        start / c..end / c
    }

    /// Verifies a signature on a message at an epoch.
    ///
    /// # Overview
    ///
    /// 1. Re-encode the message with the signature's randomness into a codeword x.
    /// 2. Walk chain i from position x_i to the end, w - 1 - x_i more steps.
    /// 3. Hash the chain ends into the epoch's leaf.
    /// 4. Climb the authentication path, and compare with the public root.
    ///
    /// Every input is public, so verification need not run in constant time.
    ///
    /// # Errors
    ///
    /// Names the first check that fails.
    pub fn verify(
        &self,
        public: &PublicKey,
        epoch: LeafEpoch,
        message: &[u8; MESSAGE_LEN],
        signature: &Signature,
    ) -> Result<(), VerifyError> {
        let epoch = epoch.0;
        if u64::from(epoch) >= self.lifetime() {
            return Err(VerifyError::BeyondLifetime {
                epoch: u64::from(epoch),
                lifetime: self.lifetime(),
            });
        }
        self.check_shapes(public, signature)?;

        let codeword = self.encode(&public.parameter, epoch, &signature.randomness, message)?;
        let hash = self.tweak_hash(public.parameter);
        let last = self.base - 1;
        let ends: Vec<Digest> = signature
            .chain_values
            .iter()
            .zip(&codeword)
            .enumerate()
            .map(|(chain, (value, &position))| {
                hash.walk(
                    epoch,
                    chain as u8,
                    position,
                    last - usize::from(position),
                    value,
                )
            })
            .collect();
        let leaf = hash.leaf(epoch, &ends);
        let root = root_from_path(&hash, u64::from(epoch), leaf, &signature.path);
        if root == public.root {
            Ok(())
        } else {
            Err(VerifyError::RootMismatch)
        }
    }

    /// Checks that a key and a signature have this instantiation's lengths.
    fn check_shapes(&self, public: &PublicKey, signature: &Signature) -> Result<(), VerifyError> {
        let digest_lengths = std::iter::once(&public.root)
            .chain(&signature.path)
            .chain(&signature.chain_values)
            .map(|digest| digest.elements().len());
        let checks = [
            (
                "authentication path",
                self.log_lifetime as usize,
                signature.path.len(),
            ),
            ("chain values", self.dimension, signature.chain_values.len()),
            (
                "randomness",
                self.rand_len,
                signature.randomness.elements().len(),
            ),
        ];
        for (part, expected, actual) in checks {
            if expected != actual {
                return Err(VerifyError::Shape {
                    part,
                    expected,
                    actual,
                });
            }
        }
        for actual in digest_lengths {
            if actual != self.hash_len {
                return Err(VerifyError::Shape {
                    part: "digest",
                    expected: self.hash_len,
                    actual,
                });
            }
        }
        Ok(())
    }

    /// Decodes a public key: the root, then the parameter.
    ///
    /// # Errors
    ///
    /// Fails on a wrong length or a non-canonical element.
    pub fn decode_public_key(&self, bytes: &[u8]) -> Result<PublicKey, DecodeError> {
        let mut reader = Reader::new(bytes);
        let root = reader.words(self.hash_len)?;
        let mut parameter = [KoalaBear::ZERO; PARAMETER_LEN];
        for element in &mut parameter {
            *element = reader.element()?;
        }
        reader.finish()?;
        Ok(PublicKey {
            root,
            parameter: PublicParameter(parameter),
        })
    }

    /// Decodes a signature, refusing any other shape than this instantiation's.
    ///
    /// # Errors
    ///
    /// Fails on a wrong offset, a wrong count, a non-canonical element, or trailing bytes.
    pub fn decode_signature(&self, bytes: &[u8]) -> Result<Signature, DecodeError> {
        let digest = self.hash_len * ELEMENT_BYTES;
        let path_offset = 2 * OFFSET_BYTES + self.rand_len * ELEMENT_BYTES;
        let chains_offset = path_offset + OFFSET_BYTES + self.log_lifetime as usize * digest;

        let mut reader = Reader::new(bytes);
        reader.offset(path_offset)?;
        let randomness = reader.words(self.rand_len)?;
        let chains_at = reader.u32()? as usize;
        // The path's length is fixed, so the second offset is too; a wrong one is a wrong count.
        if chains_at != chains_offset {
            let actual = chains_at.saturating_sub(path_offset + OFFSET_BYTES) / digest;
            return Err(DecodeError::Count {
                list: "authentication path",
                expected: self.log_lifetime as usize,
                actual,
            });
        }
        reader.offset(OFFSET_BYTES)?;
        let path = (0..self.log_lifetime)
            .map(|_| reader.words(self.hash_len))
            .collect::<Result<Vec<Digest>, _>>()?;
        let chain_values = reader.words_to_end(self.hash_len)?;
        if chain_values.len() != self.dimension {
            return Err(DecodeError::Count {
                list: "chain values",
                expected: self.dimension,
                actual: chain_values.len(),
            });
        }
        Ok(Signature {
            path,
            randomness,
            chain_values,
        })
    }

    /// Decodes a stored secret key.
    ///
    /// # Errors
    ///
    /// Fails on any layout or shape the key's activation does not imply.
    pub fn decode_secret_key(&self, bytes: &[u8]) -> Result<SecretKey, DecodeError> {
        SecretKey::decode(*self, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        entropy::SeedStream,
        instantiation::{HypercubeLifetime, Instantiation},
    };

    #[test]
    fn activation_widens_to_whole_bottom_trees() {
        // Fixture state: lifetime 2^8, so bottom trees of c = 16 epochs, 16 trees in all.
        let scheme = Instantiation::Hypercube(HypercubeLifetime::TestOnly8).scheme();

        // Epochs 16 to 63: trees 1 to 3, already whole.
        assert_eq!(scheme.expand(16..64), 1..4);
        // Epochs 17 to 20: one partial tree widens to two whole ones.
        assert_eq!(scheme.expand(17..21), 1..3);
        // Epochs 250 to 255: the two trees would pass the lifetime, so they slide left.
        assert_eq!(scheme.expand(250..256), 14..16);
        // The whole lifetime.
        assert_eq!(scheme.expand(0..256), 0..16);
    }

    #[test]
    fn sizes() {
        // Lifetime 2^32: 3 offsets, 7 randomness elements, 32 siblings and 46 chain values of 8 elements.
        let scheme = Instantiation::Hypercube(HypercubeLifetime::Epochs32).scheme();
        assert_eq!(scheme.signature_len(), 12 + 28 + 32 * 32 + 46 * 32);
        assert_eq!(scheme.public_key_len(), 52);
    }

    #[test]
    fn key_generation_refuses_empty_and_oversized_activations() {
        let scheme = Instantiation::Hypercube(HypercubeLifetime::TestOnly8).scheme();
        let mut stream = SeedStream::new(b"refused");
        assert_eq!(
            scheme.generate(&mut stream, 5..5).map(|_| ()),
            Err(KeyGenError::Empty)
        );
        assert_eq!(
            scheme.generate(&mut stream, 200..257).map(|_| ()),
            Err(KeyGenError::BeyondLifetime {
                start: 200,
                count: 57,
                lifetime: 256
            })
        );
    }

    #[test]
    fn verification_names_the_failed_check() {
        // Fixture state: a key over epochs 16 to 47 of the test lifetime.
        let scheme = Instantiation::Hypercube(HypercubeLifetime::TestOnly8).scheme();
        let (public, secret) = scheme
            .generate(&mut SeedStream::new(b"verification"), 16..48)
            .unwrap();
        let signature = secret.sign(LeafEpoch(20), &[1; 32]).unwrap();

        // Epoch 256 is past the lifetime.
        assert_eq!(
            scheme.verify(&public, LeafEpoch(256), &[1; 32], &signature),
            Err(VerifyError::BeyondLifetime {
                epoch: 256,
                lifetime: 256
            })
        );

        // A signature of the 2^32 instantiation has 32 siblings, not 8.
        let other = Instantiation::Hypercube(HypercubeLifetime::Epochs32).scheme();
        assert_eq!(
            other.verify(&public, LeafEpoch(20), &[1; 32], &signature),
            Err(VerifyError::Shape {
                part: "authentication path",
                expected: 32,
                actual: 8
            })
        );
    }

    #[test]
    fn any_changed_sibling_or_chain_value_breaks_the_root() {
        // Fixture state: a key over epochs 0 to 31, signing at epoch 21.
        let scheme = Instantiation::Hypercube(HypercubeLifetime::TestOnly8).scheme();
        let (public, secret) = scheme
            .generate(&mut SeedStream::new(b"tamper"), 0..32)
            .unwrap();
        let signature = secret.sign(LeafEpoch(21), &[3; 32]).unwrap();
        let one = KoalaBear::ONE;

        // Mutation: add one to the first element of each of the 8 siblings and 4 chain values.
        // The codeword is unchanged, so each failure is at the root.
        for index in 0..signature.path.len() + signature.chain_values.len() {
            let mut tampered = signature.clone();
            let (list, at) = if index < tampered.path.len() {
                (&mut tampered.path, index)
            } else {
                (&mut tampered.chain_values, index - signature.path.len())
            };
            let mut elements = list[at].elements().to_vec();
            elements[0] += one;
            list[at] = Words::from_slice(&elements);
            assert_eq!(
                scheme.verify(&public, LeafEpoch(21), &[3; 32], &tampered),
                Err(VerifyError::RootMismatch),
                "part {index}"
            );
        }
    }
}
