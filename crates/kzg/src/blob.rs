//! Blobs: 4096 field elements, the evaluations of a polynomial over the roots of unity.

use std::fmt;

use axiom_bls12_381::{SCALAR_BYTES, Scalar};

use crate::{
    BYTES_PER_BLOB, Bytes32, Bytes48, FIELD_ELEMENTS_PER_BLOB, KzgError, transcript::Transcript,
};

/// Domain tag of the blob evaluation challenge, FIAT_SHAMIR_PROTOCOL_DOMAIN in the Deneb spec.
const FIAT_SHAMIR_PROTOCOL_DOMAIN: &[u8; 16] = b"FSBLOBVERIFY_V1_";

/// A validated blob: 4096 canonical field elements.
///
/// Element i is p(omega^{rev(i)}) for the polynomial p of degree below 4096 the blob encodes.
/// Here omega is the root of unity of order 4096 and rev reverses 12 bits.
///
/// See Blob and blob_to_polynomial in the Deneb polynomial commitments spec, and EIP-4844.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob(Box<[Scalar; FIELD_ELEMENTS_PER_BLOB]>);

impl Blob {
    /// Decodes and validates the 131072 bytes of a blob.
    ///
    /// # Errors
    ///
    /// Fails when the length is wrong or any field element is not canonical.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KzgError> {
        if bytes.len() != BYTES_PER_BLOB {
            return Err(KzgError::InvalidBlobLength(bytes.len()));
        }
        // Each 32-byte chunk is one big-endian element, as blob_to_polynomial reads it.
        let (chunks, _) = bytes.as_chunks::<SCALAR_BYTES>();
        let elements = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| {
                Bytes32(*chunk)
                    .to_scalar()
                    .ok_or(KzgError::NonCanonicalBlobElement { index })
            })
            .collect::<Result<Box<[Scalar]>, _>>()?;
        // Invariant: the length check above leaves exactly 4096 chunks.
        let Ok(elements) = elements.try_into() else {
            unreachable!("a blob of 131072 bytes holds 4096 elements");
        };
        Ok(Self(elements))
    }

    /// Encodes the blob back into its 131072 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.iter().flat_map(Scalar::to_bytes_be).collect()
    }

    /// The evaluation point of an opening of this blob, compute_challenge in the Deneb spec.
    ///
    /// ```text
    ///     SHA-256( tag || 4096 as u128 || blob || commitment )  mod r
    /// ```
    pub(crate) fn challenge(&self, commitment: &Bytes48) -> Scalar {
        let mut transcript = Transcript::new(FIAT_SHAMIR_PROTOCOL_DOMAIN);
        // The polynomial degree bound, as a 16-byte big-endian integer.
        transcript.append((FIELD_ELEMENTS_PER_BLOB as u128).to_be_bytes());
        transcript.append(self.to_bytes());
        transcript.append(commitment.0);
        transcript.challenge()
    }

    /// The evaluations, in bit-reversal order of the domain.
    pub(crate) fn evaluations(&self) -> &[Scalar; FIELD_ELEMENTS_PER_BLOB] {
        &self.0
    }
}

impl fmt::Debug for Blob {
    /// Shows the first field element only, since a full blob prints 256 KiB of hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blob({:?}, ..)", self.0[0])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use axiom_yaml::Yaml;
    use proptest::prelude::*;

    use super::*;
    use crate::{BYTES_PER_FIELD_ELEMENT, test_vectors::cases};

    #[test]
    fn challenge_matches_vectors() {
        // Each case hashes a blob and a commitment into the evaluation point.
        for case in cases("compute_challenge") {
            let input = case.get("input").unwrap();
            let blob_bytes = input.get("blob").and_then(Yaml::as_hex_bytes).unwrap();
            let blob = Blob::from_bytes(&blob_bytes).unwrap();
            let commitment = Bytes48(input.get("commitment").unwrap().as_hex_array().unwrap());
            let expected = case.get("output").unwrap().as_hex_array().unwrap();
            assert_eq!(blob.challenge(&commitment).to_bytes_be(), expected);
        }
    }

    #[test]
    fn length_must_be_exact() {
        // One byte short of 4096 * 32 = 131072 is rejected with the received length.
        assert_eq!(
            Blob::from_bytes(&vec![0; BYTES_PER_BLOB - 1]),
            Err(KzgError::InvalidBlobLength(131_071))
        );
    }

    #[test]
    fn non_canonical_element_is_rejected() {
        // Fixture state: element 4095 is all 0xff bytes, far above the modulus.
        let mut bytes = vec![0; BYTES_PER_BLOB];
        bytes[BYTES_PER_BLOB - 32..].fill(0xff);
        assert_eq!(
            Blob::from_bytes(&bytes),
            Err(KzgError::NonCanonicalBlobElement { index: 4095 })
        );
    }

    #[test]
    fn bytes_round_trip() {
        // Fixture state: element i holds the integer i, written in the last two bytes.
        let mut bytes = vec![0; BYTES_PER_BLOB];
        for (i, element) in bytes.as_chunks_mut::<32>().0.iter_mut().enumerate() {
            element[30..].copy_from_slice(&(i as u16).to_be_bytes());
        }
        let blob = Blob::from_bytes(&bytes).unwrap();
        assert_eq!(blob.evaluations()[4095], Scalar::from_u64(4095));
        assert_eq!(blob.to_bytes(), bytes);
    }

    /// A blob from a seed: every element takes 32 pseudorandom bytes with the top two bits cleared.
    ///
    /// Clearing them keeps each integer below 2^254 < r, so every element is canonical.
    pub(crate) fn blob_from_seed(seed: u64) -> Blob {
        // Xorshift64 is enough to fill a blob with varied, reproducible bytes.
        let mut state = seed | 1;
        let mut bytes = vec![0_u8; BYTES_PER_BLOB];
        for chunk in bytes.as_chunks_mut::<8>().0 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *chunk = state.to_be_bytes();
        }
        for element in bytes.as_chunks_mut::<BYTES_PER_FIELD_ELEMENT>().0 {
            element[0] &= 0x3f;
        }
        Blob::from_bytes(&bytes).expect("every element is below 2^254")
    }

    /// Random blobs, drawn through their seeds.
    pub(crate) fn arb_blob() -> impl Strategy<Value = Blob> {
        any::<u64>().prop_map(blob_from_seed)
    }
}
