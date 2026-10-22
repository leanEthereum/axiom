//! Blobs: 4096 field elements, the evaluations of a polynomial over the roots of unity.

use std::fmt;

use axiom_bls12_381::Scalar;

use crate::{
    BYTES_PER_BLOB, FIELD_ELEMENTS_PER_BLOB, KzgError,
    bytes::{decode_field_elements, encode_field_elements, into_boxed_array},
};

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
        // The length check above guarantees exactly 4096 elements.
        Ok(Self(into_boxed_array(decode_field_elements(bytes)?)))
    }

    /// Encodes the blob back into its 131072 bytes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        encode_field_elements(self.0.as_slice())
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
mod tests {
    use super::*;

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
            Err(KzgError::NonCanonicalFieldElement)
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
}
