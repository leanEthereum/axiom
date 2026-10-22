//! Raw byte strings at the library boundary: field elements, commitments, and proofs.
//!
//! The specs pass these as untrusted bytes and validate them inside each public method.
//! Commitments stay bytes because batch verification deduplicates and hashes them as bytes.

use std::fmt;

use axiom_bls12_381::{G1_COMPRESSED_BYTES, G1Affine, G1Projective, SCALAR_BYTES, Scalar};

use crate::KzgError;

/// A 32-byte big-endian field element, as an evaluation point or an evaluation.
///
/// See Bytes32 and bytes_to_bls_field in the Deneb polynomial commitments spec.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes32(pub [u8; SCALAR_BYTES]);

impl Bytes32 {
    /// Decodes the canonical field element these bytes encode.
    ///
    /// # Errors
    ///
    /// Fails when the integer is not below the scalar field modulus.
    pub(crate) fn to_scalar(self) -> Result<Scalar, KzgError> {
        Scalar::from_bytes_be(&self.0).ok_or(KzgError::NonCanonicalFieldElement)
    }

    /// Encodes a field element canonically.
    pub(crate) fn from_scalar(scalar: &Scalar) -> Self {
        Self(scalar.to_bytes_be())
    }
}

impl From<[u8; SCALAR_BYTES]> for Bytes32 {
    fn from(bytes: [u8; SCALAR_BYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Bytes32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bytes32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// A 48-byte compressed G1 point, as a commitment or a proof.
///
/// See KZGCommitment and KZGProof in the Deneb polynomial commitments spec.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes48(pub [u8; G1_COMPRESSED_BYTES]);

impl Bytes48 {
    /// Decodes a commitment, as in the spec's KeyValidate check that admits the identity.
    ///
    /// # Errors
    ///
    /// Fails unless the bytes encode a point of the prime-order subgroup.
    pub(crate) fn to_commitment(self) -> Result<G1Affine, KzgError> {
        // The checked decoder accepts exactly one encoding of the identity.
        // It rejects points off the curve and points outside the subgroup.
        G1Affine::from_compressed(&self.0).map_err(KzgError::InvalidCommitment)
    }

    /// Decodes a proof, under the same rules as a commitment.
    ///
    /// # Errors
    ///
    /// Fails unless the bytes encode a point of the prime-order subgroup.
    pub(crate) fn to_proof(self) -> Result<G1Affine, KzgError> {
        G1Affine::from_compressed(&self.0).map_err(KzgError::InvalidProof)
    }

    /// Compresses a point into its 48-byte encoding.
    pub(crate) fn from_point(point: &G1Projective) -> Self {
        Self(G1Affine::from(point).to_compressed())
    }
}

impl From<[u8; G1_COMPRESSED_BYTES]> for Bytes48 {
    fn from(bytes: [u8; G1_COMPRESSED_BYTES]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Bytes48 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bytes48 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// Decodes consecutive 32-byte big-endian field elements, as blob_to_polynomial does.
///
/// The length must be a multiple of 32.
///
/// # Errors
///
/// Fails when any element is not below the scalar field modulus.
pub(crate) fn decode_field_elements(bytes: &[u8]) -> Result<Vec<Scalar>, KzgError> {
    let (elements, rest) = bytes.as_chunks::<SCALAR_BYTES>();
    debug_assert!(rest.is_empty(), "field elements span 32 bytes each");
    elements
        .iter()
        .map(|element| Bytes32(*element).to_scalar())
        .collect()
}

/// Encodes field elements as consecutive 32-byte big-endian strings.
pub(crate) fn encode_field_elements(elements: &[Scalar]) -> Vec<u8> {
    elements.iter().flat_map(Scalar::to_bytes_be).collect()
}

/// Moves a vector of known length into a boxed array, without a stack copy of the array.
///
/// # Panics
///
/// Panics when the length differs from N, which callers rule out by construction.
pub(crate) fn into_boxed_array<T, const N: usize>(values: Vec<T>) -> Box<[T; N]> {
    let length = values.len();
    // Invariant: every caller builds exactly N values, by a loop or a map over N inputs.
    let Ok(array) = values.into_boxed_slice().try_into() else {
        unreachable!("expected {N} values, built {length}");
    };
    array
}

/// Renders bytes as 0x-prefixed lowercase hex, the form the specs and vectors print.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("0x")?;
    for byte in bytes {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axiom_bls12_381::PointDecodeError;

    use super::*;

    #[test]
    fn field_elements_must_be_canonical() {
        // The modulus r itself is congruent to zero but has a shorter encoding, so it is rejected.
        //
        //     r = 0x73eda753...00000001
        let mut modulus = [0_u8; 32];
        modulus[..8].copy_from_slice(&0x73ed_a753_299d_7d48_u64.to_be_bytes());
        modulus[8..16].copy_from_slice(&0x3339_d808_09a1_d805_u64.to_be_bytes());
        modulus[16..24].copy_from_slice(&0x53bd_a402_fffe_5bfe_u64.to_be_bytes());
        modulus[24..].copy_from_slice(&0xffff_ffff_0000_0001_u64.to_be_bytes());
        assert_eq!(
            Bytes32(modulus).to_scalar(),
            Err(KzgError::NonCanonicalFieldElement)
        );

        // r - 1 is the largest canonical element and round-trips.
        modulus[31] = 0;
        let largest = Bytes32(modulus).to_scalar().unwrap();
        assert_eq!(largest, -Scalar::ONE);
        assert_eq!(Bytes32::from_scalar(&largest), Bytes32(modulus));
    }

    #[test]
    fn identity_is_a_valid_commitment() {
        // The identity encodes as the compression and infinity flags over zero bits: 0xc0 00 .. 00.
        let mut identity = [0_u8; 48];
        identity[0] = 0xc0;
        assert_eq!(Bytes48(identity).to_commitment(), Ok(G1Affine::IDENTITY));
        assert_eq!(
            Bytes48::from_point(&G1Projective::IDENTITY),
            Bytes48(identity)
        );

        // The same flags with a stray payload bit are rejected, with the curve-level reason kept.
        identity[47] = 1;
        assert_eq!(
            Bytes48(identity).to_proof(),
            Err(KzgError::InvalidProof(
                PointDecodeError::InvalidInfinityEncoding
            ))
        );
    }

    #[test]
    fn debug_prints_hex() {
        // Debug output matches the 0x-prefixed form of the vectors.
        assert_eq!(
            format!("{:?}", Bytes32([0xab; 32])),
            format!("0x{}", "ab".repeat(32))
        );
    }
}
