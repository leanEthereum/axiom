//! ECDSA P-256 signatures in their DER form, as certificates and TLS carry them.

use axiom_crypto::p256::Signature;

use super::{
    CertificateError,
    der::{DerError, DerReader, DerWriter},
};

/// Bytes of one P-256 scalar.
const SCALAR_LEN: usize = 32;

/// An ECDSA signature in the DER form of RFC 3279, section 2.2.3: a SEQUENCE of r and s.
///
/// TLS 1.3 signs with this form too, per RFC 8446, section 4.2.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdsaSigValue(Signature);

impl EcdsaSigValue {
    /// Decodes the strict DER form.
    ///
    /// # Errors
    ///
    /// Fails on any non-canonical encoding, a component wider than 32 bytes, or r or s outside [1, n).
    pub fn from_der(bytes: &[u8]) -> Result<Self, CertificateError> {
        let mut outer = DerReader::new(bytes);
        let mut body = outer.sequence()?;
        outer.finish()?;
        let r = body.unsigned_integer()?;
        let s = body.unsigned_integer()?;
        body.finish()?;

        // Left-pad each magnitude to 32 bytes.
        let mut compact = [0_u8; 2 * SCALAR_LEN];
        for (magnitude, slot) in [r, s].into_iter().zip(compact.chunks_mut(SCALAR_LEN)) {
            if magnitude.len() > SCALAR_LEN {
                return Err(DerError::IntegerTooLong {
                    length: magnitude.len(),
                    max: SCALAR_LEN,
                }
                .into());
            }
            slot[SCALAR_LEN - magnitude.len()..].copy_from_slice(magnitude);
        }
        Ok(Self(Signature::from_bytes(&compact)?))
    }

    /// The strict DER form.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        let mut writer = DerWriter::new();
        writer.sequence(|body| {
            body.unsigned_integer(&self.0.r());
            body.unsigned_integer(&self.0.s());
        });
        writer.into_bytes()
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> Signature {
        self.0
    }
}

impl From<Signature> for EcdsaSigValue {
    fn from(signature: Signature) -> Self {
        Self(signature)
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::{P256Error, SecretKey};
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn components_are_range_checked() {
        // r = 0 decodes as DER but is no valid component.
        assert_eq!(
            EcdsaSigValue::from_der(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]),
            Err(CertificateError::P256(P256Error::InvalidSignature {
                offset: 0
            }))
        );

        // A 33-byte magnitude cannot be a P-256 scalar.
        let mut wide = vec![0x30, 0x26, 0x02, 0x21];
        wide.extend([0x7f; 33]);
        wide.extend([0x02, 0x01, 0x01]);
        assert_eq!(
            EcdsaSigValue::from_der(&wide),
            Err(CertificateError::Der(DerError::IntegerTooLong {
                length: 33,
                max: 32
            }))
        );

        // A trailing byte after the sequence.
        assert_eq!(
            EcdsaSigValue::from_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]),
            Err(CertificateError::Der(DerError::TrailingBytes { count: 1 }))
        );
    }

    proptest! {
        #[test]
        fn round_trip(secret in any::<[u8; 32]>(), hash in any::<[u8; 32]>()) {
            let Ok(key) = SecretKey::from_bytes(&secret) else {
                return Ok(());
            };
            let value = EcdsaSigValue::from(key.sign(&hash));
            let der = value.to_der();
            prop_assert!(der.len() <= 72);
            prop_assert_eq!(EcdsaSigValue::from_der(&der), Ok(value));
        }
    }
}
