//! ECDSA signatures in their DER form, as certificates and TLS carry them.

use axiom_crypto::p256::Signature;

use crate::{
    der::{DerError, DerReader, DerWriter},
    x509::X509Error,
};

/// Bytes of one P-256 scalar.
const SCALAR_LEN: usize = 32;

/// An ECDSA signature in the DER form of RFC 3279, section 2.2.3: a SEQUENCE of r and s.
///
/// TLS 1.3 signs with this form too, per RFC 8446, section 4.2.3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EcdsaSigValue(Signature);

impl EcdsaSigValue {
    /// Decodes the strict DER form of a P-256 signature.
    ///
    /// # Errors
    ///
    /// Fails on any non-canonical encoding, a component wider than 32 bytes, or r or s outside [1, n).
    pub fn from_der(bytes: &[u8]) -> Result<Self, X509Error> {
        let compact = EcdsaComponents::from_der(bytes)?.to_fixed::<{ 2 * SCALAR_LEN }>()?;
        Signature::from_bytes(&compact)
            .map(Self)
            .map_err(|_| X509Error::MalformedSignature)
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

/// The two integers of a DER ECDSA signature, as minimal magnitudes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EcdsaComponents<'a> {
    /// The magnitude of r.
    r: &'a [u8],
    /// The magnitude of s.
    s: &'a [u8],
}

impl<'a> EcdsaComponents<'a> {
    /// Decodes the strict DER SEQUENCE of two non-negative integers.
    pub(crate) fn from_der(bytes: &'a [u8]) -> Result<Self, X509Error> {
        let mut outer = DerReader::new(bytes);
        let mut body = outer.sequence()?;
        outer.finish()?;
        let r = body.unsigned_integer()?;
        let s = body.unsigned_integer()?;
        body.finish()?;
        Ok(Self { r, s })
    }

    /// The fixed-width form r || s, each half left-padded to N / 2 bytes.
    ///
    /// The range of each component is left to the curve's own decoder.
    pub(crate) fn to_fixed<const N: usize>(self) -> Result<[u8; N], X509Error> {
        let half = N / 2;
        let mut out = [0_u8; N];
        for (magnitude, slot) in [self.r, self.s].into_iter().zip(out.chunks_mut(half)) {
            if magnitude.len() > half {
                return Err(DerError::IntegerTooLong {
                    length: magnitude.len(),
                    max: half,
                }
                .into());
            }
            slot[half - magnitude.len()..].copy_from_slice(magnitude);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use axiom_crypto::p256::SecretKey;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn components_are_range_checked() {
        // r = 0 decodes as DER but is no valid component.
        assert_eq!(
            EcdsaSigValue::from_der(&[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01]),
            Err(X509Error::MalformedSignature)
        );

        // A 33-byte magnitude cannot be a P-256 scalar.
        let mut wide = vec![0x30, 0x26, 0x02, 0x21];
        wide.extend([0x7f; 33]);
        wide.extend([0x02, 0x01, 0x01]);
        assert_eq!(
            EcdsaSigValue::from_der(&wide),
            Err(X509Error::Der(DerError::IntegerTooLong {
                length: 33,
                max: 32
            }))
        );

        // A trailing byte after the sequence.
        assert_eq!(
            EcdsaSigValue::from_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00]),
            Err(X509Error::Der(DerError::TrailingBytes { count: 1 }))
        );
    }

    #[test]
    fn components_pad_to_the_curve_width() {
        // r = 1 and s = 0x0102 in a 96-byte P-384 form: 47 zeros then 01, 46 zeros then 01 02.
        let der = [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x01, 0x02];
        let fixed = EcdsaComponents::from_der(&der)
            .unwrap()
            .to_fixed::<96>()
            .unwrap();
        let mut expected = [0_u8; 96];
        expected[47] = 1;
        expected[94] = 1;
        expected[95] = 2;
        assert_eq!(fixed, expected);
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
