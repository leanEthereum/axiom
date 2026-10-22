//! HKDF-SHA256, the extract-then-expand key derivation of RFC 5869.

use std::{error::Error, fmt};

use crate::{ct::wipe, hmac::HmacSha256};

/// Longest output one pseudorandom key can expand to.
///
/// The block counter is one byte, so at most 255 blocks of 32 bytes, per RFC 5869, section 2.3.
const MAX_OUTPUT_LEN: usize = 255 * HmacSha256::OUTPUT_LEN;

/// A pseudorandom key, ready to expand into any number of derived keys.
///
/// # Overview
///
/// ```text
/// extract : PRK = HMAC(salt, IKM)
/// expand  : T(i) = HMAC(PRK, T(i - 1) || info || i),  T(0) = empty
///           OKM  = first L bytes of T(1) || T(2) || ...
/// ```
///
/// # Examples
///
/// ```
/// use axiom_crypto::hkdf::Hkdf;
///
/// let hkdf = Hkdf::extract(b"salt", b"input keying material");
/// let mut key = [0_u8; 16];
/// hkdf.expand(b"context", &mut key).unwrap();
/// ```
#[derive(Clone)]
pub struct Hkdf {
    /// The pseudorandom key.
    prk: [u8; HmacSha256::OUTPUT_LEN],
}

impl Hkdf {
    /// Concentrates input keying material into a pseudorandom key.
    ///
    /// An empty salt equals a salt of 32 zero bytes, since HMAC zero-pads its key.
    #[must_use]
    pub fn extract(salt: &[u8], ikm: &[u8]) -> Self {
        // PRK = HMAC-SHA256(key = salt, message = IKM), per RFC 5869, section 2.2.
        Self {
            prk: HmacSha256::mac(salt, ikm),
        }
    }

    /// Wraps a pseudorandom key derived elsewhere.
    #[must_use]
    pub const fn from_prk(prk: [u8; HmacSha256::OUTPUT_LEN]) -> Self {
        Self { prk }
    }

    /// The pseudorandom key.
    #[must_use]
    pub const fn prk(&self) -> &[u8; HmacSha256::OUTPUT_LEN] {
        &self.prk
    }

    /// Fills the output with key material bound to the context string.
    ///
    /// # Errors
    ///
    /// Fails when the output is longer than 255 * 32 = 8160 bytes.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), HkdfError> {
        if okm.len() > MAX_OUTPUT_LEN {
            return Err(HkdfError::OutputTooLong {
                len: okm.len(),
                max: MAX_OUTPUT_LEN,
            });
        }

        // Chain the blocks: each one feeds the previous block, the context, and its index.
        //
        //     T(1) = HMAC(PRK,        info || 0x01)
        //     T(2) = HMAC(PRK, T(1) || info || 0x02)
        let mut previous = [0_u8; HmacSha256::OUTPUT_LEN];
        for (index, chunk) in (1_u8..=255).zip(okm.chunks_mut(HmacSha256::OUTPUT_LEN)) {
            let mut mac = HmacSha256::new(&self.prk);
            // T(0) is empty, so the first block skips the chaining input.
            if index > 1 {
                mac.update(&previous);
            }
            mac.update(info);
            mac.update(&[index]);
            previous = mac.finalize();

            // The last block may be cut short to the requested length.
            chunk.copy_from_slice(&previous[..chunk.len()]);
        }

        // The chaining value reveals output bytes: clear it.
        wipe(&mut previous);
        Ok(())
    }
}

impl Drop for Hkdf {
    fn drop(&mut self) {
        wipe(&mut self.prk);
    }
}

impl fmt::Debug for Hkdf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The pseudorandom key is secret: never print it.
        f.debug_struct("Hkdf").finish_non_exhaustive()
    }
}

/// A key derivation request HKDF cannot serve.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HkdfError {
    /// The requested output exceeds 255 hash blocks.
    OutputTooLong {
        /// Bytes requested.
        len: usize,
        /// Most bytes one expansion produces.
        max: usize,
    },
}

impl fmt::Display for HkdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLong { len, max } => {
                write!(f, "output of {len} bytes exceeds the HKDF limit of {max}")
            }
        }
    }
}

impl Error for HkdfError {}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Runs one RFC 5869 case end to end, checking both the PRK and the OKM.
    fn check(ikm: &[u8], salt: &[u8], info: &[u8], prk: &str, okm: &str) {
        let hkdf = Hkdf::extract(salt, ikm);
        assert_eq!(hkdf.prk().to_vec(), hex(prk));
        let mut out = vec![0; okm.len() / 2];
        hkdf.expand(info, &mut out).unwrap();
        assert_eq!(out, hex(okm));
    }

    #[test]
    fn rfc_5869_basic_case() {
        // RFC 5869, appendix A.1: 22-byte IKM, 13-byte salt, 10-byte info, 42-byte output.
        check(
            &[0x0b; 22],
            &hex("000102030405060708090a0b0c"),
            &hex("f0f1f2f3f4f5f6f7f8f9"),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );
    }

    #[test]
    fn rfc_5869_long_inputs() {
        // RFC 5869, appendix A.2: 80-byte IKM, salt, and info.
        // 82-byte output over three blocks.
        let ikm: Vec<u8> = (0x00..=0x4f).collect();
        let salt: Vec<u8> = (0x60..=0xaf).collect();
        let info: Vec<u8> = (0xb0..=0xff).collect();
        check(
            &ikm,
            &salt,
            &info,
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );
    }

    #[test]
    fn rfc_5869_empty_salt_and_info() {
        // RFC 5869, appendix A.3: the empty salt stands for 32 zero bytes.
        check(
            &[0x0b; 22],
            &[],
            &[],
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
        assert_eq!(
            Hkdf::extract(&[], b"ikm").prk(),
            Hkdf::extract(&[0; 32], b"ikm").prk()
        );
    }

    #[test]
    fn output_length_limit() {
        // 8160 bytes is the most one key expands to: 255 blocks of 32.
        let hkdf = Hkdf::from_prk([7; 32]);
        assert_eq!(hkdf.expand(b"", &mut [0; 8160]), Ok(()));

        // One byte more would need a 256th block, which the one-byte counter cannot index.
        assert_eq!(
            hkdf.expand(b"", &mut [0; 8161]),
            Err(HkdfError::OutputTooLong {
                len: 8161,
                max: 8160
            })
        );
    }

    proptest! {
        #[test]
        fn shorter_outputs_are_prefixes(
            len in 0_usize..200,
            info in prop::collection::vec(any::<u8>(), 0..40),
        ) {
            // Expansion is a stream: asking for fewer bytes cuts the longer output.
            let hkdf = Hkdf::extract(b"salt", b"ikm");
            let mut long = [0_u8; 200];
            hkdf.expand(&info, &mut long).unwrap();
            let mut short = vec![0_u8; len];
            hkdf.expand(&info, &mut short).unwrap();
            prop_assert_eq!(&short[..], &long[..len]);
        }
    }
}
