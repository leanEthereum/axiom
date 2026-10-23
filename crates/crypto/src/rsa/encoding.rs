//! The EMSA-PKCS1-v1_5 and EMSA-PSS encodings of a message digest, per RFC 8017, section 9.

use super::{error::RsaError, hash::RsaHash};

/// Zero bytes that open the PSS hash input M', per RFC 8017, section 9.1.1, step 5.
const PSS_PADDING: [u8; 8] = [0; 8];

/// The byte that closes every PSS encoded message, per RFC 8017, section 9.1.1, step 12.
const PSS_TRAILER: u8 = 0xbc;

/// A message digest with the hash that produced it, its length checked.
#[derive(Clone, Copy, Debug)]
pub(super) struct MessageDigest<'a> {
    /// The hash function.
    hash: RsaHash,
    /// The digest, exactly as long as the hash output.
    digest: &'a [u8],
}

impl<'a> MessageDigest<'a> {
    /// Pairs a digest with its hash.
    ///
    /// # Errors
    ///
    /// Fails when the digest length differs from the hash output length.
    pub(super) const fn new(hash: RsaHash, digest: &'a [u8]) -> Result<Self, RsaError> {
        if digest.len() != hash.output_len() {
            return Err(RsaError::DigestLength {
                expected: hash.output_len(),
                actual: digest.len(),
            });
        }
        Ok(Self { hash, digest })
    }

    /// The EMSA-PKCS1-v1_5 encoded message of a given length, per RFC 8017, section 9.2.
    ///
    /// ```text
    /// EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo prefix || digest
    /// ```
    ///
    /// PS is all 0xff bytes, at least eight of them.
    ///
    /// # Errors
    ///
    /// Fails when the length leaves fewer than eight bytes of padding.
    pub(super) fn pkcs1v15(&self, em_len: usize) -> Result<Vec<u8>, RsaError> {
        let prefix = self.hash.digest_info_prefix();
        let t_len = prefix.len() + self.digest.len();

        // Step 3: three marker bytes and at least eight bytes of padding.
        let required = t_len + 11;
        if em_len < required {
            return Err(RsaError::EncodingTooShort {
                required,
                available: em_len,
            });
        }
        let mut em = Vec::with_capacity(em_len);
        em.extend_from_slice(&[0x00, 0x01]);
        em.resize(em_len - t_len - 1, 0xff);
        em.push(0x00);
        em.extend_from_slice(prefix);
        em.extend_from_slice(self.digest);
        Ok(em)
    }

    /// The EMSA-PSS encoded message for a salt, per RFC 8017, section 9.1.1.
    ///
    /// # Algorithm
    ///
    /// ```text
    /// H  = Hash(0x00 * 8 || digest || salt)
    /// DB = 0x00 * (emLen - sLen - hLen - 2) || 0x01 || salt
    /// EM = (DB xor MGF1(H)) || H || 0xbc
    /// ```
    ///
    /// The top 8 emLen - emBits bits of EM are cleared, so EM stays below the modulus.
    ///
    /// # Errors
    ///
    /// Fails when the salt and digest leave no room in emLen bytes.
    pub(super) fn pss_encode(&self, salt: &[u8], em_bits: usize) -> Result<Vec<u8>, RsaError> {
        let h_len = self.hash.output_len();
        let em_len = em_bits.div_ceil(8);

        // Step 3: the salt, the digest, the 0x01 separator and the trailer must fit.
        let required = h_len + salt.len() + 2;
        if em_len < required {
            return Err(RsaError::EncodingTooShort {
                required,
                available: em_len,
            });
        }

        // Steps 5 and 6: H = Hash(M').
        let h = self.hash.digest(&[&PSS_PADDING, self.digest, salt]);

        // Steps 7 to 10: DB = PS || 0x01 || salt, then masked by MGF1(H).
        let db_len = em_len - h_len - 1;
        let mut em = vec![0_u8; db_len];
        em[db_len - salt.len() - 1] = 0x01;
        em[db_len - salt.len()..].copy_from_slice(salt);
        self.hash.apply_mgf1(&h, &mut em);

        // Step 11: clear the bits above emBits.
        em[0] &= Self::top_byte_mask(em_len, em_bits);

        // Step 12: EM = maskedDB || H || 0xbc.
        em.extend_from_slice(&h);
        em.push(PSS_TRAILER);
        Ok(em)
    }

    /// Holds when an encoded message is a valid PSS encoding with the given salt length.
    ///
    /// This is EMSA-PSS-VERIFY of RFC 8017, section 9.1.2, for an EM of emLen bytes.
    /// It runs in variable time: the encoded message comes from a public signature.
    pub(super) fn pss_verify(&self, em: &[u8], em_bits: usize, salt_len: usize) -> bool {
        let h_len = self.hash.output_len();
        let em_len = em.len();
        debug_assert_eq!(em_len, em_bits.div_ceil(8), "EM spans emLen bytes");

        // Steps 3 and 4: room for the salt, and the trailer byte.
        let Some(required) = salt_len.checked_add(h_len + 2) else {
            return false;
        };
        if em_len < required || em[em_len - 1] != PSS_TRAILER {
            return false;
        }

        // Steps 5 and 6: split, and refuse set bits above emBits.
        let (masked_db, rest) = em.split_at(em_len - h_len - 1);
        let h = &rest[..h_len];
        let top = Self::top_byte_mask(em_len, em_bits);
        if masked_db[0] & !top != 0 {
            return false;
        }

        // Steps 7 to 9: unmask DB and clear the bits above emBits.
        let mut db = masked_db.to_vec();
        self.hash.apply_mgf1(h, &mut db);
        db[0] &= top;

        // Step 10: zero padding, then the 0x01 separator.
        let padding = em_len - h_len - salt_len - 2;
        if db[..padding].iter().any(|&byte| byte != 0) || db[padding] != 0x01 {
            return false;
        }

        // Steps 11 to 14: recompute H from the recovered salt.
        let salt = &db[padding + 1..];
        self.hash.digest(&[&PSS_PADDING, self.digest, salt]) == h
    }

    /// The mask that keeps the low emBits bits of the first byte of an emLen-byte string.
    const fn top_byte_mask(em_len: usize, em_bits: usize) -> u8 {
        // Threshold: 8 emLen - emBits is between 0 and 7, so the shift stays in range.
        0xff >> (8 * em_len - em_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_length_is_checked() {
        assert_eq!(
            MessageDigest::new(RsaHash::Sha384, &[0; 32]).unwrap_err(),
            RsaError::DigestLength {
                expected: 48,
                actual: 32
            }
        );
    }

    #[test]
    fn pkcs1v15_layout() {
        // 128 bytes: 0x00 0x01, 74 bytes of 0xff, 0x00, the 19-byte prefix, the 32-byte digest.
        let digest = [0xab_u8; 32];
        let em = MessageDigest::new(RsaHash::Sha256, &digest)
            .unwrap()
            .pkcs1v15(128)
            .unwrap();
        let mut expected = vec![0x00, 0x01];
        expected.extend_from_slice(&[0xff; 74]);
        expected.push(0x00);
        expected.extend_from_slice(RsaHash::Sha256.digest_info_prefix());
        expected.extend_from_slice(&digest);
        assert_eq!(em, expected);

        // Threshold: 51 bytes of DigestInfo need 62 bytes, and 61 are refused.
        let message = MessageDigest::new(RsaHash::Sha256, &digest).unwrap();
        assert_eq!(message.pkcs1v15(62).map(|em| em.len()), Ok(62));
        assert_eq!(
            message.pkcs1v15(61),
            Err(RsaError::EncodingTooShort {
                required: 62,
                available: 61
            })
        );
    }

    #[test]
    fn pss_round_trip_and_mutations() {
        // emBits = 1023 for a 1024-bit modulus, so EM is 128 bytes with the top bit clear.
        let digest = [0x5a_u8; 64];
        let salt = [0x11_u8; 20];
        let message = MessageDigest::new(RsaHash::Sha512, &digest).unwrap();
        let em = message.pss_encode(&salt, 1023).unwrap();
        assert_eq!(em.len(), 128);
        assert_eq!(em[0] & 0x80, 0);
        assert_eq!(em[127], PSS_TRAILER);
        assert!(message.pss_verify(&em, 1023, 20));

        // Mutation: the wrong salt length, the trailer, a top bit, and a digest byte.
        assert!(!message.pss_verify(&em, 1023, 19));
        assert!(!message.pss_verify(&em, 1023, 21));
        let mut bad = em.clone();
        bad[127] = 0xbd;
        assert!(!message.pss_verify(&bad, 1023, 20));
        let mut bad = em.clone();
        bad[0] |= 0x80;
        assert!(!message.pss_verify(&bad, 1023, 20));
        let other = MessageDigest::new(RsaHash::Sha512, &[0x5b; 64]).unwrap();
        assert!(!other.pss_verify(&em, 1023, 20));

        // An absurd salt length is refused without overflow.
        assert!(!message.pss_verify(&em, 1023, usize::MAX));

        // Threshold: 64 + 62 + 2 = 128 bytes fit exactly, and a 63-byte salt does not.
        assert_eq!(
            message.pss_encode(&[0; 62], 1023).map(|em| em.len()),
            Ok(128)
        );
        assert_eq!(
            message.pss_encode(&[0; 63], 1023),
            Err(RsaError::EncodingTooShort {
                required: 129,
                available: 128
            })
        );
    }

    #[test]
    fn pss_with_whole_byte_em_bits() {
        // emBits = 1024 keeps every bit of the first byte, and an empty salt is legal.
        let message = MessageDigest::new(RsaHash::Sha256, &[7; 32]).unwrap();
        let em = message.pss_encode(&[], 1024).unwrap();
        assert_eq!(em.len(), 128);
        assert!(message.pss_verify(&em, 1024, 0));
        assert!(!message.pss_verify(&em, 1024, 1));
    }
}
