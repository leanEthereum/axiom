//! Validator secret keys as bytes, and the EIP-2333 tree that derives them.

use std::fmt;

use axiom_bls::SecretKey;
use axiom_crypto::{hkdf::Hkdf, hmac::HmacSha256};
use axiom_types::BlsPubkey;
use sha2::{Digest, Sha256};

use crate::keys::{KeyError, lamport::LamportSecretKey, residue::Residue, wipe::Wipe};

/// A BLS12-381 secret key in its 32-byte big-endian encoding: a nonzero scalar below r.
///
/// The bytes are overwritten with zero on drop, and debug output hides them.
pub struct SecretKeyBytes {
    /// The encoding, always of a nonzero scalar below r.
    bytes: [u8; 32],
}

impl SecretKeyBytes {
    /// Bytes in the encoding.
    pub const LEN: usize = 32;

    /// Fewest seed bytes EIP-2333 accepts: 256 bits.
    pub const MIN_SEED_LEN: usize = 32;

    /// Output bytes of the key generation hash: L = ceil(3 * ceil(log2(r)) / 16) = 48.
    ///
    /// See HKDF_mod_r in EIP-2333; the 128 extra bits make the modulo bias negligible.
    const OKM_LEN: u16 = 48;

    /// Initial salt of the key generation, before its first hash.
    const KEYGEN_SALT: &'static [u8] = b"BLS-SIG-KEYGEN-SALT-";

    /// Wraps an encoded key.
    ///
    /// # Errors
    ///
    /// Fails on zero and on any integer not below r.
    pub fn from_bytes(bytes: &[u8; Self::LEN]) -> Result<Self, KeyError> {
        // Validation lives in the signature library: it decodes and rejects exactly these.
        SecretKey::from_bytes(bytes).map_err(|_| KeyError::InvalidSecretKey)?;
        Ok(Self { bytes: *bytes })
    }

    /// The master key of the tree a seed grows, derive_master_SK of EIP-2333.
    ///
    /// # Errors
    ///
    /// Fails when the seed is shorter than 32 bytes.
    pub fn from_seed(seed: &[u8]) -> Result<Self, KeyError> {
        if seed.len() < Self::MIN_SEED_LEN {
            return Err(KeyError::SeedTooShort {
                len: seed.len(),
                min: Self::MIN_SEED_LEN,
            });
        }
        Ok(Self::hkdf_mod_r(seed))
    }

    /// The child at an index below this key, derive_child_SK of EIP-2333.
    ///
    /// Every child is hardened: it depends on the parent's secret, never on its public key.
    #[must_use]
    pub fn child(&self, index: u32) -> Self {
        let compressed = LamportSecretKey::compressed_public_key(&self.bytes, index);
        Self::hkdf_mod_r(&compressed)
    }

    /// The encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.bytes
    }

    /// The key, ready to sign.
    #[must_use]
    pub fn secret_key(&self) -> SecretKey {
        // Invariant: every constructor checks the scalar is nonzero and below r.
        SecretKey::from_bytes(&self.bytes).expect("the bytes encode a valid key")
    }

    /// The compressed public key.
    #[must_use]
    pub fn public_key(&self) -> BlsPubkey {
        BlsPubkey(self.secret_key().public_key().to_bytes())
    }

    /// Hashes key material to a nonzero scalar below r, HKDF_mod_r of EIP-2333.
    ///
    /// # Overview
    ///
    /// ```text
    /// salt = "BLS-SIG-KEYGEN-SALT-"
    /// repeat:
    ///     salt = SHA256(salt)
    ///     PRK  = HKDF-Extract(salt, IKM || I2OSP(0, 1))
    ///     OKM  = HKDF-Expand(PRK, I2OSP(48, 2), 48)
    ///     SK   = OS2IP(OKM) mod r
    /// until SK != 0
    /// ```
    ///
    /// The key info is empty in EIP-2333, so the expand info is the length alone.
    /// This equals KeyGen of draft-irtf-cfrg-bls-signature-05, section 2.3.
    fn hkdf_mod_r(ikm: &[u8]) -> Self {
        let mut salt: [u8; 32] = Sha256::digest(Self::KEYGEN_SALT).into();
        loop {
            // HKDF-Extract is HMAC keyed by the salt, so the trailing zero streams in.
            let mut extract = HmacSha256::new(&salt);
            extract.update(ikm);
            extract.update(&[0]);
            let prk = Hkdf::from_prk(extract.finalize());

            let mut okm = [0_u8; Self::OKM_LEN as usize];
            // Invariant: 48 bytes is far below the HKDF limit of 8160.
            prk.expand(&Self::OKM_LEN.to_be_bytes(), &mut okm)
                .expect("48 bytes is within the HKDF limit");
            let residue = Residue::from_be_bytes(&okm);
            okm.wipe();

            // Zero has probability about 2^-255: the retry is for correctness, not for speed.
            if !residue.is_zero() {
                return Self {
                    bytes: residue.to_be_bytes(),
                };
            }
            salt = Sha256::digest(salt).into();
        }
    }
}

impl Drop for SecretKeyBytes {
    fn drop(&mut self) {
        self.bytes.wipe();
    }
}

impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKeyBytes(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string in a test vector.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Encodes a decimal integer below 2^256 as 32 big-endian bytes.
    fn decimal(text: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for digit in text.bytes() {
            // out = 10 out + digit, byte by byte from the least significant end.
            let mut carry = u32::from(digit - b'0');
            for byte in out.iter_mut().rev() {
                let value = u32::from(*byte) * 10 + carry;
                *byte = value as u8;
                carry = value >> 8;
            }
        }
        out
    }

    /// Checks one EIP-2333 case: the master key of the seed, then one child.
    fn check(seed: &str, master: &str, index: u32, child: &str) {
        let master_key = SecretKeyBytes::from_seed(&hex(seed)).unwrap();
        assert_eq!(*master_key.as_bytes(), decimal(master));
        assert_eq!(*master_key.child(index).as_bytes(), decimal(child));
    }

    #[test]
    fn eip_2333_case_0() {
        // A 64-byte seed: the BIP-39 seed of "abandon ... about" under passphrase TREZOR.
        check(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            "6083874454709270928345386274498605044986640685124978867557563392430687146096",
            0,
            "20397789859736650942317412262472558107875392172444076792671091975210932703118",
        );
    }

    #[test]
    fn eip_2333_case_1() {
        check(
            "3141592653589793238462643383279502884197169399375105820974944592",
            "29757020647961307431480504535336562678282505419141012933316116377660817309383",
            3_141_592_653,
            "25457201688850691947727629385191704516744796114925897962676248250929345014287",
        );
    }

    #[test]
    fn eip_2333_case_2() {
        // The largest index, 2^32 - 1, fills all four salt bytes.
        check(
            "0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
            "27580842291869792442942448775674722299803720648445448686099262467207037398656",
            4_294_967_295,
            "29358610794459428860402234341874281240803786294062035874021252734817515685787",
        );
    }

    #[test]
    fn eip_2333_case_3() {
        check(
            "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
            "19022158461524446591288038168518313374041767046816487870552872741050760015818",
            42,
            "31372231650479070279774297061823572166496564838472787488249775572789064611981",
        );
    }

    #[test]
    fn seeds_below_256_bits_are_refused() {
        // Threshold: 32 bytes. A 31-byte seed is refused, a 32-byte one accepted.
        assert_eq!(
            SecretKeyBytes::from_seed(&[7; 31]).err(),
            Some(KeyError::SeedTooShort { len: 31, min: 32 })
        );
        assert!(SecretKeyBytes::from_seed(&[7; 32]).is_ok());
    }

    #[test]
    fn invalid_encodings_are_refused() {
        // Zero would sign everything with the identity; r itself is not below r.
        assert_eq!(
            SecretKeyBytes::from_bytes(&[0; 32]).err(),
            Some(KeyError::InvalidSecretKey)
        );
        let r = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        assert_eq!(
            SecretKeyBytes::from_bytes(&r.try_into().unwrap()).err(),
            Some(KeyError::InvalidSecretKey)
        );
    }

    #[test]
    fn the_public_key_matches_the_signature_library() {
        // Key 1 has public key G1, the generator, whose compressed form is published.
        let mut one = [0; 32];
        one[31] = 1;
        let key = SecretKeyBytes::from_bytes(&one).unwrap();
        assert_eq!(
            key.public_key().0.to_vec(),
            hex(
                "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
            )
        );
        assert_eq!(format!("{key:?}"), "SecretKeyBytes(<redacted>)");
    }
}
