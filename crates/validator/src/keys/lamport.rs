//! The Lamport keys EIP-2333 passes through between a parent key and its child.

use axiom_crypto::hkdf::Hkdf;
use sha2::{Digest, Sha256};

use crate::keys::wipe::Wipe;

/// Chunks in one Lamport secret key.
///
/// HKDF-SHA256 expands to at most 255 blocks of 32 bytes, per RFC 5869, section 2.3.
/// So EIP-2333 sets L = 255 * 32, one chunk per block.
const CHUNKS: usize = 255;

/// Bytes in one chunk: the SHA-256 digest size K of EIP-2333.
const CHUNK_LEN: usize = 32;

/// A Lamport secret key: 255 chunks of 32 bytes, wiped on drop.
///
/// See IKM_to_lamport_SK in EIP-2333.
pub(crate) struct LamportSecretKey {
    /// The chunks, back to back.
    bytes: [u8; CHUNKS * CHUNK_LEN],
}

impl LamportSecretKey {
    /// Stretches key material under a salt into a Lamport secret key.
    ///
    /// # Overview
    ///
    /// ```text
    /// PRK        = HKDF-Extract(salt, IKM)
    /// OKM        = HKDF-Expand(PRK, "", 255 * 32)
    /// lamport_SK = OKM split into 32-byte chunks
    /// ```
    pub(crate) fn from_ikm(ikm: &[u8; 32], salt: [u8; 4]) -> Self {
        let mut key = Self {
            bytes: [0; CHUNKS * CHUNK_LEN],
        };
        // Invariant: 255 * 32 = 8160 bytes is exactly the HKDF limit, so expansion succeeds.
        Hkdf::extract(&salt, ikm)
            .expand(&[], &mut key.bytes)
            .expect("8160 bytes is within the HKDF limit");
        key
    }

    /// The chunks, in order.
    pub(crate) fn chunks(&self) -> impl Iterator<Item = &[u8; CHUNK_LEN]> {
        self.bytes.as_chunks::<CHUNK_LEN>().0.iter()
    }

    /// The compressed Lamport public key of a parent key and a child index.
    ///
    /// See parent_SK_to_lamport_PK in EIP-2333.
    ///
    /// # Overview
    ///
    /// ```text
    /// salt      = I2OSP(index, 4)
    /// lamport_0 = IKM_to_lamport_SK(parent_SK, salt)
    /// lamport_1 = IKM_to_lamport_SK(flip_bits(parent_SK), salt)
    /// PK        = SHA256(SHA256(lamport_0[0]) || ... || SHA256(lamport_1[254]))
    /// ```
    ///
    /// The 510 chunk digests stream into the outer hash instead of a 16 KiB buffer.
    pub(crate) fn compressed_public_key(parent: &[u8; 32], index: u32) -> [u8; 32] {
        let salt = index.to_be_bytes();
        let mut flipped = parent.map(|byte| !byte);
        let halves = [Self::from_ikm(parent, salt), Self::from_ikm(&flipped, salt)];
        flipped.wipe();

        let mut outer = Sha256::new();
        for chunk in halves.iter().flat_map(Self::chunks) {
            outer.update(Sha256::digest(chunk));
        }
        outer.finalize().into()
    }
}

impl Drop for LamportSecretKey {
    fn drop(&mut self) {
        self.bytes.wipe();
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

    /// The SHA-256 digest of every chunk of a key, back to back.
    fn digest(key: &LamportSecretKey) -> Vec<u8> {
        Sha256::digest(key.bytes).to_vec()
    }

    /// The parent key of the EIP-2333 intermediate vector: master_SK of test case 0.
    ///
    /// 6083874454709270928345386274498605044986640685124978867557563392430687146096 in hex.
    fn parent() -> [u8; 32] {
        hex("0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070")
            .try_into()
            .unwrap()
    }

    #[test]
    fn eip_2333_intermediate_lamport_keys() {
        // EIP-2333, "Test Vector with Intermediate values", child index 0.
        // The 255 chunks of each key are pinned by their first, their last, and a digest of all.
        // The digest is SHA-256 over the 8160 bytes of the published list.
        let salt = 0_u32.to_be_bytes();
        let lamport_0 = LamportSecretKey::from_ikm(&parent(), salt);
        assert_eq!(lamport_0.chunks().count(), 255);
        assert_eq!(
            lamport_0.chunks().next().unwrap().to_vec(),
            hex("e345d0ad7be270737de05cf036f688f385d5f99c7fddb054837658bdd2ebd519")
        );
        assert_eq!(
            lamport_0.chunks().last().unwrap().to_vec(),
            hex("65963bb743d5db080005c4db59e29c4a4e86f92ab1dd7a59f69ea7eaf8e9aa79")
        );
        assert_eq!(
            digest(&lamport_0),
            hex("f51a7dd26192d8622302bb7f85e98d92defe9e681c174fb6259767d436437a41")
        );

        // The second key stretches the bitwise complement of the parent.
        let lamport_1 = LamportSecretKey::from_ikm(&parent().map(|byte| !byte), salt);
        assert_eq!(
            lamport_1.chunks().next().unwrap().to_vec(),
            hex("9c0bfb14de8d2779f88fc8d5b016f8668be9e231e745640096d35dd5f53b0ae2")
        );
        assert_eq!(
            lamport_1.chunks().last().unwrap().to_vec(),
            hex("261a605fa5f2a9bdc7cffac530edcf976e7ea7af4e443b625fe01ed39dad44b6")
        );
        assert_eq!(
            digest(&lamport_1),
            hex("2ddf7dbfe161a3b069b2b069ded2b904dff0c306018e9e4920eed7866fbaf726")
        );

        // Both keys compress into the published public key.
        assert_eq!(
            LamportSecretKey::compressed_public_key(&parent(), 0).to_vec(),
            hex("dd635d27d1d52b9a49df9e5c0c622360a4dd17cba7db4e89bce3cb048fb721a5")
        );
    }
}
