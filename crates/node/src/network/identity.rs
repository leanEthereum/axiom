//! The node's long-term network key, and the identifiers derived from it.

use std::{
    fs::{self, File},
    io::{self, Read},
    path::Path,
};

use axiom_crypto::{keccak::Keccak256, secp256k1::SecretKey};
use axiom_das::NodeId;
use axiom_p2p::PublicKey;
use axiom_ssz::U256;

/// The secp256k1 key that names this node on the network.
///
/// # Overview
///
/// One key yields every network identity, so they always agree:
///
/// ```text
///     secret key ──> public key ──┬──> libp2p peer id (compressed point)
///                                 └──> discovery node id = keccak256(x || y)
///                                          └──> custody groups, attestation subnets
/// ```
///
/// The key persists across restarts: peers and custody assignments recognize the node.
#[derive(Debug)]
pub struct NodeKey {
    /// The secret scalar.
    secret: SecretKey,
}

impl NodeKey {
    /// Loads the key from a file, or creates and saves a fresh one.
    ///
    /// # Errors
    ///
    /// Fails when the file cannot be read or written, or holds an invalid key.
    pub fn load_or_generate(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let bytes: [u8; 32] = fs::read(path)?.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "a node key is 32 bytes")
            })?;
            return Self::from_bytes(bytes);
        }
        let key = Self::generate()?;
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory)?;
        }
        fs::write(path, key.secret.to_bytes())?;
        Ok(key)
    }

    /// A fresh key from the operating system's randomness.
    ///
    /// # Errors
    ///
    /// Fails when no randomness is available.
    pub fn generate() -> io::Result<Self> {
        // A scalar of zero or past the group order is rejected; the chance is about 2^-128.
        loop {
            let mut bytes = [0; 32];
            File::open("/dev/urandom")?.read_exact(&mut bytes)?;
            if let Ok(key) = Self::from_bytes(bytes) {
                return Ok(key);
            }
        }
    }

    /// The key with a given secret.
    ///
    /// # Errors
    ///
    /// Fails when the bytes are zero or not below the group order.
    pub fn from_bytes(bytes: [u8; 32]) -> io::Result<Self> {
        SecretKey::from_bytes(&bytes)
            .map(|secret| Self { secret })
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not a secp256k1 secret key"))
    }

    /// The secret, for the transport handshake.
    #[must_use]
    pub const fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// The public key as libp2p encodes it.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::secp256k1(self.secret.public_key().to_compressed())
    }

    /// The discovery node identifier: keccak256 of the uncompressed point without its tag byte.
    ///
    /// The digest reads as a big-endian integer; the stored form is little-endian.
    /// See the "v4" identity scheme of EIP-778.
    #[must_use]
    pub fn node_id(&self) -> NodeId {
        let point = self.secret.public_key().to_uncompressed();
        let mut digest = Keccak256::digest(&point[1..]);
        digest.reverse();
        NodeId(U256(digest))
    }
}

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    /// Hex text as bytes.
    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let mut bytes = [0; N];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap();
        }
        bytes
    }

    #[test]
    fn node_ids_match_the_discovery_test_vectors() {
        // Nodes A and B of the discv5 wire test vectors.
        let cases = [
            (
                "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f",
                "aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb",
            ),
            (
                "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628",
                "bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9",
            ),
        ];
        for (secret, id) in cases {
            let key = NodeKey::from_bytes(hex(secret)).unwrap();
            let mut expected: [u8; 32] = hex(id);
            expected.reverse();

            assert_eq!(key.node_id(), NodeId(U256(expected)));
        }
    }

    #[test]
    fn a_saved_key_loads_back_identically() {
        let path = env::temp_dir().join(format!("axiom-node-key-{}", process::id()));

        let first = NodeKey::load_or_generate(&path).unwrap();
        let second = NodeKey::load_or_generate(&path).unwrap();

        assert_eq!(first.node_id(), second.node_id());
        fs::remove_file(&path).unwrap();
    }
}
