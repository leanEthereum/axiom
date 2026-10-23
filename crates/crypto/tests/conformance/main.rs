//! Conformance of every primitive against its published reference vectors.
//!
//! The vectors live outside the repository and come from make -C testing/ef-tests.
//! Point AXIOM_VECTORS at their root, which defaults to the workspace's testing/vectors.
//!
//! ```text
//!     $AXIOM_VECTORS/wycheproof/testvectors_v1/*.json
//!     $AXIOM_VECTORS/nist-cavp/{aes,gcm}/*.rsp
//!     $AXIOM_VECTORS/keccak-kat/*.txt
//! ```

mod aead;
mod cavp;
mod der;
mod ecdh;
mod ecdsa;
mod keccak;
mod mac;
mod p256;
mod p384;
mod pbkdf2;
mod rsa;
mod vectors;
mod wycheproof;
mod x25519;
