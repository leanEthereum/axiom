//! Transport cryptography for the consensus networking stack.
//!
//! # Overview
//!
//! Each module serves one protocol need.
//!
//! - Keccak-256 hashes public keys into node identities and addresses.
//! - SHA-3 and SHAKE, the rest of the Keccak family, serve the hash-based signatures.
//! - secp256k1 signs node records and agrees on discv5 session keys.
//! - X25519 and ChaCha20-Poly1305 run the libp2p Noise handshake.
//! - AES-128-GCM seals discv5 messages, and AES-128-CTR masks their headers.
//! - HMAC-SHA256 and HKDF-SHA256 derive every session key.
//!
//! Secret-dependent code runs in constant time.
//! Secret keys clear their bytes when dropped.
//! Fast paths behind runtime CPU detection are pinned to portable references by property tests.

mod aead;
mod ct;

pub mod aes;
pub mod chacha20poly1305;
pub mod hkdf;
pub mod hmac;
pub mod keccak;
pub mod secp256k1;
pub mod x25519;

pub use aead::AeadError;
