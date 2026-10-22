//! Transport and key-storage cryptography for the consensus client.
//!
//! # Overview
//!
//! Each module serves one protocol need.
//!
//! - Keccak-256 hashes public keys into node identities and addresses.
//! - secp256k1 signs node records and agrees on discv5 session keys.
//! - P-256 ECDSA signs and checks the certificates of the libp2p TLS handshake.
//! - X25519 and ChaCha20-Poly1305 run the libp2p Noise handshake.
//! - AES-128-GCM seals discv5 messages, and AES-128-CTR masks their headers.
//! - HMAC-SHA256 and HKDF-SHA256 derive every session key.
//! - scrypt and PBKDF2-HMAC-SHA256 derive the keys that encrypt EIP-2335 keystores.
//! - PBKDF2-HMAC-SHA512 stretches BIP-39 mnemonics into seeds.
//!
//! Secret-dependent code runs in constant time.
//! scrypt is the one exception: its table lookups follow the password by design.
//! Secret keys clear their bytes when dropped.
//! Fast paths behind runtime CPU detection are pinned to portable references by property tests.

mod aead;
mod ct;
mod rfc6979;
mod uint;

pub mod aes;
pub mod chacha20poly1305;
pub mod hkdf;
pub mod hmac;
pub mod keccak;
pub mod p256;
pub mod pbkdf2;
pub mod scrypt;
pub mod secp256k1;
pub mod x25519;

pub use aead::AeadError;
