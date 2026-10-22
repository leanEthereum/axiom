//! X.509 certificates, per RFC 5280: parsing, keys, and signature checks.
//!
//! # Overview
//!
//! A certificate binds a subject name and a public key, signed by an issuer.
//! Parsing here is strict DER and checks structure only.
//! What a certificate must contain is a profile's choice: web PKI and libp2p each check their own.
//!
//! # Timing
//!
//! Certificates and signatures are public, so parsing and verification may take variable time.

mod algorithm;
mod certificate;
mod error;
mod extension;
mod name;
mod name_constraints;
pub mod oid;
mod public_key;

pub use algorithm::SignatureAlgorithm;
pub use certificate::{Certificate, Validity, Version};
pub use error::X509Error;
pub use extension::{BasicConstraints, Extension, Extensions, KeyUsage};
pub use name::{GeneralName, GeneralNames, Name};
pub use name_constraints::NameConstraints;
pub use public_key::{MIN_RSA_BITS, PublicKey};
