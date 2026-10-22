//! The Wycheproof X25519 suite.
//!
//! The crate refuses an all-zero shared secret, as RFC 7748, section 6.1, allows and Noise requires.
//! Wycheproof marks the 31 low-order public keys that yield it acceptable, so those count as rejected.
//! Every other acceptable case, such as a twist point or a non-canonical u, must give the published secret.

use axiom_crypto::x25519::{PublicKey, SecretKey};

use crate::wycheproof::{Outcome, Tally, VectorFile};

#[test]
fn x25519() {
    let Some(file) = VectorFile::load("x25519_test.json") else {
        return;
    };
    let tally = file.run(|case| {
        let private: [u8; 32] = case.hex("private").try_into().expect("32-byte scalar");
        let public: [u8; 32] = case.hex("public").try_into().expect("32-byte u-coordinate");
        let shared = case.hex("shared");
        match SecretKey::from_bytes(private).diffie_hellman(&PublicKey::from_bytes(public)) {
            // Invariant: only a zero secret is refused, so the published one must be zero.
            Err(_) if shared == [0; 32] => Outcome::Rejected,
            Err(error) => Outcome::WrongOutput(format!("refused a nonzero secret: {error}")),
            Ok(secret) if secret.as_bytes()[..] == shared[..] => Outcome::Accepted,
            Ok(secret) => Outcome::WrongOutput(format!("computed {:02x?}", secret.as_bytes())),
        }
    });
    // 518 cases: 264 valid, 254 acceptable, of which 31 give the zero secret.
    assert_eq!(
        tally,
        Tally {
            valid: 264,
            acceptable_accepted: 223,
            acceptable_rejected: 31,
            ..Tally::default()
        }
    );
}
