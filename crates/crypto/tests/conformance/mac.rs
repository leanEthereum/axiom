//! Wycheproof HMAC-SHA256 and HKDF-SHA256 suites.

use axiom_crypto::{hkdf::Hkdf, hmac::HmacSha256};

use crate::wycheproof::{Outcome, Tally, VectorFile};

#[test]
fn hmac_sha256() {
    let Some(file) = VectorFile::load("hmac_sha256_test.json") else {
        return;
    };
    let tally = file.run(|case| {
        let key = case.hex("key");
        let message = case.hex("msg");
        let tag = case.hex("tag");

        // A full 32-byte tag goes through the constant-time verifier.
        if let Ok(full) = <[u8; 32]>::try_from(tag.as_slice()) {
            let mut mac = HmacSha256::new(&key);
            mac.update(&message);
            return if mac.verify(&full) {
                Outcome::Accepted
            } else {
                Outcome::Rejected
            };
        }

        // A truncated tag, here 16 bytes, is the prefix of the full one, per RFC 2104, section 5.
        // The crate has no truncated verifier, so the prefix is compared here.
        let computed = HmacSha256::mac(&key, &message);
        if computed.get(..tag.len()) == Some(tag.as_slice()) {
            Outcome::Accepted
        } else {
            Outcome::Rejected
        }
    });
    // 174 cases: 66 valid, 108 with a modified tag, half of each with 128-bit tags.
    assert_eq!(
        tally,
        Tally {
            valid: 66,
            invalid: 108,
            ..Tally::default()
        }
    );
}

#[test]
fn hkdf_sha256() {
    let Some(file) = VectorFile::load("hkdf_sha256_test.json") else {
        return;
    };
    let tally = file.run(|case| {
        // An empty salt stands for 32 zero bytes, which HMAC pads to the same key, per RFC 5869.
        let prk = Hkdf::extract(&case.hex("salt"), &case.hex("ikm"));
        let mut okm = vec![0; case.u64("size") as usize];
        match prk.expand(&case.hex("info"), &mut okm) {
            Err(_) => Outcome::Rejected,
            Ok(()) if okm == case.hex("okm") => Outcome::Accepted,
            Ok(()) => Outcome::WrongOutput(format!("derived {okm:02x?}")),
        }
    });
    // 86 cases: 83 valid, and 3 asking for more than 255 * 32 = 8160 bytes.
    assert_eq!(
        tally,
        Tally {
            valid: 83,
            invalid: 3,
            ..Tally::default()
        }
    );
}
