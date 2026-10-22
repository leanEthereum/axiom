//! Wycheproof PBKDF2-HMAC-SHA256 and PBKDF2-HMAC-SHA512 suites.

use axiom_crypto::pbkdf2::{Pbkdf2, Pbkdf2Error};

use crate::wycheproof::{Case, Outcome, Tally, VectorFile};

/// One PBKDF2 variant, as the public API exposes it.
type Derive = fn(&[u8], &[u8], u32, &mut [u8]) -> Result<(), Pbkdf2Error>;

/// Runs one case through a PBKDF2 variant and compares the derived key.
fn check(case: &Case<'_>, derive: Derive) -> Outcome {
    let iterations = u32::try_from(case.u64("iterationCount")).expect("iteration count fits u32");
    let mut dk = vec![0; case.u64("dkLen") as usize];
    match derive(
        &case.hex("password"),
        &case.hex("salt"),
        iterations,
        &mut dk,
    ) {
        Err(_) => Outcome::Rejected,
        Ok(()) if dk == case.hex("dk") => Outcome::Accepted,
        Ok(()) => Outcome::WrongOutput(format!("derived {dk:02x?}")),
    }
}

#[test]
fn pbkdf2_hmac_sha256() {
    let Some(file) = VectorFile::load("pbkdf2_hmacsha256_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Pbkdf2::sha256));
    // 60 valid cases: 58 at 4096 iterations, and the two RFC 7914 ones at 1 and 80000.
    // Outputs of 16 to 65 bytes cover a partial third block.
    assert_eq!(
        tally,
        Tally {
            valid: 60,
            ..Tally::default()
        }
    );
}

#[test]
fn pbkdf2_hmac_sha512() {
    let Some(file) = VectorFile::load("pbkdf2_hmacsha512_test.json") else {
        return;
    };
    let tally = file.run(|case| check(case, Pbkdf2::sha512));
    // 58 valid cases at 4096 iterations; a 65-byte output spills one byte into a second block.
    assert_eq!(
        tally,
        Tally {
            valid: 58,
            ..Tally::default()
        }
    );
}
