//! JWT with HS256, the authentication of the engine API.
//!
//! The scheme is in the execution-apis repository, `src/engine/authentication.md`.
//!
//! ```text
//!     token = b64url(header) "." b64url(claims) "." b64url(HMAC-SHA256(secret, signing input))
//!
//!     header   {"alg":"HS256","typ":"JWT"}
//!     claims   {"iat":1700000000}               issued-at, seconds since the epoch
//!     signing input = the first two segments with their dot, as ASCII
//! ```
//!
//! Each HTTP request carries a fresh token in its authorization field.
//! The execution client accepts an issued-at within 60 seconds of its own clock.

use std::fmt;

use axiom_json::{Data, Json, Object};
use thiserror::Error;

use super::{base64url::Base64Url, hmac::HmacSha256};

/// The encoded header every token carries: `{"alg":"HS256","typ":"JWT"}`.
const HEADER: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

/// Widest gap between a token's issued-at and the verifier's clock.
///
/// The authentication spec says an execution client should accept plus or minus 60 seconds.
pub const MAX_CLOCK_SKEW: u64 = 60;

/// The 256-bit secret shared by the consensus and execution clients.
///
/// Debug output hides the key, so logs never leak it.
#[derive(Clone, PartialEq, Eq)]
pub struct JwtSecret([u8; 32]);

impl JwtSecret {
    /// A secret from its raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Reads the hex text of a `jwt.hex` file.
    ///
    /// Surrounding whitespace and a 0x prefix are tolerated, as common tooling writes both.
    ///
    /// # Errors
    ///
    /// Fails unless the rest is exactly 64 hex digits.
    pub fn from_hex(text: &str) -> Result<Self, JwtError> {
        let text = text.trim();
        // Reuse the DATA decoder, which wants the prefix; add it when the file lacks one.
        let prefixed = if text.starts_with("0x") {
            text.to_owned()
        } else {
            format!("0x{text}")
        };
        <[u8; 32]>::from_data(&prefixed)
            .map(Self)
            .map_err(|_| JwtError::InvalidSecret)
    }

    /// Issues a token stamped with a time in seconds since the epoch.
    #[must_use]
    pub fn token(&self, issued_at: u64) -> String {
        // The claims are a single member object, serialized compactly.
        let mut claims = Object::new();
        claims.insert("iat", Json::from(issued_at));
        let claims = Json::Object(claims).to_string();

        // Sign the ASCII of "header.claims" and append the signature as a third segment.
        let signing_input = format!("{HEADER}.{}", Base64Url(claims.as_bytes()));
        let signature = HmacSha256::new(&self.0).mac(signing_input.as_bytes());
        format!("{signing_input}.{}", Base64Url(&signature))
    }

    /// Checks a token's signature and freshness against a clock reading.
    ///
    /// The execution side runs this check; the mock engine uses it in tests.
    ///
    /// # Errors
    ///
    /// Fails on a malformed token, any algorithm but HS256, a bad signature, or a stale issued-at.
    pub fn verify(&self, token: &str, now: u64) -> Result<Claims, JwtError> {
        let token = Token::split(token)?;

        // The header must name HS256.
        // "none" in particular is refused, as the authentication spec requires.
        let header = token.header.json()?;
        match header.get("alg").and_then(Json::as_str) {
            Some("HS256") => {}
            Some(other) => return Err(JwtError::UnsupportedAlgorithm(other.to_owned())),
            None => return Err(JwtError::Malformed),
        }

        // Recompute the MAC over the first two segments as sent, then compare in constant time.
        let signature = token.signature.bytes()?;
        if !HmacSha256::new(&self.0).verify(token.signing_input.as_bytes(), &signature) {
            return Err(JwtError::BadSignature);
        }

        // Only an authentic token's claims are read.
        // Unknown claims, such as "id" and "clv", are ignored as the spec requires.
        let claims = token.claims.json()?;
        let issued_at = claims
            .get("iat")
            .and_then(Json::as_u64)
            .ok_or(JwtError::MissingIssuedAt)?;
        if issued_at.abs_diff(now) > MAX_CLOCK_SKEW {
            return Err(JwtError::Stale { issued_at, now });
        }
        Ok(Claims { issued_at })
    }
}

impl fmt::Debug for JwtSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JwtSecret(..)")
    }
}

/// A token cut into its three segments, none of them checked yet.
#[derive(Clone, Copy, Debug)]
struct Token<'a> {
    /// The header and claims segments with the dot between them, as signed.
    signing_input: &'a str,
    /// The encoded header.
    header: Segment<'a>,
    /// The encoded claims.
    claims: Segment<'a>,
    /// The encoded signature.
    signature: Segment<'a>,
}

impl<'a> Token<'a> {
    /// Splits a token at its dots.
    fn split(token: &'a str) -> Result<Self, JwtError> {
        // Exactly three dot-separated segments.
        let mut segments = token.split('.');
        let (Some(header), Some(claims), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(JwtError::Malformed);
        };
        Ok(Self {
            signing_input: &token[..token.len() - signature.len() - 1],
            header: Segment(header),
            claims: Segment(claims),
            signature: Segment(signature),
        })
    }
}

/// One base64url segment of a token.
#[derive(Clone, Copy, Debug)]
struct Segment<'a>(&'a str);

impl Segment<'_> {
    /// The bytes the segment encodes.
    fn bytes(self) -> Result<Vec<u8>, JwtError> {
        Base64Url::decode(self.0).ok_or(JwtError::Malformed)
    }

    /// The JSON value the segment encodes.
    fn json(self) -> Result<Json, JwtError> {
        Json::parse(self.bytes()?).map_err(|_| JwtError::Malformed)
    }
}

/// The claims of a verified token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claims {
    /// When the token was issued, in seconds since the epoch.
    pub issued_at: u64,
}

/// A secret or token that fails the authentication rules.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum JwtError {
    /// The secret is not 32 bytes of hex.
    #[error("JWT secret is not 32 bytes of hex")]
    InvalidSecret,

    /// The token is not three base64url segments of JSON.
    #[error("malformed JWT")]
    Malformed,

    /// The header names an algorithm other than HS256.
    #[error("unsupported JWT algorithm {0:?}")]
    UnsupportedAlgorithm(String),

    /// The signature does not match the secret.
    #[error("JWT signature does not match")]
    BadSignature,

    /// The claims lack an integer issued-at.
    #[error("JWT lacks an issued-at claim")]
    MissingIssuedAt,

    /// The issued-at is too far from the verifier's clock.
    #[error("JWT issued at {issued_at} is stale at {now}")]
    Stale {
        /// The token's issued-at.
        issued_at: u64,
        /// The verifier's clock.
        now: u64,
    },
}

#[cfg(test)]
mod tests {
    use std::array;

    use proptest::prelude::*;

    use super::*;

    /// The secret 0x00 0x01 ... 0x1f.
    fn secret() -> JwtSecret {
        JwtSecret::new(array::from_fn(|i| i as u8))
    }

    #[test]
    fn header_constant_encodes_hs256() {
        // The precomputed header decodes to the exact JSON the scheme prescribes.
        let header = Base64Url::decode(HEADER).unwrap();
        assert_eq!(header, br#"{"alg":"HS256","typ":"JWT"}"#);
    }

    #[test]
    fn issued_token_verifies_within_skew() {
        // Issued at t = 1000, checked at 1000, 1060, and 940: all within 60 seconds.
        let token = secret().token(1000);
        for now in [1000, 1060, 940] {
            assert_eq!(secret().verify(&token, now), Ok(Claims { issued_at: 1000 }));
        }

        // 61 seconds either way is stale.
        assert_eq!(
            secret().verify(&token, 1061),
            Err(JwtError::Stale {
                issued_at: 1000,
                now: 1061
            })
        );
        assert!(secret().verify(&token, 939).is_err());
    }

    #[test]
    fn token_matches_an_independent_computation() {
        // Claims {"iat":1000} encode to "eyJpYXQiOjEwMDB9".
        let token = secret().token(1000);
        let (signing_input, _) = token.rsplit_once('.').unwrap();
        assert_eq!(signing_input, format!("{HEADER}.eyJpYXQiOjEwMDB9"));
    }

    #[test]
    fn tampering_is_detected() {
        let token = secret().token(1000);

        // Another secret, one byte different, rejects the signature.
        let mut other = [0_u8; 32];
        other[31] = 1;
        assert_eq!(
            JwtSecret::new(other).verify(&token, 1000),
            Err(JwtError::BadSignature)
        );

        // Swapping in claims with a later iat breaks the signature.
        let forged_claims = Base64Url(br#"{"iat":1050}"#);
        let parts: Vec<&str> = token.split('.').collect();
        let forged = format!("{}.{forged_claims}.{}", parts[0], parts[2]);
        assert_eq!(secret().verify(&forged, 1000), Err(JwtError::BadSignature));

        // An unsigned token with alg "none" is refused before any MAC is computed.
        let none_header = Base64Url(br#"{"alg":"none"}"#);
        let unsigned = format!("{none_header}.{}.", parts[1]);
        assert_eq!(
            secret().verify(&unsigned, 1000),
            Err(JwtError::UnsupportedAlgorithm("none".to_owned()))
        );

        // Two segments only.
        assert_eq!(secret().verify("a.b", 1000), Err(JwtError::Malformed));
    }

    #[test]
    fn secret_file_forms() {
        // 64 digits with a prefix and a trailing newline, as tooling writes them.
        let hex = format!("0x{}\n", "ab".repeat(32));
        assert_eq!(JwtSecret::from_hex(&hex), Ok(JwtSecret::new([0xab; 32])));

        // Bare digits work too; 62 digits do not.
        assert!(JwtSecret::from_hex(&"cd".repeat(32)).is_ok());
        assert_eq!(
            JwtSecret::from_hex(&"cd".repeat(31)),
            Err(JwtError::InvalidSecret)
        );

        // Debug output never shows key material.
        assert_eq!(format!("{:?}", secret()), "JwtSecret(..)");
    }

    proptest! {
        #[test]
        fn jwt_round_trip_and_tamper_detection(
            key in any::<[u8; 32]>(),
            issued_at in 0_u64..4_000_000_000,
            position in any::<prop::sample::Index>(),
        ) {
            let secret = JwtSecret::new(key);
            let token = secret.token(issued_at);
            prop_assert_eq!(secret.verify(&token, issued_at).map(|claims| claims.issued_at), Ok(issued_at));

            // Replacing any one character with a different symbol breaks the token.
            let mut bytes = token.into_bytes();
            let at = position.index(bytes.len());
            bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(bytes).unwrap();
            prop_assert!(secret.verify(&tampered, issued_at).is_err());
        }
    }
}
