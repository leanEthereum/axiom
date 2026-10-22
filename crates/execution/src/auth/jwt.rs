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

use std::{error::Error, fmt};

use axiom_json::{Json, Object, data};

use super::{
    base64url,
    hmac::{constant_time_eq, hmac_sha256},
};

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
        data::decode_array::<32>(&prefixed)
            .map(Self)
            .map_err(|_| JwtError::InvalidSecret)
    }

    /// Issues a token stamped with a time in seconds since the epoch.
    #[must_use]
    pub fn token(&self, issued_at: u64) -> String {
        // The claims are a single member object, serialized compactly.
        let mut claims = Object::new();
        claims.insert("iat", Json::from(issued_at));
        let claims = base64url::encode(Json::Object(claims).to_string().as_bytes());

        // Sign the ASCII of "header.claims" and append the signature as a third segment.
        let signing_input = format!("{HEADER}.{claims}");
        let signature = hmac_sha256(&self.0, signing_input.as_bytes());
        format!("{signing_input}.{}", base64url::encode(&signature))
    }

    /// Checks a token's signature and freshness against a clock reading.
    ///
    /// The execution side runs this check; the mock engine uses it in tests.
    ///
    /// # Errors
    ///
    /// Fails on a malformed token, any algorithm but HS256, a bad signature, or a stale issued-at.
    pub fn verify(&self, token: &str, now: u64) -> Result<Claims, JwtError> {
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

        // The header must name HS256.
        // "none" in particular is refused, as the authentication spec requires.
        let header = decode_segment(header)?;
        match header.get("alg").and_then(Json::as_str) {
            Some("HS256") => {}
            Some(other) => return Err(JwtError::UnsupportedAlgorithm(other.to_owned())),
            None => return Err(JwtError::Malformed),
        }

        // Recompute the MAC over the first two segments as sent, then compare in constant time.
        let signing_input = &token[..token.len() - signature.len() - 1];
        let expected = hmac_sha256(&self.0, signing_input.as_bytes());
        let signature = base64url::decode(signature).ok_or(JwtError::Malformed)?;
        if !constant_time_eq(&signature, &expected) {
            return Err(JwtError::BadSignature);
        }

        // Only an authentic token's claims are read.
        // Unknown claims, such as "id" and "clv", are ignored as the spec requires.
        let claims = decode_segment(claims)?;
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

/// Decodes one JSON segment of a token.
fn decode_segment(segment: &str) -> Result<Json, JwtError> {
    let bytes = base64url::decode(segment).ok_or(JwtError::Malformed)?;
    Json::parse(bytes).map_err(|_| JwtError::Malformed)
}

/// The claims of a verified token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Claims {
    /// When the token was issued, in seconds since the epoch.
    pub issued_at: u64,
}

/// A secret or token that fails the authentication rules.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtError {
    /// The secret is not 32 bytes of hex.
    InvalidSecret,

    /// The token is not three base64url segments of JSON.
    Malformed,

    /// The header names an algorithm other than HS256.
    UnsupportedAlgorithm(String),

    /// The signature does not match the secret.
    BadSignature,

    /// The claims lack an integer issued-at.
    MissingIssuedAt,

    /// The issued-at is too far from the verifier's clock.
    Stale {
        /// The token's issued-at.
        issued_at: u64,
        /// The verifier's clock.
        now: u64,
    },
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret => f.write_str("JWT secret is not 32 bytes of hex"),
            Self::Malformed => f.write_str("malformed JWT"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "unsupported JWT algorithm {alg:?}"),
            Self::BadSignature => f.write_str("JWT signature does not match"),
            Self::MissingIssuedAt => f.write_str("JWT lacks an issued-at claim"),
            Self::Stale { issued_at, now } => {
                write!(f, "JWT issued at {issued_at} is stale at {now}")
            }
        }
    }
}

impl Error for JwtError {}

#[cfg(test)]
mod tests {
    use std::array;

    use super::*;

    /// The secret 0x00 0x01 ... 0x1f.
    fn secret() -> JwtSecret {
        JwtSecret::new(array::from_fn(|i| i as u8))
    }

    #[test]
    fn header_constant_encodes_hs256() {
        // The precomputed header decodes to the exact JSON the scheme prescribes.
        let header = base64url::decode(HEADER).unwrap();
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
        let forged_claims = base64url::encode(br#"{"iat":1050}"#);
        let parts: Vec<&str> = token.split('.').collect();
        let forged = format!("{}.{forged_claims}.{}", parts[0], parts[2]);
        assert_eq!(secret().verify(&forged, 1000), Err(JwtError::BadSignature));

        // An unsigned token with alg "none" is refused before any MAC is computed.
        let none_header = base64url::encode(br#"{"alg":"none"}"#);
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
}
