//! Bearer token authentication, checked before any route runs.

use std::{fmt, hint::black_box};

use axiom_http::Request;
use sha2::{Digest, Sha256};

use crate::keymanager::reply::ApiError;

/// The token every keymanager request must carry.
///
/// Only the token's SHA-256 digest is kept, and a presented token is hashed before the comparison.
/// The comparison then reads every byte of two equal-length digests.
/// So its time reveals neither the token's length nor the position of a first difference.
pub(crate) struct ApiToken {
    /// SHA-256 of the token.
    digest: [u8; 32],
}

impl ApiToken {
    /// The authentication scheme of RFC 6750 section 2.1.
    const SCHEME: &'static str = "Bearer ";

    /// A token, as written in the token file.
    pub(crate) fn new(token: &str) -> Self {
        Self {
            digest: Sha256::digest(token.as_bytes()).into(),
        }
    }

    /// Admits a request carrying the token.
    ///
    /// # Errors
    ///
    /// Refuses with 401 when no bearer token is present, and with 403 when it is wrong.
    pub(crate) fn check(&self, request: &Request) -> Result<(), ApiError> {
        let presented = request
            .headers
            .get("authorization")
            .and_then(Self::bearer)
            .ok_or_else(|| ApiError::unauthorized("missing bearer token"))?;
        if !self.matches(presented) {
            return Err(ApiError::forbidden("invalid bearer token"));
        }
        Ok(())
    }

    /// The token of an authorization field, whose scheme name is case-insensitive.
    fn bearer(field: &str) -> Option<&str> {
        let scheme = field.get(..Self::SCHEME.len())?;
        let token = field[Self::SCHEME.len()..].trim();
        (scheme.eq_ignore_ascii_case(Self::SCHEME) && !token.is_empty()).then_some(token)
    }

    /// Whether a presented token is the token.
    fn matches(&self, presented: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        // Timing: every byte is folded in before the one test, and the barrier keeps it a fold.
        let difference = digest
            .iter()
            .zip(&self.digest)
            .fold(0_u8, |acc, (a, b)| black_box(acc | (a ^ b)));
        difference == 0
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Even the digest stays out of logs.
        f.debug_struct("ApiToken").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use axiom_http::Method;

    use super::*;

    /// A request carrying an authorization field, or none.
    fn request(authorization: Option<&str>) -> Request {
        let request = Request::new(Method::Get, "/eth/v1/keystores");
        match authorization {
            Some(value) => request.with_header("authorization", value),
            None => request,
        }
    }

    #[test]
    fn the_right_token_is_admitted_under_any_scheme_case() {
        let token = ApiToken::new("0a1b");
        assert_eq!(token.check(&request(Some("Bearer 0a1b"))), Ok(()));
        assert_eq!(token.check(&request(Some("bearer 0a1b"))), Ok(()));
    }

    #[test]
    fn a_missing_token_is_unauthorized() {
        let token = ApiToken::new("0a1b");
        let missing = ApiError::unauthorized("missing bearer token");
        // No field, another scheme, and an empty token all carry no bearer token.
        assert_eq!(token.check(&request(None)), Err(missing.clone()));
        assert_eq!(
            token.check(&request(Some("Basic 0a1b"))),
            Err(missing.clone())
        );
        assert_eq!(token.check(&request(Some("Bearer "))), Err(missing));
    }

    #[test]
    fn a_wrong_token_is_forbidden() {
        let token = ApiToken::new("0a1b");
        // A prefix of the token is as wrong as any other text.
        assert_eq!(
            token.check(&request(Some("Bearer 0a1"))),
            Err(ApiError::forbidden("invalid bearer token"))
        );
    }
}
