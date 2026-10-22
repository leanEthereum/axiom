//! Content negotiation: JSON or SSZ, from the accept and content type fields.
//!
//! The beacon API speaks JSON by default and SSZ where a route allows it.
//! A client states its preference with quality values, per RFC 9110 section 12.5.1.

use axiom_http::Request;

use super::reply::ApiError;

/// Media type of JSON bodies.
pub(crate) const JSON: &str = "application/json";

/// Media type of SSZ bodies.
pub(crate) const SSZ: &str = "application/octet-stream";

/// The two encodings the beacon API knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// JSON, the default.
    Json,
    /// SSZ bytes, offered by routes that serve consensus objects.
    Ssz,
}

impl Encoding {
    /// The encoding a client prefers among those a route can produce.
    ///
    /// No accept field means JSON.
    /// On equal quality, the type the client named exactly wins over a wildcard, then JSON wins.
    ///
    /// # Errors
    ///
    /// Fails with 406 when the client accepts nothing the route produces.
    pub(crate) fn accepted(request: &Request, ssz_allowed: bool) -> Result<Self, ApiError> {
        let Some(accept) = request.headers.get("accept") else {
            return Ok(Self::Json);
        };
        let json = Preference::of(accept, JSON);
        let ssz = if ssz_allowed {
            Preference::of(accept, SSZ)
        } else {
            Preference::REFUSED
        };
        match (json.acceptable(), ssz.acceptable()) {
            (false, false) => Err(ApiError::not_acceptable(ssz_allowed)),
            (false, true) => Ok(Self::Ssz),
            (true, true) if ssz > json => Ok(Self::Ssz),
            (true, _) => Ok(Self::Json),
        }
    }

    /// The encoding of a request's body.
    ///
    /// No content type means JSON, the API's default.
    ///
    /// # Errors
    ///
    /// Fails with 415 for any other media type, or SSZ where the route takes only JSON.
    pub(crate) fn of_body(request: &Request, ssz_allowed: bool) -> Result<Self, ApiError> {
        let Some(kind) = request.headers.get("content-type") else {
            return Ok(Self::Json);
        };
        // Parameters such as a charset follow the type after a semicolon.
        let kind = kind.split(';').next().unwrap_or_default().trim();
        if kind.eq_ignore_ascii_case(JSON) {
            Ok(Self::Json)
        } else if ssz_allowed && kind.eq_ignore_ascii_case(SSZ) {
            Ok(Self::Ssz)
        } else {
            Err(ApiError::unsupported_media_type(kind))
        }
    }
}

/// How much a client wants one media type: its quality, then how exactly it named the type.
///
/// Qualities are thousandths, as RFC 9110 allows at most three decimals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Preference {
    /// Quality between 0 and 1000.
    quality: u16,
    /// Two for the exact type, one for a subtype wildcard, zero for the full wildcard.
    exactness: u8,
}

impl Preference {
    /// A type the client does not accept.
    const REFUSED: Self = Self {
        quality: 0,
        exactness: 0,
    };

    /// The best preference an accept field gives a media type.
    ///
    /// The most specific matching range decides, per RFC 9110 section 12.5.1.
    fn of(accept: &str, media_type: &str) -> Self {
        let (kind, _) = media_type.split_once('/').unwrap_or((media_type, ""));
        let mut best: Option<Self> = None;
        for range in accept.split(',') {
            let mut parts = range.split(';');
            let name = parts.next().unwrap_or_default().trim();
            let exactness = if name.eq_ignore_ascii_case(media_type) {
                2
            } else if name
                .strip_suffix("/*")
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(kind))
            {
                1
            } else if name == "*/*" {
                0
            } else {
                continue;
            };
            let quality = parts
                .filter_map(|parameter| parameter.trim().strip_prefix("q="))
                .find_map(Self::quality)
                .unwrap_or(1000);
            let preference = Self { quality, exactness };
            // A more specific range overrides a less specific one, whatever their qualities.
            if best.is_none_or(|best| exactness > best.exactness) {
                best = Some(preference);
            }
        }
        best.unwrap_or(Self::REFUSED)
    }

    /// Reads a quality value, such as "0.9", in thousandths.
    fn quality(text: &str) -> Option<u16> {
        let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
        if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let thousandths = format!("{fraction:0<3}").parse::<u16>().ok()?;
        match whole {
            "0" => Some(thousandths),
            "1" if thousandths == 0 => Some(1000),
            _ => None,
        }
    }

    /// Whether the client accepts the type at all.
    const fn acceptable(self) -> bool {
        self.quality > 0
    }
}

#[cfg(test)]
mod tests {
    use axiom_http::Method;

    use super::*;

    fn accepting(accept: &str) -> Request {
        Request::new(Method::Get, "/").with_header("accept", accept)
    }

    #[test]
    fn each_accept_field_picks_its_encoding() {
        let cases = [
            // The spec's own example prefers SSZ by quality.
            (
                "application/octet-stream;q=1.0,application/json;q=0.9",
                Encoding::Ssz,
            ),
            (
                "application/json;q=0.5,application/octet-stream;q=0.6",
                Encoding::Ssz,
            ),
            ("application/octet-stream", Encoding::Ssz),
            ("application/json", Encoding::Json),
            // Wildcards and ties fall back to JSON.
            ("*/*", Encoding::Json),
            ("application/*", Encoding::Json),
            ("application/json,application/octet-stream", Encoding::Json),
            // An exact type beats a wildcard of equal quality.
            ("*/*,application/octet-stream", Encoding::Ssz),
        ];
        for (accept, expected) in cases {
            assert_eq!(
                Encoding::accepted(&accepting(accept), true),
                Ok(expected),
                "{accept}"
            );
        }

        // No accept field at all means JSON.
        assert_eq!(
            Encoding::accepted(&Request::new(Method::Get, "/"), true),
            Ok(Encoding::Json)
        );
    }

    #[test]
    fn nothing_acceptable_is_a_406() {
        // Plain text is not served, and quality zero refuses JSON.
        for accept in ["text/plain", "application/json;q=0"] {
            assert_eq!(
                Encoding::accepted(&accepting(accept), true),
                Err(ApiError::not_acceptable(true)),
                "{accept}"
            );
        }

        // SSZ alone, on a JSON-only route.
        assert_eq!(
            Encoding::accepted(&accepting("application/octet-stream"), false),
            Err(ApiError::not_acceptable(false))
        );
    }

    #[test]
    fn body_types_map_to_encodings() {
        let with = |kind: &str| Request::new(Method::Post, "/").with_header("content-type", kind);
        assert_eq!(
            Encoding::of_body(&with("application/json; charset=utf-8"), true),
            Ok(Encoding::Json)
        );
        assert_eq!(
            Encoding::of_body(&with("application/octet-stream"), true),
            Ok(Encoding::Ssz)
        );
        assert_eq!(
            Encoding::of_body(&with("application/octet-stream"), false),
            Err(ApiError::unsupported_media_type("application/octet-stream"))
        );
        assert_eq!(
            Encoding::of_body(&with("text/plain"), true),
            Err(ApiError::unsupported_media_type("text/plain"))
        );
    }
}
