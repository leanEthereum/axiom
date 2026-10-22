//! Object identifiers, as the content bytes of their DER encoding.
//!
//! Each is compared byte for byte with what a certificate carries, so no OID is ever decoded.

/// id-ecPublicKey, 1.2.840.10045.2.1, per RFC 5480, section 2.1.1.
pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// prime256v1, the curve P-256, 1.2.840.10045.3.1.7, per RFC 5480, section 2.1.1.1.
pub const PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// secp384r1, the curve P-384, 1.3.132.0.34, per RFC 5480, section 2.1.1.1.
pub const SECP384R1: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];

/// ecdsa-with-SHA256, 1.2.840.10045.4.3.2, per RFC 5758, section 3.2.
pub const ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// ecdsa-with-SHA384, 1.2.840.10045.4.3.3, per RFC 5758, section 3.2.
pub const ECDSA_WITH_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];

/// rsaEncryption, 1.2.840.113549.1.1.1, per RFC 3279, section 2.3.1.
pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// RSASSA-PSS, 1.2.840.113549.1.1.10, per RFC 4055, section 3.1.
pub const RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];

/// id-mgf1, 1.2.840.113549.1.1.8, per RFC 4055, section 2.2.
pub const MGF1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08];

/// sha256WithRSAEncryption, 1.2.840.113549.1.1.11, per RFC 4055, section 5.
pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];

/// sha384WithRSAEncryption, 1.2.840.113549.1.1.12, per RFC 4055, section 5.
pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];

/// sha512WithRSAEncryption, 1.2.840.113549.1.1.13, per RFC 4055, section 5.
pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];

/// id-sha256, 2.16.840.1.101.3.4.2.1, per RFC 4055, section 2.1.
pub const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// id-sha384, 2.16.840.1.101.3.4.2.2, per RFC 4055, section 2.1.
pub const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

/// id-sha512, 2.16.840.1.101.3.4.2.3, per RFC 4055, section 2.1.
pub const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

/// id-ce-keyUsage, 2.5.29.15, per RFC 5280, section 4.2.1.3.
pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

/// id-ce-subjectAltName, 2.5.29.17, per RFC 5280, section 4.2.1.6.
pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];

/// id-ce-basicConstraints, 2.5.29.19, per RFC 5280, section 4.2.1.9.
pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

/// id-ce-nameConstraints, 2.5.29.30, per RFC 5280, section 4.2.1.10.
pub const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];

/// id-ce-cRLDistributionPoints, 2.5.29.31, per RFC 5280, section 4.2.1.13.
pub const CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];

/// id-ce-extKeyUsage, 2.5.29.37, per RFC 5280, section 4.2.1.12.
pub const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

/// anyExtendedKeyUsage, 2.5.29.37.0, per RFC 5280, section 4.2.1.12.
pub const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// id-kp-serverAuth, 1.3.6.1.5.5.7.3.1, per RFC 5280, section 4.2.1.12.
pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// id-at-commonName, 2.5.4.3, per RFC 5280, appendix A.1.
pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// id-at-organizationName, 2.5.4.10, per RFC 5280, appendix A.1.
pub const ORGANIZATION_NAME: &[u8] = &[0x55, 0x04, 0x0a];
