//! Key exchange groups and the ephemeral secrets of each handshake.

use axiom_crypto::{p256, x25519};

use crate::ProtocolError;

/// A named group code point, per RFC 8446, section 4.2.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    /// secp256r1, the curve P-256.
    pub const SECP256R1: Self = Self(0x0017);
    /// x25519.
    pub const X25519: Self = Self(0x001d);

    /// The groups this stack implements, in preference order.
    ///
    /// X25519 comes first: it is faster, and every TLS 1.3 peer in practice supports it.
    pub const ALL: [Self; 2] = [Self::X25519, Self::SECP256R1];
}

/// One side's ephemeral secret in one group.
///
/// Each secret clears itself when dropped.
#[derive(Debug)]
pub(crate) enum KeyShareSecret {
    /// An X25519 scalar.
    X25519(x25519::SecretKey),
    /// A P-256 scalar.
    P256(p256::SecretKey),
}

impl KeyShareSecret {
    /// The secret of a group drawn from 32 random bytes.
    ///
    /// # Returns
    ///
    /// Nothing for P-256 when the bytes are zero or not below the group order, with odds near 2^-32.
    pub(crate) fn new(group: NamedGroup, bytes: [u8; 32]) -> Option<Self> {
        match group {
            NamedGroup::X25519 => Some(Self::X25519(x25519::SecretKey::from_bytes(bytes))),
            NamedGroup::SECP256R1 => p256::SecretKey::from_bytes(&bytes).ok().map(Self::P256),
            _ => None,
        }
    }

    /// The group.
    pub(crate) const fn group(&self) -> NamedGroup {
        match self {
            Self::X25519(_) => NamedGroup::X25519,
            Self::P256(_) => NamedGroup::SECP256R1,
        }
    }

    /// The public value: 32 bytes for X25519, an uncompressed point for P-256.
    pub(crate) fn public(&self) -> Vec<u8> {
        match self {
            Self::X25519(secret) => secret.public_key().to_bytes().to_vec(),
            Self::P256(secret) => secret.public_key().to_uncompressed().to_vec(),
        }
    }

    /// The shared secret with a peer's public value.
    ///
    /// RFC 8446, section 4.2.8.2: P-256 values are uncompressed points, checked to lie on the curve.
    /// RFC 8446, section 7.4.2: an all-zero X25519 result means a low-order share.
    pub(crate) fn agree(&self, peer: &[u8]) -> Result<[u8; 32], ProtocolError> {
        let invalid = ProtocolError::InvalidKeyShare {
            group: self.group().0,
            length: peer.len(),
        };
        match self {
            Self::X25519(secret) => {
                let peer: [u8; 32] = peer.try_into().map_err(|_| invalid)?;
                let shared = secret
                    .diffie_hellman(&x25519::PublicKey::from_bytes(peer))
                    .map_err(|_| ProtocolError::LowOrderKeyShare)?;
                Ok(*shared.as_bytes())
            }
            Self::P256(secret) => {
                let peer: &[u8; 65] = peer.try_into().map_err(|_| invalid)?;
                let peer = p256::PublicKey::from_uncompressed(peer).map_err(|_| invalid)?;
                Ok(secret.diffie_hellman(&peer).x_coordinate())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_agree() {
        for group in NamedGroup::ALL {
            let a = KeyShareSecret::new(group, [3; 32]).unwrap();
            let b = KeyShareSecret::new(group, [5; 32]).unwrap();
            assert_eq!(a.agree(&b.public()), b.agree(&a.public()), "{group:?}");
        }
    }

    #[test]
    fn malformed_shares_are_refused() {
        let x25519 = KeyShareSecret::new(NamedGroup::X25519, [3; 32]).unwrap();
        let p256 = KeyShareSecret::new(NamedGroup::SECP256R1, [3; 32]).unwrap();
        // Mutation: a 31-byte X25519 share, the all-zero low-order point, and a compressed P-256 point.
        assert_eq!(
            x25519.agree(&[9; 31]),
            Err(ProtocolError::InvalidKeyShare {
                group: 0x001d,
                length: 31
            })
        );
        assert_eq!(x25519.agree(&[0; 32]), Err(ProtocolError::LowOrderKeyShare));
        let compressed = vec![0x02; 33];
        assert_eq!(
            p256.agree(&compressed),
            Err(ProtocolError::InvalidKeyShare {
                group: 0x0017,
                length: 33
            })
        );
        // Mutation: an uncompressed point off the curve.
        let mut off_curve = p256.public();
        off_curve[64] ^= 1;
        assert_eq!(
            p256.agree(&off_curve),
            Err(ProtocolError::InvalidKeyShare {
                group: 0x0017,
                length: 65
            })
        );
        // The P-256 scalar must be below the group order.
        assert!(KeyShareSecret::new(NamedGroup::SECP256R1, [0xff; 32]).is_none());
    }
}
