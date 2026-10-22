//! The TLS 1.2 pseudorandom function over HMAC-SHA256, per RFC 5246, section 5.

use axiom_crypto::hmac::HmacSha256;

/// The TLS 1.2 PRF keyed with a secret.
///
/// ```text
/// PRF(secret, label, seed) = P_SHA256(secret, label || seed)
/// P_SHA256(secret, s)      = HMAC(secret, A(1) || s) || HMAC(secret, A(2) || s) || ...
/// A(0) = s,  A(i) = HMAC(secret, A(i - 1))
/// ```
#[derive(Debug)]
pub(crate) struct Prf<'a> {
    /// The secret.
    secret: &'a [u8],
}

impl<'a> Prf<'a> {
    /// The PRF under a secret.
    pub(crate) const fn new(secret: &'a [u8]) -> Self {
        Self { secret }
    }

    /// Fills an output with PRF(secret, label, seed).
    pub(crate) fn expand(&self, label: &[u8], seed: &[&[u8]], out: &mut [u8]) {
        let mut a = self.mac(
            &[label]
                .into_iter()
                .chain(seed.iter().copied())
                .collect::<Vec<_>>(),
        );
        for chunk in out.chunks_mut(HmacSha256::OUTPUT_LEN) {
            let mut parts: Vec<&[u8]> = vec![&a, label];
            parts.extend_from_slice(seed);
            let block = self.mac(&parts);
            chunk.copy_from_slice(&block[..chunk.len()]);
            a = self.mac(&[&a]);
        }
    }

    /// HMAC-SHA256 under the secret over the concatenated parts.
    fn mac(&self, parts: &[&[u8]]) -> [u8; HmacSha256::OUTPUT_LEN] {
        let mut mac = HmacSha256::new(self.secret);
        for part in parts {
            mac.update(part);
        }
        mac.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes hex.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn known_answer() {
        // The TLS 1.2 PRF-SHA256 test vector published on the IETF TLS list, 100 bytes of output.
        let secret = hex("9bbe436ba940f017b17652849a71db35");
        let seed = hex("a0ba9f936cda311827a6f796ffd5198c");
        let mut out = [0_u8; 100];
        Prf::new(&secret).expand(b"test label", &[&seed], &mut out);
        assert_eq!(
            out.to_vec(),
            hex(concat!(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9",
                "a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082",
                "d122ee42c5a72e5a5110fff70187347b66"
            ))
        );
    }
}
