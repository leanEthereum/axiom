//! Traffic secrets: the per-direction keys each level hands to the transport.

use std::{fmt, hint::black_box};

use axiom_crypto::{hkdf::Hkdf, hmac::HmacSha256};

use super::CipherSuite;

/// The prefix RFC 8446, section 7.1, puts before every label.
const LABEL_PREFIX: &[u8] = b"tls13 ";

/// Longest output HKDF-SHA256 can expand: 255 blocks of 32 bytes.
const MAX_EXPAND_LEN: usize = 255 * 32;

/// A 32-byte traffic secret and the suite whose hash and AEAD it keys.
///
/// Both suites of this stack hash with SHA-256, so every secret is 32 bytes.
/// The bytes clear when dropped.
#[derive(Clone, Eq)]
pub struct TrafficSecret {
    /// The suite the secret belongs to.
    suite: CipherSuite,
    /// The secret.
    secret: [u8; 32],
}

impl TrafficSecret {
    /// Wraps secret bytes under a suite.
    #[must_use]
    pub const fn new(suite: CipherSuite, secret: [u8; 32]) -> Self {
        Self { suite, secret }
    }

    /// The suite the secret belongs to.
    #[must_use]
    pub const fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// The secret bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Fills an output with HKDF-Expand-Label of this secret, per RFC 8446, section 7.1.
    ///
    /// The label is given without the "tls13 " prefix, which the function adds.
    ///
    /// ```text
    /// HkdfLabel = length: u16 || label: <7..255> "tls13 " + label || context: <0..255>
    /// ```
    ///
    /// # Panics
    ///
    /// Panics when the label exceeds 249 bytes, the context 255 bytes, or the output 8160 bytes.
    /// Every label and output of TLS and QUIC is far shorter.
    pub fn expand_label(&self, label: &[u8], context: &[u8], out: &mut [u8]) {
        assert!(
            LABEL_PREFIX.len() + label.len() <= 255 && context.len() <= 255,
            "HKDF label or context exceeds 255 bytes"
        );
        assert!(
            out.len() <= MAX_EXPAND_LEN,
            "HKDF output exceeds 8160 bytes"
        );
        let mut info = Vec::with_capacity(4 + LABEL_PREFIX.len() + label.len() + context.len());
        info.extend_from_slice(&(out.len() as u16).to_be_bytes());
        info.push((LABEL_PREFIX.len() + label.len()) as u8);
        info.extend_from_slice(LABEL_PREFIX);
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        // Invariant: the output length was checked against the HKDF bound above.
        Hkdf::from_prk(self.secret)
            .expand(&info, out)
            .expect("output within the HKDF bound");
    }

    /// The secret derived under a label with an empty context, keeping the suite.
    #[must_use]
    pub fn derive(&self, label: &[u8]) -> Self {
        let mut secret = [0; 32];
        self.expand_label(label, &[], &mut secret);
        Self::new(self.suite, secret)
    }

    /// The verify data of a Finished message over a transcript hash, per RFC 8446, section 4.4.4.
    ///
    /// ```text
    /// finished_key = HKDF-Expand-Label(secret, "finished", "", 32)
    /// verify_data  = HMAC(finished_key, transcript hash)
    /// ```
    pub(crate) fn finished(&self, transcript_hash: &[u8; 32]) -> [u8; 32] {
        self.finished_mac(transcript_hash).finalize()
    }

    /// Whether received verify data matches the transcript, compared in constant time.
    pub(crate) fn verify_finished(&self, transcript_hash: &[u8; 32], received: &[u8; 32]) -> bool {
        self.finished_mac(transcript_hash).verify(received)
    }

    /// The HMAC under the finished key, fed with the transcript hash.
    fn finished_mac(&self, transcript_hash: &[u8; 32]) -> HmacSha256 {
        let mut key = [0_u8; 32];
        self.expand_label(b"finished", &[], &mut key);
        let mut mac = HmacSha256::new(&key);
        key.fill(0);
        black_box(&mut key);
        mac.update(transcript_hash);
        mac
    }
}

impl PartialEq for TrafficSecret {
    fn eq(&self, other: &Self) -> bool {
        // Fold every byte difference, so the time does not reveal where secrets differ.
        let difference = self
            .secret
            .iter()
            .zip(&other.secret)
            .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
        self.suite == other.suite && black_box(difference) == 0
    }
}

impl Drop for TrafficSecret {
    fn drop(&mut self) {
        self.secret.fill(0);
        // The barrier keeps the stores, which the optimizer could otherwise drop before a free.
        black_box(&mut self.secret);
    }
}

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The secret is never printed.
        f.debug_struct("TrafficSecret")
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}

/// The traffic secrets of one level, one per direction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secrets {
    /// Protects what this side sends.
    pub local: TrafficSecret,
    /// Protects what the peer sends.
    pub remote: TrafficSecret,
}
