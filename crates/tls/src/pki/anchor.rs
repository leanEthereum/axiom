//! Trust anchors: the roots a client trusts, and the store that holds them.

use crate::{
    PemBlock, PemError,
    x509::{Certificate, NameConstraints, PublicKey, X509Error, oid},
};

/// The PEM label of a certificate.
const CERTIFICATE_LABEL: &str = "CERTIFICATE";

/// A trusted root: a subject name, its key, and any name constraints it carries.
///
/// Only these parts of a root certificate count.
/// Its validity, extensions and self-signature are the trust store's business, not the client's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    /// The subject name's whole encoding.
    subject: Vec<u8>,
    /// The root's public key.
    key: PublicKey,
    /// The value of a name constraints extension, if present.
    name_constraints: Option<Vec<u8>>,
}

impl TrustAnchor {
    /// The anchor a DER certificate defines; version 1 roots are accepted.
    ///
    /// # Errors
    ///
    /// Fails on a malformed certificate or a key this stack cannot verify with.
    pub fn from_der(der: &[u8]) -> Result<Self, X509Error> {
        let certificate = Certificate::parse(der)?;
        let key = certificate.public_key()?;
        let name_constraints = match certificate.extensions().get(oid::NAME_CONSTRAINTS) {
            Some(extension) => {
                // Decode once now, so a malformed constraint never loads.
                NameConstraints::from_der(extension.value)?;
                Some(extension.value.to_vec())
            }
            None => None,
        };
        Ok(Self {
            subject: certificate.subject().encoding().to_vec(),
            key,
            name_constraints,
        })
    }

    /// The subject name's whole encoding.
    #[must_use]
    pub fn subject(&self) -> &[u8] {
        &self.subject
    }

    /// The public key.
    #[must_use]
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The name constraints, if any.
    pub(crate) fn name_constraints(&self) -> Option<NameConstraints<'_>> {
        // Invariant: the value decoded when the anchor was built.
        self.name_constraints
            .as_deref()
            .and_then(|value| NameConstraints::from_der(value).ok())
    }
}

/// The roots a client trusts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RootStore {
    /// The anchors, in the order added.
    anchors: Vec<TrustAnchor>,
}

/// What loading a bundle of roots did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadSummary {
    /// Roots added.
    pub added: usize,
    /// Certificates skipped, because malformed or keyed with an unsupported algorithm.
    pub skipped: usize,
}

impl RootStore {
    /// An empty store.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// Adds one root.
    pub fn add(&mut self, anchor: TrustAnchor) {
        if !self.anchors.contains(&anchor) {
            self.anchors.push(anchor);
        }
    }

    /// Adds every certificate of a PEM bundle, skipping the ones this stack cannot use.
    ///
    /// System bundles hold a few roots with keys this stack does not verify, such as Ed25519.
    /// Skipping them matches how a trust store degrades: those roots simply anchor nothing.
    ///
    /// # Errors
    ///
    /// Fails when the file is not PEM.
    pub fn add_pem_bundle(&mut self, pem: &[u8]) -> Result<LoadSummary, PemError> {
        let mut summary = LoadSummary::default();
        for block in PemBlock::parse_all(pem)? {
            if block.label != CERTIFICATE_LABEL {
                continue;
            }
            match TrustAnchor::from_der(&block.der) {
                Ok(anchor) => {
                    self.add(anchor);
                    summary.added += 1;
                }
                Err(_) => summary.skipped += 1,
            }
        }
        Ok(summary)
    }

    /// The number of roots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.anchors.len()
    }

    /// Whether the store holds no root.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }

    /// The roots whose subject is a given name.
    pub(crate) fn issuers_of<'a>(
        &'a self,
        issuer: &'a [u8],
    ) -> impl Iterator<Item = &'a TrustAnchor> {
        self.anchors
            .iter()
            .filter(move |anchor| anchor.subject == issuer)
    }
}
