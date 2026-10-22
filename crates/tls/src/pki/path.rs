//! Path validation: from a server's certificate, through its intermediates, to a trusted root.
//!
//! # Algorithm
//!
//! A depth-first search over issuers, per RFC 5280, section 6, and RFC 4158 on path building.
//! At each step the candidates are the roots, then the intermediates, whose subject is the issuer.
//! A candidate joins the path once its own checks pass and its key verifies the signature below.
//! A failed branch backtracks, so an expired cross-sign does not hide a valid path.
//!
//! # Invariants
//!
//! The search is bounded on every axis an attacker controls:
//!
//! - at most six intermediates in a path;
//! - no certificate twice in one path;
//! - at most 100 signature checks and 200000 candidate steps per verification;
//! - at most 250000 name constraint comparisons per verification.
//!
//! Every input is public, so the search may take variable time.

use super::{CertificateError, RootStore, ServerName};
use crate::{
    der::Timestamp,
    x509::{Certificate, KeyUsage, NameConstraints, PublicKey, Version, X509Error, oid},
};

/// Most intermediates in one path.
///
/// Public web PKI paths hold one to three; the bound stops a peer from forcing deep searches.
pub const MAX_INTERMEDIATES: usize = 6;

/// Most signature checks in one verification, against chains built to exhaust a verifier.
const MAX_SIGNATURES: usize = 100;

/// Most issuer candidates considered in one verification.
const MAX_STEPS: usize = 200_000;

/// Most name and subtree pairs compared in one verification.
///
/// A CA with thousands of subtrees over a leaf with thousands of names is otherwise quadratic.
const MAX_COMPARISONS: usize = 250_000;

/// Extensions this verifier processes, and so may be critical.
const KNOWN_EXTENSIONS: [&[u8]; 6] = [
    oid::KEY_USAGE,
    oid::SUBJECT_ALT_NAME,
    oid::BASIC_CONSTRAINTS,
    oid::NAME_CONSTRAINTS,
    oid::EXTENDED_KEY_USAGE,
    oid::CRL_DISTRIBUTION_POINTS,
];

/// The state of one path search.
#[derive(Debug)]
struct PathSearch<'a, 'c> {
    /// The trusted roots.
    roots: &'a RootStore,
    /// The certificates the peer sent after its own, parsed; unparseable ones are skipped.
    intermediates: Vec<Certificate<'c>>,
    /// The time the path must be valid at.
    now: Timestamp,
    /// Signature checks spent.
    signatures: usize,
    /// Candidates considered.
    steps: usize,
    /// Name and subtree pairs compared.
    comparisons: usize,
}

impl RootStore {
    /// Checks a server's certificate chain and returns the server's key.
    ///
    /// The chain is the server's certificate first, then any intermediates in any order.
    ///
    /// # Errors
    ///
    /// Fails when the server's certificate is unusable or does not name the server,
    /// or when no valid path reaches a root.
    pub fn verify_server(
        &self,
        chain: &[&[u8]],
        name: &ServerName,
        now: Timestamp,
    ) -> Result<PublicKey, CertificateError> {
        let (&leaf, rest) = chain.split_first().ok_or(CertificateError::EmptyChain)?;
        let at_leaf = |source| CertificateError::X509 { depth: 0, source };
        let leaf = Certificate::parse(leaf).map_err(at_leaf)?;
        let key = leaf.public_key().map_err(at_leaf)?;
        PathSearch::check_end_entity(&leaf, now)?;
        if !name.is_named_by(&leaf).map_err(at_leaf)? {
            return Err(CertificateError::NotValidForName);
        }

        let mut search = PathSearch {
            roots: self,
            intermediates: rest
                .iter()
                .filter_map(|der| Certificate::parse(der).ok())
                .collect(),
            now,
            signatures: 0,
            steps: 0,
            comparisons: 0,
        };
        let mut path = vec![leaf];
        search.extend(&mut path)?;
        Ok(key)
    }
}

impl<'c> PathSearch<'_, 'c> {
    /// Finds an issuer for the last certificate of the path, recursing until a root.
    fn extend(&mut self, path: &mut Vec<Certificate<'c>>) -> Result<(), CertificateError> {
        // Invariant: the path starts as the leaf and every pop follows a push.
        let child = path.last().expect("the path always holds the leaf").clone();
        let mut failure = None;

        // Roots end the search at once, so they come first.
        for anchor in self.roots.issuers_of(child.issuer().encoding()) {
            self.step()?;
            match self.accept_root(path, &child, anchor.key(), anchor.name_constraints()) {
                Ok(()) => return Ok(()),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }

        for index in 0..self.intermediates.len() {
            let candidate = self.intermediates[index].clone();
            if candidate.subject() != child.issuer()
                || path.iter().any(|seen| seen.der() == candidate.der())
            {
                continue;
            }
            self.step()?;
            let result = self
                .accept_intermediate(path, &child, &candidate)
                .and_then(|()| {
                    path.push(candidate);
                    let outcome = self.extend(path);
                    path.pop();
                    outcome
                });
            match result {
                Ok(()) => return Ok(()),
                // A spent budget ends the whole search, not just this branch.
                Err(error @ CertificateError::BudgetExceeded) => return Err(error),
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        Err(failure.unwrap_or(CertificateError::UnknownIssuer))
    }

    /// Checks a root issued the last certificate, and that its constraints hold over the path.
    fn accept_root(
        &mut self,
        path: &[Certificate<'c>],
        child: &Certificate<'c>,
        key: &PublicKey,
        constraints: Option<NameConstraints<'_>>,
    ) -> Result<(), CertificateError> {
        let depth = path.len();
        self.verify_signature(child, key, depth - 1)?;
        if let Some(constraints) = constraints {
            self.check_constraints(path, &constraints, depth)?;
        }
        Ok(())
    }

    /// Checks an intermediate may issue the last certificate of the path, and did.
    fn accept_intermediate(
        &mut self,
        path: &[Certificate<'c>],
        child: &Certificate<'c>,
        issuer: &Certificate<'c>,
    ) -> Result<(), CertificateError> {
        let depth = path.len();
        if depth > MAX_INTERMEDIATES {
            return Err(CertificateError::MaxDepthExceeded {
                max: MAX_INTERMEDIATES,
            });
        }
        let at = |source| CertificateError::X509 { depth, source };
        Self::check_common(issuer, depth, self.now)?;
        let extensions = issuer.extensions();

        // RFC 5280, section 4.2.1.9: only a CA certificate may issue others.
        let constraints = extensions.basic_constraints().map_err(at)?;
        let Some(constraints) = constraints.filter(|constraints| constraints.ca) else {
            return Err(CertificateError::EndEntityUsedAsCa { depth });
        };
        if issuer.subject().is_empty() {
            return Err(at(X509Error::InvalidExtension));
        }

        // RFC 5280, section 4.2.1.9: self-issued CAs below do not count towards the limit.
        if let Some(allowed) = constraints.path_len {
            let actual = path[1..]
                .iter()
                .filter(|certificate| !Self::is_self_issued(certificate))
                .count();
            if u64::try_from(actual).map_or(true, |actual| actual > allowed) {
                return Err(CertificateError::PathLenExceeded {
                    depth,
                    allowed,
                    actual,
                });
            }
        }
        if let Some(usage) = extensions.key_usage().map_err(at)?
            && !usage.contains(KeyUsage::KEY_CERT_SIGN)
        {
            return Err(CertificateError::MissingKeyCertSign { depth });
        }
        Self::check_server_auth(issuer, depth)?;

        let key = issuer.public_key().map_err(at)?;
        self.verify_signature(child, &key, depth - 1)?;
        if let Some(name_constraints) = extensions.name_constraints().map_err(at)? {
            self.check_constraints(path, &name_constraints, depth)?;
        }
        Ok(())
    }

    /// The checks the server's own certificate must pass, before any path.
    fn check_end_entity(leaf: &Certificate<'_>, now: Timestamp) -> Result<(), CertificateError> {
        let at = |source| CertificateError::X509 { depth: 0, source };
        Self::check_common(leaf, 0, now)?;
        let extensions = leaf.extensions();
        // RFC 5280, section 4.2.1.10: name constraints belong in CA certificates only.
        if extensions.get(oid::NAME_CONSTRAINTS).is_some() {
            return Err(at(X509Error::InvalidExtension));
        }
        let is_ca = extensions
            .basic_constraints()
            .map_err(at)?
            .is_some_and(|constraints| constraints.ca);
        if is_ca {
            return Err(CertificateError::CaUsedAsEndEntity);
        }
        // RFC 5280, section 4.2.1.3: keyCertSign requires the cA bit.
        if extensions
            .key_usage()
            .map_err(at)?
            .is_some_and(|usage| usage.contains(KeyUsage::KEY_CERT_SIGN))
        {
            return Err(at(X509Error::InvalidExtension));
        }
        // RFC 5280, section 4.2.1.6: an empty subject requires a critical alternative name.
        if leaf.subject().is_empty()
            && !extensions
                .get(oid::SUBJECT_ALT_NAME)
                .is_some_and(|extension| extension.critical)
        {
            return Err(at(X509Error::InvalidExtension));
        }
        // Parse the names now, so a malformed entry fails here rather than in a match.
        extensions.subject_alt_names().map_err(at)?;
        Self::check_server_auth(leaf, 0)
    }

    /// The checks every non-root certificate must pass: version, issuer, dates, and extensions.
    fn check_common(
        certificate: &Certificate<'_>,
        depth: usize,
        now: Timestamp,
    ) -> Result<(), CertificateError> {
        if certificate.version() != Version::V3 {
            return Err(CertificateError::UnsupportedVersion { depth });
        }
        // RFC 5280, section 4.1.2.4: the issuer field is never empty.
        if certificate.issuer().is_empty() {
            return Err(CertificateError::X509 {
                depth,
                source: X509Error::InvalidExtension,
            });
        }
        let validity = certificate.validity();
        if now < validity.not_before {
            return Err(CertificateError::NotYetValid {
                depth,
                not_before: validity.not_before.unix_seconds(),
                now: now.unix_seconds(),
            });
        }
        if now > validity.not_after {
            return Err(CertificateError::Expired {
                depth,
                not_after: validity.not_after.unix_seconds(),
                now: now.unix_seconds(),
            });
        }
        if certificate
            .extensions()
            .iter()
            .any(|extension| extension.critical && !KNOWN_EXTENSIONS.contains(&extension.oid))
        {
            return Err(CertificateError::UnsupportedCriticalExtension { depth });
        }
        Ok(())
    }

    /// Refuses a certificate whose extended key usage excludes server authentication.
    fn check_server_auth(
        certificate: &Certificate<'_>,
        depth: usize,
    ) -> Result<(), CertificateError> {
        let purposes = certificate
            .extensions()
            .extended_key_usage()
            .map_err(|source| CertificateError::X509 { depth, source })?;
        match purposes {
            // RFC 5280, section 4.2.1.12: no extension means any purpose.
            None => Ok(()),
            Some(purposes) if purposes.contains(&oid::SERVER_AUTH) => Ok(()),
            Some(_) => Err(CertificateError::RequiredEkuNotFound { depth }),
        }
    }

    /// Checks a CA's name constraints over every certificate below it.
    ///
    /// RFC 5280, section 6.1.3: a self-issued intermediate is exempt; the server's certificate never is.
    fn check_constraints(
        &mut self,
        path: &[Certificate<'_>],
        constraints: &NameConstraints<'_>,
        depth: usize,
    ) -> Result<(), CertificateError> {
        for (position, certificate) in path.iter().enumerate() {
            if position > 0 && Self::is_self_issued(certificate) {
                continue;
            }
            let at = |source| CertificateError::X509 { depth, source };
            let names = certificate
                .extensions()
                .subject_alt_names()
                .map_err(at)?
                .map_or(0, Iterator::count);
            self.comparisons = self
                .comparisons
                .saturating_add((names + 1).saturating_mul(constraints.subtree_count()));
            if self.comparisons > MAX_COMPARISONS {
                return Err(CertificateError::BudgetExceeded);
            }
            let permitted = constraints
                .permits(certificate)
                .map_err(|source| CertificateError::X509 { depth, source })?;
            if !permitted {
                return Err(CertificateError::NameConstraintViolation { depth });
            }
        }
        Ok(())
    }

    /// Checks a signature under the budget.
    fn verify_signature(
        &mut self,
        certificate: &Certificate<'_>,
        key: &PublicKey,
        depth: usize,
    ) -> Result<(), CertificateError> {
        self.signatures += 1;
        if self.signatures > MAX_SIGNATURES {
            return Err(CertificateError::BudgetExceeded);
        }
        certificate
            .verify_signed_by(key)
            .map_err(|source| CertificateError::X509 { depth, source })
    }

    /// Counts one candidate against the budget.
    const fn step(&mut self) -> Result<(), CertificateError> {
        self.steps += 1;
        if self.steps > MAX_STEPS {
            return Err(CertificateError::BudgetExceeded);
        }
        Ok(())
    }

    /// Whether a certificate's subject and issuer are the same name.
    fn is_self_issued(certificate: &Certificate<'_>) -> bool {
        certificate.subject() == certificate.issuer()
    }
}
