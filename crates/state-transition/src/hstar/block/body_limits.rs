//! The operation limits of an Hstar block body.

use axiom_types::{Preset, hstar::BeaconBlockBody};

use crate::BlockError;

/// A block body, checked against the per-block operation limits.
///
/// The lists are progressive and carry no bound of their own, so processing checks each limit.
/// Hstar adds the registration limit to Gloas's, see EIP-8450.
#[derive(Clone, Copy, Debug)]
pub struct BodyLimits<'a, P: Preset>(pub &'a BeaconBlockBody<P>);

impl<P: Preset> BodyLimits<'_, P> {
    /// Checks every operation list against its limit.
    ///
    /// # Errors
    ///
    /// Fails at the first list longer than its limit.
    pub fn check(self) -> Result<(), BlockError> {
        let body = self.0;
        let lists = [
            (
                "proposer slashings",
                body.proposer_slashings.len(),
                P::MAX_PROPOSER_SLASHINGS,
            ),
            (
                "attester slashings",
                body.attester_slashings.len(),
                P::MAX_ATTESTER_SLASHINGS_ELECTRA,
            ),
            (
                "attestations",
                body.attestations.len(),
                P::MAX_ATTESTATIONS_ELECTRA,
            ),
            (
                "voluntary exits",
                body.voluntary_exits.len(),
                P::MAX_VOLUNTARY_EXITS,
            ),
            (
                "credential changes",
                body.bls_to_execution_changes.len(),
                P::MAX_BLS_TO_EXECUTION_CHANGES,
            ),
            (
                "payload attestations",
                body.payload_attestations.len(),
                P::MAX_PAYLOAD_ATTESTATIONS,
            ),
            (
                "key registrations",
                body.pq_key_registrations.len(),
                P::MAX_PQ_KEY_REGISTRATIONS,
            ),
        ];
        for (operation, count, limit) in lists {
            if count as u64 > limit {
                return Err(BlockError::TooManyOperations {
                    operation,
                    count,
                    limit,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::{Minimal, hstar::SignedPqKeyRegistration};

    use super::*;

    #[test]
    fn a_ninth_registration_exceeds_the_limit() {
        // Every preset allows 8 registrations per block; the body carries 9.
        let mut body = BeaconBlockBody::<Minimal>::default();
        for _ in 0..9 {
            body.pq_key_registrations
                .push(SignedPqKeyRegistration::default());
        }

        assert_eq!(
            BodyLimits(&body).check(),
            Err(BlockError::TooManyOperations {
                operation: "key registrations",
                count: 9,
                limit: 8,
            })
        );
    }
}
