//! The operation limits of a Gloas block body, which its progressive lists no longer enforce.

use axiom_types::{Preset, gloas::BeaconBlockBody};

use crate::BlockError;

/// A block body, checked against the per-block operation limits.
///
/// Before Gloas each list type carried its limit, so decoding enforced it.
/// Gloas made the lists progressive, so processing checks each limit instead, see EIP-7688.
/// See `process_operations` in the Gloas beacon chain spec.
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
    use axiom_types::{Minimal, gloas::PayloadAttestation};

    use super::*;

    #[test]
    fn a_fifth_payload_attestation_exceeds_the_limit() {
        // The minimal preset allows 4 payload attestations; the body carries 5.
        let mut body = BeaconBlockBody::<Minimal>::default();
        for _ in 0..5 {
            body.payload_attestations
                .push(PayloadAttestation::default());
        }

        assert_eq!(
            BodyLimits(&body).check(),
            Err(BlockError::TooManyOperations {
                operation: "payload attestations",
                count: 5,
                limit: 4,
            })
        );
    }
}
