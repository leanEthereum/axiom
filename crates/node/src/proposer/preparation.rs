//! What validators told the node about their coming proposals.

use std::collections::HashMap;

use axiom_types::{
    BlsPubkey, ExecutionAddress, ValidatorIndex, bellatrix::ValidatorRegistrationV1,
};

/// The gas limit a payload aims for when no validator asked for another.
///
/// It matches the limit execution clients target by default on mainnet.
pub(crate) const DEFAULT_GAS_LIMIT: u64 = 60_000_000;

/// Fee recipients and builder registrations, by validator.
///
/// # Overview
///
/// A validator client names the fee recipient of each of its validators ahead of time.
/// The node then asks its engine to start building before the proposal slot.
/// A builder registration also names the gas limit the validator wants.
///
/// Nothing here is consensus data: a lost entry only falls back to the defaults.
/// See the prepare beacon proposer and register validator routes in beacon-APIs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Preparations {
    /// The fee recipient when a validator named none.
    default_fee_recipient: ExecutionAddress,
    /// Fee recipients by validator index.
    fee_recipients: HashMap<ValidatorIndex, ExecutionAddress>,
    /// Builder registrations by validator key.
    registrations: HashMap<BlsPubkey, ValidatorRegistrationV1>,
}

impl Preparations {
    /// Preparations falling back to a fee recipient.
    pub(crate) fn new(default_fee_recipient: ExecutionAddress) -> Self {
        Self {
            default_fee_recipient,
            ..Self::default()
        }
    }

    /// Records the fee recipient a validator named.
    pub(crate) fn prepare(&mut self, validator: ValidatorIndex, fee_recipient: ExecutionAddress) {
        self.fee_recipients.insert(validator, fee_recipient);
    }

    /// Records a builder registration, keeping the latest by timestamp.
    ///
    /// See `process_registration` in the Bellatrix builder spec.
    pub(crate) fn register(&mut self, registration: ValidatorRegistrationV1) {
        let newer = self
            .registrations
            .get(&registration.pubkey)
            .is_none_or(|known| registration.timestamp >= known.timestamp);
        if newer {
            self.registrations.insert(registration.pubkey, registration);
        }
    }

    /// Whether a validator asked the node to prepare its proposals.
    pub(crate) fn is_prepared(&self, validator: ValidatorIndex) -> bool {
        self.fee_recipients.contains_key(&validator)
    }

    /// The fee recipient of a validator's payload.
    ///
    /// A recipient named for the beacon node wins over one named for builders.
    pub(crate) fn fee_recipient(
        &self,
        validator: ValidatorIndex,
        key: &BlsPubkey,
    ) -> ExecutionAddress {
        self.fee_recipients
            .get(&validator)
            .copied()
            .or_else(|| self.registrations.get(key).map(|known| known.fee_recipient))
            .unwrap_or(self.default_fee_recipient)
    }

    /// The gas limit a validator wants its payloads to aim for.
    pub(crate) fn gas_limit(&self, key: &BlsPubkey) -> u64 {
        self.registrations
            .get(key)
            .map_or(DEFAULT_GAS_LIMIT, |known| known.gas_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration(fee: u8, gas_limit: u64, timestamp: u64) -> ValidatorRegistrationV1 {
        ValidatorRegistrationV1 {
            fee_recipient: ExecutionAddress([fee; 20]),
            gas_limit,
            timestamp,
            pubkey: BlsPubkey([7; 48]),
        }
    }

    #[test]
    fn a_prepared_recipient_wins_over_a_registered_one_and_the_default() {
        // Fixture state: default recipient 0x01..; validator 3 holds key 0x07...
        let mut preparations = Preparations::new(ExecutionAddress([1; 20]));
        let key = BlsPubkey([7; 48]);
        assert_eq!(
            preparations.fee_recipient(ValidatorIndex(3), &key),
            ExecutionAddress([1; 20])
        );

        preparations.register(registration(2, 30_000_000, 10));
        assert_eq!(
            preparations.fee_recipient(ValidatorIndex(3), &key),
            ExecutionAddress([2; 20])
        );
        assert_eq!(preparations.gas_limit(&key), 30_000_000);

        preparations.prepare(ValidatorIndex(3), ExecutionAddress([3; 20]));
        assert_eq!(
            preparations.fee_recipient(ValidatorIndex(3), &key),
            ExecutionAddress([3; 20])
        );
        assert!(preparations.is_prepared(ValidatorIndex(3)));
    }

    #[test]
    fn an_older_registration_does_not_replace_a_newer_one() {
        // Registration at time 20 stays when one from time 10 arrives later.
        let mut preparations = Preparations::default();
        preparations.register(registration(2, 36_000_000, 20));
        preparations.register(registration(9, 1, 10));
        assert_eq!(preparations.gas_limit(&BlsPubkey([7; 48])), 36_000_000);
    }
}
