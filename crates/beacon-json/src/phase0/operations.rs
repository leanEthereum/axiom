//! Block headers, slashings, deposits, exits, and the fork record, from the phase0 beacon chain spec.

use axiom_json::Json;
use axiom_types::{
    Preset,
    phase0::{
        AttesterSlashing, BeaconBlockHeader, Deposit, DepositData, Eth1Data, Fork,
        ProposerSlashing, SignedBeaconBlockHeader, SignedVoluntaryExit, VoluntaryExit,
    },
};

use crate::{ApiJson, ApiJsonError, reader::Fields};

impl ApiJson for BeaconBlockHeader {
    fn to_json(&self) -> Json {
        Json::from([
            ("slot", self.slot.to_json()),
            ("proposer_index", self.proposer_index.to_json()),
            ("parent_root", self.parent_root.to_json()),
            ("state_root", self.state_root.to_json()),
            ("body_root", self.body_root.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            slot: fields.required("slot")?,
            proposer_index: fields.required("proposer_index")?,
            parent_root: fields.required("parent_root")?,
            state_root: fields.required("state_root")?,
            body_root: fields.required("body_root")?,
        })
    }
}

impl ApiJson for SignedBeaconBlockHeader {
    fn to_json(&self) -> Json {
        Json::from([
            ("message", self.message.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            message: fields.required("message")?,
            signature: fields.required("signature")?,
        })
    }
}

impl ApiJson for ProposerSlashing {
    fn to_json(&self) -> Json {
        Json::from([
            ("signed_header_1", self.signed_header_1.to_json()),
            ("signed_header_2", self.signed_header_2.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            signed_header_1: fields.required("signed_header_1")?,
            signed_header_2: fields.required("signed_header_2")?,
        })
    }
}

impl<P: Preset> ApiJson for AttesterSlashing<P> {
    fn to_json(&self) -> Json {
        Json::from([
            ("attestation_1", self.attestation_1.to_json()),
            ("attestation_2", self.attestation_2.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            attestation_1: fields.required("attestation_1")?,
            attestation_2: fields.required("attestation_2")?,
        })
    }
}

impl ApiJson for Eth1Data {
    fn to_json(&self) -> Json {
        Json::from([
            ("deposit_root", self.deposit_root.to_json()),
            ("deposit_count", self.deposit_count.to_json()),
            ("block_hash", self.block_hash.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            deposit_root: fields.required("deposit_root")?,
            deposit_count: fields.required("deposit_count")?,
            block_hash: fields.required("block_hash")?,
        })
    }
}

impl ApiJson for DepositData {
    fn to_json(&self) -> Json {
        Json::from([
            ("pubkey", self.pubkey.to_json()),
            (
                "withdrawal_credentials",
                self.withdrawal_credentials.to_json(),
            ),
            ("amount", self.amount.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            pubkey: fields.required("pubkey")?,
            withdrawal_credentials: fields.required("withdrawal_credentials")?,
            amount: fields.required("amount")?,
            signature: fields.required("signature")?,
        })
    }
}

impl ApiJson for Deposit {
    fn to_json(&self) -> Json {
        Json::from([
            ("proof", self.proof.to_json()),
            ("data", self.data.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            proof: fields.required("proof")?,
            data: fields.required("data")?,
        })
    }
}

impl ApiJson for VoluntaryExit {
    fn to_json(&self) -> Json {
        Json::from([
            ("epoch", self.epoch.to_json()),
            ("validator_index", self.validator_index.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            epoch: fields.required("epoch")?,
            validator_index: fields.required("validator_index")?,
        })
    }
}

impl ApiJson for SignedVoluntaryExit {
    fn to_json(&self) -> Json {
        Json::from([
            ("message", self.message.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            message: fields.required("message")?,
            signature: fields.required("signature")?,
        })
    }
}

impl ApiJson for Fork {
    fn to_json(&self) -> Json {
        Json::from([
            ("previous_version", self.previous_version.to_json()),
            ("current_version", self.current_version.to_json()),
            ("epoch", self.epoch.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            previous_version: fields.required("previous_version")?,
            current_version: fields.required("current_version")?,
            epoch: fields.required("epoch")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axiom_types::Minimal;
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for BeaconBlockHeader {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                slot: sampler.draw(),
                proposer_index: sampler.draw(),
                parent_root: sampler.draw(),
                state_root: sampler.draw(),
                body_root: sampler.draw(),
            }
        }
    }

    impl Sample for SignedBeaconBlockHeader {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for ProposerSlashing {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                signed_header_1: sampler.draw(),
                signed_header_2: sampler.draw(),
            }
        }
    }

    impl<P: Preset> Sample for AttesterSlashing<P> {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                attestation_1: sampler.draw(),
                attestation_2: sampler.draw(),
            }
        }
    }

    impl Sample for Eth1Data {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                deposit_root: sampler.draw(),
                deposit_count: sampler.draw(),
                block_hash: sampler.draw(),
            }
        }
    }

    impl Sample for DepositData {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                pubkey: sampler.draw(),
                withdrawal_credentials: sampler.draw(),
                amount: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for Deposit {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                proof: sampler.draw(),
                data: sampler.draw(),
            }
        }
    }

    impl Sample for VoluntaryExit {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                epoch: sampler.draw(),
                validator_index: sampler.draw(),
            }
        }
    }

    impl Sample for SignedVoluntaryExit {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for Fork {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                previous_version: sampler.draw(),
                current_version: sampler.draw(),
                epoch: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn operations_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BeaconBlockHeader>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBeaconBlockHeader>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<ProposerSlashing>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<AttesterSlashing<Minimal>>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<Eth1Data>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<DepositData>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<Deposit>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<VoluntaryExit>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedVoluntaryExit>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<Fork>().map_err(TestCaseError::fail)?;
        }
    }
}
