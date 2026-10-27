//! The post-quantum key registry and its leanXMSS signatures, see EIP-8450.

use axiom_json::Json;
use axiom_types::hstar::{
    PendingPqKeyAuthorization, PqKeyAuthorizationRequest, PqKeyRegistration, PqPublicKeys,
    SignedPqKeyRegistration, XmssLayerSignature, XmssSignature,
};

use crate::{
    ApiJson, ApiJsonError,
    reader::{Fields, Reader},
};

impl ApiJson for XmssLayerSignature {
    fn to_json(&self) -> Json {
        Json::from([
            ("randomness", self.randomness.to_json()),
            ("chain_values", self.chain_values.to_json()),
            ("merkle_path", self.merkle_path.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            randomness: fields.required("randomness")?,
            chain_values: fields.required("chain_values")?,
            merkle_path: fields.required("merkle_path")?,
        })
    }
}

impl ApiJson for XmssSignature {
    fn to_json(&self) -> Json {
        Json::from([
            ("leaf_index", self.leaf_index.to_json()),
            ("bottom", self.bottom.to_json()),
            ("top", self.top.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            leaf_index: fields.required("leaf_index")?,
            bottom: fields.required("bottom")?,
            top: fields.required("top")?,
        })
    }
}

impl ApiJson for PqPublicKeys {
    fn to_json(&self) -> Json {
        Json::from([
            ("version", Json::String(self.version.to_string())),
            ("xmss_public_key", self.xmss_public_key.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            version: fields.read("version", Reader::u8)?,
            xmss_public_key: fields.required("xmss_public_key")?,
        })
    }
}

impl ApiJson for PqKeyRegistration {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("public_keys", self.public_keys.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            public_keys: fields.required("public_keys")?,
        })
    }
}

impl ApiJson for SignedPqKeyRegistration {
    fn to_json(&self) -> Json {
        Json::from([
            ("message", self.message.to_json()),
            ("possession", self.possession.to_json()),
            ("signature", self.signature.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            message: fields.required("message")?,
            possession: fields.required("possession")?,
            signature: fields.required("signature")?,
        })
    }
}

impl ApiJson for PqKeyAuthorizationRequest {
    fn to_json(&self) -> Json {
        Json::from([
            ("source_address", self.source_address.to_json()),
            ("validator_pubkey", self.validator_pubkey.to_json()),
            ("public_keys_root", self.public_keys_root.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            source_address: fields.required("source_address")?,
            validator_pubkey: fields.required("validator_pubkey")?,
            public_keys_root: fields.required("public_keys_root")?,
        })
    }
}

impl ApiJson for PendingPqKeyAuthorization {
    fn to_json(&self) -> Json {
        Json::from([
            ("validator_index", self.validator_index.to_json()),
            ("source_address", self.source_address.to_json()),
            ("public_keys_root", self.public_keys_root.to_json()),
            ("expiry_epoch", self.expiry_epoch.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            validator_index: fields.required("validator_index")?,
            source_address: fields.required("source_address")?,
            public_keys_root: fields.required("public_keys_root")?,
            expiry_epoch: fields.required("expiry_epoch")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for XmssLayerSignature {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                randomness: sampler.draw(),
                chain_values: sampler.draw(),
                merkle_path: sampler.draw(),
            }
        }
    }

    impl Sample for XmssSignature {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                leaf_index: sampler.draw(),
                bottom: sampler.draw(),
                top: sampler.draw(),
            }
        }
    }

    impl Sample for PqKeyRegistration {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                validator_index: sampler.draw(),
                public_keys: sampler.draw(),
            }
        }
    }

    impl Sample for SignedPqKeyRegistration {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                possession: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for PqKeyAuthorizationRequest {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                source_address: sampler.draw(),
                validator_pubkey: sampler.draw(),
                public_keys_root: sampler.draw(),
            }
        }
    }

    impl Sample for PendingPqKeyAuthorization {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                validator_index: sampler.draw(),
                source_address: sampler.draw(),
                public_keys_root: sampler.draw(),
                expiry_epoch: sampler.draw(),
            }
        }
    }

    impl Sample for PqPublicKeys {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                // The low byte of a word covers every version.
                version: sampler.word() as u8,
                xmss_public_key: sampler.draw(),
            }
        }
    }

    #[test]
    fn a_version_above_255_is_refused() {
        // The version is a uint8, so "256" overflows its decimal form.
        let json = Json::from([
            ("version", Json::String("256".into())),
            ("xmss_public_key", [0_u8; 32].to_json()),
        ]);
        assert!(PqPublicKeys::from_json(&json).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]

        #[test]
        fn registry_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<XmssLayerSignature>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<XmssSignature>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<PqPublicKeys>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<PqKeyRegistration>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedPqKeyRegistration>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<PqKeyAuthorizationRequest>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<PendingPqKeyAuthorization>().map_err(TestCaseError::fail)?;
        }
    }
}
