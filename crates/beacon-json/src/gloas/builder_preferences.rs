//! A proposer's preferences for one builder, from the Gloas types of the builder API.

use axiom_json::Json;
use axiom_ssz::{ByteList, Length};
use axiom_types::gloas::{
    BuilderPreferences, BuilderPreferencesEntry, BuilderPreferencesRequest, BuilderRequestAuth,
    SignedBuilderRequestAuth,
};

use crate::{ApiJson, ApiJsonError, ApiJsonErrorKind, reader::Fields};

impl ApiJson for BuilderRequestAuth {
    fn to_json(&self) -> Json {
        Json::from([("data", self.data.to_json()), ("slot", self.slot.to_json())])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            data: fields.required("data")?,
            slot: fields.required("slot")?,
        })
    }
}

impl ApiJson for SignedBuilderRequestAuth {
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

impl ApiJson for BuilderPreferences {
    fn to_json(&self) -> Json {
        Json::from([(
            "max_execution_payment",
            self.max_execution_payment.to_json(),
        )])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            max_execution_payment: fields.required("max_execution_payment")?,
        })
    }
}

impl ApiJson for BuilderPreferencesRequest {
    fn to_json(&self) -> Json {
        Json::from([
            ("preferences", self.preferences.to_json()),
            ("auth", self.auth.to_json()),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        Ok(Self {
            preferences: fields.required("preferences")?,
            auth: fields.required("auth")?,
        })
    }
}

impl ApiJson for BuilderPreferencesEntry {
    /// The URL travels as text, its UTF-8 bytes exactly; every other member as usual.
    fn to_json(&self) -> Json {
        Json::from([
            ("proposer_pubkey", self.proposer_pubkey.to_json()),
            (
                "url",
                Json::from(String::from_utf8_lossy(&self.url).as_ref()),
            ),
            ("auth", self.auth.to_json()),
            (
                "max_execution_payment",
                self.max_execution_payment.to_json(),
            ),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, ApiJsonError> {
        let fields = Fields::of(value)?;
        let url: String = fields.required("url")?;
        Ok(Self {
            proposer_pubkey: fields.required("proposer_pubkey")?,
            url: utf8_list(url).map_err(|error| error.in_member("url"))?,
            auth: fields.required("auth")?,
            max_execution_payment: fields.required("max_execution_payment")?,
        })
    }
}

/// The UTF-8 bytes of a text, within a byte list's limit.
fn utf8_list<N: Length>(text: String) -> Result<ByteList<N>, ApiJsonError> {
    let actual = text.len();
    ByteList::try_from(text.into_bytes()).map_err(|_| {
        ApiJsonError::new(ApiJsonErrorKind::TooLong {
            limit: N::LEN,
            actual,
        })
    })
}

#[cfg(test)]
mod tests {
    use axiom_types::{BlsPubkey, BlsSignature, Gwei, Slot};
    use proptest::prelude::*;

    use super::*;
    use crate::sample::{Sample, Sampler};

    impl Sample for BuilderRequestAuth {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                data: sampler.draw(),
                slot: sampler.draw(),
            }
        }
    }

    impl Sample for SignedBuilderRequestAuth {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                message: sampler.draw(),
                signature: sampler.draw(),
            }
        }
    }

    impl Sample for BuilderPreferences {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                max_execution_payment: sampler.draw(),
            }
        }
    }

    impl Sample for BuilderPreferencesRequest {
        fn sample(sampler: &mut Sampler) -> Self {
            Self {
                preferences: sampler.draw(),
                auth: sampler.draw(),
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn requests_round_trip(seed in any::<u64>()) {
            // Each container, drawn from one seed, survives its JSON form and that form's text.
            let mut sampler = Sampler::new(seed);
            sampler.round_trip::<BuilderRequestAuth>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<SignedBuilderRequestAuth>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<BuilderPreferences>().map_err(TestCaseError::fail)?;
            sampler.round_trip::<BuilderPreferencesRequest>().map_err(TestCaseError::fail)?;
        }
    }

    #[test]
    fn an_entry_reads_its_url_as_text() {
        // The entry of the beacon-APIs example, with a three-byte auth for slot 9.
        let text = format!(
            r#"{{"proposer_pubkey":"0x{}","url":"https://builder.example.com","auth":{{"message":{{"data":"0x010203","slot":"9"}},"signature":"0x{}"}},"max_execution_payment":"1000000000"}}"#,
            "07".repeat(48),
            "05".repeat(96)
        );
        let entry = BuilderPreferencesEntry::from_json(&Json::parse(&text).unwrap()).unwrap();
        let expected = BuilderPreferencesEntry {
            proposer_pubkey: BlsPubkey([7; 48]),
            url: ByteList::try_from(b"https://builder.example.com".as_slice()).unwrap(),
            auth: SignedBuilderRequestAuth {
                message: BuilderRequestAuth {
                    data: ByteList::try_from(vec![1, 2, 3]).unwrap(),
                    slot: Slot(9),
                },
                signature: BlsSignature([5; 96]),
            },
            max_execution_payment: Gwei(1_000_000_000),
        };
        assert_eq!(entry, expected);
        assert_eq!(entry.to_json(), Json::parse(&text).unwrap());

        // A URL of 2049 bytes is one past the limit.
        let long = text.replace(
            "https://builder.example.com",
            &format!("http://{}", "a".repeat(2042)),
        );
        let error = BuilderPreferencesEntry::from_json(&Json::parse(&long).unwrap()).unwrap_err();
        assert_eq!(
            error,
            ApiJsonError::new(ApiJsonErrorKind::TooLong {
                limit: 2048,
                actual: 2049
            })
            .in_member("url")
        );
    }
}
