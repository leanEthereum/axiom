//! How the node builds blocks: fee recipient, graffiti, builders, and payload preparation.

use std::time::Duration;

use axiom_json::Data;
use axiom_node::{BuilderClientSettings, BuilderFallback, ProposerSettings};
use axiom_types::{Bytes32, ExecutionAddress};

use crate::cli::{CliError, arguments::Arguments};

/// The usage lines of the proposer flags.
pub(crate) const PROPOSER_USAGE: &str = "\
    --suggested-fee-recipient <ADDR>
                                 fee recipient when a validator names none
    --graffiti <TEXT>            graffiti when a block request names none, up to 32 bytes
    --builder <URL>              builder API endpoint, such as a relay multiplexer, repeatable
    --builder-header-timeout <MS>
                                 bid deadline, at most 3000 [default: 1000]
    --builder-user-agent <TEXT>  user agent sent to builders [default: axiom/VERSION]
    --builder-fallback-skips <N> missed slots in a row past which builders are not asked
    --builder-fallback-skips-per-epoch <N>
                                 missed slots in the last epoch past which builders are not asked
    --builder-fallback-epochs-since-finalization <N>
                                 epochs without finality past which builders are not asked
    --builder-fallback-disable-checks
                                 ask builders whatever the chain's health
    --prepare-payload-lookahead <MS>
                                 how early a slot's payload is prepared [default: a third of a slot]
    --always-prepare-payload     prepare a payload for every slot, with --suggested-fee-recipient
";

/// The longest bid deadline accepted.
///
/// A proposer waiting past three seconds of a twelve-second slot risks its block arriving too late.
const MAX_HEADER_TIMEOUT: Duration = Duration::from_secs(3);

/// The proposer flags as given.
#[derive(Debug, Default)]
pub(crate) struct ProposerFlags {
    /// The fallback fee recipient.
    fee_recipient: Option<ExecutionAddress>,
    /// The fallback graffiti.
    graffiti: Option<Bytes32>,
    /// Builder endpoints.
    builders: Vec<String>,
    /// The bid deadline.
    header_timeout: Option<Duration>,
    /// The user agent sent to builders.
    user_agent: Option<String>,
    /// Breaker thresholds.
    fallback: BuilderFallback,
    /// How early payloads are prepared.
    lookahead: Option<Duration>,
    /// Whether payloads are prepared for every slot.
    always_prepare: bool,
    /// Whether a builder-specific flag was given, which needs a builder.
    builder_tuned: Option<&'static str>,
}

impl ProposerFlags {
    /// Takes a proposer flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--suggested-fee-recipient" => {
                let text = words.value("--suggested-fee-recipient")?;
                let bytes = <[u8; 20]>::from_data(&text).map_err(|_| CliError::InvalidValue {
                    flag: "--suggested-fee-recipient",
                    value: text,
                })?;
                self.fee_recipient = Some(ExecutionAddress(bytes));
            }
            "--graffiti" => self.graffiti = Some(Self::graffiti(words.value("--graffiti")?)?),
            "--builder" => self.builders.push(words.value("--builder")?),
            "--builder-header-timeout" => {
                let millis: u64 = words.parsed("--builder-header-timeout")?;
                let timeout = Duration::from_millis(millis);
                if timeout > MAX_HEADER_TIMEOUT {
                    return Err(CliError::InvalidValue {
                        flag: "--builder-header-timeout",
                        value: millis.to_string(),
                    });
                }
                self.header_timeout = Some(timeout);
                self.builder_tuned = Some("--builder-header-timeout");
            }
            "--builder-user-agent" => {
                self.user_agent = Some(words.value("--builder-user-agent")?);
                self.builder_tuned = Some("--builder-user-agent");
            }
            "--builder-fallback-skips" => {
                self.fallback.skips = Some(words.parsed("--builder-fallback-skips")?);
            }
            "--builder-fallback-skips-per-epoch" => {
                self.fallback.skips_per_epoch =
                    Some(words.parsed("--builder-fallback-skips-per-epoch")?);
            }
            "--builder-fallback-epochs-since-finalization" => {
                self.fallback.epochs_since_finalization =
                    Some(words.parsed("--builder-fallback-epochs-since-finalization")?);
            }
            "--builder-fallback-disable-checks" => self.fallback.disable_checks = true,
            "--prepare-payload-lookahead" => {
                let millis = words.parsed("--prepare-payload-lookahead")?;
                self.lookahead = Some(Duration::from_millis(millis));
            }
            "--always-prepare-payload" => self.always_prepare = true,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// The proposer settings, checking that each flag has what it needs.
    ///
    /// Builders and the fee recipient serve payloads, so they need an engine.
    pub(crate) fn resolve(self, has_engine: bool) -> Result<ProposerSettings, CliError> {
        if !has_engine {
            if !self.builders.is_empty() {
                return Err(CliError::Requires {
                    flag: "--builder",
                    needs: "--execution-endpoint",
                });
            }
            if self.fee_recipient.is_some() {
                return Err(CliError::Requires {
                    flag: "--suggested-fee-recipient",
                    needs: "--execution-endpoint",
                });
            }
        }
        if let Some(flag) = self.builder_tuned
            && self.builders.is_empty()
        {
            return Err(CliError::Requires {
                flag,
                needs: "--builder",
            });
        }
        if self.always_prepare && self.fee_recipient.is_none() {
            return Err(CliError::Requires {
                flag: "--always-prepare-payload",
                needs: "--suggested-fee-recipient",
            });
        }
        // Builders learn which client asks, as with any HTTP client.
        let user_agent = self
            .user_agent
            .unwrap_or_else(|| format!("axiom/{}", env!("CARGO_PKG_VERSION")));
        Ok(ProposerSettings {
            default_fee_recipient: self.fee_recipient.unwrap_or_default(),
            builder_client: BuilderClientSettings {
                header_timeout: self.header_timeout,
                user_agent: (!self.builders.is_empty()).then_some(user_agent),
            },
            builders: self.builders,
            builder_fallback: self.fallback,
            graffiti: self.graffiti,
            prepare_lookahead: self.lookahead,
            always_prepare_payload: self.always_prepare,
            // The reorg flags have their own group, which sets this.
            ..ProposerSettings::default()
        })
    }

    /// Graffiti text as the 32 bytes a block carries, padded with zeros.
    fn graffiti(text: String) -> Result<Bytes32, CliError> {
        let bytes = text.as_bytes();
        if bytes.len() > 32 {
            return Err(CliError::InvalidValue {
                flag: "--graffiti",
                value: text,
            });
        }
        let mut graffiti = [0; 32];
        graffiti[..bytes.len()].copy_from_slice(bytes);
        Ok(Bytes32(graffiti))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(words: &[&str], has_engine: bool) -> Result<ProposerSettings, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = ProposerFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        flags.resolve(has_engine)
    }

    #[test]
    fn no_flags_build_locally_with_the_zero_recipient() {
        assert_eq!(resolve(&[], false).unwrap(), ProposerSettings::default());
    }

    #[test]
    fn every_proposer_flag_reaches_the_settings() {
        let recipient = "0x00000000219ab540356cbb839cbe05303d7705fa";
        let settings = resolve(
            &[
                "--suggested-fee-recipient",
                recipient,
                "--graffiti",
                "axiom",
                "--builder",
                "http://127.0.0.1:18550",
                "--builder-header-timeout",
                "2500",
                "--builder-user-agent",
                "mev-sidecar",
                "--builder-fallback-skips",
                "5",
                "--builder-fallback-skips-per-epoch",
                "10",
                "--builder-fallback-epochs-since-finalization",
                "6",
                "--prepare-payload-lookahead",
                "8000",
                "--always-prepare-payload",
            ],
            true,
        )
        .unwrap();

        let mut graffiti = [0; 32];
        graffiti[..5].copy_from_slice(b"axiom");
        assert_eq!(
            settings,
            ProposerSettings {
                default_fee_recipient: ExecutionAddress(<[u8; 20]>::from_data(recipient).unwrap()),
                builders: vec!["http://127.0.0.1:18550".to_owned()],
                builder_client: BuilderClientSettings {
                    header_timeout: Some(Duration::from_millis(2500)),
                    user_agent: Some("mev-sidecar".to_owned()),
                },
                builder_fallback: BuilderFallback {
                    skips: Some(5),
                    skips_per_epoch: Some(10),
                    epochs_since_finalization: Some(6),
                    disable_checks: false,
                },
                graffiti: Some(Bytes32(graffiti)),
                prepare_lookahead: Some(Duration::from_secs(8)),
                always_prepare_payload: true,
                ..ProposerSettings::default()
            }
        );
    }

    #[test]
    fn builders_name_the_client_by_default() {
        let settings = resolve(&["--builder", "http://127.0.0.1:18550"], true).unwrap();
        assert_eq!(
            settings.builder_client.user_agent,
            Some(format!("axiom/{}", env!("CARGO_PKG_VERSION")))
        );
    }

    #[test]
    fn flags_without_what_they_need_are_refused() {
        // A builder or a fee recipient without an engine.
        assert!(matches!(
            resolve(&["--builder", "http://127.0.0.1:18550"], false),
            Err(CliError::Requires {
                flag: "--builder",
                needs: "--execution-endpoint"
            })
        ));
        assert!(matches!(
            resolve(
                &[
                    "--suggested-fee-recipient",
                    "0x00000000219ab540356cbb839cbe05303d7705fa"
                ],
                false
            ),
            Err(CliError::Requires {
                flag: "--suggested-fee-recipient",
                needs: "--execution-endpoint"
            })
        ));
        // A builder setting without a builder.
        assert!(matches!(
            resolve(&["--builder-user-agent", "x"], true),
            Err(CliError::Requires {
                flag: "--builder-user-agent",
                needs: "--builder"
            })
        ));
        // Preparing every slot needs someone to pay.
        assert!(matches!(
            resolve(&["--always-prepare-payload"], true),
            Err(CliError::Requires {
                flag: "--always-prepare-payload",
                needs: "--suggested-fee-recipient"
            })
        ));
    }

    #[test]
    fn out_of_range_values_are_refused() {
        // 3001 ms is past the three-second cap; 33 bytes do not fit the graffiti.
        assert!(matches!(
            resolve(&["--builder-header-timeout", "3001"], true),
            Err(CliError::InvalidValue {
                flag: "--builder-header-timeout",
                ..
            })
        ));
        let long = "g".repeat(33);
        assert!(matches!(
            resolve(&["--graffiti", &long], true),
            Err(CliError::InvalidValue {
                flag: "--graffiti",
                ..
            })
        ));
    }
}
