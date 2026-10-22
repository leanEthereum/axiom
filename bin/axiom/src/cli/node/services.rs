//! The node's servers and its engine: the beacon API, metrics, and the execution endpoint.

use std::{net::SocketAddr, path::PathBuf};

use axiom_http::Cors;
use axiom_node::EngineConfig;

use crate::cli::{Cli, CliError, arguments::Arguments};

/// Default address of the beacon API, the port every client uses.
const DEFAULT_HTTP_ADDRESS: &str = "127.0.0.1:5052";

/// The usage lines of the service flags.
pub(crate) const SERVICE_USAGE: &str = "\
    --http-address <ADDR>        beacon API address [default: 127.0.0.1:5052]
    --no-http                    disable the beacon API
    --staking                    serve the beacon API for a validator client, even with --no-http
    --http-allow-origin <ORIGIN> browser origin admitted to the beacon API, or * for any
                                 [default: the API's own address]
    --metrics-address <ADDR>     Prometheus endpoint address [default: disabled]
    --metrics-allow-origin <ORIGIN>
                                 browser origin admitted to the metrics, or * for any
                                 [default: the endpoint's own address]
    --execution-endpoint <URL>   engine API endpoint, such as http://127.0.0.1:8551
    --jwt-secret <FILE>          hex JWT secret shared with the engine
    --execution-timeout-multiplier <N>
                                 factor on every engine call's timeout [default: 1]
";

/// The service flags as given.
#[derive(Debug, Default)]
pub(crate) struct ServiceFlags {
    /// The beacon API address.
    http_address: Option<SocketAddr>,
    /// Whether the beacon API is off.
    no_http: bool,
    /// Whether the node serves validators, which needs the beacon API.
    staking: bool,
    /// The browser origins the beacon API admits.
    http_allow_origin: Option<Cors>,
    /// The metrics address.
    pub(crate) metrics_address: Option<SocketAddr>,
    /// The browser origins the metrics admit.
    metrics_allow_origin: Option<Cors>,
    /// The engine endpoint.
    execution_endpoint: Option<String>,
    /// The engine secret file.
    jwt_secret: Option<PathBuf>,
    /// Factor on every engine call's timeout.
    timeout_multiplier: Option<u32>,
}

/// What the service flags resolve to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServiceChoice {
    /// The beacon API address, or none.
    pub(crate) http_address: Option<SocketAddr>,
    /// The browser origins the beacon API admits.
    pub(crate) http_allow_origin: Option<Cors>,
    /// The metrics address, or none.
    pub(crate) metrics_address: Option<SocketAddr>,
    /// The browser origins the metrics admit.
    pub(crate) metrics_allow_origin: Option<Cors>,
    /// The engine, or none.
    pub(crate) engine: Option<EngineConfig>,
}

impl ServiceFlags {
    /// Takes a service flag, returning whether the flag was one.
    pub(crate) fn read<I: Iterator<Item = String>>(
        &mut self,
        flag: &str,
        words: &mut Arguments<I>,
    ) -> Result<bool, CliError> {
        match flag {
            "--http-address" => self.http_address = Some(words.parsed("--http-address")?),
            "--no-http" => self.no_http = true,
            "--staking" => self.staking = true,
            "--http-allow-origin" => {
                self.http_allow_origin = Some(Self::origin("--http-allow-origin", words)?);
            }
            "--metrics-address" => self.metrics_address = Some(words.parsed("--metrics-address")?),
            "--metrics-allow-origin" => {
                self.metrics_allow_origin = Some(Self::origin("--metrics-allow-origin", words)?);
            }
            "--execution-endpoint" => {
                self.execution_endpoint = Some(words.value("--execution-endpoint")?);
            }
            "--jwt-secret" => self.jwt_secret = Some(words.path("--jwt-secret")?),
            "--execution-timeout-multiplier" => {
                self.timeout_multiplier = Some(words.parsed("--execution-timeout-multiplier")?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// A cross-origin policy: the wildcard or one origin, such as `http://localhost:3000`.
    fn origin<I: Iterator<Item = String>>(
        flag: &'static str,
        words: &mut Arguments<I>,
    ) -> Result<Cors, CliError> {
        let value = words.value(flag)?;
        Cors::parse(&value).map_err(|_| CliError::InvalidValue { flag, value })
    }

    /// The servers and the engine.
    pub(crate) fn resolve(self) -> Result<ServiceChoice, CliError> {
        let engine = match (self.execution_endpoint, self.jwt_secret) {
            (Some(url), Some(jwt_secret)) => Some(EngineConfig {
                url,
                jwt_secret,
                timeout_multiplier: self.timeout_multiplier.unwrap_or(1),
            }),
            (None, None) => None,
            _ => return Err(CliError::IncompleteEngine),
        };
        // Validators need the API, so staking keeps it on whatever else was asked.
        let http_on = self.staking || !self.no_http;
        let http_address = http_on.then(|| {
            self.http_address
                .unwrap_or_else(|| Cli::default_address(DEFAULT_HTTP_ADDRESS))
        });
        if self.http_allow_origin.is_some() && http_address.is_none() {
            return Err(CliError::Requires {
                flag: "--http-allow-origin",
                needs: "the beacon API",
            });
        }
        if self.metrics_allow_origin.is_some() && self.metrics_address.is_none() {
            return Err(CliError::Requires {
                flag: "--metrics-allow-origin",
                needs: "--metrics-address",
            });
        }
        Ok(ServiceChoice {
            http_address,
            http_allow_origin: self.http_allow_origin,
            metrics_address: self.metrics_address,
            metrics_allow_origin: self.metrics_allow_origin,
            engine,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(words: &[&str]) -> Result<ServiceChoice, CliError> {
        let mut words = Arguments::new(words.iter().map(|word| (*word).to_owned()));
        let mut flags = ServiceFlags::default();
        while let Some(flag) = words.next_flag() {
            assert!(flags.read(&flag, &mut words)?, "{flag}");
        }
        flags.resolve()
    }

    #[test]
    fn staking_keeps_the_api_on() {
        let choice = resolve(&["--no-http", "--staking"]).unwrap();
        assert_eq!(choice.http_address, Some("127.0.0.1:5052".parse().unwrap()));
        assert_eq!(resolve(&["--no-http"]).unwrap().http_address, None);
    }

    #[test]
    fn the_engine_takes_its_multiplier() {
        let choice = resolve(&[
            "--execution-endpoint",
            "http://127.0.0.1:8551",
            "--jwt-secret",
            "jwt.hex",
            "--execution-timeout-multiplier",
            "4",
        ])
        .unwrap();
        assert_eq!(
            choice.engine,
            Some(EngineConfig {
                url: "http://127.0.0.1:8551".to_owned(),
                jwt_secret: "jwt.hex".into(),
                timeout_multiplier: 4,
            })
        );
    }

    #[test]
    fn an_origin_needs_the_api() {
        let choice = resolve(&["--http-allow-origin", "*"]).unwrap();
        assert_eq!(choice.http_allow_origin, Some(Cors::parse("*").unwrap()));
        // A URL with a path is no origin.
        assert!(matches!(
            resolve(&["--http-allow-origin", "http://localhost:3000/app"]),
            Err(CliError::InvalidValue {
                flag: "--http-allow-origin",
                ..
            })
        ));
        assert!(matches!(
            resolve(&["--no-http", "--http-allow-origin", "*"]),
            Err(CliError::Requires {
                flag: "--http-allow-origin",
                ..
            })
        ));
    }

    #[test]
    fn a_metrics_origin_needs_the_metrics() {
        let choice = resolve(&[
            "--metrics-address",
            "127.0.0.1:5054",
            "--metrics-allow-origin",
            "http://grafana.local:3000",
        ])
        .unwrap();
        assert_eq!(
            choice.metrics_allow_origin,
            Some(Cors::parse("http://grafana.local:3000").unwrap())
        );
        assert!(matches!(
            resolve(&["--metrics-allow-origin", "*"]),
            Err(CliError::Requires {
                flag: "--metrics-allow-origin",
                needs: "--metrics-address"
            })
        ));
    }
}
