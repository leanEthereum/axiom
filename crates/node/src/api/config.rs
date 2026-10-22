//! The config namespace: every preset and configuration value, the fork schedule, and the deposit contract.

use std::iter;

use axiom_http::Request;
use axiom_json::{Json, Object};
use axiom_types::{
    ChainConfig, ConfigValue, DomainType, Epoch, ForkName, Preset,
    constants::{
        BLS_WITHDRAWAL_PREFIX, BUILDER_WITHDRAWAL_PREFIX, COMPOUNDING_WITHDRAWAL_PREFIX,
        DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_MASK, DOMAIN_BEACON_ATTESTER,
        DOMAIN_BEACON_BUILDER, DOMAIN_BEACON_PROPOSER, DOMAIN_BLS_TO_EXECUTION_CHANGE,
        DOMAIN_BUILDER_DEPOSIT, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_DEPOSIT,
        DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SELECTION_PROOF,
        DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
        ETH1_ADDRESS_WITHDRAWAL_PREFIX, SYNC_COMMITTEE_SUBNET_COUNT,
        TARGET_AGGREGATORS_PER_COMMITTEE, TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    },
};

use super::{
    ApiContext,
    encoding::Encoding,
    reply::{ApiError, ApiResult, Reply, Routes},
};

/// The domain types a signer needs, under their spec names.
///
/// See the domain type tables of each fork's beacon chain spec.
const DOMAINS: [(&str, DomainType); 17] = [
    ("DOMAIN_BEACON_PROPOSER", DOMAIN_BEACON_PROPOSER),
    ("DOMAIN_BEACON_ATTESTER", DOMAIN_BEACON_ATTESTER),
    ("DOMAIN_RANDAO", DOMAIN_RANDAO),
    ("DOMAIN_DEPOSIT", DOMAIN_DEPOSIT),
    ("DOMAIN_VOLUNTARY_EXIT", DOMAIN_VOLUNTARY_EXIT),
    ("DOMAIN_SELECTION_PROOF", DOMAIN_SELECTION_PROOF),
    ("DOMAIN_AGGREGATE_AND_PROOF", DOMAIN_AGGREGATE_AND_PROOF),
    ("DOMAIN_SYNC_COMMITTEE", DOMAIN_SYNC_COMMITTEE),
    (
        "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF",
        DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    ),
    (
        "DOMAIN_CONTRIBUTION_AND_PROOF",
        DOMAIN_CONTRIBUTION_AND_PROOF,
    ),
    (
        "DOMAIN_BLS_TO_EXECUTION_CHANGE",
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
    ),
    ("DOMAIN_BEACON_BUILDER", DOMAIN_BEACON_BUILDER),
    ("DOMAIN_PTC_ATTESTER", DOMAIN_PTC_ATTESTER),
    ("DOMAIN_PROPOSER_PREFERENCES", DOMAIN_PROPOSER_PREFERENCES),
    ("DOMAIN_BUILDER_DEPOSIT", DOMAIN_BUILDER_DEPOSIT),
    ("DOMAIN_APPLICATION_MASK", DOMAIN_APPLICATION_MASK),
    // The application builder domain of the builder API shares the mask's value.
    ("DOMAIN_APPLICATION_BUILDER", DOMAIN_APPLICATION_MASK),
];

/// Withdrawal credential prefixes, one byte each.
///
/// See the withdrawal prefix tables of the phase0, Capella, Electra, and Gloas specs.
const PREFIXES: [(&str, u8); 4] = [
    ("BLS_WITHDRAWAL_PREFIX", BLS_WITHDRAWAL_PREFIX),
    (
        "ETH1_ADDRESS_WITHDRAWAL_PREFIX",
        ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    ),
    (
        "COMPOUNDING_WITHDRAWAL_PREFIX",
        COMPOUNDING_WITHDRAWAL_PREFIX,
    ),
    ("BUILDER_WITHDRAWAL_PREFIX", BUILDER_WITHDRAWAL_PREFIX),
];

/// Validator guide constants that clients read from the spec route.
///
/// See the phase0 and Altair validator guides.
const VALIDATOR_CONSTANTS: [(&str, u64); 3] = [
    (
        "TARGET_AGGREGATORS_PER_COMMITTEE",
        TARGET_AGGREGATORS_PER_COMMITTEE,
    ),
    (
        "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE",
        TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE,
    ),
    ("SYNC_COMMITTEE_SUBNET_COUNT", SYNC_COMMITTEE_SUBNET_COUNT),
];

/// Routes under `/eth/v1/config`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConfigRoutes;

impl ConfigRoutes {
    /// Adds this namespace's routes.
    pub(crate) fn register<P: Preset>(routes: Routes<ApiContext<P>>) -> Routes<ApiContext<P>> {
        routes
            .get("/eth/v1/config/spec", Self::spec::<P>)
            .get("/eth/v1/config/fork_schedule", Self::fork_schedule::<P>)
            .get(
                "/eth/v1/config/deposit_contract",
                Self::deposit_contract::<P>,
            )
    }

    /// Every preset value, configuration value, and signing constant, by spec name.
    async fn spec<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let config = Self::config(&context).await?;
        Ok(Reply::data(Self::spec_object::<P>(&config), None))
    }

    /// The spec object: presets, then configuration, then constants.
    ///
    /// Every scalar is a string, as the beacon API writes them.
    pub(crate) fn spec_object<P: Preset>(config: &ChainConfig) -> Json {
        let mut object = Object::new();
        for (name, value) in P::entries() {
            object.insert(name, Reply::number(value));
        }
        for (name, value) in config.entries(P::NAME) {
            let json = match value {
                ConfigValue::Number(number) => Reply::number(number),
                ConfigValue::Text(text) => Json::from(text),
                ConfigValue::Schedule(schedule) => Json::Array(
                    schedule
                        .into_iter()
                        .map(|(epoch, limit)| {
                            Json::from([
                                ("EPOCH", Reply::number(epoch.0)),
                                ("MAX_BLOBS_PER_BLOCK", Reply::number(limit)),
                            ])
                        })
                        .collect(),
                ),
            };
            object.insert(name, json);
        }
        for (name, domain) in DOMAINS {
            object.insert(name, Reply::text(&domain));
        }
        for (name, prefix) in PREFIXES {
            object.insert(name, Json::from(format!("0x{prefix:02x}")));
        }
        for (name, value) in VALIDATOR_CONSTANTS {
            object.insert(name, Reply::number(value));
        }
        Json::Object(object)
    }

    /// Every fork the configuration schedules, with the version before it.
    async fn fork_schedule<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let config = Self::config(&context).await?;
        let forks = iter::successors(Some(ForkName::Phase0), |fork| fork.next())
            .filter(|fork| config.fork_epoch(*fork) != Epoch::FAR_FUTURE)
            .map(|fork| {
                let previous = fork.previous().unwrap_or(fork);
                Json::from([
                    (
                        "previous_version",
                        Reply::text(&config.fork_version(previous)),
                    ),
                    ("current_version", Reply::text(&config.fork_version(fork))),
                    ("epoch", Reply::number(config.fork_epoch(fork).0)),
                ])
            })
            .collect();
        Ok(Reply::data(Json::Array(forks), None))
    }

    /// The deposit contract's chain and address.
    async fn deposit_contract<P: Preset>(context: ApiContext<P>, request: Request) -> ApiResult {
        Encoding::accepted(&request, false)?;
        let config = Self::config(&context).await?;
        Ok(Reply::data(
            Json::from([
                ("chain_id", Reply::number(config.deposit_chain_id)),
                ("address", Reply::text(&config.deposit_contract_address)),
            ]),
            None,
        ))
    }

    /// The chain's configuration.
    async fn config<P: Preset>(context: &ApiContext<P>) -> Result<ChainConfig, ApiError> {
        context.query(|chain| Ok(chain.config().clone())).await
    }
}
