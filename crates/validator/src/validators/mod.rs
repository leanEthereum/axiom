//! The validators this client runs: their signers, their proposal settings, and their indices.
//!
//! # Overview
//!
//! Each setting has a client default, which a validator may override.
//! A proposal resolves the two once, when it needs them.
//!
//! - Fee recipient and gas limit pay and size the block.
//! - Graffiti comes from a graffiti file first, then the override, then the default.
//! - Builder settings decide whether a builder's bid may win, and by what margin.

mod builder;
mod error;
mod graffiti;
mod settings;
mod store;
mod yaml;

pub use builder::{
    BuilderConfig, BuilderEntry, MAX_BUILDER_AUTH_DATA_SIZE, MAX_BUILDER_ENTRIES,
    MAX_BUILDER_PUBKEYS, MAX_BUILDER_URL_SIZE, ResolvedBuilderConfig, ResolvedBuilderEntry,
};
pub use error::{BuilderConfigError, FieldError, GraffitiError, GraffitiFileError};
pub use graffiti::{Graffiti, GraffitiFile};
pub use settings::{
    DEFAULT_GAS_LIMIT, NEUTRAL_BOOST_FACTOR, ProposerDefaults, ProposerSettings, ValidatorSettings,
};
pub use store::ValidatorStore;
pub(crate) use yaml::{YamlFields, YamlWriter};
