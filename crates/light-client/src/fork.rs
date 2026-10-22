//! What varies between the forks' light client data: the header, and the containers around it.

use std::fmt::Debug;

use axiom_ssz::{Root, Ssz};
use axiom_types::{ChainConfig, ForkName, Preset, phase0::BeaconBlockHeader};

use crate::{BootstrapData, Execution, Layout, LightClientError, UpdateData};

/// A light client header of one fork's format.
///
/// # Overview
///
/// A header in a later format can describe a block of an earlier fork.
/// The spec's checks then depend on the block's fork, which the caller resolves once.
/// Each format answers for the execution shapes it can describe; the header type does the rest.
pub trait Header<P: Preset>: Clone + Debug + Default + Eq + Send + Sync {
    /// The beacon block header.
    fn beacon(&self) -> &BeaconBlockHeader;

    /// Whether the execution data matches the block body, for a block of the given shape.
    ///
    /// See `is_valid_light_client_header` in the Capella, Deneb, and Gloas sync protocols.
    fn is_valid(&self, execution: Execution) -> bool;

    /// Root of the block's execution payload header, zero before Capella.
    ///
    /// See `get_lc_execution_root` in the Capella, Deneb, and Gloas sync protocols.
    fn execution_root(&self, execution: Execution) -> Root;

    /// Whether the header is valid, resolving its block's shape from the fork schedule.
    fn is_valid_at(&self, config: &ChainConfig) -> bool {
        self.is_valid(Layout::at::<P>(config, self.beacon().slot).execution)
    }

    /// The execution root, resolving the block's shape from the fork schedule.
    fn execution_root_at(&self, config: &ChainConfig) -> Root {
        self.execution_root(Layout::at::<P>(config, self.beacon().slot).execution)
    }
}

/// One fork's light client data format: its containers, and their fields.
///
/// # Overview
///
/// Altair, Capella, Deneb, Electra, and Gloas each define the containers anew.
/// Bellatrix keeps Altair's, and Fulu keeps Electra's.
/// The store's rules are the same for all of them, written once over the fields.
///
/// A trait exists here because five formats are real variation.
pub trait LightClientFork: Copy + Debug + Default + Eq + Send + Sync + 'static {
    /// The fork that introduced the format.
    const FORK: ForkName;

    /// The header.
    type Header<P: Preset>: Header<P> + Ssz;

    /// The bootstrap.
    type Bootstrap<P: Preset>: Clone + Debug + Default + Eq + Ssz;

    /// The update.
    type Update<P: Preset>: Clone + Debug + Default + Eq + Ssz;

    /// The finality update.
    type FinalityUpdate<P: Preset>: Clone + Debug + Default + Eq + Ssz;

    /// The optimistic update.
    type OptimisticUpdate<P: Preset>: Clone + Debug + Default + Eq + Ssz;

    /// The fields of a bootstrap.
    fn bootstrap_data<P: Preset>(
        bootstrap: Self::Bootstrap<P>,
    ) -> BootstrapData<Self::Header<P>, P>;

    /// A bootstrap from its fields, padding the branch to the format's length.
    ///
    /// # Errors
    ///
    /// Fails when the branch is longer than the format's.
    fn bootstrap<P: Preset>(
        data: BootstrapData<Self::Header<P>, P>,
    ) -> Result<Self::Bootstrap<P>, LightClientError>;

    /// The fields of an update.
    fn update_data<P: Preset>(update: Self::Update<P>) -> UpdateData<Self::Header<P>, P>;

    /// An update from its fields, padding the branches to the format's lengths.
    ///
    /// # Errors
    ///
    /// Fails when a branch is longer than the format's.
    fn update<P: Preset>(
        data: UpdateData<Self::Header<P>, P>,
    ) -> Result<Self::Update<P>, LightClientError>;

    /// The fields of a finality update, with no next committee.
    ///
    /// See `process_light_client_finality_update` in the Altair light client sync protocol.
    fn finality_update_data<P: Preset>(
        update: Self::FinalityUpdate<P>,
    ) -> UpdateData<Self::Header<P>, P>;

    /// A finality update from an update's fields, dropping the next committee.
    ///
    /// See `create_light_client_finality_update` in the Altair light client full node spec.
    ///
    /// # Errors
    ///
    /// Fails when the finality branch is longer than the format's.
    fn finality_update<P: Preset>(
        data: UpdateData<Self::Header<P>, P>,
    ) -> Result<Self::FinalityUpdate<P>, LightClientError>;

    /// The fields of an optimistic update, with neither next committee nor finality.
    ///
    /// See `process_light_client_optimistic_update` in the Altair light client sync protocol.
    fn optimistic_update_data<P: Preset>(
        update: Self::OptimisticUpdate<P>,
    ) -> UpdateData<Self::Header<P>, P>;

    /// An optimistic update from an update's fields, keeping the attested header and signature.
    ///
    /// See `create_light_client_optimistic_update` in the Altair light client full node spec.
    fn optimistic_update<P: Preset>(
        data: UpdateData<Self::Header<P>, P>,
    ) -> Self::OptimisticUpdate<P>;
}

/// A format that upgrades the one before it.
///
/// Only the header changes in a way the fork's spec writes out.
/// Containers around it carry their fields over, padding branches to the new lengths.
///
/// See the `upgrade_lc_*` functions of each fork's light client fork logic.
pub trait Upgrade: LightClientFork {
    /// The format this one replaces.
    type Previous: LightClientFork;

    /// The header in this format, for a block of the given shape.
    ///
    /// See `upgrade_lc_header_to_*` in the fork's light client fork logic.
    fn upgrade_header<P: Preset>(
        pre: <Self::Previous as LightClientFork>::Header<P>,
        execution: Execution,
    ) -> Self::Header<P>;

    /// The header in this format, resolving its block's shape from the fork schedule.
    fn upgrade_header_at<P: Preset>(
        pre: <Self::Previous as LightClientFork>::Header<P>,
        config: &ChainConfig,
    ) -> Self::Header<P> {
        let execution = Layout::at::<P>(config, pre.beacon().slot).execution;
        Self::upgrade_header(pre, execution)
    }

    /// A bootstrap in this format.
    ///
    /// # Errors
    ///
    /// Fails when the branch is longer than this format's.
    fn upgrade_bootstrap<P: Preset>(
        pre: <Self::Previous as LightClientFork>::Bootstrap<P>,
        config: &ChainConfig,
    ) -> Result<Self::Bootstrap<P>, LightClientError> {
        let data = Self::Previous::bootstrap_data(pre)
            .map(|header| Self::upgrade_header_at(header, config));
        Self::bootstrap(data)
    }

    /// An update in this format.
    ///
    /// # Errors
    ///
    /// Fails when a branch is longer than this format's.
    fn upgrade_update<P: Preset>(
        pre: <Self::Previous as LightClientFork>::Update<P>,
        config: &ChainConfig,
    ) -> Result<Self::Update<P>, LightClientError> {
        Self::update(Self::upgrade_data(
            Self::Previous::update_data(pre),
            config,
        )?)
    }

    /// A finality update in this format.
    ///
    /// # Errors
    ///
    /// Fails when the branch is longer than this format's.
    fn upgrade_finality_update<P: Preset>(
        pre: <Self::Previous as LightClientFork>::FinalityUpdate<P>,
        config: &ChainConfig,
    ) -> Result<Self::FinalityUpdate<P>, LightClientError> {
        let data = Self::Previous::finality_update_data(pre);
        Self::finality_update(Self::upgrade_data(data, config)?)
    }

    /// An optimistic update in this format.
    ///
    /// # Errors
    ///
    /// Never fails today; the signature matches the other upgrades.
    fn upgrade_optimistic_update<P: Preset>(
        pre: <Self::Previous as LightClientFork>::OptimisticUpdate<P>,
        config: &ChainConfig,
    ) -> Result<Self::OptimisticUpdate<P>, LightClientError> {
        let data = Self::Previous::optimistic_update_data(pre);
        Ok(Self::optimistic_update(Self::upgrade_data(data, config)?))
    }

    /// An update's fields with both headers in this format and branches at this format's lengths.
    ///
    /// # Errors
    ///
    /// Fails when a branch is longer than this format's.
    fn upgrade_data<P: Preset>(
        pre: UpdateData<<Self::Previous as LightClientFork>::Header<P>, P>,
        config: &ChainConfig,
    ) -> Result<UpdateData<Self::Header<P>, P>, LightClientError> {
        let data = pre.map(|header| Self::upgrade_header_at(header, config));
        // A round trip through this format's container pads the branches to its lengths.
        Self::update(data).map(Self::update_data)
    }
}

/// A block that light client data can describe.
pub trait LightClientBlock<P: Preset> {
    /// The format of the block's light client header.
    type Fork: LightClientFork;

    /// The block's light client header, with the execution data its fork commits to.
    ///
    /// See `block_to_light_client_header` in each fork's light client full node spec.
    fn light_client_header(&self) -> <Self::Fork as LightClientFork>::Header<P>;
}
