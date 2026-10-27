//! An Hstar state with real BLS and leanXMSS keys, for the registry's block tests.

use std::sync::LazyLock;

use axiom_bls::SecretKey as BlsSecretKey;
use axiom_ssz::Ssz;
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ChainConfig, Domain, Epoch, ExecutionAddress, Gwei, Minimal,
    Root, ValidatorIndex, XmssLeafIndex, XmssPublicKey,
    constants::{DOMAIN_PQ_KEY_REGISTRATION, G2_POINT_AT_INFINITY, PQ_KEYS_VERSION_1},
    hstar::{BeaconState, PqKeyRegistration, PqPublicKeys, SignedPqKeyRegistration, XmssSignature},
    phase0::{SigningData, Validator},
};
use lean_pq::xmss::SecretKey as XmssSecretKey;

use crate::{
    BlockError, BlockProcessor, CachedState, Caches, Operation, Verification,
    hstar::block::PossessionProof,
};

/// Validators in the fixture registry.
pub(crate) const VALIDATORS: u64 = 4;

/// Epoch the fixture state is at, past genesis so expiry has room on both sides.
pub(crate) const EPOCH: Epoch = Epoch(5);

/// Two leanXMSS keys, generated once per test process.
///
/// Key generation builds a top tree of 2^16 one-time keys, so tests share these two.
static XMSS_KEYS: LazyLock<[XmssSecretKey; 2]> = LazyLock::new(|| {
    [
        XmssSecretKey::from_seed([1; 32]),
        XmssSecretKey::from_seed([2; 32]),
    ]
});

/// The BLS secret key of a fixture validator: the scalar index + 1.
pub(crate) fn bls_key(index: u64) -> BlsSecretKey {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index + 1).to_be_bytes());
    BlsSecretKey::from_bytes(&bytes).expect("small scalars are valid keys")
}

/// The withdrawal address of a fixture validator: twenty bytes of index + 0x10.
pub(crate) fn withdrawal_address(index: u64) -> ExecutionAddress {
    ExecutionAddress([index as u8 + 0x10; 20])
}

/// The registry entry of one of the two fixture leanXMSS keys.
pub(crate) fn keys(key: usize) -> PqPublicKeys {
    PqPublicKeys {
        version: PQ_KEYS_VERSION_1,
        xmss_public_key: XmssPublicKey(XMSS_KEYS[key].public_key().to_bytes()),
    }
}

/// An Hstar state at epoch 5 with four active validators and no registered key.
///
/// Validator `i` has BLS key `i + 1` and 0x01 credentials paying the address `i + 0x10`.
pub(crate) fn state() -> BeaconState<Minimal> {
    let mut state = BeaconState::<Minimal> {
        slot: EPOCH.start_slot::<Minimal>(),
        genesis_validators_root: Root([0x77; 32]),
        ..BeaconState::default()
    };
    for index in 0..VALIDATORS {
        let mut credentials = [0; 32];
        credentials[0] = 0x01;
        credentials[12..].copy_from_slice(&withdrawal_address(index).0);
        let validator = Validator {
            pubkey: BlsPubkey(bls_key(index).public_key().to_bytes()),
            withdrawal_credentials: Bytes32(credentials),
            effective_balance: Gwei(32_000_000_000),
            exit_epoch: Epoch::FAR_FUTURE,
            withdrawable_epoch: Epoch::FAR_FUTURE,
            ..Validator::default()
        };
        state.validators.push(validator);
        state.balances.push(Gwei(32_000_000_000));
        state.pq_public_keys.push(PqPublicKeys::default());
    }
    state
}

/// The chain configuration of the fixture: the minimal one.
pub(crate) fn config() -> ChainConfig {
    ChainConfig::minimal()
}

/// A registration of one of the fixture keys for a validator, with no authority yet.
///
/// The proof of possession is a real leanXMSS signature at the reserved leaf index.
pub(crate) fn registration(
    state: &BeaconState<Minimal>,
    index: u64,
    key: usize,
) -> SignedPqKeyRegistration {
    let message = PqKeyRegistration {
        validator_index: ValidatorIndex(index),
        public_keys: keys(key),
    };
    SignedPqKeyRegistration {
        message,
        possession: possession(state, &message, key, XmssLeafIndex(0)),
        signature: G2_POINT_AT_INFINITY,
    }
}

/// A leanXMSS signature of a registration's signing root by a fixture key at a leaf index.
pub(crate) fn possession(
    state: &BeaconState<Minimal>,
    message: &PqKeyRegistration,
    key: usize,
    leaf_index: XmssLeafIndex,
) -> XmssSignature {
    let placeholder = XmssSignature::default();
    let root = PossessionProof::new(message, &placeholder)
        .signing_root(&config(), state.genesis_validators_root);
    let signature = XMSS_KEYS[key]
        .sign(&root.0, leaf_index.0)
        .expect("2^32 randomizer trials find a codeword");
    XmssSignature::decode(&signature.to_bytes()).expect("leanXMSS bytes are the SSZ layout")
}

/// The same registration, authorized on the operator path by the validator's BLS key.
pub(crate) fn operator_signed(
    state: &BeaconState<Minimal>,
    mut registration: SignedPqKeyRegistration,
) -> SignedPqKeyRegistration {
    let index = registration.message.validator_index.0;
    let domain = Domain::compute(
        DOMAIN_PQ_KEY_REGISTRATION,
        config().genesis_fork_version,
        state.genesis_validators_root,
    );
    let root = SigningData::signing_root(&registration.message, domain);
    registration.signature = BlsSignature(bls_key(index).sign(&root.0).to_bytes());
    registration
}

/// Applies an operation to the state, with every signature checked, as a block would.
pub(crate) fn apply<O: Operation<BeaconState<Minimal>>>(
    state: &mut BeaconState<Minimal>,
    operation: &O,
) -> Result<(), BlockError> {
    let config = config();
    let mut caches = Caches::default();
    let mut processor = BlockProcessor::new(
        CachedState::new(state, &mut caches),
        &config,
        Verification::Verify,
    );
    processor.apply(operation)?;
    processor.finish()
}
