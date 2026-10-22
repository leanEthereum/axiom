//! Signed deposits, and the deposit data files that carry them to the deposit contract.

use axiom_bls::{PublicKey, Signature};
use axiom_json::{Json, Object};
use axiom_ssz::Ssz;
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, Domain, ExecutionAddress, Gwei, Root, Version,
    constants::{
        BLS_WITHDRAWAL_PREFIX, COMPOUNDING_WITHDRAWAL_PREFIX, DOMAIN_DEPOSIT,
        ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    },
    phase0::{DepositData, DepositMessage, SigningData},
};
use sha2::{Digest, Sha256};

use crate::keys::{DepositError, SecretKeyBytes, fields::Fields, hex::BareHex};

/// Where a validator's withdrawals go, which its withdrawal credentials commit to.
///
/// See "Withdrawal credentials" in the phase0 validator spec, and EIP-7251 for compounding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WithdrawalTarget {
    /// A BLS withdrawal key, by EIP-2334 the parent of the signing key.
    ///
    /// Withdrawals wait until the key signs a change to an execution address.
    Bls(BlsPubkey),
    /// An execution address, paid the excess over the activation balance.
    Execution(ExecutionAddress),
    /// An execution address of a compounding validator, from Electra on.
    Compounding(ExecutionAddress),
}

impl WithdrawalTarget {
    /// The 32-byte withdrawal credentials.
    ///
    /// ```text
    /// Bls(pk)              : 0x00 || SHA256(pk)[1..32]
    /// Execution(address)   : 0x01 || 11 zero bytes || address
    /// Compounding(address) : 0x02 || 11 zero bytes || address
    /// ```
    #[must_use]
    pub fn credentials(&self) -> Bytes32 {
        let mut credentials = [0; 32];
        match self {
            Self::Bls(pubkey) => {
                credentials.copy_from_slice(&Sha256::digest(pubkey.0));
                credentials[0] = BLS_WITHDRAWAL_PREFIX;
            }
            Self::Execution(address) => {
                credentials[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
                credentials[12..].copy_from_slice(&address.0);
            }
            Self::Compounding(address) => {
                credentials[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
                credentials[12..].copy_from_slice(&address.0);
            }
        }
        Bytes32(credentials)
    }
}

/// One entry of a deposit data file: a signed deposit and the network it is meant for.
///
/// The members and their order follow the deposit_data JSON files of the staking deposit CLI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositEntry {
    /// The signed deposit.
    data: DepositData,
    /// The genesis fork version of the network, which the signature commits to.
    fork_version: Version,
    /// The network's name, for people.
    network_name: String,
    /// The tool that wrote the entry.
    cli_version: String,
}

impl DepositEntry {
    /// The tool version this client writes into an entry.
    pub const CLI_VERSION: &'static str = concat!("axiom-", env!("CARGO_PKG_VERSION"));

    /// Signs a deposit of a key, as the deposit contract and the launchpad accept it.
    ///
    /// # Overview
    ///
    /// The signature is a proof of possession over the deposit message.
    /// Its domain has no chain in it, so it verifies before genesis:
    ///
    /// ```text
    /// domain = compute_domain(DOMAIN_DEPOSIT, fork_version, Root::ZERO)
    /// ```
    ///
    /// See "Deposits" in the phase0 validator spec, and the deposit processing of the beacon chain spec.
    #[must_use]
    pub fn sign(
        key: &SecretKeyBytes,
        withdrawal: WithdrawalTarget,
        amount: Gwei,
        fork_version: Version,
        network_name: impl Into<String>,
    ) -> Self {
        let message = DepositMessage {
            pubkey: key.public_key(),
            withdrawal_credentials: withdrawal.credentials(),
            amount,
        };
        let root = Self::signing_root(&message, fork_version);
        let signature = BlsSignature(key.secret_key().sign(&root.0).to_bytes());
        Self {
            data: DepositData {
                pubkey: message.pubkey,
                withdrawal_credentials: message.withdrawal_credentials,
                amount,
                signature,
            },
            fork_version,
            network_name: network_name.into(),
            cli_version: Self::CLI_VERSION.to_owned(),
        }
    }

    /// The signed deposit.
    #[must_use]
    pub const fn data(&self) -> &DepositData {
        &self.data
    }

    /// The part of the deposit the signature covers.
    #[must_use]
    pub const fn message(&self) -> DepositMessage {
        DepositMessage {
            pubkey: self.data.pubkey,
            withdrawal_credentials: self.data.withdrawal_credentials,
            amount: self.data.amount,
        }
    }

    /// The genesis fork version the signature commits to.
    #[must_use]
    pub const fn fork_version(&self) -> Version {
        self.fork_version
    }

    /// The network's name.
    #[must_use]
    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    /// The tool that wrote the entry.
    #[must_use]
    pub fn cli_version(&self) -> &str {
        &self.cli_version
    }

    /// Checks the signature under the deposit domain of the entry's fork version.
    ///
    /// The beacon chain skips a deposit whose signature fails, and its ether stays locked.
    ///
    /// # Errors
    ///
    /// Fails when the key or signature does not decode, or the signature does not verify.
    pub fn verify(&self) -> Result<(), DepositError> {
        let pubkey = self.data.pubkey;
        let key =
            PublicKey::from_bytes(&pubkey.0).map_err(|_| DepositError::InvalidPubkey { pubkey })?;
        let failed = DepositError::Signature {
            pubkey,
            fork_version: self.fork_version,
        };
        let signature =
            Signature::from_bytes(&self.data.signature.0).map_err(|_| failed.clone())?;
        let root = Self::signing_root(&self.message(), self.fork_version);
        if signature.verify(&key, &root.0) {
            Ok(())
        } else {
            Err(failed)
        }
    }

    /// Reads an entry, checking both stored roots against the deposit they describe.
    ///
    /// The signature is not checked here; see the verification method.
    ///
    /// # Errors
    ///
    /// Fails on a missing or malformed member, or a root that does not match.
    pub fn from_json(json: &Json) -> Result<Self, DepositError> {
        let fields = Fields::of(json, "deposit")?;
        let entry = Self {
            data: DepositData {
                pubkey: BlsPubkey(fields.hex_array("pubkey")?),
                withdrawal_credentials: Bytes32(fields.hex_array("withdrawal_credentials")?),
                amount: Gwei(fields.number("amount")?),
                signature: BlsSignature(fields.hex_array("signature")?),
            },
            fork_version: Version(fields.hex_array("fork_version")?),
            network_name: fields.text("network_name")?.to_owned(),
            cli_version: fields.text("deposit_cli_version")?.to_owned(),
        };

        let stored = Root(fields.hex_array("deposit_message_root")?);
        let computed = entry.message().hash_tree_root();
        if stored != computed {
            return Err(DepositError::MessageRoot { stored, computed });
        }
        let stored = Root(fields.hex_array("deposit_data_root")?);
        let computed = entry.data.hash_tree_root();
        if stored != computed {
            return Err(DepositError::DataRoot { stored, computed });
        }
        Ok(entry)
    }

    /// The entry as JSON, members in the order of the staking deposit CLI.
    ///
    /// Hex has no prefix, and the amount is a JSON number of Gwei.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let data = &self.data;
        let mut entry = Object::new();
        entry.insert("pubkey", Json::from(BareHex::encode(&data.pubkey.0)));
        entry.insert(
            "withdrawal_credentials",
            Json::from(BareHex::encode(&data.withdrawal_credentials.0)),
        );
        entry.insert("amount", Json::from(data.amount.0));
        entry.insert("signature", Json::from(BareHex::encode(&data.signature.0)));
        entry.insert(
            "deposit_message_root",
            Json::from(BareHex::encode(&self.message().hash_tree_root().0)),
        );
        entry.insert(
            "deposit_data_root",
            Json::from(BareHex::encode(&data.hash_tree_root().0)),
        );
        entry.insert(
            "fork_version",
            Json::from(BareHex::encode(&self.fork_version.0)),
        );
        entry.insert("network_name", Json::from(self.network_name.as_str()));
        entry.insert("deposit_cli_version", Json::from(self.cli_version.as_str()));
        Json::from(entry)
    }

    /// The root a deposit signature covers: the message root under the pre-genesis domain.
    fn signing_root(message: &DepositMessage, fork_version: Version) -> Root {
        SigningData {
            object_root: message.hash_tree_root(),
            domain: Domain::compute(DOMAIN_DEPOSIT, fork_version, Root::ZERO),
        }
        .hash_tree_root()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axiom_types::{ChainConfig, Mainnet};

    use super::*;
    use crate::{
        keys::{DerivationPath, FieldError, HexError},
        signing::{SigningContext, SigningRequest},
    };

    /// The seed of EIP-2333 test case 0, the BIP-39 seed of "abandon ... about" under TREZOR.
    fn seed() -> Vec<u8> {
        BareHex::decode("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04").unwrap()
    }

    #[test]
    fn the_message_root_matches_an_independent_merkleization() {
        // Fixture state: the first deposit of the deposit CLI's documentation example.
        // The expected root was computed separately, with SHA-256 over the SSZ chunks:
        //
        //     pubkey_root = H(pubkey[0..32], pubkey[32..48] || 16 zero bytes)
        //     root        = H(H(pubkey_root, credentials), H(amount_le || 24 zeros, 32 zeros))
        //
        // The example's own stored root differs: its fields were edited after signing.
        let entry = DepositEntry {
            data: DepositData {
                pubkey: BlsPubkey(BareHex::decode_array("962195958e742b8dc5b2a25adede82fc5cd661827cb1e1237025e3d7847801aa5584d5bfdc6893413264cccfbff54128").unwrap()),
                withdrawal_credentials: Bytes32(BareHex::decode_array("02000000000000000000000000000000219ab540356cBB839Cbe05303d7705Fa").unwrap()),
                amount: Gwei(64_000_000_000),
                signature: BlsSignature([0; 96]),
            },
            fork_version: Version([0; 4]),
            network_name: String::new(),
            cli_version: String::new(),
        };
        assert_eq!(
            BareHex::encode(&entry.message().hash_tree_root().0),
            "e3723860b843008a87ec102c6c7bc731ff9b79a4a0e6033b1f800c3618ca8ca0"
        );
    }

    #[test]
    fn credentials_follow_each_prefix() {
        let address = ExecutionAddress([0xaa; 20]);
        let mut execution = [0; 32];
        execution[0] = 0x01;
        execution[12..].fill(0xaa);
        assert_eq!(
            WithdrawalTarget::Execution(address).credentials(),
            Bytes32(execution)
        );
        execution[0] = 0x02;
        assert_eq!(
            WithdrawalTarget::Compounding(address).credentials(),
            Bytes32(execution)
        );

        // The BLS form keeps 31 bytes of the key's digest behind the zero prefix.
        let pubkey = BlsPubkey([0x11; 48]);
        let digest = Sha256::digest(pubkey.0);
        let credentials = WithdrawalTarget::Bls(pubkey).credentials();
        assert_eq!(credentials.0[0], 0x00);
        assert_eq!(credentials.0[1..], digest[1..]);
    }

    #[test]
    fn a_signed_entry_verifies_and_round_trips() {
        // Fixture state: validator 0 of the seed, BLS withdrawal key per EIP-2334, 32 ETH on mainnet.
        let signing = DerivationPath::validator_signing(0)
            .derive(&seed())
            .unwrap();
        let withdrawal = DerivationPath::validator_withdrawal(0)
            .derive(&seed())
            .unwrap();
        let entry = DepositEntry::sign(
            &signing,
            WithdrawalTarget::Bls(withdrawal.public_key()),
            Gwei(32_000_000_000),
            Version([0; 4]),
            "mainnet",
        );
        assert_eq!(entry.verify(), Ok(()));
        assert_eq!(DepositEntry::from_json(&entry.to_json()), Ok(entry.clone()));

        // The signing context computes the same root from the chain's genesis fork version.
        let context = SigningContext::new(Arc::new(ChainConfig::mainnet()), Root([0x11; 32]));
        let message = entry.message();
        let root = context.signing_root(&SigningRequest::<Mainnet>::Deposit(&message));
        assert_eq!(root, DepositEntry::signing_root(&message, Version([0; 4])));

        // Mutation: the same entry claimed for another network's fork version fails.
        let mut moved = entry;
        moved.fork_version = Version([0x10, 0x00, 0x09, 0x10]);
        assert_eq!(
            moved.verify(),
            Err(DepositError::Signature {
                pubkey: signing.public_key(),
                fork_version: Version([0x10, 0x00, 0x09, 0x10])
            })
        );
    }

    #[test]
    fn stored_roots_must_match_the_deposit() {
        // Mutation: the amount changes after the roots were written.
        let key = DerivationPath::validator_signing(1)
            .derive(&seed())
            .unwrap();
        let entry = DepositEntry::sign(
            &key,
            WithdrawalTarget::Execution(ExecutionAddress([0x22; 20])),
            Gwei(1_000_000_000),
            Version([0; 4]),
            "mainnet",
        );
        let Json::Object(mut object) = entry.to_json() else {
            panic!("an entry is an object");
        };
        object.insert("amount", Json::from(2_000_000_000_u64));
        let mut changed = entry.clone();
        changed.data.amount = Gwei(2_000_000_000);
        assert_eq!(
            DepositEntry::from_json(&Json::from(object.clone())),
            Err(DepositError::MessageRoot {
                stored: entry.message().hash_tree_root(),
                computed: changed.message().hash_tree_root(),
            })
        );

        // Mutation: the message root is fixed up, but the data root still names the old deposit.
        object.insert(
            "deposit_message_root",
            Json::from(BareHex::encode(&changed.message().hash_tree_root().0)),
        );
        assert_eq!(
            DepositEntry::from_json(&Json::from(object.clone())),
            Err(DepositError::DataRoot {
                stored: entry.data.hash_tree_root(),
                computed: changed.data.hash_tree_root(),
            })
        );

        // A 47-byte public key is refused before any root is computed.
        object.insert("pubkey", Json::from("11".repeat(47)));
        assert_eq!(
            DepositEntry::from_json(&Json::from(object)),
            Err(DepositError::Field(FieldError::Hex {
                object: "deposit",
                field: "pubkey",
                source: HexError::Length {
                    expected: 48,
                    actual: 47
                }
            }))
        );
    }
}
