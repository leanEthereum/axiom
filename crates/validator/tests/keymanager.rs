//! The keymanager API, driven route by route through its router, without a socket.

use std::{
    env, fs,
    future::Future,
    path::PathBuf,
    process,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axiom_beacon_json::ApiJson;
use axiom_bls::{PublicKey, Signature};
use axiom_http::{HttpError, Method, Request, Router, StatusCode};
use axiom_json::Json;
use axiom_node::ManualClock;
use axiom_types::{
    BlsPubkey, BlsSignature, Bytes32, ChainConfig, Domain, Epoch, ExecutionAddress, Minimal, Root,
    Slot, SlotClock, ValidatorIndex,
    constants::DOMAIN_VOLUNTARY_EXIT,
    phase0::{SigningData, VoluntaryExit},
};
use axiom_validator::{
    duties::SlotTimer,
    keymanager::{KeyDirectory, Keymanager},
    keys::{
        DerivationPath, EncryptionParams, Kdf, Keystore, KeystoreError, Password, SecretKeyBytes,
    },
    protection::{
        Interchange, ProtectionError, Refusal, SignedAttestation, SignedBlock, SlashingDatabase,
        ValidatorHistory, VoteCheck,
    },
    signing::{LocalKey, SigningContext, SigningGuard, ValidatorSigner},
    validators::{
        BuilderConfig, BuilderEntry, DEFAULT_GAS_LIMIT, Graffiti, ProposerDefaults,
        ValidatorSettings, ValidatorStore,
    },
};
use tokio::runtime::Builder;

/// The token every request carries.
const TOKEN: &str = "0123456789abcdef";

/// The chain's genesis validators root.
const GENESIS_VALIDATORS_ROOT: Root = Root([1; 32]);

/// The fee recipient every validator uses unless overridden.
const DEFAULT_FEE_RECIPIENT: ExecutionAddress = ExecutionAddress([0xee; 20]);

/// A keymanager over an empty store and key directory.
struct Fixture {
    /// The routes under test.
    router: Router,
    /// The validators the routes edit.
    store: Arc<ValidatorStore>,
    /// The directory the routes persist to.
    directory: Arc<KeyDirectory>,
    /// The fork schedule.
    config: Arc<ChainConfig>,
}

impl Fixture {
    /// A fresh fixture; with doppelganger detection on, new keys start disabled.
    ///
    /// Fixture state: the minimal preset, every fork up to Fulu from genesis, the clock in slot 17.
    fn new(doppelganger: bool) -> Self {
        let mut config = ChainConfig::minimal();
        config.altair_fork_epoch = Epoch(0);
        config.bellatrix_fork_epoch = Epoch(0);
        config.capella_fork_epoch = Epoch(0);
        config.deneb_fork_epoch = Epoch(0);
        config.electra_fork_epoch = Epoch(0);
        config.fulu_fork_epoch = Epoch(0);
        let config = Arc::new(config);

        let context = SigningContext::new(Arc::clone(&config), GENESIS_VALIDATORS_ROOT);
        let protection = Arc::new(
            SlashingDatabase::in_memory(GENESIS_VALIDATORS_ROOT).expect("an empty database opens"),
        );
        let store = Arc::new(ValidatorStore::new(
            SigningGuard::new(context, protection),
            ProposerDefaults {
                fee_recipient: DEFAULT_FEE_RECIPIENT,
                gas_limit: DEFAULT_GAS_LIMIT,
                ..ProposerDefaults::default()
            },
        ));
        let directory =
            Arc::new(KeyDirectory::open(Self::scratch()).expect("a scratch directory opens"));

        // Six-second slots from genesis at zero: 102 seconds is slot 17, in epoch 2 of 8 slots.
        let clock = ManualClock::at(102_000);
        let timer = SlotTimer::new(Arc::new(clock), SlotClock::new(0, 6_000));
        let router = Keymanager::<Minimal>::new(
            Arc::clone(&store),
            Arc::clone(&directory),
            TOKEN,
            timer,
            doppelganger,
        )
        .router();
        Self {
            router,
            store,
            directory,
            config,
        }
    }

    /// An empty directory of its own for each fixture.
    fn scratch() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!("axiom-keymanager-{}-{id}", process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).expect("a stale scratch directory is removable");
        }
        path
    }

    /// Sends a request with the right token, and returns the status and the parsed body.
    fn call(&self, method: Method, target: &str, body: Option<&Json>) -> (StatusCode, Json) {
        let request =
            Request::new(method, target).with_header("authorization", format!("Bearer {TOKEN}"));
        self.send(match body {
            Some(body) => request.with_body("application/json", body.to_string().into_bytes()),
            None => request,
        })
    }

    /// Sends a request as it is, and returns the status and the parsed body.
    fn send(&self, request: Request) -> (StatusCode, Json) {
        let response = block_on(self.router.handle(request));
        let body = if response.body.is_empty() {
            Json::Null
        } else {
            Json::parse(&response.body).expect("every reply body is JSON")
        };
        (response.status, body)
    }

    /// Runs a key that is already decrypted, as one loaded at startup.
    fn run(&self, n: u8) -> BlsPubkey {
        let key = LocalKey::new(secret(n).secret_key());
        self.store
            .add(ValidatorSigner::Local(key), true)
            .expect("an in-memory database registers keys")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // A failed removal only leaves a scratch directory behind.
        let _removed = fs::remove_dir_all(self.directory.path());
    }
}

/// Runs a future on a fresh runtime, whose blocking pool decrypts keystores.
fn block_on<F: Future>(future: F) -> F::Output {
    Builder::new_current_thread()
        .build()
        .expect("a runtime builds")
        .block_on(future)
}

/// The secret key n.
fn secret(n: u8) -> SecretKeyBytes {
    let mut bytes = [0; 32];
    bytes[31] = n;
    SecretKeyBytes::from_bytes(&bytes).expect("small secrets are valid keys")
}

/// The JSON text of a one-round PBKDF2 keystore of the secret key n, at signing path 0.
fn keystore(n: u8, password: &str) -> String {
    let params = EncryptionParams::random(Kdf::pbkdf2(1).expect("one round is allowed"))
        .expect("entropy is readable");
    Keystore::encrypt(&secret(n), &Password::new(password), &params)
        .with_path(DerivationPath::validator_signing(0))
        .to_json()
        .to_string()
}

/// A JSON array of strings.
fn strings(items: &[&str]) -> Json {
    Json::from(
        items
            .iter()
            .map(|item| Json::from(*item))
            .collect::<Vec<_>>(),
    )
}

/// A data member holding a list of status objects.
fn statuses(items: &[Json]) -> Json {
    Json::from([("data", Json::from(items.to_vec()))])
}

/// A status object without a message.
fn status(name: &str) -> Json {
    Json::from([("status", Json::from(name))])
}

/// A status object with a message.
fn error(message: String) -> Json {
    Json::from([
        ("status", Json::from("error")),
        ("message", Json::from(message)),
    ])
}

/// The keymanager API's error object.
fn message(text: &str) -> Json {
    Json::from([("message", Json::from(text))])
}

/// A body holding a list of public keys.
fn pubkeys(keys: &[BlsPubkey]) -> Json {
    Json::from([(
        "pubkeys",
        Json::from(keys.iter().map(ApiJson::to_json).collect::<Vec<_>>()),
    )])
}

#[test]
fn every_route_requires_the_token() {
    let fixture = Fixture::new(false);

    // No authorization field: 401, even on a route about an unknown key.
    let target = format!("/eth/v1/validator/{}/feerecipient", secret(9).public_key());
    assert_eq!(
        fixture.send(Request::new(Method::Get, &target)),
        (StatusCode::UNAUTHORIZED, message("missing bearer token"))
    );

    // A wrong token: 403.
    let wrong = Request::new(Method::Get, "/eth/v1/keystores")
        .with_header("authorization", "Bearer 0123456789abcdee");
    assert_eq!(
        fixture.send(wrong),
        (StatusCode::FORBIDDEN, message("invalid bearer token"))
    );

    // The right token: the empty key list.
    assert_eq!(
        fixture.call(Method::Get, "/eth/v1/keystores", None),
        (StatusCode::OK, statuses(&[]))
    );
}

#[test]
fn keystores_import_list_and_delete_with_their_history() {
    let fixture = Fixture::new(false);
    let five = secret(5).public_key();
    let six = secret(6).public_key();

    // Fixture state: an interchange with a block and a vote of key 5, and a vote of key 6.
    let history = ValidatorHistory {
        pubkey: five,
        signed_blocks: vec![SignedBlock {
            slot: Slot(9),
            signing_root: Some(Root([9; 32])),
        }],
        signed_attestations: vec![SignedAttestation {
            source_epoch: Epoch(0),
            target_epoch: Epoch(3),
            signing_root: Some(Root([3; 32])),
        }],
    };
    let other = ValidatorHistory {
        pubkey: six,
        signed_blocks: Vec::new(),
        signed_attestations: vec![SignedAttestation {
            source_epoch: Epoch(1),
            target_epoch: Epoch(2),
            signing_root: None,
        }],
    };
    let interchange = Interchange {
        genesis_validators_root: GENESIS_VALIDATORS_ROOT,
        data: vec![history.clone(), other],
    };

    // Import key 5 alone, with the whole interchange.
    let body = Json::from([
        ("keystores", strings(&[&keystore(5, "pw")])),
        ("passwords", strings(&["pw"])),
        (
            "slashing_protection",
            Json::from(interchange.to_json().to_string()),
        ),
    ]);
    assert_eq!(
        fixture.call(Method::Post, "/eth/v1/keystores", Some(&body)),
        (StatusCode::OK, statuses(&[status("imported")]))
    );

    // Only the imported key's history entered the database, and the key signs at once.
    let protection = fixture.store.guard().protection();
    assert!(protection.is_registered(&five));
    assert!(!protection.is_registered(&six));
    assert!(fixture.store.is_enabled(&five));

    // The list shows the key with the derivation path its keystore records.
    let listed = Json::from([
        ("validating_pubkey", five.to_json()),
        ("derivation_path", Json::from("m/12381/3600/0/0/0")),
        ("readonly", Json::from(false)),
    ]);
    assert_eq!(
        fixture.call(Method::Get, "/eth/v1/keystores", None),
        (StatusCode::OK, statuses(&[listed]))
    );

    // Deleting key 5 and an unknown key 6 returns key 5's history alone.
    let exported = Interchange {
        genesis_validators_root: GENESIS_VALIDATORS_ROOT,
        data: vec![history],
    };
    let deleted = |first: &str| {
        Json::from([
            ("data", Json::from(vec![status(first), status("not_found")])),
            (
                "slashing_protection",
                Json::from(exported.to_json().to_string()),
            ),
        ])
    };
    let request = pubkeys(&[five, six]);
    assert_eq!(
        fixture.call(Method::Delete, "/eth/v1/keystores", Some(&request)),
        (StatusCode::OK, deleted("deleted"))
    );
    assert!(!fixture.store.contains(&five));
    assert!(!fixture.directory.holds_keystore(&five));

    // The history stays: a conflicting vote for target 3 is still refused.
    let conflict = VoteCheck {
        pubkey: five,
        source: Epoch(0),
        target: Epoch(3),
        signing_root: Root([4; 32]),
    };
    let refusal = Refusal::DoubleVote {
        pubkey: five,
        target_epoch: Epoch(3),
        recorded: Some(Root([3; 32])),
        asked: Some(Root([4; 32])),
    };
    assert!(matches!(
        protection.check_vote(conflict),
        Err(ProtectionError::Refused(found)) if *found == refusal
    ));

    // A repeated delete finds the key inactive and returns the same history.
    assert_eq!(
        fixture.call(Method::Delete, "/eth/v1/keystores", Some(&request)),
        (StatusCode::OK, deleted("not_active"))
    );
}

#[test]
fn a_repeated_keystore_is_a_duplicate_and_a_wrong_password_an_error() {
    let fixture = Fixture::new(false);
    let five = keystore(5, "pw");

    // Key 5 twice, then key 6 under a wrong password.
    let body = Json::from([
        ("keystores", strings(&[&five, &five, &keystore(6, "pw")])),
        ("passwords", strings(&["pw", "pw", "wrong"])),
    ]);
    let wrong = KeystoreError::WrongPassword;
    assert_eq!(
        fixture.call(Method::Post, "/eth/v1/keystores", Some(&body)),
        (
            StatusCode::OK,
            statuses(&[
                status("imported"),
                status("duplicate"),
                error(format!("cannot decrypt keystore: {wrong}")),
            ])
        )
    );
    // The failed key left no file behind.
    assert!(!fixture.directory.holds_keystore(&secret(6).public_key()));

    // Two keystores with one password is malformed as a whole.
    let body = Json::from([
        ("keystores", strings(&[&five, &five])),
        ("passwords", strings(&["pw"])),
    ]);
    assert_eq!(
        fixture.call(Method::Post, "/eth/v1/keystores", Some(&body)),
        (
            StatusCode::BAD_REQUEST,
            message("2 keystores but 1 passwords")
        )
    );
}

#[test]
fn with_doppelganger_detection_new_keys_wait_disabled() {
    let fixture = Fixture::new(true);
    let body = Json::from([
        ("keystores", strings(&[&keystore(5, "pw")])),
        ("passwords", strings(&["pw"])),
    ]);
    fixture.call(Method::Post, "/eth/v1/keystores", Some(&body));

    // The key runs but may not sign until detection clears it.
    let five = secret(5).public_key();
    assert!(fixture.store.contains(&five));
    assert!(!fixture.store.is_enabled(&five));
}

#[test]
fn a_fee_recipient_override_is_set_read_and_cleared() {
    let fixture = Fixture::new(false);
    let five = fixture.run(5);
    let target = format!("/eth/v1/validator/{five}/feerecipient");
    let reply = |address: ExecutionAddress| {
        Json::from([(
            "data",
            Json::from([
                ("pubkey", five.to_json()),
                ("ethaddress", address.to_json()),
            ]),
        )])
    };

    // Without an override, the default applies.
    assert_eq!(
        fixture.call(Method::Get, &target, None),
        (StatusCode::OK, reply(DEFAULT_FEE_RECIPIENT))
    );

    // An override is accepted, then read back.
    let address = ExecutionAddress([0x11; 20]);
    let body = Json::from([("ethaddress", address.to_json())]);
    assert_eq!(
        fixture.call(Method::Post, &target, Some(&body)),
        (StatusCode::ACCEPTED, Json::Null)
    );
    assert_eq!(
        fixture.call(Method::Get, &target, None),
        (StatusCode::OK, reply(address))
    );

    // The zero address burns fees, so it is refused.
    let zero = Json::from([("ethaddress", ExecutionAddress::default().to_json())]);
    assert_eq!(
        fixture.call(Method::Post, &target, Some(&zero)),
        (
            StatusCode::BAD_REQUEST,
            message("the zero address cannot be a fee recipient")
        )
    );

    // Clearing the override restores the default.
    assert_eq!(
        fixture.call(Method::Delete, &target, None),
        (StatusCode::NO_CONTENT, Json::Null)
    );
    assert_eq!(
        fixture.call(Method::Get, &target, None),
        (StatusCode::OK, reply(DEFAULT_FEE_RECIPIENT))
    );

    // A key the client does not run is not found.
    let six = secret(6).public_key();
    assert_eq!(
        fixture.call(
            Method::Get,
            &format!("/eth/v1/validator/{six}/feerecipient"),
            None
        ),
        (
            StatusCode::NOT_FOUND,
            message(&format!("validator {six} is not managed by this client"))
        )
    );
}

#[test]
fn gas_limit_and_graffiti_overrides_round_trip() {
    let fixture = Fixture::new(false);
    let five = fixture.run(5);
    let gas = format!("/eth/v1/validator/{five}/gas_limit");
    let graffiti = format!("/eth/v1/validator/{five}/graffiti");
    let reply = |name: &str, value: Json| {
        Json::from([(
            "data",
            Json::from([("pubkey", five.to_json()), (name, value)]),
        )])
    };

    // A gas limit of 30 million replaces the default of 60 million, until cleared.
    let body = Json::from([("gas_limit", 30_000_000_u64.to_json())]);
    fixture.call(Method::Post, &gas, Some(&body));
    assert_eq!(
        fixture.call(Method::Get, &gas, None),
        (StatusCode::OK, reply("gas_limit", Json::from("30000000")))
    );
    fixture.call(Method::Delete, &gas, None);
    assert_eq!(
        fixture.call(Method::Get, &gas, None),
        (StatusCode::OK, reply("gas_limit", Json::from("60000000")))
    );

    // Graffiti text is stored zero-padded and read back as the same text, until cleared.
    let body = Json::from([("graffiti", Json::from("axiom"))]);
    assert_eq!(
        fixture.call(Method::Post, &graffiti, Some(&body)),
        (StatusCode::ACCEPTED, Json::Null)
    );
    let mut padded = [0; 32];
    padded[..5].copy_from_slice(b"axiom");
    assert_eq!(fixture.store.graffiti(&five), Graffiti(Bytes32(padded)));
    assert_eq!(
        fixture.call(Method::Get, &graffiti, None),
        (StatusCode::OK, reply("graffiti", Json::from("axiom")))
    );
    fixture.call(Method::Delete, &graffiti, None);
    assert_eq!(
        fixture.call(Method::Get, &graffiti, None),
        (StatusCode::OK, reply("graffiti", Json::from("")))
    );
}

#[test]
fn a_voluntary_exit_verifies_under_the_capella_domain() {
    let fixture = Fixture::new(false);
    let five = fixture.run(5);
    fixture.store.set_index(&five, ValidatorIndex(7));

    // EIP-7044: from Deneb on, every exit is signed under the Capella fork version.
    let domain = Domain::compute(
        DOMAIN_VOLUNTARY_EXIT,
        fixture.config.capella_fork_version,
        GENESIS_VALIDATORS_ROOT,
    );
    let signed = |target: &str, epoch: u64| {
        let (status, body) = fixture.call(Method::Post, target, None);
        assert_eq!(status, StatusCode::OK);
        let data = body.get("data").unwrap();
        let message = VoluntaryExit {
            epoch: Epoch(epoch),
            validator_index: ValidatorIndex(7),
        };
        assert_eq!(
            VoluntaryExit::from_json(data.get("message").unwrap()).unwrap(),
            message
        );
        let signature = BlsSignature::from_json(data.get("signature").unwrap()).unwrap();
        let root = SigningData::signing_root(&message, domain);
        let public = PublicKey::from_bytes(&five.0).unwrap();
        assert!(
            Signature::from_bytes(&signature.0)
                .unwrap()
                .verify(&public, &root.0)
        );
    };

    // An explicit epoch 4, then the default: slot 17 is in epoch 2.
    signed(
        &format!("/eth/v1/validator/{five}/voluntary_exit?epoch=4"),
        4,
    );
    signed(&format!("/eth/v1/validator/{five}/voluntary_exit"), 2);

    // A key whose registry index no beacon node has reported cannot exit yet.
    let six = fixture.run(6);
    assert_eq!(
        fixture.call(
            Method::Post,
            &format!("/eth/v1/validator/{six}/voluntary_exit"),
            None
        ),
        (
            StatusCode::BAD_REQUEST,
            message(&format!(
                "validator {six} has no registry index yet: no beacon node has reported it"
            ))
        )
    );
}

#[test]
fn remote_keys_import_list_and_delete() {
    let fixture = Fixture::new(false);
    let seven = secret(7).public_key();
    let eight = secret(8).public_key();
    let nine = secret(9).public_key();
    let url = "http://127.0.0.1:9000";

    // Key 7 twice, key 8 without a signer, key 9 behind https, which the client does not speak.
    let entry = |pubkey: BlsPubkey, url: Option<&str>| match url {
        Some(url) => Json::from([("pubkey", pubkey.to_json()), ("url", Json::from(url))]),
        None => Json::from([("pubkey", pubkey.to_json())]),
    };
    let body = Json::from([(
        "remote_keys",
        Json::from(vec![
            entry(seven, Some(url)),
            entry(seven, Some(url)),
            entry(eight, None),
            entry(nine, Some("ftp://signer")),
        ]),
    )]);
    assert_eq!(
        fixture.call(Method::Post, "/eth/v1/remotekeys", Some(&body)),
        (
            StatusCode::OK,
            statuses(&[
                status("imported"),
                status("duplicate"),
                error("no remote signer URL given".to_owned()),
                error(format!(
                    "remote signer URL \"ftp://signer\" is not an http or https URL: {}",
                    HttpError::InvalidUrl
                )),
            ])
        )
    );

    // The list shows key 7 with its signer; the local key list stays empty.
    let listed = Json::from([
        ("pubkey", seven.to_json()),
        ("url", Json::from(url)),
        ("readonly", Json::from(false)),
    ]);
    assert_eq!(
        fixture.call(Method::Get, "/eth/v1/remotekeys", None),
        (StatusCode::OK, statuses(&[listed]))
    );
    assert_eq!(
        fixture.call(Method::Get, "/eth/v1/keystores", None),
        (StatusCode::OK, statuses(&[]))
    );

    // Deleting key 7 stops it and forgets its signer; a second delete finds nothing.
    let request = pubkeys(&[seven]);
    assert_eq!(
        fixture.call(Method::Delete, "/eth/v1/remotekeys", Some(&request)),
        (StatusCode::OK, statuses(&[status("deleted")]))
    );
    assert!(!fixture.store.contains(&seven));
    assert!(fixture.directory.remotes().unwrap().is_empty());
    assert_eq!(
        fixture.call(Method::Delete, "/eth/v1/remotekeys", Some(&request)),
        (StatusCode::OK, statuses(&[status("not_found")]))
    );
}

#[test]
fn settings_of_an_imported_key_persist_in_its_definition() {
    let fixture = Fixture::new(false);
    let five = secret(5).public_key();
    let body = Json::from([
        ("keystores", strings(&[&keystore(5, "pw")])),
        ("passwords", strings(&["pw"])),
    ]);
    fixture.call(Method::Post, "/eth/v1/keystores", Some(&body));

    // A gas limit set through the API lands in the key's definition, which a restart reads.
    let gas = Json::from([("gas_limit", 30_000_000_u64.to_json())]);
    assert_eq!(
        fixture.call(
            Method::Post,
            &format!("/eth/v1/validator/{five}/gas_limit"),
            Some(&gas)
        ),
        (StatusCode::ACCEPTED, Json::Null)
    );
    let definitions = fixture.directory.definitions().unwrap();
    assert_eq!(
        definitions.get(&five).unwrap().settings,
        ValidatorSettings {
            gas_limit: Some(30_000_000),
            ..ValidatorSettings::default()
        }
    );
    let reloaded = KeyDirectory::open(fixture.directory.path())
        .unwrap()
        .load()
        .unwrap();
    assert_eq!(reloaded[0].settings.gas_limit, Some(30_000_000));

    // Deleting the key forgets its definition with its keystore.
    fixture.call(Method::Delete, "/eth/v1/keystores", Some(&pubkeys(&[five])));
    assert!(
        fixture
            .directory
            .definitions()
            .unwrap()
            .get(&five)
            .is_none()
    );
}

#[test]
fn a_builder_config_replaces_in_full_and_reads_back_resolved() {
    let fixture = Fixture::new(false);
    let five = fixture.run(5);
    let target = format!("/eth/v1/validator/{five}/builder_config");

    // With no configuration, the client's own resolves: no floor, local preferred, no builders.
    let resolved = |min_bid: &str, factor: &str, builders: Vec<Json>| {
        Json::from([(
            "data",
            Json::from([
                ("min_bid", Json::from(min_bid)),
                ("builder_boost_factor", Json::from(factor)),
                ("builders", Json::from(builders)),
            ]),
        )])
    };
    assert_eq!(
        fixture.call(Method::Get, &target, None),
        (StatusCode::OK, resolved("0", "0", Vec::new()))
    );

    // One builder with a floor of 10; its factor and data resolve from the key and the URL.
    let body = Json::parse(
        r#"{"min_bid":"10","builder_boost_factor":"120",
            "builders":[{"url":"https://builder.example.com/bids"}]}"#,
    )
    .unwrap();
    assert_eq!(
        fixture.call(Method::Post, &target, Some(&body)),
        (StatusCode::ACCEPTED, Json::Null)
    );
    let entry = Json::parse(
        r#"{"url":"https://builder.example.com/bids",
            "auth_data":"0x6275696c6465722e6578616d706c652e636f6d","builder_pubkeys":[],
            "max_execution_payment":"0","min_bid":"10","builder_boost_factor":"120"}"#,
    )
    .unwrap();
    assert_eq!(
        fixture.call(Method::Get, &target, None),
        (StatusCode::OK, resolved("10", "120", vec![entry]))
    );
    assert_eq!(
        fixture.store.overrides(&five).unwrap().builder_config,
        Some(BuilderConfig {
            min_bid: Some(10),
            builder_boost_factor: Some(120),
            builders: Some(vec![BuilderEntry {
                url: "https://builder.example.com/bids".to_owned(),
                auth_data: None,
                builder_pubkeys: None,
                max_execution_payment: None,
                min_bid: None,
                builder_boost_factor: None,
            }]),
        })
    );

    // Two entries with one URL and one implied data are refused, and the stored one stays.
    let twice =
        Json::parse(r#"{"builders":[{"url":"https://b.example"},{"url":"https://b.example"}]}"#)
            .unwrap();
    assert_eq!(
        fixture.call(Method::Post, &target, Some(&twice)),
        (
            StatusCode::BAD_REQUEST,
            message(
                "invalid builder config: builders 0 and 1 share URL \"https://b.example\" and auth_data"
            )
        )
    );

    // Deleting returns the key to the client's configuration.
    assert_eq!(
        fixture.call(Method::Delete, &target, None),
        (StatusCode::NO_CONTENT, Json::Null)
    );
    assert_eq!(
        fixture.call(Method::Get, &target, None),
        (StatusCode::OK, resolved("0", "0", Vec::new()))
    );
}
