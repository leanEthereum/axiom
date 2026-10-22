//! The slashing protection database: durable records and the checks over them.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    sync::{Mutex, MutexGuard, PoisonError},
};

use axiom_store::{Batch, Options, Store, Table};
use axiom_types::{BlsPubkey, Epoch, Root, Slot};

use crate::protection::{
    Interchange, ProtectionError, Refusal, Safety, SignedAttestation, SignedBlock,
    ValidatorHistory,
    history::History,
    records::{
        BLOCKS, GENESIS_VALIDATORS_ROOT, META, RecordKey, StoredRoot, StoredVote, VALIDATORS, VOTES,
    },
};

/// A vote to check before signing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VoteCheck {
    /// The attester.
    pub pubkey: BlsPubkey,
    /// Epoch of the source checkpoint.
    pub source: Epoch,
    /// Epoch of the target checkpoint.
    pub target: Epoch,
    /// The root the key would sign.
    pub signing_root: Root,
}

/// What an import added.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ImportSummary {
    /// Validators in the interchange.
    pub validators: usize,
    /// Blocks recorded that the database did not hold.
    pub blocks: usize,
    /// Votes recorded that the database did not hold.
    pub votes: usize,
}

/// The table handles of the database.
#[derive(Clone, Copy, Debug)]
struct Tables {
    /// Registered validators.
    validators: Table,
    /// Signed blocks.
    blocks: Table,
    /// Signed votes.
    votes: Table,
}

/// The EIP-3076 slashing protection database of one chain.
///
/// # Overview
///
/// No key it protects ever signs two slashable messages.
/// That holds against a beacon node that feeds conflicting or surrounding data.
/// It holds across crashes, since a record is on stable storage before its signature exists.
///
/// New messages must move forward past every recorded one, signed here or imported.
/// That is EIP-3076's conditions 1 to 5 applied to the whole history.
///
/// # Invariants
///
/// A check and its record happen under one lock, so two tasks never both pass a conflict.
/// The in-memory history is a superset of the stored one.
/// A failed write leaves extra records in memory, which can only refuse more.
#[derive(Debug)]
pub struct SlashingDatabase {
    /// The durable store.
    store: Store,
    /// Its tables.
    tables: Tables,
    /// The chain this database protects.
    genesis_validators_root: Root,
    /// Every registered validator's history, rebuilt from the store at open.
    histories: Mutex<HashMap<BlsPubkey, History>>,
}

impl SlashingDatabase {
    /// Opens the database of a chain in a directory, creating it if needed.
    ///
    /// # Errors
    ///
    /// Fails when the directory holds another chain's database, a record is corrupt, or the store fails.
    pub fn open(directory: &Path, genesis_validators_root: Root) -> Result<Self, ProtectionError> {
        // The default policy syncs each batch before the write returns.
        Self::over(
            Store::open(directory, Options::default())?,
            genesis_validators_root,
        )
    }

    /// Opens an existing database, for the chain it was created for.
    ///
    /// Tools that export or inspect a database use it, as they may not know the chain.
    ///
    /// # Errors
    ///
    /// Fails when the directory holds no database, a record is corrupt, or the store fails.
    pub fn open_existing(directory: &Path) -> Result<Self, ProtectionError> {
        let store = Store::open(directory, Options::default())?;
        let meta = store.table(META)?;
        let stored = store
            .get(meta, GENESIS_VALIDATORS_ROOT)?
            .ok_or(ProtectionError::Uninitialized)?;
        let root = StoredRoot::decode(&stored, META)?.0.unwrap_or(Root::ZERO);
        Self::over(store, root)
    }

    /// A database in memory only, for tests and simulations.
    ///
    /// # Errors
    ///
    /// Fails only when the store cannot create its tables.
    pub fn in_memory(genesis_validators_root: Root) -> Result<Self, ProtectionError> {
        Self::over(Store::in_memory(), genesis_validators_root)
    }

    /// The database over an open store, bound to a chain.
    fn over(store: Store, genesis_validators_root: Root) -> Result<Self, ProtectionError> {
        let meta = store.table(META)?;
        match store.get(meta, GENESIS_VALIDATORS_ROOT)? {
            None => store.put(meta, GENESIS_VALIDATORS_ROOT, &genesis_validators_root.0)?,
            Some(stored) => {
                let expected = StoredRoot::decode(&stored, META)?.0.unwrap_or(Root::ZERO);
                if expected != genesis_validators_root {
                    return Err(ProtectionError::WrongChain {
                        expected,
                        actual: genesis_validators_root,
                    });
                }
            }
        }
        let tables = Tables {
            validators: store.table(VALIDATORS)?,
            blocks: store.table(BLOCKS)?,
            votes: store.table(VOTES)?,
        };
        let histories = Self::load(&store, tables)?;
        Ok(Self {
            store,
            tables,
            genesis_validators_root,
            histories: Mutex::new(histories),
        })
    }

    /// Rebuilds every validator's history from the store.
    fn load(store: &Store, tables: Tables) -> Result<HashMap<BlsPubkey, History>, ProtectionError> {
        let snapshot = store.snapshot();
        let mut histories = HashMap::new();
        for entry in snapshot.entries(tables.validators)? {
            let (key, _) = entry?;
            histories.insert(
                RecordKey::decode_pubkey(&key, VALIDATORS)?,
                History::default(),
            );
        }
        for entry in snapshot.entries(tables.blocks)? {
            let (key, value) = entry?;
            let (pubkey, slot) = RecordKey::decode(&key, BLOCKS)?;
            histories
                .entry(pubkey)
                .or_default()
                .record_block(Slot(slot), StoredRoot::decode(&value, BLOCKS)?.0);
        }
        for entry in snapshot.entries(tables.votes)? {
            let (key, value) = entry?;
            let (pubkey, target) = RecordKey::decode(&key, VOTES)?;
            let StoredVote { source, root } = StoredVote::decode(&value)?;
            histories
                .entry(pubkey)
                .or_default()
                .record_vote(source, Epoch(target), root);
        }
        Ok(histories)
    }

    /// The chain this database protects.
    #[must_use]
    pub const fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }

    /// Starts protecting keys, which may then sign.
    ///
    /// # Errors
    ///
    /// Fails when the store fails.
    pub fn register(
        &self,
        pubkeys: impl IntoIterator<Item = BlsPubkey>,
    ) -> Result<(), ProtectionError> {
        let mut histories = self.lock();
        let mut batch = Batch::new();
        let mut added = Vec::new();
        for pubkey in pubkeys {
            if !histories.contains_key(&pubkey) && !added.contains(&pubkey) {
                batch.put(self.tables.validators, &pubkey.0, &[])?;
                added.push(pubkey);
            }
        }
        self.store.write(&batch)?;
        for pubkey in added {
            histories.insert(pubkey, History::default());
        }
        drop(histories);
        Ok(())
    }

    /// Whether a key is protected.
    #[must_use]
    pub fn is_registered(&self, pubkey: &BlsPubkey) -> bool {
        self.lock().contains_key(pubkey)
    }

    /// Checks a block and records it durably, before its signature exists.
    ///
    /// # Errors
    ///
    /// Refuses a slashable or unregistered block; fails when the store fails.
    pub fn check_block(
        &self,
        pubkey: &BlsPubkey,
        slot: Slot,
        signing_root: Root,
    ) -> Result<Safety, ProtectionError> {
        let mut histories = self.lock();
        let history = histories
            .get_mut(pubkey)
            .ok_or(Refusal::Unregistered { pubkey: *pubkey })?;
        let safety = history.check_block(*pubkey, slot, signing_root)?;
        if safety == Safety::Fresh {
            history.record_block(slot, Some(signing_root));
            self.store.put(
                self.tables.blocks,
                &RecordKey::new(pubkey, slot.0).0,
                &StoredRoot(Some(signing_root)).encode(),
            )?;
        }
        // The record is durable: other tasks may now check this key.
        drop(histories);
        Ok(safety)
    }

    /// Checks a vote and records it durably, before its signature exists.
    ///
    /// # Errors
    ///
    /// Refuses a slashable or unregistered vote; fails when the store fails.
    pub fn check_vote(&self, check: VoteCheck) -> Result<Safety, ProtectionError> {
        let mut outcomes = self.check_votes(&[check])?;
        // Invariant: one check in, one outcome out.
        let outcome = outcomes.pop().expect("one outcome per check");
        Ok(outcome?)
    }

    /// Checks many votes at once and records the safe ones in one durable write.
    ///
    /// A slot's votes for every key then cost one disk flush instead of one each.
    /// Votes are checked in order, so a later vote also sees the earlier ones.
    ///
    /// # Errors
    ///
    /// Fails when the store fails, in which case no vote may be signed.
    pub fn check_votes(
        &self,
        checks: &[VoteCheck],
    ) -> Result<Vec<Result<Safety, Refusal>>, ProtectionError> {
        let mut histories = self.lock();
        let mut batch = Batch::new();
        let mut outcomes = Vec::with_capacity(checks.len());
        for check in checks {
            let outcome = histories
                .get_mut(&check.pubkey)
                .ok_or(Refusal::Unregistered {
                    pubkey: check.pubkey,
                })
                .and_then(|history| {
                    let safety = history.check_vote(
                        check.pubkey,
                        check.source,
                        check.target,
                        check.signing_root,
                    )?;
                    if safety == Safety::Fresh {
                        history.record_vote(check.source, check.target, Some(check.signing_root));
                    }
                    Ok(safety)
                });
            if outcome == Ok(Safety::Fresh) {
                batch.put(
                    self.tables.votes,
                    &RecordKey::new(&check.pubkey, check.target.0).0,
                    &StoredVote {
                        source: check.source,
                        root: Some(check.signing_root),
                    }
                    .encode(),
                )?;
            }
            outcomes.push(outcome);
        }
        self.store.write(&batch)?;
        // The records are durable: other tasks may now check these keys.
        drop(histories);
        Ok(outcomes)
    }

    /// Imports an interchange, all of it or nothing.
    ///
    /// Each validator in it is registered.
    /// Records the database already holds are skipped.
    ///
    /// # Errors
    ///
    /// Fails when the interchange is for another chain, or is slashable against itself or the database.
    pub fn import(&self, interchange: &Interchange) -> Result<ImportSummary, ProtectionError> {
        if interchange.genesis_validators_root != self.genesis_validators_root {
            return Err(ProtectionError::WrongChain {
                expected: self.genesis_validators_root,
                actual: interchange.genesis_validators_root,
            });
        }
        let mut histories = self.lock();
        // Phase 1: merge into copies, so a slashable entry changes nothing.
        let mut merged: HashMap<BlsPubkey, History> = HashMap::new();
        let mut batch = Batch::new();
        let mut summary = ImportSummary::default();
        for entry in &interchange.data {
            let history = match merged.remove(&entry.pubkey) {
                Some(history) => history,
                None => histories.get(&entry.pubkey).cloned().unwrap_or_default(),
            };
            let history = self.merge(entry, history, &mut batch, &mut summary)?;
            merged.insert(entry.pubkey, history);
        }
        summary.validators = merged.len();

        // Phase 2: one durable write, then the new histories replace the old.
        self.store.write(&batch)?;
        histories.extend(merged);
        drop(histories);
        Ok(summary)
    }

    /// Merges one validator's imported records into its history.
    fn merge(
        &self,
        entry: &ValidatorHistory,
        mut history: History,
        batch: &mut Batch,
        summary: &mut ImportSummary,
    ) -> Result<History, ProtectionError> {
        let pubkey = entry.pubkey;
        batch.put(self.tables.validators, &pubkey.0, &[])?;
        for block in &entry.signed_blocks {
            match history.blocks.get(&block.slot) {
                // The same record is already held.
                Some(recorded) if *recorded == block.signing_root => {}
                Some(&recorded) => {
                    return Err(ProtectionError::SlashableImport(Box::new(
                        Refusal::DoubleProposal {
                            pubkey,
                            slot: block.slot,
                            recorded,
                            asked: block.signing_root,
                        },
                    )));
                }
                None => {
                    history.record_block(block.slot, block.signing_root);
                    batch.put(
                        self.tables.blocks,
                        &RecordKey::new(&pubkey, block.slot.0).0,
                        &StoredRoot(block.signing_root).encode(),
                    )?;
                    summary.blocks += 1;
                }
            }
        }
        for vote in &entry.signed_attestations {
            let (source, target) = (vote.source_epoch, vote.target_epoch);
            let safety = history
                .check_imported_vote(pubkey, source, target, vote.signing_root)
                .map_err(|refusal| ProtectionError::SlashableImport(Box::new(refusal)))?;
            if safety == Safety::Repeat {
                continue;
            }
            history.record_vote(source, target, vote.signing_root);
            batch.put(
                self.tables.votes,
                &RecordKey::new(&pubkey, target.0).0,
                &StoredVote {
                    source,
                    root: vote.signing_root,
                }
                .encode(),
            )?;
            summary.votes += 1;
        }
        Ok(history)
    }

    /// Exports the history of some keys, or of every key, in the interchange format.
    #[must_use]
    pub fn export(&self, pubkeys: Option<&[BlsPubkey]>) -> Interchange {
        let histories = self.lock();
        let selected: BTreeSet<BlsPubkey> = match pubkeys {
            Some(pubkeys) => pubkeys
                .iter()
                .filter(|pubkey| histories.contains_key(pubkey))
                .copied()
                .collect(),
            None => histories.keys().copied().collect(),
        };
        let data = selected
            .into_iter()
            .filter_map(|pubkey| {
                let history = histories.get(&pubkey)?;
                Some(ValidatorHistory {
                    pubkey,
                    signed_blocks: history
                        .blocks
                        .iter()
                        .map(|(&slot, &signing_root)| SignedBlock { slot, signing_root })
                        .collect(),
                    signed_attestations: history
                        .votes
                        .iter()
                        .map(|(&target_epoch, vote)| SignedAttestation {
                            source_epoch: vote.source,
                            target_epoch,
                            signing_root: vote.root,
                        })
                        .collect(),
                })
            })
            .collect();
        drop(histories);
        Interchange {
            genesis_validators_root: self.genesis_validators_root,
            data,
        }
    }

    /// The histories, under the lock that serializes check and record.
    fn lock(&self) -> MutexGuard<'_, HashMap<BlsPubkey, History>> {
        // A panic while holding the lock leaves histories that are supersets of the stored ones.
        // Continuing can only refuse more, so the poison carries no danger.
        self.histories
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs, process};

    use proptest::prelude::*;

    use super::*;

    /// The chain every test protects.
    const CHAIN: Root = Root([0x42; 32]);

    /// A validator key, one per byte value.
    const fn key(byte: u8) -> BlsPubkey {
        BlsPubkey([byte; 48])
    }

    /// A fresh scratch directory for one test.
    fn scratch(name: &str) -> PathBufGuard {
        let path = env::temp_dir().join(format!("axiom-protection-{name}-{}", process::id()));
        let _absent = fs::remove_dir_all(&path);
        PathBufGuard(path)
    }

    /// A directory removed when the test ends.
    struct PathBufGuard(std::path::PathBuf);

    impl Drop for PathBufGuard {
        fn drop(&mut self) {
            let _absent = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn records_survive_a_restart() {
        let directory = scratch("restart");

        // Sign block 0x01...01 at slot 9 and a vote from 3 to 4, then close as a crash would.
        {
            let database = SlashingDatabase::open(&directory.0, CHAIN).unwrap();
            database.register([key(1)]).unwrap();
            database
                .check_block(&key(1), Slot(9), Root([1; 32]))
                .unwrap();
            database
                .check_vote(VoteCheck {
                    pubkey: key(1),
                    source: Epoch(3),
                    target: Epoch(4),
                    signing_root: Root([1; 32]),
                })
                .unwrap();
        }

        // After reopening, another block at slot 9 is a double proposal.
        let database = SlashingDatabase::open(&directory.0, CHAIN).unwrap();
        assert!(matches!(
            database.check_block(&key(1), Slot(9), Root([2; 32])),
            Err(ProtectionError::Refused(refusal)) if *refusal == Refusal::DoubleProposal {
                pubkey: key(1),
                slot: Slot(9),
                recorded: Some(Root([1; 32])),
                asked: Some(Root([2; 32])),
            }
        ));

        // And the vote is still there: re-signing it is a repeat.
        assert_eq!(
            database
                .check_vote(VoteCheck {
                    pubkey: key(1),
                    source: Epoch(3),
                    target: Epoch(4),
                    signing_root: Root([1; 32]),
                })
                .unwrap(),
            Safety::Repeat
        );
    }

    #[test]
    fn an_existing_database_opens_for_its_own_chain() {
        let directory = scratch("existing");

        // Nothing there yet: no chain to open for.
        assert!(matches!(
            SlashingDatabase::open_existing(&directory.0),
            Err(ProtectionError::Uninitialized)
        ));

        // Once created for a chain, it reopens bound to that chain.
        drop(SlashingDatabase::open(&directory.0, CHAIN).unwrap());
        let database = SlashingDatabase::open_existing(&directory.0).unwrap();
        assert_eq!(database.genesis_validators_root(), CHAIN);
    }

    #[test]
    fn a_database_serves_one_chain() {
        let directory = scratch("chain");
        drop(SlashingDatabase::open(&directory.0, CHAIN).unwrap());

        // Mutation: reopen for the chain whose root is 0x43...43.
        assert!(matches!(
            SlashingDatabase::open(&directory.0, Root([0x43; 32])),
            Err(ProtectionError::WrongChain { expected: CHAIN, actual })
                if actual == Root([0x43; 32])
        ));
    }

    #[test]
    fn an_unregistered_key_never_signs() {
        let database = SlashingDatabase::in_memory(CHAIN).unwrap();
        assert!(matches!(
            database.check_block(&key(7), Slot(1), Root([1; 32])),
            Err(ProtectionError::Refused(refusal)) if *refusal == Refusal::Unregistered { pubkey: key(7) }
        ));
    }

    #[test]
    fn a_batch_sees_its_own_earlier_votes() {
        // Fixture state: validator 1 asks for two different votes for target 5 in one batch.
        let database = SlashingDatabase::in_memory(CHAIN).unwrap();
        database.register([key(1), key(2)]).unwrap();
        let vote = |pubkey, root| VoteCheck {
            pubkey,
            source: Epoch(4),
            target: Epoch(5),
            signing_root: Root([root; 32]),
        };
        let outcomes = database
            .check_votes(&[vote(key(1), 1), vote(key(1), 2), vote(key(2), 2)])
            .unwrap();

        // The first passes, the second is its double vote, and validator 2 is independent.
        assert_eq!(
            outcomes,
            [
                Ok(Safety::Fresh),
                Err(Refusal::DoubleVote {
                    pubkey: key(1),
                    target_epoch: Epoch(5),
                    recorded: Some(Root([1; 32])),
                    asked: Some(Root([2; 32])),
                }),
                Ok(Safety::Fresh),
            ]
        );
    }

    #[test]
    fn an_export_imports_into_an_equal_database() {
        // Fixture state: two validators with a block and two votes between them.
        let source = SlashingDatabase::in_memory(CHAIN).unwrap();
        source.register([key(1), key(2)]).unwrap();
        source.check_block(&key(1), Slot(3), Root([1; 32])).unwrap();
        source
            .check_votes(&[
                VoteCheck {
                    pubkey: key(1),
                    source: Epoch(0),
                    target: Epoch(1),
                    signing_root: Root([2; 32]),
                },
                VoteCheck {
                    pubkey: key(2),
                    source: Epoch(1),
                    target: Epoch(2),
                    signing_root: Root([3; 32]),
                },
            ])
            .unwrap();
        let exported = source.export(None);

        // Importing it into an empty database records 1 block and 2 votes for 2 validators.
        let destination = SlashingDatabase::in_memory(CHAIN).unwrap();
        assert_eq!(
            destination.import(&exported).unwrap(),
            ImportSummary {
                validators: 2,
                blocks: 1,
                votes: 2,
            }
        );
        assert_eq!(destination.export(None), exported);

        // Importing it again adds nothing.
        assert_eq!(
            destination.import(&exported).unwrap(),
            ImportSummary {
                validators: 2,
                blocks: 0,
                votes: 0,
            }
        );
    }

    #[test]
    fn a_slashable_import_changes_nothing() {
        // Fixture state: validator 1 voted from 2 to 6.
        let database = SlashingDatabase::in_memory(CHAIN).unwrap();
        database.register([key(1)]).unwrap();
        database
            .check_vote(VoteCheck {
                pubkey: key(1),
                source: Epoch(2),
                target: Epoch(6),
                signing_root: Root([1; 32]),
            })
            .unwrap();
        let before = database.export(None);

        // Mutation: an interchange with validator 2's block, then validator 1 voting 3 to 5 inside 2 to 6.
        let interchange = Interchange {
            genesis_validators_root: CHAIN,
            data: vec![
                ValidatorHistory {
                    pubkey: key(2),
                    signed_blocks: vec![SignedBlock {
                        slot: Slot(1),
                        signing_root: None,
                    }],
                    signed_attestations: Vec::new(),
                },
                ValidatorHistory {
                    pubkey: key(1),
                    signed_blocks: Vec::new(),
                    signed_attestations: vec![SignedAttestation {
                        source_epoch: Epoch(3),
                        target_epoch: Epoch(5),
                        signing_root: None,
                    }],
                },
            ],
        };
        assert!(matches!(
            database.import(&interchange),
            Err(ProtectionError::SlashableImport(refusal)) if *refusal == Refusal::Surrounded {
                pubkey: key(1),
                source_epoch: Epoch(3),
                target_epoch: Epoch(5),
                recorded_source: Epoch(2),
                recorded_target: Epoch(6),
            }
        ));

        // Validator 2 was not registered, and validator 1's history is untouched.
        assert!(!database.is_registered(&key(2)));
        assert_eq!(database.export(None), before);
    }

    /// One request in a random signing history.
    #[derive(Clone, Copy, Debug)]
    enum Request {
        /// A block by a validator at a slot with a root byte.
        Block(u8, u64, u8),
        /// A vote by a validator from a source to a target with a root byte.
        Vote(u8, u64, u64, u8),
        /// A restart of the database from disk.
        Reopen,
    }

    /// Requests over 3 validators, small slots and epochs, and 2 roots, so conflicts are frequent.
    fn request() -> impl Strategy<Value = Request> {
        prop_oneof![
            4 => (0_u8..3, 0_u64..12, 0_u8..2).prop_map(|(v, s, r)| Request::Block(v, s, r)),
            8 => (0_u8..3, 0_u64..10, 0_u64..10, 0_u8..2)
                .prop_map(|(v, s, t, r)| Request::Vote(v, s, t, r)),
            1 => Just(Request::Reopen),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn no_approved_pair_is_ever_slashable(
            requests in prop::collection::vec(request(), 1..80),
        ) {
            // Any sequence of requests and restarts, approved messages form no slashable pair.
            let directory = scratch(&format!("property-{}", requests.len()));
            let mut database = SlashingDatabase::open(&directory.0, CHAIN).unwrap();
            database.register((0..3).map(key)).unwrap();
            let mut blocks: Vec<(u8, u64, u8)> = Vec::new();
            let mut votes: Vec<(u8, u64, u64, u8)> = Vec::new();
            for request in requests {
                match request {
                    Request::Block(v, slot, root) => {
                        let outcome = database.check_block(&key(v), Slot(slot), Root([root; 32]));
                        if outcome.is_ok() {
                            blocks.push((v, slot, root));
                        }
                    }
                    Request::Vote(v, source, target, root) => {
                        let outcome = database.check_vote(VoteCheck {
                            pubkey: key(v),
                            source: Epoch(source),
                            target: Epoch(target),
                            signing_root: Root([root; 32]),
                        });
                        if outcome.is_ok() {
                            votes.push((v, source, target, root));
                        }
                    }
                    Request::Reopen => {
                        drop(database);
                        database = SlashingDatabase::open(&directory.0, CHAIN).unwrap();
                    }
                }
            }
            // Oracle: compare every approved pair against the spec's slashing conditions.
            for (i, a) in blocks.iter().enumerate() {
                for b in &blocks[i + 1..] {
                    prop_assert!(!(a.0 == b.0 && a.1 == b.1 && a.2 != b.2), "double proposal {a:?} {b:?}");
                }
            }
            for (i, a) in votes.iter().enumerate() {
                for b in &votes[i + 1..] {
                    if a.0 != b.0 {
                        continue;
                    }
                    let double = a.2 == b.2 && (a.1 != b.1 || a.3 != b.3);
                    let surround = (a.1 < b.1 && b.2 < a.2) || (b.1 < a.1 && a.2 < b.2);
                    prop_assert!(!double && !surround, "slashable votes {a:?} {b:?}");
                }
            }
        }
    }
}
