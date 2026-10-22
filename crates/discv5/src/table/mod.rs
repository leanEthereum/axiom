//! The Kademlia routing table: 256 k-buckets indexed by logarithmic distance.
//!
//! See discv5-theory.md, "Node Table" and "Table Maintenance In Practice".

mod bucket;
mod entry;
mod ip_limit;

use std::time::Duration;

pub use bucket::{KBucket, Pending};
pub use entry::Entry;
pub use ip_limit::IpLimits;

use crate::{distance::LogDistance, enr::Enr, node_id::NodeId, rng::Csprng};

/// Buckets in the table, one per distance from 1 to 256.
const BUCKETS: usize = 256;

/// Settings of the routing table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableConfig {
    /// Most entries per bucket: k.
    pub bucket_size: usize,
    /// Subnet caps, or none to admit any address.
    pub ip_limits: Option<IpLimits>,
    /// How long a newcomer waits on a full bucket's stalest node.
    pub pending_timeout: Duration,
}

impl Default for TableConfig {
    fn default() -> Self {
        // k = 16 per discv5-theory.md; the wait covers one request timeout with margin.
        Self {
            bucket_size: 16,
            ip_limits: Some(IpLimits::default()),
            pending_timeout: Duration::from_secs(2),
        }
    }
}

/// What an insertion did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The node joined its bucket.
    Inserted,

    /// The node was known; its newer record replaced the old one.
    Updated,

    /// The node was known with this record or a newer one.
    Unchanged,

    /// The bucket is full: the node waits while the stalest entry is checked.
    Pending {
        /// The stalest entry, which the caller should ping.
        check: Box<Enr>,
    },

    /// The bucket is full and already has a candidate waiting.
    BucketFull,

    /// The node's /24 subnet is at its cap.
    IpLimited,

    /// The record is the local node's own.
    LocalNode,
}

/// The local node's view of the network, organised by distance.
///
/// # Invariants
///
/// Every entry sits in the bucket of its distance to the local node.
/// No bucket holds more than k entries.
/// With limits on, no /24 exceeds its per-bucket or per-table cap.
#[derive(Clone, Debug)]
pub struct RoutingTable {
    /// The local node's id, the reference point of every distance.
    local_id: NodeId,
    /// The settings.
    config: TableConfig,
    /// Bucket i holds the nodes at distance i + 1.
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    /// An empty table around a local node.
    #[must_use]
    pub fn new(local_id: NodeId, config: TableConfig) -> Self {
        Self {
            local_id,
            config,
            buckets: vec![KBucket::default(); BUCKETS],
        }
    }

    /// The local node's id.
    #[must_use]
    pub const fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// The bucket index of a node, absent for the local node.
    fn bucket_index(&self, node: &NodeId) -> Option<usize> {
        self.local_id.log_distance(node).bucket()
    }

    /// Offers a record to the table.
    pub fn insert(&mut self, enr: Enr, now: Duration) -> InsertOutcome {
        let node = enr.node_id();
        let Some(index) = self.bucket_index(&node) else {
            return InsertOutcome::LocalNode;
        };

        // Phase 1: a known node only ever moves to a newer record.
        if let Some(entry) = self.buckets[index].get(&node) {
            if enr.seq() <= entry.enr.seq() {
                return InsertOutcome::Unchanged;
            }
            if !self.ip_allowed(index, &enr, Some(&node)) {
                return InsertOutcome::IpLimited;
            }
            if let Some(entry) = self.buckets[index].get_mut(&node) {
                entry.enr = enr;
            }
            return InsertOutcome::Updated;
        }

        // Phase 2: a newcomer must fit the subnet caps.
        if !self.ip_allowed(index, &enr, None) {
            return InsertOutcome::IpLimited;
        }

        // Phase 3: join a bucket with room, or wait on the stalest entry of a full one.
        let bucket_size = self.config.bucket_size;
        let deadline = now + self.config.pending_timeout;
        let bucket = &mut self.buckets[index];
        if bucket.len() < bucket_size {
            bucket.push(Entry::new(enr));
            return InsertOutcome::Inserted;
        }
        if bucket.pending().is_some() {
            return InsertOutcome::BucketFull;
        }
        let Some(check) = bucket.stalest().map(|entry| Box::new(entry.enr.clone())) else {
            return InsertOutcome::BucketFull;
        };
        bucket.set_pending(Pending {
            entry: Entry::new(enr),
            deadline,
        });
        InsertOutcome::Pending { check }
    }

    /// Whether a record's /24 has room in a bucket and in the table.
    ///
    /// An existing entry being updated is left out of the count.
    fn ip_allowed(&self, index: usize, enr: &Enr, updating: Option<&NodeId>) -> bool {
        let (Some(limits), Some(ip)) = (self.config.ip_limits, enr.endpoints().ip4) else {
            return true;
        };
        let subnet = IpLimits::subnet(ip);
        let others = |entry: &&Entry| Some(&entry.node_id()) != updating;
        let in_bucket =
            IpLimits::count(self.buckets[index].entries().iter().filter(others), subnet);
        let in_table = IpLimits::count(self.iter().filter(others), subnet);
        in_bucket < limits.per_bucket && in_table < limits.per_table
    }

    /// Records that a node answered: it is verified and becomes the freshest of its bucket.
    ///
    /// A newcomer waiting on this node gives up: the incumbent stays.
    pub fn record_success(&mut self, node: &NodeId) {
        let Some(index) = self.bucket_index(node) else {
            return;
        };
        let bucket = &mut self.buckets[index];
        let was_stalest = bucket
            .stalest()
            .is_some_and(|entry| entry.node_id() == *node);
        let Some(entry) = bucket.get_mut(node) else {
            return;
        };
        entry.record_success();
        bucket.touch(node);
        if was_stalest {
            bucket.take_pending();
        }
    }

    /// Records that a node missed an answer, evicting it past its tolerance.
    ///
    /// An evicted node's place goes to the bucket's pending candidate.
    ///
    /// # Returns
    ///
    /// Whether the node was evicted.
    pub fn record_failure(&mut self, node: &NodeId) -> bool {
        let Some(index) = self.bucket_index(node) else {
            return false;
        };
        let bucket = &mut self.buckets[index];
        let Some(entry) = bucket.get_mut(node) else {
            return false;
        };
        if !entry.record_failure() {
            return false;
        }
        // Mutation: the failed node leaves, and the candidate takes the freshest slot.
        bucket.remove(node);
        if let Some(pending) = bucket.take_pending() {
            bucket.push(pending.entry);
        }
        true
    }

    /// Drops candidates whose wait has run out.
    ///
    /// Reaching the deadline means the stalest node never failed, so it keeps its slot.
    pub fn expire_pending(&mut self, now: Duration) {
        for bucket in &mut self.buckets {
            if bucket
                .pending()
                .is_some_and(|pending| pending.deadline <= now)
            {
                bucket.take_pending();
            }
        }
    }

    /// The earliest candidate deadline.
    #[must_use]
    pub fn next_pending_deadline(&self) -> Option<Duration> {
        self.buckets
            .iter()
            .filter_map(|bucket| bucket.pending().map(|pending| pending.deadline))
            .min()
    }

    /// Removes a node outright.
    pub fn remove(&mut self, node: &NodeId) -> Option<Entry> {
        let index = self.bucket_index(node)?;
        self.buckets[index].remove(node)
    }

    /// The entry of a node.
    #[must_use]
    pub fn get(&self, node: &NodeId) -> Option<&Entry> {
        let index = self.bucket_index(node)?;
        self.buckets[index].get(node)
    }

    /// Every entry, nearest bucket first.
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.buckets
            .iter()
            .flat_map(|bucket| bucket.entries().iter())
    }

    /// Entries held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(KBucket::len).sum()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(KBucket::is_empty)
    }

    /// The bucket for a distance from 1 to 256.
    #[must_use]
    pub fn bucket(&self, distance: LogDistance) -> Option<&KBucket> {
        self.buckets.get(distance.bucket()?)
    }

    /// Up to n records closest to a target, verified or not.
    #[must_use]
    pub fn closest(&self, target: &NodeId, n: usize) -> Vec<Enr> {
        // Sort every entry by XOR distance; the table is small enough for a full sort.
        let mut entries: Vec<&Entry> = self.iter().collect();
        entries.sort_by_key(|entry| entry.node_id().distance(target));
        entries
            .into_iter()
            .take(n)
            .map(|entry| entry.enr.clone())
            .collect()
    }

    /// Verified records at a distance from the local node, for a FINDNODE answer.
    #[must_use]
    pub fn verified_at(&self, distance: LogDistance) -> Vec<Enr> {
        self.bucket(distance)
            .map(|bucket| {
                bucket
                    .entries()
                    .iter()
                    .filter(|entry| entry.verified)
                    .map(|entry| entry.enr.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The stalest record of a random non-empty bucket, the next liveness check.
    pub fn revalidation_target(&self, rng: &mut Csprng) -> Option<Enr> {
        let filled: Vec<&KBucket> = self.buckets.iter().filter(|b| !b.is_empty()).collect();
        if filled.is_empty() {
            return None;
        }
        filled[rng.below(filled.len())]
            .stalest()
            .map(|entry| entry.enr.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use axiom_crypto::secp256k1::SecretKey;

    use super::*;

    /// A record with a given key seed and IPv4 address.
    fn record(seed: u8, ip: Ipv4Addr) -> Enr {
        let mut secret = [0; 32];
        secret[31] = seed;
        secret[0] = 1;
        let key = SecretKey::from_bytes(&secret).expect("valid key");
        Enr::builder()
            .ip4(ip)
            .udp4(9000)
            .build(&key)
            .expect("record fits")
    }

    /// Records sharing a bucket of the local node: distance 256 means the top bit differs.
    fn far_records(local: &NodeId, count: usize, ip: impl Fn(usize) -> Ipv4Addr) -> Vec<Enr> {
        (1..=255_u8)
            .map(|seed| record(seed, ip(usize::from(seed))))
            .filter(|enr| local.log_distance(&enr.node_id()) == LogDistance::MAX)
            .take(count)
            .collect()
    }

    #[test]
    fn full_bucket_keeps_incumbents_until_they_fail() {
        // Fixture state: local id zero, so half of all ids fall in bucket 255.
        let local = NodeId([0; 32]);
        let config = TableConfig {
            ip_limits: None,
            ..TableConfig::default()
        };
        let mut table = RoutingTable::new(local, config);
        let records = far_records(&local, 18, |i| Ipv4Addr::new(10, 0, i as u8, 1));
        let now = Duration::from_secs(1);
        for enr in &records[..16] {
            assert_eq!(table.insert(enr.clone(), now), InsertOutcome::Inserted);
        }
        // The 17th waits on the stalest, the first inserted.
        assert_eq!(
            table.insert(records[16].clone(), now),
            InsertOutcome::Pending {
                check: Box::new(records[0].clone())
            }
        );
        // The 18th finds a candidate already waiting.
        assert_eq!(
            table.insert(records[17].clone(), now),
            InsertOutcome::BucketFull
        );
        // The stalest answers: it stays, moves to the fresh end, and the candidate leaves.
        table.record_success(&records[0].node_id());
        let bucket = table.bucket(LogDistance::MAX).expect("bucket 255");
        assert_eq!(bucket.pending(), None);
        assert_eq!(bucket.entries()[15].node_id(), records[0].node_id());
        assert!(bucket.entries()[15].verified);

        // Phase 2: the 17th tries again; now the stalest is the second record, never verified.
        assert_eq!(
            table.insert(records[16].clone(), now),
            InsertOutcome::Pending {
                check: Box::new(records[1].clone())
            }
        );
        // It fails its check: evicted at once, and the candidate takes the freshest slot.
        assert!(table.record_failure(&records[1].node_id()));
        let bucket = table.bucket(LogDistance::MAX).expect("bucket 255");
        assert_eq!(bucket.len(), 16);
        assert_eq!(bucket.entries()[15].node_id(), records[16].node_id());
        assert!(table.get(&records[1].node_id()).is_none());
    }

    #[test]
    fn verified_nodes_tolerate_two_misses() {
        // A verified node survives two failures and goes on the third.
        let local = NodeId([0; 32]);
        let mut table = RoutingTable::new(local, TableConfig::default());
        let enr = record(1, Ipv4Addr::new(10, 0, 0, 1));
        table.insert(enr.clone(), Duration::ZERO);
        table.record_success(&enr.node_id());
        assert!(!table.record_failure(&enr.node_id()));
        assert!(!table.record_failure(&enr.node_id()));
        assert!(table.record_failure(&enr.node_id()));
        assert!(table.is_empty());
    }

    #[test]
    fn subnet_caps() {
        // All records in 10.0.0.0/24: two per bucket at most.
        let local = NodeId([0; 32]);
        let mut table = RoutingTable::new(local, TableConfig::default());
        let records = far_records(&local, 3, |i| Ipv4Addr::new(10, 0, 0, i as u8));
        assert_eq!(
            table.insert(records[0].clone(), Duration::ZERO),
            InsertOutcome::Inserted
        );
        assert_eq!(
            table.insert(records[1].clone(), Duration::ZERO),
            InsertOutcome::Inserted
        );
        assert_eq!(
            table.insert(records[2].clone(), Duration::ZERO),
            InsertOutcome::IpLimited
        );

        // Ten per table across buckets: fill 10 from one /24 spread over many buckets.
        let mut table = RoutingTable::new(local, TableConfig::default());
        let mut admitted = 0;
        let mut refused = 0;
        for seed in 1..=255_u8 {
            match table.insert(record(seed, Ipv4Addr::new(10, 1, 1, seed)), Duration::ZERO) {
                InsertOutcome::Inserted => admitted += 1,
                InsertOutcome::IpLimited => refused += 1,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert_eq!(admitted, 10);
        assert_eq!(refused, 245);
    }

    #[test]
    fn updates_and_lookups() {
        let local = NodeId([0; 32]);
        let mut table = RoutingTable::new(local, TableConfig::default());
        let key = SecretKey::from_bytes(&[7; 32]).expect("valid key");
        let first = Enr::builder()
            .ip4(Ipv4Addr::new(10, 0, 0, 1))
            .udp4(1)
            .build(&key)
            .expect("fits");
        let second = first.to_builder().udp4(2).build(&key).expect("fits");
        assert_eq!(
            table.insert(first.clone(), Duration::ZERO),
            InsertOutcome::Inserted
        );
        // The same record again changes nothing; a newer one replaces it.
        assert_eq!(
            table.insert(first.clone(), Duration::ZERO),
            InsertOutcome::Unchanged
        );
        assert_eq!(
            table.insert(second.clone(), Duration::ZERO),
            InsertOutcome::Updated
        );
        assert_eq!(
            table.insert(first, Duration::ZERO),
            InsertOutcome::Unchanged
        );
        assert_eq!(table.get(&second.node_id()).map(|e| e.enr.seq()), Some(2));
        // Unverified nodes are never relayed; verified ones are.
        let distance = local.log_distance(&second.node_id());
        assert!(table.verified_at(distance).is_empty());
        table.record_success(&second.node_id());
        assert_eq!(table.verified_at(distance), vec![second.clone()]);
        // The local record is never stored.
        let local_key = SecretKey::from_bytes(&[8; 32]).expect("valid key");
        let local_enr = Enr::builder().build(&local_key).expect("fits");
        let mut own = RoutingTable::new(local_enr.node_id(), TableConfig::default());
        assert_eq!(
            own.insert(local_enr, Duration::ZERO),
            InsertOutcome::LocalNode
        );
        // Closest returns the one entry.
        assert_eq!(table.closest(&NodeId([0xff; 32]), 5), vec![second]);
    }

    #[test]
    fn pending_candidates_expire() {
        // A candidate waits 2 seconds, then gives up.
        let local = NodeId([0; 32]);
        let config = TableConfig {
            bucket_size: 1,
            ip_limits: None,
            ..TableConfig::default()
        };
        let mut table = RoutingTable::new(local, config);
        let records = far_records(&local, 2, |i| Ipv4Addr::new(10, 0, i as u8, 1));
        table.insert(records[0].clone(), Duration::from_secs(1));
        table.insert(records[1].clone(), Duration::from_secs(1));
        assert_eq!(table.next_pending_deadline(), Some(Duration::from_secs(3)));
        table.expire_pending(Duration::from_millis(2999));
        assert!(table.next_pending_deadline().is_some());
        table.expire_pending(Duration::from_secs(3));
        assert_eq!(table.next_pending_deadline(), None);
    }
}
