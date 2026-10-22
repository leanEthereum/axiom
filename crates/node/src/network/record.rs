//! The node's discovery record, re-signed whenever its consensus entries change.

use axiom_crypto::secp256k1::SecretKey;
use axiom_discv5::{
    Enr, EnrBuilder, EnrError,
    enr::{Attnets, EnrForkId, Syncnets},
};
use axiom_types::{ChainConfig, Epoch, ForkDigest, Root};

use super::nat::AdvertisedEndpoint;

/// The consensus entries of the node's record at one epoch.
///
/// The fork entries move at every fork and every blob step.
/// The attestation subnets move when the long-lived assignment rotates.
/// The node joins no long-lived sync committee subnet, so that field stays empty.
///
/// See "ENR structure" in the phase0, Altair, and Fulu p2p specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecordEntries {
    /// The eth2 entry: the current digest and the next fork.
    fork_id: EnrForkId,
    /// The nfd entry: the digest of the next fork, regular or blob-only.
    next_fork_digest: ForkDigest,
    /// Long-lived attestation subnets, one bit per subnet.
    attnets: u64,
}

impl RecordEntries {
    /// The entries at a wall-clock epoch, with the node's attestation subnets.
    pub(crate) fn at(
        config: &ChainConfig,
        genesis_validators_root: Root,
        epoch: Epoch,
        attnets: u64,
    ) -> Self {
        // The next fork, regular or blob-only, and the version in force once it comes.
        // A blob step keeps the version, so the next version may equal the current one.
        let next_epoch = config.next_fork_epoch(epoch);
        let scheduled = next_epoch != Epoch::FAR_FUTURE;
        let next_fork_version = if scheduled {
            config.fork_version_at(next_epoch)
        } else {
            config.fork_version_at(epoch)
        };
        // With no fork scheduled, the next digest is all zeros.
        let next_fork_digest = if scheduled {
            config.fork_digest(genesis_validators_root, next_epoch)
        } else {
            ForkDigest::ZERO
        };
        Self {
            fork_id: EnrForkId {
                fork_digest: config.fork_digest(genesis_validators_root, epoch),
                next_fork_version,
                next_fork_epoch: next_epoch,
            },
            next_fork_digest,
            attnets,
        }
    }

    /// Writes the entries into a record under construction, replacing earlier values.
    fn write(self, builder: EnrBuilder) -> EnrBuilder {
        let mut attnets = Attnets::default();
        for index in 0..64 {
            attnets.set(index, self.attnets >> index & 1 == 1);
        }
        builder
            .fork_id(&self.fork_id)
            .attnets(&attnets)
            .syncnets(&Syncnets::default())
            .next_fork_digest(self.next_fork_digest)
    }
}

/// The node's signed record and the consensus entries it states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalRecord {
    /// The signed record.
    enr: Enr,
    /// The consensus entries the record states.
    entries: RecordEntries,
}

impl LocalRecord {
    /// Signs the first record: the base entries, then the consensus entries.
    ///
    /// # Errors
    ///
    /// Fails when the record exceeds the size cap.
    pub(crate) fn new(
        base: EnrBuilder,
        entries: RecordEntries,
        key: &SecretKey,
    ) -> Result<Self, EnrError> {
        Ok(Self {
            enr: entries.write(base).build(key)?,
            entries,
        })
    }

    /// Re-signs the record under the next sequence number, when the entries differ.
    ///
    /// # Returns
    ///
    /// Whether the record changed.
    ///
    /// # Errors
    ///
    /// Fails when the record exceeds the size cap, leaving the old record in place.
    pub(crate) fn update(
        &mut self,
        entries: RecordEntries,
        key: &SecretKey,
    ) -> Result<bool, EnrError> {
        // Invariant: an unchanged record keeps its sequence number, so peers refetch nothing.
        if entries == self.entries {
            return Ok(false);
        }
        self.enr = entries.write(self.enr.to_builder()).build(key)?;
        self.entries = entries;
        Ok(true)
    }

    /// Re-signs the record under the next sequence number, when it does not state the endpoint.
    ///
    /// Only the address and port entries move; the consensus entries stay.
    ///
    /// # Returns
    ///
    /// Whether the record changed.
    ///
    /// # Errors
    ///
    /// Fails when the record exceeds the size cap, leaving the old record in place.
    pub(crate) fn set_endpoint(
        &mut self,
        endpoint: AdvertisedEndpoint,
        key: &SecretKey,
    ) -> Result<bool, EnrError> {
        // Invariant: a record already stating the endpoint keeps its sequence number.
        if endpoint.is_stated_by(self.enr.endpoints()) {
            return Ok(false);
        }
        self.enr = endpoint.write(self.enr.to_builder()).build(key)?;
        Ok(true)
    }

    /// The signed record.
    pub(crate) const fn enr(&self) -> &Enr {
        &self.enr
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use axiom_discv5::enr::Endpoints;
    use axiom_types::{BlobParameters, BlobSchedule, ForkName, Version};

    use super::*;

    #[test]
    fn the_record_follows_forks_and_blob_steps() {
        // Fixture state: minimal, Electra at genesis, Fulu at epoch 2.
        // A blob step raises the limit to 12 at epoch 4, with no fork version change.
        let mut config = ChainConfig::minimal()
            .with_forks_at_genesis(ForkName::Electra)
            .with_fork_epoch(ForkName::Fulu, Epoch(2));
        config.blob_schedule = BlobSchedule::new(vec![
            BlobParameters {
                epoch: Epoch(2),
                max_blobs_per_block: 9,
            },
            BlobParameters {
                epoch: Epoch(4),
                max_blobs_per_block: 12,
            },
        ]);
        let root = Root([7; 32]);
        let key = SecretKey::from_bytes(&[5; 32]).expect("valid key");
        let fulu = Version([0x06, 0, 0, 0x01]);
        let digest = |epoch| config.fork_digest(root, Epoch(epoch));

        // Epoch 1, Electra: the next fork is Fulu at epoch 2.
        let mut record = LocalRecord::new(
            Enr::builder().tcp4(9000),
            RecordEntries::at(&config, root, Epoch(1), 0b11),
            &key,
        )
        .expect("record fits");
        let first = record.enr().clone();
        assert_eq!(first.seq(), 1);
        assert_eq!(
            first.eth2().fork_id,
            Some(EnrForkId {
                fork_digest: digest(1),
                next_fork_version: fulu,
                next_fork_epoch: Epoch(2),
            })
        );
        assert_eq!(first.eth2().next_fork_digest, Some(digest(2)));

        // Epoch 1 again: nothing changed, so the same record and sequence stay.
        let changed = record
            .update(RecordEntries::at(&config, root, Epoch(1), 0b11), &key)
            .expect("record fits");
        assert!(!changed);
        assert_eq!(record.enr(), &first);

        // Epoch 2, Fulu: the next step is the blob step at epoch 4, under the same version.
        let changed = record
            .update(RecordEntries::at(&config, root, Epoch(2), 0b11), &key)
            .expect("record fits");
        assert!(changed);
        assert_eq!(record.enr().seq(), 2);
        assert_eq!(
            record.enr().eth2().fork_id,
            Some(EnrForkId {
                fork_digest: digest(2),
                next_fork_version: fulu,
                next_fork_epoch: Epoch(4),
            })
        );
        assert_eq!(record.enr().eth2().next_fork_digest, Some(digest(4)));
        // The blob step alone changes the digest: Fulu at 9 blobs and at 12 differ.
        assert_ne!(digest(2), digest(4));

        // Epoch 4: after the last step, nothing is scheduled.
        let changed = record
            .update(RecordEntries::at(&config, root, Epoch(4), 0b11), &key)
            .expect("record fits");
        assert!(changed);
        assert_eq!(record.enr().seq(), 3);
        assert_eq!(
            record.enr().eth2().fork_id,
            Some(EnrForkId {
                fork_digest: digest(4),
                next_fork_version: fulu,
                next_fork_epoch: Epoch::FAR_FUTURE,
            })
        );
        assert_eq!(record.enr().eth2().next_fork_digest, Some(ForkDigest::ZERO));

        // Epoch 4 with subnets 2 and 3 instead of 0 and 1: only the attnets entry moves.
        let changed = record
            .update(RecordEntries::at(&config, root, Epoch(4), 0b1100), &key)
            .expect("record fits");
        assert!(changed);
        assert_eq!(record.enr().seq(), 4);
        let set: Vec<usize> = (0..64)
            .filter(|&subnet| record.enr().eth2().on_attestation_subnet(subnet))
            .collect();
        assert_eq!(set, [2, 3]);
        // The endpoint of the base record survives every update.
        assert_eq!(record.enr().get_raw(b"tcp"), first.get_raw(b"tcp"));
    }

    #[test]
    fn the_endpoint_moves_without_touching_the_consensus_entries() {
        // Fixture state: a record on TCP 9000 and UDP 9001, with no address, at sequence 1.
        let config = ChainConfig::minimal().with_forks_at_genesis(ForkName::Fulu);
        let root = Root([7; 32]);
        let key = SecretKey::from_bytes(&[5; 32]).expect("valid key");
        let entries = RecordEntries::at(&config, root, Epoch(0), 0b101);
        let mut record = LocalRecord::new(Enr::builder().tcp4(9000).udp4(9001), entries, &key)
            .expect("record fits");
        let eth2 = record.enr().eth2().clone();

        // Peers confirmed 81.2.3.4:40000 for discovery; the gateway forwards QUIC 9002 too.
        let endpoint = AdvertisedEndpoint {
            ip: Ipv4Addr::new(81, 2, 3, 4),
            udp: Some(40000),
            tcp: None,
            quic: Some(9002),
        };
        assert_eq!(record.set_endpoint(endpoint, &key), Ok(true));
        assert_eq!(record.enr().seq(), 2);
        assert_eq!(
            *record.enr().endpoints(),
            Endpoints {
                ip4: Some(Ipv4Addr::new(81, 2, 3, 4)),
                tcp4: Some(9000),
                udp4: Some(40000),
                quic4: Some(9002),
                ..Endpoints::default()
            }
        );
        assert_eq!(record.enr().eth2(), &eth2);

        // The same endpoint again changes nothing, so peers refetch nothing.
        assert_eq!(record.set_endpoint(endpoint, &key), Ok(false));
        assert_eq!(record.enr().seq(), 2);

        // A later fork update keeps the new endpoint.
        let later = RecordEntries::at(&config, root, Epoch(0), 0b111);
        assert_eq!(record.update(later, &key), Ok(true));
        assert_eq!(
            record.enr().endpoints().udp_socket(),
            Some("81.2.3.4:40000".parse().expect("socket"))
        );
    }
}
