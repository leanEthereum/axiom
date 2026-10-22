//! The gossip subnets a node joins for its own sake, derived from its node identifier.

use axiom_das::NodeId;
use axiom_ssz::Root;
use axiom_state_transition::SwapOrNot;
use axiom_types::{Bytes32, ChainConfig, Epoch, Preset, SubnetId};

/// Long-lived attestation subnets, fixed by the node identifier and rotated slowly.
///
/// # Overview
///
/// Every node backs a few attestation subnets, so every subnet has a mesh.
/// The choice is a deterministic function of the node identifier and the epoch.
/// Peers can therefore check a node's claim, and the assignment rotates without coordination.
///
/// ```text
///     prefix  = top bits of the node identifier, one per subnet
///     offset  = node identifier mod the rotation period, staggering rotations
///     seed    = sha256(le64((epoch + offset) / period))
///     subnet_i = (shuffle(prefix, seed) + i) mod subnet count
/// ```
///
/// See `compute_subscribed_subnets` in the phase0 p2p spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AttestationSubnets {
    /// The node identifier the assignment derives from.
    node_id: NodeId,
}

impl AttestationSubnets {
    /// The assignment of a node.
    pub(crate) const fn new(node_id: NodeId) -> Self {
        Self { node_id }
    }

    /// The subnets the node joins in an epoch.
    pub(crate) fn at<P: Preset>(&self, epoch: Epoch, config: &ChainConfig) -> Vec<SubnetId> {
        (0..config.subnets_per_node)
            .map(|index| self.subnet::<P>(epoch, index, config))
            .collect()
    }

    /// The subnets of an epoch as a bitfield, one bit per subnet, as metadata and records carry them.
    /// The bitfield naming every attestation subnet, as a node joined to all of them states it.
    pub(crate) const fn all(config: &ChainConfig) -> u64 {
        // Subnets past 63 cannot occur with 64 subnets; the bitfield holds the first 64.
        match config.attestation_subnet_count {
            0 => 0,
            count if count >= 64 => u64::MAX,
            count => (1 << count) - 1,
        }
    }

    pub(crate) fn bits<P: Preset>(&self, epoch: Epoch, config: &ChainConfig) -> u64 {
        // Subnets past 63 cannot occur with 64 subnets; the guard keeps the shift in range.
        self.at::<P>(epoch, config)
            .iter()
            .filter(|subnet| subnet.0 < 64)
            .fold(0, |bits, subnet| bits | (1 << subnet.0))
    }

    /// One of the node's subnets in an epoch.
    ///
    /// See `compute_subscribed_subnet` in the phase0 p2p spec.
    fn subnet<P: Preset>(&self, epoch: Epoch, index: u64, config: &ChainConfig) -> SubnetId {
        let bytes = self.node_id.0.to_le_bytes();

        // The prefix is the identifier's top bits, as many as it takes to name every subnet.
        //
        //     64 subnets, no extra bits  ->  6 prefix bits  ->  64 prefixes
        let prefix_bits = u64::from(
            config
                .attestation_subnet_count
                .next_power_of_two()
                .trailing_zeros(),
        ) + config.attestation_subnet_extra_bits;
        let mut top = [0; 8];
        top.copy_from_slice(&bytes[24..]);
        let prefix = u64::from_le_bytes(top) >> (64 - prefix_bits);

        // The offset staggers nodes, so they do not all rotate in the same epoch.
        let period = config.epochs_per_subnet_subscription;
        let offset = Self::modulo(&bytes, period);

        // Shuffle the prefix among all prefixes, with a seed that changes once a period.
        let rotation = (epoch.0 + offset) / period;
        let seed = Bytes32(Root::sha256(&rotation.to_le_bytes()).0);
        let shuffled =
            SwapOrNot::new(seed, P::SHUFFLE_ROUND_COUNT).shuffled_index(prefix, 1 << prefix_bits);
        SubnetId((shuffled + index) % config.attestation_subnet_count)
    }

    /// A 256-bit little-endian integer modulo a 64-bit one.
    fn modulo(bytes: &[u8; 32], modulus: u64) -> u64 {
        // Horner's rule from the most significant byte keeps every step below 2^72.
        let remainder = bytes.iter().rev().fold(0_u128, |acc, byte| {
            (acc * 256 + u128::from(*byte)) % u128::from(modulus)
        });
        // The remainder is below the 64-bit modulus, so it fits.
        u64::try_from(remainder).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use axiom_ssz::U256;
    use axiom_types::Mainnet;

    use super::*;

    /// A node identifier from its 32 big-endian bytes.
    fn node(big_endian: [u8; 32]) -> NodeId {
        let mut little = big_endian;
        little.reverse();
        NodeId(U256(little))
    }

    #[test]
    fn subnets_match_the_executable_spec() {
        // Expected pairs from the pyspec's compute_subscribed_subnets, mainnet, v1.7.0-beta.4.
        let mut high = [0; 32];
        high[0] = 0x80;
        high[30] = 0x30;
        high[31] = 0x39;
        let mut one = [0; 32];
        one[31] = 1;
        let cases: [([u8; 32], u64, [u64; 2]); 10] = [
            ([0; 32], 0, [49, 50]),
            ([0; 32], 256, [16, 17]),
            (one, 0, [49, 50]),
            (one, 255, [16, 17]),
            ([0xff; 32], 0, [57, 58]),
            ([0xff; 32], 1_000_000, [18, 19]),
            ([0xab; 32], 0, [3, 4]),
            ([0xab; 32], 255, [0, 1]),
            (high, 0, [27, 28]),
            (high, 255, [52, 53]),
        ];
        let config = ChainConfig::mainnet();
        for (id, epoch, expected) in cases {
            let subnets = AttestationSubnets::new(node(id)).at::<Mainnet>(Epoch(epoch), &config);
            assert_eq!(subnets, expected.map(SubnetId), "epoch {epoch}");
        }
    }
}
