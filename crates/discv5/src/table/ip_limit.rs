//! Caps on how many table entries may share an IPv4 /24 subnet.

use std::net::Ipv4Addr;

use super::Entry;

/// Subnet caps that make an eclipse attack cost many address blocks.
///
/// Most clients cap a /24 at 2 entries per bucket and 10 per table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpLimits {
    /// Most entries of one /24 in one bucket.
    pub per_bucket: usize,
    /// Most entries of one /24 in the whole table.
    pub per_table: usize,
}

impl Default for IpLimits {
    fn default() -> Self {
        Self {
            per_bucket: 2,
            per_table: 10,
        }
    }
}

/// The /24 prefix of an IPv4 address, the unit the caps count in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Subnet24(pub [u8; 3]);

impl Subnet24 {
    /// The /24 prefix of an address.
    #[must_use]
    pub(crate) const fn of(ip: Ipv4Addr) -> Self {
        let [a, b, c, _] = ip.octets();
        Self([a, b, c])
    }

    /// How many entries advertise an address in this prefix.
    pub(crate) fn count_in<'a>(self, entries: impl Iterator<Item = &'a Entry>) -> usize {
        // Entries without an IPv4 address never count.
        entries
            .filter(|entry| {
                entry
                    .enr
                    .endpoints()
                    .ip4
                    .is_some_and(|ip| Self::of(ip) == self)
            })
            .count()
    }
}
