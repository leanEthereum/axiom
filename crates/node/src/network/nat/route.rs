//! The IPv4 default gateway, read from the Linux routing table text.
//!
//! The kernel prints one route per line under a header, whitespace separated.
//! Destination, gateway, and mask are 8 hex digits of the address in memory order.
//! Flags are hex; the route must be up and must go through a gateway.

use std::net::Ipv4Addr;

/// The route is up, per the kernel's route flags.
const RTF_UP: u32 = 0x1;

/// The route goes through a gateway, per the kernel's route flags.
const RTF_GATEWAY: u32 = 0x2;

/// The text of the kernel's IPv4 routing table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RouteTable<'a>(pub(crate) &'a str);

impl RouteTable<'_> {
    /// The gateway of the default route with the lowest metric.
    ///
    /// A malformed line is skipped, so one odd route never hides the default one.
    pub(crate) fn default_gateway(self) -> Option<Ipv4Addr> {
        self.0
            .lines()
            .skip(1)
            .filter_map(Self::default_route)
            .min_by_key(|&(metric, _)| metric)
            .map(|(_, gateway)| gateway)
    }

    /// The metric and gateway of a line, when it is a usable default route.
    fn default_route(line: &str) -> Option<(u32, Ipv4Addr)> {
        // Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT.
        let columns: Vec<&str> = line.split_whitespace().collect();
        let [_, destination, gateway, flags, _, _, metric, mask, ..] = columns.as_slice() else {
            return None;
        };
        let destination = Self::address(destination)?;
        let mask = Self::address(mask)?;
        let flags = u32::from_str_radix(flags, 16).ok()?;
        let up_via_gateway = flags & (RTF_UP | RTF_GATEWAY) == RTF_UP | RTF_GATEWAY;
        if !destination.is_unspecified() || !mask.is_unspecified() || !up_via_gateway {
            return None;
        }
        Some((metric.parse().ok()?, Self::address(gateway)?))
    }

    /// An address the kernel printed as its 32 bits in host order.
    fn address(hex: &str) -> Option<Ipv4Addr> {
        // Why: the kernel prints the network-order word as a host integer.
        // Its native bytes are therefore the address octets, on either endianness.
        let word = u32::from_str_radix(hex, 16).ok()?;
        Some(Ipv4Addr::from(word.to_ne_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host integer for an address, as the kernel would print it on this machine.
    fn hex(address: Ipv4Addr) -> String {
        format!("{:08X}", u32::from_ne_bytes(address.octets()))
    }

    #[test]
    fn the_lowest_metric_default_route_wins() {
        // Fixture state: a wired default via 192.168.1.1 at metric 100,
        // a wireless one via 192.168.50.1 at metric 600, and the local subnet.
        let wired = hex(Ipv4Addr::new(192, 168, 1, 1));
        let wireless = hex(Ipv4Addr::new(192, 168, 50, 1));
        let subnet = hex(Ipv4Addr::new(192, 168, 1, 0));
        let mask = hex(Ipv4Addr::new(255, 255, 255, 0));
        let table = format!(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
             wlan0\t00000000\t{wireless}\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
             eth0\t00000000\t{wired}\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
             eth0\t{subnet}\t00000000\t0001\t0\t0\t100\t{mask}\t0\t0\t0\n"
        );
        assert_eq!(
            RouteTable(&table).default_gateway(),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
    }

    #[test]
    fn little_endian_kernel_text_reads_as_written() {
        // On x86_64 and aarch64 the kernel prints 192.168.1.1 as 0101A8C0.
        if cfg!(target_endian = "little") {
            let table = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                         eth0 00000000 0101A8C0 0003 0 0 100 00000000 0 0 0\n";
            assert_eq!(
                RouteTable(table).default_gateway(),
                Some(Ipv4Addr::new(192, 168, 1, 1))
            );
        }
    }

    #[test]
    fn unusable_routes_are_skipped() {
        // A down default route, a default route without a gateway, and a garbled line.
        let gateway = hex(Ipv4Addr::new(10, 0, 0, 1));
        let table = format!(
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
             eth0 00000000 {gateway} 0002 0 0 100 00000000 0 0 0\n\
             tun0 00000000 00000000 0001 0 0 50 00000000 0 0 0\n\
             eth1 zz {gateway} 0003\n"
        );
        assert_eq!(RouteTable(&table).default_gateway(), None);
        // Only a header, as on a host without IPv4 routes.
        assert_eq!(RouteTable("Iface Destination\n").default_gateway(), None);
    }
}
