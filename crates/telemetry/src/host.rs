//! What the process and its host use: CPU, memory, disks, and network, read from the kernel.
//!
//! Only Linux exposes these through the proc file system; elsewhere every reading is zero.

#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use crate::metrics::process::{ProcessStat, ProcessValue};

/// Clock ticks per second in the CPU times the kernel reports.
///
/// The kernel exports user-visible ticks at a fixed 100 Hz on every mainstream architecture.
/// Source: the definition of user ticks in the Linux kernel parameter headers.
const TICKS_PER_SECOND: u64 = 100;

/// What the running process uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessUsage {
    /// User and system CPU time, in whole seconds.
    pub cpu_seconds: u64,
    /// Resident memory, in bytes.
    pub resident_bytes: u64,
}

impl ProcessUsage {
    /// The process's usage now, zero where the platform does not tell.
    #[must_use]
    pub fn sample() -> Self {
        Self::read().unwrap_or_default()
    }

    #[cfg(target_os = "linux")]
    fn read() -> Option<Self> {
        let cpu_seconds = match ProcessStat::CpuSeconds.sample()? {
            ProcessValue::Ticks(ticks) => ticks / TICKS_PER_SECOND,
            ProcessValue::Integer(seconds) => seconds,
        };
        let resident_bytes = match ProcessStat::ResidentMemory.sample()? {
            ProcessValue::Integer(bytes) | ProcessValue::Ticks(bytes) => bytes,
        };
        Some(Self {
            cpu_seconds,
            resident_bytes,
        })
    }

    #[cfg(not(target_os = "linux"))]
    const fn read() -> Option<Self> {
        None
    }
}

/// What the host machine uses, summed over its CPUs, disks, and network interfaces.
///
/// CPU times are whole seconds since boot; byte and operation counts are totals since boot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SystemUsage {
    /// Physical CPU cores.
    pub cpu_cores: u64,
    /// Hardware threads.
    pub cpu_threads: u64,
    /// CPU time of every kind, in seconds.
    pub cpu_total_seconds: u64,
    /// CPU time in user mode, in seconds.
    pub cpu_user_seconds: u64,
    /// CPU time waiting for input and output, in seconds.
    pub cpu_iowait_seconds: u64,
    /// CPU time idle, in seconds.
    pub cpu_idle_seconds: u64,
    /// Memory installed, in bytes.
    pub memory_total_bytes: u64,
    /// Memory unused, in bytes.
    pub memory_free_bytes: u64,
    /// Memory holding the page cache, in bytes.
    pub memory_cached_bytes: u64,
    /// Memory holding block device buffers, in bytes.
    pub memory_buffers_bytes: u64,
    /// Reads completed by the disks.
    pub disk_reads: u64,
    /// Writes completed by the disks.
    pub disk_writes: u64,
    /// Bytes received by the network interfaces, loopback excluded.
    pub network_received_bytes: u64,
    /// Bytes sent by the network interfaces, loopback excluded.
    pub network_transmitted_bytes: u64,
    /// When the host booted, in seconds since the Unix epoch.
    pub boot_time_seconds: u64,
}

impl SystemUsage {
    /// The host's usage now, zero where the platform does not tell.
    #[must_use]
    pub fn sample() -> Self {
        #[cfg(target_os = "linux")]
        {
            let mut usage = Self::default();
            if let Ok(stat) = fs::read_to_string("/proc/stat") {
                usage.read_stat(&stat);
            }
            if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
                usage.cpu_cores = Self::cores(&cpuinfo).max(1);
            }
            if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
                usage.read_meminfo(&meminfo);
            }
            if let Ok(diskstats) = fs::read_to_string("/proc/diskstats") {
                usage.read_diskstats(&diskstats);
            }
            if let Ok(netdev) = fs::read_to_string("/proc/net/dev") {
                usage.read_netdev(&netdev);
            }
            usage
        }
        #[cfg(not(target_os = "linux"))]
        Self::default()
    }

    /// Reads CPU times and the boot time from the kernel's statistics.
    ///
    /// ```text
    ///     cpu  user nice system idle iowait irq softirq steal ...    in ticks
    ///     cpu0 ...                                                   one line per thread
    ///     btime 1700000000
    /// ```
    fn read_stat(&mut self, stat: &str) {
        for line in stat.lines() {
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("cpu") => {
                    let ticks: Vec<u64> = fields.filter_map(|field| field.parse().ok()).collect();
                    let at =
                        |index: usize| ticks.get(index).copied().unwrap_or(0) / TICKS_PER_SECOND;
                    self.cpu_user_seconds = at(0);
                    self.cpu_idle_seconds = at(3);
                    self.cpu_iowait_seconds = at(4);
                    self.cpu_total_seconds = ticks.iter().sum::<u64>() / TICKS_PER_SECOND;
                }
                Some(name) if name.starts_with("cpu") => self.cpu_threads += 1,
                Some("btime") => {
                    self.boot_time_seconds =
                        fields.next().and_then(|t| t.parse().ok()).unwrap_or(0);
                }
                _ => {}
            }
        }
    }

    /// Physical cores: the cores of each distinct physical package.
    fn cores(cpuinfo: &str) -> u64 {
        let mut packages = Vec::new();
        let mut cores_per_package = 0;
        for line in cpuinfo.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                "physical id" if !packages.contains(&value) => packages.push(value),
                "cpu cores" => cores_per_package = value.parse().unwrap_or(0),
                _ => {}
            }
        }
        cores_per_package * (packages.len().max(1) as u64)
    }

    /// Reads memory sizes, given in kibibytes.
    fn read_meminfo(&mut self, meminfo: &str) {
        for line in meminfo.lines() {
            let mut fields = line.split_whitespace();
            let (Some(key), Some(kib)) = (fields.next(), fields.next()) else {
                continue;
            };
            let bytes = kib.parse::<u64>().unwrap_or(0).saturating_mul(1024);
            match key {
                "MemTotal:" => self.memory_total_bytes = bytes,
                "MemFree:" => self.memory_free_bytes = bytes,
                "Cached:" => self.memory_cached_bytes = bytes,
                "Buffers:" => self.memory_buffers_bytes = bytes,
                _ => {}
            }
        }
    }

    /// Sums completed reads and writes over whole disks, partitions and virtual devices excluded.
    ///
    /// ```text
    ///     major minor name reads ... writes ...    reads is field 4, writes field 8
    /// ```
    fn read_diskstats(&mut self, diskstats: &str) {
        for line in diskstats.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let Some(name) = fields.get(2) else {
                continue;
            };
            // Loop and memory devices hold no data of their own.
            if name.starts_with("loop") || name.starts_with("ram") {
                continue;
            }
            let number = |index: usize| fields.get(index).and_then(|f| f.parse::<u64>().ok());
            if let (Some(reads), Some(writes)) = (number(3), number(7)) {
                self.disk_reads += reads;
                self.disk_writes += writes;
            }
        }
    }

    /// Sums the bytes of every interface but loopback.
    ///
    /// ```text
    ///     eth0: rx_bytes rx_packets ... (8 receive fields) tx_bytes ...
    /// ```
    fn read_netdev(&mut self, netdev: &str) {
        for line in netdev.lines() {
            let Some((name, counters)) = line.split_once(':') else {
                continue;
            };
            if name.trim() == "lo" {
                continue;
            }
            let fields: Vec<u64> = counters
                .split_whitespace()
                .filter_map(|field| field.parse().ok())
                .collect();
            if let (Some(received), Some(transmitted)) = (fields.first(), fields.get(8)) {
                self.network_received_bytes += received;
                self.network_transmitted_bytes += transmitted;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_files_read_as_totals() {
        let mut usage = SystemUsage::default();
        // Ticks: 1000 user, 200 nice, 300 system, 5000 idle, 100 iowait.
        usage.read_stat(
            "cpu  1000 200 300 5000 100\ncpu0 1 1 1 1 1\ncpu1 1 1 1 1 1\nbtime 1700000000\n",
        );
        usage.read_meminfo("MemTotal:       2048 kB\nMemFree:        1024 kB\nCached:           16 kB\nBuffers:           8 kB\n");
        usage.read_diskstats(
            "   8       0 sda 10 0 0 0 20 0 0 0\n   7       0 loop0 99 0 0 0 99 0 0 0\n",
        );
        usage
            .read_netdev("Inter-|\n lo: 500 0 0 0 0 0 0 0 500 0\n eth0: 700 0 0 0 0 0 0 0 300 0\n");
        assert_eq!(
            usage,
            SystemUsage {
                cpu_cores: 0,
                cpu_threads: 2,
                cpu_total_seconds: 66,
                cpu_user_seconds: 10,
                cpu_iowait_seconds: 1,
                cpu_idle_seconds: 50,
                memory_total_bytes: 2048 * 1024,
                memory_free_bytes: 1024 * 1024,
                memory_cached_bytes: 16 * 1024,
                memory_buffers_bytes: 8 * 1024,
                disk_reads: 10,
                disk_writes: 20,
                network_received_bytes: 700,
                network_transmitted_bytes: 300,
                boot_time_seconds: 1_700_000_000,
            }
        );
    }

    #[test]
    fn cores_count_each_physical_package() {
        let two_packages = "physical id\t: 0\ncpu cores\t: 4\nphysical id\t: 1\ncpu cores\t: 4\n";
        assert_eq!(SystemUsage::cores(two_packages), 8);
    }
}
