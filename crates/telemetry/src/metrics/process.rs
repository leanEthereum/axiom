//! Resource usage of the running process, read at scrape time.
//!
//! The names follow the Prometheus client guidelines for process metrics.

use std::fmt::{self, Display};
#[cfg(target_os = "linux")]
use std::fs;

use crate::metrics::exposition::Kind;

/// Clock ticks per second in the CPU times the kernel reports.
///
/// The kernel exports user-visible ticks at a fixed 100 Hz on every mainstream architecture.
/// Source: the definition of user ticks in the Linux kernel parameter headers.
const TICKS_PER_SECOND: u64 = 100;

/// One process statistic the registry samples when scraped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessStat {
    /// Resident set size in bytes.
    ResidentMemory,

    /// User plus system CPU time in seconds.
    CpuSeconds,

    /// Open file descriptors.
    OpenFds,
}

impl ProcessStat {
    /// Every statistic, in registration order.
    pub(crate) const ALL: [Self; 3] = [Self::ResidentMemory, Self::CpuSeconds, Self::OpenFds];

    /// The conventional metric name.
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ResidentMemory => "process_resident_memory_bytes",
            Self::CpuSeconds => "process_cpu_seconds_total",
            Self::OpenFds => "process_open_fds",
        }
    }

    /// The help text.
    pub(crate) const fn help(self) -> &'static str {
        match self {
            Self::ResidentMemory => "Resident memory size in bytes.",
            Self::CpuSeconds => "Total user and system CPU time spent in seconds.",
            Self::OpenFds => "Number of open file descriptors.",
        }
    }

    /// The declared kind; CPU time only grows, so it is a counter.
    pub(crate) const fn kind(self) -> Kind {
        match self {
            Self::CpuSeconds => Kind::Counter,
            Self::ResidentMemory | Self::OpenFds => Kind::Gauge,
        }
    }

    /// The current value, or nothing where the platform does not expose it.
    #[cfg(target_os = "linux")]
    pub(crate) fn sample(self) -> Option<ProcessValue> {
        match self {
            // The status file reports the resident set in kibibytes on its own line.
            //
            //     VmRSS:     123456 kB
            Self::ResidentMemory => {
                let status = fs::read_to_string("/proc/self/status").ok()?;
                let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
                let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                Some(ProcessValue::Integer(kib.checked_mul(1024)?))
            }
            // The stat file holds user and system time in ticks, as fields 14 and 15.
            //
            //     pid (comm) state ppid ... utime stime ...
            //
            // The command name may hold spaces and parentheses, so fields count from the last one.
            Self::CpuSeconds => {
                let stat = fs::read_to_string("/proc/self/stat").ok()?;
                let (_, after) = stat.rsplit_once(')')?;
                let mut fields = after.split_whitespace();
                // Field 3, the state, comes first after the name, so field 14 is at offset 11.
                let user: u64 = fields.nth(11)?.parse().ok()?;
                let system: u64 = fields.next()?.parse().ok()?;
                Some(ProcessValue::Ticks(user.checked_add(system)?))
            }
            // One directory entry per open descriptor, including the one this listing holds.
            Self::OpenFds => {
                let count = fs::read_dir("/proc/self/fd").ok()?.count();
                Some(ProcessValue::Integer(u64::try_from(count).ok()?))
            }
        }
    }

    /// The current value, or nothing where the platform does not expose it.
    #[cfg(not(target_os = "linux"))]
    pub(crate) const fn sample(self) -> Option<ProcessValue> {
        // Only Linux has the proc file system read here.
        let _ = self;
        None
    }
}

/// A sampled value, kept exact until written.
///
/// Only Linux samples process values, so other platforms never build one.
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only Linux samples process values")
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessValue {
    /// A whole number.
    Integer(u64),

    /// Hundredths of a second, as the kernel counts CPU time.
    Ticks(u64),
}

impl Display for ProcessValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer(value) => write!(f, "{value}"),
            // Ticks at 100 Hz print as an exact decimal, with no float rounding.
            //
            //     1234 ticks -> 12.34
            Self::Ticks(ticks) => write!(
                f,
                "{}.{:02}",
                ticks / TICKS_PER_SECOND,
                ticks % TICKS_PER_SECOND
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Registry;

    #[test]
    fn values_print_exactly() {
        // 1234 ticks at 100 Hz are 12.34 seconds; 5 ticks are 0.05 seconds.
        assert_eq!(ProcessValue::Ticks(1234).to_string(), "12.34");
        assert_eq!(ProcessValue::Ticks(5).to_string(), "0.05");
        assert_eq!(ProcessValue::Integer(42).to_string(), "42");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_samples_are_present() {
        // A running test process has memory, has spent CPU, and holds descriptors.
        for stat in ProcessStat::ALL {
            assert!(stat.sample().is_some(), "{stat:?} missing");
        }
    }

    #[test]
    fn process_metrics_have_their_conventional_types() {
        let registry = Registry::new();
        registry.register_process_metrics().unwrap();
        let text = registry.render();

        // Linux exposes all three; other platforms leave them out.
        if cfg!(target_os = "linux") {
            assert!(text.contains("# TYPE process_cpu_seconds_total counter\n"));
            assert!(text.contains("# TYPE process_open_fds gauge\n"));
            assert!(text.contains("# TYPE process_resident_memory_bytes gauge\n"));
        } else {
            assert_eq!(text, "");
        }
    }
}
