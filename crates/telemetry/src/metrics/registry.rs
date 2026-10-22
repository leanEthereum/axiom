//! The set of metrics a scrape returns.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use crate::metrics::{
    Buckets, Counter, CounterVec, Gauge, GaugeVec, Histogram, HistogramVec, RegistryError,
    exposition::Exposition,
    family::Family,
    instrument::Instrument,
    name::{LabelName, MetricName},
    process::ProcessStat,
};

/// The label every histogram bucket line carries for its upper bound.
const BUCKET_LABEL: &str = "le";

/// Named metrics with their help text, rendered in the Prometheus text format.
///
/// # Overview
///
/// Registration validates names and hands back a metric handle.
/// The handle updates atomics; the registry reads them only when scraped.
///
/// ```text
///     startup   register a metric      -> the component keeps the handle
///     runtime   update the handle      -> one atomic operation, no lock
///     scrape    render the registry    -> text, sorted by metric name
/// ```
///
/// Clones share one set of metrics.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    /// Every entry, keyed and ordered by name.
    entries: Arc<Mutex<BTreeMap<MetricName, Entry>>>,
}

/// One registered metric.
#[derive(Clone, Debug)]
struct Entry {
    /// The help text.
    help: String,

    /// What it measures.
    instrument: Instrument,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an unlabelled counter.
    pub fn counter(&self, name: &str, help: &str) -> Result<Counter, RegistryError> {
        let counter = Counter::new();
        // The registry keeps a clone; both share one atomic.
        self.insert(name, help, Instrument::Counter(counter.clone()))?;
        Ok(counter)
    }

    /// Registers an unlabelled gauge.
    pub fn gauge(&self, name: &str, help: &str) -> Result<Gauge, RegistryError> {
        let gauge = Gauge::new();
        // The registry keeps a clone; both share one atomic.
        self.insert(name, help, Instrument::Gauge(gauge.clone()))?;
        Ok(gauge)
    }

    /// Registers an unlabelled histogram over these buckets.
    pub fn histogram(
        &self,
        name: &str,
        help: &str,
        buckets: Buckets,
    ) -> Result<Histogram, RegistryError> {
        let histogram = Histogram::new(buckets);
        // The registry keeps a clone; both share one set of slots.
        self.insert(name, help, Instrument::Histogram(histogram.clone()))?;
        Ok(histogram)
    }

    /// Registers counters keyed by these label names.
    pub fn counter_vec<const N: usize>(
        &self,
        name: &str,
        help: &str,
        labels: [&str; N],
    ) -> Result<CounterVec<N>, RegistryError> {
        // Validate the labels before the name is taken.
        let family = Arc::new(Family::new(LabelName::parse_all(&labels, &[])?));
        self.insert(name, help, Instrument::CounterFamily(Arc::clone(&family)))?;
        Ok(CounterVec::new(family))
    }

    /// Registers gauges keyed by these label names.
    pub fn gauge_vec<const N: usize>(
        &self,
        name: &str,
        help: &str,
        labels: [&str; N],
    ) -> Result<GaugeVec<N>, RegistryError> {
        // Validate the labels before the name is taken.
        let family = Arc::new(Family::new(LabelName::parse_all(&labels, &[])?));
        self.insert(name, help, Instrument::GaugeFamily(Arc::clone(&family)))?;
        Ok(GaugeVec::new(family))
    }

    /// Registers histograms keyed by these label names, all over the same buckets.
    ///
    /// The bucket bound label is reserved, since every bucket line adds it.
    pub fn histogram_vec<const N: usize>(
        &self,
        name: &str,
        help: &str,
        labels: [&str; N],
        buckets: Buckets,
    ) -> Result<HistogramVec<N>, RegistryError> {
        // A user label named like the bound label would repeat on every bucket line.
        let names = LabelName::parse_all(&labels, &[BUCKET_LABEL])?;
        let family = Arc::new(Family::new(names));
        self.insert(name, help, Instrument::HistogramFamily(Arc::clone(&family)))?;
        Ok(HistogramVec::new(family, buckets))
    }

    /// Registers resident memory, CPU time, and open descriptors, read at each scrape.
    ///
    /// On platforms without the proc file system, these metrics are left out of the output.
    pub fn register_process_metrics(&self) -> Result<(), RegistryError> {
        // Each statistic is an ordinary entry whose value is sampled when written.
        for stat in ProcessStat::ALL {
            self.insert(stat.name(), stat.help(), Instrument::Process(stat))?;
        }
        Ok(())
    }

    /// Writes every metric in the text format, sorted by name.
    pub fn encode(&self, out: &mut impl fmt::Write) -> fmt::Result {
        // Copy the handles out, so slow formatting never blocks a registration.
        let entries: Vec<(MetricName, Entry)> = self
            .lock()
            .iter()
            .map(|(name, entry)| (name.clone(), entry.clone()))
            .collect();
        let mut exposition = Exposition::new(out);
        for (name, entry) in &entries {
            entry
                .instrument
                .encode(name, &entry.help, &mut exposition)?;
        }
        Ok(())
    }

    /// Every metric in the text format, sorted by name.
    #[must_use]
    pub fn render(&self) -> String {
        let mut text = String::new();
        // Invariant: writing into a string never fails, so the result carries no information.
        let _ = self.encode(&mut text);
        text
    }

    /// Adds an entry, refusing a bad name or one whose samples clash with another entry.
    fn insert(&self, name: &str, help: &str, instrument: Instrument) -> Result<(), RegistryError> {
        let name = MetricName::parse(name)?;
        let series = instrument.series(&name);
        let mut entries = self.lock();
        // Two entries clash when any of their sample names coincide.
        //
        //     histogram "x" writes x_count
        //     counter "x_count" writes x_count   -> clash
        let clash = entries.iter().any(|(other, entry)| {
            let taken = entry.instrument.series(other);
            series.iter().any(|sample| taken.contains(sample))
        });
        if clash {
            return Err(RegistryError::DuplicateMetric(name.as_str().to_owned()));
        }
        entries.insert(
            name,
            Entry {
                help: help.to_owned(),
                instrument,
            },
        );
        // Release the lock before returning, so a concurrent scrape waits no longer than needed.
        drop(entries);
        Ok(())
    }

    /// The entry map, recovered if a panicking thread poisoned the lock.
    fn lock(&self) -> MutexGuard<'_, BTreeMap<MetricName, Entry>> {
        // No update leaves the map half-written, so a poisoned map is still valid.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clashing_names_are_refused() {
        let registry = Registry::new();
        registry
            .histogram("x", "h", Buckets::default())
            .expect("first registration");

        // The same name again.
        assert_eq!(
            registry.counter("x", "c").map(|_| ()),
            Err(RegistryError::DuplicateMetric("x".to_owned()))
        );

        // A name equal to one of the histogram's suffixed sample names.
        assert_eq!(
            registry.gauge("x_count", "g").map(|_| ()),
            Err(RegistryError::DuplicateMetric("x_count".to_owned()))
        );

        // A bad name is refused before any clash check.
        assert_eq!(
            registry.counter("1x", "c").map(|_| ()),
            Err(RegistryError::InvalidMetricName("1x".to_owned()))
        );

        // The bound label is reserved for histograms only.
        assert_eq!(
            registry
                .histogram_vec("y", "h", ["le"], Buckets::default())
                .map(|_| ()),
            Err(RegistryError::InvalidLabelName("le".to_owned()))
        );
        assert!(registry.counter_vec("z", "c", ["le"]).is_ok());
    }
}
