//! What a registry entry measures, and how it is written out.

use std::{fmt, sync::Arc};

use crate::metrics::{
    Counter, Gauge, Histogram,
    exposition::{Exposition, Kind},
    family::Family,
    name::{LabelName, MetricName},
    process::ProcessStat,
};

/// The measuring half of a registry entry.
#[derive(Clone, Debug)]
pub(crate) enum Instrument {
    /// One unlabelled counter.
    Counter(Counter),

    /// One unlabelled gauge.
    Gauge(Gauge),

    /// One unlabelled histogram.
    Histogram(Histogram),

    /// Counters keyed by label values.
    CounterFamily(Arc<Family<Counter>>),

    /// Gauges keyed by label values.
    GaugeFamily(Arc<Family<Gauge>>),

    /// Histograms keyed by label values.
    HistogramFamily(Arc<Family<Histogram>>),

    /// A process statistic read when scraped.
    Process(ProcessStat),
}

impl Instrument {
    /// The kind declared on the type line.
    pub(crate) const fn kind(&self) -> Kind {
        match self {
            Self::Counter(_) | Self::CounterFamily(_) => Kind::Counter,
            Self::Gauge(_) | Self::GaugeFamily(_) => Kind::Gauge,
            Self::Histogram(_) | Self::HistogramFamily(_) => Kind::Histogram,
            Self::Process(stat) => stat.kind(),
        }
    }

    /// Writes the help line, the type line, and every sample.
    pub(crate) fn encode<W: fmt::Write>(
        &self,
        name: &MetricName,
        help: &str,
        out: &mut Exposition<'_, W>,
    ) -> fmt::Result {
        // A process statistic the platform lacks is left out entirely.
        if let Self::Process(stat) = self {
            return match stat.sample() {
                Some(value) => {
                    out.header(name, help, self.kind())?;
                    out.sample(name, "", &[], &value)
                }
                None => Ok(()),
            };
        }

        out.header(name, help, self.kind())?;
        match self {
            Self::Counter(counter) => out.sample(name, "", &[], &counter.get()),
            Self::Gauge(gauge) => out.sample(name, "", &[], &gauge.get()),
            Self::Histogram(histogram) => out.histogram(name, &[], &histogram.snapshot()),
            // Each family child is one series, its labels paired with the declared names.
            Self::CounterFamily(family) => {
                for (values, counter) in family.children() {
                    out.sample(name, "", &pairs(family.names(), &values), &counter.get())?;
                }
                Ok(())
            }
            Self::GaugeFamily(family) => {
                for (values, gauge) in family.children() {
                    out.sample(name, "", &pairs(family.names(), &values), &gauge.get())?;
                }
                Ok(())
            }
            Self::HistogramFamily(family) => {
                for (values, histogram) in family.children() {
                    out.histogram(name, &pairs(family.names(), &values), &histogram.snapshot())?;
                }
                Ok(())
            }
            // Handled before the header, so this arm writes nothing.
            Self::Process(_) => Ok(()),
        }
    }

    /// The sample names this entry writes, to detect clashes between entries.
    ///
    /// ```text
    ///     counter or gauge "x"   ->  x
    ///     histogram "x"          ->  x, x_bucket, x_sum, x_count
    /// ```
    pub(crate) fn series(&self, name: &MetricName) -> Vec<String> {
        let base = name.as_str().to_owned();
        match self.kind() {
            Kind::Counter | Kind::Gauge => vec![base],
            // A histogram owns three suffixed names besides its own.
            Kind::Histogram => vec![
                format!("{base}_bucket"),
                format!("{base}_sum"),
                format!("{base}_count"),
                base,
            ],
        }
    }
}

/// Pairs label names with one child's values, in declaration order.
fn pairs<'a>(names: &'a [LabelName], values: &'a [String]) -> Vec<(&'a str, &'a str)> {
    // The family stores exactly one value per name, so the zip loses nothing.
    names
        .iter()
        .map(LabelName::as_str)
        .zip(values.iter().map(String::as_str))
        .collect()
}
