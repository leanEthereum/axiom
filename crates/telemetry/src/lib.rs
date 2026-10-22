//! Logging, metrics, and the metrics endpoint of the beacon node.
//!
//! # Overview
//!
//! This crate sits at the effectful edge of the node.
//! Pure crates never depend on it: they neither log nor read a clock.
//!
//! ```text
//!     logging    filter and format events, install the global subscriber
//!     metrics    atomic counters, gauges, histograms, and their registry
//!     exporter   serve the registry to a Prometheus scraper over HTTP
//!     node       the beacon node's own metric set
//! ```
//!
//! Metric updates are single atomic operations and take no lock.
//! The registry is read only when scraped, in the Prometheus text format 0.0.4.

mod exporter;
mod logging;
mod metrics;
mod node;

pub use exporter::MetricsServer;
pub use logging::{LogConfig, LogError, LogFormat};
pub use metrics::{
    Buckets, BucketsError, CONTENT_TYPE, Counter, CounterVec, Gauge, GaugeVec, Histogram,
    HistogramSnapshot, HistogramVec, Registry, RegistryError, Timer,
};
pub use node::NodeMetrics;
