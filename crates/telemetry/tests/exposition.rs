//! Exact text of the exposition for every metric kind.

use axiom_telemetry::{Buckets, Registry};

#[test]
fn every_kind_renders_exactly() {
    let registry = Registry::new();

    // An unlabelled counter at 7.
    let counter = registry.counter("a_total", "Counter.").unwrap();
    counter.inc_by(7);

    // An unlabelled gauge below zero.
    let gauge = registry.gauge("b", "Gauge.").unwrap();
    gauge.set(-3);

    // A histogram with bounds 0.5 and 1, observing 0.25, 0.75, and 3.
    //
    //     slots       0.5:1  1:1  +Inf:1
    //     cumulative  1      2    3       sum 4, count 3
    let buckets = Buckets::new(&[0.5, 1.0]).unwrap();
    let histogram = registry
        .histogram("c_seconds", "Histogram.", buckets)
        .unwrap();
    for value in [0.25, 0.75, 3.0] {
        histogram.observe(value);
    }

    // Two labels; children render sorted by value tuple, not by creation order.
    let gauges = registry
        .gauge_vec("d", "Gauge family.", ["x", "y"])
        .unwrap();
    gauges.with_label_values(["2", "a"]).set(20);
    gauges.with_label_values(["1", "b"]).set(10);

    // One label over a single bound; "put" exists but has seen nothing.
    let buckets = Buckets::new(&[1.0]).unwrap();
    let requests = registry
        .histogram_vec("e_seconds", "Histogram family.", ["method"], buckets)
        .unwrap();
    requests.with_label_values(["get"]).observe(2.0);
    let _ = requests.with_label_values(["put"]);

    // A family with no children shows only its help and type lines.
    let _empty = registry.counter_vec("f_total", "Empty.", ["x"]).unwrap();

    let expected = concat!(
        "# HELP a_total Counter.\n",
        "# TYPE a_total counter\n",
        "a_total 7\n",
        "# HELP b Gauge.\n",
        "# TYPE b gauge\n",
        "b -3\n",
        "# HELP c_seconds Histogram.\n",
        "# TYPE c_seconds histogram\n",
        "c_seconds_bucket{le=\"0.5\"} 1\n",
        "c_seconds_bucket{le=\"1\"} 2\n",
        "c_seconds_bucket{le=\"+Inf\"} 3\n",
        "c_seconds_sum 4\n",
        "c_seconds_count 3\n",
        "# HELP d Gauge family.\n",
        "# TYPE d gauge\n",
        "d{x=\"1\",y=\"b\"} 10\n",
        "d{x=\"2\",y=\"a\"} 20\n",
        "# HELP e_seconds Histogram family.\n",
        "# TYPE e_seconds histogram\n",
        "e_seconds_bucket{method=\"get\",le=\"1\"} 0\n",
        "e_seconds_bucket{method=\"get\",le=\"+Inf\"} 1\n",
        "e_seconds_sum{method=\"get\"} 2\n",
        "e_seconds_count{method=\"get\"} 1\n",
        "e_seconds_bucket{method=\"put\",le=\"1\"} 0\n",
        "e_seconds_bucket{method=\"put\",le=\"+Inf\"} 0\n",
        "e_seconds_sum{method=\"put\"} 0\n",
        "e_seconds_count{method=\"put\"} 0\n",
        "# HELP f_total Empty.\n",
        "# TYPE f_total counter\n",
    );
    assert_eq!(registry.render(), expected);
}

#[test]
fn label_values_and_help_are_escaped() {
    let registry = Registry::new();

    // Help escapes backslash and newline but keeps the quote.
    let paths = registry
        .counter_vec("p_total", "Say \"hi\"\\\nbye.", ["path"])
        .unwrap();

    // Label values escape backslash, quote, and newline.
    //
    //     a\b   -> a\\b
    //     "q"   -> \"q\"
    //     x<LF>y -> x\ny
    paths.with_label_values(["a\\b"]).inc();
    paths.with_label_values(["\"q\""]).inc();
    paths.with_label_values(["x\ny"]).inc();

    // Children sort by raw value: '"' (0x22) < 'a' (0x61) < 'x' (0x78).
    let expected = concat!(
        "# HELP p_total Say \"hi\"\\\\\\nbye.\n",
        "# TYPE p_total counter\n",
        "p_total{path=\"\\\"q\\\"\"} 1\n",
        "p_total{path=\"a\\\\b\"} 1\n",
        "p_total{path=\"x\\ny\"} 1\n",
    );
    assert_eq!(registry.render(), expected);
}

#[test]
fn special_floats_in_sums() {
    let registry = Registry::new();

    // No finite bounds: every observation lands in the infinite bucket.
    let none = Buckets::new(&[]).unwrap();

    // Minus infinity sums to minus infinity.
    let low = registry.histogram("h_low", "Low.", none.clone()).unwrap();
    low.observe(f64::NEG_INFINITY);

    // NaN sums to NaN.
    let nan = registry.histogram("h_nan", "NaN.", none.clone()).unwrap();
    nan.observe(f64::NAN);

    // Plus infinity sums to plus infinity.
    let high = registry.histogram("h_up", "High.", none).unwrap();
    high.observe(f64::INFINITY);

    let expected = concat!(
        "# HELP h_low Low.\n",
        "# TYPE h_low histogram\n",
        "h_low_bucket{le=\"+Inf\"} 1\n",
        "h_low_sum -Inf\n",
        "h_low_count 1\n",
        "# HELP h_nan NaN.\n",
        "# TYPE h_nan histogram\n",
        "h_nan_bucket{le=\"+Inf\"} 1\n",
        "h_nan_sum NaN\n",
        "h_nan_count 1\n",
        "# HELP h_up High.\n",
        "# TYPE h_up histogram\n",
        "h_up_bucket{le=\"+Inf\"} 1\n",
        "h_up_sum +Inf\n",
        "h_up_count 1\n",
    );
    assert_eq!(registry.render(), expected);
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
