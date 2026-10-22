//! Laws of the metric types, checked over random inputs.

use std::thread;

use axiom_telemetry::{Buckets, Counter, Histogram, Registry};
use proptest::{collection::vec, prelude::*};

/// Reads one exposition sample line with a single label back into its parts.
///
/// ```text
///     name{label="escaped value"} sample
/// ```
///
/// Returns the name, the label, the unescaped value, and the sample text.
fn parse_line(line: &str) -> Option<(String, String, String, String)> {
    let (name, rest) = line.split_once('{')?;
    let (label, rest) = rest.split_once("=\"")?;
    let mut value = String::new();
    let mut chars = rest.chars();
    // Walk the quoted value, undoing each of the three escapes.
    loop {
        match chars.next()? {
            '"' => break,
            '\\' => match chars.next()? {
                '\\' => value.push('\\'),
                '"' => value.push('"'),
                'n' => value.push('\n'),
                _ => return None,
            },
            c => value.push(c),
        }
    }
    // After the closing quote: a brace, a space, then the sample.
    let sample = chars.as_str().strip_prefix("} ")?;
    Some((name.to_owned(), label.to_owned(), value, sample.to_owned()))
}

proptest! {
    #[test]
    fn concurrent_increments_all_count(per_thread in vec(0_u64..2_000, 2..8)) {
        let counter = Counter::new();

        // Each thread adds one at a time, racing the others on the same atomic.
        thread::scope(|scope| {
            for &count in &per_thread {
                let counter = counter.clone();
                scope.spawn(move || {
                    for _ in 0..count {
                        counter.inc();
                    }
                });
            }
        });

        // No increment is lost: the total is the sum of every thread's share.
        prop_assert_eq!(counter.get(), per_thread.iter().sum::<u64>());
    }

    #[test]
    fn histogram_counts_match_a_reference(
        raw_bounds in vec(-1_000.0_f64..1_000.0, 0..8),
        observations in vec(prop_oneof![-2_000.0_f64..2_000.0, Just(f64::NAN)], 0..64),
    ) {
        // Sort and deduplicate random bounds into a valid strictly increasing list.
        let mut bounds = raw_bounds;
        bounds.sort_by(f64::total_cmp);
        bounds.dedup();
        let histogram = Histogram::new(Buckets::new(&bounds).unwrap());
        for &value in &observations {
            histogram.observe(value);
        }
        let snapshot = histogram.snapshot();

        // The count is the number of observations, and the last bucket equals it.
        prop_assert_eq!(snapshot.count, observations.len() as u64);
        prop_assert_eq!(snapshot.buckets.last().map(|&(_, count)| count), Some(snapshot.count));

        // Buckets never decrease from one bound to the next.
        for pair in snapshot.buckets.windows(2) {
            prop_assert!(pair[0].1 <= pair[1].1);
        }

        // Each finite bucket counts exactly the observations at or below its bound.
        // NaN is at or below nothing, so it only reaches the infinite bucket.
        for &(bound, count) in &snapshot.buckets[..bounds.len()] {
            let reference = observations.iter().filter(|&&value| value <= bound).count();
            prop_assert_eq!(count, reference as u64);
        }
    }

    #[test]
    fn label_values_round_trip(value in any::<String>()) {
        let registry = Registry::new();
        let family = registry.counter_vec("m_total", "Help.", ["v"]).unwrap();
        family.with_label_values([value.as_str()]).inc_by(5);

        // The only sample line is the third: after the help and type lines.
        let text = registry.render();
        let line = text.lines().nth(2).unwrap();

        // Escaping removed every raw newline, so the sample sits on one line.
        prop_assert_eq!(text.lines().count(), 3);

        // Parsing the line recovers the exact value.
        let parsed = parse_line(line);
        prop_assert_eq!(
            parsed,
            Some(("m_total".to_owned(), "v".to_owned(), value, "5".to_owned()))
        );
    }
}
