//! Data parallelism over scoped threads, for the independent leaves of a bottom tree.
//!
//! Every call joins its threads before returning and computes exactly what the sequential loop would.

use std::{
    num::NonZero,
    panic,
    sync::OnceLock,
    thread::{self, ScopedJoinHandle},
};

/// The cores available to data-parallel loops, queried once per process.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Threads {
    /// Number of threads worth running at once, at least one.
    count: usize,
}

impl Threads {
    /// The cores of this machine.
    pub(crate) fn available() -> Self {
        static COUNT: OnceLock<usize> = OnceLock::new();
        // The query fails on exotic platforms, which then run sequentially.
        let count = *COUNT.get_or_init(|| thread::available_parallelism().map_or(1, NonZero::get));
        Self { count }
    }

    /// Maps a function over a range of indices on all cores, results in index order.
    ///
    /// A panic in any worker resumes on the calling thread.
    pub(crate) fn map<R: Send>(self, len: usize, function: impl Fn(usize) -> R + Sync) -> Vec<R> {
        let threads = self.count.min(len);
        if threads <= 1 {
            return (0..len).map(function).collect();
        }

        // Contiguous index ranges, one per thread, concatenated back in order.
        let chunk = len.div_ceil(threads);
        let function = &function;
        thread::scope(|scope| {
            #[expect(
                clippy::needless_collect,
                reason = "every worker must be spawned before the first is joined"
            )]
            let workers: Vec<ScopedJoinHandle<'_, Vec<R>>> = (0..len)
                .step_by(chunk)
                .map(|start| {
                    let end = (start + chunk).min(len);
                    scope.spawn(move || (start..end).map(function).collect())
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| {
                    worker
                        .join()
                        .unwrap_or_else(|payload| panic::resume_unwind(payload))
                })
                .collect()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_come_back_in_index_order() {
        // Fixture state: 1000 indices, squared, over however many cores the host has.
        let squares = Threads::available().map(1000, |i| i * i);
        assert_eq!(squares, (0..1000).map(|i| i * i).collect::<Vec<_>>());

        // A single thread runs the plain loop.
        assert_eq!(Threads { count: 1 }.map(3, |i| i + 1), [1, 2, 3]);
        assert_eq!(Threads { count: 4 }.map(0, |i| i), Vec::<usize>::new());
    }
}
