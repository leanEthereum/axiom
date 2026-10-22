//! Data parallelism over scoped threads, for the independent pieces of the heavy operations.
//!
//! Every method joins its threads before returning and computes exactly what the sequential loop would.

use std::{
    num::NonZero,
    panic,
    sync::OnceLock,
    thread::{self, ScopedJoinHandle},
};

/// The cores available to data-parallel loops, queried once per process.
///
/// Every loop splits its input into one contiguous chunk per thread, at most one per item.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Threads {
    /// Number of threads worth running at once, at least one.
    count: usize,
}

impl Threads {
    /// The cores of this machine.
    ///
    /// # Performance
    ///
    /// The operating system query reads affinity masks and cgroup quotas, so its answer is cached.
    pub(crate) fn available() -> Self {
        static COUNT: OnceLock<usize> = OnceLock::new();
        // The query fails on exotic platforms, which then run sequentially.
        let count = *COUNT.get_or_init(|| thread::available_parallelism().map_or(1, NonZero::get));
        Self { count }
    }

    /// Number of threads to run over this many independent pieces of work.
    pub(crate) fn split(self, pieces: usize) -> usize {
        self.count.min(pieces)
    }

    /// Maps a function over a slice on all cores, collecting the results in input order.
    ///
    /// Collecting into a result or an option keeps the first failure in input order.
    /// A panic in any worker resumes on the calling thread.
    pub(crate) fn map<T: Sync, R: Send, C: FromIterator<R>>(
        self,
        items: &[T],
        function: impl Fn(&T) -> R + Sync,
    ) -> C {
        let threads = self.split(items.len());
        if threads <= 1 {
            return items.iter().map(function).collect();
        }

        // Contiguous chunks, one per thread, concatenated back in order.
        //
        //     items   [ a b c | d e f | g h ]
        //     threads    t0      t1     t2
        let chunk = items.len().div_ceil(threads);
        let function = &function;
        thread::scope(|scope| {
            let workers: Vec<_> = items
                .chunks(chunk)
                .map(|part| scope.spawn(move || part.iter().map(function).collect::<Vec<R>>()))
                .collect();
            workers.into_iter().flat_map(Self::finish).collect()
        })
    }

    /// Applies a function to every element of a slice in place, on all cores.
    ///
    /// A panic in any worker resumes on the calling thread.
    pub(crate) fn for_each_mut<T: Send>(self, items: &mut [T], function: impl Fn(&mut T) + Sync) {
        let threads = self.split(items.len());
        if threads <= 1 {
            items.iter_mut().for_each(function);
            return;
        }

        // Disjoint mutable chunks, one per thread.
        let chunk = items.len().div_ceil(threads);
        let function = &function;
        thread::scope(|scope| {
            let workers: Vec<_> = items
                .chunks_mut(chunk)
                .map(|part| scope.spawn(move || part.iter_mut().for_each(function)))
                .collect();
            workers.into_iter().for_each(Self::finish);
        });
    }

    /// Runs two closures concurrently and returns both results.
    ///
    /// A panic in the spawned closure resumes on the calling thread.
    pub(crate) fn join<A: Send, B: Send>(
        self,
        left: impl FnOnce() -> A + Send,
        right: impl FnOnce() -> B + Send,
    ) -> (A, B) {
        // A single core gains nothing from a second thread.
        if self.count <= 1 {
            return (left(), right());
        }

        // The right side runs on a new thread while this thread runs the left side.
        thread::scope(|scope| {
            let worker = scope.spawn(right);
            let a = left();
            (a, Self::finish(worker))
        })
    }

    /// Waits for a worker, resuming its panic on the calling thread.
    fn finish<R>(worker: ScopedJoinHandle<'_, R>) -> R {
        worker
            .join()
            .unwrap_or_else(|payload| panic::resume_unwind(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_keeps_order() {
        // Fixture state: 1000 items, more than any core count, so the input splits.
        let items: Vec<u64> = (0..1000).collect();
        let doubled: Vec<u64> = Threads::available().map(&items, |item| item * 2);
        assert_eq!(doubled, (0..1000).map(|item| item * 2).collect::<Vec<_>>());
        // An empty input maps to an empty output.
        let empty: Vec<u64> = Threads::available().map(&[] as &[u64], |item| *item);
        assert_eq!(empty, Vec::<u64>::new());
    }

    #[test]
    fn map_reports_the_first_failure_in_input_order() {
        // Items 300 and 700 fail, so the collected result names 300 whatever the split.
        let items: Vec<u64> = (0..1000).collect();
        let result: Result<Vec<u64>, u64> = Threads::available().map(&items, |item| match item {
            300 | 700 => Err(*item),
            _ => Ok(*item),
        });
        assert_eq!(result, Err(300));
    }

    #[test]
    fn single_thread_runs_sequentially() {
        // One thread splits nothing and still computes both sides of a join.
        let threads = Threads { count: 1 };
        assert_eq!(threads.split(1000), 1);
        assert_eq!(threads.join(|| 2, || 3), (2, 3));
    }
}
