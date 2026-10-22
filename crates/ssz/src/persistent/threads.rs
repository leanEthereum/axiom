//! Scoped threads that hash many cold packs at once.

use std::{
    num::NonZero,
    panic,
    sync::OnceLock,
    thread::{self, ScopedJoinHandle},
};

/// Fewest cold packs worth spreading over threads.
///
/// A pack of 64 leaves costs about 64 hashes, near 10 microseconds.
/// Spawning a thread costs a few tens of microseconds, so small batches stay on one thread.
const PARALLEL_THRESHOLD: usize = 64;

/// The cores available to hash packs, queried once per process.
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

    /// Runs a function on every item, spread over the cores when the batch is large.
    ///
    /// Every thread joins before this returns, and a worker's panic resumes here.
    /// The function's effects must not depend on the order, as with filling a cache.
    pub(crate) fn for_each<T: Sync>(self, items: &[T], function: impl Fn(&T) + Sync) {
        let threads = self.count.min(items.len() / PARALLEL_THRESHOLD);
        if threads <= 1 {
            items.iter().for_each(function);
            return;
        }

        // Contiguous chunks, one per thread.
        let chunk = items.len().div_ceil(threads);
        let function = &function;
        thread::scope(|scope| {
            let workers: Vec<_> = items
                .chunks(chunk)
                .map(|part| scope.spawn(move || part.iter().for_each(function)))
                .collect();
            workers.into_iter().for_each(Self::finish);
        });
    }

    /// Waits for a worker, resuming its panic on the calling thread.
    fn finish(worker: ScopedJoinHandle<'_, ()>) {
        worker
            .join()
            .unwrap_or_else(|payload| panic::resume_unwind(payload));
    }
}
