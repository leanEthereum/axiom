//! Data parallelism over scoped threads, for the independent pieces of the heavy operations.
//!
//! Every helper joins its threads before returning and computes exactly what the sequential loop would.
//! Group sums are exact, so the split never changes a result.

use std::{num::NonZero, panic, thread};

use axiom_bls12_381::{G1Affine, G1Projective, Scalar};

/// Below this many points per thread, a multi-scalar multiplication stays on one thread.
///
/// Spawning a thread costs tens of microseconds.
/// A 256-point MSM costs a few milliseconds, so smaller splits stop paying for themselves.
const MIN_POINTS_PER_THREAD: usize = 256;

/// Number of threads worth running, at most one per item.
fn thread_count(items: usize) -> usize {
    // The query fails on exotic platforms, which then run sequentially.
    thread::available_parallelism()
        .map_or(1, NonZero::get)
        .min(items)
}

/// Maps a function over a slice on all available cores, keeping the input order.
///
/// A panic in any worker resumes on the calling thread.
pub(crate) fn map<T: Sync, R: Send>(items: &[T], function: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let threads = thread_count(items.len());
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

/// Applies a function to every element of a slice in place, on all available cores.
///
/// A panic in any worker resumes on the calling thread.
pub(crate) fn for_each_mut<T: Send>(items: &mut [T], function: impl Fn(&mut T) + Sync) {
    let threads = thread_count(items.len());
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
        for worker in workers {
            worker
                .join()
                .unwrap_or_else(|payload| panic::resume_unwind(payload));
        }
    });
}

/// Runs two closures concurrently and returns both results.
///
/// A panic in the spawned closure resumes on the calling thread.
pub(crate) fn join<A: Send, B: Send>(
    left: impl FnOnce() -> A + Send,
    right: impl FnOnce() -> B + Send,
) -> (A, B) {
    // The right side runs on a new thread while this thread runs the left side.
    thread::scope(|scope| {
        let worker = scope.spawn(right);
        let a = left();
        let b = worker
            .join()
            .unwrap_or_else(|payload| panic::resume_unwind(payload));
        (a, b)
    })
}

/// Computes sum_i k_i P_i, splitting large inputs into one Pippenger MSM per core.
///
/// The scalars must be public, as for every multi-scalar multiplication of the curve crate.
///
/// # Panics
///
/// Panics when the two slices differ in length.
pub(crate) fn multi_exp(points: &[G1Affine], scalars: &[Scalar]) -> G1Projective {
    assert_eq!(points.len(), scalars.len(), "one scalar per point");

    // Threshold: each thread needs enough points to amortize its spawn.
    let threads = thread_count(points.len() / MIN_POINTS_PER_THREAD);
    if threads <= 1 {
        return G1Projective::multi_exp(points, scalars);
    }

    // Split both slices at the same boundaries, then add the partial sums.
    //
    //     sum_{i < n} k_i P_i = sum_t ( sum_{i in chunk t} k_i P_i )
    let chunk = points.len().div_ceil(threads);
    let pairs: Vec<(&[G1Affine], &[Scalar])> =
        points.chunks(chunk).zip(scalars.chunks(chunk)).collect();
    map(&pairs, |(points, scalars)| {
        G1Projective::multi_exp(points, scalars)
    })
    .into_iter()
    .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_keeps_order() {
        // Fixture state: 1000 items, more than any core count, so the input splits.
        let items: Vec<u64> = (0..1000).collect();
        let doubled = map(&items, |item| item * 2);
        assert_eq!(doubled, (0..1000).map(|item| item * 2).collect::<Vec<_>>());
        // An empty input maps to an empty output.
        assert_eq!(map(&[] as &[u64], |item| *item), Vec::<u64>::new());
    }

    #[test]
    fn split_msm_matches_single_msm() {
        // Fixture state: 2048 points, enough for up to 8 threads of 256 points.
        //
        //     P_i = (i + 1) G and k_i = i + 2, so the sum is sum_i (i + 1)(i + 2) G.
        let scalars: Vec<Scalar> = (0..2048).map(|i| Scalar::from_u64(i + 2)).collect();
        let points: Vec<G1Affine> = (0..2048)
            .map(|i| G1Affine::from(G1Projective::GENERATOR.mul_vartime(&Scalar::from_u64(i + 1))))
            .collect();
        assert_eq!(
            multi_exp(&points, &scalars),
            G1Projective::multi_exp(&points, &scalars)
        );
    }
}
