//! Waiting on the first of two futures.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};

/// Which of two raced futures finished first.
#[derive(Debug)]
pub(crate) enum Either<A, B> {
    /// The first future won.
    Left(A),
    /// The second future won.
    Right(B),
}

impl<A, B> Either<A, B> {
    /// Runs two futures together and returns the first output, dropping the other future.
    ///
    /// The first future is polled first on every wake, so it wins a tie.
    pub(crate) async fn race<L, R>(left: L, right: R) -> Self
    where
        L: Future<Output = A>,
        R: Future<Output = B>,
    {
        // Both futures live on this frame's stack, pinned for the duration of the race.
        let mut left = pin!(left);
        let mut right = pin!(right);
        poll_fn(|cx| {
            // Poll both on every wake; either may have been the one to wake the task.
            if let Poll::Ready(output) = left.as_mut().poll(cx) {
                return Poll::Ready(Self::Left(output));
            }
            if let Poll::Ready(output) = right.as_mut().poll(cx) {
                return Poll::Ready(Self::Right(output));
            }
            Poll::Pending
        })
        .await
    }
}
