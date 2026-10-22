//! Waiting on the first of two futures, without a macro.

use std::{
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
};

/// The output of whichever of two raced futures finished first.
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
        // Both futures live on this frame, pinned for the duration of the race.
        let mut left = pin!(left);
        let mut right = pin!(right);
        poll_fn(|cx| {
            // Poll both on every wake; either may be the one that woke the task.
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

#[cfg(test)]
mod tests {
    use std::future::{pending, ready};

    use tokio::runtime::Builder;

    use super::*;

    #[test]
    fn the_ready_future_wins_and_the_left_wins_ties() {
        let runtime = Builder::new_current_thread().build().unwrap();

        // Only the right side ever completes.
        let right: Either<(), u8> = runtime.block_on(Either::race(pending(), ready(2)));
        assert!(matches!(right, Either::Right(2)));

        // Both are ready: the left is polled first.
        let tie: Either<u8, u8> = runtime.block_on(Either::race(ready(1), ready(2)));
        assert!(matches!(tie, Either::Left(1)));
    }
}
