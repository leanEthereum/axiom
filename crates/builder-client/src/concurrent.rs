//! Driving several futures at once, taking each output as it completes.

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

/// Futures run together on the caller's task, yielding outputs in completion order.
///
/// Nothing is spawned, so the futures may borrow from the caller.
/// Dropping the set drops every unfinished future, cancelling its request.
pub(crate) struct Concurrent<F> {
    /// The futures by input position; a finished one leaves an empty slot.
    futures: Vec<Option<Pin<Box<F>>>>,
}

impl<F: Future> Concurrent<F> {
    /// Starts nothing yet: the futures run when the set is polled.
    pub(crate) fn new(futures: impl IntoIterator<Item = F>) -> Self {
        Self {
            futures: futures
                .into_iter()
                .map(|future| Some(Box::pin(future)))
                .collect(),
        }
    }

    /// The next output and its input position, or nothing once every future finished.
    ///
    /// Every unfinished future is polled on each wake, since any of them may have woken the task.
    /// On a tie the lower position comes out first.
    pub(crate) async fn next(&mut self) -> Option<(usize, F::Output)> {
        poll_fn(|cx| {
            let mut pending = false;
            for (index, slot) in self.futures.iter_mut().enumerate() {
                let Some(future) = slot else {
                    continue;
                };
                if let Poll::Ready(output) = future.as_mut().poll(cx) {
                    *slot = None;
                    return Poll::Ready(Some((index, output)));
                }
                pending = true;
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(None)
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::sleep;

    use super::*;

    #[test]
    fn outputs_come_in_completion_order() {
        // Fixture state: three timers of 30, 10, and 20 milliseconds, at positions 0, 1, and 2.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let order = runtime.block_on(async {
            let mut set = Concurrent::new([30_u64, 10, 20].map(|millis| async move {
                sleep(Duration::from_millis(millis)).await;
                millis
            }));
            let mut order = Vec::new();
            while let Some(output) = set.next().await {
                order.push(output);
            }
            order
        });
        assert_eq!(order, vec![(1, 10), (2, 20), (0, 30)]);
    }
}
