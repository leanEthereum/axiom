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
    use tokio::sync::oneshot;

    use super::*;

    #[test]
    fn outputs_come_in_completion_order() {
        // Fixture state: three futures at positions 0, 1, and 2, each waiting on its own signal.
        // The test fires the signals in the order 1, 2, 0, so no timer decides the order.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let order = runtime.block_on(async {
            let (senders, receivers): (Vec<_>, Vec<_>) =
                (0..3).map(|_| oneshot::channel::<u64>()).unzip();
            let mut set = Concurrent::new(
                receivers
                    .into_iter()
                    .map(|receiver| async move { receiver.await.unwrap() }),
            );
            let mut senders: Vec<_> = senders.into_iter().map(Some).collect();
            let mut order = Vec::new();
            for position in [1, 2, 0] {
                // Only this position's signal fires, so only it can finish next.
                let sender = senders[position].take().unwrap();
                sender.send(position as u64 * 10).unwrap();
                order.push(set.next().await.unwrap());
            }
            // Every future finished, so the set reports the end.
            assert_eq!(set.next().await, None);
            order
        });
        assert_eq!(order, vec![(1, 10), (2, 20), (0, 0)]);
    }
}
