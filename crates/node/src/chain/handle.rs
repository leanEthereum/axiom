//! The chain runs on its own thread; async services reach it through a handle.

use std::{
    io,
    thread::{self, JoinHandle},
};

use axiom_types::Preset;
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use super::Chain;

/// How many requests may queue for the chain before senders wait.
///
/// The bound turns a flood of gossip into back-pressure instead of unbounded memory.
const QUEUE_DEPTH: usize = 1024;

/// A request: a closure the chain thread runs with exclusive access.
type Job<P> = Box<dyn FnOnce(&mut Chain<P>) + Send>;

/// The chain thread is gone, so the request was never run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("chain service stopped")]
pub struct ChainStopped;

/// A cloneable way to run work on the chain thread.
///
/// # Overview
///
/// The chain is synchronous and owned by one thread, so it needs no lock.
/// Requests queue in order and run one at a time.
///
/// ```text
///     api task ───┐
///     ticker ─────┼──> queue ──> chain thread: job(&mut chain) ──> reply
///     network ────┘
/// ```
///
/// Heavy work such as a state transition blocks only the chain thread, never the async runtime.
#[derive(Debug)]
pub struct ChainHandle<P: Preset> {
    /// The request queue.
    jobs: mpsc::Sender<Job<P>>,
}

impl<P: Preset> Clone for ChainHandle<P> {
    fn clone(&self) -> Self {
        Self {
            jobs: self.jobs.clone(),
        }
    }
}

impl<P: Preset> ChainHandle<P> {
    /// Moves a chain onto a new thread and returns a handle to it.
    ///
    /// The thread ends once every handle is dropped and the queue drains.
    ///
    /// # Errors
    ///
    /// Fails when the operating system refuses a new thread.
    pub fn spawn(mut chain: Chain<P>) -> io::Result<(Self, JoinHandle<Chain<P>>)> {
        let (jobs, mut queue) = mpsc::channel::<Job<P>>(QUEUE_DEPTH);
        let thread = thread::Builder::new()
            .name("chain".to_owned())
            .spawn(move || {
                // Blocking receive is right here: this thread does nothing else.
                while let Some(job) = queue.blocking_recv() {
                    job(&mut chain);
                }
                chain
            })?;
        Ok((Self { jobs }, thread))
    }

    /// Runs a closure on the chain thread and returns its result.
    ///
    /// # Errors
    ///
    /// Fails when the chain thread has stopped.
    pub async fn run<R: Send + 'static>(
        &self,
        job: impl FnOnce(&mut Chain<P>) -> R + Send + 'static,
    ) -> Result<R, ChainStopped> {
        let (reply, answer) = oneshot::channel();
        let job: Job<P> = Box::new(move |chain| {
            // The requester may have given up waiting, which is not the chain's concern.
            let _abandoned = reply.send(job(chain));
        });
        self.jobs.send(job).await.map_err(|_| ChainStopped)?;
        answer.await.map_err(|_| ChainStopped)
    }
}
