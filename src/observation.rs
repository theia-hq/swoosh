//! Following the connection an observed Open attached to through `swoosh serve`: a receipt for its
//! reference, and one observer that samples it beside the run and finishes it at the end.
//!
//! The observer keeps three things apart. The run's own result is the caller's; the observer returns
//! the final observation, read by a Finish after the run, and at most one earlier failure to sample,
//! kept beside it rather than in its place. A failed observation never turns a measured run into a
//! failed one, and an old sample is never offered as the final one.

use core::convert::Infallible;
use core::future::Future;
use core::time::Duration;
use std::rc::Rc;

use bifrost::ConnInfo;
use tokio::time::Instant;

use crate::node_client::UidSocket;
use crate::serve::control_codec::{ControlError, PathAction, PathRef, PathReply, PathRequest};

/// The least time between the starts of two queries on one receipt, the Finish included, and between
/// the Attached report and the first periodic sample. The Attached report is the Open's reply, not a
/// query, so a Finish with no query before it waits for nothing.
pub const SPACING: Duration = Duration::from_secs(1);

/// Where a receipt's queries go: the resident's control socket, or a test's stand-in.
pub trait PathSource {
    /// Send `request` and read its reply.
    fn path(&self, request: PathRequest) -> impl Future<Output = Result<PathReply, ControlError>>;
}

impl PathSource for UidSocket {
    fn path(&self, request: PathRequest) -> impl Future<Output = Result<PathReply, ControlError>> {
        Self::path(self, request)
    }
}

/// Why a query on a receipt gave no sample.
#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    /// The resident no longer answers for the reference: finished, past its retention, or from a run
    /// that has since restarted.
    #[error("the connection's path is no longer observable through swoosh serve")]
    Unavailable,
    /// The exchange with the resident failed.
    #[error(transparent)]
    Control(#[from] ControlError),
}

/// An observed Open's receipt: its reference and the checked socket it was handed out on.
///
/// Not `Clone`, and [`finish`](Self::finish) consumes it, so one receipt is finished at most once. A
/// sample borrows it; the reference is public, so a sample confers nothing a Finish needs.
#[derive(Debug)]
pub struct Receipt<P: PathSource = UidSocket> {
    reference: PathRef,
    source: Rc<P>,
}

impl<P: PathSource> Receipt<P> {
    /// The receipt for `reference`, queried through `source`, the socket its Open was answered on.
    pub fn new(reference: PathRef, source: Rc<P>) -> Self {
        Self { reference, source }
    }

    /// Sample the connection; the reference stays.
    ///
    /// # Errors
    ///
    /// [`ObservationError`] when the resident has no sample or the exchange fails.
    pub async fn sample(&self) -> Result<ConnInfo, ObservationError> {
        self.ask(PathAction::Sample).await
    }

    /// Sample the connection once more and retire the reference. Whatever the outcome, the receipt is
    /// spent: a Finish whose reply was lost is not tried again, since the resident has already retired
    /// the reference and a retry could only read Unavailable.
    ///
    /// # Errors
    ///
    /// [`ObservationError`] when the resident has no sample or the exchange fails.
    pub async fn finish(self) -> Result<ConnInfo, ObservationError> {
        self.ask(PathAction::Finish).await
    }

    async fn ask(&self, action: PathAction) -> Result<ConnInfo, ObservationError> {
        let request = PathRequest {
            reference: self.reference,
            action,
        };
        match self.source.path(request).await? {
            PathReply::Sample(info) => Ok(info),
            PathReply::Unavailable => Err(ObservationError::Unavailable),
        }
    }
}

/// What a finished observation found.
#[derive(Debug)]
pub struct Observed {
    /// The final observation: the Finish's sample, or why there is none. Never an earlier sample.
    pub last: Result<ConnInfo, ObservationError>,
    /// The first sample that failed during the run, if one did, kept apart from the final observation.
    pub earlier: Option<ObservationError>,
}

/// The one observer of a receipt, driven beside the run that uses its stream: it samples the connection
/// at most once per [`SPACING`], whether or not anything prints, and finishes it once the run is over.
#[derive(Debug)]
pub struct Observer<P: PathSource = UidSocket> {
    receipt: Receipt<P>,
    latest: ConnInfo,
    earlier: Option<ObservationError>,
    /// When the Attached report was read: the first periodic sample waits a [`SPACING`] after it.
    attached_at: Instant,
    /// When the last query started, if one has. Only a query spaces the Finish.
    queried: Option<Instant>,
    /// Set once the resident has said the reference is gone: no later sample can say otherwise.
    gone: bool,
}

impl<P: PathSource> Observer<P> {
    /// Observe `receipt`, whose Open attached on a connection reading `attached`. The Attached report is
    /// the first observation; the first sample waits a whole [`SPACING`] after it.
    pub fn new(receipt: Receipt<P>, attached: ConnInfo) -> Self {
        Self {
            receipt,
            latest: attached,
            earlier: None,
            attached_at: Instant::now(),
            queried: None,
            gone: false,
        }
    }

    /// The latest successful sample, or the Attached report before the first.
    pub fn latest(&self) -> &ConnInfo {
        &self.latest
    }

    /// Sample the connection once per [`SPACING`] until dropped. Dropping it mid-query cancels that
    /// query at once; the spacing it began still holds for the next.
    pub async fn watch(&mut self) -> Infallible {
        self.watch_with(|_| {}).await
    }

    /// [`watch`](Self::watch), handing each successful sample to `on_sample` as it lands. A failed
    /// sample reaches it never: it is kept as the earlier failure, and the caller's view keeps what it
    /// last showed.
    pub async fn watch_with(&mut self, mut on_sample: impl FnMut(&ConnInfo)) -> Infallible {
        loop {
            if self.gone {
                return core::future::pending().await;
            }
            tokio::time::sleep_until(after_spacing(self.queried.unwrap_or(self.attached_at))).await;
            // Counted from the query's start, before the await, so a query cut short still spaces the
            // next one, the Finish included.
            self.queried = Some(Instant::now());
            match self.receipt.sample().await {
                Ok(info) => {
                    on_sample(&info);
                    self.latest = info;
                }
                Err(error) => {
                    self.gone = matches!(error, ObservationError::Unavailable);
                    self.earlier.get_or_insert(error);
                }
            }
        }
    }

    /// Finish the receipt once what is left of the last query's spacing has passed, at once when no
    /// query has started, never a whole query's bound, and return the final observation beside the
    /// run's earlier failure, if any.
    pub async fn finish(self) -> Observed {
        if let Some(queried) = self.queried {
            tokio::time::sleep_until(after_spacing(queried)).await;
        }
        Observed {
            last: self.receipt.finish().await,
            earlier: self.earlier,
        }
    }

    /// [`finish`](Self::finish) for a run whose result does not wait on the reading: given what is left
    /// of the spacing plus `grace`, and dropped past that, `None` then. A resident that accepts the
    /// query and stalls holds the exit no longer; the resident lets the reference go at the end of its
    /// retention instead.
    pub async fn finish_within(self, grace: Duration) -> Option<Observed> {
        let now = Instant::now();
        let spaced = self.queried.map_or(now, after_spacing).max(now);
        let deadline = spaced.checked_add(grace).unwrap_or(spaced);
        tokio::time::timeout_at(deadline, self.finish()).await.ok()
    }
}

/// [`SPACING`] after `start`. A clock that cannot hold it leaves the next query unspaced rather than
/// panicking or waiting forever.
fn after_spacing(start: Instant) -> Instant {
    start.checked_add(SPACING).unwrap_or(start)
}

#[cfg(test)]
#[path = "observation_tests.rs"]
mod tests;
