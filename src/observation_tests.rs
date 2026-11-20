use core::cell::RefCell;
use core::num::NonZeroU64;
use core::time::Duration;
use std::collections::VecDeque;
use std::rc::Rc;

use bifrost::{ConnInfo, Path};
use tokio::time::Instant;

use super::{ObservationError, Observer, PathSource, Receipt};
use crate::serve::control_codec::{
    ControlError, Epoch, PathAction, PathRef, PathReply, PathRequest, Ticket,
};

/// What the stand-in resident does with one query.
enum Step {
    /// Answer at once.
    Answer(Result<PathReply, ControlError>),
    /// Never answer.
    Stall,
}

/// A resident stand-in that answers queries in order and records when each started and what it asked.
#[derive(Default)]
struct Scripted {
    steps: RefCell<VecDeque<Step>>,
    asked: RefCell<Vec<(Duration, PathAction)>>,
    start: RefCell<Option<Instant>>,
}

impl Scripted {
    fn new(steps: impl IntoIterator<Item = Step>) -> Rc<Self> {
        Rc::new(Self {
            steps: RefCell::new(steps.into_iter().collect()),
            asked: RefCell::default(),
            start: RefCell::new(Some(Instant::now())),
        })
    }

    /// Each query's start, as time since the script began, and its action.
    fn asked(&self) -> Vec<(Duration, PathAction)> {
        self.asked.borrow().clone()
    }
}

impl PathSource for Scripted {
    async fn path(&self, request: PathRequest) -> Result<PathReply, ControlError> {
        let since = Instant::now() - self.start.borrow().unwrap();
        self.asked.borrow_mut().push((since, request.action));
        let step = self.steps.borrow_mut().pop_front();
        match step {
            Some(Step::Answer(answer)) => answer,
            Some(Step::Stall) | None => core::future::pending().await,
        }
    }
}

fn reference() -> PathRef {
    PathRef::new(
        Epoch::draw(&mut rand::rngs::OsRng).unwrap(),
        Ticket::at(NonZeroU64::MIN),
    )
}

fn observer(script: &Rc<Scripted>) -> Observer<Scripted> {
    Observer::new(Receipt::new(reference(), Rc::clone(script)), relayed())
}

fn sample(info: ConnInfo) -> Step {
    Step::Answer(Ok(PathReply::Sample(info)))
}

fn direct() -> ConnInfo {
    ConnInfo {
        path: Path::Direct,
        ..ConnInfo::default()
    }
}

fn relayed() -> ConnInfo {
    ConnInfo {
        path: Path::Relayed(bifrost::Relay::from(
            url::Url::parse("https://relay.example/").unwrap(),
        )),
        ..ConnInfo::default()
    }
}

/// Drive `observer` as a run that lasts `run` would, then return it for its Finish.
async fn run_for(observer: &mut Observer<Scripted>, run: Duration) {
    tokio::select! {
        never = observer.watch() => match never {},
        () = tokio::time::sleep(run) => {}
    }
}

fn secs(secs: f64) -> Duration {
    Duration::from_secs_f64(secs)
}

#[tokio::test(start_paused = true)]
async fn a_quiet_run_is_sampled_once_a_second_and_finished_after_it() {
    let script = Scripted::new([
        sample(relayed()),
        sample(direct()),
        sample(ConnInfo::default()),
        sample(direct()),
    ]);
    let mut observer = observer(&script);
    run_for(&mut observer, secs(3.5)).await;
    // An Unknown sample replaces a Direct one: it is a reading of the same connection.
    assert_eq!(observer.latest(), &ConnInfo::default());
    let observed = observer.finish().await;
    assert_eq!(observed.last.unwrap(), direct());
    assert!(observed.earlier.is_none());
    assert_eq!(
        script.asked(),
        [
            (secs(1.0), PathAction::Sample),
            (secs(2.0), PathAction::Sample),
            (secs(3.0), PathAction::Sample),
            (secs(4.0), PathAction::Finish),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_sample_is_cut_when_the_run_ends_and_finish_waits_only_the_spacing_left() {
    let script = Scripted::new([Step::Stall, sample(direct())]);
    let mut observer = observer(&script);
    run_for(&mut observer, secs(1.2)).await;
    let ended = Instant::now();
    let observed = observer.finish().await;
    // Finished one spacing after the stalled sample began, not a whole query's bound after it.
    assert_eq!(Instant::now() - ended, secs(0.8));
    assert_eq!(observed.last.unwrap(), direct());
    assert_eq!(
        script.asked(),
        [
            (secs(1.0), PathAction::Sample),
            (secs(2.0), PathAction::Finish)
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_run_shorter_than_the_spacing_is_finished_one_spacing_after_attached() {
    let script = Scripted::new([sample(direct())]);
    let mut observer = observer(&script);
    run_for(&mut observer, secs(0.3)).await;
    let observed = observer.finish().await;
    assert_eq!(observed.last.unwrap(), direct());
    assert_eq!(script.asked(), [(secs(1.0), PathAction::Finish)]);
}

#[tokio::test(start_paused = true)]
async fn an_earlier_failure_stays_beside_a_fresh_final_sample() {
    let script = Scripted::new([
        Step::Answer(Err(ControlError::Timeout {
            phase: "response read",
        })),
        sample(relayed()),
        sample(direct()),
    ]);
    let mut observer = observer(&script);
    run_for(&mut observer, secs(2.5)).await;
    let observed = observer.finish().await;
    assert_eq!(observed.last.unwrap(), direct());
    assert!(matches!(
        observed.earlier,
        Some(ObservationError::Control(ControlError::Timeout { .. }))
    ));
}

#[tokio::test(start_paused = true)]
async fn an_unavailable_finish_is_a_failure_never_the_last_sample() {
    let script = Scripted::new([sample(direct()), Step::Answer(Ok(PathReply::Unavailable))]);
    let mut observer = observer(&script);
    run_for(&mut observer, secs(1.5)).await;
    assert_eq!(observer.latest(), &direct());
    let observed = observer.finish().await;
    assert!(matches!(observed.last, Err(ObservationError::Unavailable)));
    assert!(observed.earlier.is_none());
}

#[tokio::test(start_paused = true)]
async fn a_reference_gone_mid_run_stops_the_sampling() {
    let script = Scripted::new([
        Step::Answer(Ok(PathReply::Unavailable)),
        Step::Answer(Ok(PathReply::Unavailable)),
    ]);
    let mut observer = observer(&script);
    run_for(&mut observer, secs(5.5)).await;
    let observed = observer.finish().await;
    assert!(matches!(observed.last, Err(ObservationError::Unavailable)));
    assert!(matches!(
        observed.earlier,
        Some(ObservationError::Unavailable)
    ));
    // One sample found the reference gone; nothing more was asked until the Finish.
    assert_eq!(
        script.asked(),
        [
            (secs(1.0), PathAction::Sample),
            (secs(5.5), PathAction::Finish)
        ]
    );
}
