use core::time::Duration;

use nauthy::VerifyKey;

use super::{Artifact, STAT_DEBOUNCE};
use crate::contacts::DeviceLabel;
use crate::roster::{Epoch, RosterDoc};
use crate::testkit::TestRoot;

/// The byte the signet's fixed key is seeded with, so a test's cut is reproducible and verifiable.
const SIGNET: u8 = 11;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-roster-artifact-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("roster")
}

fn doc(epoch: u64, labels: &[&str]) -> RosterDoc {
    let members = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            signet()
                .member(
                    VerifyKey::new([u8::try_from(index).expect("small") + 1; 32]),
                    label.parse::<DeviceLabel>().expect("a valid label"),
                )
                .expect("a member")
        })
        .collect();
    RosterDoc::new(Epoch(epoch), members).expect("a well-formed doc")
}

fn signet() -> TestRoot {
    TestRoot::seeded(SIGNET)
}

/// An absent file opens as an EMPTY artifact, and the file APPEARING is picked up with no reload. This is
/// the founder's opening move: `serve` before any device has been invited, then invite one from
/// another terminal. The old path cut once at serve start, so that invite needed a restart to publish.
#[tokio::test]
async fn an_absent_artifact_opens_empty_and_fills_in_when_the_signet_cuts() {
    let path = scratch("absent");
    let artifact = Artifact::open(path.clone())
        .await
        .expect("an absent file is not an error");
    assert!(
        artifact.bytes().is_empty(),
        "there is nothing to serve until the signet cuts"
    );

    Artifact::write(&path, signet().identity(), &doc(1, &["desk"]))
        .await
        .expect("the first membership edit cuts one");
    tokio::time::sleep(STAT_DEBOUNCE + Duration::from_millis(50)).await;
    let served = crate::roster::verify(&artifact.bytes(), signet().verify_key())
        .expect("a roster cut after serve started is served without a restart");
    assert_eq!(served.epoch(), Epoch(1));
}

#[tokio::test]
async fn a_written_artifact_verifies_against_the_signet_that_cut_it() {
    let path = scratch("verifies");
    Artifact::write(&path, signet().identity(), &doc(1, &["desk"]))
        .await
        .expect("write");
    let artifact = Artifact::open(path).await.expect("load");
    let parsed = crate::roster::verify(&artifact.bytes(), signet().verify_key())
        .expect("the served bytes verify against the signet");
    assert_eq!(parsed.epoch(), Epoch(1));
    assert_eq!(parsed.members().len(), 1);
}

/// THE freshness property, and the whole reason the artifact is an oracle rather than a blob: a
/// membership edit in ANOTHER process rewrites the file, and a node that is already serving picks it up
/// on the next read. Before this, the snapshot was cut once at serve start and a restart was the only
/// way to publish a new member.
#[tokio::test]
async fn a_re_cut_is_picked_up_without_a_reload() {
    let path = scratch("recut");
    Artifact::write(&path, signet().identity(), &doc(1, &["desk"]))
        .await
        .expect("write");
    let artifact = Artifact::open(path.clone()).await.expect("load");
    let first = crate::roster::verify(&artifact.bytes(), signet().verify_key()).expect("verify");
    assert_eq!(first.members().len(), 1);

    // Another process (an `invite add`) re-cuts at the next version with one more member.
    Artifact::write(&path, signet().identity(), &doc(2, &["desk", "phone"]))
        .await
        .expect("re-cut");
    // Past the debounce, so the next read stats and sees the change; inside it, the oracle is allowed to
    // serve what it last read, exactly as its two siblings are.
    tokio::time::sleep(STAT_DEBOUNCE + Duration::from_millis(50)).await;

    let second = crate::roster::verify(&artifact.bytes(), signet().verify_key()).expect("verify");
    assert_eq!(
        second.epoch(),
        Epoch(2),
        "the serving node must see the re-cut with no restart"
    );
    assert_eq!(second.members().len(), 2);
}

/// Deleting the file does not empty the fleet. A botched cleanup (or a local attacker) must never turn
/// into "you have no members" for every device that pulls, so the oracle keeps its last-known blob, the
/// same fail-closed posture both sibling oracles take.
#[tokio::test]
async fn a_deleted_artifact_keeps_serving_the_last_cut() {
    let path = scratch("deleted");
    Artifact::write(&path, signet().identity(), &doc(1, &["desk"]))
        .await
        .expect("write");
    let artifact = Artifact::open(path.clone()).await.expect("load");
    let before = artifact.bytes();
    std::fs::remove_file(&path).expect("remove the artifact");
    tokio::time::sleep(STAT_DEBOUNCE + Duration::from_millis(50)).await;
    assert_eq!(
        artifact.bytes(),
        before,
        "a vanished artifact keeps the last-known fleet, never an empty one"
    );
}
