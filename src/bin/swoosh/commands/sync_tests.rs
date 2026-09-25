//! `sync`: how it reads each reply, what it prints, and where it refuses.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::Parser as _;
use keystore::{KeyFile, Protection};
use swoosh::home::Home;
use swoosh::roster::Epoch;
use swoosh::sync::Answer;
use swoosh::testkit::{TestNode, TestRoot};

use super::{Row, refuse_unless_device, report};

#[test]
fn sync_reads_each_reply_as_its_row() {
    let cases = [
        (Some(Answer::Same), Row::InSync),
        (Some(Answer::Took), Row::Took),
        (Some(Answer::Gave), Row::Gave),
        (Some(Answer::Forked), Row::Fork),
        (Some(Answer::ForkRecorded { floor: Epoch(4) }), Row::Fork),
        (Some(Answer::Refused), Row::NoAnswer),
        (None, Row::NoAnswer),
    ];
    for (answer, row) in cases {
        assert_eq!(Row::of(answer), row, "{answer:?} reads as {row:?}");
    }
}

#[test]
fn sync_prints_its_lines() {
    let rows = |rows: &[(&str, Row)]| -> Vec<(String, Row)> {
        rows.iter()
            .map(|(name, row)| ((*name).to_owned(), *row))
            .collect()
    };
    assert_eq!(
        report(&rows(&[
            ("me/nas", Row::InSync),
            ("me/laptop", Row::InSync),
            ("me/phone", Row::NoAnswer),
        ])),
        "in sync with me/nas, me/laptop (me/phone did not answer).\n"
    );
    assert_eq!(
        report(&rows(&[("me/nas", Row::Took), ("me/laptop", Row::Gave)])),
        "took the newest list of your devices from me/nas; gave it to me/laptop.\n"
    );
    assert_eq!(
        report(&rows(&[("me/nas", Row::Gave)])),
        "gave the newest list of your devices to me/nas.\n"
    );
    assert_eq!(
        report(&rows(&[("me/nas", Row::NoAnswer)])),
        "no device answered; your devices get it at their next sync.\n"
    );
    assert_eq!(
        report(&rows(&[])),
        "no device answered; your devices get it at their next sync.\n"
    );
    assert_eq!(
        report(&rows(&[("me/nas", Row::Fork)])),
        "me/nas holds a different list of your devices. Kept every revoked key from both; your next \
         swoosh invite or swoosh revoke settles it.\n"
    );
}

/// A fresh home holding only this machine's key.
fn home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!(
        "swoosh-sync-cmd-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    swoosh::config::create_store_dir(&dir).unwrap();
    let home = Home::resolve(Some(dir)).unwrap();
    let mut seed = TestNode::seeded(0x11).seed();
    KeyFile::device(home.identity_key())
        .write(&keystore::Secret::take(&mut seed), Protection::Plain)
        .unwrap();
    home
}

#[tokio::test]
async fn sync_refuses_each_standing_that_is_not_a_device() {
    let unpinned = home("unpinned");
    let error = refuse_unless_device(&unpinned).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "this machine is not one of your devices yet: nothing to sync. To join yours: swoosh join"
    );

    let interrupted = home("interrupted");
    let root = TestRoot::seeded(0x21);
    swoosh::config::create_store_dir(&interrupted.root()).unwrap();
    let mut seed = root.seed();
    let passphrase =
        keystore::Passphrase::try_from(zeroize::Zeroizing::new("a root passphrase".to_owned()))
            .unwrap();
    KeyFile::root(interrupted.root().join("root.key"))
        .write(
            &keystore::Secret::take(&mut seed),
            Protection::Passphrase(&passphrase),
        )
        .unwrap();
    let error = refuse_unless_device(&interrupted).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "root: root:{}… made here, not finished: the next swoosh invite finishes it.",
            root.node_id().short()
        )
    );

    let damaged = home("damaged");
    let badge = root
        .device_badge(
            TestNode::seeded(0x11).node_id(),
            std::time::SystemTime::now() + core::time::Duration::from_secs(3600),
        )
        .unwrap();
    swoosh::config::write_badge(&damaged, &badge).await.unwrap();
    let error = refuse_unless_device(&damaged).await.unwrap_err();
    let line = error.to_string();
    assert!(
        line.starts_with("root: this machine's records disagree (")
            && line.ends_with(
                "): swoosh cannot tell which root it trusts. Run swoosh leave to start over; a root \
                 kept here stays."
            ),
        "{line}"
    );
}

#[test]
fn sync_takes_no_argument() {
    let error = crate::Cli::try_parse_from(["swoosh", "sync", "me/nas"]).unwrap_err();
    assert_eq!(error.exit_code(), 2, "a positional is a usage error");
    assert!(crate::Cli::try_parse_from(["swoosh", "sync"]).is_ok());
}
