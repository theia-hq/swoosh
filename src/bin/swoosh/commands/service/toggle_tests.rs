//! Tests for the `service enable`/`disable` file toggle: the round-trip on `<home>/disabled`, the sorted
//! atomic rewrite, and idempotency.

use std::collections::BTreeSet;

use swoosh::home::Home;

use super::{ServiceToggleCmd, read};

/// A fresh, empty home under a unique temp dir, so parallel tests never share a `<home>/disabled`.
fn temp_home(tag: &str) -> Home {
    let dir = std::env::temp_dir().join(format!("swoosh-toggle-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create the temp home");
    Home::resolve(Some(dir)).expect("resolve the temp home")
}

/// The disabled set currently on disk, read back through the same parse the oracle uses.
fn disabled_on_disk(home: &Home) -> BTreeSet<String> {
    read(&home.disabled()).expect("read the disabled file")
}

/// A `disable` writes the name into `<home>/disabled`; an `enable` takes it back out. The core round-trip.
#[tokio::test]
async fn disable_then_enable_round_trips() {
    let home = temp_home("round-trip");

    ServiceToggleCmd {
        service: "speed".parse().expect("a service"),
    }
    .run_disable(&home)
    .await
    .expect("disable speed");
    assert!(
        disabled_on_disk(&home).contains("speed"),
        "speed is written to the disabled file"
    );

    ServiceToggleCmd {
        service: "speed".parse().expect("a service"),
    }
    .run_enable(&home)
    .await
    .expect("enable speed");
    assert!(
        !disabled_on_disk(&home).contains("speed"),
        "speed is removed from the disabled file"
    );

    let _ = std::fs::remove_dir_all(home.dir());
}

/// Disabling accumulates distinct names and the file is name-sorted (a clean diff, the denylist's shape).
#[tokio::test]
async fn disables_accumulate_sorted_and_idempotent() {
    let home = temp_home("accumulate");

    for name in ["speed", "ping", "speed"] {
        ServiceToggleCmd {
            service: name.parse().expect("a service"),
        }
        .run_disable(&home)
        .await
        .expect("disable");
    }

    let on_disk = disabled_on_disk(&home);
    assert_eq!(
        on_disk.iter().cloned().collect::<Vec<_>>(),
        vec!["ping".to_owned(), "speed".to_owned()],
        "distinct names only (idempotent), name-sorted"
    );

    // The raw file body is sorted with a trailing newline, so the mtime-watched oracle parses it cleanly.
    let body = std::fs::read_to_string(home.disabled()).expect("read raw");
    assert_eq!(body, "ping\nspeed\n", "sorted, newline-terminated");

    let _ = std::fs::remove_dir_all(home.dir());
}

/// Enabling a service that was never disabled is a no-op, not an error (idempotent).
#[tokio::test]
async fn enable_of_an_untouched_service_is_a_noop() {
    let home = temp_home("enable-noop");
    ServiceToggleCmd {
        service: "ping".parse().expect("a service"),
    }
    .run_enable(&home)
    .await
    .expect("enable a never-disabled service succeeds");
    assert!(disabled_on_disk(&home).is_empty(), "nothing disabled");
    let _ = std::fs::remove_dir_all(home.dir());
}
