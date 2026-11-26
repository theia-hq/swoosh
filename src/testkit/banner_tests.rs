use core::time::Duration;
use std::time::Instant;

use super::{key_and_loopback, read};

#[test]
fn the_key_and_the_loopback_row_are_read() {
    let banner = "swoosh is serving\n\n  key            ed01exampleid\n\nreach\n  internet       off (--local)\n  this computer  127.0.0.1:1234\n";
    assert_eq!(
        key_and_loopback(banner),
        Some(("ed01exampleid".to_owned(), "127.0.0.1:1234".to_owned()))
    );
}

#[test]
fn a_service_named_key_does_not_replace_the_first_key_row() {
    let key = bifrost::NodeId::from_ed25519_secret(&[0x11; 32]).to_string();
    let banner = format!(
        "  key            {key}\n  this computer  127.0.0.1:1234\n\nserving\n  key  your devices  echo:\n"
    );
    assert_eq!(
        key_and_loopback(&banner),
        Some((key, "127.0.0.1:1234".to_owned()))
    );
}

/// A colon record is not the key row, and a banner with no loopback row is not read as ready.
#[test]
fn a_colon_record_or_a_missing_row_is_not_a_banner() {
    assert_eq!(
        key_and_loopback("key: ed01exampleid\n  this computer  127.0.0.1:1234\n"),
        None
    );
    assert_eq!(
        key_and_loopback("  key            ed01exampleid\n  this network   192.168.1.20:1234\n"),
        None
    );
}

/// The reader takes lines until both rows are in, and a silent open pipe or an ended one fails.
#[test]
fn the_reader_waits_for_both_rows_and_is_bounded() {
    let (sender, lines) = std::sync::mpsc::channel();
    for line in [
        "swoosh is serving",
        "  key            ed01exampleid",
        "reach",
        "  this computer  127.0.0.1:1234",
    ] {
        sender
            .send(Ok(line.to_owned()))
            .expect("the reader listens");
    }
    assert_eq!(
        read(lines, Instant::now() + Duration::from_secs(1)),
        ("ed01exampleid".to_owned(), "127.0.0.1:1234".to_owned())
    );
    let (sender, lines) = std::sync::mpsc::channel();
    sender
        .send(Ok("key: ed01exampleid".to_owned()))
        .expect("the reader listens");
    drop(sender);
    assert!(
        std::panic::catch_unwind(|| read(lines, Instant::now() + Duration::from_secs(1))).is_err()
    );
    let (_sender, lines) = std::sync::mpsc::channel();
    assert!(
        std::panic::catch_unwind(|| read(lines, Instant::now() + Duration::from_millis(10)))
            .is_err()
    );
}
