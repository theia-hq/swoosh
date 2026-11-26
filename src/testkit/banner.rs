//! `swoosh serve`'s banner as a test reads it: the key the machine answers at, and the loopback address
//! its `reach` block names, which a `--local` serve always shows.

use std::io;
use std::sync::mpsc::Receiver;
use std::time::Instant;

/// The key and the loopback address in `banner`, once both rows are in it. The key is the first `key`
/// row, since a service named `key` has a row of its own in the `serving` block further down.
pub fn key_and_loopback(banner: &str) -> Option<(String, String)> {
    let mut key = None;
    let mut loopback = None;
    for line in banner.lines() {
        if key.is_none()
            && let Some(row) = line.strip_prefix("  key  ")
        {
            key = Some(row.trim().to_owned());
        }
        if let Some(row) = line.strip_prefix("  this computer  ") {
            loopback = Some(row.trim().to_owned());
        }
    }
    key.zip(loopback)
}

/// Read a running serve's stdout, a line at a time from `lines`, until [`key_and_loopback`] finds both
/// rows. The deadline bounds every receive, so a child whose pipe stays open and silent still fails.
///
/// # Panics
///
/// When `deadline` passes, or the stream ends or fails, before both rows arrive.
#[expect(
    clippy::expect_used,
    reason = "a serve that shows no banner stops the test"
)]
pub fn read(lines: Receiver<io::Result<String>>, deadline: Instant) -> (String, String) {
    let mut banner = String::new();
    loop {
        if let Some(found) = key_and_loopback(&banner) {
            return found;
        }
        assert!(Instant::now() < deadline, "serve showed no banner in time");
        let line = lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("serve showed no banner in time")
            .expect("read the banner");
        banner.push_str(&line);
        banner.push('\n');
    }
}

#[cfg(test)]
#[path = "banner_tests.rs"]
mod tests;
