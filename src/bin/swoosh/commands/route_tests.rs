//! A route's lines that carry another process's text: cut to the room their line leaves.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use swoosh::streams::Unopened;

use super::Route;
use crate::commands::through_serve::tests::{book, machine, nas};

/// The resident's error reason, in wide glyphs, is cut to the room its `error:` line leaves, counted at
/// two columns for every scalar that is not ASCII, so it cannot wrap into a forged line.
#[tokio::test]
async fn a_wide_serve_error_is_cut_to_its_room() {
    // Wide glyphs to fill the room twice over, then a whole row shaped like swoosh's own.
    let forged = "error: me/boss refused ssh";
    let wide = format!("{}{forged}", "\u{6587}\u{4ef6}".repeat(40));
    let bound = swoosh::transport::Bound {
        local: false,
        reach: swoosh::transport::Reach::default(),
    };
    let route = Route::Own {
        bound: &bound,
        this: nas(),
    };
    let line = route
        .line(Unopened::ServeError(wide), &machine(&book(), "me/nas"))
        .await;
    let line = format!("error: {line:#}");
    assert!(
        crate::commands::through_serve::tests::columns_at_most(&line) < 80,
        "{line}"
    );
    assert!(!line.contains(forged), "{line}");
}
