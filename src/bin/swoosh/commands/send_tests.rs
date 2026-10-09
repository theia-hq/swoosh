//! The sender's own lines render a hostile file name through the shared escaper, so a newline in a name
//! cannot forge a second line on this terminal and an ESC cannot drive it.
//!
//! The name is not the only surface: the skip line prints the whole error chain beside the escaped
//! prefix, so a path-bearing context built with a raw `Path::display` (the `stat`/`read` walk and the
//! no-file-name error) would leak the bytes the prefix escaped. These tests drive the operator's
//! exact hostile names through those paths.

use std::path::Path;

use clap::Parser as _;
use swoosh::contacts::Contacts;
use swoosh::testkit::HostilePeer;

use super::{SendCmd, collect_files, file_name, send_one};

/// The operator's exact hostile name for the skip shape (`missing\nname\u{1b}[31m.txt`): a path that
/// cannot be stat'ed is skipped, and the WHOLE line, error chain included, must render escaped. This
/// is the leak the review caught: the prefix was escaped, the `stat <path>` context was not.
#[tokio::test]
async fn a_hostile_missing_path_renders_escaped_in_the_skip_error() {
    let path = std::env::temp_dir().join("missing\nname\u{1b}[31m.txt");
    let error = collect_files(&path)
        .await
        .expect_err("a path that does not exist is a skip");

    let message = format!("{error:#}");
    assert!(
        message.contains("stat ") && message.contains(r"missing\nname\u{1b}[31m.txt"),
        "the stat context renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC rides the error chain onto the skip line: {message:?}"
    );
}

/// The other skip shape the directory walk builds: an unreadable directory is wrapped as
/// `read <path>`, and that context renders escaped too.
#[cfg(unix)]
#[tokio::test]
async fn a_hostile_unreadable_directory_renders_escaped_in_the_read_error() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = std::env::temp_dir().join(format!(
        "swoosh-send-{}-no-read\nname\u{1b}[31m.txt",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("the hostile directory is created");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000))
        .expect("the directory is closed");
    let result = collect_files(&dir).await;
    // Reopen and remove first, so the asserts (and a failed one) leave no unreadable tree behind.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .expect("the directory is reopened");
    let _ = std::fs::remove_dir_all(&dir);

    // Root ignores mode 000, so the walk succeeds and this environment cannot exercise the shape.
    let Err(error) = result else {
        return;
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("read ") && message.contains(r"no-read\nname\u{1b}[31m.txt"),
        "the read context renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC rides the error chain onto the skip line: {message:?}"
    );
}

/// A path with no final component is a hard error rather than a silent misname, and its one
/// path-bearing message renders escaped like every other.
#[test]
fn a_hostile_path_with_no_file_name_renders_escaped() {
    let error = file_name(Path::new("evil\nname\u{1b}[31m/.."))
        .expect_err("a path with no final component has no file name");

    let message = format!("{error:#}");
    assert!(
        message.contains(r"path has no file name: evil\nname\u{1b}[31m/.."),
        "the no-file-name error renders the path escaped: {message:?}"
    );
    assert!(
        !message.contains('\n') && !message.contains('\u{1b}'),
        "no raw newline or ESC reaches the skip line: {message:?}"
    );
}

/// A receiver that refuses the stream sends its own detail, and the skip line prints it: a carriage
/// return, an ESC CSI sequence and a bidi override there print as escapes, so the refusal cannot erase
/// the skip line and draw a `sent` line in its place. Driven through `send_one` over a session that
/// refuses every stream, so it is the stream's own error path this pins, not the renderer alone.
#[tokio::test]
async fn a_hostile_refusal_prints_escaped() {
    let path = std::env::temp_dir().join(format!("swoosh-send-{}-refused.txt", std::process::id()));
    std::fs::write(&path, b"a").expect("write the file to send");
    let session = HostilePeer::RefusesStreams("no\r\u{1b}[2Ksent a.txt (1 bytes)\u{202e}");

    let error = send_one(&session, "a.txt".to_owned(), path.clone())
        .await
        .expect_err("a refused stream is a skip");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        format!("skip: {error:#}"),
        r"skip: stream refused: unavailable: no\r\u{1b}[2Ksent a.txt (1 bytes)\u{202e}"
    );
}

/// A peer that closes the dial gives a reason, and `send` prints the connect chain that carries it: a
/// carriage return, an ESC CSI sequence and a bidi override there print as escapes, so the reason cannot
/// erase the error and draw a `sent` line in its place. Driven through `run_send` over a transport whose
/// dial fails with that reason, so it is `send`'s own connect this pins.
#[tokio::test]
async fn a_hostile_connect_failure_prints_escaped() {
    #[derive(clap::Parser)]
    struct Wrap {
        #[command(flatten)]
        send: SendCmd,
    }

    let at = HostilePeer::node_id().to_string();
    let send = Wrap::try_parse_from(["x", "/etc/hosts", &at])
        .expect("send <path> <key> parses")
        .send;
    let node = bifrost::Node::new(
        HostilePeer::Unreachable("closed by peer: no\r\u{1b}[2Ksent hosts (1 bytes)\u{202e}"),
        bifrost::NoDiscovery,
    );

    let machine = send
        .peer
        .machine(&Contacts::default())
        .expect("a key is one machine");
    let error = send
        .run_send(&node, &machine, None, None)
        .await
        .expect_err("a dial the peer closed is an error");
    assert_eq!(
        format!("{error:#}"),
        r"connect to peer: closed by peer: no\r\u{1b}[2Ksent hosts (1 bytes)\u{202e}"
    );
}
