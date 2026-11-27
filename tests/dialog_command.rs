//! The command a process names reaches the dialog that opens a key to use it. A file of its own, so its own
//! process: the name is set once per process, and no other test sees it.

use swoosh::touch::{self, Reason};

/// Unnamed, the dialog says the bare act; once named, `for swoosh <path>`; a second name is ignored, so the
/// first command stands. Red when the name is not read, or a later call moves it.
#[test]
fn a_named_command_reaches_the_use_dialog() {
    let reason = || Reason::to_use(touch::USE_MACHINE_KEY).to_string();
    assert_eq!(reason(), "use this machine's key");
    touch::for_command("serve");
    assert_eq!(reason(), "use this machine's key for swoosh serve");
    touch::for_command("ping");
    assert_eq!(reason(), "use this machine's key for swoosh serve");
    assert_eq!(
        Reason::Change(touch::CHECK_MACHINE_KEY).to_string(),
        "add Touch ID to this machine's key"
    );
}
