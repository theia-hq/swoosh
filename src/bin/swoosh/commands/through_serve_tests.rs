//! The lines `forward <machine> <service> -` prints when it runs through `serve`, pinned to their ruled
//! words.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bifrost::{NodeId, RefusalDetail};
use swoosh::contacts::Contacts;
use swoosh::peer::{Machine as PeerMachine, Peer};
use swoosh::serve::control_codec::{ControlError, OpenRefusal, PeerRefusal};
use swoosh::transport::ReachArgs;

use super::{Busy, Moot, Pipe, Skew, ThisMachine, after_a_cut};
use crate::commands::connect::{ConnectionLost, Machine};

/// The key of `me/nas`.
fn nas() -> NodeId {
    NodeId::from_ed25519_secret(&[0x61; 32])
}

fn book() -> Contacts {
    let mut contacts = Contacts::default();
    contacts.save(&"me/nas".parse().unwrap(), nas()).unwrap();
    contacts
}

fn machine(contacts: &Contacts, typed: &str) -> PeerMachine {
    typed.parse::<Peer>().unwrap().machine(contacts).unwrap()
}

/// How `report` prints at the composition root.
fn printed(report: &eyre::Report) -> String {
    format!("error: {report:#}\n")
}

/// The reach flags `argv` sets on a `forward`, read as clap reads them.
fn reach(argv: &[&str]) -> ReachArgs {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Forward {
        #[command(flatten)]
        reach: ReachArgs,
    }
    Forward::parse_from(argv).reach
}

#[test]
fn a_reach_flag_while_serve_runs_names_the_first_set() {
    let line = |argv: &[&str]| Moot::first(&reach(argv)).map(|moot| printed(&moot.into()));
    assert_eq!(line(&["forward"]), None);
    assert_eq!(
        line(&["forward", "--resolver", "https://dns.example", "--local"]).unwrap(),
        "error: --local or SWOOSH_LOCAL does not apply while swoosh serve runs here\n  Commands \
         here connect through swoosh serve.\n  Set it on swoosh serve, or stop swoosh serve and run \
         this command again.\n"
    );
    assert!(
        line(&["forward", "--resolver", "https://dns.example"])
            .unwrap()
            .starts_with("error: --resolver or SWOOSH_RESOLVER does not apply")
    );
    assert!(
        line(&[
            "forward",
            "--relay",
            "https://relay.example",
            "--resolver",
            "https://dns.example"
        ])
        .unwrap()
        .starts_with("error: --relay or SWOOSH_RELAY does not apply")
    );
}

#[test]
fn serve_lines_keep_their_ruled_words() {
    assert_eq!(
        printed(&Busy.into()),
        "error: too many connections open through swoosh serve on this machine\n  Close one, or \
         wait for one to end, then try again.\n"
    );
    assert_eq!(
        printed(&Skew.into()),
        "error: swoosh serve on this machine is a different version\n  Restart it with this \
         version.\n"
    );
}

#[test]
fn a_cut_with_nothing_answering_names_serve_and_otherwise_is_connection_lost() {
    let contacts = book();
    let named = Machine::of(&contacts, nas());
    let stopped = after_a_cut(Err(ControlError::NoResident), &named);
    assert_eq!(
        printed(&stopped),
        "error: swoosh serve stopped here and ended the connection to me/nas\n  Commands here \
         connect through it while it runs.\n  Run this command again to reconnect.\n"
    );
    for gone in [
        ControlError::Io(tokio::io::ErrorKind::ConnectionReset.into()),
        ControlError::Timeout {
            phase: "response read",
        },
    ] {
        assert!(
            printed(&after_a_cut(Err(gone), &named)).starts_with("error: swoosh serve stopped")
        );
    }
    // `serve` still answers: the cut was the pipe's, and the line is the own bind's.
    let lost = after_a_cut(Ok(()), &named);
    assert!(lost.is::<ConnectionLost>());
    assert_eq!(printed(&lost), "error: connection lost\n");
}

#[test]
fn this_machine_prints_as_it_was_typed() {
    let contacts = book();
    assert_eq!(
        ThisMachine::of(&machine(&contacts, "me/nas")).to_string(),
        "me/nas is this machine"
    );
    assert_eq!(
        ThisMachine::of(&machine(&Contacts::default(), &nas().to_string())).to_string(),
        "that key is this machine's"
    );
}

#[test]
fn a_refusal_through_serve_prints_the_own_binds_line() {
    let contacts = book();
    let peer = machine(&contacts, "me/nas");
    let service = "ssh".parse().unwrap();
    let reach = reach(&["forward"]);
    let pipe = Pipe {
        machine: &peer,
        service: &service,
        slip: None,
        reach: &reach,
        contacts: &contacts,
    };
    // The dial refusal for one of your devices, with no cause asked: the same head the own bind prints
    // when it cannot tell.
    assert_eq!(
        printed(&pipe.refused(OpenRefusal::Peer(PeerRefusal::NotAdmitted))),
        printed(&crate::commands::machine::refused(&peer, &service, None))
    );
    assert!(pipe.refused(OpenRefusal::Busy).is::<Busy>());
    assert!(pipe.refused(OpenRefusal::NotHere).is::<ThisMachine>());
    // Peer text is escaped, as every peer word in an error chain is.
    let hostile = RefusalDetail::try_from("no\u{1b}[2K").unwrap();
    let line = printed(&pipe.refused(OpenRefusal::Peer(PeerRefusal::Unavailable(hostile))));
    assert!(!line.contains('\u{1b}'), "{line}");
}
