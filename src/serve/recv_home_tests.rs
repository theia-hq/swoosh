use core::cell::Cell;
use std::path::{Path, PathBuf};

use super::{Dir, RecvService, Started, extract_recv_services, refuse_recv_into_home_with};
use crate::serve_toml::ServeToml;

#[test]
fn an_excluded_receiver_consumes_zero_receive_home_probes() {
    let selected = Started::relative(
        &ServeToml {
            services: Some(vec!["drop=recv:".into()]),
            ..ServeToml::default()
        },
        &["ok=echo:".into()],
        &["drop".into()],
        Path::new("/captured/cwd"),
    )
    .unwrap();
    let mut requested = selected.entries();
    let receivers = extract_recv_services(&mut requested, || {
        panic!("an excluded receiver must not resolve its inbox")
    })
    .unwrap();
    assert!(receivers.is_empty());
    assert_eq!(requested, ["ok=echo:"]);

    let probes = Cell::new(0);
    refuse_recv_into_home_with(&receivers, || {
        probes.set(probes.get() + 1);
        panic!("an empty receive selection must not resolve or probe either home")
    })
    .unwrap();
    assert_eq!(probes.get(), 0);
}

#[test]
fn a_selected_receiver_consumes_home_probes_and_keeps_its_home_refusal() {
    let out = PathBuf::from("/synthetic-selected-receive-home");
    let receivers = [RecvService {
        name: "drop".into(),
        out: PathBuf::clone(&out),
        inbox: false,
    }];
    let probes = Cell::new(0);
    let refused = refuse_recv_into_home_with(&receivers, || {
        probes.set(probes.get() + 1);
        (Dir::of(&out), None)
    });
    assert_eq!(
        probes.get(),
        1,
        "selected receive safety consumes the resolver"
    );
    assert!(
        refused
            .unwrap_err()
            .to_string()
            .contains("it is the swoosh home")
    );
}
