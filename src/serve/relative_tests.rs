use core::cell::Cell;
use std::path::Path;

use super::{ServingError, Started};
use crate::serve::{DefinitionCause, DefinitionError, Operand, extract_recv_services};
use crate::serve_toml::ServeToml;

fn entries(list: &[&str]) -> Vec<String> {
    list.iter().map(|text| (*text).to_owned()).collect()
}

fn select(
    base: Option<&[&str]>,
    additions: &[&str],
    exclusions: &[&str],
) -> Result<Started, ServingError> {
    Started::relative(
        &ServeToml {
            services: base.map(entries),
            ..ServeToml::default()
        },
        &entries(additions),
        &entries(exclusions),
        Path::new("/captured/./cwd"),
    )
}

#[test]
fn relative_default_empty_and_full_exclusion_do_not_restore_defaults_or_write_policy() {
    assert_eq!(
        select(None, &[], &[]).unwrap().entries(),
        ["ping=ping:", "speed=speed:"]
    );
    assert_eq!(
        select(None, &["web=echo:"], &["PING"]).unwrap().entries(),
        ["speed=speed:", "web=echo:"]
    );
    assert!(
        select(None, &[], &["speed", "ping"])
            .unwrap()
            .entries()
            .is_empty()
    );
    assert!(select(Some(&[]), &[], &[]).unwrap().entries().is_empty());
    assert_eq!(
        select(Some(&[]), &["web=echo:"], &[]).unwrap().entries(),
        ["web=echo:"]
    );
    let file = ServeToml {
        off: ["ping".into()].into(),
        ..ServeToml::default()
    };
    let before = ServeToml::clone(&file);
    let selected = Started::relative(
        &file,
        &entries(&["other=echo:"]),
        &entries(&["speed"]),
        Path::new("/work"),
    )
    .unwrap();
    assert!(matches!(selected, Started::Named(_)));
    assert_eq!(file, before);
}

#[test]
fn relative_operand_order_does_not_change_the_selected_list() {
    let first = select(None, &["z=echo:", "a=echo:"], &["speed", "ping"]).unwrap();
    let second = select(None, &["a=echo:", "z=echo:"], &["PING", "SPEED"]).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.entries(), ["a=echo:", "z=echo:"]);
}

#[test]
fn relative_names_and_collisions_have_finite_indexed_refusals() {
    assert!(matches!(
        select(None, &[], &["control.stop"]),
        Err(ServingError::InvalidExclusion { index: 1 })
    ));
    assert!(matches!(
        select(None, &[], &["missing"]),
        Err(ServingError::MissingExclusion { index: 1 })
    ));
    assert!(matches!(
        select(Some(&[]), &[], &["ping"]),
        Err(ServingError::MissingExclusion { index: 1 })
    ));
    assert!(matches!(
        select(None, &[], &["PING", "ping"]),
        Err(ServingError::DuplicateExclusion { index: 2 })
    ));
    assert!(matches!(
        select(None, &["PING", "ping"], &[]),
        Err(ServingError::Definition(DefinitionError {
            operand: Operand::Addition,
            index: 2,
            cause: DefinitionCause::Collision
        }))
    ));
    assert!(matches!(
        select(None, &["ping"], &["PING"]),
        Err(ServingError::ExcludedAddition { index: 1 })
    ));
    assert!(matches!(
        select(None, &["ping=echo:"], &[]),
        Err(ServingError::ConflictingAddition { index: 1 })
    ));
    assert_eq!(
        select(None, &["PING"], &[]).unwrap().entries(),
        ["ping=ping:", "speed=speed:"]
    );
}

#[test]
fn relative_target_equality_is_anchored_retained_text_not_filesystem_identity() {
    let base = Some(&["logs=file:./~/log", "drop=recv:./~/drop+lossy"][..]);
    assert_eq!(
        select(
            base,
            &[
                "logs=file:/captured/./cwd/./~/log",
                "drop=recv:/captured/./cwd/./~/drop+lossy"
            ],
            &[]
        )
        .unwrap()
        .entries(),
        [
            "logs=file:/captured/./cwd/./~/log",
            "drop=recv:/captured/./cwd/./~/drop+lossy"
        ]
    );
    assert!(matches!(
        select(base, &["logs=file:/captured/cwd/~/log"], &[]),
        Err(ServingError::ConflictingAddition { index: 1 })
    ));
}

#[test]
fn an_addition_is_a_constructor_never_a_saved_target_lookup() {
    assert!(matches!(
        select(Some(&["custom=echo:"]), &["custom"], &[]),
        Err(ServingError::Definition(DefinitionError {
            operand: Operand::Addition,
            cause: DefinitionCause::Arity,
            ..
        }))
    ));
    #[cfg(feature = "ssh")]
    {
        assert!(matches!(
            select(Some(&["ssh=tcp:localhost:22"]), &["ssh"], &[]),
            Err(ServingError::ConflictingAddition { index: 1 })
        ));
        assert_eq!(
            select(Some(&[]), &["ssh"], &[]).unwrap().entries(),
            ["ssh=sshd:"]
        );
    }
    #[cfg(not(feature = "ssh"))]
    assert!(matches!(
        select(Some(&["ssh=tcp:localhost:22"]), &["ssh"], &[]),
        Err(ServingError::Definition(DefinitionError {
            operand: Operand::Addition,
            cause: DefinitionCause::Scheme,
            ..
        }))
    ));
}

#[test]
fn exclusion_cannot_hide_malformed_or_duplicate_base_entries() {
    for base in [
        entries(&["raw=stdin:", "bad=ping:80"]),
        entries(&["bad=echo:", "BAD=echo:"]),
    ] {
        let file = ServeToml {
            services: Some(base),
            ..ServeToml::default()
        };
        assert!(matches!(
            Started::relative(&file, &[], &entries(&["bad", "raw"]), Path::new("/work")),
            Err(ServingError::Definition(DefinitionError {
                operand: Operand::Base,
                index: 2,
                ..
            }))
        ));
    }
    assert!(matches!(
        select(None, &["ok=echo:", "bad=stdin:tail"], &["ping", "speed"]),
        Err(ServingError::Definition(DefinitionError {
            operand: Operand::Addition,
            index: 2,
            ..
        }))
    ));
}

#[test]
fn excluded_valid_backends_never_reach_receive_preparation() {
    let mut selected = select(
        Some(&[
            "raw=stdin:",
            "drop=recv:",
            "logs=file:/does-not-exist",
            "pipe=fifo:/does-not-exist",
            "sock=unix:/does-not-exist",
        ]),
        &["ok=echo:"],
        &["raw", "drop", "logs", "pipe", "sock"],
    )
    .unwrap()
    .entries();
    let calls = Cell::new(0);
    let recv = extract_recv_services(&mut selected, || {
        calls.set(calls.get() + 1);
        None
    })
    .unwrap();
    assert_eq!(calls.get(), 0);
    assert!(recv.is_empty());
    assert_eq!(selected, ["ok=echo:"]);
    let mut selected = select(Some(&["drop=recv:"]), &[], &[]).unwrap().entries();
    assert!(
        extract_recv_services(&mut selected, || {
            calls.set(calls.get() + 1);
            None
        })
        .is_err()
    );
    assert_eq!(calls.get(), 1, "selected receive still resolves its inbox");
}

#[test]
fn relative_refusal_wrappers_and_source_chains_never_retain_credentials() {
    let secret = "https://user:credential-sentinel@example.test/path";
    let invalid = format!("bad=proxy:{secret}");
    let base = [invalid.as_str()];
    let errors = [
        select(Some(&base), &[], &["bad"]).unwrap_err(),
        select(None, &[&invalid], &[]).unwrap_err(),
        select(None, &[], &[secret]).unwrap_err(),
        select(None, &[], &["absent"]).unwrap_err(),
        select(None, &[], &["ping", "PING"]).unwrap_err(),
        select(None, &["ping"], &["ping"]).unwrap_err(),
        select(None, &["ping=echo:"], &[]).unwrap_err(),
    ];
    for error in errors {
        let mut cause: Option<&(dyn core::error::Error + 'static)> = Some(&error);
        while let Some(error) = cause {
            let text = format!("{error:?} {error}");
            assert!(!text.contains(secret));
            assert!(!text.contains("credential-sentinel"));
            cause = error.source();
        }
        let report = eyre::Report::new(error);
        assert!(!format!("{report:#} {report:?}").contains("credential-sentinel"));
    }
}
