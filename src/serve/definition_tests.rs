use std::path::Path;

use super::{DefinitionCause, DefinitionError, Operand, ValidatedDefinition};

#[test]
fn every_complete_scheme_has_one_pure_grammar() {
    for text in [
        "probe=ping:",
        "test=speed:",
        "web=tcp:host:0",
        "ipv6=tcp:::1:65535",
        "socket=unix:./socket",
        "log=file:./log",
        "stream=fifo:./pipe+lossy",
        "raw=stdin:",
        "lossy=stdin:+lossy",
        "reflect=echo:",
        "recv:",
        "drop=recv:dir+lossy",
        "proxy:https://EXAMPLE.test:443/",
    ] {
        let definition =
            ValidatedDefinition::parse(text).unwrap_or_else(|cause| panic!("{text}: {cause}"));
        assert_eq!(
            ValidatedDefinition::parse(&definition.entry())
                .unwrap_or_else(|cause| panic!("{cause}"))
                .entry(),
            definition.entry()
        );
    }
    #[cfg(feature = "ssh")]
    assert!(matches!(
        ValidatedDefinition::parse("SSH").unwrap().target,
        super::Target::Sshd
    ));
    #[cfg(not(feature = "ssh"))]
    assert!(matches!(
        ValidatedDefinition::parse("SSH"),
        Err(DefinitionCause::Scheme)
    ));
    for text in [
        "shell=sshd:tail",
        "probe=ping:80",
        "test=speed:tail",
        "raw=stdin:tail",
        "reflect=echo:tail",
        "web=tcp:host:65536",
        "web=tcp::1",
        "log=file:",
        "stream=fifo:",
        "socket=unix:",
        "log=file:path+lossy",
        "web=tcp:host:1+lossy",
        "reflect=echo:+lossy",
        "probe=ping:+lossy",
        "CONTROL=ping:",
        "lookup=echo:",
        "control.stop=echo:",
        "UPPER:tail",
        "a=ECHO:",
    ] {
        assert!(ValidatedDefinition::parse(text).is_err(), "{text}");
    }
}

#[test]
fn empty_paths_fail_before_anchoring_and_suffixes_are_not_receive_options() {
    for text in ["a=file:", "a=fifo:", "a=fifo:+lossy", "a=unix:"] {
        assert!(
            ValidatedDefinition::parse(text)
                .and_then(|definition| definition.anchored(Path::new("/work")))
                .is_err(),
            "{text}"
        );
    }
    for (text, expected) in [
        (
            "a=fifo:./pipe+lossy+lossy",
            "a=fifo:/work/./pipe+lossy+lossy",
        ),
        ("a=recv:./pipe+lossy", "a=recv:/work/./pipe+lossy"),
        ("a=recv:", "a=recv:"),
        ("a=file:~/a/.././b", "a=file:/work/~/a/.././b"),
        ("a=file:/a/../b", "a=file:/a/../b"),
    ] {
        assert_eq!(
            ValidatedDefinition::parse(text)
                .unwrap()
                .anchored(Path::new("/work"))
                .unwrap()
                .entry(),
            expected
        );
    }
    for text in ["a=echo:", "a=recv:", "a=file:/absolute"] {
        assert!(
            ValidatedDefinition::parse(text)
                .unwrap()
                .anchored(Path::new("relative"))
                .is_err()
        );
    }
}

#[test]
fn proxy_origins_retain_valid_spelling_and_refuse_all_other_scope() {
    let text = "site=proxy:HTTPS://EXAMPLE.test:443/";
    assert_eq!(ValidatedDefinition::parse(text).unwrap().entry(), text);
    for origin in [
        "",
        "not-a-url",
        "file:///tmp/a",
        "https://host.test/path",
        "https://host.test/?token=secret",
        "https://host.test/#secret",
        "https://user:secret@host.test/",
        "https://host.test:99999",
    ] {
        let error =
            ValidatedDefinition::list(&[format!("site=proxy:{origin}")], Operand::Saved, None)
                .err()
                .unwrap();
        assert_eq!(error.cause, DefinitionCause::Origin);
        assert_eq!(
            error.to_string(),
            "invalid saved service definition at index 1: invalid proxy origin"
        );
        assert!(!format!("{error:?}").contains("secret"));
    }
}

#[test]
fn complete_lists_fail_late_without_preparing_earlier_backends() {
    let input = [
        "raw=stdin:",
        "inbox=recv:",
        "missing=file:/absent/source",
        "bad=ping:80",
    ]
    .map(str::to_owned);
    let error = ValidatedDefinition::list(&input, Operand::Base, Some(Path::new("/work")))
        .err()
        .unwrap();
    assert_eq!(
        error,
        DefinitionError {
            operand: Operand::Base,
            index: 4,
            cause: DefinitionCause::Arity
        }
    );
    // No preparation callback or ambient runtime input exists on this path.
    assert!(
        ValidatedDefinition::list(&input[..3], Operand::Base, Some(Path::new("/work"))).is_ok()
    );
    let duplicate = ["RAW=stdin:".into(), "raw=echo:".into()];
    assert!(matches!(
        ValidatedDefinition::list(&duplicate, Operand::Addition, None),
        Err(DefinitionError {
            index: 2,
            cause: DefinitionCause::Collision,
            ..
        })
    ));
}

#[test]
fn invalid_definition_errors_and_all_wrappers_have_no_input_or_parser_source() {
    use core::error::Error as _;
    for input in [
        "https://user:secret@host.test",
        "bad=proxy:https://user:secret@host.test/?token=private",
        "secret/name=echo:",
        "bad=secret:tail",
        "bad=ping:secret",
        "bad=file:\nsecret",
    ] {
        let error = ValidatedDefinition::list(&[input.to_owned()], Operand::Saved, None)
            .err()
            .unwrap();
        assert!(error.source().is_none());
        let serving = crate::serve::ServingError::Definition(error);
        let policy = crate::serve_toml::ServeTomlError::Definition(serving);
        let report = eyre::Report::new(policy)
            .wrap_err("Edit the saved service file to fix or remove the entry.");
        let shown = format!("{report:?} {report:#}");
        for forbidden in [input, "secret", "private", "user:", "host.test"] {
            assert!(!shown.contains(forbidden), "{shown}");
        }
        for cause in report.chain() {
            assert!(!format!("{cause:?} {cause}").contains("secret"));
        }
    }
}

#[cfg(unix)]
#[test]
fn invalid_utf8_cwd_is_needed_only_for_relative_paths() {
    use std::os::unix::ffi::OsStrExt as _;
    let cwd = Path::new(std::ffi::OsStr::from_bytes(b"/work/\xff"));
    for text in [
        "a=file:path",
        "a=fifo:path+lossy",
        "a=unix:path",
        "a=recv:path",
    ] {
        assert!(matches!(
            ValidatedDefinition::parse(text).unwrap().anchored(cwd),
            Err(DefinitionCause::Encoding)
        ));
    }
    for text in ["a=file:/path", "a=recv:/path", "a=echo:", "a=recv:"] {
        assert_eq!(
            ValidatedDefinition::parse(text)
                .unwrap()
                .anchored(cwd)
                .unwrap()
                .entry(),
            text
        );
    }
}

#[cfg(windows)]
#[test]
fn receive_and_primitive_anchoring_refuse_ambient_drive_state() {
    for scheme in ["file", "unix", "fifo", "recv"] {
        for path in [r"C:relative", r"\root-relative"] {
            let text = format!("a={scheme}:{path}");
            assert!(
                ValidatedDefinition::parse(&text)
                    .unwrap()
                    .anchored(Path::new(r"C:\work"))
                    .is_err()
            );
        }
        let text = format!("a={scheme}:~/a/.././b");
        let expected = format!(r"a={scheme}:C:\work\~/a/.././b");
        assert_eq!(
            ValidatedDefinition::parse(&text)
                .unwrap()
                .anchored(Path::new(r"C:\work"))
                .unwrap()
                .entry(),
            expected
        );
    }
}
