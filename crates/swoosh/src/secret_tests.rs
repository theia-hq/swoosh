//! Tests for the secret-value convention: how an argv value parses, how it resolves against the
//! environment (exactly one source, argv wins), and how a resolved source reads.

use std::path::Path;

use super::SecretSource;

#[test]
fn a_bare_dash_is_stdin() {
    let source = "-".parse::<SecretSource>().expect("infallible parse");
    assert!(matches!(source, SecretSource::Stdin));
}

#[test]
fn an_at_prefix_is_a_file_path() {
    let source = "@/etc/swoosh/authkey"
        .parse::<SecretSource>()
        .expect("infallible parse");
    assert!(matches!(source, SecretSource::File(path) if path == Path::new("/etc/swoosh/authkey")));
}

#[test]
fn anything_else_is_a_literal_including_a_double_dash() {
    // Only an EXACT `-` is stdin, and only a leading `@` is a file, so a value that is neither, even one
    // that merely starts with `-`, is carried verbatim as the secret itself.
    let source = "authkey:abcdef"
        .parse::<SecretSource>()
        .expect("infallible parse");
    assert!(matches!(source, SecretSource::Literal(value) if value == "authkey:abcdef"));
    let dashes = "--".parse::<SecretSource>().expect("infallible parse");
    assert!(matches!(dashes, SecretSource::Literal(value) if value == "--"));
}

#[test]
fn argv_wins_over_the_environment() {
    // An argv value in ANY form beats the environment: exactly one source resolves, and the explicit one
    // on the command line is it.
    let resolved = SecretSource::resolve(
        Some(SecretSource::Stdin),
        Some("authkey:from-env".to_owned()),
        "authkey",
        "SWOOSH_AUTHKEY",
    )
    .expect("resolves to the argv source");
    assert!(matches!(resolved, SecretSource::Stdin));
}

#[test]
fn the_environment_is_the_fallback_when_argv_is_absent() {
    let resolved = SecretSource::resolve(
        None,
        Some("authkey:from-env".to_owned()),
        "authkey",
        "SWOOSH_AUTHKEY",
    )
    .expect("resolves to the env literal");
    assert!(matches!(resolved, SecretSource::Literal(value) if value == "authkey:from-env"));
}

#[test]
fn no_source_at_all_is_an_error_naming_every_way_to_supply_it() {
    let err = SecretSource::resolve(None, None, "authkey", "SWOOSH_AUTHKEY")
        .expect_err("no source is an error");
    let message = format!("{err}");
    // The error unblocks the operator: it names the missing secret, the stdin/file forms, and the env var.
    assert!(message.contains("authkey"), "names the secret: {message}");
    assert!(message.contains("stdin"), "names the stdin form: {message}");
    assert!(
        message.contains("@<path>"),
        "names the file form: {message}"
    );
    assert!(
        message.contains("SWOOSH_AUTHKEY"),
        "names the env var: {message}"
    );
}

#[test]
fn a_literal_reads_verbatim() {
    let value = SecretSource::Literal("authkey:literal".to_owned())
        .read()
        .expect("a literal reads without touching stdin or disk");
    assert_eq!(value.as_str(), "authkey:literal");
}

/// Restrict a secret file to owner-only (`0600`) so the unix permission guard admits it. A no-op off unix,
/// where the guard is skipped and the file is read as given.
#[cfg(unix)]
fn make_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
}
#[cfg(not(unix))]
fn make_owner_only(_path: &Path) {}

#[test]
fn a_file_reads_and_trims_a_trailing_newline() {
    // A file written by `echo authkey:... > file` (or any editor) ends in a newline that is not part of the
    // secret, so `read` drops it. The value itself is returned intact.
    let dir = std::env::temp_dir().join(format!("swoosh-secret-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("authkey");
    std::fs::write(&path, "authkey:from-file\n").expect("write the secret file");
    // The unix guard refuses a group/world-readable secret file, so lock it to owner-only first.
    make_owner_only(&path);

    let source = format!("@{}", path.display())
        .parse::<SecretSource>()
        .expect("infallible parse");
    let value = source.read().expect("reads the file");
    assert_eq!(value.as_str(), "authkey:from-file");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
#[cfg(unix)]
fn a_group_or_world_readable_file_is_refused_with_a_chmod_hint() {
    use std::os::unix::fs::PermissionsExt as _;
    // `@<path>` exists FOR privacy, so a secret file others can read is refused rather than silently used.
    let dir = std::env::temp_dir().join(format!("swoosh-secret-perm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("authkey");
    std::fs::write(&path, "authkey:too-open\n").expect("write the secret file");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");

    let source = format!("@{}", path.display())
        .parse::<SecretSource>()
        .expect("infallible parse");
    let err = source
        .read()
        .expect_err("a group/world-readable file is refused");
    let message = format!("{err:#}");
    // The error unblocks the operator: it names the file and hints exactly how to fix the permissions.
    assert!(
        message.contains("too open"),
        "explains why it is refused: {message}"
    );
    assert!(
        message.contains(&format!("chmod 600 {}", path.display())),
        "hints the fix: {message}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_file_read_is_capped_so_an_unbounded_source_cannot_exhaust_memory() {
    // A `@<path>` (or stdin) read is bounded: a source larger than the cap is truncated at the cap rather
    // than read in full, so `@/dev/zero` cannot grow until OOM. Write past the cap and assert the truncation.
    let dir = std::env::temp_dir().join(format!("swoosh-secret-cap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("authkey");
    let oversized = "a".repeat(super::READ_LIMIT as usize + 4096);
    std::fs::write(&path, &oversized).expect("write the oversized file");
    make_owner_only(&path);

    let source = format!("@{}", path.display())
        .parse::<SecretSource>()
        .expect("infallible parse");
    let value = source.read().expect("reads up to the cap");
    // The read stops at the cap (no trailing newline to trim), never reading the whole oversized file.
    assert_eq!(value.len(), super::READ_LIMIT as usize, "read is capped");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_bare_argv_literal_warns_while_the_private_forms_and_env_stay_quiet() {
    // The argv-leak warning fires ONLY for a bare literal on argv, and ONLY there: `-`/`@<path>` are the
    // private forms, and the env fallback's exposure is documented elsewhere, so none of them warn. Drive
    // `resolve_to` with a captured sink to observe exactly when the one-line warning is emitted.
    let warned = |arg, env| {
        let mut sink = Vec::<u8>::new();
        SecretSource::resolve_to(arg, env, "authkey", "SWOOSH_AUTHKEY", &mut sink)
            .expect("resolves");
        String::from_utf8(sink).expect("utf8 warning")
    };

    let literal = warned(
        Some(SecretSource::Literal("authkey:leaky".to_owned())),
        None,
    );
    assert!(
        literal.contains("warning") && literal.lines().count() == 1,
        "a bare argv literal warns on one line: {literal:?}"
    );
    assert!(
        warned(Some(SecretSource::Stdin), None).is_empty(),
        "stdin stays quiet"
    );
    assert!(
        warned(Some(SecretSource::File("/etc/swoosh/authkey".into())), None).is_empty(),
        "a file stays quiet"
    );
    assert!(
        warned(None, Some("authkey:from-env".to_owned())).is_empty(),
        "the env fallback stays quiet"
    );
}

#[test]
fn reading_a_missing_file_is_an_error_naming_the_path() {
    let missing = "/no/such/swoosh/authkey";
    let source = format!("@{missing}")
        .parse::<SecretSource>()
        .expect("infallible parse");
    let err = source.read().expect_err("a missing file is an error");
    assert!(
        format!("{err:#}").contains(missing),
        "names the path: {err:#}"
    );
}
