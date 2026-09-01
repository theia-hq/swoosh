use super::safe_relative_path;

#[test]
fn a_traversal_header_is_reduced_to_a_safe_relative_path() {
    // A sender that names an absolute escape or a `..` climb cannot write outside the output directory:
    // roots, prefixes, and parent components are dropped, leaving only the normal tail.
    assert_eq!(
        safe_relative_path(b"../../etc/authorized_keys"),
        std::path::Path::new("etc/authorized_keys")
    );
    assert_eq!(
        safe_relative_path(b"/etc/passwd"),
        std::path::Path::new("etc/passwd")
    );
    // A plain nested name is kept as-is, so a directory push preserves its structure.
    assert_eq!(
        safe_relative_path(b"photos/2026/trip.jpg"),
        std::path::Path::new("photos/2026/trip.jpg")
    );
}

#[test]
fn an_empty_or_all_stripped_header_falls_back_to_download() {
    // An empty header, or one that is nothing but `..`/roots, still lands somewhere nameable rather
    // than at the output directory itself (which `rename` could not target).
    assert_eq!(safe_relative_path(b""), std::path::Path::new("download"));
    assert_eq!(
        safe_relative_path(b"../.."),
        std::path::Path::new("download")
    );
}
