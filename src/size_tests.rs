//! A size as a person reads it, at each unit's edges.

use super::Size;

/// Under a KiB a size is whole bytes; past it, one decimal in the largest unit that keeps it at 1 or more.
#[test]
fn sizes_read_one_decimal() {
    for (bytes, printed) in [
        (0, "0 B"),
        (12, "12 B"),
        (1023, "1023 B"),
        (1024, "1.0 KiB"),
        (3174, "3.1 KiB"),
        (30_000_000, "28.6 MiB"),
        (1_288_490_189, "1.2 GiB"),
        (2 * 1024u64.pow(4), "2.0 TiB"),
        (5000 * 1024u64.pow(4), "5000.0 TiB"),
    ] {
        assert_eq!(Size(bytes).to_string(), printed, "{bytes}");
    }
}

/// A value that rounds to 1024.0 in its unit is printed in the next one.
#[test]
fn a_size_that_rounds_to_a_whole_unit_takes_the_next() {
    assert_eq!(Size(1024 * 1024 - 1).to_string(), "1.0 MiB");
    assert_eq!(Size(1024 * 1024 * 1024 - 1).to_string(), "1.0 GiB");
}
