use super::{Name, NameError, suggest_from};

/// Every character outside `a-z`, `0-9` and `-`, a leading `-`, and a 64th character each break the rule,
/// so no name can hold the invite's `.`, a marker's `:`, a path, or whitespace.
#[test]
fn a_name_outside_the_alphabet_refuses() {
    let too_long = "a".repeat(Name::MAX_LEN + 1);
    for text in [
        "a.b",
        "a:b",
        "a/b",
        "./x",
        "~x",
        "-x",
        too_long.as_str(),
        "a b",
        "",
    ] {
        assert_eq!(
            text.parse::<Name>(),
            Err(NameError::NotAName(text.to_owned())),
            "{text:?} is not a name"
        );
    }
    assert_eq!(
        "a.b".parse::<Name>().map_err(|error| error.to_string()),
        Err(
            "a.b is not a name: a name uses a-z, 0-9 and -, and starts with a letter or digit."
                .to_owned()
        )
    );
    let longest = "a".repeat(Name::MAX_LEN);
    for text in ["a", "0", "ci-runner", "9-lives", "x-", longest.as_str()] {
        assert!(text.parse::<Name>().is_ok(), "{text:?} is a name");
    }
}

/// ASCII capitals fold, so a name has one stored spelling; any other letter is outside the alphabet.
#[test]
fn a_capital_name_folds_to_the_one_spelling() {
    assert_eq!(
        "Alice".parse::<Name>().map(String::from),
        Ok("alice".to_owned())
    );
    assert_eq!(
        "\u{c9}mile".parse::<Name>(),
        Err(NameError::NotAName("\u{c9}mile".to_owned())),
        "only ASCII capitals fold"
    );
}

/// `me`, `root` and `anyone` are names, and reserved: naming a person or a device with one refuses.
#[test]
fn a_reserved_name_is_a_name_that_names_nothing() {
    for text in Name::RESERVED {
        let name = text
            .parse::<Name>()
            .expect("a reserved word is still a name");
        assert_eq!(name.unreserved(), Err(NameError::Reserved(text.to_owned())));
    }
    assert!("fleet".parse::<Name>().and_then(Name::unreserved).is_ok());
}

/// The suggestion is the hostname before its first `.`, made a name; a hostname with nothing left is `this`.
#[test]
fn the_suggested_name_is_the_hostname_before_its_first_dot() {
    for (hostname, suggested) in [
        ("Mac-Book.local", "mac-book"),
        ("...", "this"),
        ("", "this"),
        ("--My  Laptop's--", "my-laptop-s"),
        ("caf\u{e9}-box.lan", "caf-box"),
    ] {
        assert_eq!(suggest_from(hostname).as_str(), suggested, "{hostname:?}");
    }
    assert_eq!(suggest_from(&"x".repeat(100)).as_str().len(), Name::MAX_LEN);
}
