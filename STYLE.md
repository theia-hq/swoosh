# STYLE.md

_How this codebase is built. It is the contract: a reviewer never spends a comment on a pattern written here.
The code should be beautiful to read and tell a story as you scroll._

## Philosophy
- **Correctness first, cleverness never.** The boring right tool beats the impressive wrong one.
- **Parse, don't validate.** Turn input into a typed value once, at the edge; everything after receives a value that is valid by construction.
- **Make illegal states unrepresentable.** Push invariants into types so the compiler catches the mistake and guides the next person away from the cliff.
- **Every abstraction is justified,** and a reader can trust it without reading its insides.
- **Performance from line one,** never bolted on later.

## Types
- **Newtype every id and domain scalar.** Never a raw `String`, `u64`, or `Uuid` across a boundary; the newtype is what appears in every parameter, field, and return. Parse it once (`FromStr`), render it once (`Display`); validating a string and passing the string through is the leak.
- **Enums over bools.** State is an `enum` with an exhaustive `match`, so a new variant is a compile error at every decision site. A closed set of modes is one typed selector (`--to <port | - | unix:PATH>` parses to one enum), never two flags or a pile of bools.
- **`::new` only when construction has logic.** A 1:1 field assignment is a struct literal, `Default`, or `From`.
- **Constraints live in the type system,** and constant relationships in `const { assert!(..) }`.
- **`#[must_use`] where ignoring the return is a bug,** with `unused_must_use = deny`.
- **In trait impls, name associated types as `Self::Assoc`,** so changing one propagates.
- **A wire form and a domain form are different types.** Convert at the boundary; a cohesive family of conversions is one small local trait, not a bag of free functions.
- **A measurement returns its report and knows nothing of display.** A live view is a caller-supplied observer; the plain run is the same loop with a no-op observer.

## Ownership
- **Borrow, stream, iterate.** No clone or allocation the caller did not ask for. Take `u64`, not `&u64`.
- **Receive minimally, expose maximally.** Accept `&str` / `impl AsRef<str>` / `impl IntoIterator`; return `impl Iterator` unless you already hold a `Vec`.
- **Share memory by communicating.** Channels first; a `Mutex` gets a why-comment.
- **Batch async work** rather than issuing it one call at a time.

## Errors
- **Libraries: `thiserror`.** Typed, enumerated, matchable; errors are part of the API and the cause rides the `source()` chain, never a stringified message.
- **Binaries: `eyre::Result`,** path-qualified, never `use eyre::Result`. A user sees the message chain (`{report:#}`), never a `file:line` or a backtrace.
- **A refusal crosses a boundary as a value.** On the wire it is uniform and payload-free (a stranger, a revoked holder, a disabled service, and an absent name read the same); on the host it is the full typed cause, logged. A consumer matches the variant; it never `strip_prefix`es or `contains`es another crate's text.
- **Messages are lowercase with no trailing punctuation;** they compose into chains.
- **Never panic on input.** No `unwrap`/`expect` outside tests; a panic names why the state is unreachable.

## Control flow
- **Guard clauses and early returns;** the happy path stays un-nested.
- **`let ... else`** when the else branch needs no binding; `if let` when it does.
- **`match` / `if let` / `?`** over `is_some()` then `unwrap()`.
- **No boolean parameters** that flip behavior: split the function or take an enum.

## Command lines
- **A CLI is a module tree.** `main` parses and dispatches; each group is a module, each leaf its own file, and every leaf owns `async fn run(self, ..)`. Import the command module and qualify the leaf (`adopt::AdoptCmd`).
- **The parser hands `run` domain values.** A field is a `Service`, a `Link`, a `Duration`; never a `String` the handler re-parses.
- **Every argument names its `value_name` in lowercase,** the concept word, the same word for the same concept across the family (`<peer>`, `<link>`, `<service>`).
- **`-h` is a one-line map; `--help` adds at most one line.** Caveats and rationale live on the reference page. Never re-spell what clap renders (an `env` var, a default).
- **A foreseeable mistake gets a teaching error** that names the concept and the fix, never a raw OS or parser error.
- **A verb takes only the state it needs.** A reach-outward verb mints an ephemeral key; only a serving verb persists one.
- **Announce success only after it is real.** Probe admission, surface a refusal as one line with the peer's reason, exit non-zero; only then print `ready`.
- **A refusal is a typed error, never a measured value.** Never `0`, `100% loss`, or an empty result where a `Refused` variant belongs; the report type is unconstructable from a refusal.
- **Short aliases** (`ls`, `rm`) through the parser.

## Concurrency
- **A capability to request, never the authority to perform.** A handler that may stop or change a shared resource holds a cloneable token or a bounded channel; the one owner acts, in one place.
- **A byte pump ends on the direction that means done.** Name it in a comment; do not park on a stream that never closes.
- **A hand-rolled `poll_*` registers interest before it checks the condition, and holds the `Notified` across polls.** The worked case is `tightbeam::raw_stream_fanout::Cursor::poll_read`.
- **A timeout around a blocking syscall leaks the thread.** Make the syscall nonblocking and drive readiness through the reactor; the worked case is `tightbeam::raw_stream::open_path`.
- **A concurrency primitive gets a why-comment** at the site.

## Layering
- **Wrap a foreign stack once, at the composition root.** Downstream code is generic over your own traits; a concrete backend import outside `main` is a leak.
- **A library speaks only its own vocabulary.** It never names a consumer's binary, flags, or service names, in code or docs. A lib README may point at one real consumer once, as a link, and never spell its commands. The layering gate scans docs as well as code.
- **Bind behavior to types.** A free function is legitimate only as a pure helper over no receiver you own, a policy resolver at the right layer over foreign inputs, or a boundary adapter for a type that lives in a lower crate. Auth operations are methods on the credential type, never functions over link text.
- **A layer touches only its own concern.** A byte-moving layer knows nothing of paths or files; naming and temp-then-rename belong to the application.
- **A wire contract has one home,** the crate that writes it; a consumer imports the declaration or carries a typed error.

## Layout
- **Top-down story.** A high-level item references helpers defined below it.
- **No `mod.rs`.** `<module>.rs` with a sibling `<module>/` directory.
- **Imports in `StdExternalCrate` order, one `use` per module path,** never a wildcard, never `self::`. Qualify one level where it reads better (`use std::io;` then `io::Error`; `use tokio::io;` then `io::AsyncRead`, with extension traits `as _`).
- **Path-qualify derive macros** (`#[derive(thiserror::Error, Debug)]`).
- **`cargo sort --grouped`:** in-tree dependencies first, a blank line, then externals, each group alphabetical.

## Comments and docs
- **Why, not what.** A comment that restates the next line is deleted. No deliberation numbers, review names, or process history in shipped source: the invariant is stated as a rule, the story lives in the notes corpus.
- **`///` on every public item and every enforced invariant,** saying why at the point of enforcement.
- **No em dashes** anywhere: comments, docs, READMEs, commit messages, PR text.
- **Docs are cut against the reader-first bar** (`DOCS-BAR.md`): say what it is first, a real command early, captured output only (one marker per block), one limit per page, no manifest or process leaks, a lib README shows the API and a bin README shows verbs. The voice is `DOC-VOICE.md`; the founder's register is `FOUNDER-DOC-STYLE.md`. Both live in the theia-hq notes corpus.

## Tests
- **Unit tests in `<module>_tests.rs`** beside the module, never inline; integration tests in `tests/`.
- **Zero, one, many, error** per behavior; `assert!(matches!(..))` for enums.
- **Concurrency is tested with a barrier,** asserting the invariant holds under release.
- **Names read as documentation:** `a_stranger_is_refused_at_control_services`.
- **A runnable example is the intuitiveness gate for a library surface;** every `examples/` file is referenced from the README and runs in CI.

## Observability and security
- **`tracing` with structured fields,** never string formatting: `info!(order_id = %id, "checkout started")`.
- **`zeroize` secrets.**
- **A trust default degrades to self,** never to open and never to a dead end: an unprovisioned gate roots at the node's own key.

## Tooling
- **`cargo +nightly fmt`, `cargo clippy --all-targets -D warnings`, `cargo sort --grouped`, `just gate`** clean before every commit.
- **`core::` over `std::`** where the item exists in `core`.
- **Sized integers over `usize`** where the width is semantic.
- **Macros and dependencies sparingly,** each with a reason a reviewer would accept.

## Commits and PRs
- **Subject: one imperative line, about 70 characters, no period.** The body names the reason, the constraint, and the evidence.
- **Each commit builds and passes on its own** and says what it sets up.
- **Small, reviewable diffs.** An "and also" section was two PRs.
- **Stage explicit paths, never `git add -A`.** `git checkout Cargo.lock` before a commit from a patched build; relock last, in a patch-free checkout.
