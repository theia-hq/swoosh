# STYLE.md

_How this codebase is built. It is the contract: reviewers (human or machine) should never spend a comment on a pattern documented here. All in all, it should be **beautiful to read** and tell a story as you scroll._

## Philosophy
- **Correctness first, cleverness never.** The boring right tool beats the impressive wrong one. Restraint is the senior signal.
- **Parse, don't validate.** Turn unstructured input into a strictly-typed instance once, at the edge; the rest of the code receives things that are already valid by construction.
- **Make illegal states unrepresentable.** Push invariants into the type system so the compiler catches mistakes and guides future development. Assume human error is inevitable; the software should guide the next person away from the cliff.
- **Every abstraction earns its keep,** and a reader must be able to offload context onto it and trust it without reading its insides.
- **Performance is a first-class concern from line one,** never an afterthought bolted on later.

## Types & domain modeling
- **Newtype every ID and domain scalar.** `UserId(Uuid)`, `Money`, `Quantity`. Never raw `Uuid`/`i64`/`String` across a boundary. Kills primitive obsession and argument-swap bugs.
- **Prefer enums to bools.** State is an `enum` with exhaustive `match`, not a `bool` or a stringly-typed field. A new variant then forces a compile error at every decision site.
- **Positional field access reads fine when trivial, murky when dense.** A one-line accessor (`&self.0`) is perfectly clear. But in denser logic a bare `.0`/`.1` is as opaque as an unlabeled eighth function argument, so destructure with a *name* there (`let Self(value) = self`) and let the reader stop counting positions. Keep newtypes as tuple structs; reach for a named field only when the name carries real information (`Money { minor_units }`), not as reflexive wrapping (`Name(String)`). The same instinct prefers named or struct arguments over long positional parameter lists.
- **`Money`:** integer minor units inside, **never floating point**, explicit currency, one documented rounding rule, overflow handled by explicit checked/saturating methods.
- **`::new` only when construction has real logic** that must run to produce a valid `Self`. If it just assigns the fields 1:1, use a struct literal or `Default`/`From` instead. A `new` that adds nothing is noise.
- **Encode constraints in the type system** wherever a conditional or a validation would otherwise live at runtime. **Compile-time assertions** (`const { assert!(..) }`) for invariants knowable at build time.
- **`#[must_use]` where ignoring a return is a bug** (builders, freshly-constructed domain values, a result that must be acted on), only where relevant, not reflexively. Complemented by `unused_must_use = deny`.
- **In trait impls, name associated types via `Self::Assoc` in signatures**, not the concrete type: `fn from_row(value: Self::Row)`, not `fn from_row(value: i64)`. The associated type stays the single source of truth, so changing it propagates to every signature.
- **A measurement's live view is a caller-supplied observer, not a presentation the measurement owns.** A one-shot run (`Ping::run`, `Speedtest::run`) returns its final report and knows nothing of how it is displayed. When a caller wants to WATCH the run unfold (a line per probe, a rate per second), the run gains a sibling that feeds each increment out to a caller-supplied sink as it happens: a builder taking a shared counter (`Speedtest::tracking(Progress)`) or a method taking a per-iteration callback (`Ping::observing(session, |probe| …)`). The plain `run` is that same path with a no-op observer, so it stays the simple default and there is one loop, not two. The measurement never learns the terminal, a format, or the word "print"; it hands out typed increments (`Probe { seq, rtt }`) and the CLI decides what to render. This keeps the domain transport-and-presentation-blind (the same run drives a test over `mem`, a live view over `iroh`) and the live view opt-in.

## Three representations: wire, domain, storage
- **A domain type is not a wire type is not a DB row.** Keep three distinct representations and map explicitly between them at the boundaries.
  - **Wire**, the codec-generated types (transport concern: field numbers, optionality, serialization quirks).
  - **Domain**, pure Rust, the currency of the business logic. Carries **no codec derives at all**, no ORM/row derives, no serde. It answers to correctness, not to any transport or storage format.
  - **Storage**, row structs owned by the repo layer, carrying the persistence derives.
- **Do not compound codec derives onto one struct.** A single type wearing both a row-mapping derive and the wire/serde derives couples persistence and transport into the domain and lets each layer's constraints leak into the others. Conversions live at the boundary (`From`/`TryFrom` in the repo and the service layer), never as derives on the domain type.
- **A cohesive class of conversions is a local trait, not a bag of free functions.** When several functions perform the same kind of transformation (domain to wire, row to domain, primitive to scalar), group them under one small local trait with an associated type naming the counterpart, rather than scattering `to_x` / `from_x` free functions. The trait names the relationship, keeps the impls discoverable together, and, when the two types live in different crates, sidesteps the orphan rule that forbids a foreign `From` / `TryFrom` (e.g. a `FromRow` trait for storage, a `ToWire`/`FromWire` pair for the transport interface).

## Ownership, memory & performance
- **No unnecessary clones or allocations.** Prefer borrowing; prefer streaming and iteration over materializing collections.
- **Make clones explicit and greppable:** `T::clone(&x)`, not `x.clone()`. A clone should be visible at the callsite as a deliberate cost.
- **Don't take references to `Copy` types.** Take `u64`, not `&u64`.
- **Receive minimally, expose maximally.** Accept the least-committal type that works (`impl AsRef<str>`, `&str`, `impl IntoIterator`); return the most useful/maximal one. **Return `impl Iterator` over a `Vec`** unless you already hold a `Vec`, let the consumer decide whether to allocate; preallocating for a consumer that streams is waste.
- **Amortize async operations by batching** rather than issuing them one at a time.
- **Share memory by communicating** (channels), don't communicate by sharing memory. **Be wary of `Mutex`/`RwLock`**, they carry ownership-tracking overhead and invite deadlock; lean on the type system and message-passing first.

## Error handling
- **Libraries: `thiserror`.** Typed, enumerated, matchable error kinds, errors are part of the API.
- **Binaries: `eyre::Result`** (thiserror loses backtrace information, so it stays out of bins). Use it **path-qualified** (`eyre::Result<T>`); never `use eyre::Result`, keep it visibly distinct from `core::result::Result`.
- **User-facing CLI errors show the message chain, never a `file:line` / backtrace / spantrace.** A handled error a user hits is a report about their input or environment, not a crash: print the eyre chain with `Display` alternate (`eprintln!("Error: {report:#}")` or an eyre hook that suppresses the location), never the `Debug` (`{:?}`) form that trails a source `Location:` and spantrace. A source path is noise to a user and reads as "go read our source". Keep the location/backtrace for `RUST_BACKTRACE`/debug diagnostics, out of the default user path. (`main` returning `eyre::Result` prints `Debug` by default, so install a minimal hook or print-and-exit rather than leaning on the `?`-from-`main` default.)
- **The underlying error kind is contained and returned by reference** via the source chain (`std::error::Error::source`), `ParseIntError` inside your variant is the textbook shape. Don't stringify away the cause.
- **Error messages are lowercase and carry no trailing punctuation**, they *will* compose into larger chains, so `invalid quantity` not `Invalid quantity.`
- **No `.unwrap()` / `.expect()` in non-test code** (clippy-denied). Panic only on a genuinely unreachable invariant, with a message saying why it's unreachable.
- **Never panic on bad input**, return an error.
- **At a transport boundary**, map typed errors to precise status codes for that protocol (e.g. `FailedPrecondition`, `Aborted`, `ResourceExhausted`), never a blanket `Internal`.

## Control flow
- **Guard clauses and early returns.** Handle the edge/error first; keep the happy path un-nested.
- **`let ... else`** when the else branch is independent of the conditional's bindings; `if let` when it needs them.
- **Short-circuit** conditionals; order predicates cheapest/most-likely-to-decide first.
- **`match` / `if let` / `?` over `is_some()` + `unwrap()`.** Use the value you just proved exists.
- **No boolean parameters** that flip behavior, split the function or take an enum.

## Command-line interfaces
- **A CLI is a module tree, not one file.** `main` parses and dispatches; each command group is a module and each leaf command its own file (`user.rs`, then `user/create.rs`), and every command owns an `async fn run(self, ...)` that consumes it. Dispatch is a `match` that delegates to the command's `run`.
- **Let the argument parser hand you already-valid domain instances.** A command field is a domain type (a `UserId`, a `Price`, a `Currency`), never a `String` the handler re-parses. Parsing happens once, at the parser boundary (clap's value parser via the type's `FromStr`), so `run` receives domain values: the strictly-typed core is the whole point. Never leak an internal representation into a flag; `--price 4.50` parses to a `Price`, not `--price-minor 450`.
- **Every positional and option sets an explicit lowercase `value_name` (the concept word), never clap's auto-uppercased field name.** Clap defaults an argument's value-name to the SHOUTING-CASE of its Rust field (`service: Service` renders `<SERVICE>`); that is an implementation detail leaking into the help text. Give each `#[arg(...)]` a `value_name = "..."` that is the concept word in lowercase angle brackets (`<peer>`, `<link>`, `<service>`, `<duration>`). One word per concept, family-wide: the same field meaning renders the same value-name in every crate (a capability link is `<link>` in tightbeam and swoosh both), so the wrapping tool's help reads identically to the tool it wraps. The value-name is decoupled from the field, so pick the reader's word even when the field must differ (a `node` field that means a peer still shows `<peer>`).
- **The short help is a one-line MAP; detail lives in `long_help`, the `//!` note, and the README.** A flag's `///` doc comment (shown on `-h`) states what it is and its value forms in ONE line, nothing more. Footguns, security caveats, and rationale go in `#[arg(long_help = "...")]` (shown only on `--help`), the module `//!` note, or the README, never the short line. A reader scanning `-h` gets the map; a reader who wants the why asks for `--help`. Unify one phrasing per concept family-wide, so the same slot reads identically across every verb (`the peer to reach: a petname (...), a raw node id, or a `sheer:` link`). Corollary: do not re-spell in the help text anything the parser already renders. A `#[arg(env = "VAR")]` makes clap append `[env: VAR=]` itself, so naming the var again in the `///` double-prints it.
- **Guard a foreseeable user mistake with a teaching error, not a raw OS or parser error.** When a user-supplied value can hit a confusing low-level error (`--key <dir>` surfacing `Is a directory (os error 21)`, a mistyped key surfacing a crypto-suite-tag error), catch it at the boundary and return a message that names the concept and the fix (`--key wants a key file, not a directory: <p>. Name a file inside it, e.g. <p>/identity.key`). The bar: the message unblocks a first-time user who typed the wrong thing, rather than leaking the implementation's own vocabulary. This is the input twin of "fail loudly with the reason": the reason must also teach.
- **Give commands short aliases** (`list`/`ls`, `create`/`new`) through the parser's alias support.
- **A verb requires only the state it genuinely needs; ephemeral by default, persist only where the semantics demand it.** A verb that reaches outward (a `ping`, a `speed`, a `status`) addresses a peer and is never dialed back, so it must not require or create a persistent identity: it mints a fresh random ephemeral key each run, nothing provisioned, nothing left on disk. Only a verb that must be reachable at a stable address (a `serve`) persists its identity. The rule generalizes past identity to any acquired resource (a key, a config dir, a temp file): default to the cheapest lifetime the verb's job allows, and keep an explicit override (`--key`, `SWOOSH_KEY`) for the caller who does want the pinned version. The choice belongs to the verb, not to a one-size composition root: dispatch decides the intent, and the root honors it.
- **Never announce success before it is real; fail loudly with the reason.** A readiness/success line (`forwarding …`, `ready`, `connected`) is a claim, so print it ONLY after the operation is actually admitted or established, never optimistically before the seam that can refuse. The false-success shape (print "forwarding …", then have the gate refuse the stream and reset mutely) reads as connected-then-mysteriously-dead and hides the reason the caller most needs. When a remote seam can refuse (a gate, a handshake, an auth check), probe admission first: on refusal, surface the remote's own reason on stderr in one line (`refused by <peer>: <reason>`) and exit non-zero; on success, only then announce. A silent reset behind a hopeful banner is a bug, not an edge case. This is the output twin of parse-don't-validate: prove the thing before you say it happened.
- **A refusal is a TYPED error, never a measured value.** A refusal, an unsupported service, or an unreachable target must surface as a distinct error, NEVER as a metric shaped like success: not `0`, not `100% loss`, not `0.00 MiB/s`, not an empty result, not a plausible small number. The previous rule guards the success BANNER (output order); this one guards the metric VALUE, the seam the banner rule walks past because `ping`/`speed`/`status` print a true "reached" and then a false number. If a remote seam can refuse AFTER admission (a wrong-method handler, a mid-stream gate), the protocol carries a refusal FRAME so the client can tell "refused" from "measured badly" (measure's `Response::Unsupported`, the twin of tightbeam's `Response::Error`); a silent stream close is not enough, because the measurement loop reads a silent close as data (loss, zero bytes). Enforce this with a TYPE the conflation cannot compile through, not a convention: a `Refused` error variant distinct from `Io`, decoded at every `Response::read` match site, so a render site MUST handle it explicitly; and a report type (`PingReport`, `SpeedReport`) the refusal short-circuits BEFORE, so it is structurally unconstructable from a refusal. A future verb that dials a service the node does not serve gets a `Refused` it cannot fold into a `0`, because `0` is not a legal arm for it.
- **Mutually-exclusive modes are ONE typed selector, not a bag of bools or an `ArgGroup`.** When a flag chooses among a small closed set of alternatives (bind a port / stream to stdout / a unix listener), model it as one value that parses to a closed `enum` (`--to <port | - | unix:PATH>` → `enum To { Port(u16), Stdout, UnixListener(PathBuf) }`), not two flags fenced by `ArgGroup::required(true)` nor a pile of booleans. A single value can hold exactly one arm, so "two modes at once" is unrepresentable with no runtime group machinery, and `run` matches an enum instead of reconstructing intent from `Option`/`bool` combinations. Parse-don't-validate at the boundary: disambiguate the arms by a prefix test in a fixed order (`unix:` before `-` before a numeric port) so a bare path can never masquerade as a port, and reject anything else as a hard parse error whose message names the legal forms (never a silent misparse). Reserve an arm you have not built yet by parsing it and returning a clear "reserved, not yet built" error, so the grammar is closed and future-proof while the binary never claims a mode it lacks.

## Concurrency & persistence
- **All correctness-critical coordination lives in the database**, not in app-memory locks, so the service tier is stateless and horizontally scalable.
- **Typed repository trait per aggregate** (`UserRepo`, `OrderRepo`, `PaymentRepo`); **the query layer is fully contained behind them.** The rest of the codebase sees only domain types. A local/embedded store follows the same shape with its own trait.
- **Transactions are explicit and short**; no network call is held open inside a DB transaction.
- **Concurrency primitives are named and intentional** and each gets a why-comment: guarded atomic `UPDATE ... WHERE qty >= n`, `UNIQUE` for idempotency, optimistic `version` for concurrent edits.
- **A byte pump terminates on the direction that actually signals "done", not always on both.** A duplex splice between two closable sockets is a symmetric wait-for-both (each direction half-closes its writer on EOF, then both must finish), correct there, because a request/response protocol needs the response after the request half-closes. But a pump with an ASYMMETRIC end is a real bug when it waits for both: an ssh-`ProxyCommand`-style stdio bridge reads a local stdin that (at a terminal) never reaches EOF, so waiting for both hangs forever after the remote command exits. Pick the termination on the direction that means the work is done (the PEER closing = the service is finished) with `select!`, half-close the other way, and return; do not park on a stream that will never close. Name which direction is authoritative and why in a comment. Verify the fix with a real run that a `-- <cmd>` invocation exits promptly with the command's status.
- **A hand-rolled `poll_read`/`poll_*` that parks on a `tokio::sync::Notify` must register interest BEFORE it checks the shared condition, and hold the `Notified` future ACROSS polls, else it loses wakes and stalls.** `Notify::notify_waiters` stores no permit: it wakes only waiters ALREADY registered, so a check-THEN-register order can miss the append/close that lands in the gap and park forever (an intermittent, load-dependent hang). Order it the other way: (1) obtain the `Notified` future and poll it once to register the waker with THIS `cx`, (2) then inspect the shared state under its lock: any change after step 1 is now guaranteed to wake you, any change before it is observed by the inspection. The future must live across `poll_read` calls (store it in the reader, e.g. `Option<Pin<Box<dyn Future + Send>>>` owning the shared `Arc`, so it is `'static`), because dropping it on each `Pending` deregisters the waker; clear it only when you make progress (read bytes or observe close). If the pre-check poll returns `Ready` (a wake already fired), still fall through to inspect, then loop to re-register. Prove it with a SILENT consumer (opens, never reads) that must not stall the producer or the other consumers, run enough times to catch the race. See tightbeam `raw_stream_fanout::Cursor::poll_read`.
- **A `tokio::time::timeout` around a blocking syscall does NOT cancel the syscall: it cancels the await and LEAKS the parked thread. Kill the leak at the syscall (nonblocking + reactor), don't cap around it.** When a peer can make the node do a syscall that parks (a `fifo:` `open()` that blocks until a writer appears, a socket read), wrapping a `spawn_blocking` in a timeout only abandons the await; the blocking-pool thread stays parked until the syscall returns on its own, so a peer cycling the operation LEAKS one thread per go and eventually exhausts the pool (a whole-node DoS), regardless of any concurrency cap (a cap bounds CONCURRENT parks, never ACCUMULATED leaks). The fix is to make the operation nonblocking so nothing ever parks: open with `O_NONBLOCK` (a read-only FIFO/socket open then returns AT ONCE with a valid fd) and drive readiness through the reactor (`tokio::io::unix::AsyncFd`), awaiting readable/writable bounded by the timeout; on elapse, drop the fd (cheap, no parked thread) and refuse. Preserve the semantics the block gave you: a writer-less nonblocking FIFO reads as instant EOF, so still await a WRITER (readable readiness) before calling the stream open, so the peer gets real bytes, not an empty stream. See tightbeam `raw_stream::open_path` + `NonblockingReader`. A concurrency cap (`RAW_STREAM_OPEN_PERMITS`, a named `Semaphore` sized well below the shared pool, `try_acquire` → a clean `Response::Error` over the cap) is still healthy DEFENSE-IN-DEPTH (it bounds the fds a peer holds mid-open, the availability twin of `MAX_STREAMS_PER_SESSION`/`MAX_SESSIONS`), but it is NOT what makes the flood safe: the nonblocking open that never parks is. Do not let a cap's doc claim it bounds a leak it cannot bound. When O_NONBLOCK does not cover a variant (a regular-file open on a hung NFS mount ignores it and blocks in the kernel), that needs real pool isolation, not a cap; name it as a known gap rather than pretending the cap covers it.

## Comments & docs
- **Why, not what.** Code is the most reliable description of the logic; a comment that merely restates the next line is unconstrained, will drift, and becomes a lie. Delete it.
- **`///` on every public item and every enforced invariant.** Document *why* the invariant exists at the point it's enforced.
- **No em dashes** anywhere in prose (comments, docs, README, commit messages, PR text).

## Documentation
_The doc voice, proven across every repo. A README, crate description, or `--help` line follows these._
- **Say what it IS, not how it came to be.** Lead with what the thing does for the reader. No lineage as the opener ("built on X", "part of the Y suite"); name a building block only where it genuinely helps the reader understand or use the thing.
- **A stranger gets it from the first paragraph** with zero knowledge of any other project or its history.
- **No jargon, no phrases that sound like something but mean nothing.** If a phrase needs decoding, cut it or replace it with the plain thing.
- **Do not sell.** No superlatives, no "unified", no "reduces the need to manage N tools". Describe; let the reader judge.
- **Concrete over abstract.** Show a real command and its real output, or a real code snippet. The reader learns by seeing it work.
- **Captured output is real, and stays real.** Any command output a doc shows is pasted from an actual run, never hand-written or imagined, and re-captured when the surface changes. A banner or line that no longer prints is a fabrication, the worst doc bug there is: a reader trusts what they cannot yet run themselves. If you have not captured a paste, mark it (`<!-- pending live-run -->`) rather than inventing a plausible line.
- **Define a word before you use it.** The first time a doc leans on a term of art (a "slip", a "fleet", a "signet"), say in one line what it is. A reader should never meet a load-bearing noun they cannot decode from the page in front of them.
- **A runnable `examples/` file is the intuitiveness gate for a library surface.** Reduced to one small task against the PUBLIC API, an example exposes where the design is awkward before a stranger hits it: a step that should have a default, a raw type where a domain one belongs, a builder easy to misorder, a `Result` that must be threaded where a value reads cleaner. Write the example a stranger would, then FIX what it reveals rather than papering over it in prose. It must COMPILE and RUN green in CI (it is a real reader following the docs); if the clean path does not work over the example's transport, say why in the module note (e.g. mem gives a synthetic node id, so present the link with `to_node` rather than `from_link`) instead of leaving the reader to discover it as a runtime failure. Prefer the library's own convenience seam (`mint_link`) over reaching past it into a dependency's raw API (`Identity::mint().link()`): if the raw path is the one a reader reaches for and it is a footgun, that is the signal to fix the seam, not the example.
- **Describe what ships, not what is planned.** Planned work goes in a clearly-marked section ("Not yet", "Planned"), never mixed into the description of what the thing does today.
- **Terse. KISS.** Every sentence earns its place. Long enough to be clear, not one word longer.
- **The one-line help / crate `about` states the action in the reader's terms,** no metaphor that needs decoding. Rich rationale lives in the `//!` module note or the README, never in the `about` line.
- **If the name is a metaphor, a "The name." note earns it** after the reader already knows what the thing does. State the what plainly first; then, in one to three sentences, say why it carries that name. The payoff comes after the what, never as the lead.

## Code layout & readability
- **Top-down story.** Lay items out so meaning is discovered reading downward: a high-level item on line 1 references helpers defined below it, so a reader chasing a detail reads *on* until satisfied, then exits, never scrolls up to assemble context first.
- **No `mod.rs`.** Use `<module>.rs` with submodules in a sibling `<module>/` directory.
- **Clear separation of concerns:** pure domain (DB-free) < repos < service handlers (thin) < transport.
- **Imports follow the `StdExternalCrate` group order**, blank-line separated, in this exact sequence (rustfmt `group_imports = "StdExternalCrate"`):
  1. Standard library (`std` / `core` / `alloc`)
  2. External crates
  3. Symbols from the local crate and parent module (`crate::`, `super::`)
  4. Local module declarations (`mod ...;`)
  5. Symbols from those local modules (optional), referenced bare, `use rows::UserRow;`, never `use self::rows::UserRow;`. The `self::` prefix is noise; the bare path resolves to the child module already in scope.
- **Module import granularity** (rustfmt `imports_granularity = "Module"`): one `use` per module path; never collapse different submodules of a crate into one braced block.
  - Allowed: `use core::future::{pending, Future};` / `use core::pin::Pin;` / `use std::time::Duration;`
  - Not allowed: `use core::{future::{pending, Future}, pin::Pin};` / `use std::{thread, time::Duration};`
- **Qualify one level** where it reads better than pulling the leaf in: `use std::io;` → `io::Error`; `use tokio::sync::{mpsc, oneshot};` → `mpsc::channel`; `use tokio::time;` → `time::Duration`, `time::sleep`.
- **Path-qualify derive macros from crates:** `#[derive(thiserror::Error, Debug)]`, not a bare `Error` brought in by `use`.
- **Never wildcard-import** (`use foo::*`); bring every name in explicitly so a reader always knows where a symbol comes from. Enforced by `clippy::wildcard_imports = deny`.
- **`cargo sort --grouped`** keeps `Cargo.toml` dependencies ordered. Local (in-tree/path) dependencies are grouped first, blank-line-separated from the externals, in both `[dependencies]` and `[workspace.dependencies]`; each group is then sorted alphabetically within itself (the `--grouped` flag honors the blank-line groups and sorts inside them). This mirrors the `use`-statement local/external split: a reader scanning a manifest sees at a glance which deps are in-tree and will move with a refactor. Sort within the group alphabetically, not by dependency layer.

## Tests
- **Test-first for the domain layer** (it's pure, so tests are fast and DB-free).
- **Unit tests in a separate `<module>_tests.rs` file**, not inline in the module. Integration tests (real transport + database + external mocks via testcontainers) in `tests/`.
- **Cover zero / one / many / error** per behavior. Prefer **`assert_matches!`** for enum/error assertions; it is nightly-unstable, so on stable use `assert!(matches!(...))`.
- **Assert on invariants**, including **compile-time assertions** for constant relationships.
- **Concurrency is tested with a barrier** (N tasks released together) asserting the invariant holds, not hoped at.
- **Names read like documentation:** `checkout_decline_leaves_order_open_and_inventory_untouched`. DRY setup via shared builders.

## Observability
- **`tracing` with spans.** Key operations open a span carrying the correlation id (idempotency key, request id) so an operation is traceable end-to-end.
- **Structured fields, never string formatting:** `info!(order_id = %id, "checkout started")`, not `info!("checkout started for {id}")`.

## Serialization
- **Tagged enums when using JSON:** `{ "kind": "...", "data": ... }` with the variant name in **PascalCase** under `kind`, not `{ "<variant>": <data> }`.

## Security
- **`zeroize` sensitive data** so secrets don't linger in freed memory.
- **A trust default degrades to SELF, never to open and never to a dead end.** When a gate needs a trust root and none is provisioned, root it at the node's OWN identity key (self-trust: admit yourself and whom you delegate, refuse strangers) rather than forcing the operator to either open the gate to everyone or hit a "nothing to gate on" error. A node is its own root of trust by default. The permissive opt-out (`--public`) stays an explicit, named choice; absence of provisioning is not a reason to fall open, and self-trust keeps a plain node useful without weakening the stranger-refused guarantee (person-zero self-signet, swoosh `serve`).
- **A mutation handler holds a CAPABILITY to request an action, never the AUTHORITY to perform it.** When an admitted request may change a shared resource's lifecycle (stop the node, drain it, rotate a key), hand the handler a narrow, cloneable capability that only REQUESTS the effect (a `CancellationToken` clone, a bounded command channel), not a handle to the resource itself. The one owner acts on the request in one place; the handler never tears anything down directly. So "who may trigger the action" stays a cap-gated property of who holds a capability clone, and "how the action happens" lives with the single owner, never scattered across every handler that can ask for it (tightbeam `Exposer::run` owns teardown; `control.stop` and `serve --for` hold token clones).

## Tooling & dependencies
- **`cargo fmt`, `cargo clippy -D warnings`, `cargo sort --grouped`** all clean before every commit, part of the definition of done. `--grouped` is the house form so the local-above-external manifest grouping (see Code layout) survives the sort.
- **Prefer `core::` over `std::`** wherever the item exists in `core`. Do not prefer `alloc::` over `std::`: if an item lives only in `alloc` (not `core`), just use `std::`. Enforced by `clippy::std_instead_of_core` (restriction lint, `warn`).
- **Explicitly-sized integer types over arch-specific** (`u64`/`u32`, not `usize`) wherever the width is semantic rather than a container index.
- **Macros defined sparingly.** Great power, great responsibility: only with irrefutable rationale.
- **Dependencies introduced sparingly**, every one indisputable and absolutely necessary.

## Commits & PRs (read like a story)
- **Each commit is one coherent step, builds and passes on its own,** and its message says what it did *and* what it sets up, earlier commits visibly lay the groundwork a later feature clicks into.
- **PR body uses the house template:** Motivation / In this PR / Test Plan / Backwards compatibility / Future Work. Narrate the correctness invariants so review questions are pre-answered.
- **Small, reviewable diffs.** An "and also" section means it was two PRs.

## House rules (flagged in review)
_Preferences called out during review. Add to this as more are flagged; reviewers should never have
to flag the same smell twice._

- **Bind behaviour to types; free functions are a smell.** Nearly everything should be a method on a
  type, composable and consumable. Model an operation as a type you construct and consume
  (`Digest::of(reader)`, `Encoder::new(w, r).send(header, &item, source)`); a one-shot op takes `self`
  by value. Reserve bare
  free functions for genuinely standalone pure helpers, and even then prefer a local trait for a
  cohesive family of conversions (see the wire/domain/storage section).
- **The discriminator for a free function is who owns the type the behaviour binds, and which direction a method would force the code to move.** A free function is a smell, and the fix is a method, when it (a) constructs one of this crate's types, especially a boxed enum variant, or (b) threads the state of a type this crate owns. It is legitimate in exactly three cases: (1) a pure helper over no receiver you own; (2) a policy resolver at the correct layer, over foreign inputs, yielding a value that belongs to a lower crate (e.g. `resolve_gate`); (3) a serialization or edge adapter that marshals a wire form into a lower-crate type and then delegates to one method that already exists there (e.g. `mint_link`). The test is not pure-versus-impure: it is ownership and direction. Making a legitimate free function into a method would invert the dependency, forcing code to move the wrong way; making a smelly one into a method moves the behaviour home to the type that owns it. Builders are earned only by staged optional assembly with a build-time invariant, never by wrapping a fixed-arity one-shot.
- **Wrap a foreign stack once, at the composition root; everything downstream speaks your own vocabulary.**
  An app names a concrete external implementation (a specific transport, driver, or backend) exactly once,
  where it builds its root object. Every subsequent operation is generic over your own traits. If a file
  imports the concrete backend crate outside `main`, that is a leak.
- **A library speaks only its OWN vocabulary; it never names or alludes to a consumer's flags, binary, or
  bin-specific concepts, in code OR docs.** A library is consumed by callers it will never enumerate, so a
  doc, identifier, or comment that reaches UP to one specific consumer (a CLI flag like `serve --for` /
  `--public` / `--peer`, a named bin, a consumer's own service name) overfits the lib to that one bin and
  rots the moment another consumer arrives or a flag is renamed. Name the concept the library itself OWNS,
  never the surface a consumer paints over it: tightbeam owns THE CANCELLATION TOKEN an exposer holds (a
  caller may hold a clone to trigger teardown; who fires it, and why, is the consumer's concern and goes
  unnamed here), so that is the only vocabulary its docs may use, never `serve --for`; nauthy owns [`Gate::Open`]
  (building an open gate is the caller's own choice), never `--public`; bifrost owns a DIRECT ADDRESS HINT,
  never `--peer`; bifrost-core owns the DERIVED-KEY payload a machine adopts, never `--authkey`. The same
  holds dep->consumer: a dependency never alludes to the app that consumes it, and the consumer bin name
  (`swoosh`, or any other) NEVER appears in the prime libraries (`nauthy`, `tightbeam`, `bifrost`, `quirk`).
  Where a lib doc genuinely must gesture at how it is driven, say "a consumer" / "a CLI over this library" /
  "the caller", never the bin: the library-vs-CLI boundary is worth explaining, the consumer's name is not.
  This is the up-the-stack twin of "wrap a foreign stack once": that rule stops a consumer leaking a
  dependency's vocabulary DOWN, this one stops a library leaking a consumer's vocabulary UP. A frozen
  protocol constant that merely CONTAINS such a token (a KDF domain-separator string) is not an allusion and
  must not be reworded, since changing it changes the bytes.
- **Keep layer concerns pure.** A layer touches only its own concern and knows nothing of the layers around
  it: a byte-moving layer knows nothing of files, paths, filenames, temp files, or the filesystem (its
  sources and sinks are `AsyncRead`/`AsyncWrite` the caller supplies); naming and temp-then-rename are the
  application's job. Each layer touches only its own concern.
- **`tokio::io` is imported one level qualified:** `use tokio::io;` then `io::AsyncRead`, `io::copy`,
  `io::duplex`, `io::split`, `io::WriteHalf`. Extension traits whose methods you call but whose names
  you do not use come in anonymously: `use tokio::io::AsyncReadExt as _;`.
