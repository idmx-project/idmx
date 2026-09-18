---
name: rust-strict
description: Personal Rust guidelines — type-driven design (enums, newtypes, type-state), error handling (anyhow vs thiserror), project structure, visibility, performance, testing, tooling, and CI hardening. Use when writing, reviewing, or refactoring Rust code, or when the user invokes /rust-strict.
---

# Strict Rust Guidelines

Apply these when writing, reviewing, or refactoring Rust. Core idea: **make invalid states
unrepresentable and let the compiler enforce the business logic.** When reviewing, report
violations as `file:line — rule — fix`.

## 1. Type-driven design

### Enums over flag structs
A struct with flags/options permits contradictory states (`paid: true` *and* `error: Some(..)`).
Model mutually exclusive states as an enum; `match` forces every state to be handled.

```rust
// Bad
struct Order { paid: bool, shipped: bool, error: Option<String> }

// Good
enum Order {
    Pending,
    Paid { receipt: Receipt },
    Shipped { tracking: TrackingId },
    Failed { reason: String },
}
```

- Avoid wildcard `_ =>` arms on your own enums — a new variant should break the build.

### Newtypes over primitives
Replace bare `String`/`u64`/etc. with dedicated types validated on construction. Once a value
exists it is valid; no re-validation downstream.

```rust
pub struct Email(String);

impl Email {
    pub fn parse(s: &str) -> Result<Self, EmailError> { /* validate once */ }
    pub fn as_str(&self) -> &str { &self.0 }
}
```

- Keep the inner field private; the only way in is the validating constructor
  (`parse`/`new`/`TryFrom`/`FromStr`).
- Do not derive `Default` or expose mutators that can break the invariant.
- Newtypes also prevent argument mix-ups (`UserId` vs `OrderId`).

### Type-state pattern
Move runtime state (`is_open: bool`, verified vs unverified) into the type. Methods exist only
on the state where they are legal, so misuse fails to compile instead of failing at runtime.

```rust
use std::marker::PhantomData;

pub struct Open;
pub struct Closed;

pub struct Connection<S> { addr: String, _state: PhantomData<S> }

impl Connection<Closed> {
    pub fn open(self) -> Result<Connection<Open>, ConnectError> { /* ... */ }
}

impl Connection<Open> {
    pub fn send(&mut self, msg: &[u8]) -> Result<(), SendError> { /* ... */ }
    pub fn close(self) -> Connection<Closed> { /* ... */ }
}
```

- Transitions consume `self` and return the new state, so the old state cannot be reused.
- Use it for real protocol/business flows (unverified → verified user, draft → signed message).
  Do not use it when the state is only known at runtime — use an enum there.

## 2. Error handling

| Situation | Use |
|---|---|
| Application / binary code; caller only needs "it failed" plus a good message | `anyhow` |
| Library code, or caller must branch on specific failure modes | `thiserror` (typed error enum) |

The split is by *who handles the error*, not "anyhow wherever it compiles":

- Every binary's `main` returns `anyhow::Result<()>`; startup, config, and CLI glue use
  `anyhow` with context. That is where errors are only printed before exiting.
- Library crates never depend on `anyhow` (dev-dependencies for test helpers are fine) and
  never expose `anyhow::Error` in their public API.
- Inside a binary, code whose caller must *react* to the failure — retry vs. give up, map to
  an HTTP status or protocol error code, assert a specific variant in a test — still uses a
  typed `thiserror` enum. `anyhow` erases the type; a `match` on an enum breaks the build
  when a variant is added, an opaque error cannot.

### anyhow
- Return `anyhow::Result<T>` instead of hand-writing an error enum per situation.
- Attach context to every fallible boundary (I/O, network, parsing). Prefer `with_context`
  when the message allocates/formats — the closure only runs on the error path, so the happy
  path costs nothing.

```rust
use anyhow::{bail, anyhow, Context, Result};

fn load(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    let cfg: Config = toml::from_str(&raw).context("parsing config")?;
    if cfg.port == 0 {
        bail!("port must be non-zero");          // create + early return
    }
    let host = cfg.host.clone().ok_or_else(|| anyhow!("missing host"))?; // error value for `?`
    Ok(cfg)
}
```

- `anyhow!` builds an error value (use with `?`, `ok_or_else`, `map_err`).
- `bail!` = `return Err(anyhow!(..))`.

### thiserror
```rust
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("signature expired at {0}")]
    Expired(u64),
    #[error("unknown key selector {0}")]
    UnknownKey(String),
    #[error(transparent)]
    Dns(#[from] ResolveError),
}
```

### General
- No `unwrap()`/`expect()` outside tests, examples, and proven-infallible cases (then `expect`
  with the reason).
- `#[must_use]` on functions/types whose result must not be silently dropped (builders,
  validation results, guards).

## 3. Scaling the code

- **Type reuse:** start with trait objects (`Box<dyn Trait>`, `&dyn Trait`) for simplicity;
  switch to generics (`impl Trait`, `T: Trait`) when you need static dispatch performance or
  compile-time guarantees. Do not add generics speculatively.
- **Macros:** use `macro_rules!` (or derive macros) to remove genuinely repetitive code — after
  the pattern has repeated, not before. Prefer a function or generic if one suffices.
- **Project structure:** keep `main.rs` thin (parse args, wire things up, call into the lib).
  Logic lives in modules / `lib.rs`. A small, curated `prelude` module is fine for imports
  used almost everywhere — keep it curated, no glob re-export of everything.
- **Visibility:** default to private. Use `pub(crate)` for crate-internal sharing; `pub` only
  for the intended API. Every `pub` item is a refactoring constraint.

## 4. Performance

Cheap habits below are defaults. Anything bigger: measure first (`cargo bench`/criterion,
`cargo flamegraph`), always in `--release`.

- **Borrow, don't allocate:** take `&str` / `&[T]` / `&Path` in parameters instead of
  `String` / `Vec<T>` / `PathBuf` unless the function needs ownership. Return slices into the
  input where lifetimes allow. In hot loops avoid `to_string()`, `clone()`, `format!`, and
  `collect()` into a temporary `Vec` just to iterate again. Reuse buffers (`clear()` and
  refill) and use `with_capacity` when the size is known. `Cow<'_, str>` when only some paths
  need to allocate.
- **Evaluate fallbacks lazily:** `ok_or_else`, `unwrap_or_else`, `map_or_else`,
  `or_insert_with` over the eager forms (`ok_or`, `unwrap_or`, `or_insert`) whenever the
  fallback allocates, formats, or computes — eager arguments are built even on the happy
  path. Eager forms are fine for constants and cheap `Copy` values.
- **Don't repeat work:** one lookup instead of check + insert + update — use the `entry` API.

  ```rust
  // Bad: up to three hash lookups
  if !counts.contains_key(word) { counts.insert(word, 0); }
  *counts.get_mut(word).unwrap() += 1;

  // Good: one
  *counts.entry(word).or_insert(0) += 1;
  ```

  Same idea elsewhere: `if let Some(x) = map.get(k)` over `contains_key` + index, hoist
  invariant computations out of loops, compile regexes once (`LazyLock`).
- **Use all cores:** for CPU-bound, independent per-item work over large inputs, write the
  loop as an iterator chain and switch to `rayon` (`par_iter()`, `par_lines()`,
  `par_chunks()`). Combine results with `map`/`reduce`/`fold`/`collect`, not a shared
  `Mutex`. Not for small inputs or I/O-bound work (overhead dominates), and never inside an
  async runtime's worker threads.
- **`swap_remove` when order doesn't matter:** `Vec::remove(i)` shifts every later element
  (O(n)); `swap_remove(i)` moves the last element into the hole (O(1)). For removing many
  elements use `retain`; for queue behaviour use `VecDeque`.

## 5. Dev loop

- `dbg!(expr)` over `println!` for debugging — prints file/line, expression, and value, and
  returns the value. Never commit it.
- `todo!()` over `// TODO` comments for unfinished paths — code keeps compiling and the gap is
  loud at runtime. Never ship it: `todo!()` is for work in progress only. Anything deferred
  past a commit becomes `// TODO(#123): ...` with a linked issue; a bare `// TODO` is not
  allowed.
- `bacon` for a continuous check/clippy/test feedback loop.
- `cargo nextest run` for faster, parallel test runs.
- Compiler-driven development: read the full error and its suggestion; ownership/borrowing
  errors usually point at a design problem. Fix the design — don't silence it with `clone()`,
  `Rc<RefCell<_>>`, or `'static`.

## 6. Testing

- Name tests after behavior: `parse_should_return_error_when_input_empty`. The name is the
  failure message.
- One behavior per test, ideally one assertion. Several assertions on the same result are
  fine; several scenarios in one test are not.
- Test the error paths, not only the happy path — assert on the specific variant
  (`assert!(matches!(err, VerifyError::Expired(_)))`), which is another reason libraries use
  typed errors.
- `assert_eq!`/`assert_ne!` over `assert!(a == b)` for useful diffs; add a message when the
  condition is not self-explanatory.
- Unit tests in `#[cfg(test)] mod tests` next to the code; integration tests in `tests/`
  exercise only the public API; doc tests (`///` examples) for public API usage — they keep
  the docs honest.
- `cargo insta` snapshots for large generated output (serialized messages, rendered text).
  Keep snapshots small and review every diff; never accept blindly.

## 7. Quality gates and CI

Run locally before committing and enforce in CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-features
cargo audit            # known vulnerabilities (RustSec)
cargo deny check       # licenses, banned/duplicate deps, sources
cargo tarpaulin        # test coverage
```

Clippy discipline:

- Fix warnings, don't silence them. For a real false positive use
  `#[expect(clippy::lint_name)]` with a comment saying why — not `#[allow]`; `expect` warns
  once the suppression is no longer needed.
- Lints to take seriously: `redundant_clone`, `needless_collect`, `large_enum_variant` (box
  the big variant), and the whole `clippy::perf` group.
- Configure lints once in `Cargo.toml` instead of per-file attributes:

  ```toml
  [workspace.lints.clippy]
  perf = { level = "deny", priority = -1 }
  redundant_clone = "deny"

  # in each member crate
  [lints]
  workspace = true
  ```

## Review checklist

1. Any struct with bools/Options encoding exclusive states? → enum.
2. Any primitive carrying a domain invariant (email, amount, id, selector)? → newtype with
   validating constructor.
3. Any runtime "is this allowed right now?" check on a known-at-compile-time flow? → type-state.
4. Library depending on `anyhow`, `main` not returning `anyhow::Result`, error enum nobody
   matches on, or `anyhow` where the caller must branch on the failure? → swap.
5. Fallible I/O without `context`/`with_context`? → add.
6. `pub` that could be `pub(crate)` or private? → narrow.
7. Leftover `dbg!`, `todo!`, `unwrap()`, bare `// TODO` without issue? → remove / link issue.
8. Owned params (`String`, `Vec<T>`) that are only read? Double map lookups? `Vec::remove` where
   order is irrelevant? → `&str`/`&[T]`, `entry`, `swap_remove`.
9. New behavior and its error paths covered by descriptively named tests?
10. `#[allow(clippy::..)]` without justification? → fix or `#[expect]` with reason.
11. fmt, clippy `-D warnings`, tests, audit, deny all green?
