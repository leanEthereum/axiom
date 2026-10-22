# Axiom engineering standards

Axiom is a research consensus client for the Ethereum beacon chain, written in Rust.

It tracks the latest release of `ethereum/consensus-specs` and must pass its test suite.

These rules are binding for every crate, every file, and every contributor, human or agent.

## Targets

- Fork: Fulu, the fork live on mainnet.
- Specification: `ethereum/consensus-specs` at the version pinned in `testing/ef-tests/Makefile`.
- Presets: `mainnet` and `minimal`, both compiled in.

## Dependency policy

Axiom owns its protocol stack. A dependency must earn its place.

Allowed, and already declared in the root `Cargo.toml`:

- `sha2`, for SHA-256.
- `tokio`, for the async runtime at the effectful edge only, with the features it needs.
- `tracing` and `tracing-subscriber`, for telemetry, with default features off and no serde.
- `thiserror`, for error types.
- `proptest`, as a dev-dependency only.
- `criterion`, as a dev-dependency of benchmarks only.

Everything else is written here:

- Encodings: SSZ and merkleization, snappy, YAML, JSON, RLP.
- Cryptography: BLS12-381, KZG, secp256k1, X25519, Keccak, the AEADs.
- Systems: the database, HTTP, the engine API, Prometheus metrics.
- Networking: libp2p, Noise, yamux, gossipsub, discv5.

Adding a crate requires a reason recorded in the commit message and in the root manifest.

`anyhow` and `serde` are not used.

Errors derive `thiserror::Error`: one `#[error("...")]` message per variant, `#[from]` or `#[source]` for wrapped causes.

An error carries what a reader of the log needs to act on it:

- A count or length mismatch carries both sides: expected and actual.
- A bound violation carries the value and the bound.
- A failed check on an item names the item: its index, slot, root, or peer.
- The message prints every field, so the log line stands on its own.

A variant stays bare only when there is nothing to add, such as an empty input.

## Crate graph

Dependencies point one way only.

```text
L0  ssz, yaml, snappy, json, rlp            encodings                          pure
L0  bls12-381, bls, kzg, crypto             curves, signatures, commitments    pure
L0  types                                   newtypes, presets, containers      pure
L1  state-transition                        per-slot, per-block, per-epoch     pure
L2  fork-choice, das, gossip, light-client  the store and the network's rules  pure
L3  store, http, execution, p2p, discv5     database, sockets, engine API      effects
L3  telemetry                               logs and metrics                   effects
L4  node                                    chain thread, services, sync       async
L5  bin/axiom                               the command line                   async
```

Nothing in L0 to L2 reads a clock, opens a socket, touches a disk, spawns a task, or logs.

Scoped data-parallel threads are allowed in L0 when they are always joined and the result is deterministic.
KZG uses them for multi-scalar multiplications.

The node's chain lives on one thread and owns all consensus state.
Async services reach it through a queue of closures, so no lock guards consensus data.

## Rust style

- Edition 2024, latest stable toolchain, pinned in `rust-toolchain.toml`.
- Format with nightly rustfmt: `cargo +nightly fmt --all`.
- Lint with `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- Newtype every domain scalar. A bare `u64` slot is a defect.
- Make illegal states unrepresentable. Validate at the boundary, trust inside.
- No `unwrap` or `expect` outside tests, unless an invariant makes failure impossible and a comment proves it.
- No `unsafe` without a `// SAFETY:` comment tied to a checked invariant.
- Imports sit at the top of the file or of `mod tests`. Never inline-qualify a path.
- One concern per file. Every `impl` block sits right after its type, in the type's module.
- A module that grows unrelated types becomes a folder of focused files.
- Prefer methods on well-named types to free functions. See "Abstractions" below.
- A trait exists only for real variation. A closed set of alternatives is an enum.
- No `macro_rules!`, and no proc macros besides the `thiserror` derive. Write the expansion by hand.
- Standard derives only: `Clone`, `Copy`, `Debug`, `Default`, `PartialEq`, `Eq`, `Hash`, `PartialOrd`, `Ord`, plus `thiserror::Error` on error types.

## Abstractions

Behaviour lives on the type it belongs to, the way `std` puts it there.

A module-level function is allowed only when it has no natural receiver:

- A crate's single, obvious entry point over plain inputs, such as hashing a byte slice.
- A stateless transform whose inputs are all primitives or foreign types, with no family of siblings.
- A `const fn` that builds a compile-time table.

Everything else is a method. These signals mean a type is missing:

- Several functions pass the same bundle of arguments to each other: that bundle is a struct.
- A position or offset threads through calls and comes back in a tuple: that is a cursor or reader.
- A function returns an `Option` meaning "need more input": that is an incremental decoder with state.
- A function allocates a scratch buffer on every call: that is an encoder that owns and reuses it.
- A helper reads or writes one type's fields: it is a method of that type.
- A function named after a type, such as decoding, encoding, parsing, or writing it: it is that type's associated function.
  Many types sharing one codec shape justify one small codec trait.
- One type's impl blocks spread over several files: it is a god object doing several jobs.
  Moving the impls into one file only makes a bigger god object.
  Find the seams instead, give each job a type that owns its state, and let the original type compose them.

Design the API before the body:

- Name types after what they are: `FrameDecoder`, `Cursor`, `Encoder`, `Field`, not `Helper` or `Utils`.
- Keep the public surface minimal; private steps are private methods.
- A refactor never changes behaviour: vectors and tests pin it, and hot paths are benchmarked before and after.

## Documentation

Every public item, field, and variant has a header doc.

The four hard rules:

1. One sentence per line. A sentence never wraps across two comment lines.
2. Blank lines between logical groups. Never more than three contiguous prose lines.
3. Short sentences, under fifteen words when possible. Active voice, present tense.
4. Never name a function, method, variable, or type in prose, not even with an intra-doc link.

More rules:

- Header docs are one line by default. Add a body only for a non-obvious choice or invariant.
- Never enumerate a struct's fields or an enum's variants in its header.
- Constants document the constraint that produced the value, not the value.
- Cite the spec, the EIP, or the paper for every non-obvious rule or constant.
- Section names: `# Overview`, `# Algorithm`, `# Invariants`, `# Performance`, `# Arguments`, `# Returns`, `# Errors`, `# Panics`, `# Safety`.
- No code examples in docs: tests show usage, and examples only go stale and bury the explanation.
  Diagrams fenced as `text` stay.
- Diagrams in `///` docs are fenced as `text`. In `//` comments they are indented four spaces.
- Inline comments explain the reasoning and teach the domain, glued to the line they explain.
- Useful labels: `// Invariant:`, `// Threshold:`, `// Timing:`, `// Phase N:`, `// Fixture state:`, `// Mutation:`.
- Never reference the past: no "previously", "used to", "regression".
- No banner separators such as `// =====` or `// -----`.
- No backticks in `//` comments. In `///` docs, backticks only around literal values and paths.
- Tests have no header doc. Their bodies are narrated line by line with concrete numbers.

## Testing

- Unit and property tests live in the file they test, in a `#[cfg(test)] mod tests` at the bottom.
- `tests/` holds only black-box suites over the public API: end-to-end runs, simulations, crash and model tests, and conformance against external vector files.
  A unit test moves to `tests/` only if keeping it inline would make its file unreadable.
- Benchmarks are criterion benches under `benches/`, never ignored tests.
  Each bench target sets `harness = false` and drives criterion from a plain `main`, without its macros.

- Consensus spec vectors are the interop contract. They run from `testing/ef-tests`.
- Property tests with `proptest` for every law: round-trips, reference equality, determinism.
- Cover every scenario exactly once. Assert whole values and complete errors.

## Commands

```sh
cargo build --workspace
make -C testing/ef-tests            # download the consensus spec, BLS, and KZG vectors
cargo test --workspace --release
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```
