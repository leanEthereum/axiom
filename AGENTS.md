# Axiom engineering standards

Axiom is a research consensus client for the Ethereum beacon chain, written in Rust.

It tracks the latest release of `ethereum/consensus-specs` and must pass its test suite.

These rules are binding for every crate, every file, and every contributor, human or agent.
They are how Axiom was built, and every change keeps to them.

## Who works here

Every change is made as four people at once, and dropping one shows.

- A cryptographer: states the identity a line of code preserves, and the bound that keeps it in range.
- A consensus researcher: states the guarantee a rule protects, and the adversary it must survive.
- A Rust compiler and standard library contributor: knows what rustc and LLVM make of the code, and designs APIs that read like `std`.
- A machine-level performance engineer: measures first, knows the roofline, and proves every fast path equal to its reference.

A correct but unreadable change, a fast but unsound one, and a clean one with an ugly API all fail.

Correctness comes first, then clarity, then performance.
None of them is ever traded to zero.

## Targets

- Forks: phase0, Altair, Bellatrix, Capella, Deneb, Electra, Fulu, and Gloas.
  Fulu is the fork live on mainnet.
- Specification: `ethereum/consensus-specs` at the version pinned in `testing/ef-tests/Makefile`.
- Presets: `mainnet` and `minimal`, both compiled in.

## Workflow

1. Read the primary source before writing code: the spec function, the EIP, the RFC, or the paper.
   Memory of a spec is not a spec.
   When a source contradicts memory, the source wins.
2. Read the neighbouring code, and match its types, traits, and idioms.
   New code should be indistinguishable from the best code already here.
3. Read a strong existing implementation when one exists, such as lighthouse or grandine.
   Note what it got right, and which of its mistakes to avoid.
4. Design the API before the body: types, signatures, bounds, and error enums.
5. Write the clear, correct version first.
   Specialize a hot path only where a measurement points.
6. Test it: vectors, properties, and every scenario once.
7. Document it as you go, never as a final polish pass.
8. Verify it: format, lint, docs, and the impacted tests.
   Report what ran and what it said, failures included.

## Forks

Supporting every fork is smooth, never a burden.
Fork N+1 is one new folder per crate that changes, plus one variant per combined enum.

- Data shapes vary: every container version is its own struct, in the fork that introduced it.
  `axiom_types::<fork>` re-exports the fork before it and shadows what its spec changed.
- Rules vary: a fork writes out the spec functions it changed and calls the earlier ones it kept.
- Constants vary: one table per constant family, as a method on the fork name.
- The fork in force varies by slot: dispatch happens once, at the boundary.
  Below it, code works on one concrete fork type.
- Generic code imports a container from the fork that defines it, or uses a combined enum or an accessor trait.
  It never names a later fork only to reach an inherited type.

Forbidden, because each makes forks a burden:

- Runtime fork comparisons scattered through shared code.
- The same eight-arm match repeated across consumers.
  Combined enums carry a small fixed set of methods; other consumers use accessor traits.
- A superset struct with optional fields, which makes illegal states representable.
- Generated code.

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
- Generics are no wider than the problem.
  Static dispatch at the leaves, trait objects only at the composition root.
- Convert with `.into()` wherever the target type is known.
- No `unwrap` or `expect` outside tests, unless an invariant makes failure impossible and a comment proves it.
- No `unsafe` without a `// SAFETY:` comment tied to a checked invariant.
- Imports sit at the top of the file or of `mod tests`. Never inline-qualify a path.
  A name collision between two imports is a design smell, not a reason to qualify.
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
- A field of `Option<Identity>` that every method checks first: pair a view with the identity in a borrowing type instead.
- A check the caller may forget before a risky path: return a distinct type from the check, and accept only that type downstream.

Design the API before the body:

- Name types after what they are: `FrameDecoder`, `Cursor`, `Encoder`, `Field`, not `Helper` or `Utils`.
- Keep the public surface minimal; private steps are private methods.
- Reuse an existing abstraction rather than adding a parallel one.
- A refactor never changes behaviour: vectors and tests pin it, and hot paths are benchmarked before and after.

## Errors

Errors derive `thiserror::Error`: one `#[error("...")]` message per variant, `#[from]` or `#[source]` for wrapped causes.

Each crate has its own error enums, and a variant names the invariant that broke.

An error carries what a reader of the log needs to act on it:

- A count or length mismatch carries both sides: expected and actual.
- A bound violation carries the value and the bound.
- A failed check on an item names the item: its index, slot, root, or peer.
- The message prints every field, so the log line stands on its own.

A variant stays bare only when there is nothing to add, such as an empty input.

## Consensus

- State the guarantee a rule protects, safety or liveness, and under which assumptions.
- Name the adversary.
  Check fork choice and aggregation changes against balancing, bouncing, ex ante reorgs, withholding, equivocation, and long-range attacks.
- Fork choice is a pure function of the store.
  Same store in, same head out, whatever the arrival order.
- Two messages from one validator for one slot are a first-class case, never an edge case.
- Never let a tiebreak's winner become a contract.
  Assert the invariant that decides a tie, never the identity of the winner.
- Every decoded wire message is attacker-controlled.
  Bound every index and check every length at the edge, so the pure core can trust its input.
- Cite the spec for every constant. A magic number with no cited constraint is a defect.

## Cryptography

- State the identity a computation preserves.
  For any reordering or lazy reduction, state the bound that keeps every intermediate in range.
- Constant time wherever secrets flow: no secret-dependent branches, memory indices, or variable-latency instructions.
  Say explicitly when a path handles only public data.
- Validate domain parameters and reject malformed inputs at the boundary: points on the curve, in the subgroup, scalars in range.
- Never weaken a parameter, a reduction, or a check for speed.
- Cite the paper and section for any non-obvious algorithm or formula.

## Performance

- Measure first. No change starts without a baseline, a profile that locates the time, and a hypothesis about the limit.
- Know the roofline.
  Compute the memory bound, the throughput bound of the scarce unit, and the latency bound of the longest chain.
  Attack the largest one.
- Change the algorithm before the instructions.
  Fewer passes over memory, a better reduction, batching, a better layout.
  Then intrinsics, and assembly last.
- Reach for the lowest level that measurably wins, and no lower.
- Bytes are the first cost.
  Fuse passes, size working sets to cache levels, reuse buffers, and avoid zero-fill that is overwritten anyway.
- Every fast path keeps its scalar reference in the tree, as the fallback and the oracle.
  A property test pins them equal on random and boundary inputs.
- Choose the dispatch once: a function pointer, a lazily initialised lock, or a compile-time `cfg`.
  Never choose it per element.
- `#[target_feature]` functions are the unit of specialization.
  Keep helpers inlined inside one feature context.
- x86_64 and aarch64 are both first-class.
  A win on one target that loses on the other gets its own arm, never a compromise.
- Every `cfg` arm type-checks, including the targets the host cannot run.

Benchmarks are minimal, fair, and honest:

- Bench the kernel alone at a realistic size, plus the end-to-end number if it moved.
- Same host, flags, inputs, and thread count for both sides.
- Report the median and the spread. A difference inside the spread is no change.
- Report regressions as prominently as wins.
- Tie the result to the model, such as "now at the L2 bandwidth".

Numbers live in commit messages and pull requests, never in code comments.
A comment may say which way a result went and why, never by how much.

## Documentation

Every public item, field, and variant has a header doc.

The four hard rules:

1. One sentence per line. A sentence never wraps across two comment lines.
   A sentence too long for one line is too long: split it, bullet it, or make it a formula.
2. Blank lines between logical groups. Never more than three contiguous prose lines.
3. Short sentences, under fifteen words when possible. Active voice, present tense.
4. Never name a function, method, variable, or type in prose, not even with an intra-doc link.
   Names change and docs go stale; describe the behaviour in plain English.

Header docs:

- Header docs are one line by default. Add a body only for a non-obvious choice or invariant.
- A data type's header is the shortest of all: a shape needs a sentence, not an essay.
- Never enumerate a struct's fields or an enum's variants in its header.
- Never describe generic parameters; the signature says it.
- No doc comment above an `impl` block.
- Constants document the constraint that produced the value, not the value.
- Cite the spec, the EIP, the RFC, or the paper for every non-obvious rule or constant.
- Section names: `# Overview`, `# Algorithm`, `# Invariants`, `# Performance`, `# Arguments`, `# Returns`, `# Errors`, `# Panics`, `# Safety`.
  `# Algorithm` is for a real mathematical idea, never a restatement of the body's steps.
- No code examples in docs: tests show usage, and examples only go stale and bury the explanation.

Plain text:

- Docs must read well as plain text in an editor, not only as rendered rustdoc.
- No ASCII art: no underbrace annotations, no box-drawing characters, no unicode arrows, no flow charts.
  A flow is a numbered list of short steps; a relation is one plain formula per line.
- Small plain-ASCII tables and one-line formulas are fine, fenced as `text` in `///` docs and indented four spaces in `//` comments.
- Math is plain ASCII: `_` for subscripts, `^` for exponents, `sum_i`, `prod_k`. No unicode symbols.

Inline comments teach:

- Inline comments explain the reasoning and teach the domain, glued to the line they explain.
- Write for a reader with no context about the change that produced the code.
  Describe what the code does and why, never the discussion that led to it.
- Concrete over abstract: real numbers from the context, never "handle the edge case".
- Never restate the code in English. Say why, not what.
- Useful labels: `// Invariant:`, `// Threshold:`, `// Timing:`, `// Phase N:`, `// Fixture state:`, `// Mutation:`, `// Why:`.
- Never reference the past: no "previously", "used to", "regression".
- No banner separators such as `// =====` or `// -----`.
- No backticks in `//` comments. In `///` docs, backticks only around literal values and paths.
- No filler, hedging, or marketing words: never "powerful", "seamless", "robust", "this is used to".

A comment in the house style:

```rust
// Invariant: each committee votes once per slot.
//
// Fixture state: 4 validators, 2 committees of 2.
// Mutation: validator 3 also signs for committee 0.
//
//     committee 0 bits: [1, 1, 1]
//     committee 0 size: 2
//
// Three bits for two members is out of range, so the aggregate is refused.
```

## Testing

- Unit and property tests live in the file they test, in a `#[cfg(test)] mod tests` at the bottom.
- `tests/` holds only black-box suites over the public API: end-to-end runs, simulations, crash and model tests, and conformance against external vector files.
  A unit test moves to `tests/` only if keeping it inline would make its file unreadable.
- Benchmarks are criterion benches under `benches/`, never ignored tests.
  Each bench target sets `harness = false` and drives criterion from a plain `main`, without its macros.

Reference vectors are the interop contract:

- Consensus spec vectors run from `testing/ef-tests`, for every fork and both presets.
- Every implemented standard runs its published vectors: RFC examples, NIST CAVP, Wycheproof, multiformats, the Keccak team, the BLS and KZG suites.
  Prefer Wycheproof for cryptography: it targets malleability and edge cases.
- Small vectors sit inline in unit tests; large files download into `testing/vectors`, pinned by version, commit, or checksum.
- A runner fails on a handler or case it does not know, and asserts its exact case count.
  A vector is never skipped silently.
- Missing vectors fail when `AXIOM_REQUIRE_VECTORS` is set, as CI sets it.

Properties and coverage:

- Property tests with `proptest` for every law: round-trips, reference equality, determinism, algebraic identities.
- Every specialized path is pinned equal to its reference by a property test.
- Cover every scenario exactly once: boundaries such as zero, one, p-1, empty, and max; success and failure paths; each branch.
  A duplicate test costs readability and adds no coverage.
- Assert whole values and complete errors, never one field or a substring.
- Test the invariant, not an incidental outcome that could legitimately change.
- A test that would pass with the logic broken is worse than none.
  Check new tests by breaking the code once.

Tests have no header doc.
Their bodies are narrated line by line with concrete numbers.

## Version control

- Commit in coherent steps. A commit message says what changed and why, in plain prose.
- Pull requests are squash-merged, so `main` reads as one commit per change.
- Run only the impacted tests locally; CI runs the full suite.

## Commands

```sh
cargo build --workspace
make -C testing/ef-tests            # download every reference vector set
cargo test --workspace --release
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo deny check
```

## Definition of done

- [ ] The primary source was read, and the code cites it.
- [ ] The API is minimal, reads like `std`, and reuses existing abstractions.
- [ ] Forks follow the fork rules: one dispatch, no fork comparisons in shared code.
- [ ] No new dependency, or one justified in the commit and the manifest.
- [ ] Identities, bounds, guarantees, and adversaries are stated where they matter.
- [ ] Fast paths have a reference, a property test, and a before/after benchmark.
- [ ] Vectors, properties, and every scenario are tested once, with whole values asserted.
- [ ] Docs follow the four hard rules, with no ASCII art and no names in prose.
- [ ] Format, clippy, docs, and the impacted tests ran, and the result is reported plainly.
