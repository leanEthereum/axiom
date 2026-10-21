# Axiom

A Rust consensus client for [Lean Ethereum](https://github.com/leanEthereum) research.

Axiom tracks the [leanSpec](https://github.com/leanEthereum/leanSpec) specification. It is built to make protocol ideas cheap to try: modular, readable, and tested, with correctness ahead of production hardening.

> [!WARNING]
> Axiom is research software under active development. It is not audited and must not be used to secure real value.

## Getting started

Axiom requires a stable Rust toolchain (MSRV 1.88). The pinned toolchain in `rust-toolchain.toml` is picked up automatically by `rustup`.

```sh
git clone https://github.com/leanEthereum/axiom
cd axiom
cargo run --release
```

## Repository layout

```
bin/axiom/   the client binary
crates/      library crates, one per component
```

## Development

The checks below are the ones CI runs:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
