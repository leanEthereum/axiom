# Axiom

An Ethereum consensus client in Rust, written to be read.

Axiom implements the beacon chain at Fulu, the fork live on mainnet.
It passes the full [consensus-specs](https://github.com/ethereum/consensus-specs) test suite for the `mainnet` and `minimal` presets.

It owns its whole stack.
SSZ, BLS12-381, KZG, secp256k1, Noise, libp2p, gossipsub, discv5, the database, HTTP, JSON, and the metrics are all written here.
The only external crates are `sha2`, `tokio`, `tracing`, and `proptest` for tests.

> [!WARNING]
> Axiom is research software. It is not audited and must not secure real value.

## What it does

- **Consensus.** The Fulu state transition, LMD-GHOST and Casper FFG fork choice, the fast confirmation rule, optimistic sync, and light client updates.
- **Data availability.** PeerDAS custody, column sidecar checks, and KZG cell proofs with FK20.
- **Networking.** libp2p over TCP with Noise and yamux, gossipsub v1.2 with peer scoring, every Fulu gossip rule, req/resp, status handshakes, and range sync of blocks with their custody columns.
- **Discovery.** discv5 with a signed record carrying the fork, attestation subnets, and custody group count.
- **Publishing.** Proposed blocks are checked, split into their 128 column sidecars, gossiped, and imported.
- **Execution.** The engine API with JWT authentication; without an engine the node follows the chain optimistically.
- **Interfaces.** A beacon API subset, Prometheus metrics, and structured logs in compact, pretty, or JSON form.

## Getting started

The toolchain is pinned in `rust-toolchain.toml` and installed by `rustup` on first use.

```sh
git clone https://github.com/leanEthereum/axiom
cd axiom
cargo build --release
./target/release/axiom --help
```

A node needs a genesis state, a trusted checkpoint, or a database it already wrote:

```sh
./target/release/axiom \
    --network minimal \
    --genesis-state genesis.ssz \
    --datadir data \
    --metrics-address 127.0.0.1:5054 \
    --enr-address 203.0.113.7 \
    --boot-enr enr:-IS4Q...
```

To start from a checkpoint instead, pass `--checkpoint-state` and `--checkpoint-block`, the block's SSZ post-state and the SSZ signed block.

## Repository layout

```text
bin/axiom/              the command line
crates/
  ssz, yaml, snappy,    encodings
  json, rlp
  bls12-381, bls, kzg,  cryptography
  crypto
  types                 presets, configuration, and every container
  state-transition      slots, blocks, and epochs
  fork-choice           the store, its handlers, and the head
  das, gossip,          data availability, gossip rules, light clients
  light-client
  store, http,          the database, HTTP, and the engine API
  execution
  p2p, discv5           libp2p, Noise, gossipsub, req/resp, and discovery
  telemetry             logs and Prometheus metrics
  node                  the chain thread and the services around it
testing/ef-tests/       the consensus spec test runner
```

Pure crates never read a clock, open a socket, or touch a disk.
`AGENTS.md` holds the engineering, documentation, and testing standards, for humans and agents alike.
`CLAUDE.md` imports it, so Claude Code reads the same rules.

## Testing

The spec vectors are downloaded once into `testing/vectors`:

```sh
make -C testing/ef-tests
cargo test --workspace --release
```

The suite covers SSZ, operations, epoch processing, sanity, finality, rewards, forks, shuffling, fork choice, fast confirmation, optimistic sync, networking and gossip, merkle proofs, and light clients.
The same fork choice vectors also run through the node's chain with a real database.
End-to-end tests boot whole nodes from a spec genesis or a checkpoint, publish blocks over HTTP, sync a second node over Noise, and find peers through discv5.

CI runs:

```sh
cargo +nightly fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --release
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
