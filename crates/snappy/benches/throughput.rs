//! Throughput of compression, decompression, and CRC-32C on real consensus data.
//!
//! Run with `cargo bench -p axiom-snappy --bench throughput`.
//!
//! `AXIOM_SNAPPY_CORPUS` may list corpus files, colon-separated, to measure instead of the states.
#![allow(
    clippy::print_stdout,
    reason = "a benchmark reports its corpus and ratio on stdout"
)]
#![allow(
    clippy::cast_precision_loss,
    reason = "a compression ratio needs far fewer than 52 bits of precision"
)]

use std::{
    env, fs,
    hint::black_box,
    path::{Path, PathBuf},
};

use axiom_snappy::{Crc32c, frame, raw};
use criterion::{Criterion, Throughput};

/// Bytes of corpus to gather: a few MiB, the size of a mainnet state's hot parts.
const CORPUS_LEN: usize = 8 << 20;

/// Size of one small message, the order of a gossiped attestation.
const MESSAGE_LEN: usize = 512;

/// Directory of the downloaded vectors, if present.
fn vectors_dir() -> Option<PathBuf> {
    if let Some(dir) = env::var_os("AXIOM_VECTORS") {
        return Some(PathBuf::from(dir));
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .map(|dir| dir.join("testing/vectors"))
        .find(|dir| dir.is_dir())
}

/// Concatenated decompressed SSZ beacon states, the largest objects a client compresses.
fn state_corpus(root: &Path) -> Vec<u8> {
    let mut corpus = Vec::new();
    let mut pending = vec![root.join("consensus-spec-tests/tests/mainnet")];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().is_some_and(|n| n == "pre.ssz_snappy") {
                let compressed = fs::read(&path).expect("vector file is readable");
                let data = raw::decompress(&compressed, 1 << 30).expect("vector decodes");
                corpus.extend_from_slice(&data);
                if corpus.len() >= CORPUS_LEN {
                    corpus.truncate(CORPUS_LEN);
                    return corpus;
                }
            }
        }
    }
    corpus
}

/// Registers every path on one corpus as a group named after it.
fn bench_corpus(criterion: &mut Criterion, name: &str, corpus: &[u8]) {
    let block = raw::compress(corpus);
    let framed = frame::compress(corpus);
    let n = corpus.len();
    println!(
        "{name}: {n} B -> {} B (ratio {:.2})",
        block.len(),
        n as f64 / block.len() as f64
    );

    let mut group = criterion.benchmark_group(name);
    // Throughput is always measured against the uncompressed size.
    group.throughput(Throughput::Bytes(n as u64));

    group.bench_function("raw compress", |b| {
        b.iter(|| raw::compress(black_box(corpus)));
    });
    group.bench_function("raw decompress", |b| {
        b.iter(|| raw::decompress(black_box(&block), n).expect("block decodes"));
    });

    // Gossip compresses many small messages, where per-call setup dominates.
    //
    // One encoder and one output buffer are reused, as a gossip pipeline would.
    let mut encoder = raw::Encoder::new();
    let mut out = Vec::new();
    group.bench_function("raw compress 512B", |b| {
        b.iter(|| {
            for message in corpus.chunks(MESSAGE_LEN) {
                out.clear();
                encoder.compress_into(black_box(message), &mut out);
                black_box(&out);
            }
        });
    });
    // The one-shot form allocates its table and its output per message.
    group.bench_function("one-shot 512B", |b| {
        b.iter(|| {
            for message in corpus.chunks(MESSAGE_LEN) {
                black_box(raw::compress(black_box(message)));
            }
        });
    });

    group.bench_function("frame compress", |b| {
        b.iter(|| frame::compress(black_box(corpus)));
    });
    group.bench_function("frame decompress", |b| {
        b.iter(|| frame::decompress(black_box(&framed), n).expect("stream decodes"));
    });
    group.bench_function("crc32c", |b| {
        b.iter(|| Crc32c::checksum(black_box(corpus)));
    });
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    // Explicit corpus files win over the built-in state corpus.
    if let Some(files) = env::var_os("AXIOM_SNAPPY_CORPUS") {
        for path in env::split_paths(&files) {
            let corpus = fs::read(&path).expect("corpus file is readable");
            bench_corpus(&mut criterion, &path.display().to_string(), &corpus);
        }
    } else if let Some(root) = vectors_dir() {
        bench_corpus(&mut criterion, "mainnet states", &state_corpus(&root));
    } else {
        println!("skipped: no testing/vectors found");
    }

    criterion.final_summary();
}
