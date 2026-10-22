//! Throughput of compression, decompression, and CRC-32C on real consensus data.
//!
//! Run with `cargo test -p axiom-snappy --release --test throughput -- --ignored --nocapture`.
//!
//! `AXIOM_SNAPPY_CORPUS` may list corpus files, colon-separated, to measure instead of the states.
#![allow(
    clippy::print_stdout,
    reason = "a benchmark reports its figures on stdout"
)]
#![allow(
    clippy::cast_precision_loss,
    reason = "throughput figures need far fewer than 52 bits of precision"
)]

use std::{
    env, fs,
    hint::black_box,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axiom_snappy::{Crc32c, frame, raw};

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

/// Best throughput of a closure over several runs, in MB/s of the given byte count.
fn megabytes_per_second(bytes: usize, mut run: impl FnMut()) -> f64 {
    // Warm up caches and the branch predictor.
    run();
    let mut best = Duration::MAX;
    for _ in 0..10 {
        let start = Instant::now();
        run();
        best = best.min(start.elapsed());
    }
    bytes as f64 / best.as_secs_f64() / 1e6
}

/// Prints ratio and throughput of every path on one corpus.
fn report(name: &str, corpus: &[u8]) {
    let block = raw::compress(corpus);
    let framed = frame::compress(corpus);
    let n = corpus.len();
    println!(
        "{name}: {n} B -> {} B (ratio {:.2})",
        block.len(),
        n as f64 / block.len() as f64
    );

    // Throughput is always measured against the uncompressed size.
    let compress = megabytes_per_second(n, || {
        black_box(raw::compress(black_box(corpus)));
    });
    let decompress = megabytes_per_second(n, || {
        black_box(raw::decompress(black_box(&block), n).expect("block decodes"));
    });
    let frame_compress = megabytes_per_second(n, || {
        black_box(frame::compress(black_box(corpus)));
    });
    let frame_decompress = megabytes_per_second(n, || {
        black_box(frame::decompress(black_box(&framed), n).expect("stream decodes"));
    });
    // Gossip compresses many small messages, where per-call setup dominates.
    //
    // One encoder and one output buffer are reused, as a gossip pipeline would.
    let mut encoder = raw::Encoder::new();
    let mut out = Vec::new();
    let small = megabytes_per_second(n, || {
        for message in corpus.chunks(MESSAGE_LEN) {
            out.clear();
            encoder.compress_into(black_box(message), &mut out);
            black_box(&out);
        }
    });
    // The one-shot form allocates its table and its output per message.
    let small_one_shot = megabytes_per_second(n, || {
        for message in corpus.chunks(MESSAGE_LEN) {
            black_box(raw::compress(black_box(message)));
        }
    });
    let crc = megabytes_per_second(n, || {
        black_box(Crc32c::checksum(black_box(corpus)));
    });
    println!("    raw compress      {compress:>8.0} MB/s");
    println!("    raw decompress    {decompress:>8.0} MB/s");
    println!("    raw compress 512B {small:>8.0} MB/s");
    println!("    one-shot 512B     {small_one_shot:>8.0} MB/s");
    println!("    frame compress    {frame_compress:>8.0} MB/s");
    println!("    frame decompress  {frame_decompress:>8.0} MB/s");
    println!("    crc32c            {crc:>8.0} MB/s");
}

#[test]
#[ignore = "benchmark: run explicitly in release mode"]
fn throughput_on_consensus_data() {
    // Explicit corpus files win over the built-in state corpus.
    if let Some(files) = env::var_os("AXIOM_SNAPPY_CORPUS") {
        for path in env::split_paths(&files) {
            let corpus = fs::read(&path).expect("corpus file is readable");
            report(&path.display().to_string(), &corpus);
        }
        return;
    }
    let Some(root) = vectors_dir() else {
        println!("skipped: no testing/vectors found");
        return;
    };
    report("mainnet states", &state_corpus(&root));
}
