//! Criterion benchmarks for FEC encode + reconstruct (XOR and Reed-Solomon).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use freespoof::config::FecMode;
use freespoof::fec::{FecDecoder, FecEncoder};

fn bench_encode(c: &mut Criterion) {
    let shard_len = 1500;
    let mut group = c.benchmark_group("fec_encode_group8");
    group.throughput(Throughput::Bytes((shard_len * 8) as u64));
    for (name, mode, parity) in [
        ("xor", FecMode::Xor, 1),
        ("reed_solomon_p3", FecMode::ReedSolomon, 3),
    ] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let mut enc = FecEncoder::new(mode, 8, parity, shard_len).unwrap();
                let frame = vec![0xABu8; 1200];
                for _ in 0..8 {
                    let out = enc.push(black_box(&frame)).unwrap();
                    black_box(&out.data);
                }
            })
        });
    }
    group.finish();
}

fn bench_recover(c: &mut Criterion) {
    let shard_len = 1500;
    c.bench_function("fec_rs_recover_2loss", |b| {
        b.iter(|| {
            let mut enc = FecEncoder::new(FecMode::ReedSolomon, 8, 3, shard_len).unwrap();
            let mut dec = FecDecoder::new(FecMode::ReedSolomon, 8);
            let mut datagrams = Vec::new();
            for i in 0..8u8 {
                let out = enc.push(&vec![i; 1000]).unwrap();
                datagrams.push(out.data);
                for p in out.parity {
                    datagrams.push(p);
                }
            }
            // Drop two data shards; feed the rest.
            for (i, dg) in datagrams.iter().enumerate() {
                if i == 1 || i == 4 {
                    continue;
                }
                black_box(dec.push(dg).unwrap());
            }
        })
    });
}

criterion_group!(benches, bench_encode, bench_recover);
criterion_main!(benches);
