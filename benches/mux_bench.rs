//! Criterion benchmark for multiplexing batch encode/decode throughput.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use freespoof::mux::{decode_batch, encode_batch};

fn bench_mux(c: &mut Criterion) {
    // 20 packets of ~100 bytes per batch.
    let packets: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 100]).collect();
    let refs: Vec<&[u8]> = packets.iter().map(|p| p.as_slice()).collect();

    let mut group = c.benchmark_group("mux_batch_20x100");
    group.throughput(Throughput::Bytes(2000));
    group.bench_function("encode", |b| {
        b.iter(|| {
            let batch = encode_batch(black_box(&refs)).unwrap();
            black_box(batch);
        })
    });
    let batch = encode_batch(&refs).unwrap();
    group.bench_function("decode", |b| {
        b.iter(|| {
            let pkts = decode_batch(black_box(&batch)).unwrap();
            black_box(pkts);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_mux);
criterion_main!(benches);
