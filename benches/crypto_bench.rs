//! Criterion benchmarks for the crypto hot paths: per-frame AEAD and the
//! handshake (classical vs ML-KEM hybrid).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use freespoof::config::{AeadKind, PqLevel};
use freespoof::crypto::aead::DataCipher;
use freespoof::crypto::handshake::{HandshakeParams, Initiator, Responder};

fn bench_aead(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let aad = [0u8; 20];
    let mut group = c.benchmark_group("aead_seal_1400");
    group.throughput(Throughput::Bytes(1400));
    for (name, kind) in [
        ("chacha20poly1305", AeadKind::Chacha20Poly1305),
        ("aes256gcm", AeadKind::Aes256Gcm),
    ] {
        let cipher = DataCipher::new(kind, &key);
        group.bench_function(name, |b| {
            let mut ctr = 0u64;
            b.iter(|| {
                let mut buf = vec![0u8; 1400];
                ctr += 1;
                cipher.seal(ctr, black_box(&aad), &mut buf).unwrap();
                black_box(&buf);
            })
        });
    }
    group.finish();
}

fn keypair() -> ([u8; 32], [u8; 32]) {
    let kp = freespoof::crypto::generate_static_keypair().unwrap();
    (
        freespoof::crypto::decode_key_b64(&kp.private_b64, "p").unwrap(),
        freespoof::crypto::decode_key_b64(&kp.public_b64, "P").unwrap(),
    )
}

fn bench_handshake(c: &mut Criterion) {
    let (c_priv, c_pub) = keypair();
    let (s_priv, s_pub) = keypair();
    let mk = |local, peer, pq| HandshakeParams {
        local_private: local,
        peer_public: peer,
        psk: None,
        pq_hybrid: pq,
        pq_level: PqLevel::MlKem768,
        aead: AeadKind::Chacha20Poly1305,
        local_version: 1,
        allowed_peers: vec![],
    };

    let mut group = c.benchmark_group("handshake");
    for (name, pq) in [("classical", false), ("ml_kem_hybrid", true)] {
        group.bench_function(name, |b| {
            b.iter(|| {
                let (initiator, msg1) = Initiator::start(mk(c_priv, s_pub, pq)).unwrap();
                let responder = Responder::start(mk(s_priv, c_pub, pq)).unwrap();
                let (msg2, _s) = responder.respond(&msg1).unwrap();
                let _c = initiator.finish(&msg2).unwrap();
                black_box(msg2);
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_aead, bench_handshake);
criterion_main!(benches);
