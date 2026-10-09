#![no_main]
//! Fuzz the raw-packet / frame decode paths — the primary attack surface.
//!
//! None of these parsers may panic, index out of bounds, or over-read on
//! arbitrary input; they must only ever return `Ok`/`Err`. The fuzzer feeds
//! unconstrained bytes into every decoder that touches untrusted wire data.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Wire frame header.
    let _ = freespoof::wire::Header::decode(data);

    // IPv4 parser (never trusts IHL / total-length fields).
    let _ = freespoof::spoof::ipv4::parse(data);

    // Multiplex batch splitter (length-prefixed, bounds-checked).
    let _ = freespoof::mux::decode_batch(data);

    // FEC datagram decoder.
    let mut dec = freespoof::fec::FecDecoder::new(freespoof::config::FecMode::ReedSolomon, 4);
    let _ = dec.push(data);
});
