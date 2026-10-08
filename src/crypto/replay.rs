//! Per-session anti-replay sliding window.
//!
//! Implements the RFC 6479 bitmap algorithm: O(1) per packet, no per-packet
//! allocation, tolerant of reordering within the window, and rejecting
//! replays and stale frames outside it. The window width is configurable
//! (multiple of 64, validated in config).

/// Bits tracked per word.
const BITS_PER_WORD: u64 = 64;

/// A sliding-window replay filter over a monotonic 64-bit counter.
pub struct ReplayWindow {
    /// Bitmap ring of seen counters.
    bitmap: Vec<u64>,
    /// Highest counter accepted so far.
    last: u64,
    /// Number of bits in the window.
    window: u64,
    /// Whether any packet has been accepted yet.
    seeded: bool,
}

impl ReplayWindow {
    /// Create a window of `window_bits` width (rounded up to a multiple of 64).
    pub fn new(window_bits: u32) -> Self {
        let window = (window_bits as u64).max(BITS_PER_WORD);
        let words = (window / BITS_PER_WORD) as usize + 1;
        ReplayWindow {
            bitmap: vec![0u64; words],
            last: 0,
            window,
            seeded: false,
        }
    }

    /// Check whether `counter` is acceptable and, if so, record it.
    ///
    /// Returns `true` if the frame is fresh (accept) and `false` if it is a
    /// replay or too old (drop). Never panics.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        let total_bits = self.bitmap.len() as u64 * BITS_PER_WORD;

        if !self.seeded {
            // First accepted packet seeds the window.
            self.seeded = true;
            self.last = counter;
            let idx = (counter % total_bits) as usize / BITS_PER_WORD as usize;
            let bit = counter % BITS_PER_WORD;
            self.bitmap[idx] = 1u64 << bit;
            return true;
        }

        if counter > self.last {
            // Advance: clear the words we skip over so stale bits don't alias.
            let diff = counter - self.last;
            if diff >= total_bits {
                // Jumped past the whole window: reset the bitmap.
                self.bitmap.fill(0);
            } else {
                let mut i = self.last + 1;
                while i <= counter {
                    let idx = (i % total_bits) as usize / BITS_PER_WORD as usize;
                    if i % BITS_PER_WORD == 0 {
                        self.bitmap[idx] = 0;
                    }
                    i += 1;
                }
            }
            self.last = counter;
            let idx = (counter % total_bits) as usize / BITS_PER_WORD as usize;
            let bit = counter % BITS_PER_WORD;
            self.bitmap[idx] |= 1u64 << bit;
            true
        } else {
            // counter <= last: inside or behind the window.
            let delta = self.last - counter;
            if delta >= self.window {
                return false; // too old
            }
            let idx = (counter % total_bits) as usize / BITS_PER_WORD as usize;
            let bit = counter % BITS_PER_WORD;
            let mask = 1u64 << bit;
            if self.bitmap[idx] & mask != 0 {
                false // replay
            } else {
                self.bitmap[idx] |= mask;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order() {
        let mut w = ReplayWindow::new(128);
        for c in 0..1000 {
            assert!(w.check_and_update(c), "should accept {c}");
        }
    }

    #[test]
    fn rejects_replay() {
        let mut w = ReplayWindow::new(128);
        assert!(w.check_and_update(5));
        assert!(!w.check_and_update(5));
    }

    #[test]
    fn tolerates_reorder_within_window() {
        let mut w = ReplayWindow::new(128);
        assert!(w.check_and_update(10));
        assert!(w.check_and_update(8)); // reordered, still fresh
        assert!(w.check_and_update(9));
        assert!(!w.check_and_update(8)); // now a replay
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new(64);
        assert!(w.check_and_update(1000));
        assert!(!w.check_and_update(1)); // far outside the window
    }

    #[test]
    fn handles_large_jump() {
        let mut w = ReplayWindow::new(128);
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(1_000_000));
        assert!(!w.check_and_update(1)); // old
        assert!(w.check_and_update(1_000_001));
    }
}
