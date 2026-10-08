//! Adaptive FEC redundancy controller.
//!
//! Tracks the loss rate with an exponentially-weighted moving average and
//! recommends a parity-shard count so that, on average, a group still has
//! enough shards to reconstruct. The session periodically reads
//! [`Adaptive::recommended_parity`] and rebuilds the [`super::FecEncoder`] when
//! it changes (both sides carry the counts in the FEC header, so the decoder
//! follows automatically).

/// Loss-driven parity recommendation.
pub struct Adaptive {
    ewma_loss: f64,
    alpha: f64,
    data_shards: usize,
    min_parity: usize,
    max_parity: usize,
}

impl Adaptive {
    /// Create a controller for a given data-shard count and parity bounds.
    pub fn new(data_shards: usize, min_parity: usize, max_parity: usize) -> Adaptive {
        Adaptive {
            ewma_loss: 0.0,
            alpha: 0.2,
            data_shards: data_shards.max(1),
            min_parity: min_parity.max(1),
            max_parity: max_parity.max(min_parity.max(1)),
        }
    }

    /// Feed an observation: `received` of `expected` datagrams arrived.
    pub fn observe(&mut self, received: usize, expected: usize) {
        if expected == 0 {
            return;
        }
        let lost = expected.saturating_sub(received) as f64 / expected as f64;
        self.ewma_loss = self.alpha * lost + (1.0 - self.alpha) * self.ewma_loss;
    }

    /// Current smoothed loss estimate in `[0, 1]`.
    pub fn loss(&self) -> f64 {
        self.ewma_loss
    }

    /// Recommended parity-shard count for the current loss estimate.
    ///
    /// Targets covering the expected number of losses in a group plus a small
    /// safety margin, clamped to the configured `[min, max]` bounds.
    pub fn recommended_parity(&self) -> usize {
        let p = self.ewma_loss.clamp(0.0, 0.95);
        // Expected losses across (data + parity) ≈ p * data / (1 - p); add 1 margin.
        let expected_losses = (p * self.data_shards as f64 / (1.0 - p)).ceil() as usize + 1;
        expected_losses.clamp(self.min_parity, self.max_parity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_loss_uses_min() {
        let mut a = Adaptive::new(8, 1, 6);
        for _ in 0..20 {
            a.observe(10, 10); // no loss
        }
        assert_eq!(a.recommended_parity(), 1);
    }

    #[test]
    fn high_loss_increases_parity() {
        let mut a = Adaptive::new(8, 1, 6);
        for _ in 0..20 {
            a.observe(7, 10); // 30% loss
        }
        assert!(a.recommended_parity() > 1);
        assert!(a.recommended_parity() <= 6);
    }
}
