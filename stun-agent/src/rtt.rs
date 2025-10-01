use std::{cmp, time::Duration};

use log::trace;

const K: u32 = 4;
const ALPHA: f32 = 0.125; // (1/8);
const BETA: f32 = 0.25; // (1/4)

pub const DEFAULT_GRANULARITY: Duration = Duration::from_millis(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttCalcuator {
    rto: Duration,
    srtt: Duration,
    rttvar: Duration,
    granularity: Duration,
    configured_rto: Duration,
}

impl RttCalcuator {
    // Creates a new `RttCalcuator`
    // # Arguments
    // * `rto` - The initial retransmission timeout value
    // * `granularity` - The granularity of the RTT calculation
    // # Returns
    // A new `RttCalcuator` instance
    pub fn new(rto: Duration, granularity: Duration) -> Self {
        Self {
            srtt: Duration::default(),
            rttvar: Duration::default(),
            rto,
            granularity,
            configured_rto: rto,
        }
    }

    // Resets the RTT calculation. This should be called when current
    // value should be considered stale and discarded
    pub fn reset(&mut self) {
        self.srtt = Duration::default();
        self.rttvar = Duration::default();
        self.rto = self.configured_rto;
    }

    // Updates the RTT calculation
    // # Arguments
    // * `r` - The round trip time
    pub fn update(&mut self, r: Duration) {
        if self.srtt == Duration::default() {
            // First RTT measurement
            self.srtt = r;
            self.rttvar = r / 2;
            self.rto = self.srtt + cmp::max(self.granularity, self.rttvar * K);
            trace!(
                "First RTT measurement: srtt={}ms, rttvar={}ms, rto={}ms",
                self.srtt.as_millis(),
                self.rttvar.as_millis(),
                self.rto.as_millis()
            );
        } else {
            // Subsequent RTT measurements
            self.rttvar = self.rttvar.mul_f32(1.0 - BETA) + self.srtt.abs_diff(r).mul_f32(BETA);
            self.srtt = self.srtt.mul_f32(1.0 - ALPHA) + r.mul_f32(ALPHA);
            self.rto = self.srtt + cmp::max(self.granularity, self.rttvar.mul_f32(K as f32));
            trace!(
                "Subsequent RTT measurements: srtt={}ms, rttvar={}ms, rto={}ms",
                self.srtt.as_millis(),
                self.rttvar.as_millis(),
                self.rto.as_millis()
            );
        }
    }

    // Returns the current retransmission timeout value
    // # Returns
    // The current retransmission timeout value
    pub fn rto(&self) -> Duration {
        self.rto
    }
}

#[cfg(test)]
mod rtt_calculator_tests {
    use super::*;

    fn init_logging() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_rtt_calculator_stun() {
        init_logging();

        let rto = Duration::from_millis(500);
        let granularity = Duration::from_millis(1);
        let mut rtt = RttCalcuator::new(rto, granularity);

        rtt.update(Duration::from_millis(100));
        // First RTT measurement
        // srtt = 100ms
        // rttvar = 50ms
        // rto = 100 + max(1ms, 50ms * 4) = 300ms
        assert_eq!(
            rtt.rto().as_millis(),
            Duration::from_millis(300).as_millis()
        );

        rtt.update(Duration::from_millis(200));
        // Subsequent RTT measurements
        // rttvar = 50 * (1 - 0.25) + abs(100 - 200) * 0.25 = 62.5ms
        // srtt = 100 * (1 - 0.125) + 200 * 0.125 = 112.5ms
        // rto = 112.5 + max(1, 62 * 4) = 362.5ms
        assert_eq!(
            rtt.rto().as_millis(),
            Duration::from_millis(362).as_millis()
        );

        rtt.update(Duration::from_millis(300));
        // rttvar = 62.5 * (1 - 0.25) + abs(112.5 - 300) * 0.25 = 93.75ms
        // srtt = 112.5 * (1 - 0.125) + 300 * 0.125 = 135.94ms
        // rto = 135.94 + max(1, 93.75 * 4) = 510.94ms
        assert_eq!(
            rtt.rto().as_millis(),
            Duration::from_millis(510).as_millis()
        );
    }

    #[test]
    fn test_rtt_calculator_stun_granularity() {
        init_logging();

        let rto = Duration::from_millis(500);
        let granularity = Duration::from_millis(1);
        let mut rtt = RttCalcuator::new(rto, granularity);

        // Set a very lower update in terms of nanoseconds,
        // the RTT should not be lower than the granularity
        rtt.update(Duration::from_nanos(10));
        // First RTT measurement can not be lower than the granularity
        assert_eq!(rtt.rto().as_millis(), granularity.as_millis());

        let rto = Duration::from_millis(500);
        let granularity = Duration::from_millis(1);
        let mut rtt = RttCalcuator::new(rto, granularity);

        rtt.update(Duration::from_millis(25));
        // First RTT measurement should set rtto to 75ms
        assert_eq!(rtt.rto().as_millis(), Duration::from_millis(75).as_millis());

        // Check that the RTT can not be lower than the granularity
        for _i in 0..50 {
            rtt.update(Duration::from_nanos(1));
        }
        assert_eq!(rtt.rto().as_millis(), granularity.as_millis());
    }
}
