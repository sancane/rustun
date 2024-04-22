use log::debug;
use std::cmp::Ordering;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};
use stun_rs::TransactionId;

#[derive(Debug, Eq)]
struct TimeoutItem {
    instant: Instant,
    timeout: Duration,
    transaction_id: TransactionId,
}

impl Ord for TimeoutItem {
    fn cmp(&self, other: &Self) -> Ordering {
        let expires = self.instant + self.timeout;
        let other_expires = other.instant + other.timeout;
        expires.cmp(&other_expires)
    }
}

impl PartialOrd for TimeoutItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TimeoutItem {
    fn eq(&self, other: &Self) -> bool {
        let expires = self.instant + self.timeout;
        let other_expires = other.instant + other.timeout;
        expires == other_expires
    }
}

#[derive(Debug, Default)]
pub struct StunMessageTimeout {
    timeouts: BinaryHeap<Reverse<TimeoutItem>>,
}

impl StunMessageTimeout {
    pub fn add(&mut self, instant: Instant, timeout: Duration, transaction_id: TransactionId) {
        self.timeouts.push(Reverse(TimeoutItem {
            instant,
            timeout,
            transaction_id,
        }));
    }

    pub fn remove(&mut self, transaction_id: &TransactionId) {
        self.timeouts
            .retain(|item| &item.0.transaction_id != transaction_id);
    }

    pub fn next_timeout(&mut self, instant: Instant) -> Option<(TransactionId, Duration)> {
        if let Some(item) = self.timeouts.peek() {
            let expires = item.0.instant + item.0.timeout;
            if expires > instant {
                return Some((item.0.transaction_id, expires - instant));
            } else {
                return Some((item.0.transaction_id, Duration::from_secs(0)));
            }
        }
        None
    }

    pub fn check(&mut self, instant: Instant) -> Vec<TransactionId> {
        let mut expired = Vec::new();
        while let Some(item) = self.timeouts.peek() {
            if item.0.instant + item.0.timeout <= instant {
                expired.push(item.0.transaction_id);
                self.timeouts.pop();
            } else {
                break;
            }
        }
        expired
    }
}

pub const DEFAULT_RTO: u16 = 500;
pub const DEFAULT_RC: u16 = 7;
pub const DEFAULT_RM: u16 = 16;

#[derive(Debug)]
pub struct TimeoutCalculator {
    rtt: u16,
    rm: u16,
    rc: u16,
    last_rm: u16,
}

impl Default for TimeoutCalculator {
    fn default() -> Self {
        Self {
            rtt: DEFAULT_RTO,
            rm: 1,
            rc: DEFAULT_RC,
            last_rm: DEFAULT_RM,
        }
    }
}

impl TimeoutCalculator {
    pub fn new(rtt: u16, rm: u16, rc: u16) -> Self {
        Self {
            rtt,
            rm: 1,
            rc,
            last_rm: rm,
        }
    }

    pub fn next_rto(&mut self) -> Option<Duration> {
        if self.rc == 0 {
            return None;
        }

        let ms = if self.rc == 1 {
            self.rtt * self.last_rm
        } else {
            self.rtt * self.rm
        };

        self.rm *= 2;
        self.rc -= 1;

        Some(Duration::from_millis(ms as u64))
    }
}

#[derive(Debug, Default)]
pub struct TimeoutManager {
    latest: Option<Instant>,
    last_rto: Duration,
    calculator: TimeoutCalculator,
}

impl TimeoutManager {
    pub fn new(rtt: u16, rm: u16, rc: u16) -> Self {
        Self {
            latest: None,
            last_rto: Duration::default(),
            calculator: TimeoutCalculator::new(rtt, rm, rc),
        }
    }

    pub fn next_rto(&mut self, instant: Instant) -> Option<Duration> {
        if let Some(latest) = self.latest {
            let next_timeout = latest + self.last_rto;
            if instant >= next_timeout {
                let mut next_timeout = latest + self.last_rto;
                // Skip next rto until the timeout is greater than the current instant
                while let Some(timeout) = self.calculator.next_rto() {
                    next_timeout += timeout;
                    if next_timeout > instant {
                        self.last_rto = next_timeout - instant;
                        self.latest = Some(instant);
                        return Some(self.last_rto);
                    }
                }
                // No more timeouts
                return None;
            } else {
                self.last_rto = next_timeout - instant;
            }
        } else {
            match self.calculator.next_rto() {
                Some(timeout) => {
                    self.last_rto = timeout;
                }
                None => {
                    debug!("No more timeouts");
                    return None;
                }
            }
        }
        self.latest = Some(instant);
        Some(self.last_rto)
    }
}

#[cfg(test)]
mod tests_stun_msg_timout {
    use super::*;

    #[test]
    fn test_timeout_one() {
        let mut timeout = StunMessageTimeout::default();
        let id_1 = TransactionId::from([1; 12]);

        let now = Instant::now();
        timeout.add(now, Duration::from_millis(50), id_1);

        let expired = timeout.check(now + Duration::from_millis(1000));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_1);

        let expired = timeout.check(now + Duration::from_millis(1000));
        assert_eq!(expired.len(), 0);
    }

    #[test]
    fn test_timeout_all() {
        let mut timeout = StunMessageTimeout::default();
        let id_1 = TransactionId::from([1; 12]);
        let id_2 = TransactionId::from([2; 12]);
        let id_3 = TransactionId::from([3; 12]);

        let now = Instant::now();

        timeout.add(now, Duration::from_millis(50), id_1);
        timeout.add(now, Duration::from_millis(10), id_2);
        timeout.add(now, Duration::from_millis(5), id_3);

        let expired = timeout.check(now + Duration::from_millis(1000));
        assert_eq!(expired.len(), 3);
        assert_eq!(expired[0], id_3);
        assert_eq!(expired[1], id_2);
        assert_eq!(expired[2], id_1);

        let expired = timeout.check(now + Duration::from_millis(1000));
        assert_eq!(expired.len(), 0);
    }

    #[test]
    fn test_timeout_all_scalated() {
        let mut timeout = StunMessageTimeout::default();
        let id_1 = TransactionId::from([1; 12]);
        let id_2 = TransactionId::from([2; 12]);
        let id_3 = TransactionId::from([3; 12]);

        let i1 = Instant::now();
        let i2 = i1 + Duration::from_millis(5);
        let i3 = i2 + Duration::from_millis(5);

        timeout.add(i1, Duration::from_millis(25), id_1);
        timeout.add(i2, Duration::from_millis(5), id_2);
        timeout.add(i3, Duration::from_millis(10), id_3);

        let expired = timeout.check(i1 + Duration::from_millis(1000));
        assert_eq!(expired.len(), 3);
        assert_eq!(expired[0], id_2);
        assert_eq!(expired[1], id_3);
        assert_eq!(expired[2], id_1);

        let i4 = i3 + Duration::from_millis(1000);
        let expired = timeout.check(i4 + Duration::from_millis(10));
        assert_eq!(expired.len(), 0);
    }

    #[test]
    fn test_timeout_partial() {
        let mut timeout = StunMessageTimeout::default();
        let id_1 = TransactionId::from([1; 12]);
        let id_2 = TransactionId::from([2; 12]);
        let id_3 = TransactionId::from([3; 12]);

        let i1 = Instant::now();
        let i2 = i1 + Duration::from_millis(5);
        let i3 = i2 + Duration::from_millis(5);

        timeout.add(i1, Duration::from_millis(5), id_1); // 5 ms
        timeout.add(i2, Duration::from_millis(5), id_2); // 10 ms
        timeout.add(i3, Duration::from_millis(5), id_3); // 15 ms

        // in 4 ms nothing should expire
        let mut t = i1 + Duration::from_millis(4);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 0);

        // in 5 ms id_1 should expire
        t += Duration::from_millis(1);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_1);

        // in 9 ms nothing should expire
        t += Duration::from_millis(4);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 0);

        // in 10 ms id_2 should expire
        t += Duration::from_millis(1);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_2);

        // in 14 ms nothing should expire
        t += Duration::from_millis(4);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 0);

        // in 15 ms id_3 should expire
        t += Duration::from_millis(1);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_3);

        // in 1000 ms nothing should expire
        t += Duration::from_millis(1000);
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 0);
    }

    #[test]
    fn test_timeout_partial_adding_timeouts() {
        let mut timeout = StunMessageTimeout::default();
        let id_1 = TransactionId::from([1; 12]);
        let id_2 = TransactionId::from([2; 12]);
        let id_3 = TransactionId::from([3; 12]);
        let id_4 = TransactionId::from([3; 12]);

        let i1 = Instant::now();
        let i2 = i1 + Duration::from_millis(5);
        let i3 = i2 + Duration::from_millis(5);
        let i4 = i3 + Duration::from_millis(5);

        timeout.add(i1, Duration::from_millis(5), id_1); // 5 ms
        timeout.add(i2, Duration::from_millis(5), id_2); // 10 ms
        timeout.add(i3, Duration::from_millis(5), id_3); // 15 ms

        // in 5 ms id_1 should expire
        let mut t = i1 + Duration::from_millis(6); // 6ms
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_1);

        // Add a new timeout that must be added at the end
        timeout.add(i4, Duration::from_millis(5), id_4); // 20 ms

        t += Duration::from_millis(9); // 15ms
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 2);
        assert_eq!(expired[0], id_2);
        assert_eq!(expired[1], id_3);

        // only id_4 is in the queue
        // Add id_1 again with a timeout that must be added at the beginning
        let i = t + Duration::from_millis(2); // 17ms
        timeout.add(i, Duration::from_millis(2), id_1); // expires in the ms 19

        // Make the first timeout expired, it should be id_1 again
        t += Duration::from_millis(4); // 19ms
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_1);

        // Make the id_4 expire
        t += Duration::from_millis(1); // 20ms
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id_4);

        // No more timeouts must be expired
        // Make the id_4 expire
        t += Duration::from_millis(100); // 120ms
        let expired = timeout.check(t);
        assert_eq!(expired.len(), 0);
    }
}

#[cfg(test)]
mod tests_timout_controller {
    use super::*;

    #[test]
    fn test_timeout_calculator() {
        let mut calculator = TimeoutCalculator::default();
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(500)));
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(1000)));
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(2000)));
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(4000)));
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(8000)));
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(16000)));
        assert_eq!(calculator.next_rto(), Some(Duration::from_millis(8000)));
        assert_eq!(calculator.next_rto(), None);

        // No more rto must be provided
        assert_eq!(calculator.next_rto(), None);
    }
}

#[cfg(test)]
mod tests_timout_manager {
    use super::*;

    #[test]
    fn test_timeout_manager_on_time() {
        let mut manager = TimeoutManager::default();
        let mut instant = Instant::now();
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(500));

        // Advance 500 ms to cause a timeout
        instant += rto;
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(1000));

        // Advance 1000 ms to cause a timeout
        instant += rto;
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(2000));

        // Advance 2000 ms to cause a timeout
        instant += rto;
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(4000));

        // Advance 4000 ms to cause a timeout
        instant += rto;
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(8000));

        // Advance 8000 ms to cause a timeout
        instant += rto;
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(16000));

        // Advance 16000 ms to cause a timeout
        instant += rto;
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(8000));

        // Advance 8000 to check that no more rto will be calculated
        instant += rto;
        assert!(manager.next_rto(instant).is_none());

        // No matter how much time has passed, no more rto will be calculated
        instant += rto;
        assert!(manager.next_rto(instant).is_none());
    }

    #[test]
    fn test_timeout_manager_adjusted() {
        let mut manager = TimeoutManager::default();
        let mut instant = Instant::now();
        // [time: 0 ms] First timeout is 500 ms
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(500));

        instant += Duration::from_millis(400);
        // [time: 400 ms]. Call a bit sooner than the timeout
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(100));

        instant += Duration::from_millis(80);
        // [time: 480 ms] Call before timeout expired
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(20));

        instant += Duration::from_millis(21);
        // [time: 501 ms] Call 1 millisecond later than the timeout
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(999));

        instant += Duration::from_millis(499);
        // [time: 1000 ms] Next timeout is in 999 ms, call 499 ms before it expired
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(500));

        // If we call a second later, the timeout will have expired by 500 ms,
        // the next rto would 2000 ms, but we are over the 500 ms, so the next
        // rto will be 1500 ms
        instant += Duration::from_millis(1000);
        // [time: 2000 ms] Next timout is in 1500 ms
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(1500));

        instant += Duration::from_millis(13400);
        // [time: 15400 ms] next timeout is in 100 ms
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(100));
    }

    #[test]
    fn test_timeout_delayed_with_timeout() {
        let mut manager = TimeoutManager::default();
        let mut instant = Instant::now();
        // [time: 0 ms] First timeout is 500 ms
        let rto = manager.next_rto(instant).expect("Expected a timeout");
        assert_eq!(rto, Duration::from_millis(500));

        instant += Duration::from_millis(39500);
        // Timed out, no more rto will be calculated
        assert!(manager.next_rto(instant).is_none());
    }
}
