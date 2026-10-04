//! Per-client rate limit, GCRA (the generic cell rate algorithm, a token
//! bucket stated in exact integer time).
//!
//! Each client may burst to `rate_per_minute` requests and then sustain one per
//! `60 s / rate_per_minute`, never twice the limit across a window boundary.
//!
//! IPv6 clients are keyed by their /64. One subscriber usually holds a whole
//! /64, so keying by full address would let a single client mint 2^64 fresh
//! buckets. IPv4 clients, and IPv4-mapped IPv6 ones, are keyed by full address.
//!
//! The table is bounded. When it is full, idle clients are dropped; if none are
//! idle, a new client is refused rather than admitted unmetered.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Most distinct clients tracked at once.
pub const MAX_TRACKED: usize = 100_000;

pub struct Limiter {
    /// Time one request "costs".
    interval: Duration,
    /// How far ahead of now a client's schedule may run: the burst, less one.
    tolerance: Duration,
    max_tracked: usize,
    /// Per client, the theoretical arrival time of its next request.
    tat: Mutex<HashMap<IpAddr, Instant>>,
}

/// The bucket a client address is metered under.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

impl Limiter {
    pub fn new(rate_per_minute: u32) -> Limiter {
        Limiter::with_capacity(rate_per_minute, MAX_TRACKED)
    }

    pub fn with_capacity(rate_per_minute: u32, max_tracked: usize) -> Limiter {
        let rate = rate_per_minute.max(1);
        let interval = Duration::from_secs(60) / rate;
        Limiter {
            interval,
            tolerance: interval * (rate - 1),
            max_tracked,
            tat: Mutex::new(HashMap::new()),
        }
    }

    /// Admit one request from `ip`, or say how long until one would be.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        self.check_at(ip, Instant::now())
    }

    pub fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        let key = client_key(ip);
        let mut table = self.tat.lock().unwrap_or_else(|p| p.into_inner());
        if !table.contains_key(&key) && table.len() >= self.max_tracked {
            table.retain(|_, tat| *tat > now);
            if table.len() >= self.max_tracked {
                return Err(self.interval);
            }
        }
        let tat = table.get(&key).copied().unwrap_or(now).max(now);
        let ahead = tat - now;
        if ahead > self.tolerance {
            return Err(ahead - self.tolerance);
        }
        table.insert(key, tat + self.interval);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_client_gets_exactly_the_limit_then_waits_for_refill() {
        let l = Limiter::new(3);
        let t = Instant::now();
        for _ in 0..3 {
            assert!(l.check_at(ip("192.0.2.1"), t).is_ok());
        }
        let wait = l.check_at(ip("192.0.2.1"), t).unwrap_err();
        assert_eq!(wait, Duration::from_secs(20));
        // Another client has its own bucket.
        assert!(l.check_at(ip("192.0.2.2"), t).is_ok());
        // One token refills in 20 s at 3/min, and only one.
        let later = t + Duration::from_secs(20);
        assert!(l.check_at(ip("192.0.2.1"), later).is_ok());
        assert!(l.check_at(ip("192.0.2.1"), later).is_err());
    }

    #[test]
    fn ipv6_clients_share_a_bucket_per_slash_64() {
        let l = Limiter::new(1);
        let t = Instant::now();
        assert!(l.check_at(ip("2001:db8:1:2::1"), t).is_ok());
        assert!(l.check_at(ip("2001:db8:1:2:ffff::9"), t).is_err());
        assert!(l.check_at(ip("2001:db8:1:3::1"), t).is_ok());
        assert_eq!(client_key(ip("::ffff:192.0.2.7")), ip("192.0.2.7"));
    }

    #[test]
    fn a_full_table_drops_idle_buckets_and_otherwise_refuses() {
        let l = Limiter::with_capacity(1, 2);
        let t = Instant::now();
        assert!(l.check_at(ip("192.0.2.1"), t).is_ok());
        assert!(l.check_at(ip("192.0.2.2"), t).is_ok());
        // Both clients are active, so a third is refused, not unmetered.
        assert!(l.check_at(ip("192.0.2.3"), t).is_err());
        // Once their schedules have elapsed they are idle and make room.
        let later = t + Duration::from_secs(60);
        assert!(l.check_at(ip("192.0.2.3"), later).is_ok());
    }
}
