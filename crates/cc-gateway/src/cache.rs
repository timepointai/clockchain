//! Response cache keyed by corpus digest.
//!
//! Every v1 read names the `corpus_digest` it was folded from, and a read is a
//! pure function of (rule identity, corpus, request): the rule identity is
//! fixed for the life of a node, so within one corpus digest the same request
//! has the same answer. The cache therefore holds entries for exactly one
//! digest, the most recently observed one, and drops them all the moment a
//! different digest is observed.
//!
//! The gateway cannot see an admit happen. It learns the current digest from
//! every node read it makes and, when that knowledge is older than the
//! configured freshness window, from a probe read. So an admit is visible
//! through the gateway at most one freshness window after it commits; with a
//! window of zero, every request first asks the node for its digest.
//!
//! An observation only replaces a newer one if it was requested later, so a
//! slow response carrying an older digest cannot roll the generation back.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::Bytes;

/// One cached answer: the status the node gave and the stripped body.
#[derive(Clone)]
pub struct Entry {
    pub status: u16,
    pub body: Bytes,
}

pub struct Cache {
    freshness: Duration,
    max_bytes: usize,
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    /// The digest the entries belong to, and when it was requested.
    generation: Option<(String, Instant)>,
    /// Each entry with the tick of its last use.
    entries: HashMap<String, (Entry, u64)>,
    /// Ticks in use order, oldest first, for least-recently-used eviction.
    order: BTreeMap<u64, String>,
    tick: u64,
    bytes: usize,
}

impl Inner {
    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }

    fn touch(&mut self, key: &str) -> u64 {
        self.tick += 1;
        let tick = self.tick;
        if let Some((_, used)) = self.entries.get_mut(key) {
            self.order.remove(used);
            *used = tick;
        }
        self.order.insert(tick, key.to_string());
        tick
    }
}

impl Cache {
    pub fn new(freshness: Duration, max_bytes: usize) -> Cache {
        Cache {
            freshness,
            max_bytes,
            inner: Mutex::new(Inner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The current digest, if it was observed within the freshness window.
    pub fn fresh_digest(&self, now: Instant) -> Option<String> {
        match &self.lock().generation {
            Some((d, at)) if now.saturating_duration_since(*at) < self.freshness => Some(d.clone()),
            _ => None,
        }
    }

    /// Record that a node read requested at `requested` answered `digest`.
    /// A different digest starts a new generation and empties the cache.
    pub fn observe(&self, digest: &str, requested: Instant) {
        let mut inner = self.lock();
        match &inner.generation {
            Some((_, at)) if *at > requested => {}
            Some((d, _)) if d == digest => inner.generation = Some((d.clone(), requested)),
            _ => {
                inner.generation = Some((digest.to_string(), requested));
                inner.clear();
            }
        }
    }

    pub fn get(&self, digest: &str, key: &str) -> Option<Entry> {
        let mut inner = self.lock();
        if !matches!(&inner.generation, Some((d, _)) if d == digest) {
            return None;
        }
        let entry = inner.entries.get(key)?.0.clone();
        inner.touch(key);
        Some(entry)
    }

    /// Keep `entry` only if it was folded from the current generation and fits
    /// the byte bound, evicting the least recently used entries to make room.
    pub fn put(&self, digest: &str, key: &str, entry: Entry) {
        let mut inner = self.lock();
        if !matches!(&inner.generation, Some((d, _)) if d == digest) {
            return;
        }
        let size = key.len() + entry.body.len();
        if inner.entries.contains_key(key) || size > self.max_bytes {
            return;
        }
        while inner.bytes + size > self.max_bytes {
            let Some((_, old)) = inner.order.pop_first() else {
                break;
            };
            if let Some((e, _)) = inner.entries.remove(&old) {
                inner.bytes -= old.len() + e.body.len();
            }
        }
        inner.bytes += size;
        inner.entries.insert(key.to_string(), (entry, 0));
        inner.touch(key);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.lock().entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(s: &str) -> Entry {
        Entry {
            status: 200,
            body: Bytes::from(s.to_string()),
        }
    }

    #[test]
    fn entries_live_only_within_their_digest() {
        let c = Cache::new(Duration::from_secs(5), 1 << 20);
        let t = Instant::now();
        c.observe("d1", t);
        c.put("d1", "/a", entry("one"));
        // An answer folded from another digest is never stored.
        c.put("d2", "/b", entry("two"));
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("d1", "/a").unwrap().body, "one");
        assert!(c.get("d2", "/a").is_none());
        c.observe("d2", t + Duration::from_millis(1));
        assert_eq!(c.len(), 0);
        assert!(c.get("d1", "/a").is_none());
    }

    #[test]
    fn an_older_observation_cannot_roll_the_generation_back() {
        let c = Cache::new(Duration::from_secs(5), 1 << 20);
        let t = Instant::now();
        c.observe("new", t + Duration::from_millis(10));
        c.observe("old", t);
        assert_eq!(
            c.fresh_digest(t + Duration::from_millis(20)).unwrap(),
            "new"
        );
    }

    #[test]
    fn freshness_expires_and_zero_means_always_ask() {
        let t = Instant::now();
        let c = Cache::new(Duration::from_secs(1), 1 << 20);
        c.observe("d", t);
        assert!(c.fresh_digest(t + Duration::from_millis(999)).is_some());
        assert!(c.fresh_digest(t + Duration::from_secs(1)).is_none());
        let z = Cache::new(Duration::ZERO, 1 << 20);
        z.observe("d", t);
        assert!(z.fresh_digest(t).is_none());
    }

    #[test]
    fn the_byte_bound_holds() {
        let c = Cache::new(Duration::from_secs(5), 10);
        let t = Instant::now();
        c.observe("d", t);
        c.put("d", "/a", entry("12345"));
        // Too big to fit even in an empty cache: never stored.
        c.put("d", "/b", entry("1234567890"));
        assert_eq!(c.len(), 1);
        assert!(c.get("d", "/a").is_some());
    }

    #[test]
    fn a_full_cache_evicts_the_least_recently_used_entry() {
        // Each entry is a two-byte key plus a two-byte body: two fit.
        let c = Cache::new(Duration::from_secs(5), 8);
        let t = Instant::now();
        c.observe("d", t);
        c.put("d", "/a", entry("aa"));
        c.put("d", "/b", entry("bb"));
        // Using /a makes /b the least recently used.
        assert!(c.get("d", "/a").is_some());
        c.put("d", "/c", entry("cc"));
        assert_eq!(c.len(), 2);
        assert!(c.get("d", "/b").is_none());
        assert!(c.get("d", "/a").is_some());
        assert!(c.get("d", "/c").is_some());
    }
}
