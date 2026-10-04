//! Boot configuration, read once from the environment and validated before the
//! listener is bound. Every failure is fatal: there is no arm that degrades
//! into serving without a node, without a read key, or without a rate limit.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::http::HeaderName;
use reqwest::Url;

/// The node's read credential. It is sent to the node in one header and goes
/// nowhere else: no `Display`, a redacting `Debug`, and no accessor other than
/// the one the upstream client uses to build that header.
#[derive(Clone)]
pub struct ReadKey(String);

impl ReadKey {
    /// Validate a presented key with the node's own boot rule: at least 32
    /// characters, at least 8 distinct ones, no padding, and visible ASCII only
    /// so it is a legal header value.
    pub fn new(raw: String) -> Result<ReadKey, ConfigError> {
        if raw.is_empty() {
            return Err(ConfigError::Weak("empty"));
        }
        if raw.trim() != raw {
            return Err(ConfigError::Weak("has leading or trailing whitespace"));
        }
        if !raw.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ConfigError::Weak("is not visible ASCII"));
        }
        if raw.len() < 32 {
            return Err(ConfigError::Weak("shorter than 32 characters"));
        }
        let distinct: std::collections::BTreeSet<u8> = raw.bytes().collect();
        if distinct.len() < 8 {
            return Err(ConfigError::Weak("fewer than 8 distinct characters"));
        }
        Ok(ReadKey(raw))
    }

    /// The `Authorization` value for an upstream request.
    pub(crate) fn bearer(&self) -> String {
        format!("Bearer {}", self.0)
    }
}

impl std::fmt::Debug for ReadKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadKey(<redacted>)")
    }
}

/// Everything the gateway needs, from `CC_GATEWAY_*` and `PORT`.
#[derive(Clone, Debug)]
pub struct Config {
    /// The private node's base URL, with no path, query, fragment or userinfo.
    pub node_url: Url,
    pub read_key: ReadKey,
    /// Requests each client may make per minute; a token bucket of this size
    /// refilled continuously.
    pub rate_per_minute: u32,
    /// How long an observed corpus digest is trusted before the gateway asks
    /// the node again. Also the staleness bound after an admit.
    pub freshness: Duration,
    /// When set, the client address is read from this header instead of the
    /// socket peer. Only for deployments where a proxy overwrites it.
    pub client_ip_header: Option<HeaderName>,
    /// Upper bound on cached response bytes, keys included.
    pub cache_bytes: usize,
    /// Largest node response the gateway will read; larger is a 502.
    pub max_body_bytes: usize,
    pub upstream_timeout: Duration,
    pub bind: SocketAddr,
}

/// Defaults, stated once.
pub const DEFAULT_RATE_PER_MINUTE: u32 = 60;
pub const DEFAULT_FRESHNESS_MS: u64 = 1_000;
pub const DEFAULT_CACHE_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_PORT: u16 = 8080;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Absent(&'static str),
    #[error("CC_GATEWAY_READ_KEY is not fit to use: {0}")]
    Weak(&'static str),
    #[error("CC_GATEWAY_NODE_URL must be an http(s) origin with no path, query, fragment or credentials")]
    NodeUrl,
    #[error("{name} must be a decimal integer in {min}..={max}")]
    Range {
        name: &'static str,
        min: u64,
        max: u64,
    },
    #[error("CC_GATEWAY_CLIENT_IP_HEADER is not a valid header name")]
    Header,
}

impl Config {
    pub fn from_env() -> Result<Config, ConfigError> {
        Config::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let raw_url =
            get("CC_GATEWAY_NODE_URL").ok_or(ConfigError::Absent("CC_GATEWAY_NODE_URL"))?;
        let node_url = node_url(&raw_url)?;
        let read_key = ReadKey::new(
            get("CC_GATEWAY_READ_KEY").ok_or(ConfigError::Absent("CC_GATEWAY_READ_KEY"))?,
        )?;
        let num = |name: &'static str, default: u64, min: u64, max: u64| match get(name) {
            None => Ok(default),
            Some(s) => s
                .parse::<u64>()
                .ok()
                .filter(|n| n.to_string() == s && (min..=max).contains(n))
                .ok_or(ConfigError::Range { name, min, max }),
        };
        let rate_per_minute = num(
            "CC_GATEWAY_RATE_PER_MINUTE",
            DEFAULT_RATE_PER_MINUTE.into(),
            1,
            100_000,
        )? as u32;
        let freshness = Duration::from_millis(num(
            "CC_GATEWAY_FRESHNESS_MS",
            DEFAULT_FRESHNESS_MS,
            0,
            60_000,
        )?);
        let cache_bytes = num(
            "CC_GATEWAY_CACHE_BYTES",
            DEFAULT_CACHE_BYTES as u64,
            0,
            1 << 32,
        )? as usize;
        let max_body_bytes = num(
            "CC_GATEWAY_MAX_BODY_BYTES",
            DEFAULT_MAX_BODY_BYTES as u64,
            1024,
            1 << 30,
        )? as usize;
        let upstream_timeout = Duration::from_millis(num(
            "CC_GATEWAY_UPSTREAM_TIMEOUT_MS",
            DEFAULT_UPSTREAM_TIMEOUT_MS,
            100,
            120_000,
        )?);
        let port = num("PORT", DEFAULT_PORT.into(), 1, 65_535)? as u16;
        let client_ip_header = match get("CC_GATEWAY_CLIENT_IP_HEADER") {
            None => None,
            Some(h) => Some(HeaderName::from_bytes(h.as_bytes()).map_err(|_| ConfigError::Header)?),
        };
        Ok(Config {
            node_url,
            read_key,
            rate_per_minute,
            freshness,
            client_ip_header,
            cache_bytes,
            max_body_bytes,
            upstream_timeout,
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        })
    }
}

/// An origin only. Paths are the gateway's to build, from a fixed list.
fn node_url(raw: &str) -> Result<Url, ConfigError> {
    let url = Url::parse(raw).map_err(|_| ConfigError::NodeUrl)?;
    let origin_only = matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none();
    if origin_only {
        Ok(url)
    } else {
        Err(ConfigError::NodeUrl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf";

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn defaults_apply_and_the_key_is_redacted() {
        let c = Config::from_lookup(env(&[
            ("CC_GATEWAY_NODE_URL", "http://node.internal:8080"),
            ("CC_GATEWAY_READ_KEY", KEY),
        ]))
        .unwrap();
        assert_eq!(c.rate_per_minute, 60);
        assert_eq!(c.freshness, Duration::from_millis(1_000));
        assert_eq!(c.bind.port(), 8080);
        assert!(c.client_ip_header.is_none());
        let debug = format!("{c:?}");
        assert!(!debug.contains(KEY), "{debug}");
        assert!(debug.contains("ReadKey(<redacted>)"), "{debug}");
    }

    #[test]
    fn missing_or_weak_keys_and_bad_urls_refuse_to_boot() {
        let url = ("CC_GATEWAY_NODE_URL", "http://node.internal:8080");
        assert!(matches!(
            Config::from_lookup(env(&[url])),
            Err(ConfigError::Absent("CC_GATEWAY_READ_KEY"))
        ));
        for weak in [
            "short",
            &format!(" {KEY}"),
            &"ab".repeat(20),
            "x y z 1 2 3 4 5 6 7 8 9 a b c d e f",
        ] {
            let r = Config::from_lookup(env(&[url, ("CC_GATEWAY_READ_KEY", weak)]));
            assert!(matches!(r, Err(ConfigError::Weak(_))), "{weak:?}");
        }
        for bad in [
            "node.internal:8080",
            "ftp://node.internal",
            "http://user:pw@node.internal",
            "http://node.internal/v1",
            "http://node.internal/?a=b",
        ] {
            let r = Config::from_lookup(env(&[
                ("CC_GATEWAY_NODE_URL", bad),
                ("CC_GATEWAY_READ_KEY", KEY),
            ]));
            assert!(matches!(r, Err(ConfigError::NodeUrl)), "{bad}");
        }
    }

    #[test]
    fn numeric_settings_are_canonical_and_bounded() {
        let base = [
            ("CC_GATEWAY_NODE_URL", "http://node.internal"),
            ("CC_GATEWAY_READ_KEY", KEY),
        ];
        for bad in ["0", "-1", "060", "1e3", "100001", ""] {
            let mut pairs = base.to_vec();
            pairs.push(("CC_GATEWAY_RATE_PER_MINUTE", bad));
            let r = Config::from_lookup(env(&pairs));
            assert!(matches!(r, Err(ConfigError::Range { .. })), "{bad:?}");
        }
        let mut pairs = base.to_vec();
        pairs.push(("CC_GATEWAY_RATE_PER_MINUTE", "5"));
        pairs.push(("CC_GATEWAY_CLIENT_IP_HEADER", "fly-client-ip"));
        let c = Config::from_lookup(env(&pairs)).unwrap();
        assert_eq!(c.rate_per_minute, 5);
        assert_eq!(c.client_ip_header.unwrap().as_str(), "fly-client-ip");
    }
}
