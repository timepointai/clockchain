//! Boot configuration. Read once, from named keys only, and **fail closed**.
//!
//! Two rules govern everything here.
//!
//! **Unknown environment variables are ignored by construction.** We read only
//! the keys named below; there is no `deny_unknown` deserializer over the
//! environment. Environments accrete legacy vars across deploys, and a strict
//! loader turns every cleanup into an outage.
//!
//! **Auth is a required field, never an `Option` that silently means "off".**
//! v1's auth stack fell *open* when its token vars were unset — survivable in a
//! cooperative alpha, catastrophic one deploy later. Here a missing, weak or
//! whitespace-padded key is a boot failure with a non-zero exit, so a node that
//! would have served open never reaches the listener at all.

use cc_core::ExhibitId;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// The node's intended posture. Typed and two-state: a freeze is a config flip,
/// not a string compared at a call site.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Posture {
    /// Reads and writes.
    Live,
    /// Reads alive, writes refused with an honest envelope. This is the mode a
    /// facade is put into, and it is boot-frozen so `/health`'s pinned bytes
    /// always describe the posture actually running.
    Frozen,
}

impl Posture {
    /// The wire spelling, used on `/health` and in every refusal body.
    pub fn as_str(self) -> &'static str {
        match self {
            Posture::Live => "live",
            Posture::Frozen => "frozen",
        }
    }

    /// Whether this posture permits the write path to run at all.
    pub fn writes_permitted(self) -> bool {
        matches!(self, Posture::Live)
    }
}

/// The API key, held only as a SHA-256 digest.
///
/// The plaintext is dropped at the end of [`Config::from_env`], so after boot
/// there is nothing in this process to leak into a log line, a panic message or
/// a core dump. `Debug` is hand-written to redact, because the derived one would
/// print the digest — which is not the secret, but is still a credential-shaped
/// artifact nobody needs in a trace.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyDigest([u8; 32]);

impl std::fmt::Debug for KeyDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyDigest(<redacted>)")
    }
}

impl KeyDigest {
    /// Digest a presented credential for comparison.
    pub fn of(presented: &str) -> KeyDigest {
        KeyDigest(Sha256::digest(presented.as_bytes()).into())
    }

    /// Constant-time equality.
    ///
    /// The accumulate-then-compare shape is the point: an early `return false`
    /// on the first differing byte would make the comparison's duration a
    /// function of how much of the key the caller guessed. Comparing digests
    /// rather than raw keys additionally removes any length signal, since both
    /// sides are always 32 bytes.
    pub fn matches(&self, presented: &str) -> bool {
        let got = KeyDigest::of(presented);
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.0[i] ^ got.0[i];
        }
        diff == 0
    }
}

/// Everything read from the environment at boot.
///
/// `Debug` is hand-written (below) because two of these fields are credentials:
/// a derived `Debug` would put the database password into any `tracing` line or
/// panic message that formats the config, which is precisely how a secret ends
/// up in a transcript and turns a rotation into an incident.
#[derive(Clone)]
pub struct Config {
    /// Where to listen. Never touched by `/health`.
    pub bind: SocketAddr,
    /// The projection store. Parsed at boot; **not connected to** at boot, so a
    /// database outage cannot stop the node from answering liveness.
    pub database_url: String,
    pub posture: Posture,
    /// The one credential. There is deliberately no second path.
    pub api_key: KeyDigest,
    /// An optional **read-only** credential.
    ///
    /// Absent by default, and absence means there is no read-only access at all
    /// — not "anyone may read". A node that grew a second credential path
    /// because a variable was unset would be the open read surface
    /// [`ConfigError::AuthAbsent`] exists to prevent.
    ///
    /// It opens every route the full key opens **except the write path**, which
    /// is the whole point: a key that can be handed to a reader without handing
    /// them the ledger.
    pub read_key: Option<KeyDigest>,
    /// Narrower than `read_key`: opens the public gallery feed only.
    pub gallery_key: Option<KeyDigest>,
    /// Opens entity lookup and feasibility only — beta's two routes.
    pub beta_key: Option<KeyDigest>,
    /// The same two routes as `beta_key`, held by telemetry. A separate
    /// credential so either holder can be revoked without the other.
    pub telemetry_key: Option<KeyDigest>,
    /// Optional pin of the founding exhibit's committed hash, published on
    /// `/health` so an auditor can see which corpus this node was seeded from.
    pub genesis_exhibit: Option<ExhibitId>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("bind", &self.bind)
            .field("database_url", &"<redacted>")
            .field("posture", &self.posture)
            .field("api_key", &self.api_key)
            .field("read_key", &self.read_key)
            .field("genesis_exhibit", &self.genesis_exhibit.map(|e| e.to_hex()))
            .finish()
    }
}

/// The shortest key we will boot with.
///
/// 32 characters is roughly 128 bits at base64 density and exactly 128 bits at
/// hex density. The number is a policy choice, stated here rather than buried,
/// and it is a floor on *length* only — [`weak_reason`] carries the rest.
const MIN_KEY_LEN: usize = 32;

/// The minimum number of distinct characters.
///
/// A key of the right length made of one or two repeated characters is a
/// placeholder somebody generated by holding a key down. Eight distinct
/// characters is far below what any real generator produces (a random 32-char
/// hex string has ~16) and far above what a mashed placeholder has.
const MIN_KEY_ALPHABET: usize = 8;

/// Substrings that mark a key as a placeholder somebody meant to replace.
///
/// Matched case-insensitively. These cannot occur in a hex key at all, and the
/// odds of one appearing inside a random base64 key are ~1e-6 — so the check
/// costs essentially nothing and catches the `.env.example` that shipped.
const PLACEHOLDERS: &[&str] = &[
    "changeme",
    "change-me",
    "placeholder",
    "password",
    "secret",
    "example",
    "letmein",
    "your-key",
    "yourkey",
    "test-key",
    "testkey",
    "dev-key",
    "devkey",
    "insecure",
];

impl Config {
    /// Read the named keys, validate, and fail closed on anything missing or
    /// weak. The plaintext key does not outlive this function.
    pub fn from_env() -> Result<Config, ConfigError> {
        // --- auth: required, validated, then digested and dropped ----------
        let raw_key = std::env::var("CC_NODE_API_KEY").map_err(|_| ConfigError::AuthAbsent)?;
        if let Some(reason) = weak_reason(&raw_key) {
            return Err(ConfigError::AuthWeak(reason));
        }
        let api_key = KeyDigest::of(&raw_key);

        // --- optional read-only credential ---------------------------------
        // Held to the same strength bar as the full key: a weak read key is
        // still a credential on a private surface, and "it can only read" is
        // not a reason to accept a guessable one.
        let read_key = match std::env::var("CC_NODE_READ_KEY") {
            Err(_) => None,
            Ok(raw_read) => {
                if let Some(reason) = weak_reason(&raw_read) {
                    return Err(ConfigError::ReadKeyWeak(reason));
                }
                // Refused rather than deduplicated: if the two are the same
                // string, the operator believes they issued a read-only
                // credential and has actually issued a second copy of the
                // write key. Silently accepting that is how a scope becomes
                // decorative.
                if raw_read == raw_key {
                    return Err(ConfigError::ReadKeyEqualsApiKey);
                }
                Some(KeyDigest::of(&raw_read))
            }
        };

        // A third scope, narrower than read: it opens exactly one route.
        // Held to the same strength bar for the same reason — "it can only
        // read one thing" is not a licence to issue a guessable credential —
        // and refused if it duplicates either existing key, because a scope
        // that is a copy of a wider credential is decorative.
        let gallery_key = match std::env::var("CC_NODE_GALLERY_KEY") {
            Err(_) => None,
            Ok(raw_gallery) => {
                if let Some(reason) = weak_reason(&raw_gallery) {
                    return Err(ConfigError::GalleryKeyWeak(reason));
                }
                if raw_gallery == raw_key {
                    return Err(ConfigError::GalleryKeyEqualsApiKey);
                }
                if std::env::var("CC_NODE_READ_KEY").is_ok_and(|r| r == raw_gallery) {
                    return Err(ConfigError::GalleryKeyEqualsReadKey);
                }
                Some(KeyDigest::of(&raw_gallery))
            }
        };

        // A fourth scope: beta's sims read entities and ask feasibility
        // questions. They asked for exactly those two and nothing else, so the
        // credential opens exactly those two — the read key would also hand
        // them /v1/moments and /health/deep, which they did not ask for and
        // should not carry.
        let beta_key = match std::env::var("CC_NODE_BETA_KEY") {
            Err(_) => None,
            Ok(raw_beta) => {
                if let Some(reason) = weak_reason(&raw_beta) {
                    return Err(ConfigError::BetaKeyWeak(reason));
                }
                if raw_beta == raw_key
                    || std::env::var("CC_NODE_READ_KEY").is_ok_and(|r| r == raw_beta)
                    || std::env::var("CC_NODE_GALLERY_KEY").is_ok_and(|g| g == raw_beta)
                {
                    return Err(ConfigError::BetaKeyDuplicatesAnother);
                }
                Some(KeyDigest::of(&raw_beta))
            }
        };

        // A fifth scope, on the SAME two routes as beta's, and deliberately a
        // SEPARATE credential. Telemetry co-owns the TT conformance verdict and
        // needs to poke the live boundary itself. Handing them beta's key would
        // have been one less variable and two lost properties: you could not
        // revoke one consumer without breaking the other, and a leaked key
        // would name nobody. Scope is what a credential opens; identity is who
        // holds it. One credential per holder is what makes either revocable.
        let telemetry_key = match std::env::var("CC_NODE_TELEMETRY_KEY") {
            Err(_) => None,
            Ok(raw_tel) => {
                if let Some(reason) = weak_reason(&raw_tel) {
                    return Err(ConfigError::TelemetryKeyWeak(reason));
                }
                if raw_tel == raw_key
                    || std::env::var("CC_NODE_READ_KEY").is_ok_and(|r| r == raw_tel)
                    || std::env::var("CC_NODE_GALLERY_KEY").is_ok_and(|g| g == raw_tel)
                    || std::env::var("CC_NODE_BETA_KEY").is_ok_and(|b| b == raw_tel)
                {
                    return Err(ConfigError::TelemetryKeyDuplicatesAnother);
                }
                Some(KeyDigest::of(&raw_tel))
            }
        };
        drop(raw_key);

        // --- posture: required, never defaulted ----------------------------
        // No default. The posture is a published claim about intent that a
        // monitor keys its alarms off; defaulting it would put words in an
        // operator's mouth, and defaulting it to `live` would put the *unsafe*
        // words there. An unrecognized value is a refusal, never a fallback.
        let posture = match std::env::var("CC_NODE_POSTURE").as_deref() {
            Ok("live") => Posture::Live,
            Ok("frozen") => Posture::Frozen,
            Ok(other) => return Err(ConfigError::PostureUnrecognized(other.to_string())),
            Err(_) => return Err(ConfigError::PostureAbsent),
        };

        // --- store: parsed, not connected ----------------------------------
        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| ConfigError::DatabaseAbsent)?;
        if database_url.trim().is_empty() {
            return Err(ConfigError::DatabaseAbsent);
        }

        // --- listener ------------------------------------------------------
        let port: u16 = match std::env::var("PORT") {
            Ok(p) => p
                .trim()
                .parse()
                .map_err(|_| ConfigError::PortMalformed(p.clone()))?,
            Err(_) => 8080,
        };
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);

        // --- optional exhibit pin ------------------------------------------
        // Validated if present. A malformed pin is a refusal rather than a
        // silently dropped one: publishing `null` when the operator believed
        // they had pinned a corpus is exactly the quiet lie `/health` exists to
        // make impossible.
        let genesis_exhibit = match std::env::var("CC_GENESIS_EXHIBIT") {
            Err(_) => None,
            Ok(h) => {
                let h = h.trim().to_string();
                if h.is_empty() {
                    None
                } else {
                    let bytes = hex::decode(&h).map_err(|_| ConfigError::ExhibitMalformed)?;
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .map_err(|_| ConfigError::ExhibitMalformed)?;
                    Some(ExhibitId(arr))
                }
            }
        };

        Ok(Config {
            bind,
            database_url,
            posture,
            api_key,
            read_key,
            gallery_key,
            beta_key,
            telemetry_key,
            genesis_exhibit,
        })
    }
}

/// Why a key is not fit to boot with, or `None` if it is.
///
/// Whitespace padding is rejected rather than trimmed. Trimming would make the
/// node accept a credential that is not the one in the secret store, and the
/// caller who copied the padded value would authenticate while a rotation
/// verifier comparing exact bytes says the key is wrong — a divergence that
/// only shows up under incident pressure.
fn weak_reason(key: &str) -> Option<&'static str> {
    if key.is_empty() {
        return Some("empty");
    }
    if key.trim() != key {
        return Some("has leading or trailing whitespace");
    }
    if key.len() < MIN_KEY_LEN {
        return Some("shorter than 32 characters");
    }
    let distinct: std::collections::BTreeSet<char> = key.chars().collect();
    if distinct.len() < MIN_KEY_ALPHABET {
        return Some("fewer than 8 distinct characters (looks like a placeholder)");
    }
    let lowered = key.to_ascii_lowercase();
    if PLACEHOLDERS.iter().any(|p| lowered.contains(p)) {
        return Some("contains a known placeholder word");
    }
    None
}

/// Boot-time configuration failures. Every one of these is fatal: there is no
/// arm here that degrades into serving.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "CC_NODE_API_KEY is not set. The node refuses to start rather than serve \
         an open read surface; set it to a high-entropy secret of at least 32 characters."
    )]
    AuthAbsent,
    #[error(
        "CC_NODE_API_KEY is not fit to serve with ({0}). The node refuses to start; \
         generate one with `openssl rand -hex 32`."
    )]
    AuthWeak(&'static str),
    #[error(
        "CC_NODE_READ_KEY is not fit to serve with ({0}). A read-only credential is still a \
         credential; generate one with `openssl rand -hex 32`."
    )]
    ReadKeyWeak(&'static str),
    #[error(
        "CC_NODE_READ_KEY is identical to CC_NODE_API_KEY. That is not a read-only credential, \
         it is a second copy of the write key. Set a different value or unset it."
    )]
    ReadKeyEqualsApiKey,
    #[error(
        "CC_NODE_GALLERY_KEY is not fit to serve with ({0}). The narrowest scope is still a \
         credential; generate one with `openssl rand -hex 32`."
    )]
    GalleryKeyWeak(&'static str),
    #[error(
        "CC_NODE_GALLERY_KEY is identical to CC_NODE_API_KEY. That is not a gallery credential, \
         it is a second copy of the write key."
    )]
    GalleryKeyEqualsApiKey,
    #[error(
        "CC_NODE_GALLERY_KEY is identical to CC_NODE_READ_KEY. A scope that duplicates a wider \
         credential is decorative; set a different value or unset it."
    )]
    GalleryKeyEqualsReadKey,
    #[error(
        "CC_NODE_BETA_KEY is not fit to serve with ({0}). Generate one with \
         `openssl rand -hex 32`."
    )]
    BetaKeyWeak(&'static str),
    #[error(
        "CC_NODE_BETA_KEY duplicates another credential. A scope that is a copy of a wider one \
         is decorative; set a different value or unset it."
    )]
    BetaKeyDuplicatesAnother,
    #[error(
        "CC_NODE_TELEMETRY_KEY is not fit to serve with ({0}). Generate one with \
         `openssl rand -hex 32`."
    )]
    TelemetryKeyWeak(&'static str),
    #[error(
        "CC_NODE_TELEMETRY_KEY duplicates another credential. Two holders sharing one secret \
         cannot be revoked or told apart; set a different value or unset it."
    )]
    TelemetryKeyDuplicatesAnother,
    #[error("CC_NODE_POSTURE is not set. Set it to `live` or `frozen` — the posture is published on /health and must be a stated intent, not a default.")]
    PostureAbsent,
    #[error("CC_NODE_POSTURE={0:?} is not a posture. The only values are `live` and `frozen`.")]
    PostureUnrecognized(String),
    #[error("DATABASE_URL is not set. The node fails closed rather than boot without a projection store.")]
    DatabaseAbsent,
    #[error("PORT={0:?} is not a port number.")]
    PortMalformed(String),
    #[error("CC_GENESIS_EXHIBIT is not 32 bytes of hex. Unset it or pin the real committed hash; a wrong exhibit id is worse than an absent one.")]
    ExhibitMalformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    // These are pure-function tests over the credential policy. There is no I/O
    // to fake here, so the no-mocks rule is not in play: `weak_reason` is a
    // total function of a string.

    #[test]
    fn a_strong_key_is_accepted() {
        assert_eq!(
            weak_reason("9f2c7a1b4e6d8c0a35f71b9e2d4c6a8071b3e5d7c9a1f3b5d7e9c1a3f5b7d9e1"),
            None
        );
    }

    #[test]
    fn short_keys_are_refused() {
        assert!(weak_reason("9f2c7a1b4e6d8c0a35f71b9e").is_some());
    }

    #[test]
    fn low_entropy_keys_are_refused() {
        assert!(weak_reason(&"ab".repeat(32)).is_some());
        assert!(weak_reason(&"x".repeat(64)).is_some());
    }

    #[test]
    fn placeholder_keys_are_refused() {
        assert!(weak_reason("changeme-changeme-changeme-changeme").is_some());
        assert!(weak_reason("this-is-a-long-enough-secret-value-x").is_some());
    }

    #[test]
    fn padded_keys_are_refused_not_trimmed() {
        let padded = format!(" {} ", "9f2c7a1b4e6d8c0a35f71b9e2d4c6a80");
        assert!(weak_reason(&padded).is_some());
    }

    #[test]
    fn digest_comparison_is_exact() {
        let d = KeyDigest::of("9f2c7a1b4e6d8c0a35f71b9e2d4c6a80");
        assert!(d.matches("9f2c7a1b4e6d8c0a35f71b9e2d4c6a80"));
        assert!(!d.matches("9f2c7a1b4e6d8c0a35f71b9e2d4c6a81"));
        assert!(!d.matches(""));
        // A prefix of the real key must not authenticate.
        assert!(!d.matches("9f2c7a1b"));
    }

    #[test]
    fn key_digest_debug_redacts() {
        let d = KeyDigest::of("9f2c7a1b4e6d8c0a35f71b9e2d4c6a80");
        assert_eq!(format!("{d:?}"), "KeyDigest(<redacted>)");
        // And the whole Config, which is what would land in a startup log line.
        let c = Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            database_url: "postgres://u:p@h/db".to_string(),
            posture: Posture::Live,
            api_key: d,
            read_key: None,
            gallery_key: None,
            beta_key: None,
            telemetry_key: None,
            genesis_exhibit: None,
        };
        let rendered = format!("{c:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("9f2c7a1b"));
        // The database password is a credential too, and a derived `Debug`
        // would have printed it.
        assert!(!rendered.contains("p@h"));
    }
}
