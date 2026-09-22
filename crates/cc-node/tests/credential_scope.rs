//! **The credential-scope matrix — this file IS the scope document.**
//!
//! The claim under test: *each named credential is accepted by exactly these
//! boundaries and no others.* Specified by timepoint-telemetry; the reasoning
//! is theirs and worth keeping, because it explains every awkward choice below.
//!
//! `auth.rs` used to say a credential's scope is readable from **the router's
//! shape** — each layer mounted on exactly one route, so scope could be read
//! without reading conditions. That held while every scoped key appeared in
//! exactly one guard. The moment one key appears in two, scope becomes "the set
//! of guards naming it", which takes a grep and is therefore not read at all.
//!
//! The discipline does not have to erode; it has to move somewhere that can
//! fail. So it moved here, and this is strictly stronger than readable-by-shape
//! because a shape cannot fail a test run.
//!
//! Four properties make it catch the failure it exists for — someone adding an
//! arm to one guard and forgetting the others:
//!
//! 1. **Driven through the real `router()`, over a real socket.** The router's
//!    shape is part of the claim. A guard tested in isolation passes happily
//!    while the router mounts it on the wrong route, and v2 shipped
//!    `422`-before-`401` precisely because its tests exercised handlers instead
//!    of the pipeline in front of them.
//! 2. **Every cell is a literal.** No loops, no wildcards, no
//!    "wider-keys-accept-everywhere-below" generator on the acceptance side — a
//!    generator would encode the belief under test and agree with itself. The
//!    only thing a loop may do here is walk the table.
//! 3. **`AppState` is built with exhaustive struct syntax, no
//!    `..Default::default()`.** A new credential field therefore fails to
//!    COMPILE until it is named here, which forces a new row, which forces
//!    every cell of that row to be decided. Compile-time beats run-time for
//!    this, because a forgotten row cannot be a skipped test.
//! 4. **Distinct tokens per credential, asserted pairwise.** If two fixture
//!    tokens collided, an `Accept` could pass for the wrong reason. Same
//!    principle as issuing one secret per holder so a leak names its leaker: a
//!    match must name its matcher.
//!
//! **To change a scope, change a cell and the arm in the same diff.** The diff
//! is then the scope change, reviewable as one thing.

use axum::body::Bytes;
use cc_filter::Filter;
use cc_node::{
    config::{KeyDigest, Posture},
    protocol::{genesis_filter_params, health_doc},
    router,
    state::AppState,
};
use std::net::Ipv4Addr;
use std::sync::Arc;

// Fixture tokens. Not secrets: they never leave this binary and the databases
// it talks to are ephemeral. Distinct by construction and asserted distinct
// below.
const FULL: &str = "11114b9c7e05a2d836be1904cf72ad5e3b8c60d94f17e2a5b3c8d70e916f2aaaa";
const READ: &str = "2222c7a1e64b8f025ac91de37b04f6c8215ae90d47f3b62c1e805a9f4c76dbbbb";
const GALLERY: &str = "333381f60d29b47e5081cfa63b7d940e2158c7fb03d64a91e2c8570df46b1cccc";
const BETA: &str = "44442c4a7d8b30f96e2417ca85d0b3f7196e4c802a5d71fb3908c6e24da51dddd";
const TELEMETRY: &str = "5555f0b91d2e6a35847bc1f0e93a5d7268b4e0c1a97f3d582e6b40a19c73feeee";
/// A well-formed credential this node has never issued.
const STRANGER: &str = "66660000000000000000000000000000000000000000000000000000000ffffff";

#[derive(Clone, Copy, Debug)]
enum Cred {
    Full,
    Read,
    Gallery,
    Beta,
    Telemetry,
    Stranger,
    /// No `Authorization` header at all — a different fact from a bad one.
    None,
}

impl Cred {
    fn token(self) -> Option<&'static str> {
        match self {
            Cred::Full => Some(FULL),
            Cred::Read => Some(READ),
            Cred::Gallery => Some(GALLERY),
            Cred::Beta => Some(BETA),
            Cred::Telemetry => Some(TELEMETRY),
            Cred::Stranger => Some(STRANGER),
            Cred::None => None,
        }
    }
}

/// What the auth boundary did, which is all this file asserts.
///
/// `Accept` means "the boundary let it through" — the handler's own answer
/// (`200`, `404`, `400`, even `503`) is not this file's business. `401` and
/// `403` are kept apart deliberately: the distinction is the whole point of
/// having scoped credentials, and collapsing them here would let the regression
/// that sent a valid-key holder to rotate a good credential pass unnoticed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum V {
    Accept,
    Unauthorized,
    Forbidden,
}
use V::{Accept, Forbidden, Unauthorized};

/// Every authenticated route in `router()`, with the boundary it sits behind.
///
/// **Not one representative per boundary.** That was the first version and
/// telemetry caught what it left out: representative-per-boundary tests the
/// guards but not the route-to-boundary MAPPING, so `/v1/feasibility` could
/// migrate to a different layer and all 42 cells would stay green — and that is
/// the route their key exercises most.
///
/// The fourth element is the route TEMPLATE as `router()` registers it, which
/// is what `every_authenticated_route_appears_in_the_matrix` censuses against.
/// `None` marks the fallback probe, which is not a registered route.
const BOUNDARIES: [(&str, &str, &str, Option<&str>); 14] = [
    // (label, method, request path, route template in router())
    (
        "health (unauthenticated)",
        "GET",
        "/health",
        Some("/health"),
    ),
    (
        "read: health/deep",
        "GET",
        "/health/deep",
        Some("/health/deep"),
    ),
    (
        "read: moments",
        "GET",
        "/v1/moments?as_of=0",
        Some("/v1/moments"),
    ),
    (
        "gallery: recents",
        "GET",
        "/v1/recents?as_of=0&limit=1",
        Some("/v1/recents"),
    ),
    (
        "entity_read: entity",
        "GET",
        "/v1/entities/1?as_of=0",
        Some("/v1/entities/:entity_id"),
    ),
    (
        "entity_read: feasibility",
        "POST",
        "/v1/feasibility",
        Some("/v1/feasibility"),
    ),
    ("write: events", "POST", "/v1/events", Some("/v1/events")),
    // The fallback sits INSIDE the read boundary. BELOW read scope an unknown
    // path answers 401 rather than a 404 that would enumerate the surface for a
    // prober; AT read scope or above it answers 404, because the boundary let
    // the caller through and the fallback is just a missing route.
    //
    // The unqualified version of this sentence sat here, directly above the
    // seven cells that contradict it — Full and Read read `Accept` in this
    // column, which is the 404. The cells were right and the prose was wrong,
    // for the reason telemetry named: prose next to a mechanism is the
    // least-tested artifact in the file and drifts toward the general claim,
    // because a general sentence reads better and nothing executes it.
    (
        "unknown path (read fallback)",
        "GET",
        "/v1/no-such-route",
        None,
    ),
    (
        "read: images",
        "GET",
        "/v1/images?entity_id=1&as_of=0",
        Some("/v1/images"),
    ),
    (
        "read: image bytes",
        "GET",
        "/v1/images/00",
        Some("/v1/images/:sha"),
    ),
    ("write: images", "POST", "/v1/images", Some("/v1/images")),
    (
        "read: typed media",
        "GET",
        "/v2/media?entity_id=1&as_of=0",
        Some("/v2/media"),
    ),
    (
        "write: absence",
        "POST",
        "/v2/media/absence-decisions",
        Some("/v2/media/absence-decisions"),
    ),
    (
        "read: edge evidence",
        "GET",
        "/v1/edges/00/evidence?as_of=0",
        Some("/v1/edges/:id/evidence"),
    ),
];

/// **The matrix.** Rows are credentials, columns are `BOUNDARIES` in order.
/// Every cell written out; nothing derived.
#[rustfmt::skip]
const MATRIX: [(Cred, [V; 14]); 7] = [
    //                health   read:deep     read:moments  gallery       entity        feasibility   write         unknown
    (Cred::Full,      [Accept, Accept,       Accept,       Accept,       Accept,       Accept,       Accept,       Accept      , Accept, Accept, Accept, Accept, Accept, Accept]),
    // The read key is accepted on gallery and entity_read on purpose: it can
    // already reach that data by other routes, so refusing it there would be
    // ceremony rather than a boundary. On write it is 403, never 401.
    (Cred::Read,      [Accept, Accept,       Accept,       Accept,       Accept,       Accept,       Forbidden,    Accept      , Accept, Accept, Forbidden, Accept, Forbidden, Accept]),
    // Gallery opens exactly one route. Everything else, including the unknown
    // path, is the same 401 a stranger gets.
    (Cred::Gallery,   [Accept, Unauthorized, Unauthorized, Accept,       Unauthorized, Unauthorized, Forbidden,    Unauthorized, Unauthorized, Unauthorized, Forbidden, Unauthorized, Forbidden, Unauthorized]),
    // Beta asked for these two routes and nothing else. The read key would
    // additionally hand them /v1/moments and /health/deep — a scope that grants
    // more than was asked for is not a scope, and those two cells say so.
    (Cred::Beta,      [Accept, Unauthorized, Unauthorized, Unauthorized, Accept,       Accept,       Forbidden,    Unauthorized, Unauthorized, Unauthorized, Forbidden, Unauthorized, Forbidden, Unauthorized]),
    // Telemetry holds beta's scope on a separate secret, PLUS the gallery route
    // as of Sean's direct authorisation 2026-08-18 — so their daily gate can run
    // the Ed25519 triple check on their own credential against the live surface
    // rather than reading my output. The gallery cell below and the arm in
    // `require_gallery` are the whole of that change. Still refused on
    // /health/deep and /v1/moments: they asked for one route and got one route.
    (Cred::Telemetry, [Accept, Unauthorized, Unauthorized, Accept,       Accept,       Accept,       Forbidden,    Unauthorized, Unauthorized, Unauthorized, Forbidden, Unauthorized, Forbidden, Unauthorized]),
    // A known-format token this node never issued is unknown everywhere — 401,
    // never 403, because 403 would confirm the token is real.
    (Cred::Stranger,  [Accept, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized]),
    (Cred::None,      [Accept, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized, Unauthorized]),
];

/// Boot the real router over a real ephemeral database.
///
/// **Exhaustive struct syntax, deliberately.** `AppState::build` is not used
/// here: it would keep compiling when a credential field is added, and the
/// point of this fixture is that it does not.
async fn boot() -> (String, tokio::task::JoinHandle<()>, cc_testkit::Cleanup) {
    let (pool, cleanup) = cc_testkit::ephemeral_db().await;
    let filter = Filter::new(genesis_filter_params());
    let doc = health_doc(&filter, Posture::Live.as_str(), None);
    let state = AppState {
        pool,
        filter: Arc::new(filter),
        posture: Posture::Live,
        health_body: Bytes::from(
            serde_json::to_string(&doc).expect("the health document is plain scalars"),
        ),
        api_key: KeyDigest::of(FULL),
        read_key: Some(KeyDigest::of(READ)),
        gallery_key: Some(KeyDigest::of(GALLERY)),
        beta_key: Some(KeyDigest::of(BETA)),
        telemetry_key: Some(KeyDigest::of(TELEMETRY)),
    };
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind an ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router(state)).await;
    });
    (format!("http://{addr}"), server, cleanup)
}

#[tokio::test]
async fn the_credential_scope_matrix_holds() {
    // Requirement 4: a collision would let a cell pass for the wrong reason.
    let tokens = [FULL, READ, GALLERY, BETA, TELEMETRY, STRANGER];
    for (i, a) in tokens.iter().enumerate() {
        for b in &tokens[i + 1..] {
            assert_ne!(a, b, "fixture tokens must be pairwise distinct");
        }
    }

    let (base, server, cleanup) = boot().await;
    let http = reqwest::Client::new();
    let mut checked = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for (cred, expected) in MATRIX {
        for (col, (label, method, path, _template)) in BOUNDARIES.iter().enumerate() {
            let url = format!("{base}{path}");
            let mut req = match *method {
                "GET" => http.get(&url),
                "POST" => http
                    .post(&url)
                    .header("content-type", "application/json")
                    .body("{}"),
                m => panic!("unhandled method {m}"),
            };
            if let Some(t) = cred.token() {
                req = req.bearer_auth(t);
            }
            let status = req.send().await.expect("request").status().as_u16();
            let got = match status {
                401 => Unauthorized,
                403 => Forbidden,
                _ => Accept,
            };
            if got != expected[col] {
                failures.push(format!(
                    "  {cred:?} x {label}: expected {:?}, got {got:?} (HTTP {status})",
                    expected[col]
                ));
            }
            checked += 1;
        }
    }

    server.abort();
    cleanup.cleanup().await;

    // Counted from the arrays that were actually walked, never typed beside
    // them: a hand-written total is the one number in a report that cannot
    // fail when the thing it describes changes.
    assert_eq!(checked, MATRIX.len() * BOUNDARIES.len());
    assert!(
        failures.is_empty(),
        "the router does not match the declared scope matrix ({} of {checked} cells):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// **The route census: every route `router()` registers must own a column.**
///
/// Telemetry proposed a comment in `lib.rs` as the honest substitute, on the
/// grounds that a real census "isn't cheaply available from axum". That is true
/// of a `Router` — it exposes no route table — but the router's *source* is
/// available at compile time, and that is the thing that would actually change.
/// So the substitute is not needed: this is the census.
///
/// It is deliberately BIDIRECTIONAL. Left to right catches the failure they
/// named — a route added to `router()` with no column, where the matrix would
/// stay green while saying nothing about it. Right to left catches its twin: a
/// column pointing at a route that no longer exists, which is a test that has
/// quietly stopped testing anything while still passing.
///
/// Scanning source text is a blunt instrument and it is the right one here,
/// because the failure mode is loud and self-describing: the assertion names
/// the exact path and what to do about it. A brittle check that fails toward
/// "add a column" is worth more than an elegant one that cannot exist.
///
/// **It reads text, not syntax, and that is a choice rather than an oversight.**
/// A `.route("...")` literal inside a COMMENT counts as registered, so a
/// commented-out route in `lib.rs` fails this test with "registered with no
/// column". Confirmed deliberately, not assumed: a commented probe produces
/// exactly that message. Left as-is because the failure points the right way —
/// toward adding a column or deleting the dead comment, and a commented-out
/// route is dead code that should be deleted rather than preserved. A syntax
/// -aware scan would be more precise and would buy nothing this file wants; it
/// would only make it possible to leave a fake route lying in the source where
/// a reader will one day mistake it for a real one. Found by telemetry, whose
/// probe was a commented route.
#[test]
fn every_authenticated_route_appears_in_the_matrix() {
    const ROUTER_SRC: &str = include_str!("../src/lib.rs");

    let registered: Vec<&str> = ROUTER_SRC
        .match_indices(".route(")
        .map(|(i, m)| {
            let rest = ROUTER_SRC[i + m.len()..]
                .trim_start()
                .strip_prefix('"')
                .expect("route path must be a literal");
            &rest[..rest.find('"').expect("unterminated route literal")]
        })
        .collect();

    // A floor of "at least as many routes as columns" sat here and was WRONG in
    // the way guards usually are: deleting a real route tripped it first, so the
    // failure read "the scan has probably broken" while the router was the thing
    // that changed. It preempted the bidirectional check below, which would have
    // said exactly which column had lost its route.
    //
    // Only an EMPTY scan is genuinely ambiguous between "broken parser" and
    // "router with no routes". Everything else has a better message waiting two
    // lines down, so the guard is scoped to the one case it can speak to.
    assert!(
        !registered.is_empty(),
        "no `.route(\"...\")` literals found in lib.rs — the scan has broken, \
         since a router with no routes would not compile against this test"
    );

    let columns: Vec<&str> = BOUNDARIES.iter().filter_map(|b| b.3).collect();

    for path in &registered {
        assert!(
            columns.contains(path),
            "route {path} is registered in router() and has no column in MATRIX. \
             Add a column and decide all {} of its cells — a route with no cells \
             is a route whose scope nothing checks.",
            MATRIX.len()
        );
    }
    for path in &columns {
        assert!(
            registered.contains(path),
            "MATRIX has a column for {path}, which router() no longer registers. \
             The column is testing nothing and passing while it does so."
        );
    }
}
