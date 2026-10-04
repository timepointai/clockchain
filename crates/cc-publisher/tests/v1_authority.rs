//! `cc-publisher v1 grants`, `delegate`, `revoke` and the authority `submit`
//! path, against the real v1 serving router over real PostgreSQL. Synthetic
//! keys and data only.
//!
//! Each test boots the router the way `cc-node serve` does (a provisioned and
//! bound store, reopened with `Store::open`), publishes a synthetic Genesis
//! with the curator (root) key, and drives authority through the publisher.
//! Corrections are built here from the cc-core types: the publisher has no
//! correction command in this change, and the node is what admits them.
use cc_core::v1::{
    hash, revision_id, root_grant, AssertedTime, Decision, Envelope, Hash, Kind, Payload, Set,
    Signed, Value,
};
use cc_core::SecretKey;
use cc_ledger::v1::Store;
use cc_node::config::{KeyDigest, Posture, V1Config};
use cc_node::serve_v1::{self, V1State};
use cc_publisher::v1::authority::{
    self, AuthorityEvent, Context, GrantStatus, RevokeChoice, PREVIEW_FILE,
};
use cc_publisher::v1::authority_node;
use cc_publisher::v1::genesis::{self, Genesis, GenesisInput};
use cc_publisher::v1::node::{self, Node, RECEIPT_FILE};
use cc_publisher::v1::{key, time};
use reqwest::StatusCode;
use serde_json::{json, Value as Json};
use std::path::{Path, PathBuf};
use std::process::Command;

const WRITE: &str = "synthetic-write";
const READ: &str = "synthetic-read";
const INSTANCE: Hash = [7; 32];

struct TestNode {
    url: String,
    pool: sqlx::PgPool,
    cleanup: cc_testkit::Cleanup,
}
impl TestNode {
    async fn start(mut curators: Vec<Hash>) -> Self {
        curators.sort();
        let (pool, cleanup) = cc_testkit::ephemeral_empty_db().await;
        let filter = cc_filter::v1::FilterIdentity::governed(curators, 4).unwrap();
        Store::provision(pool.clone(), INSTANCE)
            .await
            .unwrap()
            .bind(filter.clone())
            .await
            .unwrap();
        let store = Store::open(pool.clone(), INSTANCE, filter.clone())
            .await
            .unwrap();
        let readiness = store.semantic_readiness().await.unwrap();
        assert!(readiness.serving, "{readiness:?}");
        let v1 = V1Config {
            database_url: String::new(),
            instance: INSTANCE,
            filter,
        };
        let state = V1State {
            store,
            posture: Posture::Live,
            health_body: serve_v1::health_body(&v1, Posture::Live, &readiness.semantic),
            ready_gate: Default::default(),
            api_key: KeyDigest::of(WRITE),
            read_key: Some(KeyDigest::of(READ)),
            gallery_key: None,
            beta_key: None,
            telemetry_key: None,
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = serve_v1::router(state);
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, pool, cleanup }
    }
    fn writer(&self) -> Node {
        Node::new(&self.url, Some(WRITE)).unwrap()
    }
    fn reader(&self) -> Node {
        Node::new(&self.url, Some(READ)).unwrap()
    }
    /// Retained candidates: every posted envelope, valid or not.
    async fn candidates(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM cc_v1.candidates")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn grants(&self, subject: Hash) -> Context {
        authority_node::grants(&self.reader(), subject)
            .await
            .unwrap()
    }
}

/// A synthetic key written by the real `keygen` path.
fn keyfile(dir: &Path, name: &str) -> (PathBuf, SecretKey) {
    let path = dir.join(format!("{name}.seed"));
    key::keygen(&path).unwrap();
    let k = key::load_key(&path).unwrap();
    (path, k)
}
fn public(k: &SecretKey) -> Hash {
    k.author().to_bytes()
}
fn when() -> AssertedTime {
    time::parse("1901-02-03").unwrap()
}

/// Sign, submit and read back a synthetic Genesis with the curator key.
async fn published_genesis(n: &TestNode, root: &SecretKey, dir: &Path) -> Genesis {
    let g = genesis::build(
        root,
        GenesisInput {
            instance: INSTANCE,
            kind: "scientific-discovery".into(),
            namespace: "synthetic.authority".into(),
            value: "subject".into(),
            body: b"Synthetic Genesis body.\n".to_vec(),
            asserted_time: when(),
            evidence: vec![[0xaa; 32]],
            nonce: key::os_random().unwrap(),
        },
    )
    .unwrap();
    let out = dir.join("genesis");
    g.write_dir(&out).unwrap();
    node::submit(&n.writer(), &out, false).await.unwrap();
    g
}

/// Write an authority event to a fresh directory and submit it.
async fn submit(
    n: &TestNode,
    ev: &AuthorityEvent,
    dir: &Path,
    name: &str,
    allow_untrusted: bool,
) -> anyhow::Result<node::Submitted> {
    let out = dir.join(name);
    ev.write_dir(&out).unwrap();
    node::submit(&n.writer(), &out, allow_untrusted).await
}

fn delegate(k: &SecretKey, ctx: &Context, grantee: &SecretKey) -> AuthorityEvent {
    authority::delegate(
        k,
        ctx,
        public(grantee),
        "Synthetic hot-key delegation",
        vec![[0xcc; 32]],
    )
    .unwrap()
}
fn revoke_choice(target: Hash, cascade: bool) -> RevokeChoice {
    RevokeChoice {
        target,
        cascade,
        relinquish_root: false,
        parent: None,
    }
}
fn revoke(k: &SecretKey, ctx: &Context, target: Hash, cascade: bool) -> AuthorityEvent {
    authority::revoke(
        k,
        ctx,
        revoke_choice(target, cascade),
        "Synthetic revocation",
        vec![[0xdd; 32]],
    )
    .unwrap()
}

/// A Correction signed under `grant`, replacing `old` with `body`.
fn correction(
    k: &SecretKey,
    ctx: &Context,
    grant: Hash,
    parent: Hash,
    old: Hash,
    body: &[u8],
) -> Signed {
    let parents = Set(vec![parent]);
    Signed::sign(
        k,
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: Some(ctx.subject),
            subject_key: Some(ctx.subject_key.clone()),
            grant: Some(grant),
            parents: parents.clone(),
            asserted_time: Some(when()),
            payload: Payload::Correction {
                body: hash(body),
                decision: Decision {
                    kind: Kind::Correction,
                    rationale: "Synthetic correction".into(),
                    evidence: Set(vec![[0xbb; 32]]),
                    parents,
                    old: Value::Body(old),
                    new: Value::Body(hash(body)),
                },
            },
        },
    )
    .unwrap()
}
/// Store the body and post the Correction: the node's status, state and reason.
async fn post(n: &TestNode, c: &Signed, body: &[u8]) -> (StatusCode, String, String) {
    let w = n.writer();
    w.put_body(body).await.unwrap();
    let (status, outcome) = w.post_candidate(c.bytes()).await.unwrap();
    assert_eq!(outcome.event, Some(c.id()));
    (status, outcome.state, outcome.reason)
}
/// The subject's current revision id and served prose.
async fn current(n: &TestNode, subject: Hash) -> (Hash, String) {
    let r = n.reader();
    let read = r.subject(subject).await.unwrap().unwrap();
    let rev = cc_publisher::v1::hash_json(&read["revision"]["id"]).unwrap();
    let prose = r.prose(rev).await.unwrap();
    (rev, prose["prose"].as_str().unwrap().to_owned())
}
fn status(ctx: &Context, g: Hash) -> GrantStatus {
    ctx.grant(g).unwrap().status
}
fn err<T>(r: anyhow::Result<T>) -> String {
    match r {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => format!("{e:#}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delegated_key_corrects_and_is_refused_after_revoke() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let (_, hot) = keyfile(tmp.path(), "hot");
    let (_, hot2) = keyfile(tmp.path(), "hot2");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();

    // Before any delegation the root grant is the only grant.
    let ctx = n.grants(s).await;
    assert_eq!(ctx.grants.len(), 1);
    assert_eq!(ctx.grants[0].grant, root_grant(s));
    assert_eq!(ctx.grants[0].holder, public(&root));
    assert_eq!(ctx.frontier, vec![s]);
    // The hot key holds nothing yet, so it cannot sign.
    let refused = authority::delegate(&hot, &ctx, public(&hot2), "x", vec![[1; 32]]);
    assert!(err(refused).contains("holds no grant"));

    // Ceremony: the root delegates to the hot key.
    let ctx0 = ctx.clone();
    let d = delegate(&root, &ctx, &hot);
    let done = submit(&n, &d, tmp.path(), "delegate", false).await.unwrap();
    assert_eq!(done.receipt["admission"]["result"], "admitted");
    assert_eq!(
        done.receipt["readback"]["delegate"]["new_grant"]["holder"],
        hex::encode(public(&hot))
    );
    assert!(tmp.path().join("delegate").join(RECEIPT_FILE).exists());
    let ctx = n.grants(s).await;
    let hot_grant = ctx.grant(d.id()).unwrap();
    assert_eq!(hot_grant.status, GrantStatus::Active);
    assert_eq!(hot_grant.holder, public(&hot));
    assert_eq!(hot_grant.issuer, Some(root_grant(s)));
    assert_eq!(hot_grant.lineage, vec![root_grant(s), d.id()]);
    assert_eq!(ctx.frontier, vec![d.id()]);

    // A delegate key must be fresh: offline, a key that holds or held a
    // grant (the hot key, or the root itself) is refused...
    for k in [&hot, &root] {
        let refused = authority::delegate(&root, &ctx, public(k), "x", vec![[1; 32]]);
        assert!(err(refused).contains("must be fresh"));
    }
    // ...and submit refuses one signed from a grants file read before the
    // hot key's grant existed.
    // (A different rationale: the same one would sign the same event.)
    let twice = authority::delegate(&root, &ctx0, public(&hot), "Again", vec![[0xcc; 32]]).unwrap();
    assert_ne!(twice.id(), d.id());
    let before = n.candidates().await;
    let text = err(submit(&n, &twice, tmp.path(), "twice", false).await);
    assert!(text.contains("nothing was written"), "{text}");
    assert!(text.contains("a delegate key must be fresh"), "{text}");
    assert_eq!(n.candidates().await, before);

    // A rerun reports the admitted event and posts nothing.
    let before = n.candidates().await;
    let again = node::submit(&n.writer(), &tmp.path().join("delegate"), false)
        .await
        .unwrap();
    assert_eq!(again.receipt["admission"]["result"], "already_admitted");
    assert!(!again.receipt_written);
    assert_eq!(n.candidates().await, before);

    // The hot key's Correction is admitted and becomes the current revision.
    let genesis_body = hash(&g.body);
    let body = b"Corrected by the hot key.\n";
    let c = correction(&hot, &ctx, d.id(), d.id(), genesis_body, body);
    assert_eq!(
        post(&n, &c, body).await,
        (StatusCode::CREATED, "valid".into(), String::new())
    );
    assert_eq!(
        current(&n, s).await,
        (
            revision_id(s, c.id()),
            String::from_utf8(body.to_vec()).unwrap()
        )
    );

    // The hot key is not a curator, yet submit accepts what it signs under
    // its active grant: here a sub-delegation to hot2.
    let ctx = n.grants(s).await;
    assert!(!ctx.health.curators.contains(&public(&hot)));
    let d2 = delegate(&hot, &ctx, &hot2);
    let done = submit(&n, &d2, tmp.path(), "delegate2", false)
        .await
        .unwrap();
    assert_eq!(done.receipt["trust"]["root_holder_is_curator"], true);
    assert_eq!(
        done.receipt["trust"]["grant_active_and_held_by_author"],
        true
    );
    let stale = n.grants(s).await;

    // The root revokes the hot key without cascade.
    let r = revoke(&root, &stale, d.id(), false);
    let done = submit(&n, &r, tmp.path(), "revoke", false).await.unwrap();
    assert_eq!(done.receipt["readback"]["revoke"]["cascade"], false);
    let ctx = n.grants(s).await;
    assert_eq!(status(&ctx, d.id()), GrantStatus::Tombstoned);
    // Non-cascade: hot2, issued in the revoke's past, keeps its grant.
    assert_eq!(status(&ctx, d2.id()), GrantStatus::Active);
    assert_eq!(status(&ctx, root_grant(s)), GrantStatus::Active);
    // Acts in the revoke's past stay eligible: the hot key's Correction is
    // still the current revision.
    assert_eq!(current(&n, s).await.0, revision_id(s, c.id()));

    // A rerun of the Delegate after its grant was revoked still succeeds and
    // reports the grant as it is now.
    let rerun = node::submit(&n.writer(), &tmp.path().join("delegate"), false)
        .await
        .unwrap();
    assert_eq!(rerun.receipt["admission"]["result"], "already_admitted");
    assert_eq!(
        rerun.receipt["readback"]["delegate"]["new_grant"]["status"],
        "tombstoned"
    );
    assert!(node::summary(&rerun, &tmp.path().join("delegate"))[1].contains("tombstoned"));

    // Offline: the revoked key cannot sign.
    let (_, fresh) = keyfile(tmp.path(), "fresh");
    let refused = authority::delegate(&hot, &ctx, public(&fresh), "x", vec![[1; 32]]);
    let text = err(refused);
    assert!(
        text.contains("refusing to sign") && text.contains("tombstoned"),
        "{text}"
    );

    // submit: an event the hot key signed from a stale grants file is refused
    // before anything is written.
    let late = delegate(&hot, &stale, &fresh);
    let before = n.candidates().await;
    let text = err(submit(&n, &late, tmp.path(), "late", false).await);
    assert!(text.contains("nothing was written"), "{text}");
    assert!(text.contains("is tombstoned on the node"), "{text}");
    assert_eq!(n.candidates().await, before);

    // The node: a hot-key Correction on the current head is invalid.
    let body2 = b"Hot key after revocation.\n";
    let late = correction(&hot, &ctx, d.id(), r.id(), hash(body), body2);
    assert_eq!(
        post(&n, &late, body2).await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid".into(),
            "parent_authority".into()
        )
    );
    assert_eq!(current(&n, s).await.0, revision_id(s, c.id()));
    // hot2 still corrects.
    let body3 = b"hot2 still holds a grant.\n";
    let ok = correction(&hot2, &ctx, d2.id(), r.id(), hash(body), body3);
    assert_eq!(
        post(&n, &ok, body3).await,
        (StatusCode::CREATED, "valid".into(), String::new())
    );
    assert_eq!(current(&n, s).await.0, revision_id(s, ok.id()));
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cascade_revokes_the_whole_subtree_and_nothing_else() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let (_, hot1) = keyfile(tmp.path(), "hot1");
    let (_, hot2) = keyfile(tmp.path(), "hot2");
    let (_, side) = keyfile(tmp.path(), "side");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();

    let d1 = delegate(&root, &n.grants(s).await, &hot1);
    submit(&n, &d1, tmp.path(), "d1", false).await.unwrap();
    let d2 = delegate(&hot1, &n.grants(s).await, &hot2);
    submit(&n, &d2, tmp.path(), "d2", false).await.unwrap();
    let d3 = delegate(&root, &n.grants(s).await, &side);
    submit(&n, &d3, tmp.path(), "d3", false).await.unwrap();

    let ctx = n.grants(s).await;
    let r = revoke(&root, &ctx, d1.id(), true);
    assert_eq!(r.preview()["revoke"]["cascade"], true);
    let done = submit(&n, &r, tmp.path(), "revoke", false).await.unwrap();
    assert_eq!(done.receipt["readback"]["revoke"]["cascade"], true);
    assert_eq!(
        done.receipt["readback"]["revoke"]["descendants"],
        json!([{"grant": hex::encode(d2.id()), "holder": hex::encode(public(&hot2)), "status": "tombstoned"}])
    );
    let ctx = n.grants(s).await;
    assert_eq!(status(&ctx, d1.id()), GrantStatus::Tombstoned);
    assert_eq!(status(&ctx, d2.id()), GrantStatus::Tombstoned);
    // Grants outside the target's subtree survive.
    assert_eq!(status(&ctx, d3.id()), GrantStatus::Active);
    assert_eq!(status(&ctx, root_grant(s)), GrantStatus::Active);

    let old = hash(&g.body);
    let body = b"hot2 after a cascade revoke.\n";
    let c = correction(&hot2, &ctx, d2.id(), r.id(), old, body);
    assert_eq!(
        post(&n, &c, body).await,
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid".into(),
            "parent_authority".into()
        )
    );
    let body = b"The independent key still corrects.\n";
    let c = correction(&side, &ctx, d3.id(), r.id(), old, body);
    assert_eq!(
        post(&n, &c, body).await,
        (StatusCode::CREATED, "valid".into(), String::new())
    );
    // Offline, hot2 can no longer sign either.
    let (_, fresh) = keyfile(tmp.path(), "fresh");
    let text = err(authority::delegate(
        &hot2,
        &n.grants(s).await,
        public(&fresh),
        "x",
        vec![[1; 32]],
    ));
    assert!(text.contains("tombstoned"), "{text}");
    n.cleanup.cleanup().await;
}

/// A Revoke built without the publisher's scope check, as a hostile or
/// mistaken tool would sign it.
fn unchecked_revoke(k: &SecretKey, ctx: &Context, grant: Hash, target: Hash) -> AuthorityEvent {
    unchecked_revoke_on(k, ctx, grant, target, ctx.frontier[0])
}
fn unchecked_revoke_on(
    k: &SecretKey,
    ctx: &Context,
    grant: Hash,
    target: Hash,
    parent: Hash,
) -> AuthorityEvent {
    let parents = Set(vec![parent]);
    let signed = Signed::sign(
        k,
        Envelope {
            instance: INSTANCE,
            author: [0; 32],
            subject: Some(ctx.subject),
            subject_key: Some(ctx.subject_key.clone()),
            grant: Some(grant),
            parents: parents.clone(),
            asserted_time: None,
            payload: Payload::Revoke {
                target,
                cascade: false,
                decision: Decision {
                    kind: Kind::Revoke,
                    rationale: "Out of scope".into(),
                    evidence: Set(vec![[0xee; 32]]),
                    parents,
                    old: Value::ActiveGrant(target),
                    new: Value::RevokedGrant {
                        grant: target,
                        cascade: false,
                    },
                },
            },
        },
    )
    .unwrap();
    AuthorityEvent::from_signed(signed).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issuer_scope_is_enforced_offline_by_submit_and_by_the_node() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let (_, hot1) = keyfile(tmp.path(), "hot1");
    let (_, hot2) = keyfile(tmp.path(), "hot2");
    let (_, sib) = keyfile(tmp.path(), "sib");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();
    let d1 = delegate(&root, &n.grants(s).await, &hot1);
    submit(&n, &d1, tmp.path(), "d1", false).await.unwrap();
    let d3 = delegate(&root, &n.grants(s).await, &sib);
    submit(&n, &d3, tmp.path(), "d3", false).await.unwrap();
    let d2 = delegate(&hot1, &n.grants(s).await, &hot2);
    submit(&n, &d2, tmp.path(), "d2", false).await.unwrap();
    let ctx = n.grants(s).await;
    let scope = "not a strict issuer descendant";
    let try_revoke = |k: &SecretKey, target: Hash, relinquish_root: bool| {
        let choice = RevokeChoice {
            relinquish_root,
            ..revoke_choice(target, false)
        };
        authority::revoke(k, &ctx, choice, "Synthetic", vec![[2; 32]])
    };

    // Offline refusals: upward, sideways and self (only the root may revoke
    // its own grant, and only explicitly).
    assert!(err(try_revoke(&hot2, d1.id(), false)).contains(scope));
    assert!(err(try_revoke(&sib, d1.id(), false)).contains(scope));
    assert!(err(try_revoke(&sib, d2.id(), false)).contains(scope));
    assert!(err(try_revoke(&hot1, d1.id(), false)).contains(scope));
    assert!(err(try_revoke(&hot2, root_grant(s), false)).contains(scope));
    assert!(err(try_revoke(&root, root_grant(s), false)).contains("--relinquish-root"));
    assert!(err(try_revoke(&root, d2.id(), true)).contains("--relinquish-root"));
    // In scope: a strict descendant, at any depth.
    try_revoke(&root, d2.id(), false).unwrap();
    try_revoke(&hot1, d2.id(), false).unwrap();
    let relinquish = try_revoke(&root, root_grant(s), true).unwrap();
    assert_eq!(relinquish.preview()["revoke"]["relinquishes_root"], true);

    // submit refuses an out-of-scope Revoke before writing anything.
    let upward = unchecked_revoke(&hot2, &ctx, d2.id(), d1.id());
    let before = n.candidates().await;
    let text = err(submit(&n, &upward, tmp.path(), "upward", false).await);
    assert!(
        text.contains("nothing was written") && text.contains(scope),
        "{text}"
    );
    assert_eq!(n.candidates().await, before);
    // Forced past the publisher, the node refuses it, and retains the
    // invalid envelope (which is why the publisher checks first).
    let text = err(submit(&n, &upward, tmp.path(), "upward-forced", true).await);
    assert!(text.contains("revocation_scope"), "{text}");
    assert_eq!(n.candidates().await, before + 1);
    let sideways = unchecked_revoke(&sib, &ctx, d3.id(), d2.id());
    let text = err(submit(&n, &sideways, tmp.path(), "sideways", true).await);
    assert!(text.contains("revocation_scope"), "{text}");
    let ctx = n.grants(s).await;
    assert_eq!(status(&ctx, d1.id()), GrantStatus::Active);
    assert_eq!(status(&ctx, d2.id()), GrantStatus::Active);

    // A parent before the target's Delegate: the node checks scope in the
    // parent's past, where the target does not exist yet. Refused offline,
    // and by submit even with --allow-untrusted, before anything is written.
    let choice = RevokeChoice {
        parent: Some(d1.id()),
        ..revoke_choice(d2.id(), false)
    };
    let text = err(authority::revoke(&root, &ctx, choice, "x", vec![[5; 32]]));
    assert!(text.contains("is not in the past of parent"), "{text}");
    let early = unchecked_revoke_on(&root, &ctx, root_grant(s), d2.id(), d1.id());
    let before = n.candidates().await;
    let text = err(submit(&n, &early, tmp.path(), "early", true).await);
    assert!(
        text.contains("nothing was written") && text.contains("is not in the past of parent"),
        "{text}"
    );
    assert_eq!(n.candidates().await, before);
    // Likewise a signing grant issued after the parent, offline and by submit.
    let choice = RevokeChoice {
        parent: Some(s),
        ..revoke_choice(d2.id(), false)
    };
    let text = err(authority::revoke(&hot1, &ctx, choice, "x", vec![[5; 32]]));
    assert!(
        text.contains(&format!("grant {}", hex::encode(d1.id()))),
        "{text}"
    );
    assert!(text.contains("is not in the past of parent"), "{text}");
    let early = unchecked_revoke_on(&hot1, &ctx, d1.id(), d2.id(), s);
    let text = err(submit(&n, &early, tmp.path(), "early-signer", true).await);
    assert!(text.contains("is not in the past of parent"), "{text}");
    assert_eq!(n.candidates().await, before);

    // A parent the node does not know is refused by name.
    let unknown = unchecked_revoke_on(&root, &ctx, root_grant(s), d2.id(), [0x99; 32]);
    let text = err(submit(&n, &unknown, tmp.path(), "unknown-parent", true).await);
    assert!(text.contains("is not an event of subject"), "{text}");
    assert_eq!(n.candidates().await, before);

    // A non-root issuer revokes its own delegate.
    let r = revoke(&hot1, &ctx, d2.id(), false);
    submit(&n, &r, tmp.path(), "own", false).await.unwrap();
    let ctx = n.grants(s).await;
    assert_eq!(status(&ctx, d2.id()), GrantStatus::Tombstoned);
    assert_eq!(status(&ctx, d1.id()), GrantStatus::Active);
    // The root then revokes hot1 with cascade on the event before hot1's
    // revoke, which leaves that revoke outside its past: suppressed. A rerun
    // of hot1's revoke still succeeds and reports the effect.
    let choice = RevokeChoice {
        parent: Some(r.parent()),
        ..revoke_choice(d1.id(), true)
    };
    let over = authority::revoke(&root, &ctx, choice, "Over", vec![[9; 32]]).unwrap();
    submit(&n, &over, tmp.path(), "over", true).await.unwrap();
    let rerun = node::submit(&n.writer(), &tmp.path().join("own"), false)
        .await
        .unwrap();
    assert_eq!(rerun.receipt["admission"]["result"], "already_admitted");
    assert_eq!(
        rerun.receipt["readback"]["event_effect"],
        "revoked_concurrent"
    );
    let ctx = n.grants(s).await;
    // A revoke failing two checks at once (tombstoned target, out of scope)
    // is refused with both, before anything is written.
    let both = unchecked_revoke(&sib, &ctx, d3.id(), d2.id());
    let before = n.candidates().await;
    let text = err(submit(&n, &both, tmp.path(), "both", false).await);
    assert!(
        text.contains("is tombstoned") && text.contains(scope),
        "{text}"
    );
    assert_eq!(n.candidates().await, before);
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compromise_revoke_on_the_last_good_parent_suppresses_later_acts() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let (_, hot) = keyfile(tmp.path(), "hot");
    let (_, attacker) = keyfile(tmp.path(), "attacker");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();
    let d = delegate(&root, &n.grants(s).await, &hot);
    submit(&n, &d, tmp.path(), "d", false).await.unwrap();
    let genesis_revision = current(&n, s).await;

    // The hot key leaks: a hostile Correction and a hostile sub-delegation.
    let ctx = n.grants(s).await;
    let bad = b"Hostile body.\n";
    let c = correction(&hot, &ctx, d.id(), d.id(), hash(&g.body), bad);
    assert_eq!(post(&n, &c, bad).await.0, StatusCode::CREATED);
    let da = delegate(&hot, &n.grants(s).await, &attacker);
    submit(&n, &da, tmp.path(), "da", false).await.unwrap();
    assert_eq!(current(&n, s).await.0, revision_id(s, c.id()));

    // Revoking on the current head would acknowledge the hostile acts; the
    // playbook revokes with cascade on the last trusted event instead.
    let ctx = n.grants(s).await;
    let choice = RevokeChoice {
        parent: Some(d.id()),
        ..revoke_choice(d.id(), true)
    };
    let r = authority::revoke(&root, &ctx, choice, "Hot key compromised", vec![[3; 32]]).unwrap();
    assert!(r
        .summary(&ctx)
        .contains("2 event(s) are not in this revoke's past"));
    let before = n.candidates().await;
    let text = err(submit(&n, &r, tmp.path(), "r", false).await);
    assert!(text.contains("is not the subject's sole head"), "{text}");
    assert!(text.contains(&hex::encode(c.id())) && text.contains(&hex::encode(da.id())));
    assert_eq!(n.candidates().await, before);
    let done = submit(&n, &r, tmp.path(), "r-ack", true).await.unwrap();
    assert_eq!(done.receipt["trust"]["parent_is_sole_head"], false);
    assert_eq!(done.receipt["readback"]["event_is_head"], true);

    let ctx = n.grants(s).await;
    assert_eq!(ctx.frontier, vec![r.id()]);
    assert_eq!(ctx.state, "resolved");
    assert_eq!(status(&ctx, d.id()), GrantStatus::Tombstoned);
    assert_eq!(status(&ctx, da.id()), GrantStatus::Tombstoned);
    assert_eq!(ctx.event(c.id()).unwrap().reason, "revoked_concurrent");
    assert_eq!(ctx.event(da.id()).unwrap().reason, "revoked_concurrent");
    // The subject reads the last trusted body again.
    assert_eq!(current(&n, s).await, genesis_revision);
    assert_eq!(genesis_revision.0, g.revision());
    // `verify`, as the playbook's last step runs it, passes on that revision.
    let (ok, report) = node::verify(&n.reader(), s, Some(&tmp.path().join("genesis")))
        .await
        .unwrap();
    assert!(ok, "{report}");
    assert_eq!(report["revision"]["id"], hex::encode(g.revision()));

    // A suppressed event is refused as a revoke parent offline.
    let (_, other) = keyfile(tmp.path(), "other");
    let ctx = n.grants(s).await;
    let d_other = delegate(&root, &ctx, &other);
    submit(&n, &d_other, tmp.path(), "d-other", false)
        .await
        .unwrap();
    let ctx = n.grants(s).await;
    let choice = RevokeChoice {
        parent: Some(c.id()),
        ..revoke_choice(d_other.id(), false)
    };
    let text = err(authority::revoke(&root, &ctx, choice, "x", vec![[4; 32]]));
    assert!(
        text.contains("is suppressed (revoked_concurrent)"),
        "{text}"
    );

    // Control: the same compromise revoked on the head keeps the hostile body.
    let tmp2 = tempfile::tempdir().unwrap();
    let n2 = TestNode::start(vec![public(&root)]).await;
    let g2 = published_genesis(&n2, &root, tmp2.path()).await;
    let s2 = g2.subject();
    let d = delegate(&root, &n2.grants(s2).await, &hot);
    submit(&n2, &d, tmp2.path(), "d", false).await.unwrap();
    let c = correction(
        &hot,
        &n2.grants(s2).await,
        d.id(),
        d.id(),
        hash(&g2.body),
        bad,
    );
    assert_eq!(post(&n2, &c, bad).await.0, StatusCode::CREATED);
    let r = revoke(&root, &n2.grants(s2).await, d.id(), true);
    submit(&n2, &r, tmp2.path(), "r", false).await.unwrap();
    assert_eq!(current(&n2, s2).await.0, revision_id(s2, c.id()));
    n.cleanup.cleanup().await;
    n2.cleanup.cleanup().await;
}

fn publisher() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_cc-publisher"));
    c.env_remove("CC_NODE_API_KEY")
        .env_remove("CC_NODE_READ_KEY")
        .env_remove("RUST_BACKTRACE");
    c
}
fn run(c: &mut Command) -> (i32, String, String) {
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}
fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_grants_delegate_revoke_and_submit() {
    let tmp = tempfile::tempdir().unwrap();
    let t = tmp.path();
    let (root_key, root) = keyfile(t, "root");
    let (hot_key, hot) = keyfile(t, "hot");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, t).await;
    let subject = hex::encode(g.subject());
    let ev = hex::encode([0x44u8; 32]);

    // grants: needs a token, only reads, and writes a new file only.
    let grants = |out: &Path| {
        let mut c = publisher();
        c.args(["v1", "grants", "--node", &n.url, "--subject", &subject])
            .args(["--out", s(out)])
            .env("CC_NODE_READ_KEY", READ);
        c
    };
    let (code, _, err_text) =
        run(publisher().args(["v1", "grants", "--node", &n.url, "--subject", &subject]));
    assert_eq!(code, 1);
    assert!(err_text.contains("CC_NODE_READ_KEY"), "{err_text}");
    let before = n.candidates().await;
    let g0 = t.join("grants0.json");
    let (code, stdout, err_text) = run(&mut grants(&g0));
    assert_eq!(code, 0, "{err_text}");
    let file: Json = serde_json::from_slice(&std::fs::read(&g0).unwrap()).unwrap();
    assert_eq!(serde_json::from_str::<Json>(&stdout).unwrap(), file);
    assert_eq!(
        file["active"],
        json!([hex::encode(root_grant(g.subject()))])
    );
    assert_eq!(file["root"]["holder_is_curator"], true);
    assert_eq!(n.candidates().await, before);
    let (code, _, err_text) = run(&mut grants(&g0));
    assert_eq!(code, 1);
    assert!(err_text.contains("refusing to overwrite"), "{err_text}");

    let delegate = |key: &Path, grants: &Path, out: &Path| {
        let mut c = publisher();
        c.args(["v1", "delegate", "--key", s(key), "--grants", s(grants)])
            .args(["--grantee", &hex::encode(public(&hot))])
            .args(["--rationale", "Synthetic hot key", "--evidence", &ev])
            .args(["--out", s(out)]);
        c
    };
    // A key with no grant is refused and nothing is written.
    let (code, _, err_text) = run(&mut delegate(&hot_key, &g0, &t.join("bad")));
    assert_eq!(code, 1);
    assert!(err_text.contains("refusing to sign"), "{err_text}");
    assert!(!t.join("bad").exists());
    // A tampered grants file is refused.
    let mut tampered = file.clone();
    tampered["node_health"]["fold_version"]["manifest"] = json!(hex::encode([0u8; 32]));
    let tf = t.join("tampered-fold.json");
    std::fs::write(&tf, tampered.to_string()).unwrap();
    let (code, _, err_text) = run(&mut delegate(&root_key, &tf, &t.join("bad")));
    assert_eq!(code, 1);
    assert!(err_text.contains("fold_version"), "{err_text}");
    let mut tampered = file.clone();
    tampered["active"] = json!([]);
    let ta = t.join("tampered-active.json");
    std::fs::write(&ta, tampered.to_string()).unwrap();
    let (code, _, err_text) = run(&mut delegate(&root_key, &ta, &t.join("bad")));
    assert_eq!(code, 1);
    assert!(err_text.contains("\"active\""), "{err_text}");
    assert!(!t.join("bad").exists());

    // The root signs offline; submit admits it.
    let ddir = t.join("delegate");
    let (code, stdout, err_text) = run(&mut delegate(&root_key, &g0, &ddir));
    assert_eq!(code, 0, "{err_text}");
    assert!(stdout.contains("nothing was submitted"), "{stdout}");
    let preview: Json =
        serde_json::from_slice(&std::fs::read(ddir.join(PREVIEW_FILE)).unwrap()).unwrap();
    assert_eq!(preview["event_kind"], "delegate");
    assert_eq!(preview["delegate"]["grantee"], hex::encode(public(&hot)));
    let d_id = preview["event"].as_str().unwrap().to_owned();
    let submit = |dir: &Path| {
        let mut c = publisher();
        c.args(["v1", "submit", "--node", &n.url, "--dir", s(dir)])
            .env("CC_NODE_API_KEY", WRITE);
        c
    };
    // An edited preview is refused before anything is sent.
    let edited = t.join("edited");
    std::fs::create_dir(&edited).unwrap();
    std::fs::copy(ddir.join("envelope.bin"), edited.join("envelope.bin")).unwrap();
    std::fs::write(
        edited.join(PREVIEW_FILE),
        serde_json::to_string(&json!({"schema": "x"})).unwrap(),
    )
    .unwrap();
    let before = n.candidates().await;
    let (code, _, err_text) = run(&mut submit(&edited));
    assert_eq!(code, 1);
    assert!(
        err_text.contains("preview.json does not match"),
        "{err_text}"
    );
    assert_eq!(n.candidates().await, before);
    let (code, stdout, err_text) = run(&mut submit(&ddir));
    assert_eq!(code, 0, "{err_text}");
    assert!(
        err_text.contains("delegate admitted as valid"),
        "{err_text}"
    );
    let receipt: Json = serde_json::from_str(&stdout).unwrap();
    assert_eq!(receipt["schema"], authority_node::RECEIPT_SCHEMA);
    assert!(!stdout.contains(WRITE));

    // revoke: the cascade choice is explicit, never defaulted.
    let g1 = t.join("grants1.json");
    assert_eq!(run(&mut grants(&g1)).0, 0);
    let revoke = |flags: &[&str], out: &Path| {
        let mut c = publisher();
        c.args(["v1", "revoke", "--key", s(&root_key), "--grants", s(&g1)])
            .args([
                "--target",
                &d_id,
                "--rationale",
                "Rotate",
                "--evidence",
                &ev,
            ])
            .args(flags)
            .args(["--out", s(out)]);
        c
    };
    let (code, _, err_text) = run(&mut revoke(&[], &t.join("r0")));
    assert_eq!(code, 2, "{err_text}");
    assert!(err_text.contains("--cascade") && err_text.contains("--no-cascade"));
    let (code, _, _) = run(&mut revoke(&["--cascade", "--no-cascade"], &t.join("r0")));
    assert_eq!(code, 2);
    assert!(!t.join("r0").exists());
    for (flag, cascade) in [("--cascade", true), ("--no-cascade", false)] {
        let out = t.join(format!("r{cascade}"));
        let (code, _, err_text) = run(&mut revoke(&[flag], &out));
        assert_eq!(code, 0, "{err_text}");
        let p: Json =
            serde_json::from_slice(&std::fs::read(out.join(PREVIEW_FILE)).unwrap()).unwrap();
        assert_eq!(p["revoke"]["cascade"], cascade);
        assert_eq!(p["revoke"]["target"], d_id);
    }
    let (code, _, err_text) = run(&mut submit(&t.join("rfalse")));
    assert_eq!(code, 0, "{err_text}");
    let g2 = t.join("grants2.json");
    assert_eq!(run(&mut grants(&g2)).0, 0);
    let after: Json = serde_json::from_slice(&std::fs::read(&g2).unwrap()).unwrap();
    let hot_row = after["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["grant"] == d_id)
        .unwrap();
    assert_eq!(hot_row["status"], "tombstoned");
    // The cascade variant, signed from the same file, is now stale: its
    // target is no longer active and its parent no longer the head.
    let (code, _, err_text) = run(&mut submit(&t.join("rtrue")));
    assert_eq!(code, 1);
    assert!(err_text.contains("nothing was written"), "{err_text}");
    assert!(err_text.contains("is tombstoned"), "{err_text}");
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn root_relinquishment_is_explicit_and_reads_back() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let (_, hot) = keyfile(tmp.path(), "hot");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();
    let d = delegate(&root, &n.grants(s).await, &hot);
    submit(&n, &d, tmp.path(), "d", false).await.unwrap();
    let ctx = n.grants(s).await;
    let choice = RevokeChoice {
        relinquish_root: true,
        ..revoke_choice(root_grant(s), false)
    };
    let r = authority::revoke(&root, &ctx, choice, "Relinquish", vec![[6; 32]]).unwrap();
    let done = submit(&n, &r, tmp.path(), "r", false).await.unwrap();
    assert_eq!(done.receipt["admission"]["result"], "admitted");
    assert_eq!(
        done.receipt["readback"]["revoke"]["relinquished_root"],
        true
    );
    assert_eq!(
        done.receipt["readback"]["event_effect"],
        "root_relinquished"
    );
    assert_eq!(
        status(&n.grants(s).await, root_grant(s)),
        GrantStatus::Tombstoned
    );
    // A rerun reports it and still reads back.
    let again = node::submit(&n.writer(), &tmp.path().join("r"), false)
        .await
        .unwrap();
    assert_eq!(again.receipt["admission"]["result"], "already_admitted");
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoke_on_an_earlier_parent_can_leave_the_subject_contested() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let (_, hot) = keyfile(tmp.path(), "hot");
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();
    let d = delegate(&root, &n.grants(s).await, &hot);
    submit(&n, &d, tmp.path(), "d", false).await.unwrap();
    // The root's own Correction after the Delegate, then the hot key's.
    let ctx = n.grants(s).await;
    let mine = b"The root's own correction.\n";
    let c_root = correction(&root, &ctx, root_grant(s), d.id(), hash(&g.body), mine);
    assert_eq!(post(&n, &c_root, mine).await.0, StatusCode::CREATED);
    let bad = b"Hostile body.\n";
    let c_hot = correction(&hot, &ctx, d.id(), c_root.id(), hash(mine), bad);
    assert_eq!(post(&n, &c_hot, bad).await.0, StatusCode::CREATED);
    // Revoking on the Delegate leaves the root's Correction outside the
    // revoke's past but eligible: two heads. The publisher reports it.
    let ctx = n.grants(s).await;
    let choice = RevokeChoice {
        parent: Some(d.id()),
        ..revoke_choice(d.id(), true)
    };
    let r = authority::revoke(&root, &ctx, choice, "Too early", vec![[7; 32]]).unwrap();
    let done = submit(&n, &r, tmp.path(), "r", true).await.unwrap();
    assert_eq!(done.receipt["readback"]["subject_state"], "contested");
    let ctx = n.grants(s).await;
    let mut heads = vec![c_root.id(), r.id()];
    heads.sort();
    assert_eq!(ctx.frontier, heads);
    assert_eq!(ctx.event(c_hot.id()).unwrap().effect, "revoked_concurrent");
    assert!(node::summary(&done, &tmp.path().join("r"))[1].contains("it needs a Resolve"));
    n.cleanup.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_cascade_cancels_only_direct_delegates_issued_outside_its_past() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, root) = keyfile(tmp.path(), "root");
    let keys: Vec<_> = ["h1", "h2", "h3", "h4"]
        .iter()
        .map(|k| keyfile(tmp.path(), k).1)
        .collect();
    let (h1, h2, h3, h4) = (&keys[0], &keys[1], &keys[2], &keys[3]);
    let n = TestNode::start(vec![public(&root)]).await;
    let g = published_genesis(&n, &root, tmp.path()).await;
    let s = g.subject();
    // root -> h1 -> h2 -> h3, then h1 -> h4.
    let d1 = delegate(&root, &n.grants(s).await, h1);
    submit(&n, &d1, tmp.path(), "d1", false).await.unwrap();
    let d2 = delegate(h1, &n.grants(s).await, h2);
    submit(&n, &d2, tmp.path(), "d2", false).await.unwrap();
    let d3 = delegate(h2, &n.grants(s).await, h3);
    submit(&n, &d3, tmp.path(), "d3", false).await.unwrap();
    let d4 = delegate(h1, &n.grants(s).await, h4);
    submit(&n, &d4, tmp.path(), "d4", false).await.unwrap();

    // Revoke h1 without cascade on the h2 Delegate. h2 was issued in the
    // revoke's past and h3 under it; h4 is a direct delegate issued outside.
    let ctx = n.grants(s).await;
    let choice = RevokeChoice {
        parent: Some(d2.id()),
        ..revoke_choice(d1.id(), false)
    };
    let r = authority::revoke(&root, &ctx, choice, "Partial", vec![[8; 32]]).unwrap();
    let summary = r.summary(&ctx);
    assert!(
        summary.contains("2 active grant(s) below the target stay active; 1 are canceled"),
        "{summary}"
    );
    submit(&n, &r, tmp.path(), "r", true).await.unwrap();
    let ctx = n.grants(s).await;
    assert_eq!(status(&ctx, d1.id()), GrantStatus::Tombstoned);
    assert_eq!(status(&ctx, d2.id()), GrantStatus::Active);
    assert_eq!(status(&ctx, d3.id()), GrantStatus::Active);
    assert_eq!(status(&ctx, d4.id()), GrantStatus::Canceled);
    n.cleanup.cleanup().await;
}
