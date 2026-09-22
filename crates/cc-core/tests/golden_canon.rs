//! Pinned canon vectors: the regression test that makes an accidental `H0`
//! change impossible to ship quietly.
//!
//! `H0` is the ledger's identity function. Two writers converge because they
//! compute the same `H0` from the same claim, and every migrated entry, every
//! Merkle leaf, and every anchor commits to it. So a change to `canon_event` is
//! not a refactor — it is a hard fork that silently renames every event in
//! history, and the failure mode is that nothing breaks locally while a peer on
//! the previous build stops converging with no error anywhere.
//!
//! These vectors are the tripwire. They are deliberately *not* computed from the
//! same code they check: each expected digest below was verified out-of-band
//! with `shasum -a 256` over the canon bytes, so the pin cannot drift by being
//! regenerated from a broken implementation. If one of these fails, the question
//! is never "what is the new hash" — it is "was this canon change intended, and
//! is the protocol version being bumped with it".

use cc_core::{
    canon_event, event_id, AuthorKey, ClosureState, EdgeBody, EdgeRelation, EntityBirth, EventBody,
    EventContent, EvidenceClass, ExistenceWindow, MomentBody, SecretKey, StartState, Tick,
    WindowEnd, WindowStart,
};

/// A fixed author. A seed, not a random key: a vector that changes run to run
/// pins nothing.
fn author() -> AuthorKey {
    SecretKey::from_seed([0x11; 32]).author()
}

/// An entity birth with an evidenced start and no recorded cessation — the shape
/// every row migrated out of the founding exhibit takes.
fn migrated_entity() -> EventContent {
    EventContent {
        event_time: Tick::from_i64(-61_756_675_200),
        record_time: Tick::from_i64(806_112_000),
        author: author(),
        supersedes: None,
        body: EventBody::EntityCreate(EntityBirth {
            entity_id: 4_611_686_018_427_387_904,
            resolution_key: "/ancient/rome/caesar".into(),
            canonical_name: "Julius Caesar".into(),
            window: ExistenceWindow {
                start: WindowStart::Known(Tick::from_i64(-61_756_675_200)),
                end: WindowEnd::UnknownClosure,
            },
        }),
    }
}

/// The same claim with the start unknown. Distinct from the above, and from an
/// entity whose start is evidenced at Clock Zero.
fn silent_start_entity() -> EventContent {
    let mut c = migrated_entity();
    if let EventBody::EntityCreate(e) = &mut c.body {
        e.window.start = WindowStart::Unknown;
    }
    c
}

fn moment() -> EventContent {
    EventContent {
        event_time: Tick::from_i64(-61_756_675_200),
        record_time: Tick::from_i64(806_112_000),
        author: author(),
        supersedes: None,
        body: EventBody::Moment(MomentBody {
            subject: 4_611_686_018_427_387_904,
            body_hash: [0xAB; 32],
        }),
    }
}

fn edge() -> EventContent {
    EventContent {
        event_time: Tick::from_i64(1),
        record_time: Tick::from_i64(2),
        author: author(),
        supersedes: None,
        body: EventBody::Edge(EdgeBody {
            src: 1,
            dst: 2,
            relation: EdgeRelation::CoOccurrence,
            evidence_class: EvidenceClass::SecondarySource,
        }),
    }
}

/// `(name, content, canon-bytes SHA-256 == H0)`.
///
/// Every digest below was produced by writing `canon_event(content)` to a file
/// and running the system `shasum -a 256` over it, on 2026-08-12, at canon
/// version v0 — 168, 168, 93 and 69 bytes respectively.
fn vectors() -> Vec<(&'static str, EventContent, &'static str)> {
    vec![
        (
            "entity/known-start",
            migrated_entity(),
            "fe2b0f211f7517caaf9ba21714e53ca8d45f0d3e8d80c0a0f669fe57ebaf3025",
        ),
        (
            "entity/unknown-start",
            silent_start_entity(),
            "aa53d4595ba1be6d5e764789953c92ebcd03a75e8ed6f0ca995fb288ae6eac3b",
        ),
        (
            "moment",
            moment(),
            "c7ed1cf9d89add40271273568dbacea45b06e0bcb98ab0a9791bcb85965a5d8b",
        ),
        (
            "edge",
            edge(),
            "42f8b3c7681f265eb3d49862705b7ff35274c342063c141889b717614c571900",
        ),
    ]
}

#[test]
fn canon_vectors_are_pinned() {
    let mut drift = Vec::new();
    for (name, content, expected) in vectors() {
        let got = event_id(&content).to_hex();
        if got != expected {
            drift.push(format!(
                "  {name}\n    expected {expected}\n    got      {got}\n    canon    {}",
                hex::encode(canon_event(&content))
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "canon drifted — this renames every event in history:\n{}",
        drift.join("\n")
    );
}

/// The two window discriminants are load-bearing in canon, not decoration.
///
/// Each of the four states below is a different sentence about the record, and
/// canon collapsing any pair would make two different claims share an identity.
#[test]
fn every_window_state_has_its_own_identity() {
    let mut ids = std::collections::BTreeSet::new();
    let starts = [
        WindowStart::Unknown,
        WindowStart::Known(Tick::ORIGIN),
        WindowStart::Known(Tick::from_i64(5)),
    ];
    let ends = [
        WindowEnd::KnownOpen,
        WindowEnd::UnknownClosure,
        WindowEnd::KnownClosed(Tick::from_i64(9)),
    ];
    let mut n = 0;
    for s in starts {
        for e in ends {
            let mut c = migrated_entity();
            if let EventBody::EntityCreate(b) = &mut c.body {
                b.window = ExistenceWindow { start: s, end: e };
            }
            ids.insert(event_id(&c).to_hex());
            n += 1;
        }
    }
    assert_eq!(ids.len(), n, "two window states collided on one H0");
}

/// The discriminants' wire values are themselves part of the format. Renumbering
/// them would preserve every in-process assertion and change every `H0`.
#[test]
fn discriminant_wire_values_are_pinned() {
    assert_eq!(StartState::Known as u8, 0);
    assert_eq!(StartState::Unknown as u8, 1);
    assert_eq!(ClosureState::KnownOpen as u8, 0);
    assert_eq!(ClosureState::KnownClosed as u8, 1);
    assert_eq!(ClosureState::UnknownClosure as u8, 2);
}
