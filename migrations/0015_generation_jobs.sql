-- Operational state only; no worker can sign or publish ledger events.
CREATE TABLE generation_jobs (
 id text PRIMARY KEY, brief text NOT NULL, state text NOT NULL,
 fence bigint NOT NULL DEFAULT 0, lease double precision NOT NULL DEFAULT 0,
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 result text, error text
);
CREATE TABLE generation_reservations (
 id text PRIMARY KEY, day text NOT NULL, job text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('text','image')),
 cents integer NOT NULL CHECK(cents>=0), created text NOT NULL
);
CREATE INDEX generation_reservations_day ON generation_reservations(day);
GRANT SELECT,INSERT,UPDATE ON generation_jobs TO cc_generation_worker;
GRANT SELECT,INSERT ON generation_reservations TO cc_generation_worker;
