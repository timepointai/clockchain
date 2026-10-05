/**
 * Coordinate tests. The first five mirror the Coordinates class in
 * clients/python/tests/test_client.py; the rest pin values from cc-publisher's
 * Rust tests and an independent day count.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  coordinateFromDate,
  coordinateFromDateTime,
  coordinateFromSeconds,
  coordinateFromTicks,
  secondsFromCoordinate,
  ticksFromCoordinate,
} from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../../fixtures/v1/", import.meta.url));
const META: { entries: Array<{ asserted_time: { coordinate: string } }> } = JSON.parse(
  readFileSync(`${FIXTURES}_meta.json`, "utf8"),
);
const A = META.entries[0]!;
const B = META.entries[1]!;

describe("Coordinates", () => {
  test("publisher worked example", () => {
    // docs/PUBLISHER-V1.md, "Asserted time", --asserted-time 1901-02-03
    const c = coordinateFromDate(1901, 2, 3);
    assert.equal(c, "7fffffffffffffffffffffffffffffffffffffff45f44a400000000000000000");
    assert.equal(secondsFromCoordinate(c), -3_121_329_600n);
  });

  test("agrees with the Rust publisher", () => {
    // _meta.json holds what cc-publisher (Rust) encoded for the fixtures.
    assert.equal(coordinateFromDate(1901, 2, 3), A.asserted_time.coordinate);
    assert.equal(coordinateFromDate(1950), B.asserted_time.coordinate);
  });

  test("epoch and order", () => {
    assert.equal(coordinateFromSeconds(0), "80" + "00".repeat(31));
    assert.equal(coordinateFromDate(2000, 1, 1), coordinateFromSeconds(-43_200));
    const dates: Array<[number, number, number]> = [
      [-43, 3, 15],
      [0, 1, 1],
      [1, 1, 1],
      [1600, 2, 29],
      [1969, 7, 20],
      [2000, 1, 2],
      [2026, 10, 2],
    ];
    const coords = dates.map(([y, m, d]) => coordinateFromDate(y, m, d));
    assert.deepEqual(coords, [...coords].sort());
    assert.equal(new Set(coords).size, coords.length);
  });

  test("round trips", () => {
    for (const raw of [0n, 1n, -1n, (1n << 255n) - 1n, -(1n << 255n), 12345n << 64n]) {
      assert.equal(ticksFromCoordinate(coordinateFromTicks(raw)), raw);
    }
    assert.equal(coordinateFromTicks(-(1n << 255n)), "00".repeat(32));
    assert.equal(coordinateFromTicks((1n << 255n) - 1n), "ff".repeat(32));
    assert.throws(() => coordinateFromTicks(1n << 255n), RangeError);
    assert.throws(() => coordinateFromTicks(-(1n << 255n) - 1n), RangeError);
    assert.throws(() => coordinateFromTicks(1 as unknown as bigint), TypeError);
    for (const bad of ["80".repeat(31), "80".repeat(33), "AB".repeat(32), "zz".repeat(32), ` ${"0".repeat(63)}`]) {
      assert.throws(() => ticksFromCoordinate(bad), TypeError, bad);
    }
  });

  test("datetime and calendar errors", () => {
    const when = new Date(Date.UTC(1969, 6, 20, 20, 17, 40));
    assert.equal(
      secondsFromCoordinate(coordinateFromDateTime(when)),
      secondsFromCoordinate(coordinateFromDate(1969, 7, 20)) + 73_060n,
    );
    // A Date is always an absolute instant; an invalid one or a non-Date is refused.
    assert.throws(() => coordinateFromDateTime(new Date(Number.NaN)), RangeError);
    assert.throws(() => coordinateFromDateTime("2000-01-01" as unknown as Date), TypeError);
    for (const [y, m, d] of [
      [1900, 2, 29],
      [2001, 13, 1],
      [2001, 4, 31],
      [10000, 1, 1],
      [-10000, 1, 1],
      [2001, 0, 1],
      [2001, 1, 0],
    ] as Array<[number, number, number]>) {
      assert.throws(() => coordinateFromDate(y, m, d), RangeError, `${y}-${m}-${d}`);
    }
    assert.throws(() => coordinateFromDate(2000.5), TypeError);
    assert.throws(() => coordinateFromDate(2000, true as unknown as number), TypeError);
    assert.ok(coordinateFromDate(2000, 2, 29));
  });
});

describe("Coordinates beyond the Python suite", () => {
  test("agrees with every cc-publisher asserted-time anchor", () => {
    // crates/cc-publisher/tests/v1_offline.rs, asserted_time_syntax_and_coordinates.
    // The negative-year anchors are where a flooring days_from_civil goes a day early.
    const anchors: Array<[[number, number?, number?], bigint]> = [
      [[1901, 2, 3], -3_121_329_600n],
      [[1901, 2], -3_121_502_400n],
      [[1901], -3_124_180_800n],
      [[1970, 1, 1], -946_728_000n],
      [[2000, 1, 1], -43_200n],
      [[2000, 2, 29], 5_054_400n],
      [[1600, 2, 29], -12_617_726_400n],
      [[0], -63_113_947_200n],
      [[-1, 12, 31], -63_114_033_600n],
      [[-43, 3, 15], -64_464_552_000n],
      [[-9999], -378_651_844_800n],
      [[9999, 12, 31], 252_455_486_400n],
    ];
    for (const [[y, m, d], seconds] of anchors) {
      const c = coordinateFromDate(y, m, d);
      assert.equal(secondsFromCoordinate(c), seconds, `${y}-${m}-${d}`);
      assert.equal(c, coordinateFromSeconds(seconds));
    }
  });

  test("matches a direct day count for every year", () => {
    const leap = (y: number) => y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
    let jan1 = -378_651_844_800n; // -9999-01-01, from the anchors above
    for (let y = -9999; y <= 9999; y++) {
      const feb = leap(y) ? 29n : 28n;
      const mar1 = jan1 + (31n + feb) * 86_400n;
      const dec31 = jan1 + ((leap(y) ? 366n : 365n) - 1n) * 86_400n;
      assert.equal(secondsFromCoordinate(coordinateFromDate(y)), jan1, `${y}-01-01`);
      assert.equal(secondsFromCoordinate(coordinateFromDate(y, 3, 1)), mar1, `${y}-03-01`);
      assert.equal(secondsFromCoordinate(coordinateFromDate(y, 12, 31)), dec31, `${y}-12-31`);
      jan1 = dec31 + 86_400n;
    }
  });

  test("seconds accept a bigint or a safe integer", () => {
    assert.equal(coordinateFromSeconds(-3_121_329_600), coordinateFromSeconds(-3_121_329_600n));
    assert.equal(coordinateFromSeconds(-3_121_329_600), A.asserted_time.coordinate);
    assert.throws(() => coordinateFromSeconds(1.5), TypeError);
    assert.throws(() => coordinateFromSeconds(Number.NaN), TypeError);
    assert.throws(() => coordinateFromSeconds(true as unknown as number), TypeError);
    assert.throws(() => coordinateFromSeconds("0" as unknown as number), TypeError);
    assert.throws(() => coordinateFromSeconds(2 ** 53), RangeError);
    assert.throws(() => coordinateFromSeconds(1n << 191n), RangeError);
    assert.equal(secondsFromCoordinate(coordinateFromSeconds((1n << 191n) - 1n)), (1n << 191n) - 1n);
  });

  test("fractions floor towards earlier time", () => {
    assert.equal(secondsFromCoordinate(coordinateFromTicks(-1n)), -1n);
    assert.equal(secondsFromCoordinate(coordinateFromTicks((5n << 64n) + 1n)), 5n);
    // 1969-12-31T23:59:59.500Z is Unix second -1, not 0.
    assert.equal(secondsFromCoordinate(coordinateFromDateTime(new Date(-500))), -1n - 946_728_000n);
    assert.equal(secondsFromCoordinate(coordinateFromDateTime(new Date(1_999))), 1n - 946_728_000n);
  });
});
