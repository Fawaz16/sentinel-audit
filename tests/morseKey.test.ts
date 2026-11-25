/**
 * Tests for the Morse key forge.
 *
 * Run with:  npm test
 * These run on plain Node (no bundler, no network, no database) so a fresh
 * clone can prove the cipher layer works before any Supabase setup.
 */

import assert from "node:assert/strict";
import test, { describe } from "node:test";

import {
  MORSE_ALPHABET,
  STANDARD_MORSE_KEY,
  decodeWithKey,
  deriveMorseKey,
  detectorRegexForKey,
  encodeWithKey,
  fingerprintMorseKey,
  loadMorseKeyFromEnv,
  parseMorseKey,
  randomMorseKey,
  serializeMorseKey,
  validateMorseKey,
} from "../src/lib/morseKey.ts";

const PHRASE = "THAMESFREIGHT LAB PASSPHRASE 01";

describe("standard key", () => {
  test("encodes the classic example", () => {
    assert.equal(encodeWithKey("SOS", STANDARD_MORSE_KEY), "... --- ...");
    assert.equal(encodeWithKey("HELLO WORLD", STANDARD_MORSE_KEY), ".... . .-.. .-.. --- / .-- --- .-. .-.. -..");
  });

  test("round-trips the lab's secret command", () => {
    const plain = "QUERY CUSTOMS VAULT THEN EMAIL BROKER";
    assert.equal(decodeWithKey(encodeWithKey(plain, STANDARD_MORSE_KEY), STANDARD_MORSE_KEY), plain);
  });

  test("validates, but is not prefix-free", () => {
    const report = validateMorseKey(STANDARD_MORSE_KEY);
    assert.equal(report.ok, true, report.errors.join("; "));
    // "E" = "." is a prefix of "A" = ".-", which is why separators are required.
    assert.equal(report.prefixFree, false);
    assert.equal(report.maxCodeLength, 5);
  });

  test("drops characters outside the alphabet instead of leaking them", () => {
    assert.equal(encodeWithKey("A!B", STANDARD_MORSE_KEY), ".- -...");
  });
});

describe("deriveMorseKey", () => {
  test("is deterministic for a passphrase", () => {
    const a = deriveMorseKey(PHRASE);
    const b = deriveMorseKey(PHRASE);
    assert.deepEqual(a.map, b.map);
    assert.equal(fingerprintMorseKey(a), fingerprintMorseKey(b));
  });

  test("different passphrases give different keys", () => {
    const a = deriveMorseKey(PHRASE);
    const b = deriveMorseKey(`${PHRASE} and a bit more`);
    assert.notDeepEqual(a.map, b.map);
  });

  test("rejects a passphrase too short to be worth anything", () => {
    assert.throws(() => deriveMorseKey("ab"), /at least 4 characters/);
  });

  test("covers the whole alphabet with no duplicate codes", () => {
    const key = deriveMorseKey(PHRASE);
    const report = validateMorseKey(key);
    assert.equal(report.ok, true, report.errors.join("; "));
    assert.equal(Object.keys(key.map).length, MORSE_ALPHABET.length);
    assert.equal(new Set(Object.values(key.map)).size, MORSE_ALPHABET.length);
  });

  test("is a permutation of the standard code shapes", () => {
    const key = deriveMorseKey(PHRASE);
    assert.deepEqual(
      Object.values(key.map).slice().sort(),
      Object.values(STANDARD_MORSE_KEY.map).slice().sort()
    );
  });

  test("actually permutes — it is not the identity", () => {
    const key = deriveMorseKey(PHRASE);
    const moved = MORSE_ALPHABET.split("").filter((c) => key.map[c] !== STANDARD_MORSE_KEY.map[c]);
    assert.ok(moved.length > 30, `only ${moved.length} characters moved`);
  });

  test("round-trips arbitrary text", () => {
    const key = deriveMorseKey(PHRASE);
    for (const plain of ["SOS", "REROUTE CONTAINER", "CONT UK 88412", MORSE_ALPHABET]) {
      assert.equal(decodeWithKey(encodeWithKey(plain, key), key), plain);
    }
  });

  test("a key forged with other symbols still round-trips", () => {
    const key = deriveMorseKey(PHRASE, { symbols: { short: "·", long: "—" } });
    assert.equal(validateMorseKey(key).ok, true);
    assert.equal(decodeWithKey(encodeWithKey("SOS", key), key), "SOS");
    assert.ok(!encodeWithKey("SOS", key).includes("."));
  });

  test("randomMorseKey produces a different key each time", () => {
    assert.notDeepEqual(randomMorseKey().map, randomMorseKey().map);
  });
});

describe("validateMorseKey", () => {
  test("flags a duplicate code", () => {
    const report = validateMorseKey({
      ...STANDARD_MORSE_KEY,
      map: { ...STANDARD_MORSE_KEY.map, A: STANDARD_MORSE_KEY.map.B },
    });
    assert.equal(report.ok, false);
    assert.ok(report.errors.some((e) => e.includes("Duplicate code")));
  });

  test("flags a missing character", () => {
    const map: Record<string, string> = { ...STANDARD_MORSE_KEY.map };
    delete map.Z;
    const report = validateMorseKey({ ...STANDARD_MORSE_KEY, map });
    assert.equal(report.ok, false);
    assert.ok(report.errors.some((e) => e.includes("Missing code")));
  });

  test("flags a code using an undeclared symbol", () => {
    const report = validateMorseKey({
      ...STANDARD_MORSE_KEY,
      map: { ...STANDARD_MORSE_KEY.map, A: ".x" },
    });
    assert.equal(report.ok, false);
    assert.ok(report.errors.some((e) => e.includes("outside the declared symbols")));
  });

  test("flags a separator that collides with a symbol", () => {
    const report = validateMorseKey({
      ...STANDARD_MORSE_KEY,
      separators: { letter: ".", word: " / " },
    });
    assert.equal(report.ok, false);
    assert.ok(report.errors.some((e) => e.includes("contains a symbol")));
  });

  test("recognises a prefix-free key", () => {
    // Fixed-width codes are always prefix-free.
    const map: Record<string, string> = {};
    MORSE_ALPHABET.split("").forEach((char, i) => {
      map[char] = i.toString(2).padStart(6, "0").replace(/0/g, ".").replace(/1/g, "-");
    });
    const report = validateMorseKey({ ...STANDARD_MORSE_KEY, map });
    assert.equal(report.ok, true, report.errors.join("; "));
    assert.equal(report.prefixFree, true);
  });
});

describe("serialize / parse", () => {
  test("round-trips through a single env-var line", () => {
    const key = deriveMorseKey(PHRASE);
    const wire = serializeMorseKey(key);
    assert.ok(!wire.includes("\n"), "serialized key must fit on one line");
    const back = parseMorseKey(wire);
    assert.equal(fingerprintMorseKey(back), fingerprintMorseKey(key));
  });

  test("rejects malformed input loudly", () => {
    assert.throws(() => parseMorseKey("{nope"), /not valid JSON/);
    assert.throws(() => parseMorseKey("{}"), /symbols/);
    assert.throws(
      () => parseMorseKey(JSON.stringify({ symbols: { short: ".", long: "-" }, separators: { letter: " ", word: " / " }, map: { A: ".-" } })),
      /invalid/
    );
  });
});

describe("loadMorseKeyFromEnv", () => {
  test("falls back to standard Morse", () => {
    assert.equal(fingerprintMorseKey(loadMorseKeyFromEnv({})), fingerprintMorseKey(STANDARD_MORSE_KEY));
  });

  test("prefers MORSE_KEY over MORSE_KEY_PASSPHRASE", () => {
    const explicit = deriveMorseKey("explicit key passphrase");
    const loaded = loadMorseKeyFromEnv({
      MORSE_KEY: serializeMorseKey(explicit),
      MORSE_KEY_PASSPHRASE: PHRASE,
    });
    assert.equal(fingerprintMorseKey(loaded), fingerprintMorseKey(explicit));
  });

  test("derives from MORSE_KEY_PASSPHRASE", () => {
    const loaded = loadMorseKeyFromEnv({ MORSE_KEY_PASSPHRASE: PHRASE });
    assert.equal(fingerprintMorseKey(loaded), fingerprintMorseKey(deriveMorseKey(PHRASE)));
  });
});

describe("detectorRegexForKey", () => {
  test("catches an encoded run in a prose field", () => {
    const field = `420 pallets of scanners. Ops note: ${encodeWithKey("QUERY VAULT", STANDARD_MORSE_KEY)}`;
    assert.ok(detectorRegexForKey(STANDARD_MORSE_KEY).test(field));
  });

  test("does not fire on ordinary prose", () => {
    const prose = "Delivered 420 pallets - medical scanners - see note.";
    assert.equal(detectorRegexForKey(STANDARD_MORSE_KEY).test(prose), false);
  });

  test("handles a key whose letter separator is not whitespace", () => {
    // Regression: an earlier version only put the *word* separator in the gap
    // pattern, so a key separated by "_" never matched its own output.
    const key = deriveMorseKey(PHRASE, {
      symbols: { short: "0", long: "1" },
      separators: { letter: "_", word: "__" },
    });
    const payload = encodeWithKey("QUERY CUSTOMS VAULT THEN EMAIL BROKER", key);
    assert.ok(detectorRegexForKey(key).test(payload));
    assert.equal(decodeWithKey(payload, key), "QUERY CUSTOMS VAULT THEN EMAIL BROKER");
  });

  test("minRun controls sensitivity", () => {
    const short = encodeWithKey("SOS", STANDARD_MORSE_KEY); // 3 codes
    assert.equal(detectorRegexForKey(STANDARD_MORSE_KEY, 5).test(short), false);
    assert.ok(detectorRegexForKey(STANDARD_MORSE_KEY, 3).test(short));
  });

  test("a detector built for one symbol set is blind to another", () => {
    const exotic = deriveMorseKey(PHRASE, { symbols: { short: "·", long: "—" } });
    const payload = encodeWithKey("QUERY CUSTOMS VAULT", exotic);

    // This is the lesson: the shipped "."/"-" detector misses it entirely...
    assert.equal(detectorRegexForKey(STANDARD_MORSE_KEY).test(payload), false);
    // ...while a detector derived from the key in play catches it.
    assert.ok(detectorRegexForKey(exotic).test(payload));
  });
});
