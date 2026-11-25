/**
 * morseKey.ts — build, validate, and use your own Morse-style key.
 *
 * A "Morse key" here is four things:
 *   1. two symbols            (classically "." and "-")
 *   2. two separators         (classically " " between letters, " / " between words)
 *   3. a map from characters to codes built out of those two symbols
 *   4. a fingerprint, so two parties can check they hold the same key
 *
 * Nothing in this file is a security control. A Morse key is an *encoding*,
 * not encryption: anyone who can see the ciphertext can brute-force a 36-entry
 * substitution in seconds. It is in this repo because attackers use encodings
 * to smuggle instructions past naive filters, and because building one yourself
 * is the fastest way to understand why the Cross-Domain Guard has to inspect
 * *shape* (a run of dots and dashes) rather than keywords.
 *
 * Self-contained on purpose: the only import is node:crypto, so this module can
 * be run directly by `node` (see scripts/forge-morse-key.ts) as well as bundled
 * by Next.js.
 */

import crypto from "node:crypto";

export const MORSE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

export interface MorseSymbols {
  /** The short element. Classically ".". */
  short: string;
  /** The long element. Classically "-". */
  long: string;
}

export interface MorseSeparators {
  /** Between two characters of the same word. Classically " ". */
  letter: string;
  /** Between two words. Classically " / ". */
  word: string;
}

export interface MorseKey {
  /** Human label, e.g. "standard" or "MK-9f3a1c20". */
  name: string;
  symbols: MorseSymbols;
  separators: MorseSeparators;
  /** Uppercase character -> code string made only of `symbols.short` / `symbols.long`. */
  map: Readonly<Record<string, string>>;
}

export interface MorseKeyReport {
  ok: boolean;
  /** Problems that make the key unusable. */
  errors: string[];
  /** Things that still work but will surprise you. */
  warnings: string[];
  /**
   * True when no code is a prefix of another code. Standard Morse is NOT
   * prefix-free ("E" = "." is a prefix of "A" = ".-"), which is exactly why it
   * needs a letter separator. A prefix-free key can be decoded from an
   * unseparated stream.
   */
  prefixFree: boolean;
  fingerprint: string;
  /** Longest code length in symbols — used to size the guard's detector regex. */
  maxCodeLength: number;
}

// ---------------------------------------------------------------------------
// The standard key
// ---------------------------------------------------------------------------

/**
 * ITU standard Morse for A-Z and 0-9. This is the baseline every forged key is
 * a permutation of, and the key the lab's STANDARD_MORSE attack vector uses.
 */
export const STANDARD_MORSE_MAP: Readonly<Record<string, string>> = Object.freeze({
  A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....",
  I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.",
  Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-",
  Y: "-.--", Z: "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--",
  "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
});

export const STANDARD_MORSE_KEY: MorseKey = Object.freeze({
  name: "standard",
  symbols: Object.freeze({ short: ".", long: "-" }),
  separators: Object.freeze({ letter: " ", word: " / " }),
  map: STANDARD_MORSE_MAP,
});

// ---------------------------------------------------------------------------
// Deterministic keystream (seeded, no eval, no dependencies)
// ---------------------------------------------------------------------------

/**
 * Counter-mode SHA-256 expanded into a stream of uint32s. Deterministic for a
 * given seed, which is what makes a forged key reproducible: the same
 * passphrase always yields the same key, on any machine, forever.
 */
function* keystream(seed: string): Generator<number, never, unknown> {
  let counter = 0;
  for (;;) {
    const block = crypto.createHash("sha256").update(`${seed}#${counter}`).digest();
    counter += 1;
    for (let i = 0; i + 4 <= block.length; i += 4) {
      yield block.readUInt32BE(i);
    }
  }
}

/** Uniform integer in [0, n) by rejection sampling — no modulo bias. */
function nextBelow(gen: Generator<number, never, unknown>, n: number): number {
  if (n <= 0) throw new RangeError("n must be positive");
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  for (;;) {
    const value = gen.next().value;
    if (value < limit) return value % n;
  }
}

// ---------------------------------------------------------------------------
// Forging a key
// ---------------------------------------------------------------------------

export interface DeriveMorseKeyOptions {
  /** Override the two symbols. Both must be non-empty and different. */
  symbols?: Partial<MorseSymbols>;
  /** Override the two separators. */
  separators?: Partial<MorseSeparators>;
  /** Label for the key. Defaults to its fingerprint. */
  name?: string;
}

/**
 * Derive a personal Morse key from a passphrase.
 *
 * The strategy is a seeded permutation: we keep the *exact set of code shapes*
 * standard Morse uses and only change which character wears which code. That
 * matters, because the code set determines decodability. Invent code shapes at
 * random and you can easily produce an ambiguous key; permute a known-good set
 * and your key is guaranteed to be exactly as decodable as the original.
 *
 * Same passphrase in, same key out — that is the whole point. Share the
 * passphrase (or the fingerprint, to verify) rather than the table.
 */
export function deriveMorseKey(passphrase: string, options: DeriveMorseKeyOptions = {}): MorseKey {
  const phrase = passphrase.trim();
  if (phrase.length < 4) {
    throw new Error("Passphrase must be at least 4 characters — short seeds make guessable keys");
  }

  const symbols: MorseSymbols = {
    short: options.symbols?.short ?? STANDARD_MORSE_KEY.symbols.short,
    long: options.symbols?.long ?? STANDARD_MORSE_KEY.symbols.long,
  };
  const separators: MorseSeparators = {
    letter: options.separators?.letter ?? STANDARD_MORSE_KEY.separators.letter,
    word: options.separators?.word ?? STANDARD_MORSE_KEY.separators.word,
  };

  // Re-express the standard code shapes in the chosen symbols.
  const codes = MORSE_ALPHABET.split("").map((char) =>
    STANDARD_MORSE_MAP[char]
      .split("")
      .map((s) => (s === "." ? symbols.short : symbols.long))
      .join("")
  );

  // Seeded Fisher-Yates: shuffle which character gets which code.
  const gen = keystream(`morse-key/v1/${phrase}`);
  for (let i = codes.length - 1; i > 0; i -= 1) {
    const j = nextBelow(gen, i + 1);
    const tmp = codes[i];
    codes[i] = codes[j];
    codes[j] = tmp;
  }

  const map: Record<string, string> = {};
  MORSE_ALPHABET.split("").forEach((char, index) => {
    map[char] = codes[index];
  });

  const draft: MorseKey = { name: "pending", symbols, separators, map: Object.freeze(map) };
  const fingerprint = fingerprintMorseKey(draft);

  return Object.freeze({
    name: options.name ?? fingerprint,
    symbols: Object.freeze(symbols),
    separators: Object.freeze(separators),
    map: Object.freeze(map),
  });
}

/** Forge a key from cryptographically random bytes instead of a passphrase. */
export function randomMorseKey(options: DeriveMorseKeyOptions = {}): MorseKey {
  return deriveMorseKey(crypto.randomBytes(24).toString("base64url"), options);
}

// ---------------------------------------------------------------------------
// Fingerprinting
// ---------------------------------------------------------------------------

/**
 * Stable identity for a key, independent of property order. Two people can
 * compare fingerprints over an untrusted channel to confirm they hold the same
 * key without transmitting the table.
 */
export function fingerprintMorseKey(key: MorseKey): string {
  const canonical = JSON.stringify({
    short: key.symbols.short,
    long: key.symbols.long,
    letter: key.separators.letter,
    word: key.separators.word,
    map: Object.keys(key.map)
      .sort()
      .map((char) => [char, key.map[char]]),
  });
  const digest = crypto.createHash("sha256").update(canonical).digest("hex");
  return `MK-${digest.slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// Validating a key
// ---------------------------------------------------------------------------

/**
 * Check a key before you trust it to round-trip. Catches the four mistakes
 * people actually make when hand-rolling a key:
 *   - a character missing from the map
 *   - two characters sharing one code (decode becomes guesswork)
 *   - a code containing something other than the two declared symbols
 *   - a separator that can be mistaken for a symbol
 */
export function validateMorseKey(key: MorseKey): MorseKeyReport {
  const errors: string[] = [];
  const warnings: string[] = [];

  const { short, long } = key.symbols;
  if (!short || !long) errors.push("Both symbols must be non-empty");
  if (short === long) errors.push("The two symbols must differ");
  if (!key.separators.letter) errors.push("Letter separator must be non-empty");
  if (!key.separators.word) errors.push("Word separator must be non-empty");

  if (short && long) {
    for (const sep of [key.separators.letter, key.separators.word]) {
      if (sep.includes(short) || sep.includes(long)) {
        errors.push(`Separator ${JSON.stringify(sep)} contains a symbol — decoding is ambiguous`);
      }
    }
  }

  const missing = MORSE_ALPHABET.split("").filter((char) => !key.map[char]);
  if (missing.length > 0) {
    errors.push(`Missing code(s) for: ${missing.join(", ")}`);
  }

  const seen = new Map<string, string>();
  let maxCodeLength = 0;
  for (const [char, code] of Object.entries(key.map)) {
    if (!code) {
      errors.push(`Empty code for '${char}'`);
      continue;
    }
    const owner = seen.get(code);
    if (owner) {
      errors.push(`Duplicate code ${JSON.stringify(code)} used by both '${owner}' and '${char}'`);
    } else {
      seen.set(code, char);
    }

    if (short && long) {
      const symbolCount = countSymbols(code, short, long);
      if (symbolCount === null) {
        errors.push(`Code ${JSON.stringify(code)} for '${char}' uses characters outside the declared symbols`);
      } else {
        maxCodeLength = Math.max(maxCodeLength, symbolCount);
      }
    }

    if (!MORSE_ALPHABET.includes(char)) {
      warnings.push(`Code defined for '${char}', which is outside MORSE_ALPHABET — encode() will never emit it`);
    }
  }

  const codes = [...seen.keys()];
  const prefixFree = codes.every((a) => !codes.some((b) => b !== a && b.startsWith(a)));
  if (!prefixFree) {
    warnings.push(
      "Key is not prefix-free (standard Morse is not either). Letter separators are mandatory; " +
        "an unseparated stream cannot be decoded unambiguously."
    );
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
    prefixFree,
    fingerprint: fingerprintMorseKey(key),
    maxCodeLength,
  };
}

/** Number of symbols in a code, or null if it contains anything else. */
function countSymbols(code: string, short: string, long: string): number | null {
  let i = 0;
  let count = 0;
  while (i < code.length) {
    if (code.startsWith(short, i)) {
      i += short.length;
    } else if (code.startsWith(long, i)) {
      i += long.length;
    } else {
      return null;
    }
    count += 1;
  }
  return count;
}

// ---------------------------------------------------------------------------
// Encoding and decoding with an arbitrary key
// ---------------------------------------------------------------------------

/**
 * Encode text with any key. Characters outside the key's map are dropped, so
 * punctuation vanishes rather than leaking through as literal text.
 */
export function encodeWithKey(text: string, key: MorseKey = STANDARD_MORSE_KEY): string {
  return text
    .toUpperCase()
    .split(/\s+/)
    .filter(Boolean)
    .map((word) =>
      word
        .split("")
        .map((char) => key.map[char] ?? "")
        .filter(Boolean)
        .join(key.separators.letter)
    )
    .filter(Boolean)
    .join(key.separators.word);
}

/** Decode a string produced by `encodeWithKey` with the same key. */
export function decodeWithKey(encoded: string, key: MorseKey = STANDARD_MORSE_KEY): string {
  const reverse = new Map<string, string>();
  for (const [char, code] of Object.entries(key.map)) {
    if (!reverse.has(code)) reverse.set(code, char);
  }

  // Separators may contain regex metacharacters (" / " does not, "·|·" would).
  const wordSplit = new RegExp(`\\s*${escapeRegExp(key.separators.word.trim())}\\s*`);
  const letterSplit =
    key.separators.letter.trim() === ""
      ? /\s+/
      : new RegExp(`\\s*${escapeRegExp(key.separators.letter.trim())}\\s*`);

  return encoded
    .trim()
    .split(wordSplit)
    .map((word) =>
      word
        .split(letterSplit)
        .map((token) => reverse.get(token.trim()) ?? "")
        .join("")
    )
    .join(" ")
    .trim();
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ---------------------------------------------------------------------------
// Detecting an encoded run — the part that is actually a security control
// ---------------------------------------------------------------------------

/**
 * Build the "is there a suspicious encoded run in this field?" regex for a key.
 *
 * This is the bridge between the toy and the guard. `crossDomainGuard.ts` ships
 * a hardcoded detector for the standard "."/"-" alphabet. Forge a key with
 * different symbols and that hardcoded detector goes blind — which is the
 * single most useful lesson in this repo: **a filter that matches a hardcoded
 * surface form is not a boundary.** Pass this regex into the guard (see
 * docs/BUILD-YOUR-OWN-MORSE-KEY.md) to make the detector follow the key.
 *
 * @param minRun Minimum number of consecutive codes to flag. Lower = noisier.
 */
export function detectorRegexForKey(key: MorseKey = STANDARD_MORSE_KEY, minRun = 5): RegExp {
  const report = validateMorseKey(key);
  const maxLen = Math.max(1, report.maxCodeLength || 7);
  const symbol = `(?:${escapeRegExp(key.symbols.short)}|${escapeRegExp(key.symbols.long)})`;
  const code = `${symbol}{1,${maxLen}}`;

  // A gap between two codes is either separator, with optional surrounding
  // whitespace, or plain whitespace. Both separators must be listed: a key
  // whose letter separator is not whitespace (e.g. "_") is invisible to a
  // pattern that only knows the word separator. Longest first so the regex
  // prefers "__" over "_".
  const separators = [key.separators.word.trim(), key.separators.letter.trim()]
    .filter(Boolean)
    .sort((a, b) => b.length - a.length)
    .map(escapeRegExp);
  const gap = separators.length > 0 ? `(?:\\s*(?:${separators.join("|")})\\s*|\\s+)` : "\\s+";

  const runs = Math.max(1, minRun - 1);
  return new RegExp(`(?:${code}${gap}){${runs},}${code}`, "g");
}

// ---------------------------------------------------------------------------
// Serializing a key
// ---------------------------------------------------------------------------

/** Compact JSON, suitable for a single-line env var. */
export function serializeMorseKey(key: MorseKey): string {
  return JSON.stringify({
    name: key.name,
    symbols: key.symbols,
    separators: key.separators,
    map: key.map,
  });
}

/**
 * Parse a serialized key. Throws on anything that would not round-trip, so a
 * typo in .env.local fails loudly at startup instead of silently corrupting
 * every message.
 */
export function parseMorseKey(serialized: string): MorseKey {
  let raw: unknown;
  try {
    raw = JSON.parse(serialized);
  } catch {
    throw new Error("MORSE_KEY is not valid JSON");
  }
  if (!raw || typeof raw !== "object") throw new Error("MORSE_KEY must be a JSON object");

  const obj = raw as Record<string, unknown>;
  const symbols = obj.symbols as Partial<MorseSymbols> | undefined;
  const separators = obj.separators as Partial<MorseSeparators> | undefined;
  const map = obj.map as Record<string, unknown> | undefined;

  if (!symbols?.short || !symbols?.long) throw new Error("MORSE_KEY.symbols needs 'short' and 'long'");
  if (!separators?.letter || !separators?.word) throw new Error("MORSE_KEY.separators needs 'letter' and 'word'");
  if (!map || typeof map !== "object") throw new Error("MORSE_KEY.map must be an object");

  const cleanMap: Record<string, string> = {};
  for (const [char, code] of Object.entries(map)) {
    if (typeof code !== "string") throw new Error(`MORSE_KEY.map['${char}'] must be a string`);
    cleanMap[char.toUpperCase()] = code;
  }

  const key: MorseKey = {
    name: typeof obj.name === "string" && obj.name ? obj.name : "custom",
    symbols: { short: symbols.short, long: symbols.long },
    separators: { letter: separators.letter, word: separators.word },
    map: cleanMap,
  };

  const report = validateMorseKey(key);
  if (!report.ok) throw new Error(`MORSE_KEY is invalid:\n  - ${report.errors.join("\n  - ")}`);
  return key;
}

/**
 * The key the app should use: `MORSE_KEY` (a serialized key) if set, else
 * `MORSE_KEY_PASSPHRASE` derived on the fly, else standard Morse.
 */
export function loadMorseKeyFromEnv(
  env: Record<string, string | undefined> = process.env
): MorseKey {
  if (env.MORSE_KEY) return parseMorseKey(env.MORSE_KEY);
  if (env.MORSE_KEY_PASSPHRASE) return deriveMorseKey(env.MORSE_KEY_PASSPHRASE);
  return STANDARD_MORSE_KEY;
}
