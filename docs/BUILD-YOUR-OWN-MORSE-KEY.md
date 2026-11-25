# Build your own Morse key

A walkthrough of the key forge in [`src/lib/morseKey.ts`](../src/lib/morseKey.ts)
and [`scripts/forge-morse-key.ts`](../scripts/forge-morse-key.ts).

By the end you will have forged a reproducible personal key, learned why some
keys decode and others are quietly ambiguous, and used your own key to **blind
the lab's covert-channel detector** — which is the real reason this chapter
exists.

> **Up front: a Morse key is not encryption.** It is an *encoding*. A 36-entry
> substitution falls to frequency analysis or brute force in seconds. Nothing
> here protects a secret from anyone. It is in a security repo because attackers
> use encodings to smuggle instructions past filters, and because building one
> yourself is the shortest path to understanding why filtering for encodings is
> the wrong layer to defend at.

---

## Contents

1. [What a key actually is](#1-what-a-key-actually-is)
2. [Forge one](#2-forge-one)
3. [Why the forge permutes instead of inventing](#3-why-the-forge-permutes-instead-of-inventing)
4. [Ambiguity, and prefix-freeness](#4-ambiguity-and-prefix-freeness)
5. [Designing a key by hand](#5-designing-a-key-by-hand)
6. [Fingerprints: agreeing on a key](#6-fingerprints-agreeing-on-a-key)
7. [Wire your key into the lab](#7-wire-your-key-into-the-lab)
8. [The payoff: blind the detector](#8-the-payoff-blind-the-detector)
9. [API reference](#9-api-reference)

---

## 1. What a key actually is

Four things, and you need all four to decode anything:

| Part | Classic Morse | In code |
|---|---|---|
| **Two symbols** | `.` and `-` | `key.symbols` |
| **Two separators** | `" "` between letters, `" / "` between words | `key.separators` |
| **A character → code map** | `A = ".-"`, `B = "-..."`, … | `key.map` |
| **An identity** | (Morse has no version field) | `fingerprintMorseKey(key)` |

```ts
export interface MorseKey {
  name: string;
  symbols: { short: string; long: string };
  separators: { letter: string; word: string };
  map: Readonly<Record<string, string>>;  // 36 entries: A-Z, 0-9
}
```

Two people with the same four things can talk. Change any one of them and they
cannot. That is the whole mechanism — and it is also why a defender who hardcodes
one of the four has built something an attacker can step around.

---

## 2. Forge one

```bash
npm run forge -- derive "london gateway to rotterdam 1842"
```

You get the table, a fingerprint, a round-trip proof, the detector regex for
your key, any warnings, and two ready-to-paste `.env.local` lines.

Run it twice with the same passphrase. **Identical output.** Run it with one
character changed and the table is unrecognisable. That is the property worth
internalising: the passphrase *is* the key.

```bash
# encode with your key
npm run forge -- encode "REROUTE CONTAINER" --seed "london gateway to rotterdam 1842"

# decode it back
npm run forge -- decode "<paste the output>" --seed "london gateway to rotterdam 1842"

# machine-readable, for piping
npm run forge -- encode "SOS" --seed "my passphrase" --quiet
```

A key with no passphrase behind it, from the system CSPRNG:

```bash
npm run forge -- random
```

There is no passphrase that rebuilds that one. Save the `MORSE_KEY` line it
prints or it is gone for good.

### Changing the symbols

```bash
npm run forge -- show --seed "my passphrase" --symbols "·,—"
npm run forge -- show --seed "my passphrase" --symbols "0,1" --letter-sep "_" --word-sep "__"
```

Hold on to that second one. A key over `0`/`1` separated by underscores produces
output that reads as an identifier, a hash fragment, a serial number — anything
but a hidden instruction. We come back to it in §8.

---

## 3. Why the forge permutes instead of inventing

The obvious way to build a key is to generate random code strings. `deriveMorseKey`
deliberately does not. It keeps the **exact set of 36 code shapes** standard Morse
uses and only shuffles which character wears which:

```ts
// Re-express the standard code shapes in the chosen symbols.
const codes = MORSE_ALPHABET.split("").map((char) => /* ".-" → "·—" */ );

// Seeded Fisher-Yates: shuffle which character gets which code.
const gen = keystream(`morse-key/v1/${phrase}`);
for (let i = codes.length - 1; i > 0; i -= 1) {
  const j = nextBelow(gen, i + 1);
  [codes[i], codes[j]] = [codes[j], codes[i]];
}
```

Two reasons.

**Decodability is a property of the code *set*, not the assignment.** Standard
Morse's 36 shapes are known to work with separators. Permute them and your key
inherits that guarantee exactly. Invent shapes freely and you will produce a
duplicate or an ambiguity before long — §4.

**The keyspace is already plenty.** 36! ≈ 3.7 × 10⁴¹ permutations. Not a
cryptographic quantity, but far beyond anything you would hand-enumerate, and
the forge is not claiming to be cryptography.

The randomness is a SHA-256 counter-mode keystream with **rejection sampling** in
`nextBelow`, not `% n`:

```ts
const limit = Math.floor(0x1_0000_0000 / n) * n;
for (;;) {
  const value = gen.next().value;
  if (value < limit) return value % n;   // discard the biased tail
}
```

`uint32 % 36` would make the first 16 of each 2³² values marginally more likely.
It would not break this toy. It is written correctly anyway, because
modulo bias is a bug people carry from exercises like this one into code where it
matters.

---

## 4. Ambiguity, and prefix-freeness

Here is the mistake worth making once, deliberately.

Suppose you assign `E = "."` and `A = ".-"`. Now read the stream `.-` with no
separators. Is it `A`? Or `E` followed by… something starting with `-`? **You
cannot tell.** `"."` is a *prefix* of `".-"`.

Standard Morse has this property all over it. It is not a flaw — it is the
trade-off that makes common letters short. The price is that **separators become
mandatory**. Morse over the air encodes them as timing gaps; in a text field they
are literal characters.

A **prefix-free** code has no code that is a prefix of another, so it can be
decoded from an unbroken stream. Fixed-width codes are the easy example:

```
A = ......  B = .....-  C = ....-.  ...   (6 symbols each, always)
```

Longer, but `......-.` parses one way only.

`validateMorseKey` reports which kind you have:

```bash
npm run forge -- validate --seed "my passphrase"
```

```
  ! Key is not prefix-free (standard Morse is not either). Letter separators are
    mandatory; an unseparated stream cannot be decoded unambiguously.
  ok  full-alphabet round-trip

  PASS this key is usable.
```

Not prefix-free is a **warning**, not an error — the key works, it just cannot
lose its separators. The four things that *are* errors:

| Error | Why it is fatal |
|---|---|
| Missing code for a character | `encodeWithKey` silently drops it; your message loses letters |
| Duplicate code | Decode has to guess which character was meant |
| Code using an undeclared symbol | The detector and parser disagree about the alphabet |
| Separator containing a symbol | The decoder cannot tell data from delimiter |

That last one is the sneaky one. Try it:

```bash
npm run forge -- validate --seed "my passphrase" --letter-sep "."
```

```
  x Separator "." contains a symbol — decoding is ambiguous
```

---

## 5. Designing a key by hand

For when you want to choose the assignment yourself rather than take a shuffle.

```ts
import {
  type MorseKey,
  decodeWithKey,
  encodeWithKey,
  validateMorseKey,
  MORSE_ALPHABET,
} from "./src/lib/morseKey.ts";

// A fixed-width binary key: 6 symbols per character, prefix-free by construction.
const map: Record<string, string> = {};
MORSE_ALPHABET.split("").forEach((char, i) => {
  map[char] = i.toString(2).padStart(6, "0").replace(/0/g, ".").replace(/1/g, "-");
});

const myKey: MorseKey = {
  name: "fixed-width-6",
  symbols: { short: ".", long: "-" },
  separators: { letter: " ", word: " / " },
  map,
};

const report = validateMorseKey(myKey);
console.log(report.ok, report.prefixFree);          // true true
console.log(decodeWithKey(encodeWithKey("SOS", myKey), myKey));  // "SOS"
```

Run it with `node your-file.ts` — Node ≥ 22.18 executes TypeScript directly, no
build step.

**Always validate before you trust a hand-built key.** `validateMorseKey` is
cheap, and a duplicate code in a 36-entry table is very easy to miss by eye and
very confusing to debug later.

### Rules of thumb

- **Short codes to frequent characters.** Morse gives `E` one symbol and `Q`
  four. If you are optimising for length, do the same with your own frequency
  assumptions.
- **Pick separators that cannot appear in a code.** The validator enforces this,
  but choose them deliberately rather than fixing an error later.
- **Fixed-width if you want to drop separators.** Prefix-free costs you length
  and buys you a self-delimiting stream.
- **Give the key a name and keep the fingerprint.** Six months from now, "which
  key was this encoded with?" is a real question.

---

## 6. Fingerprints: agreeing on a key

```ts
fingerprintMorseKey(key)   // "MK-1a4b174b"
```

SHA-256 over a canonicalised form of the key — sorted map entries, so property
order cannot change the answer — truncated to 8 hex characters.

It solves the practical problem: two parties need to confirm they hold the same
key, over a channel where sending the table is awkward or revealing. Read eight
characters to each other instead. Match means identical keys; mismatch means
stop before debugging ciphertext.

Two ways to distribute a key:

| | Share the passphrase | Share the serialized key |
|---|---|---|
| `.env.local` | `MORSE_KEY_PASSPHRASE="..."` | `MORSE_KEY='{...}'` |
| Size | a phrase | ~600 characters, one line |
| Rebuilt by | `deriveMorseKey` on each machine | parsed verbatim |
| Survives a forge change | no — a different algorithm version gives a different key | **yes** |
| Good for | people | config, pinning, CI |

`MORSE_KEY` wins when both are set, and `parseMorseKey` validates on load — so a
typo in `.env.local` throws at startup instead of silently mangling every message.

---

## 7. Wire your key into the lab

By default `MORSE_KEY` and `MORSE_KEY_PASSPHRASE` are unset and the lab uses
standard ITU Morse. Making it use *your* key is a three-file exercise, and
working through it teaches more than reading about it.

### Step 1 — put your key in the environment

```bash
npm run forge -- derive "london gateway to rotterdam 1842"
# copy the MORSE_KEY_PASSPHRASE line into .env.local
npm run forge -- validate --env     # confirm the app will load what you expect
```

### Step 2 — attack with your key

In [`src/app/api/simulate/route.ts`](../src/app/api/simulate/route.ts):

```ts
import { encodeWithKey, decodeWithKey, loadMorseKeyFromEnv } from "@/lib/morseKey";

const MORSE_KEY = loadMorseKeyFromEnv();
```

Then in `buildAttackPacket`, replace `encodeStandardMorse(SECRET_COMMAND)` with
`encodeWithKey(SECRET_COMMAND, MORSE_KEY)`, and in `extractDirective` replace
`decodeStandardMorse(note)` with `decodeWithKey(note, MORSE_KEY)`.

Run `▶ STANDARD_MORSE` in `HARDENED` mode. If you kept `.`/`-`, the guard still
catches it — the detector matches *shape*, and you only changed the assignment.
**Now re-forge with `--symbols "0,1" --letter-sep "_"` and run it again.** The
guard goes quiet. `tainted: false`. All four tools available.

### Step 3 — make the detector follow the key

In [`src/lib/crossDomainGuard.ts`](../src/lib/crossDomainGuard.ts), the detector
is currently hardcoded:

```ts
const MORSE_RUN = /(?:[.\-]{1,7}(?:\s*\/\s*|\s+)){4,}[.\-]{1,7}/g;
```

Make it derive from the key instead:

```ts
import { type MorseKey, STANDARD_MORSE_KEY, decodeWithKey, detectorRegexForKey } from "./morseKey.ts";

export function inspectManifestHandoff(
  rawPacket: Record<string, unknown>,
  signature: string,
  secret: string,
  morseKey: MorseKey = STANDARD_MORSE_KEY,   // ← new, defaulted, so callers still compile
): GuardInspectionResult {
  const morseRun = detectorRegexForKey(morseKey);   // fresh regex per call
  // ...then use `morseRun` in place of MORSE_RUN, and
  //    decodeWithKey(run, morseKey) in place of decodeStandardMorse(run)
}
```

Pass `loadMorseKeyFromEnv()` from `route.ts` and the detector tracks the key
again. Run `npm test` — the existing guard tests still pass, because the
parameter defaults to standard Morse.

> **Note on the `g` flag.** A module-level regex with `/g` carries `lastIndex`
> between calls, which makes `.test()` stateful and is a classic source of
> intermittent bugs. Building the regex per call, as above, sidesteps it. The
> shipped code only ever uses `.match()`, which resets, but the per-call pattern
> is the safer habit.

---

## 8. The payoff: blind the detector

Here is the lesson in six lines, from
[`tests/morseKey.test.ts`](../tests/morseKey.test.ts):

```ts
const exotic = deriveMorseKey(PHRASE, { symbols: { short: "·", long: "—" } });
const payload = encodeWithKey("QUERY CUSTOMS VAULT", exotic);

// The shipped "."/"-" detector misses it entirely...
assert.equal(detectorRegexForKey(STANDARD_MORSE_KEY).test(payload), false);
// ...while a detector derived from the key in play catches it.
assert.ok(detectorRegexForKey(exotic).test(payload));
```

You changed two characters and defeated the filter. No new technique, no
cleverness — you just moved outside the alphabet it knew about.

Now ask the uncomfortable question: **how many alphabets would the detector need
to know?** Base64. ROT13. Emoji. Zero-width binary. Whitespace counts. Homoglyphs.
A key you invent this afternoon. The set is unbounded, and the attacker picks
after seeing your filter.

So the Morse detector in `crossDomainGuard.ts` is **not** what defends this lab.
It is there to produce a useful audit line — *here is what was hidden, and here
is what it said* — and that is a genuinely valuable thing for a detector to do.
What actually stops the attack is the layer that does not care about encodings
at all:

| Control | Needs to recognise the encoding? |
|---|---|
| Morse detector | **yes** — and so it is permanently one step behind |
| Invisible-Unicode stripper | yes, for the specific code points |
| **Schema allow-list** | **no** — an unapproved field is dropped unread |
| **Biba taint lockout** | **no** — tainted turns lose the dangerous tools |

The `FRK36_TELEMETRY` vector is the clean demonstration. It has no suspicious
string in it at all — just plausible integers. Content inspection has nothing to
find. The guard stops it anyway, because `iot_telemetry` is not a field the
interface accepts, and the turn that carried it loses the vault tools.

**Detect encodings to explain an incident. Enforce allow-lists to prevent one.**

---

## 9. API reference

From [`src/lib/morseKey.ts`](../src/lib/morseKey.ts). No dependencies beyond
`node:crypto`, so it runs under `node`, under Next.js, and in tests alike.

### Forging

```ts
deriveMorseKey(passphrase: string, options?: DeriveMorseKeyOptions): MorseKey
```
Deterministic key from a passphrase. Throws if the passphrase is under 4
characters. `options`: `symbols`, `separators`, `name` (all partial, all
optional).

```ts
randomMorseKey(options?: DeriveMorseKeyOptions): MorseKey
```
From 24 CSPRNG bytes. Unrecoverable — serialize it or lose it.

### Using

```ts
encodeWithKey(text: string, key?: MorseKey): string
decodeWithKey(encoded: string, key?: MorseKey): string
```
Both default to `STANDARD_MORSE_KEY`. Encoding uppercases its input and drops
characters outside the map, so punctuation disappears rather than leaking
through as literal text. Decoding returns `""` for tokens it does not recognise.

### Checking

```ts
validateMorseKey(key: MorseKey): MorseKeyReport
```

```ts
interface MorseKeyReport {
  ok: boolean;            // no errors — safe to use
  errors: string[];        // fatal: missing/duplicate codes, bad symbols, bad separators
  warnings: string[];      // non-fatal, e.g. not prefix-free
  prefixFree: boolean;     // decodable without letter separators?
  fingerprint: string;     // "MK-xxxxxxxx"
  maxCodeLength: number;   // longest code, in symbols
}
```

```ts
fingerprintMorseKey(key: MorseKey): string
```
Stable 8-hex identity, independent of property order.

### Detecting

```ts
detectorRegexForKey(key?: MorseKey, minRun = 5): RegExp
```
A fresh `/g` regex matching runs of ≥ `minRun` consecutive codes in that key's
symbols. Lower `minRun` catches shorter payloads and produces more false
positives on ordinary prose containing hyphens or ellipses.

### Moving keys around

```ts
serializeMorseKey(key: MorseKey): string           // compact, single-line JSON
parseMorseKey(serialized: string): MorseKey        // validates; throws on anything broken
loadMorseKeyFromEnv(env?): MorseKey                // MORSE_KEY ?? MORSE_KEY_PASSPHRASE ?? standard
```

### Constants

```ts
MORSE_ALPHABET      // "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
STANDARD_MORSE_KEY  // ITU Morse as a MorseKey
STANDARD_MORSE_MAP  // just the 36-entry table
```

---

**Next:** [LAB-EXERCISES.md](LAB-EXERCISES.md) — eleven exercises that break the
guard and ask you to work out why.
