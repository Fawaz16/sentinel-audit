#!/usr/bin/env node
/**
 * forge-morse-key — build and inspect your own Morse-style key.
 *
 * Runs on plain Node (>= 22.18) with no build step and no dependencies.
 *
 *   npm run forge -- help
 *   npm run forge -- derive "my long passphrase"
 *   npm run forge -- show
 *   npm run forge -- encode "QUERY CUSTOMS VAULT" --seed "my long passphrase"
 *   npm run forge -- decode "... --- ..."
 *   npm run forge -- validate --env
 *   npm run forge -- secrets
 *
 * See docs/BUILD-YOUR-OWN-MORSE-KEY.md for the walkthrough.
 */

import crypto from "node:crypto";

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
  type MorseKey,
} from "../src/lib/morseKey.ts";

// ---------------------------------------------------------------------------
// Tiny terminal helpers
// ---------------------------------------------------------------------------

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (text: string) => (useColor ? `\u001b[${code}m${text}\u001b[0m` : text);
const bold = paint("1");
const dim = paint("2");
const red = paint("31");
const green = paint("32");
const yellow = paint("33");
const cyan = paint("36");

/** "standard" or "MK-1a4b174b" — avoids printing a fingerprint twice. */
function keyLabel(key: MorseKey): string {
  const fingerprint = fingerprintMorseKey(key);
  return key.name === fingerprint ? fingerprint : `${key.name} (${fingerprint})`;
}

function heading(text: string): void {
  console.log(`\n${bold(text)}\n${dim("-".repeat(text.length))}`);
}

function fail(message: string): never {
  console.error(`${red("error")} ${message}`);
  console.error(dim("Run `npm run forge -- help` for usage."));
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Argument parsing (no dependencies, no surprises)
// ---------------------------------------------------------------------------

interface Args {
  command: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const name = token.slice(2);
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[name] = next;
      i += 1;
    } else {
      flags[name] = true;
    }
  }

  return { command: positional.shift() ?? "help", positional, flags };
}

function flagString(flags: Args["flags"], name: string): string | undefined {
  const value = flags[name];
  return typeof value === "string" ? value : undefined;
}

// ---------------------------------------------------------------------------
// Resolving which key a command should operate on
// ---------------------------------------------------------------------------

function symbolOverrides(flags: Args["flags"]) {
  const symbols = flagString(flags, "symbols");
  if (!symbols) return undefined;
  const parts = symbols.split(",").map((s) => s.trim());
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    fail('--symbols expects two values, e.g. --symbols "·,—"');
  }
  return { short: parts[0], long: parts[1] };
}

function separatorOverrides(flags: Args["flags"]) {
  const letter = flagString(flags, "letter-sep");
  const word = flagString(flags, "word-sep");
  if (!letter && !word) return undefined;
  return { ...(letter ? { letter } : {}), ...(word ? { word } : {}) };
}

/**
 * Key selection, in priority order:
 *   --seed "<phrase>"   derive from a passphrase
 *   --key-json '<json>' a serialized key
 *   --env               read MORSE_KEY / MORSE_KEY_PASSPHRASE from the environment
 *   --random            forge from random bytes
 *   (nothing)           standard ITU Morse
 */
function resolveKey(flags: Args["flags"]): MorseKey {
  const options = {
    ...(symbolOverrides(flags) ? { symbols: symbolOverrides(flags) } : {}),
    ...(separatorOverrides(flags) ? { separators: separatorOverrides(flags) } : {}),
  };

  const seed = flagString(flags, "seed");
  if (seed) return deriveMorseKey(seed, options);

  const json = flagString(flags, "key-json");
  if (json) return parseMorseKey(json);

  if (flags.random) return randomMorseKey(options);

  if (flags.env) {
    const key = loadMorseKeyFromEnv();
    if (fingerprintMorseKey(key) === fingerprintMorseKey(STANDARD_MORSE_KEY)) {
      console.log(dim("note: no MORSE_KEY or MORSE_KEY_PASSPHRASE in the environment — using standard Morse"));
    }
    return key;
  }

  return STANDARD_MORSE_KEY;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function printKeyTable(key: MorseKey): void {
  const columns = 4;
  const chars = MORSE_ALPHABET.split("");
  const rows = Math.ceil(chars.length / columns);
  // Pad on *visible* width — the ANSI escapes below are zero-width on screen.
  const cellWidth = Math.max(...chars.map((c) => key.map[c]?.length ?? 1)) + 8;

  for (let row = 0; row < rows; row += 1) {
    const line: string[] = [];
    for (let col = 0; col < columns; col += 1) {
      const index = col * rows + row;
      if (index >= chars.length) continue;
      const char = chars[index];
      const code = key.map[char] ?? "?";
      const painted = `${bold(char)} ${dim("=")} ${cyan(code)}`;
      const visibleWidth = char.length + 3 + code.length;
      line.push(painted + " ".repeat(Math.max(2, cellWidth - visibleWidth)));
    }
    console.log("  " + line.join("").trimEnd());
  }
}

function printKey(key: MorseKey, { withEnv = true }: { withEnv?: boolean } = {}): void {
  const report = validateMorseKey(key);

  heading(`Morse key: ${keyLabel(key)}`);
  console.log(`  fingerprint    ${bold(report.fingerprint)}`);
  console.log(`  symbols        short ${cyan(JSON.stringify(key.symbols.short))}   long ${cyan(JSON.stringify(key.symbols.long))}`);
  console.log(
    `  separators     letter ${cyan(JSON.stringify(key.separators.letter))}   word ${cyan(JSON.stringify(key.separators.word))}`
  );
  console.log(`  longest code   ${report.maxCodeLength} symbols`);
  console.log(`  prefix-free    ${report.prefixFree ? green("yes") : yellow("no (separators are mandatory)")}`);

  heading("Table");
  printKeyTable(key);

  heading("Round-trip check");
  const sample = "QUERY CUSTOMS VAULT";
  const encoded = encodeWithKey(sample, key);
  const decoded = decodeWithKey(encoded, key);
  console.log(`  plaintext      ${sample}`);
  console.log(`  encoded        ${cyan(encoded)}`);
  console.log(`  decoded        ${decoded === sample ? green(decoded) : red(`${decoded}  <-- MISMATCH`)}`);

  heading("Guard detector for this key");
  console.log(`  ${dim(String(detectorRegexForKey(key)))}`);
  console.log(
    dim(
      "  crossDomainGuard.ts hardcodes a detector for '.' and '-'. If you changed\n" +
        "  the symbols, that detector is now blind — see docs/BUILD-YOUR-OWN-MORSE-KEY.md."
    )
  );

  if (report.warnings.length > 0) {
    heading("Warnings");
    for (const warning of report.warnings) console.log(`  ${yellow("!")} ${warning}`);
  }
  if (report.errors.length > 0) {
    heading("Errors");
    for (const error of report.errors) console.log(`  ${red("x")} ${error}`);
  }

  if (withEnv) {
    heading("Wire it into the lab (.env.local)");
    console.log(`  ${dim("# option A — share the passphrase, derive the key on each machine")}`);
    console.log(`  MORSE_KEY_PASSPHRASE="<your passphrase>"`);
    console.log(`  ${dim("# option B — pin the exact table (one line)")}`);
    console.log(`  MORSE_KEY='${serializeMorseKey(key)}'`);
  }

  console.log();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

const USAGE = `
${bold("forge-morse-key")} — build and inspect your own Morse-style key

${bold("Usage")}
  npm run forge -- <command> [args] [key-selector] [options]

${bold("Commands")}
  derive <passphrase>   Forge a key from a passphrase and print it
  random                Forge a key from random bytes
  show                  Print the selected key (default: standard ITU Morse)
  validate              Check the selected key round-trips and is unambiguous
  encode <text>         Encode text with the selected key
  decode <encoded>      Decode text with the selected key
  secrets               Generate fresh values for the lab's .env.local secrets
  help                  This message

${bold("Key selectors")}
  --seed <passphrase>   Derive the key from a passphrase (reproducible)
  --key-json <json>     Use a serialized key
  --env                 Use MORSE_KEY / MORSE_KEY_PASSPHRASE from the environment
  --random              Use a freshly randomised key
  (none)                Standard ITU Morse

${bold("Options")}
  --symbols "<a>,<b>"   Replace "." and "-" (e.g. --symbols "·,—")
  --letter-sep <s>      Separator between characters (default " ")
  --word-sep <s>        Separator between words (default " / ")
  --quiet               Print only the essential line (good for scripts)

${bold("Examples")}
  npm run forge -- derive "london gateway to rotterdam 1842"
  npm run forge -- encode "REROUTE CONTAINER" --seed "london gateway to rotterdam 1842"
  npm run forge -- show --symbols "·,—" --seed "my passphrase"
  npm run forge -- validate --env
`;

function commandDerive(args: Args): void {
  const passphrase = args.positional.join(" ").trim() || flagString(args.flags, "seed");
  if (!passphrase) fail('derive needs a passphrase: npm run forge -- derive "my long passphrase"');

  const key = deriveMorseKey(passphrase, {
    ...(symbolOverrides(args.flags) ? { symbols: symbolOverrides(args.flags) } : {}),
    ...(separatorOverrides(args.flags) ? { separators: separatorOverrides(args.flags) } : {}),
  });

  if (args.flags.quiet) {
    console.log(serializeMorseKey(key));
    return;
  }

  printKey(key);
  console.log(
    dim(
      "  Keep the passphrase, not the table: the same passphrase always rebuilds\n" +
        "  this exact key. Compare fingerprints to confirm two parties agree.\n"
    )
  );
}

function commandRandom(args: Args): void {
  const key = randomMorseKey({
    ...(symbolOverrides(args.flags) ? { symbols: symbolOverrides(args.flags) } : {}),
    ...(separatorOverrides(args.flags) ? { separators: separatorOverrides(args.flags) } : {}),
  });
  if (args.flags.quiet) {
    console.log(serializeMorseKey(key));
    return;
  }
  printKey(key);
  console.log(
    yellow("  This key came from random bytes — there is no passphrase that rebuilds it.\n") +
      dim("  Save the MORSE_KEY line above or it is gone.\n")
  );
}

function commandShow(args: Args): void {
  printKey(resolveKey(args.flags));
}

function commandValidate(args: Args): void {
  const key = resolveKey(args.flags);
  const report = validateMorseKey(key);

  heading(`Validating ${keyLabel(key)}`);
  for (const error of report.errors) console.log(`  ${red("x")} ${error}`);
  for (const warning of report.warnings) console.log(`  ${yellow("!")} ${warning}`);

  // An independent round-trip over the whole alphabet, not just a sample.
  const probe = MORSE_ALPHABET.split("").join("") + " SOS";
  const roundTripped = decodeWithKey(encodeWithKey(probe, key), key);
  const roundTripOk = roundTripped === probe;
  console.log(`  ${roundTripOk ? green("ok") : red("x")}  full-alphabet round-trip`);

  if (report.ok && roundTripOk) {
    console.log(`\n  ${green("PASS")} this key is usable.\n`);
    return;
  }
  console.log(`\n  ${red("FAIL")} fix the errors above before using this key.\n`);
  process.exit(1);
}

function commandEncode(args: Args): void {
  const text = args.positional.join(" ");
  if (!text) fail('encode needs text: npm run forge -- encode "QUERY CUSTOMS VAULT"');

  const key = resolveKey(args.flags);
  const encoded = encodeWithKey(text, key);

  if (args.flags.quiet) {
    console.log(encoded);
    return;
  }

  heading(`Encoded with ${keyLabel(key)}`);
  console.log(`  ${cyan(encoded)}`);
  const decoded = decodeWithKey(encoded, key);
  console.log(`\n  ${dim("decodes back to")} ${decoded === text.toUpperCase() ? green(decoded) : red(decoded)}`);
  console.log(
    `  ${dim("guard detector fires:")} ${
      detectorRegexForKey(key).test(encoded) ? green("yes") : yellow("no — this run is too short or uses unseen symbols")
    }\n`
  );
}

function commandDecode(args: Args): void {
  const encoded = args.positional.join(" ");
  if (!encoded) fail('decode needs input: npm run forge -- decode "... --- ..."');

  const key = resolveKey(args.flags);
  const decoded = decodeWithKey(encoded, key);

  if (args.flags.quiet) {
    console.log(decoded);
    return;
  }

  heading(`Decoded with ${keyLabel(key)}`);
  console.log(`  ${decoded ? green(decoded) : yellow("(nothing recognised — wrong key, or wrong separators)")}\n`);
}

function commandSecrets(): void {
  heading("Fresh secrets for .env.local");
  console.log(dim("  Copy these in place of the committed example values.\n"));
  console.log(`  AGENT_AUTH_SECRET="${crypto.randomBytes(32).toString("base64url")}"`);
  console.log(`  FRK36_CIPHER_SEED="${crypto.randomBytes(24).toString("base64url")}"`);
  console.log(`  MORSE_KEY_PASSPHRASE="${crypto.randomBytes(18).toString("base64url")}"`);
  console.log(
    `\n${dim(
      "  .env.local is gitignored. The values in .env.example are placeholders and\n" +
        "  are public by design — never reuse them for anything real.\n"
    )}`
  );
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function main(): void {
  const args = parseArgs(process.argv.slice(2));

  try {
    switch (args.command) {
      case "derive":
        return commandDerive(args);
      case "random":
        return commandRandom(args);
      case "show":
        return commandShow(args);
      case "validate":
        return commandValidate(args);
      case "encode":
        return commandEncode(args);
      case "decode":
        return commandDecode(args);
      case "secrets":
        return commandSecrets();
      case "help":
      case "--help":
      case "-h":
        console.log(USAGE);
        return;
      default:
        fail(`unknown command '${args.command}'`);
    }
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}

main();
