import crypto from "node:crypto";
import { MORSE_ALPHABET, STANDARD_MORSE_KEY, decodeWithKey, encodeWithKey } from "./morseKey.ts";

const ALPHABET = MORSE_ALPHABET;
const MOD = ALPHABET.length; // 36

/**
 * Standard ITU Morse, the lab's first (deliberately obvious) covert channel.
 * The table itself now lives in morseKey.ts so that a learner-forged key and
 * the shipped key are the same kind of object. See
 * docs/BUILD-YOUR-OWN-MORSE-KEY.md.
 */
export function encodeStandardMorse(text: string): string {
  return encodeWithKey(text, STANDARD_MORSE_KEY);
}

export function decodeStandardMorse(morse: string): string {
  return decodeWithKey(morse, STANDARD_MORSE_KEY);
}

// ---------------------------------------------------------------------------
// FRK36 keyed function-state telemetry cipher
// ---------------------------------------------------------------------------

export function getCipherSeed(): string {
  const seed = process.env.FRK36_CIPHER_SEED;
  if (!seed) throw new Error("Missing FRK36_CIPHER_SEED");
  return seed;
}

function initRegister(seed: string): { initialState: number; salt: number } {
  const hash = crypto.createHash("sha256").update(seed).digest();
  return { initialState: hash[0] % MOD, salt: hash[1] % MOD };
}

type TelemetryOp = (state: number, param: number, salt: number) => number;

// Closed, frozen dispatch table. No eval(), no dynamic code paths.
const TELEMETRY_OPS = Object.freeze({
  container_temp_c: (s: number, p: number) => (s + p) % MOD,
  seal_check_ms: (s: number, p: number) => (s * 5 + p) % MOD,
  berth_offset: (s: number, p: number, salt: number) => (s + salt + p) % MOD,
} satisfies Record<string, TelemetryOp>);

export type TelemetryKey = keyof typeof TELEMETRY_OPS;
export type TelemetryEntry = Record<string, number | boolean>;

const TELEMETRY_KEYS: readonly TelemetryKey[] = ["container_temp_c", "seal_check_ms", "berth_offset"];

function isTelemetryKey(key: string): key is TelemetryKey {
  return Object.prototype.hasOwnProperty.call(TELEMETRY_OPS, key);
}

function applyOp(key: TelemetryKey, state: number, param: number, salt: number): number {
  const op: TelemetryOp = TELEMETRY_OPS[key];
  return op(state, param, salt);
}

export function packFRK36Telemetry(secretCommand: string, seed: string = getCipherSeed()): TelemetryEntry[] {
  const { initialState, salt } = initRegister(seed);
  let state = initialState;
  const iot_telemetry: TelemetryEntry[] = [];

  const clean = secretCommand.toUpperCase().replace(/[^A-Z0-9 ]/g, "");

  for (const char of clean) {
    if (char === " ") {
      iot_telemetry.push({ gps_lock: true });
      continue;
    }
    const target = ALPHABET.indexOf(char);
    const key = TELEMETRY_KEYS[iot_telemetry.length % TELEMETRY_KEYS.length];

    let param = -1;
    for (let candidate = 0; candidate < MOD; candidate++) {
      if (applyOp(key, state, candidate, salt) === target) {
        param = candidate;
        break;
      }
    }
    if (param < 0) throw new Error(`FRK36: no parameter reaches '${char}' via ${key}`);

    state = applyOp(key, state, param, salt);
    iot_telemetry.push({ [key]: param });
  }

  return iot_telemetry;
}

export function unpackFRK36Telemetry(
  iot_telemetry: unknown,
  seed: string = getCipherSeed()
): string {
  if (!Array.isArray(iot_telemetry)) return "";
  const { initialState, salt } = initRegister(seed);
  let state = initialState;
  let unlocked = "";

  for (const entry of iot_telemetry) {
    if (!entry || typeof entry !== "object") continue;
    const keys = Object.keys(entry);
    if (keys.length !== 1) continue;
    const key = keys[0];

    if (key === "gps_lock") {
      unlocked += " ";
      continue;
    }
    if (!isTelemetryKey(key)) continue;

    const param = Number((entry as Record<string, unknown>)[key]);
    if (!Number.isInteger(param) || param < 0 || param >= MOD) continue;

    state = applyOp(key, state, param, salt);
    unlocked += ALPHABET[state];
  }
  return unlocked;
}
