import crypto from "node:crypto";
import { z } from "zod";
import { decodeStandardMorse } from "./ciphers.ts";

const CleanManifestSchema = z.object({
  manifest_id: z.string().regex(/^MAN-\d{4}$/),
  container_id: z.string().regex(/^CONT-UK-\d{5}$/),
  cargo_summary: z.string().max(500),
  sender_agent_id: z.string().min(3),
  timestamp: z.number(),
});

export type CleanManifest = z.infer<typeof CleanManifestSchema>;

const APPROVED_FIELDS = Object.keys(CleanManifestSchema.shape) as (keyof CleanManifest)[];

export interface GuardInspectionResult {
  allowed: boolean;
  sanitizedPayload: CleanManifest | null;
  alerts: string[];
  tainted: boolean;
}

// High-integrity tools that a low-integrity (tainted) turn may never reach.
export const BIBA_LOCKED_TOOLS = Object.freeze([
  "query_customs_vault",
  "email_external_broker",
  "reroute_container",
] as const);

// Zero-width, bidi-control, soft hyphen, BOM, and Unicode tag characters.
const INVISIBLE_UNICODE =
  /[­᠎​-‏‪-‮⁠-⁤⁦-⁩﻿]|[\u{E0000}-\u{E007F}]/gu;

// Five or more Morse-shaped tokens separated by whitespace or "/".
const MORSE_RUN = /(?:[.\-]{1,7}(?:\s*\/\s*|\s+)){4,}[.\-]{1,7}/g;

/**
 * Hard ceiling on any single string field before it is scanned. Generous
 * relative to the schema's own limit (cargo_summary is capped at 500), so a
 * legitimate manifest never reaches it.
 */
const MAX_FIELD_CHARS = 2000;

/**
 * Deterministic serialization for signing: object keys sorted, recursively.
 *
 * `JSON.stringify` is key-order dependent, so a sender and a verifier that
 * serialize the same document in different orders compute different MACs. That
 * is invisible in this lab (signing and verifying happen in-process on one
 * object) but breaks the moment a real partner feed is wired in — and V8
 * reorders integer-like keys even on a plain JSON round-trip. Canonicalizing
 * makes the MAC a function of the document, not of its spelling. Cf. RFC 8785.
 *
 * A key whose value is `undefined` is treated as absent, which is what JSON
 * itself does; `{a:1}` and `{a:1,b:undefined}` are the same JSON document.
 */
function canonicalize(value: unknown): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new Error("Cannot sign a non-finite number");
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new Error(`Cannot sign a value of type ${typeof value}`);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonicalize).join(",")}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`).join(",")}}`;
}

export function signHandoff(payload: object, secret: string): string {
  return crypto.createHmac("sha256", secret).update(canonicalize(payload)).digest("hex");
}

/** Known-weak values for AGENT_AUTH_SECRET, including the one .env.example used to ship. */
const WEAK_SECRETS: ReadonlySet<string> = new Set([
  "captain-foxv1-thamesfreight-hmac-secret",
  "CHANGE_ME_run_npm_run_forge_secrets",
  "secret",
  "changeme",
  "password",
  "test",
]);

const MIN_SECRET_LENGTH = 24;

/**
 * Refuse to run on a guessable HMAC secret.
 *
 * The simulate response hands out both the signed manifest and its signature,
 * which is a verifiable (plaintext, MAC) pair — i.e. an offline cracking
 * oracle. That is acceptable for a teaching UI *only* while the secret has real
 * entropy: the shipped default was recoverable from a six-word dictionary.
 * Failing loudly here is cheaper than relying on everyone reading the docs.
 */
export function assertStrongAuthSecret(secret: string | undefined): string {
  if (!secret) {
    throw new Error("Missing AGENT_AUTH_SECRET — run `npm run forge -- secrets`");
  }
  if (WEAK_SECRETS.has(secret)) {
    throw new Error(
      "AGENT_AUTH_SECRET is a known placeholder value. The API returns the manifest " +
        "and its HMAC together, so a guessable secret is recoverable offline. " +
        "Run `npm run forge -- secrets`."
    );
  }
  if (secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `AGENT_AUTH_SECRET is ${secret.length} characters; at least ${MIN_SECRET_LENGTH} are required. ` +
        "Run `npm run forge -- secrets`."
    );
  }
  return secret;
}

export function verifyHandoffSignature(payload: object, signature: string, secret: string): boolean {
  if (typeof signature !== "string" || !/^[0-9a-f]{64}$/i.test(signature)) return false;
  const expected = signHandoff(payload, secret);
  return crypto.timingSafeEqual(Buffer.from(signature, "hex"), Buffer.from(expected, "hex"));
}

/** Biba taint lockout: deterministically remove high-integrity tools for a tainted turn. */
export function applyBibaTaintLockout<T extends { name: string }>(tools: readonly T[], tainted: boolean): T[] {
  if (!tainted) return [...tools];
  const locked = new Set<string>(BIBA_LOCKED_TOOLS);
  return tools.filter((t) => !locked.has(t.name));
}

export function inspectManifestHandoff(
  rawPacket: Record<string, unknown>,
  signature: string,
  secret: string
): GuardInspectionResult {
  const alerts: string[] = [];
  let tainted = false;

  // 1. Cryptographic agent identity check
  if (!verifyHandoffSignature(rawPacket, signature, secret)) {
    return {
      allowed: false,
      sanitizedPayload: null,
      alerts: ["AUTH_FAILURE: Invalid HMAC-SHA256 agent signature"],
      tainted: true,
    };
  }
  alerts.push("AUTH_OK: HMAC-SHA256 signature valid (identity ≠ integrity — continuing inspection)");

  // 2. Covert channel detection: any field outside the approved schema
  for (const key of Object.keys(rawPacket)) {
    if ((APPROVED_FIELDS as string[]).includes(key)) continue;
    tainted = true;
    const value = rawPacket[key];
    if (key === "iot_telemetry") {
      const n = Array.isArray(value) ? value.length : 0;
      alerts.push(`COVERT_CHANNEL: 'iot_telemetry' (${n} entries) — FRK36 cipher anomaly, field stripped`);
    } else {
      alerts.push(`UNAPPROVED_FIELD: '${key}' stripped by schema re-serialization`);
    }
  }

  // 3. Unicode sanitization + 4. Morse anomaly detection on approved string fields
  const candidate: Record<string, unknown> = {};
  for (const key of APPROVED_FIELDS) {
    const raw = rawPacket[key];

    if (typeof raw !== "string") {
      candidate[key] = raw;
      continue;
    }

    // `text` is explicitly string-typed, so the sanitization steps below need no
    // casts and cannot silently operate on a non-string.
    let text: string = raw;

    // Cheap structural check before any scanning. The Zod parse below enforces
    // the real limits, but it runs last, so without this cap an oversized field
    // would be scanned and copied several times first. The scans themselves are
    // linear (the character classes are disjoint, so there is no catastrophic
    // backtracking), which makes this a resource bound, not a ReDoS fix.
    if (text.length > MAX_FIELD_CHARS) {
      tainted = true;
      alerts.push(
        `OVERSIZED_FIELD: '${key}' was ${text.length} chars (limit ${MAX_FIELD_CHARS}) — truncated before inspection`
      );
      text = text.slice(0, MAX_FIELD_CHARS);
    }

    const invisible = text.match(INVISIBLE_UNICODE);
    if (invisible) {
      tainted = true;
      const codes = [
        ...new Set(
          invisible.map((c) => "U+" + c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0"))
        ),
      ];
      alerts.push(`INVISIBLE_UNICODE: ${invisible.length} hidden char(s) in '${key}' [${codes.join(", ")}] stripped`);
      text = text.replace(INVISIBLE_UNICODE, "");
    }

    const morseRuns = text.match(MORSE_RUN);
    if (morseRuns) {
      tainted = true;
      for (const run of morseRuns) {
        const decoded = decodeStandardMorse(run);
        alerts.push(`MORSE_ANOMALY: encoded sequence in '${key}' decodes to "${decoded}" — redacted`);
      }
      text = text.replace(MORSE_RUN, "[REDACTED_MORSE]").replace(/\s{2,}/g, " ").trim();
    }

    candidate[key] = text;
  }

  // 5. Strict Zod parse, then re-serialize only approved fields
  const parsed = CleanManifestSchema.safeParse(candidate);
  if (!parsed.success) {
    for (const issue of parsed.error.issues) {
      alerts.push(`SCHEMA_VIOLATION: ${issue.path.join(".") || "(root)"} — ${issue.message}`);
    }
    return { allowed: false, sanitizedPayload: null, alerts, tainted: true };
  }

  const sanitizedPayload = JSON.parse(JSON.stringify(parsed.data)) as CleanManifest;

  if (tainted) {
    alerts.push(`BIBA_TAINT: low-integrity input — locking ${BIBA_LOCKED_TOOLS.join(", ")}`);
  }

  return { allowed: true, sanitizedPayload, alerts, tainted };
}
