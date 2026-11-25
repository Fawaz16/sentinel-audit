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

export function signHandoff(payload: object, secret: string): string {
  return crypto.createHmac("sha256", secret).update(JSON.stringify(payload)).digest("hex");
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
    let value = rawPacket[key];
    if (typeof value === "string") {
      const invisible = value.match(INVISIBLE_UNICODE);
      if (invisible) {
        tainted = true;
        const codes = [...new Set(invisible.map((c) => "U+" + c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")))];
        alerts.push(`INVISIBLE_UNICODE: ${invisible.length} hidden char(s) in '${key}' [${codes.join(", ")}] stripped`);
        value = value.replace(INVISIBLE_UNICODE, "");
      }

      const morseRuns = (value as string).match(MORSE_RUN);
      if (morseRuns) {
        tainted = true;
        for (const run of morseRuns) {
          const decoded = decodeStandardMorse(run);
          alerts.push(`MORSE_ANOMALY: encoded sequence in '${key}' decodes to "${decoded}" — redacted`);
        }
        value = (value as string).replace(MORSE_RUN, "[REDACTED_MORSE]").replace(/\s{2,}/g, " ").trim();
      }
    }
    candidate[key] = value;
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
