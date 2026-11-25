"use client";

import { useEffect, useState } from "react";

type Mode = "VULNERABLE" | "HARDENED";
type Vector = "STANDARD_MORSE" | "FRK36_TELEMETRY";
type AdversaryAgent = "SCRIPTED" | "CLAUDE";

interface AuditRow {
  id: string;
  mode: string;
  attack_vector: string;
  tainted: boolean;
  alerts: string[];
  attempted_tool: string | null;
  outcome_status: string;
  created_at: string;
}

interface ToolCall {
  name: string;
  input: unknown;
  result: string;
  blocked: boolean;
}

interface SimResult {
  mode: Mode;
  vector: Vector;
  agent: AdversaryAgent;
  status: string;
  outcome: "EXFILTRATED" | "BLOCKED" | "NO_EXFIL";
  refused: boolean;
  manifest: Record<string, unknown>;
  signature: string;
  sanitizedPayload: Record<string, unknown> | null;
  guard: { allowed: boolean; tainted: boolean; alerts: string[]; enforced: boolean };
  permittedTools: string[];
  lockedTools: string[];
  toolCalls: ToolCall[];
  vaultData: Record<string, unknown> | null;
  transcript: string[];
  auditError: string | null;
  auditLog: AuditRow[];
}

const VECTORS: { id: Vector; label: string; hint: string }[] = [
  { id: "STANDARD_MORSE", label: "STANDARD_MORSE", hint: "Morse ops note + zero-width chars in cargo_summary" },
  { id: "FRK36_TELEMETRY", label: "FRK36_TELEMETRY", hint: "Keyed state-machine cipher in iot_telemetry" },
];

function Panel({ title, children, right }: { title: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="rounded-lg border border-zinc-800 bg-zinc-900/60">
      <header className="flex items-center justify-between border-b border-zinc-800 px-4 py-2">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">{title}</h3>
        {right}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Json({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all rounded bg-black/60 p-3 font-mono text-xs leading-relaxed text-zinc-300">
      {JSON.stringify(value, null, 2)}
    </pre>
  );
}

export default function Page() {
  const [mode, setMode] = useState<Mode>("VULNERABLE");
  const [agent, setAgent] = useState<AdversaryAgent>("SCRIPTED");
  const [running, setRunning] = useState<Vector | null>(null);
  const [result, setResult] = useState<SimResult | null>(null);
  const [auditLog, setAuditLog] = useState<AuditRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch("/api/simulate")
      .then((r) => r.json())
      .then((d) => setAuditLog(d.auditLog ?? []))
      .catch(() => {});
  }, []);

  async function run(vector: Vector) {
    setRunning(vector);
    setError(null);
    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, vector, agent }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? `HTTP ${res.status}`);
      setResult(data);
      setAuditLog(data.auditLog ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  }

  const breached = result?.outcome === "EXFILTRATED";
  const blocked = result?.outcome === "BLOCKED";

  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-6 text-zinc-100 md:px-8">
      <header className="mb-6 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div>
          <p className="font-mono text-xs text-zinc-500">captain-foxv1 · ThamesFreight Logistics Ltd</p>
          <h1 className="text-2xl font-bold tracking-tight">Cross-Domain Guard &amp; Biba Taint Lab</h1>
          <p className="mt-1 text-sm text-zinc-400">
            CONT-UK-88412 · London Gateway Port → Rotterdam Terminal 4
          </p>
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
          <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-900 p-1" role="group" aria-label="Mode">
            {(["VULNERABLE", "HARDENED"] as Mode[]).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                className={`rounded-md px-4 py-1.5 font-mono text-xs font-semibold transition ${
                  mode === m
                    ? m === "VULNERABLE"
                      ? "bg-red-600 text-white"
                      : "bg-emerald-600 text-white"
                    : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {m}
              </button>
            ))}
          </div>
          <div className="inline-flex rounded-lg border border-zinc-800 bg-zinc-900 p-1" role="group" aria-label="Adversary">
            {(["SCRIPTED", "CLAUDE"] as AdversaryAgent[]).map((a) => (
              <button
                key={a}
                onClick={() => setAgent(a)}
                title={
                  a === "SCRIPTED"
                    ? "Deterministic simulated compromised agent (own-lab)"
                    : "Live Claude as the agent — may refuse"
                }
                className={`rounded-md px-3 py-1.5 font-mono text-xs font-semibold transition ${
                  agent === a ? "bg-sky-600 text-white" : "text-zinc-400 hover:text-zinc-200"
                }`}
              >
                {a === "SCRIPTED" ? "⚙ SCRIPTED" : "✦ CLAUDE"}
              </button>
            ))}
          </div>
          <div className="flex gap-2">
            {VECTORS.map((v) => (
              <button
                key={v.id}
                title={v.hint}
                disabled={running !== null}
                onClick={() => run(v.id)}
                className="rounded-md border border-zinc-700 bg-zinc-800 px-3 py-1.5 font-mono text-xs font-semibold hover:border-zinc-500 hover:bg-zinc-700 disabled:opacity-50"
              >
                {running === v.id ? "Running…" : `▶ ${v.label}`}
              </button>
            ))}
          </div>
        </div>
      </header>

      {error && (
        <div className="mb-4 rounded-md border border-red-800 bg-red-950/50 px-4 py-2 font-mono text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        {/* LEFT PANE — inbound handoff + guard */}
        <div className="flex flex-col gap-6">
          <Panel
            title="Incoming manifest (raw, signed)"
            right={result && <span className="font-mono text-[10px] text-zinc-500">{result.vector}</span>}
          >
            {result ? (
              <>
                <Json value={result.manifest} />
                <p className="mt-2 truncate font-mono text-[10px] text-zinc-500">HMAC: {result.signature}</p>
              </>
            ) : (
              <p className="text-sm text-zinc-500">Choose a mode and launch an attack vector.</p>
            )}
          </Panel>

          <Panel title="permittedTools (passed to Anthropic SDK)">
            {result ? (
              <div className="flex flex-wrap gap-2">
                {result.permittedTools.map((t) => (
                  <span key={t} className="rounded border border-emerald-700 bg-emerald-950/60 px-2 py-0.5 font-mono text-xs text-emerald-300">
                    {t}
                  </span>
                ))}
                {result.lockedTools.map((t) => (
                  <span key={t} className="rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 font-mono text-xs text-zinc-500 line-through">
                    🔒 {t}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-zinc-500">—</p>
            )}
          </Panel>

          <Panel
            title="Cross-Domain Guard alerts"
            right={
              result && (
                <div className="flex gap-2 font-mono text-[10px]">
                  <span className={result.guard.tainted ? "text-amber-400" : "text-emerald-400"}>
                    tainted: {String(result.guard.tainted)}
                  </span>
                  <span className={result.guard.enforced ? "text-emerald-400" : "text-red-400"}>
                    {result.guard.enforced ? "ENFORCED" : "OBSERVE-ONLY"}
                  </span>
                </div>
              )
            }
          >
            {result ? (
              <>
                <ul className="space-y-1.5">
                  {result.guard.alerts.map((a, i) => (
                    <li
                      key={i}
                      className={`rounded px-2 py-1 font-mono text-xs ${
                        a.startsWith("AUTH_OK") ? "bg-zinc-800/60 text-zinc-400" : "bg-amber-950/40 text-amber-300"
                      }`}
                    >
                      {a}
                    </li>
                  ))}
                </ul>
                {result.guard.enforced && result.sanitizedPayload && (
                  <div className="mt-4">
                    <p className="mb-1 text-xs text-zinc-500">Sanitized payload (Zod re-serialized):</p>
                    <Json value={result.sanitizedPayload} />
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-zinc-500">—</p>
            )}
          </Panel>
        </div>

        {/* RIGHT PANE — outcome */}
        <div className="flex flex-col gap-6">
          <div
            className={`flex min-h-36 items-center justify-center rounded-lg border-2 px-6 py-8 text-center ${
              !result
                ? "border-zinc-800 bg-zinc-900/40 text-zinc-600"
                : breached
                  ? "border-red-600 bg-red-950/60 text-red-200"
                  : blocked
                    ? "border-emerald-600 bg-emerald-950/50 text-emerald-200"
                    : "border-amber-600 bg-amber-950/40 text-amber-200"
            }`}
          >
            <p className="text-2xl font-black tracking-tight md:text-3xl">
              {result ? result.status : "AWAITING SIMULATION"}
            </p>
          </div>

          {breached && result?.vaultData && (
            <Panel title="Exposed customs_vault row">
              <Json value={result.vaultData} />
            </Panel>
          )}

          {result && (
            <Panel title="Agent tool calls">
              {result.toolCalls.length === 0 ? (
                <p className="text-sm text-zinc-500">No tool calls.{result.refused && " (model refused)"}</p>
              ) : (
                <ul className="space-y-2">
                  {result.toolCalls.map((c, i) => (
                    <li key={i} className="rounded bg-black/40 p-2 font-mono text-xs">
                      <span className={c.blocked ? "text-emerald-400" : "text-sky-300"}>{c.name}</span>
                      <span className="text-zinc-500"> {JSON.stringify(c.input)}</span>
                      <div className="mt-1 break-all text-zinc-400">→ {c.result}</div>
                    </li>
                  ))}
                </ul>
              )}
              {result.transcript.length > 0 && (
                <div className="mt-3 space-y-1 border-t border-zinc-800 pt-3 text-sm text-zinc-300">
                  {result.transcript.map((t, i) => (
                    <p key={i}>{t}</p>
                  ))}
                </div>
              )}
            </Panel>
          )}

          <Panel title="security_audit_log (recent)">
            {auditLog.length === 0 ? (
              <p className="text-sm text-zinc-500">No rows yet.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead className="text-zinc-500">
                    <tr>
                      <th className="py-1 pr-3 font-normal">time</th>
                      <th className="py-1 pr-3 font-normal">mode</th>
                      <th className="py-1 pr-3 font-normal">vector</th>
                      <th className="py-1 pr-3 font-normal">tainted</th>
                      <th className="py-1 pr-3 font-normal">tool</th>
                      <th className="py-1 font-normal">outcome</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLog.map((r) => (
                      <tr key={r.id} className="border-t border-zinc-800/70">
                        <td className="py-1 pr-3 text-zinc-500">{new Date(r.created_at).toLocaleTimeString()}</td>
                        <td className={`py-1 pr-3 ${r.mode === "HARDENED" ? "text-emerald-400" : "text-red-400"}`}>{r.mode}</td>
                        <td className="py-1 pr-3">{r.attack_vector}</td>
                        <td className="py-1 pr-3">{String(r.tainted)}</td>
                        <td className="py-1 pr-3 text-zinc-400">{r.attempted_tool ?? "—"}</td>
                        <td
                          className={`py-1 ${
                            r.outcome_status === "EXFILTRATED"
                              ? "text-red-400"
                              : r.outcome_status === "BLOCKED"
                                ? "text-emerald-400"
                                : "text-amber-400"
                          }`}
                        >
                          {r.outcome_status}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {result?.auditError && <p className="mt-2 font-mono text-xs text-red-400">audit insert: {result.auditError}</p>}
          </Panel>
        </div>
      </div>
    </main>
  );
}
