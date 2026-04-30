import { useMemo, useState } from "react";
import type { EvidenceRow, PrioritizeResponse, SignalBreakdown } from "./types";

const API_BASE: string =
  ((import.meta as any)?.env?.VITE_API_BASE as string | undefined) ?? "http://127.0.0.1:8000";

async function prioritizeQuery(query: string): Promise<PrioritizeResponse> {
  const response = await fetch(`${API_BASE}/prioritize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ query })
  });
  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(errorText || "Request failed");
  }
  return (await response.json()) as PrioritizeResponse;
}

function toolDisplayName(tool: string | null | undefined): string {
  if (tool === "release_train_api") return "ReleaseTrain";
  if (tool === "google_news_rss") return "Google News";
  return tool || "—";
}

function kindLabel(kind: string): string {
  if (kind === "cve") return "CVE";
  if (kind === "release_note") return "Release";
  if (kind === "news") return "News";
  return kind;
}

function kindColor(kind: string): string {
  if (kind === "cve") return "bg-rose-500/20 text-rose-300 border-rose-500/30";
  if (kind === "release_note") return "bg-emerald-500/20 text-emerald-300 border-emerald-500/30";
  return "bg-sky-500/20 text-sky-300 border-sky-500/30";
}

function severityColor(severity: string | undefined): string {
  const s = (severity || "").toUpperCase();
  if (s === "CRITICAL") return "text-rose-400 font-semibold";
  if (s === "HIGH") return "text-orange-400 font-semibold";
  if (s === "MEDIUM") return "text-yellow-400";
  return "text-slate-400";
}

function SignalMixBar({ sb }: { sb?: SignalBreakdown }) {
  if (!sb || sb.label === "no_evidence") return null;
  return (
    <div className="mt-2 flex h-1.5 overflow-hidden rounded-full bg-slate-800">
      <div style={{ width: `${sb.cve_pct}%` }} className="bg-rose-500" title={`CVE ${sb.cve_pct}%`} />
      <div style={{ width: `${sb.release_pct}%` }} className="bg-emerald-500" title={`Release ${sb.release_pct}%`} />
      <div style={{ width: `${sb.news_pct}%` }} className="bg-sky-500" title={`News ${sb.news_pct}%`} />
    </div>
  );
}

function EvidenceCard({ ev }: { ev: EvidenceRow }) {
  return (
    <div className={`rounded-lg border p-3 text-xs ${kindColor(ev.kind)}`}>
      <div className="flex flex-wrap items-center gap-1.5 mb-1.5">
        <span className="rounded border px-1.5 py-0.5 font-mono text-[10px] bg-black/30">{ev.ref}</span>
        <span className="rounded-full px-2 py-0.5 text-[10px] border font-medium">{kindLabel(ev.kind)}</span>
        <span className="text-[10px] opacity-60">{toolDisplayName(ev.source_tool)}</span>
        {ev.severity && (
          <span className={`text-[10px] ml-auto ${severityColor(ev.severity)}`}>{ev.severity}</span>
        )}
      </div>
      <p className="text-slate-200 leading-snug">{ev.title}</p>
      {ev.link && (
        <a
          href={ev.link}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-1.5 inline-flex items-center gap-1 text-[10px] text-brand-400 hover:text-brand-300 hover:underline"
        >
          ↗ View source
        </a>
      )}
    </div>
  );
}

// Supporting news panel (not used by LLM, just links)
function NewsPanel({ news }: { news: Array<{ title?: string; link?: string; source?: string; published?: string }> }) {
  if (!news || news.length === 0) return null;
  return (
    <div className="mt-4 rounded-xl border border-orange-900/30 bg-orange-950/10 p-3">
      <p className="text-xs font-semibold uppercase tracking-wide text-brand-400 mb-2">Supporting News ({news.length})</p>
      <div className="space-y-1.5 max-h-48 overflow-y-auto">
        {news.slice(0, 8).map((n, i) => (
          <div key={i} className="flex items-start gap-2">
            <span className="mt-0.5 text-[10px] text-slate-600">▸</span>
            <div>
              {n.link ? (
                <a href={n.link} target="_blank" rel="noopener noreferrer"
                  className="text-xs text-slate-300 hover:text-brand-300 hover:underline leading-snug">
                  {n.title}
                </a>
              ) : (
                <p className="text-xs text-slate-400">{n.title}</p>
              )}
              {n.source && <p className="text-[10px] text-slate-600">{n.source}</p>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

type Message = { role: "user" | "assistant"; text: string };

const SUGGESTIONS = [
  "Which Linux components should I update first this week?",
  "Prioritize urgent OpenSSL and kernel updates for production servers.",
  "What software should be patched first for Kubernetes worker nodes?"
];

function App() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [result, setResult] = useState<PrioritizeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const signalCounts = useMemo(() => {
    if (!result?.merged) return null;
    return {
      cves: result.merged.cves?.length ?? 0,
      releaseNotes: result.merged.release_notes?.length ?? 0,
      news: result.merged.news?.length ?? 0
    };
  }, [result]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    const cleaned = query.trim();
    if (!cleaned || loading) return;
    setError(null);
    setLoading(true);
    setMessages((prev) => [...prev, { role: "user", text: cleaned }]);
    setQuery("");
    try {
      const data = await prioritizeQuery(cleaned);
      setResult(data);
      setMessages((prev) => [
        ...prev,
        { role: "assistant", text: data.merged?.llm_summary || "Analysis complete." }
      ]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unexpected error");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="motion-bg min-h-screen text-slate-100 relative">
      <div className="relative z-10 mx-auto flex w-full max-w-6xl flex-col gap-5 p-4 md:p-8">

        {/* Header */}
        <header className="rounded-2xl border border-orange-900/40 bg-black/60 p-5 shadow-glow backdrop-blur">
          <p className="text-xs uppercase tracking-wider text-brand-400">LangGraph + Groq + NVD</p>
          <h1 className="mt-1 text-2xl font-semibold md:text-3xl">Software Update Prioritizer</h1>
          <p className="mt-1.5 text-sm text-slate-400">
            Agentic AI pipeline: orchestrates Reddit context → enriches keywords → fetches NVD CVEs + ReleaseTrain → LLM ranks with evidence.
          </p>
        </header>

        {/* Agent trace */}
        {result?.merged?.agent_pipeline ? (
          <section className="rounded-2xl border border-orange-900/30 bg-black/50 p-4">
            <h2 className="text-xs font-semibold uppercase tracking-wide text-brand-400 mb-3">Agent pipeline trace</h2>
            <ol className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-6">
              {result.merged.agent_pipeline.map((step, i) => (
                <li key={step.id} className="rounded-xl border border-orange-900/30 bg-black/40 p-2.5">
                  <p className="text-[10px] uppercase text-slate-600">{step.role.replace(/_/g, " ")}</p>
                  <p className="mt-0.5 text-xs font-semibold text-brand-400">{i + 1}. {step.label}</p>
                  <p className="mt-1 text-[10px] leading-snug text-slate-500">{step.detail}</p>
                </li>
              ))}
            </ol>
          </section>
        ) : null}

        <main className="grid grid-cols-1 gap-5 lg:grid-cols-3">

          {/* Chat panel */}
          <section className="rounded-2xl border border-orange-900/40 bg-black/60 p-4 lg:col-span-2 backdrop-blur">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-base font-semibold">Chat</h2>
              {loading && (
                <span className="flex items-center gap-1.5 text-xs text-brand-400">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-brand-400 animate-pulse" />
                  Analyzing...
                </span>
              )}
            </div>

            <div className="mb-4 h-[300px] space-y-3 overflow-y-auto rounded-xl bg-black/50 p-3 md:h-[380px]">
              {messages.length === 0 ? (
                <p className="text-sm text-slate-500">Ask about software vulnerabilities or patch urgency.</p>
              ) : null}
              {messages.map((m, idx) => (
                <div key={idx} className={`max-w-[90%] rounded-xl p-3 text-sm leading-relaxed ${
                  m.role === "user"
                    ? "ml-auto bg-brand-600 text-white"
                    : "bg-slate-900/80 border border-orange-900/30 text-slate-100"
                }`}>
                  {m.text}
                </div>
              ))}
            </div>

            <form onSubmit={onSubmit} className="space-y-3">
              <textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. Do I need to patch Nvidia drivers?"
                className="w-full rounded-xl border border-orange-900/40 bg-black/60 p-3 text-sm outline-none placeholder:text-slate-600 focus:border-brand-500 focus:ring-1 focus:ring-brand-500/50 transition"
                rows={3}
              />
              <div className="flex flex-wrap gap-2">
                {SUGGESTIONS.map((item) => (
                  <button key={item} type="button" onClick={() => setQuery(item)}
                    className="rounded-full border border-orange-900/40 px-3 py-1 text-xs text-slate-400 hover:border-brand-500 hover:text-brand-400 transition">
                    {item}
                  </button>
                ))}
              </div>
              <button type="submit" disabled={loading}
                className="w-full rounded-xl bg-brand-500 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-brand-400 disabled:cursor-not-allowed disabled:opacity-40">
                {loading ? "Running pipeline..." : "Prioritize Updates"}
              </button>
            </form>
            {error ? <p className="mt-3 text-sm text-rose-400">{error}</p> : null}
          </section>

          {/* Ranked output panel */}
          <section className="rounded-2xl border border-orange-900/40 bg-black/60 p-4 backdrop-blur overflow-y-auto max-h-[680px]">
            <h2 className="text-base font-semibold">Ranked Output</h2>
            <p className="mt-0.5 text-[11px] text-slate-500">Prioritized by CVE severity · NVD + ReleaseTrain sources</p>

            {result?.merged?.evidence_provenance_summary ? (
              <div className="mt-2 flex gap-3 text-[10px] text-slate-600">
                <span>prioritizer {result.merged.evidence_provenance_summary.llm ?? 0}</span>
                <span>repair {result.merged.evidence_provenance_summary.repair_llm ?? 0}</span>
                <span>auto {result.merged.evidence_provenance_summary.deterministic ?? 0}</span>
                <span>none {result.merged.evidence_provenance_summary.none ?? 0}</span>
              </div>
            ) : null}

            {!result ? (
              <p className="mt-4 text-sm text-slate-500">Results appear here after analysis.</p>
            ) : result.ranked.length === 0 ? (
              <p className="mt-4 text-sm text-slate-500">No ranked items — insufficient CVE or release data.</p>
            ) : (
              <div className="mt-3 space-y-3">
                {result.ranked.map((item) => (
                  <article key={`${item.rank}-${item.software}`}
                    className="rounded-xl border border-orange-900/30 bg-black/50 p-3">

                    {/* Title row */}
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-semibold text-slate-100">
                        <span className="text-brand-400 mr-1">#{item.rank}</span>{item.software}
                      </p>
                      <div className="flex gap-1">
                        {item.grounded === false && (
                          <span className="rounded-full bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 text-[10px] text-amber-400">
                            Unverified
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Signal bar */}
                    <SignalMixBar sb={item.signal_breakdown} />

                    {/* Action */}
                    <p className="mt-2 text-xs font-medium text-brand-300">{item.suggested_action}</p>

                    {/* Reasons */}
                    <ul className="mt-1.5 space-y-0.5">
                      {item.reasons.map((reason, i) => (
                        <li key={i} className="flex items-start gap-1.5 text-xs text-slate-400">
                          <span className="mt-0.5 text-brand-500">•</span>{reason}
                        </li>
                      ))}
                    </ul>

                    {/* Evidence — collapsed by default */}
                    {item.evidence && item.evidence.length > 0 && (
                      <details className="mt-2.5">
                        <summary className="cursor-pointer text-[11px] text-slate-500 hover:text-brand-400 transition select-none">
                          ▸ {item.evidence.length} evidence {item.evidence.length === 1 ? "item" : "items"}
                        </summary>
                        <div className="mt-2 space-y-2">
                          {item.evidence.map((ev) => (
                            <EvidenceCard key={ev.ref} ev={ev} />
                          ))}
                        </div>
                      </details>
                    )}
                  </article>
                ))}
              </div>
            )}

            {/* Supporting news */}
            {result?.merged?.news && result.merged.news.length > 0 && (
              <NewsPanel news={result.merged.news} />
            )}
          </section>
        </main>

        {/* Signal counters */}
        {result ? (
          <section className="grid grid-cols-3 gap-3">
            {[
              { label: "CVE Signals", value: signalCounts?.cves ?? 0, color: "text-rose-400" },
              { label: "Release Notes", value: signalCounts?.releaseNotes ?? 0, color: "text-emerald-400" },
              { label: "News Mentions", value: signalCounts?.news ?? 0, color: "text-sky-400" }
            ].map((s) => (
              <div key={s.label} className="rounded-xl border border-orange-900/30 bg-black/50 p-3">
                <p className="text-[10px] uppercase tracking-wide text-slate-500">{s.label}</p>
                <p className={`mt-1 text-2xl font-bold ${s.color}`}>{s.value}</p>
              </div>
            ))}
          </section>
        ) : null}
      </div>
    </div>
  );
}

export default App;
