import { AlertTriangle, FileDigit, Quote } from "lucide-react";
import type { AnalyzeResponse } from "../api/types";

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="font-mono text-[11px] font-semibold tracking-widest text-slate-500">
      {children}
    </h3>
  );
}

/** Badge distinguishing report evidence from AI inference. */
function ProvenanceBadge({ inferred }: { inferred: boolean }) {
  return inferred ? (
    <span className="inline-flex rounded-full bg-amber-glow/15 px-2 py-0.5 font-mono text-[10px] font-medium text-amber-glow ring-1 ring-amber-glow/40 ring-inset">
      AI INFERENCE
    </span>
  ) : (
    <span className="inline-flex rounded-full bg-signal/15 px-2 py-0.5 font-mono text-[10px] font-medium text-signal ring-1 ring-signal/40 ring-inset">
      REPORT EVIDENCE
    </span>
  );
}

function VerifiedBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="inline-flex rounded-full bg-signal/15 px-2 py-0.5 font-mono text-[10px] font-medium text-signal ring-1 ring-signal/40 ring-inset">
      VERIFIED IN REPORT
    </span>
  ) : (
    <span className="inline-flex rounded-full bg-crimson/15 px-2 py-0.5 font-mono text-[10px] font-medium text-crimson ring-1 ring-crimson/40 ring-inset">
      NOT FOUND IN REPORT
    </span>
  );
}

function EvidenceQuote({ quote }: { quote: string }) {
  if (!quote) return null;
  return (
    <p className="mt-1.5 flex gap-1.5 text-xs leading-relaxed text-slate-500">
      <Quote className="h-3 w-3 shrink-0 translate-y-0.5" />
      <span className="font-mono text-[11px] break-words">“{quote}”</span>
    </p>
  );
}

const PRIORITY_STYLE: Record<string, string> = {
  critical: "bg-crimson/15 text-crimson ring-crimson/40",
  high: "bg-orange-400/15 text-orange-300 ring-orange-400/40",
  medium: "bg-amber-glow/15 text-amber-glow ring-amber-glow/40",
  low: "bg-sky-400/15 text-sky-300 ring-sky-400/40",
};

function EmptyNote({ what }: { what: string }) {
  return (
    <p className="text-xs text-slate-500">
      None found in this report — no {what} were invented.
    </p>
  );
}

export default function AnalysisResults({ result }: { result: AnalyzeResponse }) {
  const a = result.analysis;
  return (
    <div className="flex flex-col gap-6">
      {result.warnings.length > 0 && (
        <div className="flex flex-col gap-2 rounded-md border border-amber-glow/30 bg-amber-glow/5 p-4">
          {result.warnings.map((w, i) => (
            <p key={i} className="flex gap-2 text-xs leading-relaxed text-amber-glow">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              {w}
            </p>
          ))}
        </div>
      )}
      {result.truncated && (
        <p className="flex gap-2 text-xs text-slate-400">
          <FileDigit className="h-4 w-4 shrink-0" />
          Report exceeded the analysis window ({result.char_count.toLocaleString()}{" "}
          chars) — only the first portion was analyzed.
        </p>
      )}

      <section>
        <SectionTitle>EXECUTIVE SUMMARY</SectionTitle>
        <p className="mt-2 max-w-3xl text-sm leading-relaxed text-slate-200">
          {a.executive_summary}
        </p>
      </section>

      <section>
        <SectionTitle>ATTACK TECHNIQUES ({a.attack_techniques.length})</SectionTitle>
        <div className="mt-2 flex flex-col gap-3">
          {a.attack_techniques.length === 0 && <EmptyNote what="techniques" />}
          {a.attack_techniques.map((t, i) => (
            <div key={i} className="rounded-md border border-edge bg-abyss p-3">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-[13px] font-semibold text-slate-100">{t.name}</p>
                {t.mitre_id && (
                  <span className="rounded bg-panel-2 px-1.5 py-0.5 font-mono text-[11px] text-slate-300 ring-1 ring-edge ring-inset">
                    {t.mitre_id}
                  </span>
                )}
                <span className="ml-auto">
                  <ProvenanceBadge inferred={t.inferred} />
                </span>
              </div>
              <p className="mt-1 text-xs leading-relaxed text-slate-400">{t.description}</p>
              <EvidenceQuote quote={t.evidence_quote} />
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionTitle>
          INDICATORS OF COMPROMISE ({a.indicators_of_compromise.length})
        </SectionTitle>
        <div className="mt-2 overflow-x-auto rounded-md border border-edge">
          {a.indicators_of_compromise.length === 0 ? (
            <p className="p-3 text-xs text-slate-500">
              None found in this report — no IOCs were invented.
            </p>
          ) : (
            <table className="w-full min-w-[640px] text-left text-xs">
              <thead>
                <tr className="border-b border-edge bg-abyss font-mono text-[10px] tracking-wide text-slate-500">
                  <th className="px-3 py-2 font-medium">VALUE</th>
                  <th className="px-3 py-2 font-medium">TYPE</th>
                  <th className="px-3 py-2 font-medium">SOURCE CHECK</th>
                  <th className="px-3 py-2 font-medium">EVIDENCE</th>
                </tr>
              </thead>
              <tbody>
                {a.indicators_of_compromise.map((ioc, i) => (
                  <tr key={i} className="border-b border-edge/60 align-top last:border-0">
                    <td className="max-w-64 px-3 py-2 font-mono text-[11px] break-all text-slate-200">
                      {ioc.value}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-slate-400">
                      {ioc.type}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <VerifiedBadge verified={ioc.verified_in_source} />
                    </td>
                    <td className="max-w-xs px-3 py-2 font-mono text-[11px] leading-relaxed break-words text-slate-500">
                      {ioc.evidence_quote || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </section>

      <section>
        <SectionTitle>CVES ({a.cves.length})</SectionTitle>
        <div className="mt-2 flex flex-col gap-2">
          {a.cves.length === 0 && <EmptyNote what="CVEs" />}
          {a.cves.map((cve, i) => (
            <div
              key={i}
              className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded-md border border-edge bg-abyss p-3"
            >
              <span className="font-mono text-xs font-semibold text-slate-100">
                {cve.id}
              </span>
              <VerifiedBadge verified={cve.verified_in_source} />
              {cve.description && (
                <p className="w-full text-xs leading-relaxed text-slate-400">
                  {cve.description}
                </p>
              )}
              {cve.evidence_quote && (
                <div className="w-full">
                  <EvidenceQuote quote={cve.evidence_quote} />
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionTitle>AFFECTED SYSTEMS ({a.affected_systems.length})</SectionTitle>
        <div className="mt-2 flex flex-col gap-2">
          {a.affected_systems.length === 0 && <EmptyNote what="affected systems" />}
          {a.affected_systems.map((s, i) => (
            <div key={i} className="rounded-md border border-edge bg-abyss p-3">
              <div className="flex flex-wrap items-center gap-2">
                <p className="text-[13px] font-semibold text-slate-100">{s.system}</p>
                <span className="ml-auto">
                  <ProvenanceBadge inferred={s.inferred} />
                </span>
              </div>
              {s.detail && (
                <p className="mt-1 text-xs leading-relaxed text-slate-400">{s.detail}</p>
              )}
              <EvidenceQuote quote={s.evidence_quote} />
            </div>
          ))}
        </div>
      </section>

      <section>
        <SectionTitle>RECOMMENDATIONS ({a.recommendations.length})</SectionTitle>
        <ol className="mt-2 flex list-decimal flex-col gap-2 pl-5">
          {a.recommendations.map((r, i) => (
            <li key={i} className="text-xs leading-relaxed text-slate-300">
              <span className="font-medium text-slate-100">{r.recommendation}</span>{" "}
              <span
                className={`inline-flex rounded-full px-2 py-0.5 font-mono text-[10px] font-medium ring-1 ring-inset ${PRIORITY_STYLE[r.priority]}`}
              >
                {r.priority.toUpperCase()}
              </span>
              {r.rationale && <p className="mt-0.5 text-slate-500">{r.rationale}</p>}
            </li>
          ))}
        </ol>
      </section>

      {a.supporting_evidence.length > 0 && (
        <section>
          <SectionTitle>SUPPORTING EVIDENCE</SectionTitle>
          <div className="mt-2 flex flex-col gap-2">
            {a.supporting_evidence.map((e, i) => (
              <figure
                key={i}
                className="rounded-md border border-edge bg-abyss p-3"
              >
                <blockquote className="font-mono text-[11px] leading-relaxed break-words text-slate-300">
                  “{e.quote}”
                </blockquote>
                <figcaption className="mt-1 text-xs text-slate-500">
                  {e.relevance}
                </figcaption>
              </figure>
            ))}
          </div>
        </section>
      )}

      <p className="border-t border-edge pt-3 font-mono text-[11px] leading-relaxed text-slate-500">
        AI-GENERATED ANALYSIS VIA {result.model.toUpperCase()} — VERIFY FINDINGS
        BEFORE ACTING. ITEMS MARKED “NOT FOUND IN REPORT” COULD NOT BE
        CONFIRMED AGAINST THE UPLOADED DOCUMENT.
      </p>
    </div>
  );
}
