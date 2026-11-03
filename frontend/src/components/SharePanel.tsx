import { useMemo, useState } from "react";
import {
  ArrowLeft,
  Download,
  FileDown,
  FileJson,
  Loader2,
  Plus,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  ApiError,
  downloadSharePdf,
  exportPackageStix,
  prepareShare,
} from "../api/client";
import { downloadBlob, downloadJson } from "../api/download";
import { TLP_LEVELS, mostRestrictive, tlpAudience, tlpLevel } from "../api/tlp";
import type {
  AnalyzeResponse,
  SharePrepareResponse,
  ShareRedaction,
} from "../api/types";
import AnalysisResults from "./AnalysisResults";
import MispPanel from "./MispPanel";

interface SourceRow {
  name: string;
  marking: string; // "" means unmarked
}

type Phase = "compose" | "preparing" | "preview" | "error";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-md border border-edge bg-abyss p-4">
      <h3 className="font-mono text-[11px] font-semibold tracking-widest text-slate-400">
        {title}
      </h3>
      <div className="mt-3 flex flex-col gap-2">{children}</div>
    </section>
  );
}

function TlpSelect({
  label,
  value,
  onChange,
  allowUnmarked,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  allowUnmarked?: boolean;
}) {
  return (
    <label className="flex flex-col gap-1 text-xs text-slate-400">
      {label}
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
      >
        {allowUnmarked && <option value="">Unmarked</option>}
        {TLP_LEVELS.map((l) => (
          <option key={l.marking} value={l.marking}>
            {l.marking}
          </option>
        ))}
      </select>
    </label>
  );
}

function CheckRow({
  label,
  title,
  meta,
  quote,
  checked,
  onChange,
}: {
  label: string;
  title: string;
  meta?: string;
  quote?: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <div className="rounded-md border border-edge bg-panel px-3 py-2">
      <label className="flex cursor-pointer items-start gap-2">
        <input
          type="checkbox"
          aria-label={label}
          checked={checked}
          onChange={(e) => onChange(e.target.checked)}
          className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-emerald-400"
        />
        <span className="min-w-0">
          <span className="block truncate text-[13px] text-slate-200">{title}</span>
          {meta && (
            <span className="block font-mono text-[11px] text-slate-500">{meta}</span>
          )}
        </span>
      </label>
      {quote && (
        <p className="mt-1 border-l-2 border-edge pl-2 font-mono text-[11px] leading-relaxed break-words text-slate-500">
          “{quote}”
        </p>
      )}
    </div>
  );
}

function shareErrorText(error: ApiError): { title: string; hint: string } {
  switch (error.code) {
    case "classification_required":
      return { title: "Source classification required.", hint: error.message };
    case "approval_required":
      return { title: "Analyst approval required.", hint: error.message };
    case "downgrade_attempt":
      return { title: "Downgrade blocked.", hint: error.message };
    case "invalid_tlp":
      return { title: "Invalid TLP marking.", hint: error.message };
    case "invalid_selection":
    case "empty_selection":
      return { title: "Invalid selection.", hint: error.message };
    default:
      return { title: "Sharing preparation failed.", hint: error.message };
  }
}

export default function SharePanel({
  result,
  role,
  onClose,
}: {
  result: AnalyzeResponse;
  role: string;
  onClose: () => void;
}) {
  const a = result.analysis;
  const [sources, setSources] = useState<SourceRow[]>([
    { name: result.filename, marking: "" },
  ]);
  const [analystMarking, setAnalystMarking] = useState("");
  const [proposed, setProposed] = useState("TLP:AMBER");
  const [includeSummary, setIncludeSummary] = useState(true);
  const [tech, setTech] = useState(() => a.attack_techniques.map(() => true));
  const [iocs, setIocs] = useState(() => a.indicators_of_compromise.map(() => true));
  const [cves, setCves] = useState(() => a.cves.map(() => true));
  const [systems, setSystems] = useState(() => a.affected_systems.map(() => true));
  const [recs, setRecs] = useState(() => a.recommendations.map(() => true));
  const [evidence, setEvidence] = useState(() => a.supporting_evidence.map(() => true));
  const [redactions, setRedactions] = useState<ShareRedaction[]>([]);
  const [approved, setApproved] = useState(false);
  const [justification, setJustification] = useState("");
  const [downgradeAccepted, setDowngradeAccepted] = useState(false);
  const [audienceNote, setAudienceNote] = useState("");
  const [analystNotes, setAnalystNotes] = useState("");
  const [phase, setPhase] = useState<Phase>("compose");
  const [preview, setPreview] = useState<SharePrepareResponse | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [stixBusy, setStixBusy] = useState(false);
  const [stixError, setStixError] = useState<string | null>(null);
  const [stixSummary, setStixSummary] = useState<string | null>(null);

  const marked = useMemo(() => sources.filter((s) => s.marking).map((s) => s.marking), [sources]);
  const undetermined = sources.some((s) => !s.marking) && !analystMarking;
  const effective = useMemo(
    () => mostRestrictive(analystMarking ? [...marked, analystMarking] : marked),
    [marked, analystMarking],
  );
  const downgrade =
    effective !== null && tlpLevel(proposed) >= 0 && tlpLevel(proposed) < tlpLevel(effective);
  const analystBelowKnown =
    !!analystMarking &&
    marked.length > 0 &&
    tlpLevel(analystMarking) < Math.max(...marked.map(tlpLevel));
  const selectedCount =
    (includeSummary ? 1 : 0) +
    [tech, iocs, cves, systems, recs, evidence].reduce(
      (n, arr) => n + arr.filter(Boolean).length,
      0,
    );
  const emptyRedaction = redactions.some((r) => !r.match.trim());
  const unnamedSource = sources.some((s) => !s.name.trim());

  const blockers: string[] = [];
  if (undetermined) blockers.push("Classify the unmarked source material.");
  if (analystBelowKnown)
    blockers.push("Analyst classification is below an observed marking.");
  if (unnamedSource) blockers.push("Every source needs a name.");
  if (selectedCount === 0) blockers.push("Select at least one finding.");
  if (emptyRedaction) blockers.push("Every redaction needs a match string.");
  if (!approved) blockers.push("Tick the approval checkbox.");
  if (downgrade && !downgradeAccepted)
    blockers.push("Accept the downgrade explicitly.");
  if (downgrade && justification.trim().length < 10)
    blockers.push("Downgrade justification needs at least 10 characters.");
  const canPrepare = blockers.length === 0;

  function toggle(list: boolean[], i: number, set: (v: boolean[]) => void) {
    const next = [...list];
    next[i] = !next[i];
    set(next);
  }
  function setAll(list: boolean[], set: (v: boolean[]) => void, value: boolean) {
    set(list.map(() => value));
  }

  async function handlePrepare() {
    setPhase("preparing");
    setError(null);
    try {
      const res = await prepareShare({
        analysis: result,
        sources: sources.map((s) => ({
          name: s.name.trim(),
          marking: s.marking || null,
        })),
        analyst_source_marking: analystMarking || null,
        proposed_marking: proposed,
        selection: {
          include_summary: includeSummary,
          techniques: tech.flatMap((on, i) => (on ? [i] : [])),
          iocs: a.indicators_of_compromise.flatMap((item, i) => (iocs[i] ? [item.value] : [])),
          cves: a.cves.flatMap((c, i) => (cves[i] ? [c.id] : [])),
          systems: a.affected_systems.flatMap((s, i) => (systems[i] ? [s.system] : [])),
          recommendations: recs.flatMap((on, i) => (on ? [i] : [])),
          evidence: evidence.flatMap((on, i) => (on ? [i] : [])),
        },
        redactions: redactions.map((r) => ({
          match: r.match,
          replacement: r.replacement || "[REDACTED]",
        })),
        approval: {
          approved,
          analyst: "",
          justification: justification.trim(),
          downgrade_accepted: downgradeAccepted,
        },
        audience_note: audienceNote.trim(),
        analyst_notes: analystNotes.trim(),
      });
      setPreview(res);
      setPhase("preview");
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err
          : new ApiError(0, "unknown_error", "Sharing preparation failed.", null),
      );
      setPhase("error");
    }
  }

  if (phase === "preparing") {
    return (
      <section className="rounded-lg border border-edge bg-panel p-5">
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-signal" />
          <p className="text-sm font-medium text-slate-200">Preparing classified package…</p>
          <p className="font-mono text-[11px] text-slate-500">
            VALIDATING MARKINGS · APPLYING SELECTION · RECORDING AUDIT
          </p>
        </div>
      </section>
    );
  }

  if (phase === "error" && error) {
    const friendly = shareErrorText(error);
    return (
      <section className="rounded-lg border border-crimson/40 bg-panel p-5">
        <div className="flex items-center gap-2">
          <TriangleAlert className="h-5 w-5 text-crimson" />
          <h2 className="text-sm font-semibold text-white">{friendly.title}</h2>
        </div>
        <p className="mt-2 text-xs leading-relaxed text-slate-400">{friendly.hint}</p>
        <p className="mt-1 font-mono text-[11px] text-slate-500">
          {error.code} · HTTP {error.status}
        </p>
        <div className="mt-3 flex gap-2">
          <button
            type="button"
            onClick={() => setPhase("compose")}
            className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-3 py-1.5 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to review
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md px-3 py-1.5 font-mono text-[11px] text-slate-500 hover:bg-panel-2 hover:text-slate-200"
          >
            CLOSE
          </button>
        </div>
      </section>
    );
  }

  async function handlePdfDownload() {
    if (!preview) return;
    setPdfBusy(true);
    setPdfError(null);
    try {
      const { filename, blob } = await downloadSharePdf(preview, "");
      downloadBlob(filename, blob);
    } catch (err) {
      setPdfError(err instanceof ApiError ? err.message : "PDF export failed.");
    } finally {
      setPdfBusy(false);
    }
  }

  async function handleStixDownload() {
    if (!preview) return;
    setStixBusy(true);
    setStixError(null);
    setStixSummary(null);
    try {
      const res = await exportPackageStix(preview, "");
      downloadJson(res.filename, res.bundle);
      const total = Object.values(res.object_counts).reduce((a, b) => a + b, 0);
      setStixSummary(`STIX bundle: ${total} objects, TLP marking applied.`);
    } catch (err) {
      setStixError(err instanceof ApiError ? err.message : "STIX export failed.");
    } finally {
      setStixBusy(false);
    }
  }

  if (phase === "preview" && preview) {
    const c = preview.classification;
    return (
      <section className="rounded-lg border border-signal/40 bg-panel p-5">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-signal" />
          <h2 className="text-sm font-semibold text-white">Prepared package — preview</h2>
          <span className="rounded-full bg-panel-2 px-2.5 py-0.5 font-mono text-[11px] text-slate-300 ring-1 ring-edge ring-inset">
            {c.effective_source} → {c.proposed}
          </span>
          {c.downgrade && (
            <span className="rounded-full bg-amber-glow/15 px-2.5 py-0.5 font-mono text-[11px] text-amber-glow ring-1 ring-amber-glow/40 ring-inset">
              DOWNGRADE — APPROVED
            </span>
          )}
          <span className="ml-auto flex flex-wrap gap-2">
            <button
              type="button"
              onClick={handlePdfDownload}
              disabled={pdfBusy}
              title="Download classified PDF report"
              className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:opacity-60"
            >
              {pdfBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileDown className="h-3.5 w-3.5" />}
              PDF REPORT
            </button>
            <button
              type="button"
              onClick={handleStixDownload}
              disabled={stixBusy}
              title="Download TLP-marked STIX 2.1 bundle"
              className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:opacity-60"
            >
              {stixBusy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FileJson className="h-3.5 w-3.5" />}
              STIX BUNDLE
            </button>
            <button
              type="button"
              onClick={() =>
                downloadJson(`threatlens-share-${preview.package_id.slice(0, 8)}.json`, preview)
              }
              className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70"
            >
              <Download className="h-3.5 w-3.5" />
              PACKAGE JSON
            </button>
            <button
              type="button"
              onClick={() => setPhase("compose")}
              className="rounded-md px-2 py-1 font-mono text-[11px] text-slate-500 hover:bg-panel-2 hover:text-slate-200"
            >
              EDIT
            </button>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close sharing panel"
              className="rounded-md p-1 text-slate-500 hover:bg-panel-2 hover:text-slate-200"
            >
              <X className="h-4 w-4" />
            </button>
          </span>
        </div>

        <div className="mt-3 rounded-md border border-edge bg-abyss p-3">
          <p className="font-mono text-[11px] tracking-wide text-slate-500">PERMITTED AUDIENCE</p>
          <p className="mt-1 text-xs leading-relaxed text-slate-300">{preview.audience}</p>
          {preview.audience_note && (
            <p className="mt-1 text-xs text-slate-400">Note: {preview.audience_note}</p>
          )}
        </div>

        {preview.warnings.length > 0 && (
          <div className="mt-3 flex flex-col gap-2 rounded-md border border-amber-glow/30 bg-amber-glow/5 p-3">
            {preview.warnings.map((w, i) => (
              <p key={i} className="flex gap-2 text-xs leading-relaxed text-amber-glow">
                <TriangleAlert className="h-4 w-4 shrink-0" />
                {w}
              </p>
            ))}
          </div>
        )}

        {(pdfError || stixError || stixSummary) && (
          <p className="mt-3 font-mono text-[11px] text-slate-400">
            {pdfError && <span className="text-crimson">PDF: {pdfError} </span>}
            {stixError && <span className="text-crimson">STIX: {stixError} </span>}
            {stixSummary && <span className="text-signal">{stixSummary}</span>}
          </p>
        )}
        {preview.analyst_notes && (
          <div className="mt-3 rounded-md border border-edge bg-abyss p-3">
            <p className="font-mono text-[11px] tracking-wide text-slate-500">ANALYST NOTES</p>
            <p className="mt-1 text-xs leading-relaxed whitespace-pre-wrap text-slate-300">
              {preview.analyst_notes}
            </p>
          </div>
        )}

        <p className="mt-3 font-mono text-[11px] text-slate-500">
          {preview.redactions_applied} REDACTION(S) APPLIED · PACKAGE {preview.package_id.slice(0, 8)} ·
          AUDIT {preview.audit_id.slice(0, 8)}
        </p>
        <div className="mt-3">
          <AnalysisResults
            result={{ ...result, analysis: preview.content, warnings: [] }}
          />
        </div>
        <MispPanel pkg={preview} role={role} />
        <p className="mt-3 border-t border-edge pt-3 font-mono text-[11px] text-slate-500">
          PREPARED PACKAGE — NOTHING HAS BEEN PUBLISHED. MISP DRAFTS ARE
          UNPUBLISHED UNTIL YOU EXPLICITLY PUBLISH THEM.
        </p>
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-edge bg-panel p-5" aria-label="Share intelligence">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-5 w-5 text-amber-glow" />
        <h2 className="text-sm font-semibold text-white">Share intelligence</h2>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close sharing panel"
          className="ml-auto rounded-md p-1 text-slate-500 hover:bg-panel-2 hover:text-slate-200"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      {undetermined ? (
        <p className="mt-3 rounded-md border border-crimson/40 bg-crimson/5 p-3 font-mono text-[11px] leading-relaxed text-crimson">
          UNCLASSIFIED — REVIEW REQUIRED: SOURCE MATERIAL HAS NO TLP MARKING. NOTHING IS
          ASSUMED CLEAR; SELECT AN ANALYST CLASSIFICATION TO PROCEED.
        </p>
      ) : (
        <p className="mt-3 rounded-md border border-edge bg-abyss p-3 font-mono text-[11px] leading-relaxed text-slate-400">
          EFFECTIVE SOURCE: {effective}
          {analystMarking ? " (ANALYST-ASSERTED)" : ""} · PROPOSED: {proposed}
          {downgrade ? " · DOWNGRADE" : ""}
        </p>
      )}
      {analystBelowKnown && (
        <p className="mt-2 font-mono text-[11px] text-crimson">
          Analyst classification is below an observed source marking — only the originator
          may downgrade a marking.
        </p>
      )}

      <div className="mt-3 flex flex-col gap-3">
        <Section title="1 · SOURCE MARKINGS">
          {sources.map((s, i) => (
            <div key={i} className="flex items-end gap-2">
              <label className="flex flex-1 flex-col gap-1 text-xs text-slate-400">
                Source {i + 1}
                <input
                  type="text"
                  aria-label={`Source ${i + 1} name`}
                  value={s.name}
                  onChange={(e) => {
                    const next = [...sources];
                    next[i] = { ...s, name: e.target.value };
                    setSources(next);
                  }}
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
                />
              </label>
              <TlpSelect
                label="Marking"
                value={s.marking}
                allowUnmarked
                onChange={(marking) => {
                  const next = [...sources];
                  next[i] = { ...s, marking };
                  setSources(next);
                }}
              />
              {sources.length > 1 && (
                <button
                  type="button"
                  aria-label={`Remove source ${i + 1}`}
                  onClick={() => setSources(sources.filter((_, j) => j !== i))}
                  className="rounded-md p-2 text-slate-500 hover:bg-panel-2 hover:text-slate-200"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </div>
          ))}
          <div className="flex flex-wrap items-end gap-2">
            <button
              type="button"
              onClick={() => setSources([...sources, { name: "", marking: "" }])}
              className="inline-flex items-center gap-1 rounded-md border border-edge bg-panel-2 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white"
            >
              <Plus className="h-3.5 w-3.5" /> Add source
            </button>
            <TlpSelect
              label="Analyst classification (required when any source is unmarked)"
              value={analystMarking}
              allowUnmarked
              onChange={setAnalystMarking}
            />
          </div>
        </Section>

        <Section title="2 · PROPOSED OUTPUT MARKING">
          <div className="flex flex-col gap-1.5" role="radiogroup" aria-label="Proposed marking">
            {TLP_LEVELS.map((l) => (
              <label
                key={l.marking}
                className={`flex cursor-pointer items-start gap-2 rounded-md border px-3 py-2 ${
                  proposed === l.marking
                    ? "border-signal/50 bg-signal-dim/30"
                    : "border-edge bg-panel hover:border-slate-500"
                }`}
              >
                <input
                  type="radio"
                  name="proposed-marking"
                  value={l.marking}
                  aria-label={`Proposed marking ${l.marking}`}
                  checked={proposed === l.marking}
                  onChange={() => setProposed(l.marking)}
                  className="mt-0.5 accent-emerald-400"
                />
                <span>
                  <span className="block font-mono text-xs font-semibold text-slate-100">
                    {l.marking}
                  </span>
                  <span className="block text-[11px] leading-relaxed text-slate-500">
                    {l.audience}
                  </span>
                </span>
              </label>
            ))}
          </div>
          {downgrade && (
            <p className="font-mono text-[11px] leading-relaxed text-amber-glow">
              DOWNGRADE: {effective} → {proposed}. EXPLICIT ACCEPTANCE AND JUSTIFICATION
              REQUIRED BELOW. NOTHING IS DOWNGRADED AUTOMATICALLY.
            </p>
          )}
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Audience note (optional)
            <input
              type="text"
              value={audienceNote}
              onChange={(e) => setAudienceNote(e.target.value)}
              placeholder="e.g. Energy ISAC TLP:GREEN channel"
              className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
            />
          </label>
        </Section>

        <Section title="3 · SELECT FINDINGS (EVIDENCE SHOWN FOR REVIEW)">
          <label className="flex cursor-pointer items-center gap-2 text-[13px] text-slate-200">
            <input
              type="checkbox"
              aria-label="Include executive summary"
              checked={includeSummary}
              onChange={(e) => setIncludeSummary(e.target.checked)}
              className="h-3.5 w-3.5 accent-emerald-400"
            />
            Executive summary
          </label>

          {(
            [
              ["Attack techniques", a.attack_techniques.length, tech, setTech],
              ["Indicators", a.indicators_of_compromise.length, iocs, setIocs],
              ["CVEs", a.cves.length, cves, setCves],
              ["Systems", a.affected_systems.length, systems, setSystems],
              ["Recommendations", a.recommendations.length, recs, setRecs],
              ["Evidence", a.supporting_evidence.length, evidence, setEvidence],
            ] as const
          ).map(([title, total, list, set]) => (
            <div key={title} className="flex items-center gap-2">
              <span className="text-xs font-medium text-slate-300">
                {title} ({list.filter(Boolean).length}/{total})
              </span>
              <span className="ml-auto flex gap-1">
                <button
                  type="button"
                  onClick={() => setAll(list, set, true)}
                  className="rounded px-1.5 py-0.5 font-mono text-[10px] text-slate-500 hover:bg-panel-2 hover:text-slate-200"
                >
                  ALL
                </button>
                <button
                  type="button"
                  onClick={() => setAll(list, set, false)}
                  className="rounded px-1.5 py-0.5 font-mono text-[10px] text-slate-500 hover:bg-panel-2 hover:text-slate-200"
                >
                  NONE
                </button>
              </span>
            </div>
          ))}

          <div className="flex max-h-72 flex-col gap-1.5 overflow-y-auto pr-1">
            {a.attack_techniques.map((t, i) => (
              <CheckRow
                key={`t${i}`}
                label={`Include technique ${t.name}`}
                title={t.name}
                meta={`${t.mitre_id ?? "no MITRE ID"}${t.inferred ? " · AI inference" : ""}`}
                quote={t.evidence_quote}
                checked={tech[i]}
                onChange={() => toggle(tech, i, setTech)}
              />
            ))}
            {a.indicators_of_compromise.map((item, i) => (
              <CheckRow
                key={`i${i}`}
                label={`Include IOC ${item.value}`}
                title={item.value}
                meta={`${item.type} · ${item.verified_in_source ? "verified" : "UNVERIFIED"}`}
                quote={item.evidence_quote}
                checked={iocs[i]}
                onChange={() => toggle(iocs, i, setIocs)}
              />
            ))}
            {a.cves.map((c, i) => (
              <CheckRow
                key={`c${i}`}
                label={`Include CVE ${c.id}`}
                title={c.id}
                meta={c.verified_in_source ? "verified" : "UNVERIFIED"}
                quote={c.evidence_quote}
                checked={cves[i]}
                onChange={() => toggle(cves, i, setCves)}
              />
            ))}
            {a.affected_systems.map((s, i) => (
              <CheckRow
                key={`s${i}`}
                label={`Include system ${s.system}`}
                title={s.system}
                meta={s.inferred ? "AI inference" : s.detail}
                quote={s.evidence_quote}
                checked={systems[i]}
                onChange={() => toggle(systems, i, setSystems)}
              />
            ))}
            {a.recommendations.map((r, i) => (
              <CheckRow
                key={`r${i}`}
                label={`Include recommendation ${i + 1}`}
                title={r.recommendation}
                meta={r.priority}
                checked={recs[i]}
                onChange={() => toggle(recs, i, setRecs)}
              />
            ))}
            {a.supporting_evidence.map((e, i) => (
              <CheckRow
                key={`e${i}`}
                label={`Include evidence ${i + 1}`}
                title={e.relevance}
                quote={e.quote}
                checked={evidence[i]}
                onChange={() => toggle(evidence, i, setEvidence)}
              />
            ))}
          </div>
        </Section>

        <Section title="4 · REDACTIONS (FREE TEXT ONLY — IDENTIFIERS STAY INTACT)">
          {redactions.map((r, i) => (
            <div key={i} className="flex items-end gap-2">
              <label className="flex flex-1 flex-col gap-1 text-xs text-slate-400">
                Match
                <input
                  type="text"
                  aria-label={`Redaction ${i + 1} match`}
                  value={r.match}
                  onChange={(e) => {
                    const next = [...redactions];
                    next[i] = { ...r, match: e.target.value };
                    setRedactions(next);
                  }}
                  placeholder="Exact text to replace"
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
                />
              </label>
              <label className="flex flex-1 flex-col gap-1 text-xs text-slate-400">
                Replacement
                <input
                  type="text"
                  aria-label={`Redaction ${i + 1} replacement`}
                  value={r.replacement}
                  onChange={(e) => {
                    const next = [...redactions];
                    next[i] = { ...r, replacement: e.target.value };
                    setRedactions(next);
                  }}
                  placeholder="[REDACTED]"
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
                />
              </label>
              <button
                type="button"
                aria-label={`Remove redaction ${i + 1}`}
                onClick={() => setRedactions(redactions.filter((_, j) => j !== i))}
                className="rounded-md p-2 text-slate-500 hover:bg-panel-2 hover:text-slate-200"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
          <button
            type="button"
            onClick={() => setRedactions([...redactions, { match: "", replacement: "" }])}
            className="inline-flex w-fit items-center gap-1 rounded-md border border-edge bg-panel-2 px-2.5 py-1.5 text-xs text-slate-300 hover:text-white"
          >
            <Plus className="h-3.5 w-3.5" /> Add redaction
          </button>
        </Section>

        <Section title="5 · ANALYST NOTES (INCLUDED IN PDF AND STIX EXPORTS)">
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Notes for recipients
            <textarea
              value={analystNotes}
              onChange={(e) => setAnalystNotes(e.target.value)}
              rows={3}
              placeholder="Context, caveats, or handling instructions for recipients…"
              className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
            />
          </label>
        </Section>

        <Section title="6 · ANALYST APPROVAL">
          <p className="font-mono text-[11px] text-slate-400">
            ACTING AS{" "}
            <span className="rounded-full bg-panel-2 px-2 py-0.5 text-slate-200 ring-1 ring-edge ring-inset">
              {role.toUpperCase()}
            </span>{" "}
            <span className="text-slate-500">(authenticated session — audit identity)</span>
          </p>
          <label className="flex cursor-pointer items-start gap-2 text-[13px] text-slate-200">
            <input
              type="checkbox"
              checked={approved}
              onChange={(e) => setApproved(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 accent-emerald-400"
            />
            I have reviewed the classification, selection, and redactions above and approve
            preparing this package. Nothing will be published.
          </label>
          {downgrade && (
            <>
              <label className="flex cursor-pointer items-start gap-2 text-[13px] text-amber-glow">
                <input
                  type="checkbox"
                  checked={downgradeAccepted}
                  onChange={(e) => setDowngradeAccepted(e.target.checked)}
                  className="mt-0.5 h-3.5 w-3.5 accent-amber-400"
                />
                I explicitly accept this downgrade from {effective} to {proposed}.
              </label>
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                Downgrade justification (min 10 characters)
                <textarea
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  rows={2}
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
                />
              </label>
            </>
          )}
        </Section>

        {blockers.length > 0 && (
          <ul className="flex flex-col gap-1 rounded-md border border-edge bg-abyss p-3">
            {blockers.map((b, i) => (
              <li key={i} className="font-mono text-[11px] text-slate-500">
                · {b}
              </li>
            ))}
          </ul>
        )}
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handlePrepare}
            disabled={!canPrepare}
            title={canPrepare ? "Submit for backend validation" : blockers[0]}
            className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-4 py-2 text-xs font-semibold text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <ShieldCheck className="h-4 w-4" />
            Prepare package
          </button>
          <button
            type="button"
            onClick={onClose}
            className="rounded-md px-3 py-2 font-mono text-[11px] text-slate-500 hover:bg-panel-2 hover:text-slate-200"
          >
            CANCEL
          </button>
        </div>
        <p className="font-mono text-[10px] leading-relaxed text-slate-600">
          TLP {proposed ? `PROPOSED AUDIENCE: ${tlpAudience(proposed)}` : ""}
        </p>
      </div>
    </section>
  );
}
