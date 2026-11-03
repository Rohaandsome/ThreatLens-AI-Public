import { useState } from "react";
import { AlertTriangle, Download, Loader2 } from "lucide-react";
import { ApiError, exportStix } from "../api/client";
import { downloadJson } from "../api/download";
import type { AnalyzeResponse } from "../api/types";

export default function StixExportButton({ result }: { result: AnalyzeResponse }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[] | null>(null);

  async function handleExport() {
    setBusy(true);
    setError(null);
    try {
      const res = await exportStix(result);
      downloadJson(res.filename, res.bundle);
      const total = Object.values(res.object_counts).reduce((a, b) => a + b, 0);
      const parts = Object.entries(res.object_counts)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([kind, n]) => `${n} ${kind}`)
        .join(", ");
      setSummary(`Exported ${total} STIX objects (${parts}).`);
      setWarnings(res.warnings.length > 0 ? res.warnings : null);
    } catch (err) {
      setSummary(null);
      setWarnings(null);
      setError(
        err instanceof ApiError ? err.message : "STIX export failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="ml-auto inline-flex flex-col items-end gap-1">
      <button
        type="button"
        onClick={handleExport}
        disabled={busy}
        title="Download validated STIX 2.1 bundle"
        className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70 disabled:cursor-wait disabled:opacity-60"
      >
        {busy ? (
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Download className="h-3.5 w-3.5" />
        )}
        {busy ? "EXPORTING" : "STIX 2.1 JSON"}
      </button>
      {summary && (
        <span className="font-mono text-[10px] text-slate-500">{summary}</span>
      )}
      {error && (
        <span className="font-mono text-[10px] text-crimson">{error}</span>
      )}
      {warnings && (
        <span className="flex max-w-xs flex-col gap-0.5 text-right">
          {warnings.map((w, i) => (
            <span
              key={i}
              className="inline-flex items-start justify-end gap-1 font-mono text-[10px] text-amber-glow"
            >
              <AlertTriangle className="h-3 w-3 shrink-0 translate-y-px" />
              {w}
            </span>
          ))}
        </span>
      )}
    </span>
  );
}
