import { Loader2, RotateCcw, Share2, TriangleAlert } from "lucide-react";
import { ApiError } from "../api/client";
import type { AnalyzeResponse } from "../api/types";
import AnalysisResults from "./AnalysisResults";
import StixExportButton from "./StixExportButton";

export type AnalysisState =
  | { status: "idle" }
  | { status: "loading"; file: File }
  | { status: "done"; result: AnalyzeResponse }
  | { status: "error"; file: File; error: ApiError };

function friendlyError(error: ApiError): { title: string; hint: string } {
  switch (error.code) {
    case "model_api_not_configured":
      return {
        title: "AI analysis isn't configured yet.",
        hint: "Add MODEL_API_KEY to backend/.env and restart the backend to enable analysis.",
      };
    case "model_api_auth_failed":
      return {
        title: "Model API key was rejected.",
        hint: "Check the MODEL_API_KEY value in backend/.env.",
      };
    case "rate_limited":
      return {
        title: "Too many requests — rate limited.",
        hint: error.retryAfter
          ? `Wait ${error.retryAfter} seconds, then retry.`
          : "Wait a moment, then retry.",
      };
    case "consent_required":
      return {
        title: "External AI processing not acknowledged.",
        hint: "Tick the acknowledgment checkbox in the upload panel first — the server blocks analysis until then.",
      };
    case "model_output_truncated":
      return {
        title: "The AI response was cut off.",
        hint: "The model hit its token budget before finishing. Retry — and if it persists, raise MODEL_MAX_TOKENS in backend/.env.",
      };
    case "model_api_timeout":
    case "model_api_unreachable":
    case "model_api_error":
    case "model_output_empty":
    case "model_output_malformed":
    case "model_output_invalid":
      return {
        title: "The Model API request failed.",
        hint: "The provider may be busy. Retry shortly.",
      };
    case "backend_unreachable":
      return {
        title: "Cannot reach the backend.",
        hint: "Start it with: cd backend && uvicorn app.main:app --port 8000",
      };
    default:
      return { title: "Analysis failed.", hint: error.message };
  }
}

interface AnalysisPanelProps {
  analysis: Exclude<AnalysisState, { status: "idle" }>;
  onRetry: (file: File) => void;
  onDismiss: () => void;
  onShare: () => void;
}

export default function AnalysisPanel({
  analysis,
  onRetry,
  onDismiss,
  onShare,
}: AnalysisPanelProps) {
  return (
    <section className="rounded-lg border border-edge bg-panel p-5">
      {analysis.status === "loading" && (
        <div className="flex flex-col items-center gap-3 py-10 text-center">
          <Loader2 className="h-8 w-8 animate-spin text-signal" />
          <p className="text-sm font-medium text-slate-200">
            Analyzing {analysis.file.name}…
          </p>
          <p className="max-w-md font-mono text-[11px] leading-relaxed text-slate-500">
            EXTRACTING TEXT AND QUERYING MUSE-SPARK-1.3 — THIS CAN TAKE UP TO A
            MINUTE FOR LONG REPORTS
          </p>
        </div>
      )}

      {analysis.status === "error" && (
        <div className="flex flex-col items-start gap-3 py-4">
          <div className="flex items-center gap-2">
            <TriangleAlert className="h-5 w-5 text-crimson" />
            <h2 className="text-sm font-semibold text-white">
              {friendlyError(analysis.error).title}
            </h2>
          </div>
          <p className="text-xs leading-relaxed text-slate-400">
            {friendlyError(analysis.error).hint}
          </p>
          <p className="font-mono text-[11px] text-slate-500">
            {analysis.file.name} · {analysis.error.code} · HTTP{" "}
            {analysis.error.status}
          </p>
          <button
            type="button"
            onClick={() => onRetry(analysis.file)}
            className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-3 py-1.5 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70"
          >
            <RotateCcw className="h-3.5 w-3.5" />
            Retry analysis
          </button>
        </div>
      )}

      {analysis.status === "done" && (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-semibold text-white">
              Analysis: {analysis.result.filename}
            </h2>
            <span className="rounded-full border border-edge bg-panel-2 px-2.5 py-0.5 font-mono text-[11px] text-signal">
              {analysis.result.model.toUpperCase()} · LIVE AI RESULT
            </span>
            <StixExportButton result={analysis.result} />
            <button
              type="button"
              onClick={onShare}
              className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70"
            >
              <Share2 className="h-3.5 w-3.5" />
              SHARE INTEL
            </button>
            <button
              type="button"
              onClick={onDismiss}
              className="rounded-md px-2 py-1 font-mono text-[11px] text-slate-500 transition-colors hover:bg-panel-2 hover:text-slate-200"
            >
              DISMISS
            </button>
          </div>
          <AnalysisResults result={analysis.result} />
        </>
      )}
    </section>
  );
}
