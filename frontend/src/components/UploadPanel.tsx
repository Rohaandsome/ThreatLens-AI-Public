import { useRef, useState } from "react";
import {
  FileText,
  FileUp,
  Loader2,
  ScanSearch,
  ShieldCheck,
  TriangleAlert,
  X,
} from "lucide-react";

const ACCEPTED_EXTENSIONS = [".pdf", ".txt"] as const;
const MAX_SIZE_BYTES = 10 * 1024 * 1024; // matches backend limit

interface QueuedFile {
  key: string;
  file: File;
  name: string;
  size: number;
  status: "queued" | "rejected";
  reason?: string;
}

interface UploadPanelProps {
  onAnalyze: (file: File) => void;
  analyzing: boolean;
  analyzingName: string | null;
  /** null while backend health is unknown. */
  modelReady: boolean | null;
  /** Per-session external-AI acknowledgment (server-enforced on /api/analyze). */
  consented: boolean;
  consenting: boolean;
  consentError: string | null;
  onConsent: () => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function validateFile(file: File): string | null {
  const lower = file.name.toLowerCase();
  const ok = ACCEPTED_EXTENSIONS.some((ext) => lower.endsWith(ext));
  if (!ok) return "Only PDF and TXT reports are accepted.";
  if (file.size > MAX_SIZE_BYTES) return "File exceeds the 10 MB limit.";
  if (file.size === 0) return "File is empty.";
  return null;
}

export default function UploadPanel({
  onAnalyze,
  analyzing,
  analyzingName,
  modelReady,
  consented,
  consenting,
  consentError,
  onConsent,
}: UploadPanelProps) {
  const [dragging, setDragging] = useState(false);
  const [files, setFiles] = useState<QueuedFile[]>([]);
  const [ackChecked, setAckChecked] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function addFiles(list: FileList | File[]) {
    const incoming = Array.from(list).map((f) => {
      const reason = validateFile(f);
      return {
        key: `${f.name}-${f.size}-${f.lastModified}-${Math.random().toString(36).slice(2)}`,
        file: f,
        name: f.name,
        size: f.size,
        status: (reason ? "rejected" : "queued") as QueuedFile["status"],
        reason: reason ?? undefined,
      };
    });
    setFiles((prev) => [...incoming, ...prev].slice(0, 20));
  }

  function removeFile(key: string) {
    setFiles((prev) => prev.filter((f) => f.key !== key));
  }

  const queuedCount = files.filter((f) => f.status === "queued").length;

  return (
    <section className="rounded-lg border border-edge bg-panel p-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-white">
            Upload threat reports
          </h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Drop PDF or TXT intel for AI analysis — max 10 MB per file
          </p>
        </div>
        {queuedCount > 0 && (
          <span className="rounded-full border border-edge bg-panel-2 px-2.5 py-0.5 font-mono text-[11px] text-signal">
            {queuedCount} QUEUED
          </span>
        )}
      </div>

      <div
        role="note"
        aria-label="External AI processing notice"
        className={`mt-3 rounded-md border p-3 ${
          consented
            ? "border-signal/30 bg-signal-dim/30"
            : "border-amber-glow/40 bg-amber-glow/10"
        }`}
      >
        <p
          className={`flex items-center gap-1.5 text-xs font-semibold ${
            consented ? "text-signal" : "text-amber-glow"
          }`}
        >
          <TriangleAlert className="h-3.5 w-3.5" />
          External AI processing notice
        </p>
        <p className="mt-1.5 text-xs leading-relaxed text-slate-300">
          Extracted report text will be sent to the Meta Model API
          (muse-spark-1.3) for analysis. Do not upload NDA-protected or
          confidential information without authorization.
        </p>
        {consented ? (
          <p className="mt-2 font-mono text-[11px] text-signal">
            ACKNOWLEDGED FOR THIS SESSION — ANALYSIS ENABLED
          </p>
        ) : (
          <div className="mt-2 flex flex-col gap-2">
            <label className="flex cursor-pointer items-start gap-2 text-xs text-slate-200">
              <input
                type="checkbox"
                checked={ackChecked}
                onChange={(e) => setAckChecked(e.target.checked)}
                className="mt-0.5 h-3.5 w-3.5 shrink-0 accent-amber-400"
              />
              I understand report text leaves this server for external AI
              processing, and I am authorized to submit it.
            </label>
            <div>
              <button
                type="button"
                disabled={!ackChecked || consenting}
                onClick={onConsent}
                className="inline-flex items-center gap-1.5 rounded-md bg-amber-glow/20 px-2.5 py-1.5 text-xs font-medium text-amber-glow ring-1 ring-amber-glow/40 ring-inset transition-colors hover:bg-amber-glow/30 disabled:cursor-not-allowed disabled:opacity-40"
              >
                {consenting && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                {consenting ? "Recording…" : "Acknowledge for this session"}
              </button>
            </div>
            {consentError && (
              <p role="alert" className="text-xs text-crimson">
                {consentError}
              </p>
            )}
          </div>
        )}
      </div>

      <p
        className={`mt-3 flex items-center gap-1.5 font-mono text-[11px] ${
          modelReady === false ? "text-amber-glow" : "text-slate-500"
        }`}
      >
        <span
          className={`h-1.5 w-1.5 rounded-full ${
            modelReady === null
              ? "animate-pulse bg-slate-500"
              : modelReady
                ? "bg-signal"
                : "bg-amber-glow"
          }`}
        />
        {modelReady === null
          ? "CHECKING MODEL API STATUS…"
          : modelReady
            ? "MODEL API CONNECTED — ANALYSIS ENABLED"
            : "MODEL API NOT CONFIGURED — ADD MODEL_API_KEY TO BACKEND/.ENV"}
      </p>

      <button
        type="button"
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          if (e.dataTransfer.files.length > 0) addFiles(e.dataTransfer.files);
        }}
        className={`mt-3 flex w-full cursor-pointer flex-col items-center justify-center gap-2 rounded-md border border-dashed px-6 py-8 text-center transition-colors ${
          dragging
            ? "border-signal bg-signal-dim/40"
            : "border-edge bg-abyss hover:border-slate-500"
        }`}
      >
        <FileUp
          className={`h-7 w-7 ${dragging ? "text-signal" : "text-slate-500"}`}
          strokeWidth={1.8}
        />
        <span className="block text-sm text-slate-300">
          {dragging ? (
            <>Release to add reports</>
          ) : (
            <>
              Drag &amp; drop reports here, or{" "}
              <span className="font-medium text-signal">browse files</span>
            </>
          )}
        </span>
        <span className="block font-mono text-[11px] text-slate-500">
          .PDF · .TXT — FILES ARE ANALYZED VIA POST /API/ANALYZE
        </span>
      </button>
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPTED_EXTENSIONS.join(",")}
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files) addFiles(e.target.files);
          e.target.value = "";
        }}
      />

      {files.length > 0 && (
        <ul className="mt-4 flex flex-col gap-2">
          {files.map((f) => {
            const isActive = analyzing && analyzingName === f.name;
            return (
              <li
                key={f.key}
                className="flex items-center gap-3 rounded-md border border-edge bg-abyss px-3 py-2.5"
              >
                {f.status === "queued" ? (
                  <ShieldCheck className="h-4 w-4 shrink-0 text-signal" />
                ) : (
                  <TriangleAlert className="h-4 w-4 shrink-0 text-crimson" />
                )}
                <FileText className="hidden h-4 w-4 shrink-0 text-slate-500 sm:block" />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-[13px] text-slate-200">{f.name}</p>
                  <p
                    className={`font-mono text-[11px] ${f.status === "queued" ? "text-slate-500" : "text-crimson"}`}
                  >
                    {formatSize(f.size)}
                    {f.reason ? ` — ${f.reason}` : " — ready to analyze"}
                  </p>
                </div>
                {f.status === "queued" && (
                  <button
                    type="button"
                    disabled={analyzing || !consented}
                    onClick={() => onAnalyze(f.file)}
                    title={
                      consented
                        ? "Send to POST /api/analyze"
                        : "Acknowledge external AI processing first"
                    }
                    className="inline-flex shrink-0 items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    {isActive ? (
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <ScanSearch className="h-3.5 w-3.5" />
                    )}
                    {isActive ? "Analyzing" : "Analyze"}
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => removeFile(f.key)}
                  aria-label={`Remove ${f.name}`}
                  className="rounded p-1 text-slate-500 transition-colors hover:bg-panel-2 hover:text-slate-200"
                >
                  <X className="h-4 w-4" />
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
