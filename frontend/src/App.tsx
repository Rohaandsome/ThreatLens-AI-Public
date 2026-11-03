import { useRef, useState, type RefObject } from "react";
import {
  Activity,
  AlertOctagon,
  FileSearch,
  Fingerprint,
  Share2,
  UploadCloud,
} from "lucide-react";
import Sidebar, { type View } from "./components/Sidebar";
import TopBar from "./components/TopBar";
import StatCard from "./components/StatCard";
import SeverityPanel from "./components/SeverityPanel";
import ThreatTable from "./components/ThreatTable";
import UploadPanel from "./components/UploadPanel";
import AnalysisPanel, { type AnalysisState } from "./components/AnalysisPanel";
import SharePanel from "./components/SharePanel";
import HistoryPanel from "./components/HistoryPanel";
import LoginPanel from "./components/LoginPanel";
import SettingsPanel from "./components/SettingsPanel";
import { mockStats } from "./data/mockThreats";
import { ApiError, analyzeReport } from "./api/client";
import { useHealth } from "./api/useHealth";
import { useSession } from "./api/useSession";

function reducedMotion(): boolean {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function ViewHeading({ title, sub }: { title: string; sub: string }) {
  return (
    <div>
      <h1 className="text-xl font-bold tracking-tight text-white">{title}</h1>
      <p className="mt-1 text-[13px] text-slate-500">{sub}</p>
    </div>
  );
}

interface AnalysisBlockProps {
  analysis: AnalysisState;
  anchorRef: RefObject<HTMLDivElement | null>;
  onRetry: (file: File) => void;
  onDismiss: () => void;
  onShare: () => void;
}

function AnalysisBlock({ analysis, anchorRef, onRetry, onDismiss, onShare }: AnalysisBlockProps) {
  if (analysis.status === "idle") return null;
  return (
    <div ref={anchorRef} className="scroll-mt-4">
      <AnalysisPanel analysis={analysis} onRetry={onRetry} onDismiss={onDismiss} onShare={onShare} />
    </div>
  );
}

export default function App() {
  const api = useHealth();
  const session = useSession();
  const [view, setView] = useState<View>("overview");
  const [query, setQuery] = useState("");
  const [analysis, setAnalysis] = useState<AnalysisState>({ status: "idle" });
  const resultsRef = useRef<HTMLDivElement | null>(null);

  const loggedIn = session.status?.authenticated === true;
  const role = session.status?.role ?? "anonymous";
  const modelReady = loggedIn ? session.status!.model_api_configured : null;
  const mispReady = loggedIn ? session.status!.misp_configured : null;
  const aiConsented = session.status?.ai_consent === true;

  function navigate(next: View) {
    setView(next);
    window.scrollTo({ top: 0, behavior: reducedMotion() ? "auto" : "smooth" });
  }

  function scrollToResults() {
    resultsRef.current?.scrollIntoView({
      behavior: reducedMotion() ? "auto" : "smooth",
      block: "start",
    });
  }

  async function handleAnalyze(file: File) {
    setAnalysis({ status: "loading", file });
    requestAnimationFrame(() => scrollToResults());
    try {
      const result = await analyzeReport(file);
      setAnalysis({ status: "done", result });
      requestAnimationFrame(() => scrollToResults());
    } catch (err) {
      const error =
        err instanceof ApiError
          ? err
          : new ApiError(0, "unknown_error", "Analysis failed.", null);
      setAnalysis({ status: "error", file, error });
      requestAnimationFrame(() => scrollToResults());
    }
  }

  const uploadPanel = (
    <UploadPanel
      onAnalyze={handleAnalyze}
      analyzing={analysis.status === "loading"}
      analyzingName={analysis.status === "loading" ? analysis.file.name : null}
      modelReady={modelReady}
      consented={aiConsented}
      consenting={session.consenting}
      consentError={session.consentError}
      onConsent={() => void session.consent()}
    />
  );

  const analysisBlock = (
    <AnalysisBlock
      analysis={analysis}
      anchorRef={resultsRef}
      onRetry={handleAnalyze}
      onDismiss={() => setAnalysis({ status: "idle" })}
      onShare={() => navigate("share")}
    />
  );

  if (session.checking) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-abyss font-mono text-xs text-slate-500">
        CHECKING SESSION…
      </div>
    );
  }

  if (!loggedIn) {
    return (
      <div className="min-h-screen bg-abyss font-sans text-slate-200 antialiased">
        <LoginPanel
          loginError={session.loginError}
          loggingIn={session.loggingIn}
          authConfigured={session.status?.auth_configured ?? null}
          onLogin={(key) => void session.login(key)}
        />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-abyss font-sans text-slate-200 antialiased">
      <Sidebar modelReady={modelReady} view={view} onNavigate={navigate} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          api={api}
          query={query}
          onQuery={setQuery}
          role={role}
          onLogout={() => void session.logout()}
        />
        <main className="mx-auto flex w-full max-w-6xl flex-col gap-4 px-4 py-6 md:px-8">
          {view === "overview" && (
            <>
              <div className="flex flex-wrap items-end justify-between gap-2">
                <ViewHeading
                  title="Security Operations Overview"
                  sub="Statistics below are demo data — upload a report for live AI analysis"
                />
                <div className="flex items-center gap-3">
                  <p className="font-mono text-xs text-slate-500">
                    {new Date().toLocaleDateString("en-US", {
                      weekday: "short",
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                  </p>
                  <button
                    type="button"
                    onClick={() => navigate("share")}
                    className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-3 py-1.5 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70"
                  >
                    <Share2 className="h-3.5 w-3.5" />
                    Share Intel
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <StatCard
                  label="Active threats (demo)"
                  value={String(mockStats.activeThreats)}
                  delta={`▲ ${mockStats.deltaActive}% vs last week`}
                  deltaTone="up-bad"
                  icon={Activity}
                />
                <StatCard
                  label="Critical severity (demo)"
                  value={String(mockStats.criticalCount)}
                  delta="2 need triage now"
                  deltaTone="up-bad"
                  icon={AlertOctagon}
                />
                <StatCard
                  label="Reports analyzed (demo)"
                  value={String(mockStats.reportsAnalyzed)}
                  delta={`▲ ${mockStats.deltaReports} this month`}
                  deltaTone="up-good"
                  icon={FileSearch}
                />
                <StatCard
                  label="IOCs tracked (demo)"
                  value={mockStats.iocsTracked.toLocaleString()}
                  delta="Across 41 feeds"
                  icon={Fingerprint}
                />
              </div>

              <SeverityPanel />

              <div className="grid gap-4 xl:grid-cols-5">
                <div className="xl:col-span-3">
                  <ThreatTable query={query} />
                </div>
                <div className="xl:col-span-2">{uploadPanel}</div>
              </div>

              {analysisBlock}
            </>
          )}

          {view === "feed" && (
            <>
              <ViewHeading
                title="Threat Feed"
                sub="Demo intelligence items — use the search box to filter"
              />
              <ThreatTable query={query} />
            </>
          )}

          {view === "reports" && (
            <>
              <ViewHeading
                title="Analysis Reports"
                sub="Live AI results from reports analyzed in this session"
              />
              {analysis.status === "idle" ? (
                <section className="flex flex-col items-start gap-3 rounded-lg border border-edge bg-panel p-6">
                  <h2 className="text-sm font-semibold text-white">
                    No analyses yet
                  </h2>
                  <p className="text-xs leading-relaxed text-slate-400">
                    Upload a PDF or TXT threat report to generate your first AI
                    analysis with muse-spark-1.3.
                  </p>
                  <button
                    type="button"
                    onClick={() => navigate("upload")}
                    className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-3 py-1.5 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70"
                  >
                    <UploadCloud className="h-3.5 w-3.5" />
                    Go to Upload Intel
                  </button>
                </section>
              ) : (
                analysisBlock
              )}
            </>
          )}

          {view === "upload" && (
            <>
              <ViewHeading
                title="Upload Intelligence"
                sub="Queue PDF or TXT reports and send them to POST /api/analyze"
              />
              <div className="max-w-3xl">{uploadPanel}</div>
              {analysisBlock}
            </>
          )}

          {view === "share" && (
            <>
              <ViewHeading
                title="Share Intelligence"
                sub="Classify, review, and export a completed live analysis — nothing is published automatically"
              />
              {analysis.status === "done" ? (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-xs text-slate-400">
                      Source analysis: {analysis.result.filename}
                    </p>
                    <span className="rounded-full border border-edge bg-panel-2 px-2.5 py-0.5 font-mono text-[11px] text-signal">
                      {analysis.result.model.toUpperCase()} · LIVE AI RESULT
                    </span>
                  </div>
                  <SharePanel
                    key={`${analysis.result.filename}-${analysis.result.char_count}-${analysis.result.model}`}
                    result={analysis.result}
                    role={role}
                    onClose={() => navigate("reports")}
                  />
                </>
              ) : (
                <section className="flex flex-col items-start gap-3 rounded-lg border border-edge bg-panel p-6">
                  <h2 className="text-sm font-semibold text-white">
                    No completed analysis to share
                  </h2>
                  <p className="text-xs leading-relaxed text-slate-400">
                    Sharing packages are built from a completed live analysis.
                    Upload a PDF or TXT threat report and run analysis first,
                    then return here to classify, review, and export it.
                  </p>
                  <button
                    type="button"
                    onClick={() => navigate("upload")}
                    className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-3 py-1.5 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset transition-colors hover:bg-signal-dim/70"
                  >
                    <UploadCloud className="h-3.5 w-3.5" />
                    Go to Upload Intel
                  </button>
                </section>
              )}
            </>
          )}

          {view === "history" && (
            <>
              <ViewHeading
                title="Sharing History"
                sub="Distribution records and the append-only audit log"
              />
              <HistoryPanel />
            </>
          )}

          {view === "settings" && (
            <>
              <ViewHeading
                title="Settings"
                sub="Backend connection and configuration"
              />
              <SettingsPanel
                api={api}
                modelReady={modelReady}
                mispReady={mispReady}
              />
            </>
          )}
        </main>
      </div>
    </div>
  );
}
