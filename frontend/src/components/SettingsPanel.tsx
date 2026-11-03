import { ExternalLink } from "lucide-react";
import type { ApiState } from "../api/useHealth";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-edge/60 py-2.5 last:border-0">
      <span className="text-xs text-slate-500">{label}</span>
      <span className="text-right text-[13px] text-slate-200">{children}</span>
    </div>
  );
}

export default function SettingsPanel({
  api,
  modelReady,
  mispReady,
}: {
  api: ApiState;
  modelReady: boolean | null;
  mispReady: boolean | null;
}) {
  const status =
    api.kind === "online" ? (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-signal">
        <span className="h-1.5 w-1.5 rounded-full bg-signal" /> Online
      </span>
    ) : api.kind === "offline" ? (
      <span className="inline-flex items-center gap-1.5 font-mono text-xs text-crimson">
        <span className="h-1.5 w-1.5 rounded-full bg-crimson" /> Offline
      </span>
    ) : (
      <span className="font-mono text-xs text-slate-400">Checking…</span>
    );

  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <section className="rounded-lg border border-edge bg-panel p-5">
        <h2 className="text-sm font-semibold text-white">Backend connection</h2>
        <p className="mt-0.5 text-xs text-slate-500">
          Live status of the FastAPI backend, refreshed every 30 seconds
        </p>
        <div className="mt-3">
          <Row label="Status">{status}</Row>
          <Row label="Service">
            <span className="font-mono text-xs">
              {api.kind === "online" ? api.health.service : "—"}
            </span>
          </Row>
          <Row label="Version">
            <span className="font-mono text-xs">
              {api.kind === "online" ? `v${api.health.version}` : "—"}
            </span>
          </Row>
          <Row label="Model API">
            {modelReady === null ? (
              "—"
            ) : modelReady ? (
              <span className="font-mono text-xs text-signal">
                Configured — AI analysis enabled
              </span>
            ) : (
              <span className="font-mono text-xs text-amber-glow">
                Not configured — add MODEL_API_KEY
              </span>
            )}
          </Row>
          <Row label="MISP">
            {mispReady === null ? (
              "—"
            ) : mispReady ? (
              <span className="font-mono text-xs text-signal">
                Configured — drafts enabled
              </span>
            ) : (
              <span className="font-mono text-xs text-slate-500">
                Not configured — set MISP_URL and MISP_API_KEY
              </span>
            )}
          </Row>
          <Row label="Last checked">
            <span className="font-mono text-xs">
              {api.kind === "online"
                ? new Date(api.health.timestamp).toLocaleString()
                : "—"}
            </span>
          </Row>
        </div>
      </section>

      <section className="rounded-lg border border-edge bg-panel p-5">
        <h2 className="text-sm font-semibold text-white">Configuration</h2>
        <div className="mt-3">
          <Row label="Backend env file">
            <span className="font-mono text-xs">backend/.env</span>
          </Row>
          <Row label="API docs">
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 font-mono text-xs text-signal hover:underline"
            >
              127.0.0.1:8000/docs <ExternalLink className="h-3 w-3" />
            </a>
          </Row>
        </div>
        <p className="mt-3 text-xs leading-relaxed text-slate-500">
          The Model API and MISP keys live only in the backend environment — they
          are never sent to the browser. Restart the backend after editing
          backend/.env.
        </p>
      </section>
    </div>
  );
}
