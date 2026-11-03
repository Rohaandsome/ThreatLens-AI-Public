import { sectorExposure, severityCounts } from "../data/mockThreats";

const SEVERITY_BAR: Record<keyof typeof severityCounts, string> = {
  critical: "bg-crimson",
  high: "bg-orange-400",
  medium: "bg-amber-glow",
  low: "bg-sky-400",
  info: "bg-slate-500",
};

function Bar({ value, max, className }: { value: number; max: number; className: string }) {
  return (
    <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-panel-2">
      <div
        className={`h-full rounded-full ${className}`}
        style={{ width: `${Math.max(4, (value / max) * 100)}%` }}
      />
    </div>
  );
}

export default function SeverityPanel() {
  const sevEntries = Object.entries(severityCounts) as [
    keyof typeof severityCounts,
    number,
  ][];
  const sevMax = Math.max(...sevEntries.map(([, v]) => v));
  const sectorMax = Math.max(...sectorExposure.map((s) => s.threats));

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <section className="rounded-lg border border-edge bg-panel p-5">
        <h2 className="text-sm font-semibold text-white">
          Threats by severity
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">
          Active threats in the last 30 days
        </p>
        <div className="mt-4 flex flex-col gap-3">
          {sevEntries.map(([sev, count]) => (
            <div key={sev} className="flex items-center gap-3">
              <span className="w-16 font-mono text-xs text-slate-400 capitalize">
                {sev}
              </span>
              <Bar value={count} max={sevMax} className={SEVERITY_BAR[sev]} />
              <span className="w-8 text-right font-mono text-xs font-semibold text-white">
                {count}
              </span>
            </div>
          ))}
        </div>
      </section>

      <section className="rounded-lg border border-edge bg-panel p-5">
        <h2 className="text-sm font-semibold text-white">
          Exposure by sub-sector
        </h2>
        <p className="mt-0.5 text-xs text-slate-500">
          Open items affecting energy infrastructure
        </p>
        <div className="mt-4 flex flex-col gap-3">
          {sectorExposure.map((s) => (
            <div key={s.sector} className="flex items-center gap-3">
              <span className="w-32 truncate text-xs text-slate-400">
                {s.sector}
              </span>
              <Bar value={s.threats} max={sectorMax} className="bg-signal" />
              <span className="w-8 text-right font-mono text-xs font-semibold text-white">
                {s.threats}
              </span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
