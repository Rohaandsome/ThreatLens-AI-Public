import { mockThreats, type Severity } from "../data/mockThreats";

const SEVERITY_PILL: Record<Severity, string> = {
  critical: "bg-crimson/15 text-crimson ring-crimson/40",
  high: "bg-orange-400/15 text-orange-300 ring-orange-400/40",
  medium: "bg-amber-glow/15 text-amber-glow ring-amber-glow/40",
  low: "bg-sky-400/15 text-sky-300 ring-sky-400/40",
  info: "bg-slate-500/15 text-slate-400 ring-slate-500/40",
};

const STATUS_DOT: Record<string, string> = {
  new: "bg-sky-400",
  triaging: "bg-amber-glow",
  contained: "bg-signal",
  monitoring: "bg-slate-500",
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });
}

export default function ThreatTable({ query = "" }: { query?: string }) {
  const needle = query.trim().toLowerCase();
  const threats = needle
    ? mockThreats.filter((t) =>
        [t.id, t.title, t.severity, t.sector, t.source, t.summary]
          .join(" ")
          .toLowerCase()
          .includes(needle),
      )
    : mockThreats;

  return (
    <section className="overflow-hidden rounded-lg border border-edge bg-panel">
      <div className="flex items-center justify-between px-5 pt-4 pb-3">
        <div>
          <h2 className="text-sm font-semibold text-white">Threat feed</h2>
          <p className="mt-0.5 text-xs text-slate-500">
            Latest intelligence relevant to critical infrastructure
          </p>
        </div>
        <span className="rounded-full border border-edge bg-panel-2 px-2.5 py-0.5 font-mono text-[11px] text-slate-400">
          {threats.length} ITEMS{needle ? " · FILTERED" : " · MOCK DATA"}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-sm">
          <thead>
            <tr className="border-y border-edge bg-abyss font-mono text-[11px] tracking-wide text-slate-500">
              <th className="px-5 py-2.5 font-medium">ID</th>
              <th className="px-3 py-2.5 font-medium">THREAT</th>
              <th className="px-3 py-2.5 font-medium">SEVERITY</th>
              <th className="px-3 py-2.5 font-medium">SECTOR</th>
              <th className="px-3 py-2.5 font-medium">SOURCE</th>
              <th className="px-3 py-2.5 font-medium">DETECTED</th>
              <th className="px-3 py-2.5 text-right font-medium">IOCS</th>
              <th className="px-5 py-2.5 font-medium">STATUS</th>
            </tr>
          </thead>
          <tbody>
            {threats.length === 0 && (
              <tr>
                <td colSpan={8} className="px-5 py-6 text-center text-xs text-slate-500">
                  No threats match “{query.trim()}”.
                </td>
              </tr>
            )}
            {threats.map((t) => (
              <tr
                key={t.id}
                className="border-b border-edge/60 align-top transition-colors last:border-0 hover:bg-panel-2/60"
              >
                <td className="px-5 py-3 font-mono text-xs whitespace-nowrap text-slate-400">
                  {t.id}
                </td>
                <td className="max-w-sm px-3 py-3">
                  <p className="text-[13px] leading-snug font-medium text-slate-100">
                    {t.title}
                  </p>
                  <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-slate-500">
                    {t.summary}
                  </p>
                </td>
                <td className="px-3 py-3 whitespace-nowrap">
                  <span
                    className={`inline-flex rounded-full px-2 py-0.5 font-mono text-[11px] font-medium ring-1 ring-inset ${SEVERITY_PILL[t.severity]}`}
                  >
                    {t.severity.toUpperCase()}
                  </span>
                </td>
                <td className="px-3 py-3 text-xs whitespace-nowrap text-slate-400">
                  {t.sector}
                </td>
                <td className="px-3 py-3 font-mono text-xs whitespace-nowrap text-slate-400">
                  {t.source}
                </td>
                <td className="px-3 py-3 font-mono text-xs whitespace-nowrap text-slate-400">
                  {formatDate(t.detectedAt)}
                </td>
                <td className="px-3 py-3 text-right font-mono text-xs text-slate-300">
                  {t.iocs}
                </td>
                <td className="px-5 py-3 whitespace-nowrap">
                  <span className="inline-flex items-center gap-1.5 text-xs text-slate-400 capitalize">
                    <span
                      className={`h-1.5 w-1.5 rounded-full ${STATUS_DOT[t.status]}`}
                    />
                    {t.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
