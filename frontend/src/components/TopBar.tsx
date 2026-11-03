import { Search } from "lucide-react";
import type { ApiState } from "../api/useHealth";

function ApiStatusPill({ state }: { state: ApiState }) {
  if (state.kind === "checking") {
    return (
      <span className="inline-flex items-center gap-2 rounded-full border border-edge bg-panel-2 px-3 py-1 font-mono text-xs text-slate-400">
        <span className="h-2 w-2 animate-pulse rounded-full bg-amber-glow" />
        API CHECKING…
      </span>
    );
  }
  if (state.kind === "online") {
    return (
      <span
        className="inline-flex items-center gap-2 rounded-full border border-edge bg-panel-2 px-3 py-1 font-mono text-xs text-signal"
        title={`Backend v${state.health.version} — ${state.health.timestamp}`}
      >
        <span className="h-2 w-2 rounded-full bg-signal" />
        API ONLINE · v{state.health.version}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-2 rounded-full border border-edge bg-panel-2 px-3 py-1 font-mono text-xs text-crimson">
      <span className="h-2 w-2 rounded-full bg-crimson" />
      API OFFLINE
    </span>
  );
}

interface TopBarProps {
  api: ApiState;
  query: string;
  onQuery: (query: string) => void;
  role: string;
  onLogout: () => void;
}

export default function TopBar({ api, query, onQuery, role, onLogout }: TopBarProps) {
  return (
    <header className="flex items-center gap-4 border-b border-edge bg-panel px-4 py-3 md:px-8">
      <div className="relative w-full max-w-md">
        <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-slate-500" />
        <input
          type="search"
          aria-label="Search threat feed"
          placeholder="Search threats, IOCs, CVEs…"
          value={query}
          onChange={(e) => onQuery(e.target.value)}
          className="w-full rounded-md border border-edge bg-abyss py-2 pr-3 pl-9 text-sm text-slate-200 placeholder:text-slate-500 focus:border-signal focus:ring-1 focus:ring-signal focus:outline-none"
        />
      </div>
      <div className="ml-auto flex items-center gap-3">
        <ApiStatusPill state={api} />
        <span className="hidden items-center gap-2 font-mono text-xs text-slate-500 lg:inline-flex">
          <span className="flex h-7 w-7 items-center justify-center rounded-full bg-panel-2 text-[11px] font-semibold text-slate-300 ring-1 ring-edge ring-inset">
            {role.slice(0, 2).toUpperCase()}
          </span>
          {role.toUpperCase()}
        </span>
        <button
          type="button"
          onClick={onLogout}
          title="Destroy this session"
          className="rounded-md px-2.5 py-1.5 font-mono text-[11px] text-slate-500 ring-1 ring-edge ring-inset hover:bg-panel-2 hover:text-slate-200"
        >
          LOG OUT
        </button>
      </div>
    </header>
  );
}
