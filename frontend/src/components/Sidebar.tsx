import {
  FileText,
  History,
  LayoutDashboard,
  Radio,
  Settings,
  Share2,
  ShieldHalf,
  UploadCloud,
  type LucideIcon,
} from "lucide-react";

export type View = "overview" | "feed" | "reports" | "upload" | "share" | "history" | "settings";

const NAV: { label: string; view: View; icon: LucideIcon }[] = [
  { label: "Overview", view: "overview", icon: LayoutDashboard },
  { label: "Threat Feed", view: "feed", icon: Radio },
  { label: "Reports", view: "reports", icon: FileText },
  { label: "Upload Intel", view: "upload", icon: UploadCloud },
  { label: "Share Intel", view: "share", icon: Share2 },
  { label: "History", view: "history", icon: History },
  { label: "Settings", view: "settings", icon: Settings },
];

interface SidebarProps {
  modelReady: boolean | null;
  view: View;
  onNavigate: (view: View) => void;
}

export default function Sidebar({ modelReady, view, onNavigate }: SidebarProps) {
  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-edge bg-panel md:flex">
      <div className="flex items-center gap-2.5 px-5 pt-6 pb-5">
        <span className="flex h-9 w-9 items-center justify-center rounded-md bg-signal-dim">
          <ShieldHalf className="h-5 w-5 text-signal" strokeWidth={2.2} />
        </span>
        <div>
          <p className="text-[15px] font-bold tracking-tight text-white">
            ThreatLens AI
          </p>
          <p className="font-mono text-[11px] text-slate-400">
            ENERGY SECTOR
          </p>
        </div>
      </div>

      <nav className="flex flex-col gap-1 px-3" aria-label="Primary">
        {NAV.map((item) => {
          const active = item.view === view;
          return (
            <button
              key={item.view}
              type="button"
              onClick={() => onNavigate(item.view)}
              aria-current={active ? "page" : undefined}
              className={
                active
                  ? "flex items-center gap-3 rounded-md bg-panel-2 px-3 py-2 text-sm font-medium text-white ring-1 ring-edge ring-inset"
                  : "flex items-center gap-3 rounded-md px-3 py-2 text-sm text-slate-400 transition-colors hover:bg-panel-2 hover:text-slate-200"
              }
            >
              <item.icon className="h-4 w-4" strokeWidth={2} />
              {item.label}
              {active && (
                <span className="ml-auto h-1.5 w-1.5 rounded-full bg-signal" />
              )}
            </button>
          );
        })}
      </nav>

      <div className="mt-auto px-5 py-5">
        <div className="rounded-md border border-edge bg-abyss p-3">
          <p className="font-mono text-[11px] tracking-wide text-slate-500">
            MODEL STATUS
          </p>
          <p className="mt-1 text-xs text-slate-300">
            {modelReady === null
              ? "Checking Model API status…"
              : modelReady
                ? "Meta Model API connected — AI analysis enabled."
                : "Meta Model API not connected — dashboard shows demo data."}
          </p>
        </div>
      </div>
    </aside>
  );
}
