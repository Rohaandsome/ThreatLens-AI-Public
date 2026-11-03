import type { LucideIcon } from "lucide-react";

interface StatCardProps {
  label: string;
  value: string;
  delta?: string;
  deltaTone?: "up-bad" | "up-good" | "neutral";
  icon: LucideIcon;
}

export default function StatCard({
  label,
  value,
  delta,
  deltaTone = "neutral",
  icon: Icon,
}: StatCardProps) {
  const deltaColor =
    deltaTone === "up-bad"
      ? "text-crimson"
      : deltaTone === "up-good"
        ? "text-signal"
        : "text-slate-500";

  return (
    <div className="rounded-lg border border-edge bg-panel p-5">
      <div className="flex items-center justify-between">
        <p className="text-[13px] font-medium text-slate-400">{label}</p>
        <Icon className="h-4 w-4 text-slate-500" strokeWidth={2} />
      </div>
      <p className="mt-2 font-mono text-[28px] leading-none font-semibold text-white">
        {value}
      </p>
      {delta && (
        <p className={`mt-2 font-mono text-xs ${deltaColor}`}>{delta}</p>
      )}
    </div>
  );
}
