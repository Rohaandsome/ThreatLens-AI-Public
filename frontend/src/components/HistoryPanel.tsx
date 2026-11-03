import { Fragment, useEffect, useState } from "react";
import {
  ChevronDown,
  ChevronRight,
  FileClock,
  Loader2,
  Lock,
  ScrollText,
  TriangleAlert,
} from "lucide-react";
import {
  ApiError,
  fetchAuditEvents,
  fetchAuthStatus,
  fetchHistory,
} from "../api/client";
import { TLP_LEVELS } from "../api/tlp";
import type {
  AuditListResponse,
  AuthStatusResponse,
  HistoryFilters,
  HistoryListResponse,
  HistoryRecord,
} from "../api/types";

type Tab = "history" | "audit";

const STATUS_TABS = [
  { value: "", label: "All" },
  { value: "pending_review", label: "Pending review" },
  { value: "approved", label: "Approved" },
  { value: "exported", label: "Exported" },
  { value: "draft", label: "MISP drafts" },
  { value: "published", label: "Published" },
  { value: "failed", label: "Failed" },
  { value: "denied", label: "Denied" },
];

const STATUS_TONE: Record<string, string> = {
  pending_review: "text-amber-glow ring-amber-glow/40",
  approved: "text-signal ring-signal/30",
  exported: "text-signal ring-signal/30",
  draft: "text-slate-300 ring-edge",
  published: "text-emerald-300 ring-emerald-400/30",
  failed: "text-crimson ring-crimson/40",
  denied: "text-crimson ring-crimson/40",
  cancelled: "text-slate-500 ring-edge",
};

const TLP_TONE: Record<string, string> = {
  "TLP:RED": "text-crimson ring-crimson/40",
  "TLP:AMBER+STRICT": "text-amber-glow ring-amber-glow/40",
  "TLP:AMBER": "text-amber-glow ring-amber-glow/40",
  "TLP:GREEN": "text-signal ring-signal/30",
  "TLP:CLEAR": "text-slate-300 ring-edge",
};

function errorText(err: unknown, fallback: string): string {
  return err instanceof ApiError ? `${err.message} (${err.code})` : fallback;
}

function shortTs(value: string | null): string {
  if (!value) return "—";
  return value.length >= 16 ? `${value.slice(0, 10)} ${value.slice(11, 16)}` : value;
}

function findingsLine(findings: Record<string, number>): string {
  const parts = [
    `${findings.iocs ?? 0} IOC`,
    `${findings.cves ?? 0} CVE`,
    `${findings.techniques ?? 0} TTP`,
    `${findings.systems ?? 0} SYS`,
  ];
  return parts.join(" · ");
}

function auditSummary(event: Record<string, unknown>): string {
  const rest = Object.entries(event)
    .filter(([k]) => k !== "id" && k !== "ts" && k !== "event")
    .map(([k, v]) => `${k}=${typeof v === "string" ? v : JSON.stringify(v)}`)
    .join(" ");
  return rest.length > 180 ? `${rest.slice(0, 180)}…` : rest || "—";
}

function RecordActions({ record }: { record: HistoryRecord }) {
  const terminal = ["exported", "published", "denied", "cancelled"].includes(
    record.status,
  );
  if (terminal) return <span className="font-mono text-[11px] text-slate-600">—</span>;
  const label =
    record.status === "pending_review"
      ? "APPROVE"
      : record.status === "approved"
        ? "SEND"
        : "CANCEL";
  return (
    <span className="inline-flex items-center gap-1">
      <button
        type="button"
        disabled
        title="Requires authentication — distribution is disabled until login exists (server-enforced)"
        aria-label={`${label} ${record.id} (disabled: requires authentication)`}
        className="inline-flex cursor-not-allowed items-center gap-1 rounded-md bg-panel-2 px-2 py-1 font-mono text-[11px] text-slate-600 ring-1 ring-edge ring-inset"
      >
        <Lock className="h-3 w-3" />
        {label}
      </button>
    </span>
  );
}

export default function HistoryPanel() {
  const [tab, setTab] = useState<Tab>("history");
  const [auth, setAuth] = useState<AuthStatusResponse | null>(null);
  const [applied, setApplied] = useState<HistoryFilters>({});
  const [draftTlp, setDraftTlp] = useState("");
  const [draftReport, setDraftReport] = useState("");
  const [draftRecipient, setDraftRecipient] = useState("");
  const [draftSince, setDraftSince] = useState("");
  const [draftUntil, setDraftUntil] = useState("");
  const [history, setHistory] = useState<HistoryListResponse | null>(null);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [audit, setAudit] = useState<AuditListResponse | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [auditEvent, setAuditEvent] = useState("");

  useEffect(() => {
    let cancelled = false;
    fetchAuthStatus()
      .then((res) => {
        if (!cancelled) setAuth(res);
      })
      .catch(() => {
        if (!cancelled) setAuth(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function requestHistory(next: HistoryFilters) {
    setHistoryLoading(true);
    setHistoryError(null);
    setExpanded(null);
    setApplied(next);
  }

  useEffect(() => {
    let cancelled = false;
    fetchHistory(applied)
      .then((res) => {
        if (!cancelled) {
          setHistory(res);
          setHistoryLoading(false);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setHistoryError(errorText(err, "History load failed."));
          setHistoryLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [applied]);

  function loadAudit(eventFilter: string) {
    setAuditLoading(true);
    setAuditError(null);
    fetchAuditEvents(eventFilter ? { event: eventFilter } : {})
      .then((res) => {
        setAudit(res);
        setAuditLoading(false);
      })
      .catch((err) => {
        setAuditError(errorText(err, "Audit load failed."));
        setAuditLoading(false);
      });
  }

  function openTab(next: Tab) {
    setTab(next);
    if (next === "audit" && audit === null && !auditLoading) loadAudit(auditEvent);
  }

  function applyFilters() {
    requestHistory({
      status: applied.status || undefined,
      classification: draftTlp || undefined,
      report: draftReport.trim() || undefined,
      recipient: draftRecipient.trim() || undefined,
      since: draftSince ? `${draftSince}T00:00:00` : undefined,
      until: draftUntil ? `${draftUntil}T23:59:59` : undefined,
    });
  }

  function clearFilters() {
    setDraftTlp("");
    setDraftReport("");
    setDraftRecipient("");
    setDraftSince("");
    setDraftUntil("");
    requestHistory({});
  }

  return (
    <div className="flex flex-col gap-4">
      <section className="rounded-lg border border-edge bg-panel p-5">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => openTab("history")}
            aria-current={tab === "history" ? "page" : undefined}
            className={
              tab === "history"
                ? "inline-flex items-center gap-1.5 rounded-md bg-panel-2 px-3 py-1.5 text-xs font-medium text-white ring-1 ring-edge ring-inset"
                : "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs text-slate-400 hover:bg-panel-2 hover:text-slate-200"
            }
          >
            <FileClock className="h-3.5 w-3.5" />
            Distribution history
          </button>
          <button
            type="button"
            onClick={() => openTab("audit")}
            aria-current={tab === "audit" ? "page" : undefined}
            className={
              tab === "audit"
                ? "inline-flex items-center gap-1.5 rounded-md bg-panel-2 px-3 py-1.5 text-xs font-medium text-white ring-1 ring-edge ring-inset"
                : "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs text-slate-400 hover:bg-panel-2 hover:text-slate-200"
            }
          >
            <ScrollText className="h-3.5 w-3.5" />
            Audit log
          </button>
          {auth && (
            <span className="ml-auto font-mono text-[11px] text-slate-500">
              ROLE: {auth.role.toUpperCase()} · DISTRIBUTION:{" "}
              {auth.distribution_enabled ? "ENABLED" : "DISABLED"}
            </span>
          )}
        </div>

        {tab === "history" && (
          <>
            <p className="mt-3 rounded-md border border-amber-glow/40 bg-amber-glow/5 p-3 font-mono text-[11px] leading-relaxed text-amber-glow">
              DEMONSTRATION DATA — these records are fictional seeds for design
              review. Distribution actions are disabled until authentication is
              implemented; the server rejects them regardless of what any
              client claims.
            </p>

            <div
              className="mt-3 flex flex-wrap gap-1.5"
              role="tablist"
              aria-label="Delivery status"
            >
              {STATUS_TABS.map((t) => {
                const active = (applied.status ?? "") === t.value;
                return (
                  <button
                    key={t.label}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    onClick={() =>
                      requestHistory({ ...applied, status: t.value || undefined })
                    }
                    className={
                      active
                        ? "rounded-full bg-signal-dim px-2.5 py-1 font-mono text-[11px] text-signal ring-1 ring-signal/30 ring-inset"
                        : "rounded-full bg-panel-2 px-2.5 py-1 font-mono text-[11px] text-slate-400 ring-1 ring-edge ring-inset hover:text-slate-200"
                    }
                  >
                    {t.label}
                  </button>
                );
              })}
            </div>

            <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 xl:grid-cols-5">
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                Classification
                <select
                  aria-label="Filter by classification"
                  value={draftTlp}
                  onChange={(e) => setDraftTlp(e.target.value)}
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
                >
                  <option value="">All markings</option>
                  {TLP_LEVELS.map((l) => (
                    <option key={l.marking} value={l.marking}>
                      {l.marking}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                Report
                <input
                  type="text"
                  aria-label="Filter by report"
                  value={draftReport}
                  onChange={(e) => setDraftReport(e.target.value)}
                  placeholder="e.g. ics_report"
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                Recipient
                <input
                  type="text"
                  aria-label="Filter by recipient"
                  value={draftRecipient}
                  onChange={(e) => setDraftRecipient(e.target.value)}
                  placeholder="e.g. ISAC"
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                From
                <input
                  type="date"
                  aria-label="Filter from date"
                  value={draftSince}
                  onChange={(e) => setDraftSince(e.target.value)}
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-slate-400">
                To
                <input
                  type="date"
                  aria-label="Filter to date"
                  value={draftUntil}
                  onChange={(e) => setDraftUntil(e.target.value)}
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
                />
              </label>
            </div>
            <div className="mt-2 flex gap-2">
              <button
                type="button"
                onClick={applyFilters}
                className="rounded-md bg-signal-dim px-3 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70"
              >
                APPLY FILTERS
              </button>
              <button
                type="button"
                onClick={clearFilters}
                className="rounded-md px-3 py-1.5 font-mono text-[11px] text-slate-500 hover:bg-panel-2 hover:text-slate-200"
              >
                CLEAR
              </button>
            </div>

            {historyLoading && (
              <p className="mt-4 flex items-center gap-2 font-mono text-[11px] text-slate-500">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> LOADING HISTORY…
              </p>
            )}
            {historyError && (
              <p className="mt-4 font-mono text-[11px] text-crimson">
                {historyError}{" "}
                <button
                  type="button"
                  onClick={() => requestHistory({ ...applied })}
                  className="underline hover:text-slate-200"
                >
                  Retry
                </button>
              </p>
            )}
            {history && !historyLoading && !historyError && (
              <>
                <p className="mt-3 font-mono text-[11px] text-slate-500">
                  {history.total} RECORD(S)
                  {history.demo ? " · ALL DEMONSTRATION" : ""}
                </p>
                {history.records.length === 0 ? (
                  <p className="mt-2 text-xs text-slate-400">
                    No records match these filters.
                  </p>
                ) : (
                  <div className="mt-2 overflow-x-auto rounded-md border border-edge">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="bg-panel-2 font-mono text-[11px] text-slate-500">
                          <th className="px-2 py-1.5 font-medium">REPORT</th>
                          <th className="px-2 py-1.5 font-medium">CLASS</th>
                          <th className="px-2 py-1.5 font-medium">RECIPIENT</th>
                          <th className="px-2 py-1.5 font-medium">FINDINGS</th>
                          <th className="px-2 py-1.5 font-medium">APPROVED</th>
                          <th className="px-2 py-1.5 font-medium">STATUS</th>
                          <th className="px-2 py-1.5 font-medium">MISP UUID</th>
                          <th className="px-2 py-1.5 font-medium">ACTION</th>
                        </tr>
                      </thead>
                      <tbody>
                        {history.records.map((r) => (
                          <Fragment key={r.id}>
                            <tr
                              onClick={() =>
                                setExpanded(expanded === r.id ? null : r.id)
                              }
                              className="cursor-pointer border-t border-edge/60 hover:bg-panel-2/50"
                            >
                              <td className="max-w-44 truncate px-2 py-1.5 font-mono text-[11px] text-slate-200">
                                <span className="mr-1 inline-block w-3 align-middle text-slate-500">
                                  {expanded === r.id ? (
                                    <ChevronDown className="h-3 w-3" />
                                  ) : (
                                    <ChevronRight className="h-3 w-3" />
                                  )}
                                </span>
                                {r.report_id}
                              </td>
                              <td className="px-2 py-1.5">
                                <span
                                  className={`rounded-full px-2 py-0.5 font-mono text-[11px] ring-1 ring-inset ${TLP_TONE[r.classification] ?? "text-slate-300 ring-edge"}`}
                                >
                                  {r.classification}
                                </span>
                              </td>
                              <td className="max-w-44 truncate px-2 py-1.5 text-slate-300">
                                {r.destination_label}
                              </td>
                              <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap text-slate-400">
                                {findingsLine(r.findings)}
                              </td>
                              <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap text-slate-400">
                                {shortTs(r.approved_at)}
                              </td>
                              <td className="px-2 py-1.5">
                                <span
                                  className={`rounded-full px-2 py-0.5 font-mono text-[11px] whitespace-nowrap ring-1 ring-inset ${STATUS_TONE[r.status] ?? "text-slate-300 ring-edge"}`}
                                >
                                  {r.status}
                                </span>
                              </td>
                              <td className="px-2 py-1.5 font-mono text-[11px] text-slate-400">
                                {r.misp_event_uuid ? (
                                  <span title={r.misp_event_uuid}>
                                    {r.misp_event_uuid.slice(0, 8)}…
                                  </span>
                                ) : (
                                  "—"
                                )}
                              </td>
                              <td
                                className="px-2 py-1.5"
                                onClick={(e) => e.stopPropagation()}
                              >
                                <RecordActions record={r} />
                              </td>
                            </tr>
                            {expanded === r.id && (
                              <tr key={`${r.id}-detail`} className="border-t border-edge/60 bg-abyss">
                                <td colSpan={8} className="px-3 py-2">
                                  <dl className="grid grid-cols-1 gap-x-6 gap-y-1 font-mono text-[11px] sm:grid-cols-2">
                                    <div>
                                      <dt className="text-slate-500">RECORD</dt>
                                      <dd className="text-slate-300">
                                        {r.id} · PACKAGE {r.package_id.slice(0, 12)} ·
                                        ANALYST {r.analyst}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt className="text-slate-500">DESTINATION</dt>
                                      <dd className="text-slate-300">
                                        {r.destination_kind} ·{" "}
                                        {JSON.stringify(r.destination_detail)}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt className="text-slate-500">CREATED / UPDATED</dt>
                                      <dd className="text-slate-300">
                                        {shortTs(r.created_at)} / {shortTs(r.updated_at)}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt className="text-slate-500">DATA</dt>
                                      <dd className="text-amber-glow">
                                        {r.demo ? "DEMONSTRATION" : "LIVE"}
                                      </dd>
                                    </div>
                                  </dl>
                                  {r.error && (
                                    <p className="mt-1 flex gap-1.5 font-mono text-[11px] text-crimson">
                                      <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                                      {r.error}
                                    </p>
                                  )}
                                  {r.misp_event_uuid && (
                                    <p className="mt-1 font-mono text-[11px] break-all text-slate-400">
                                      MISP EVENT {r.misp_event_uuid}
                                    </p>
                                  )}
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </>
        )}

        {tab === "audit" && (
          <>
            <p className="mt-3 rounded-md border border-edge bg-abyss p-3 font-mono text-[11px] leading-relaxed text-slate-400">
              LIVE AUDIT LOG — real append-only server events (metadata only, no
              report bodies or credentials). Entries cannot be edited or deleted
              through the application.
            </p>
            <div className="mt-3 flex flex-wrap items-end gap-2">
              <label className="flex max-w-xs flex-1 flex-col gap-1 text-xs text-slate-400">
                Event type
                <input
                  type="text"
                  aria-label="Filter audit by event"
                  value={auditEvent}
                  onChange={(e) => setAuditEvent(e.target.value)}
                  placeholder="e.g. distribution_denied"
                  className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 placeholder:text-slate-600 focus:border-signal focus:outline-none"
                />
              </label>
              <button
                type="button"
                onClick={() => loadAudit(auditEvent.trim())}
                className="rounded-md bg-signal-dim px-3 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70"
              >
                APPLY
              </button>
            </div>
            {auditLoading && (
              <p className="mt-4 flex items-center gap-2 font-mono text-[11px] text-slate-500">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> LOADING AUDIT…
              </p>
            )}
            {auditError && (
              <p className="mt-4 font-mono text-[11px] text-crimson">
                {auditError}{" "}
                <button
                  type="button"
                  onClick={() => loadAudit(auditEvent.trim())}
                  className="underline hover:text-slate-200"
                >
                  Retry
                </button>
              </p>
            )}
            {audit && !auditLoading && !auditError && (
              <>
                <p className="mt-3 font-mono text-[11px] text-slate-500">
                  {audit.total} EVENT(S), NEWEST FIRST
                </p>
                {audit.events.length === 0 ? (
                  <p className="mt-2 text-xs text-slate-400">
                    No audit events yet — analyze or share a report to generate
                    some.
                  </p>
                ) : (
                  <div className="mt-2 max-h-96 overflow-auto rounded-md border border-edge">
                    <table className="w-full text-left text-xs">
                      <thead className="sticky top-0 bg-panel-2 font-mono text-[11px] text-slate-500">
                        <tr>
                          <th className="px-2 py-1.5 font-medium">TIME</th>
                          <th className="px-2 py-1.5 font-medium">EVENT</th>
                          <th className="px-2 py-1.5 font-medium">DETAIL</th>
                        </tr>
                      </thead>
                      <tbody>
                        {audit.events.map((e, i) => (
                          <tr
                            key={`${String(e.id ?? i)}`}
                            className="border-t border-edge/60"
                          >
                            <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap text-slate-400">
                              {shortTs(typeof e.ts === "string" ? e.ts : null)}
                            </td>
                            <td className="px-2 py-1.5 font-mono text-[11px] whitespace-nowrap text-slate-200">
                              {String(e.event ?? "?")}
                            </td>
                            <td className="px-2 py-1.5 font-mono text-[11px] break-all text-slate-500">
                              {auditSummary(e)}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </section>
    </div>
  );
}
