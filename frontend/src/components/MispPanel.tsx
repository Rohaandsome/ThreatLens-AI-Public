import { useState } from "react";
import {
  ExternalLink,
  Eye,
  Loader2,
  Megaphone,
  PlugZap,
  Send,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import {
  ApiError,
  mispCreate,
  mispPreview,
  mispPublish,
  mispTest,
} from "../api/client";
import type {
  MispCreateResponse,
  MispDestinationChoice,
  MispPreviewResponse,
  MispPublishResponse,
  MispTestResponse,
  SharePrepareResponse,
} from "../api/types";

const DESTINATIONS = [
  { value: 0, label: "Your organisation only" },
  { value: 1, label: "This community only" },
  { value: 2, label: "Connected communities" },
  { value: 3, label: "All communities" },
  { value: 4, label: "Sharing group" },
];

function errorText(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) return fallback;
  const next =
    err.code === "destination_changed"
      ? " Re-preview the event: its live destination no longer matches the approved one."
      : "";
  return `${err.message}${next} (${err.code})`;
}

export default function MispPanel({
  pkg,
  role,
}: {
  pkg: SharePrepareResponse;
  role: string;
}) {
  const isAdmin = role === "administrator";
  const isRed = pkg.classification.proposed === "TLP:RED";

  const [test, setTest] = useState<MispTestResponse | null>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);

  const [distribution, setDistribution] = useState(0);
  const [groupId, setGroupId] = useState("");
  const effectiveDist = isRed ? 0 : distribution;
  const groupValue =
    effectiveDist === 4 && /^\d+$/.test(groupId.trim()) ? parseInt(groupId.trim(), 10) : null;
  const groupValid = effectiveDist !== 4 || (groupValue !== null && groupValue > 0);

  const [preview, setPreview] = useState<MispPreviewResponse | null>(null);
  const [previewFor, setPreviewFor] = useState<string>("");
  const [previewing, setPreviewing] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const destKey = `${effectiveDist}:${groupValue ?? ""}`;
  const previewCurrent = preview !== null && previewFor === destKey;

  const [approveCreate, setApproveCreate] = useState(false);
  const [confirmCreate, setConfirmCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<MispCreateResponse | null>(null);
  const [createError, setCreateError] = useState<string | null>(null);

  const [publishUnlocked, setPublishUnlocked] = useState(false);
  const [approvePublish, setApprovePublish] = useState(false);
  const [confirmPublish, setConfirmPublish] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [published, setPublished] = useState<MispPublishResponse | null>(null);
  const [publishError, setPublishError] = useState<string | null>(null);

  function destination(): MispDestinationChoice {
    return { distribution: effectiveDist, sharing_group_id: groupValue };
  }

  async function handleTest() {
    setTesting(true);
    setTestError(null);
    try {
      setTest(await mispTest());
    } catch (err) {
      setTestError(errorText(err, "Connection test failed."));
    } finally {
      setTesting(false);
    }
  }

  async function handlePreview() {
    setPreviewing(true);
    setPreviewError(null);
    try {
      const res = await mispPreview(pkg, destination());
      setPreview(res);
      setPreviewFor(destKey);
    } catch (err) {
      setPreviewError(errorText(err, "Preview failed."));
    } finally {
      setPreviewing(false);
    }
  }

  async function handleCreate() {
    setCreating(true);
    setCreateError(null);
    try {
      const res = await mispCreate(pkg, "", destination(), {
        approved: approveCreate,
        confirmed: confirmCreate,
      });
      setCreated(res);
    } catch (err) {
      setCreateError(errorText(err, "Draft creation failed."));
    } finally {
      setCreating(false);
    }
  }

  async function handlePublish() {
    if (!created) return;
    setPublishing(true);
    setPublishError(null);
    try {
      const res = await mispPublish(created.event_uuid, "", {
        approved: approvePublish,
        confirmed: confirmPublish,
      });
      setPublished(res);
    } catch (err) {
      setPublishError(errorText(err, "Publishing failed."));
    } finally {
      setPublishing(false);
    }
  }

  const destLabel =
    DESTINATIONS.find((d) => d.value === effectiveDist)?.label ?? `Level ${effectiveDist}`;

  return (
    <section
      aria-label="MISP export"
      className="mt-3 rounded-md border border-edge bg-abyss p-4"
    >
      <h3 className="font-mono text-[11px] font-semibold tracking-widest text-slate-400">
        3 · MISP EXPORT — UNPUBLISHED DRAFTS ONLY
      </h3>
      <p className="mt-1 text-xs leading-relaxed text-slate-500">
        Nothing contacts MISP until you click. Drafts are created unpublished; a
        separate explicit action publishes.
      </p>

      {/* 1 — connection */}
      <div className="mt-3 rounded-md border border-edge bg-panel p-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[11px] tracking-wide text-slate-400">
            1 · CONNECTION
          </span>
          <button
            type="button"
            onClick={handleTest}
            disabled={testing}
            className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:opacity-60"
          >
            {testing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <PlugZap className="h-3.5 w-3.5" />
            )}
            TEST CONNECTION
          </button>
          {test?.ok && (
            <span className="inline-flex items-center gap-1 font-mono text-[11px] text-signal">
              <ShieldCheck className="h-3.5 w-3.5" />
              {test.org} · {test.role} · add:{test.can_add ? "yes" : "no"} ·
              publish:{test.can_publish ? "yes" : "no"}
            </span>
          )}
        </div>
        {test && !test.ok && (
          <p className="mt-2 font-mono text-[11px] text-crimson">
            Connection failed: {test.error?.message} ({test.error?.code}). Check
            MISP_URL and MISP_API_KEY in backend/.env.
          </p>
        )}
        {testError && (
          <p className="mt-2 font-mono text-[11px] text-crimson">{testError}</p>
        )}
      </div>

      {/* 2 — destination */}
      <div className="mt-3 rounded-md border border-edge bg-panel p-3">
        <p className="font-mono text-[11px] tracking-wide text-slate-400">
          2 · DESTINATION (CHOSEN BY YOU — NEVER INFERRED FROM TLP)
        </p>
        {isRed && (
          <p className="mt-2 font-mono text-[11px] text-crimson">
            TLP:RED — drafts stay inside your organisation. Wider destinations
            are disabled and rejected by the server.
          </p>
        )}
        <div className="mt-2 flex flex-col gap-1.5" role="radiogroup" aria-label="MISP destination">
          {DESTINATIONS.map((d) => {
            const disabled = isRed && d.value !== 0;
            return (
              <label
                key={d.value}
                className={`flex cursor-pointer items-center gap-2 text-xs ${
                  disabled ? "text-slate-600" : "text-slate-300"
                }`}
              >
                <input
                  type="radio"
                  name="misp-distribution"
                  aria-label={`Destination ${d.label}`}
                  checked={effectiveDist === d.value}
                  disabled={disabled}
                  onChange={() => setDistribution(d.value)}
                  className="h-3.5 w-3.5 accent-emerald-400"
                />
                {d.label}
              </label>
            );
          })}
        </div>
        {effectiveDist === 4 && (
          <label className="mt-2 flex max-w-xs flex-col gap-1 text-xs text-slate-400">
            Sharing group ID (from your MISP instance)
            <input
              type="text"
              inputMode="numeric"
              aria-label="Sharing group ID"
              value={groupId}
              onChange={(e) => setGroupId(e.target.value)}
              placeholder="e.g. 7"
              className="rounded-md border border-edge bg-panel-2 px-2 py-1.5 text-[13px] text-slate-200 focus:border-signal focus:outline-none"
            />
          </label>
        )}
        {!groupValid && (
          <p className="mt-2 font-mono text-[11px] text-amber-glow">
            Enter a positive numeric sharing-group ID.
          </p>
        )}
      </div>

      {/* 3 — preview */}
      <div className="mt-3 rounded-md border border-edge bg-panel p-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[11px] tracking-wide text-slate-400">
            3 · FULL EVENT PREVIEW (BUILT LOCALLY)
          </span>
          <button
            type="button"
            onClick={handlePreview}
            disabled={previewing || !groupValid}
            className="inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:opacity-60"
          >
            {previewing ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Eye className="h-3.5 w-3.5" />
            )}
            PREVIEW EVENT
          </button>
        </div>
        {previewError && (
          <p className="mt-2 font-mono text-[11px] text-crimson">{previewError}</p>
        )}
        {preview && (
          <div className="mt-2 rounded-md border border-edge bg-abyss p-3">
            <p className="text-xs text-slate-200">{preview.event.info}</p>
            <p className="mt-1 font-mono text-[11px] text-slate-500">
              {preview.attribute_count} ATTRIBUTE(S) · UNPUBLISHED · {destLabel.toUpperCase()}
              {preview.event.sharing_group_id != null &&
                ` · GROUP ${preview.event.sharing_group_id}`}
            </p>
            <p className="mt-1 font-mono text-[11px] text-slate-400">
              TAGS: {preview.event.tags.join(" · ") || "—"}
            </p>
            <p className="mt-1 font-mono text-[11px] text-slate-500">
              LOCAL-ONLY PREVIEW — NOTHING HAS BEEN SENT TO MISP.
            </p>
            {preview.destination_check && (
              <p
                className={`mt-1 flex gap-1.5 font-mono text-[11px] ${
                  preview.destination_check.safe ? "text-slate-400" : "text-crimson"
                }`}
              >
                {!preview.destination_check.safe && (
                  <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                )}
                {preview.destination_check.reason}
              </p>
            )}
            {preview.warnings.map((w, i) => (
              <p key={i} className="mt-1 flex gap-1.5 font-mono text-[11px] text-amber-glow">
                <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
                {w}
              </p>
            ))}
            <div className="mt-2 max-h-56 overflow-auto rounded border border-edge">
              <table className="w-full text-left font-mono text-[11px]">
                <thead className="sticky top-0 bg-panel-2 text-slate-500">
                  <tr>
                    <th className="px-2 py-1 font-medium">TYPE</th>
                    <th className="px-2 py-1 font-medium">VALUE</th>
                    <th className="px-2 py-1 font-medium">CATEGORY</th>
                    <th className="px-2 py-1 font-medium">IDS</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.event.attributes.map((a, i) => (
                    <tr key={i} className="border-t border-edge/60 text-slate-300">
                      <td className="px-2 py-1 whitespace-nowrap">{a.type}</td>
                      <td className="px-2 py-1 break-all">{a.value}</td>
                      <td className="px-2 py-1 whitespace-nowrap text-slate-500">
                        {a.category}
                      </td>
                      <td className="px-2 py-1 text-slate-500">
                        {a.to_ids ? "yes" : "no"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!previewCurrent && (
              <p className="mt-2 font-mono text-[11px] text-amber-glow">
                Destination changed since this preview — preview again before
                creating the draft.
              </p>
            )}
          </div>
        )}
      </div>

      {/* 4 — create draft */}
      <div className="mt-3 rounded-md border border-edge bg-panel p-3">
        <p className="font-mono text-[11px] tracking-wide text-slate-400">
          4 · CREATE UNPUBLISHED DRAFT
        </p>
        <div className="mt-2 flex flex-col gap-1.5 text-xs text-slate-300">
          <label className="flex cursor-pointer items-start gap-2">
            <input
              type="checkbox"
              aria-label="Approve MISP draft creation"
              checked={approveCreate}
              onChange={(e) => setApproveCreate(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 accent-emerald-400"
            />
            I approve sending this reviewed package to MISP as an unpublished draft.
          </label>
          <label className="flex cursor-pointer items-start gap-2">
            <input
              type="checkbox"
              aria-label="Confirm MISP destination"
              checked={confirmCreate}
              onChange={(e) => setConfirmCreate(e.target.checked)}
              className="mt-0.5 h-3.5 w-3.5 accent-emerald-400"
            />
            I confirm the destination: {destLabel}
            {effectiveDist === 4 && groupValid ? ` (group ${groupValue})` : ""}.
          </label>
        </div>
        <button
          type="button"
          onClick={handleCreate}
          disabled={
            creating || !approveCreate || !confirmCreate || !previewCurrent || !groupValid
          }
          title={
            !previewCurrent
              ? "Preview the event for this destination first"
              : "Create an unpublished draft event in MISP"
          }
          className="mt-2 inline-flex items-center gap-1.5 rounded-md bg-signal-dim px-2.5 py-1.5 font-mono text-[11px] font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:opacity-60"
        >
          {creating ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Send className="h-3.5 w-3.5" />
          )}
          CREATE DRAFT
        </button>
        {createError && (
          <p className="mt-2 font-mono text-[11px] text-crimson">{createError}</p>
        )}
        {created && (
          <p className="mt-2 font-mono text-[11px] text-signal">
            {created.duplicate ? "Draft already existed — reused. " : "Draft created (unpublished). "}
            <a
              href={created.url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 hover:underline"
            >
              Open event <ExternalLink className="h-3 w-3" />
            </a>
          </p>
        )}
      </div>

      {/* 5 — publish (separate, off by default) */}
      <div className="mt-3 rounded-md border border-crimson/30 bg-panel p-3">
        <p className="font-mono text-[11px] tracking-wide text-slate-400">
          5 · PUBLISH — SEPARATE ACTION, OFF BY DEFAULT
        </p>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          Publishing alerts subscribers. ThreatLens never publishes
          automatically.
        </p>
        {!isAdmin ? (
          <p className="mt-2 font-mono text-[11px] text-amber-glow">
            Requires administrator — you are signed in as {role.toUpperCase()}.
            The server enforces this regardless of what any client sends.
          </p>
        ) : !created ? (
          <p className="mt-2 font-mono text-[11px] text-slate-500">
            Create a draft first — publishing unlocks only for drafts made here.
          </p>
        ) : (
          <>
            <label className="mt-2 flex cursor-pointer items-start gap-2 text-xs text-slate-300">
              <input
                type="checkbox"
                aria-label="Enable MISP publishing"
                checked={publishUnlocked}
                onChange={(e) => setPublishUnlocked(e.target.checked)}
                className="mt-0.5 h-3.5 w-3.5 accent-rose-400"
              />
              Enable publishing for this draft (still needs approval below).
            </label>
            {publishUnlocked && (
              <div className="mt-2 flex flex-col gap-1.5 text-xs text-slate-300">
                <label className="flex cursor-pointer items-start gap-2">
                  <input
                    type="checkbox"
                    aria-label="Approve MISP publishing"
                    checked={approvePublish}
                    onChange={(e) => setApprovePublish(e.target.checked)}
                    className="mt-0.5 h-3.5 w-3.5 accent-rose-400"
                  />
                  I approve publishing this event in MISP.
                </label>
                <label className="flex cursor-pointer items-start gap-2">
                  <input
                    type="checkbox"
                    aria-label="Confirm MISP publishing"
                    checked={confirmPublish}
                    onChange={(e) => setConfirmPublish(e.target.checked)}
                    className="mt-0.5 h-3.5 w-3.5 accent-rose-400"
                  />
                  I confirm subscribers of “{destLabel}” may see this
                  intelligence.
                </label>
              </div>
            )}
            <button
              type="button"
              onClick={handlePublish}
              disabled={
                publishing ||
                !publishUnlocked ||
                !approvePublish ||
                !confirmPublish ||
                published?.published === true
              }
              title="Publish the MISP event (alerts subscribers)"
              className="mt-2 inline-flex items-center gap-1.5 rounded-md bg-crimson/15 px-2.5 py-1.5 font-mono text-[11px] font-medium text-crimson ring-1 ring-crimson/40 ring-inset hover:bg-crimson/25 disabled:opacity-60"
            >
              {publishing ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Megaphone className="h-3.5 w-3.5" />
              )}
              PUBLISH EVENT
            </button>
          </>
        )}
        {publishError && (
          <p className="mt-2 font-mono text-[11px] text-crimson">{publishError}</p>
        )}
        {published?.published && (
          <p className="mt-2 flex items-center gap-1.5 font-mono text-[11px] text-signal">
            <ShieldCheck className="h-3.5 w-3.5" />
            Event published.
          </p>
        )}
      </div>
    </section>
  );
}
