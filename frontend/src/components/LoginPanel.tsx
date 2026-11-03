import { useState } from "react";
import { KeyRound, Loader2, ShieldHalf, TriangleAlert } from "lucide-react";

export default function LoginPanel({
  loginError,
  loggingIn,
  authConfigured,
  onLogin,
}: {
  loginError: string | null;
  loggingIn: boolean;
  authConfigured: boolean | null;
  onLogin: (key: string) => void;
}) {
  const [key, setKey] = useState("");

  function submit(e: React.FormEvent) {
    e.preventDefault();
    if (key.trim() && !loggingIn) onLogin(key.trim());
  }

  return (
    <div className="mx-auto flex w-full max-w-md flex-col gap-4 px-4 py-16">
      <section className="rounded-lg border border-edge bg-panel p-6">
        <div className="flex items-center gap-2.5">
          <span className="flex h-9 w-9 items-center justify-center rounded-md bg-signal-dim">
            <ShieldHalf className="h-5 w-5 text-signal" strokeWidth={2.2} />
          </span>
          <div>
            <h1 className="text-[15px] font-bold tracking-tight text-white">
              ThreatLens AI
            </h1>
            <p className="font-mono text-[11px] text-slate-400">
              OPERATOR LOGIN
            </p>
          </div>
        </div>
        <p className="mt-3 text-xs leading-relaxed text-slate-400">
          Enter an operator key from the backend configuration. The key is
          verified server-side and never stored in the browser — this session
          uses an HttpOnly cookie plus a CSRF token kept in memory only.
        </p>
        {authConfigured === false && (
          <p className="mt-3 flex gap-2 rounded-md border border-amber-glow/40 bg-amber-glow/5 p-3 font-mono text-[11px] leading-relaxed text-amber-glow">
            <TriangleAlert className="h-4 w-4 shrink-0" />
            Authentication is not configured on the backend. Generate
            OPERATOR_API_KEY and ADMIN_API_KEY in backend/.env and restart.
          </p>
        )}
        <form onSubmit={submit} className="mt-4 flex flex-col gap-2">
          <label className="flex flex-col gap-1 text-xs text-slate-400">
            Operator key
            <input
              type="password"
              aria-label="Operator key"
              autoComplete="off"
              spellCheck={false}
              value={key}
              onChange={(e) => setKey(e.target.value)}
              placeholder="Paste key from backend/.env"
              className="rounded-md border border-edge bg-abyss px-3 py-2 text-sm text-slate-200 placeholder:text-slate-600 focus:border-signal focus:ring-1 focus:ring-signal focus:outline-none"
            />
          </label>
          {loginError && (
            <p className="font-mono text-[11px] text-crimson">{loginError}</p>
          )}
          <button
            type="submit"
            disabled={loggingIn || !key.trim()}
            className="mt-1 inline-flex items-center justify-center gap-1.5 rounded-md bg-signal-dim px-3 py-2 text-xs font-medium text-signal ring-1 ring-signal/30 ring-inset hover:bg-signal-dim/70 disabled:opacity-60"
          >
            {loggingIn ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <KeyRound className="h-4 w-4" />
            )}
            Log in
          </button>
        </form>
      </section>
      <p className="text-center font-mono text-[11px] text-slate-600">
        LOCAL SINGLE-OPERATOR CONSOLE · KEEP THE BACKEND ON LOOPBACK
      </p>
    </div>
  );
}
