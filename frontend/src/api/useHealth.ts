import { useEffect, useState } from "react";
import { fetchHealth, type HealthResponse } from "./client";

export type ApiState =
  | { kind: "checking" }
  | { kind: "online"; health: HealthResponse }
  | { kind: "offline" };

/** Poll backend health on mount and every 30s. Single shared poller. */
export function useHealth(): ApiState {
  const [api, setApi] = useState<ApiState>({ kind: "checking" });

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    async function poll() {
      try {
        const health = await fetchHealth(controller.signal);
        if (!cancelled) setApi({ kind: "online", health });
      } catch {
        if (!cancelled) setApi({ kind: "offline" });
      }
    }

    poll();
    const timer = setInterval(poll, 30000);
    return () => {
      cancelled = true;
      controller.abort();
      clearInterval(timer);
    };
  }, []);

  return api;
}
