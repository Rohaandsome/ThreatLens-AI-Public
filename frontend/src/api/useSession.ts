import { useCallback, useEffect, useState } from "react";
import {
  ApiError,
  fetchAuthStatus,
  grantAiConsent,
  login as loginRequest,
  logout as logoutRequest,
  setCsrfToken,
} from "./client";
import type { AuthStatusResponse } from "./types";

export interface Session {
  status: AuthStatusResponse | null;
  checking: boolean;
  loginError: string | null;
  loggingIn: boolean;
  consenting: boolean;
  consentError: string | null;
  login: (key: string) => Promise<boolean>;
  logout: () => Promise<void>;
  refresh: () => void;
  consent: () => Promise<boolean>;
}

/** Operator session: login gate state, role, CSRF token, config flags. */
export function useSession(): Session {
  const [status, setStatus] = useState<AuthStatusResponse | null>(null);
  const [checking, setChecking] = useState(true);
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loggingIn, setLoggingIn] = useState(false);
  const [nonce, setNonce] = useState(0);
  const [consenting, setConsenting] = useState(false);
  const [consentError, setConsentError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchAuthStatus()
      .then((res) => {
        if (cancelled) return;
        setStatus(res);
        setCsrfToken(res.csrf_token);
        setChecking(false);
      })
      .catch(() => {
        if (cancelled) return;
        setStatus(null);
        setCsrfToken(null);
        setChecking(false);
      });
    return () => {
      cancelled = true;
    };
  }, [nonce]);

  const login = useCallback(async (key: string): Promise<boolean> => {
    setLoggingIn(true);
    setLoginError(null);
    try {
      const res = await loginRequest(key);
      setCsrfToken(res.csrf_token);
      const fresh = await fetchAuthStatus();
      setStatus(fresh);
      return true;
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.code === "auth_not_configured") {
          setLoginError(
            "Authentication is not configured. Generate OPERATOR_API_KEY and " +
              "ADMIN_API_KEY in backend/.env and restart the backend.",
          );
        } else if (err.code === "login_throttled") {
          setLoginError("Too many login attempts. Wait a minute and retry.");
        } else {
          setLoginError("Invalid operator key.");
        }
      } else {
        setLoginError("Login failed. Is the backend running?");
      }
      return false;
    } finally {
      setLoggingIn(false);
    }
  }, []);

  const logout = useCallback(async (): Promise<void> => {
    await logoutRequest().catch(() => undefined);
    setStatus(null);
    setCsrfToken(null);
    setChecking(true);
    setNonce((n) => n + 1);
  }, []);

  const refresh = useCallback(() => {
    setChecking(true);
    setNonce((n) => n + 1);
  }, []);

  const consent = useCallback(async (): Promise<boolean> => {
    setConsenting(true);
    setConsentError(null);
    try {
      const res = await grantAiConsent();
      if (!res.acknowledged) {
        setConsentError("The server did not record your acknowledgment. Retry.");
        return false;
      }
      setStatus((prev) => (prev ? { ...prev, ai_consent: true } : prev));
      return true;
    } catch (err) {
      if (err instanceof ApiError && err.code === "rate_limited") {
        setConsentError(
          err.retryAfter
            ? `Too many requests. Wait ${err.retryAfter} seconds and retry.`
            : "Too many requests. Wait a moment and retry.",
        );
      } else {
        setConsentError("Could not record acknowledgment. Is the backend running?");
      }
      return false;
    } finally {
      setConsenting(false);
    }
  }, []);

  return {
    status,
    checking,
    loginError,
    loggingIn,
    consenting,
    consentError,
    login,
    logout,
    refresh,
    consent,
  };
}
