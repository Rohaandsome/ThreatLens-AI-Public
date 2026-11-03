"""Server-side authentication and role-based authorization.

Local-MVP design:

- Two randomly generated shared secrets live ONLY in backend environment
  config: OPERATOR_API_KEY (analyst role) and ADMIN_API_KEY (administrator).
  Nothing is hardcoded; short/missing secrets fail closed.
- POST /api/auth/login verifies a key (constant-time) and mints a random
  session bound to a role. The browser holds the session ID in an HttpOnly,
  SameSite cookie; a synchronizer CSRF token (returned at login, kept in
  frontend memory only) must accompany every other state-changing request.
- Identity NEVER comes from request bodies, headers, or parameters — only
  from the verified session. Client-supplied analyst labels are ignored for
  identity (see test_auth.py).
- Sessions live in process memory: fine for a single-operator local backend
  (restarts invalidate sessions; use sticky sessions if ever multi-worker).
"""

import hmac
import secrets
import threading
import time
from collections import deque
from dataclasses import dataclass
from enum import IntEnum

from fastapi import Request, Response

from ..config import Settings
from ..errors import AnalysisError


class Role(IntEnum):
    anonymous = 0
    analyst = 1
    administrator = 2


SESSION_COOKIE = "threatlens_session"
CSRF_HEADER = "x-csrf-token"
MIN_SECRET_LENGTH = 32
LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW_SECONDS = 60.0


@dataclass
class _Session:
    role: Role
    csrf_token: str
    expires_at: float
    ai_consent: bool = False


_sessions: dict[str, _Session] = {}
_login_attempts: dict[str, deque[float]] = {}
_lock = threading.Lock()


def clear_auth_state() -> None:
    """Drop all sessions and throttle counters (tests only)."""
    with _lock:
        _sessions.clear()
        _login_attempts.clear()


def _secret_ok(value: str) -> bool:
    return isinstance(value, str) and len(value) >= MIN_SECRET_LENGTH


def auth_configured(settings: Settings) -> tuple[bool, bool]:
    """(operator_usable, admin_usable). Equal secrets collapse to operator."""
    operator_ok = _secret_ok(settings.operator_api_key)
    admin_ok = _secret_ok(settings.admin_api_key) and (
        settings.admin_api_key != settings.operator_api_key
    )
    return operator_ok, admin_ok


def check_login_throttle(request: Request) -> None:
    """Sliding-window cap on login attempts per client IP."""
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _lock:
        attempts = _login_attempts.setdefault(ip, deque())
        while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
            attempts.popleft()
        if len(attempts) >= LOGIN_MAX_ATTEMPTS:
            raise AnalysisError(
                429,
                "login_throttled",
                "Too many login attempts. Wait a minute and retry.",
                retry_after="60",
            )
        attempts.append(now)


def _matches(presented: str, expected: str) -> bool:
    try:
        return hmac.compare_digest(presented.encode(), expected.encode())
    except (TypeError, ValueError):
        return False


def login(
    settings: Settings, key: str, request: Request
) -> tuple[str, Role, str]:
    """Verify an operator key; returns (session_token, role, csrf_token)."""
    check_login_throttle(request)
    operator_ok, admin_ok = auth_configured(settings)
    if not operator_ok and not admin_ok:
        raise AnalysisError(
            503,
            "auth_not_configured",
            "Authentication is not configured. Generate OPERATOR_API_KEY "
            "(and ADMIN_API_KEY) in backend/.env and restart the backend.",
        )
    if not isinstance(key, str) or not key:
        raise AnalysisError(401, "invalid_credentials", "Invalid operator key.")
    if admin_ok and _matches(key, settings.admin_api_key):
        role = Role.administrator
    elif operator_ok and _matches(key, settings.operator_api_key):
        role = Role.analyst
    else:
        raise AnalysisError(401, "invalid_credentials", "Invalid operator key.")
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    with _lock:
        _sessions[token] = _Session(
            role=role,
            csrf_token=csrf_token,
            expires_at=time.time() + settings.session_timeout_seconds,
        )
    return token, role, csrf_token


def _session_for(request: Request) -> _Session | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    with _lock:
        session = _sessions.get(token)
        if session is None:
            return None
        if session.expires_at < time.time():
            del _sessions[token]
            return None
        return session


def resolve_role(request: Request) -> Role:
    """Return the caller's verified session role (anonymous when none).

    Client-supplied identity claims (bodies, headers, parameters) are
    deliberately ignored — only the HttpOnly session cookie counts.
    """
    session = _session_for(request)
    return session.role if session else Role.anonymous


def csrf_token_for(request: Request) -> str | None:
    """Current session's CSRF token (None when logged out/expired)."""
    session = _session_for(request)
    return session.csrf_token if session else None


def ai_consented(request: Request) -> bool:
    """Whether this session acknowledged AI processing of uploads."""
    session = _session_for(request)
    return bool(session and session.ai_consent)


def grant_ai_consent(request: Request) -> bool:
    """Record AI-processing acknowledgment. True when newly granted."""
    session = _session_for(request)
    if session is None:
        raise AnalysisError(
            401, "authentication_required", "Log in to continue."
        )
    if session.ai_consent:
        return False
    with _lock:
        session.ai_consent = True
    return True


def require_ai_consent(request: Request) -> None:
    """Gate for /api/analyze: per-session acknowledgment required."""
    if not ai_consented(request):
        raise AnalysisError(
            403,
            "consent_required",
            "AI processing acknowledgment is required before analysis. "
            "Confirm the AI processing notice first.",
        )


def current_actor(request: Request) -> str:
    """Server-derived actor label for audit identity. Raises when anonymous."""
    session = _session_for(request)
    if session is None:
        raise AnalysisError(
            401, "authentication_required", "Log in to continue."
        )
    return "administrator" if session.role == Role.administrator else "operator"


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        secure=(settings.environment == "production"),
        path="/",
        max_age=settings.session_timeout_seconds,
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


def destroy_session(request: Request) -> None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with _lock:
            _sessions.pop(token, None)


def require_role(request: Request, settings: Settings, minimum: Role, action: str) -> Role:
    """Fail-closed gate: configured auth, live session, sufficient role."""
    operator_ok, admin_ok = auth_configured(settings)
    if not operator_ok and not admin_ok:
        raise AnalysisError(
            503,
            "auth_not_configured",
            f"'{action}' is unavailable: authentication is not configured.",
        )
    role = resolve_role(request)
    if role == Role.anonymous:
        raise AnalysisError(
            401,
            "authentication_required",
            f"'{action}' needs a logged-in operator.",
        )
    if role < minimum:
        raise AnalysisError(
            403,
            "forbidden",
            f"'{action}' needs the {minimum.name} role.",
        )
    return role


def require_csrf(request: Request) -> None:
    """Synchronizer CSRF check for state-changing requests."""
    session = _session_for(request)
    presented = request.headers.get(CSRF_HEADER, "")
    if (
        session is None
        or not presented
        or not _matches(presented, session.csrf_token)
    ):
        raise AnalysisError(
            403, "csrf_required", "Missing or invalid CSRF token."
        )


def authorized(settings: Settings, minimum: Role, action: str, *, csrf: bool):
    """FastAPI dependency factory: auth (+CSRF) returning the actor label."""

    def dependency(request: Request) -> str:
        require_role(request, settings, minimum, action)
        if csrf:
            require_csrf(request)
        return current_actor(request)

    return dependency


def require_role_for(role: Role, minimum: Role, action: str) -> None:
    """Pure role check for the state machine (role already resolved).

    Anonymous callers get `distribution_disabled` (the machine has no login
    context to 401 against); insufficient authenticated roles get `forbidden`.
    """
    if role >= minimum:
        return
    if role == Role.anonymous:
        raise AnalysisError(
            403,
            "distribution_disabled",
            f"'{action}' needs an authenticated analyst or administrator.",
        )
    raise AnalysisError(
        403,
        "forbidden",
        f"'{action}' needs the {minimum.name} role.",
    )


def distribution_enabled(role: Role) -> bool:
    """Distribution actions need an authenticated role (analyst or above)."""
    return role >= Role.analyst
