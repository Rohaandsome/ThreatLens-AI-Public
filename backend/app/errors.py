"""Structured API errors for ThreatLens AI.

All analysis failures surface as JSON ``{"detail": {"code", "message"}}``
so the frontend can render specific states (not configured, rate limited,
bad file, provider error) instead of generic failures.
"""

from fastapi import Request
from fastapi.responses import JSONResponse


class AnalysisError(Exception):
    """A failure with a machine-readable code safe to show users."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        retry_after: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retry_after = retry_after


async def analysis_error_handler(_request: Request, exc: AnalysisError) -> JSONResponse:
    headers = {"Retry-After": exc.retry_after} if exc.retry_after else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"code": exc.code, "message": exc.message}},
        headers=headers,
    )
