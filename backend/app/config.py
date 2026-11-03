"""Application settings loaded from environment variables / backend/.env."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Backend configuration. See backend/.env.example for documented variables."""

    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"), extra="ignore"
    )

    app_name: str = "ThreatLens AI"
    api_version: str = "0.1.0"
    environment: str = "development"

    # Comma-separated list of allowed CORS origins for the frontend dev server.
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # Meta Model API (OpenAI-compatible). Key lives ONLY in backend/.env or the
    # process environment — it is never sent to, or readable by, the frontend.
    model_api_key: str = ""
    model_api_base_url: str = "https://api.meta.ai/v1"
    model_name: str = "muse-spark-1.3"
    model_timeout_seconds: float = 120.0
    # Must cover hidden reasoning tokens plus the full JSON analysis:
    # muse-spark-1.3 spent ~3k of a 4k budget on reasoning alone.
    model_max_tokens: int = 16000

    # Upload + analysis limits.
    max_upload_bytes: int = 10 * 1024 * 1024
    max_report_chars: int = 60000

    # MISP integration (optional). The key never leaves the backend.
    misp_url: str = ""
    misp_api_key: str = ""
    misp_verify_ssl: bool = True
    misp_timeout_seconds: float = 30.0
    # Destination allowlist (H-1). Comma-separated ints, backend env only —
    # client-supplied destinations are always validated against these.
    # Distributions default to org-only; no sharing group is allowed until
    # explicitly listed. Malformed entries fail closed (deny).
    misp_allowed_distributions: str = "0"
    misp_allowed_sharing_groups: str = ""

    # Operator authentication (local MVP). Two randomly generated shared
    # secrets, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
    # OPERATOR_API_KEY grants the analyst role; ADMIN_API_KEY (must differ)
    # grants administrator. Short/missing values fail closed (see authz.py).
    operator_api_key: str = ""
    admin_api_key: str = ""
    session_timeout_seconds: int = 43200  # 12 hours

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @staticmethod
    def _parse_id_list(raw: str) -> set[int]:
        """Parse a comma-separated allowlist. Malformed input fails closed."""
        allowed: set[int] = set()
        for part in raw.split(","):
            part = part.strip()
            if not part:
                continue
            if not part.isdigit():
                return set()
            allowed.add(int(part))
        return allowed

    @property
    def misp_distribution_allowlist(self) -> set[int]:
        return self._parse_id_list(self.misp_allowed_distributions)

    @property
    def misp_sharing_group_allowlist(self) -> set[int]:
        return self._parse_id_list(self.misp_allowed_sharing_groups)


settings = Settings()
