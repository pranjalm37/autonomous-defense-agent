from functools import lru_cache
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    """
    Single config object. Pydantic reads values from environment / .env file,
    validates types, and raises on startup if anything is missing.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────
    app_env: str = "development"
    app_name: str = "AADA Backend"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"

    # ── Database ─────────────────────────────────────────
    database_url: str  # required — no default forces explicit config
    database_pool_size: int = 10
    database_max_overflow: int = 20

    # ── JWT ──────────────────────────────────────────────
    secret_key: str          # required
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # ── CORS ─────────────────────────────────────────────
    # NoDecode: stop pydantic-settings from JSON-decoding these env vars before
    # our validator runs, so plain values like "*" or "a,b" don't crash startup.
    allowed_origins: Annotated[list[str], NoDecode] = ["http://localhost:3000"]
    allowed_hosts: Annotated[list[str], NoDecode] = ["localhost", "127.0.0.1"]

    # ── Logging ──────────────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "json"    # json | console

    # ── AI / RAG ─────────────────────────────────────────
    openai_api_key: str | None = None              # falls back to offline embeddings if unset
    embedding_model: str = "text-embedding-3-small"
    ai_model: str = "gpt-4o-mini"                  # SOC analyst chat model
    ai_temperature: float = 0.1                    # low = consistent analysis

    # ── Auth / seeding ───────────────────────────────────
    auto_seed: bool = True                          # seed roles on startup
    default_admin_email: str | None = None          # optional bootstrap admin
    default_admin_password: str | None = None

    # ── Decision engine ──────────────────────────────────
    decision_mode: str = "assisted"                # monitor | assisted | autonomous

    # ── Response engine safety policy ────────────────────
    response_protected_accounts: Annotated[list[str], NoDecode] = ["admin", "root", "breakglass"]
    response_ip_allowlist: Annotated[list[str], NoDecode] = []   # IPs the engine must never block

    # ── External threat-intel APIs (optional; clients enabled when key present) ─
    virustotal_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    nvd_api_key: str | None = None                 # NVD works without a key (lower quota)
    # ChromaDB: set a persist dir (local) OR host+port (server). Unset → in-memory.
    chroma_persist_dir: str | None = None
    chroma_host: str | None = None
    chroma_port: int = 8000
    rag_collection: str = "aada_knowledge"
    rag_chunk_size: int = 800
    rag_chunk_overlap: int = 120
    rag_top_k: int = 5

    @field_validator(
        "allowed_origins", "allowed_hosts",
        "response_protected_accounts", "response_ip_allowlist",
        mode="before",
    )
    @classmethod
    def parse_comma_list(cls, v: str | list) -> list[str]:
        """Accept a JSON array, a 'a,b,c' string, or a proper list from env."""
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                import json
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache  # instantiate once — same object reused across the app
def get_settings() -> Settings:
    return Settings()
