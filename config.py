"""
Centralized configuration for the Telco Multi-Agent AIOps Platform.

All tunables are loaded from environment variables (or .env) via pydantic-settings,
ensuring 12-factor compliance and type-safe defaults for local lab runs.
"""

from __future__ import annotations

from functools import lru_cache
import os
from pathlib import Path
import socket
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent


class Settings(BaseSettings):
    """Runtime settings for the AIOps pipeline."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---
    app_name: str = "telco-multi-agent-aiops"
    app_env: Literal["lab", "staging", "production"] = "lab"
    log_level: str = "INFO"

    # --- Syslog UDP receiver ---
    syslog_bind_host: str = "0.0.0.0"
    syslog_bind_port: int = 5514  # 514 requires root; 5514 for lab

    # --- Redis Streams ---
    redis_url: str = "redis://localhost:6379/0"
    redis_stream_key: str = "telco:syslog:events"
    redis_dlq_stream_key: str = "telco:syslog:dlq"
    redis_consumer_group: str = "aiops-pipeline"
    redis_consumer_name: str = Field(
        default_factory=lambda: f"{socket.gethostname()}-{os.getpid()}"
    )
    redis_block_ms: int = 2000
    redis_batch_size: int = 10
    redis_pending_idle_ms: int = 30_000
    redis_max_delivery_attempts: int = 3
    redis_stream_maxlen: int = 500_000

    # --- Qdrant ---
    qdrant_url: str = "http://localhost:6333"
    qdrant_collection: str = "telco_sop_knowledge"
    qdrant_vector_size: int = 1536  # text-embedding-3-small
    sop_knowledge_dir: Path = PROJECT_ROOT / "knowledge" / "sops"

    # --- LLM / Embeddings ---
    openai_api_key: SecretStr = Field(default=SecretStr(""))
    openai_base_url: str | None = None
    llm_model: str = "gpt-4o-mini"
    embedding_model: str = "text-embedding-3-small"
    llm_provider: str = "openai"  # openai | deepseek
    llm_temperature: float = 0.0
    llm_max_retries: int = 3
    # DeepSeek V4 enables chain-of-thought by default, which multiplies output
    # tokens. Diagnosis prompts are short and schema-bound, so default to the
    # cheaper non-thinking path.
    deepseek_thinking: bool = False
    # function_calling works on both OpenAI and DeepSeek; json_schema (the
    # langchain default) is not accepted by every OpenAI-compatible backend.
    llm_structured_method: Literal[
        "function_calling", "json_schema", "json_mode"
    ] = "function_calling"
    # When True (or when no API key), agents use deterministic heuristics.
    offline_mode: bool = False

    # --- Network lab targets (Containerlab FRR nodes) ---
    # Override via env if management IPs differ after `containerlab deploy`.
    lab_nodes_json: str = (
        '{"r1":{"host":"172.20.20.11","port":22,"username":"root","password":"",'
        '"device_type":"linux","mgmt_ip":"192.168.12.1"},'
        '"r2":{"host":"172.20.20.12","port":22,"username":"root","password":"",'
        '"device_type":"linux","mgmt_ip":"192.168.12.2"}}'
    )
    # Prefer docker exec against containerlab containers when True.
    prefer_docker_exec: bool = True
    # Online diagnostics must not silently turn connection errors into evidence.
    allow_simulated_telemetry: bool = False
    docker_container_prefix: str = "clab-telco-aiops-"

    # --- LangGraph persistence ---
    checkpoint_db_path: Path = PROJECT_ROOT / "lab" / "checkpoints.sqlite"

    # --- Observability ---
    otel_enabled: bool = True
    otel_service_name: str = "telco-aiops-pipeline"
    otel_exporter_endpoint: str = "http://localhost:4318"
    traceloop_api_key: SecretStr = Field(default=SecretStr(""))
    langfuse_public_key: str = ""
    langfuse_secret_key: SecretStr = Field(default=SecretStr(""))
    langfuse_host: str = "https://cloud.langfuse.com"

    def resolved_llm_base_url(self) -> str | None:
        if self.openai_base_url:
            return self.openai_base_url
        if self.llm_provider.lower() == "deepseek":
            return "https://api.deepseek.com"
        return None

    def resolved_llm_model(self) -> str:
        if self.llm_provider.lower() != "deepseek":
            return self.llm_model
        # deepseek-chat / deepseek-v4-flash are retired aliases.
        if self.llm_model in {
            "gpt-4o-mini",
            "gpt-4o",
            "",
            "deepseek-chat",
            "deepseek-reasoner",
            "deepseek-v4-flash",
        }:
            return "deepseek-flash"
        return self.llm_model

    def resolved_llm_extra_body(self) -> dict[str, object] | None:
        """Provider-specific body params (DeepSeek thinking-mode toggle)."""
        if self.llm_provider.lower() != "deepseek":
            return None
        return {"thinking": {"type": "enabled" if self.deepseek_thinking else "disabled"}}

    def is_offline(self) -> bool:
        """Return True when LLM calls should be skipped."""
        key = self.openai_api_key.get_secret_value().strip()
        return self.offline_mode or not key


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
