"""Runtime settings for the control plane."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: The default signing key. Public, so it is a development convenience and nothing more.
#: Guarded below in the same way and for the same reason as ``dev_auth_bypass``.
DEV_JWT_SECRET = "dev-secret-change-me-please-32b+"  # noqa: S105 - a placeholder, not a secret


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SS_", env_file=".env", extra="ignore")

    # --- server -------------------------------------------------------------------
    bind_host: str = "127.0.0.1"
    bind_port: int = 8000
    database_url: str = "sqlite+pysqlite:///./sixthsense.db"

    # --- authentication -----------------------------------------------------------
    jwt_secret: str = Field(default=DEV_JWT_SECRET, min_length=32)
    """HS256 needs at least 32 bytes. PyJWT warns below that, and the warning is right.

    The default is checked in :meth:`_guard_default_secret`. Anyone who can read this
    repository can mint an admin token against a deployment that kept it.
    """
    jwt_ttl_seconds: int = 8 * 3600
    auth_mode: Literal["local", "oidc"] = "local"

    dev_auth_bypass: bool = False
    """D-34: a development convenience that cannot be enabled on a public interface.

    Enforced below rather than documented, because "the development flag reached
    production" is the failure this is meant to prevent.
    """

    # --- data plane ---------------------------------------------------------------
    vector_listen_address: str = "0.0.0.0:5514"
    vector_elk_address: str = "127.0.0.1:5140"
    vector_drop_audit_address: str = "127.0.0.1:5141"
    vector_receive_buffer_bytes: int = 26_214_400
    vector_sample_rate: int = 100

    control_plane_url: str = "http://127.0.0.1:8000"

    require_vector_on_publish: bool = True
    """D-44: refuse to publish when the vector binary is missing, so the compile and runtime
    gates cannot be skipped silently.

    Defaults to on. Turn it off only for local development without Vector installed, and
    accept that a bundle published that way has been validated by nothing.
    """

    # --- sampling -----------------------------------------------------------------
    tail_buffer_size: int = 500
    """In-memory ring buffer for the live view. Bounded and non-blocking (D-37)."""

    sample_store_max_events: int = 20_000
    """Persisted traffic sample used by the impact preview and the offline replay."""

    sample_store_retain_raw: bool = True
    """Whether the sample store keeps the original event text. Turn this off when events
    can contain regulated data (D-36) and accept a less precise impact preview."""

    @property
    def binds_loopback_only(self) -> bool:
        host = self.bind_host
        if host in {"localhost", ""}:
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    @model_validator(mode="after")
    def _guard_dev_bypass(self) -> Settings:
        if self.dev_auth_bypass and not self.binds_loopback_only:
            raise ValueError(
                "SS_DEV_AUTH_BYPASS cannot be enabled while binding a non-loopback "
                f"interface (bind_host={self.bind_host!r}). This is a hard guard, not a "
                "warning."
            )
        return self

    @model_validator(mode="after")
    def _guard_default_secret(self) -> Settings:
        """Refuse to serve a public interface with the published signing key.

        The same argument as :meth:`_guard_dev_bypass`, which this deliberately mirrors: a
        development default that reaches production is the failure, and a documented warning
        does not prevent it. Both flags are equally fatal, so both get a hard guard rather
        than one getting a guard and the other a docstring.

        Anyone who has read this repository can sign an admin token against a deployment
        that kept the default, so the failure mode is total and silent.
        """
        if self.jwt_secret == DEV_JWT_SECRET and not self.binds_loopback_only:
            raise ValueError(
                "SS_JWT_SECRET is still the published development default while binding a "
                f"non-loopback interface (bind_host={self.bind_host!r}). Anyone can forge an "
                "admin token against this deployment. Set SS_JWT_SECRET to a random value "
                "of at least 32 bytes."
            )
        return self


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings_cache() -> None:
    """Test hook. Production code never calls this."""
    global _settings
    _settings = None
