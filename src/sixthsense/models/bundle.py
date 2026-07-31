"""The config bundle: what the control plane publishes and a node fetches.

A bundle is immutable once published. Nodes cache the last known good bundle and keep
running from it if the control plane is unreachable, which is the property that keeps the
UI out of the data path.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field


def checksum(text: str) -> str:
    """SHA-256 over the config text. Covers exactly what the node will write to disk."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class BundleManifest(BaseModel):
    """Metadata a node can check before applying a bundle."""

    model_config = ConfigDict(extra="forbid")

    version: int
    checksum: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    created_by: str
    rule_ids: list[str] = Field(default_factory=list)
    default_action: str
    shadow_mode: bool
    vector_min_version: str
    note: str = ""


class Bundle(BaseModel):
    """A manifest plus the Vector configuration it describes."""

    model_config = ConfigDict(extra="forbid")

    manifest: BundleManifest
    config_toml: str

    def verify(self) -> bool:
        return checksum(self.config_toml) == self.manifest.checksum


class BundleSummary(BaseModel):
    """What the version list endpoint returns."""

    model_config = ConfigDict(extra="forbid")

    version: int
    checksum: str
    created_at: datetime
    created_by: str
    rule_count: int
    active: bool
    note: str = ""
