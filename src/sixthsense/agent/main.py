"""ssagent: the node-side config fetcher.

Small on purpose. Vector posts sampled decisions to the control plane directly, so this
process never touches event data. Its only irreducible job is getting config onto disk and
telling Vector to reload.

Behavior that matters:

* Verifies the bundle checksum before writing. A corrupted or truncated download is
  discarded, not applied.
* Writes atomically (temp file plus rename), so Vector never reads a half-written config.
* Caches the last known good bundle. If the control plane is unreachable, the node keeps
  running the cached config indefinitely. Losing the control plane must never lose events.

On Kubernetes you can drop this process entirely and mount the config from a ConfigMap with
Vector's ``--watch-config``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path

import httpx

log = logging.getLogger("ssagent")

STATE_FILE = "state.json"
CONFIG_FILE = "vector.toml"


def _checksum(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Agent:
    def __init__(
        self,
        *,
        control_plane_url: str,
        config_dir: Path,
        vector_pid_file: Path | None,
        interval: float,
        client: httpx.Client | None = None,
    ) -> None:
        self.control_plane_url = control_plane_url.rstrip("/")
        self.config_dir = config_dir
        self.vector_pid_file = vector_pid_file
        self.interval = interval
        self.client = client or httpx.Client(timeout=15.0)
        self.config_dir.mkdir(parents=True, exist_ok=True)

    # -- state ---------------------------------------------------------------------

    @property
    def state_path(self) -> Path:
        return self.config_dir / STATE_FILE

    @property
    def config_path(self) -> Path:
        return self.config_dir / CONFIG_FILE

    def current_version(self) -> int:
        try:
            return int(json.loads(self.state_path.read_text())["version"])
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            return 0

    def _save_state(self, version: int, checksum: str) -> None:
        self.state_path.write_text(
            json.dumps({"version": version, "checksum": checksum}), encoding="utf-8"
        )

    # -- apply ---------------------------------------------------------------------

    def write_config(self, config_toml: str, version: int, expected_checksum: str) -> bool:
        actual = _checksum(config_toml)
        if actual != expected_checksum:
            log.error(
                "checksum mismatch for bundle %s: expected %s got %s. Keeping cached config.",
                version,
                expected_checksum[:12],
                actual[:12],
            )
            return False

        tmp = self.config_path.with_suffix(".toml.tmp")
        tmp.write_text(config_toml, encoding="utf-8")
        os.replace(tmp, self.config_path)  # atomic within the same filesystem
        self._save_state(version, actual)
        log.info("applied bundle version %s (%s)", version, actual[:12])
        return True

    def signal_vector(self) -> None:
        """Ask Vector to reload. D-28 depends on Vector rebuilding only what changed."""
        if self.vector_pid_file is None:
            log.info("no pid file configured; relying on vector --watch-config")
            return
        try:
            pid = int(self.vector_pid_file.read_text().strip())
            os.kill(pid, signal.SIGHUP)
            log.info("sent SIGHUP to vector (pid %s)", pid)
        except (OSError, ValueError) as exc:
            log.error("could not signal vector: %s", exc)

    # -- poll ----------------------------------------------------------------------

    def poll_once(self) -> bool:
        """Fetch and apply if changed. Returns True when a new bundle was applied."""
        since = self.current_version()
        try:
            response = self.client.get(
                f"{self.control_plane_url}/api/agent/bundle", params={"since": since}
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # Deliberate: log and keep running from cache. The control plane is not in the
            # data path, and a fetch failure must never interrupt forwarding.
            log.warning("bundle fetch failed (%s); continuing on cached config", exc)
            return False

        if not payload.get("changed"):
            return False

        manifest = payload["manifest"]
        applied = self.write_config(
            payload["config_toml"], manifest["version"], manifest["checksum"]
        )
        if applied:
            self.signal_vector()
        return applied

    def run(self) -> None:
        log.info(
            "ssagent polling %s every %.0fs into %s",
            self.control_plane_url,
            self.interval,
            self.config_dir,
        )
        while True:
            try:
                self.poll_once()
            except Exception:
                log.exception("unexpected error in poll loop; continuing")
            time.sleep(self.interval)


def main() -> int:
    parser = argparse.ArgumentParser(prog="ssagent", description="sixthsense node agent")
    parser.add_argument(
        "--control-plane-url",
        default=os.environ.get("SS_CONTROL_PLANE_URL", "http://127.0.0.1:8000"),
    )
    parser.add_argument(
        "--config-dir", type=Path, default=Path(os.environ.get("SS_CONFIG_DIR", "/etc/vector"))
    )
    parser.add_argument("--vector-pid-file", type=Path, default=None)
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
    )

    agent = Agent(
        control_plane_url=args.control_plane_url,
        config_dir=args.config_dir,
        vector_pid_file=args.vector_pid_file,
        interval=args.interval,
    )

    if args.once:
        agent.poll_once()
        return 0
    agent.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
