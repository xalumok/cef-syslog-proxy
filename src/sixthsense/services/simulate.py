"""Rule simulation, run through a real Vector process.

D-29 is explicit that simulation must not use a second parser. Two parsers that disagree is
a guaranteed bug class, and the whole point of a preview is that it tells the truth about
what will happen.

So this module does not evaluate rules in Python. It generates a simulation config, runs
``vector`` over the stored traffic sample, and reads back the decisions. If Vector is not
available, it says so rather than silently substituting an approximation.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import tomli_w

from sixthsense.compiler.compiler import compile_or_raise
from sixthsense.models.rule import RuleChain


@dataclass
class SimulationResult:
    total: int = 0
    forwarded: int = 0
    dropped: int = 0
    parse_errors: int = 0
    per_rule: dict[str, int] = field(default_factory=dict)
    available: bool = True
    detail: str = ""

    @property
    def drop_share(self) -> float:
        """Fraction of sampled events this chain would drop, from 0.0 to 1.0."""
        return self.dropped / self.total if self.total else 0.0

    @property
    def exceeds_confirmation_threshold(self) -> bool:
        """D-27: above 5%, the UI requires explicit confirmation before saving."""
        return self.drop_share > 0.05


def vector_available() -> bool:
    return shutil.which("vector") is not None


def _simulation_config(chain: RuleChain, chain_version: int) -> str:
    """A stdin-to-stdout topology wrapping the same compiled VRL the node will run."""
    config = {
        "sources": {
            "sim_in": {"type": "stdin", "decoding": {"codec": "bytes"}},
        },
        "transforms": {
            "decide": {
                "type": "remap",
                "inputs": ["sim_in"],
                "drop_on_error": False,
                "drop_on_abort": False,
                "source": compile_or_raise(chain, chain_version=chain_version),
            },
            "compact": {
                "type": "remap",
                "inputs": ["decide"],
                "drop_on_error": False,
                "source": (
                    '. = { "decision": .ss.decision, "rule_id": .ss.rule_id, '
                    '"reason": .ss.reason }\n'
                ),
            },
        },
        "sinks": {
            "sim_out": {
                "type": "console",
                "inputs": ["compact"],
                "encoding": {"codec": "json"},
                "target": "stdout",
            }
        },
    }
    return tomli_w.dumps(config)


def simulate(
    chain: RuleChain,
    events: list[str],
    *,
    chain_version: int = 0,
    timeout: float = 60.0,
) -> SimulationResult:
    """Run ``events`` through ``chain`` using Vector and summarize the decisions."""
    if not events:
        return SimulationResult(detail="no sample events available")

    if not vector_available():
        return SimulationResult(
            available=False,
            detail=(
                "vector binary not found. Simulation deliberately has no Python fallback: "
                "a second parser would disagree with the data plane (D-29)."
            ),
        )

    config_text = _simulation_config(chain, chain_version)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "sim.toml"
        path.write_text(config_text, encoding="utf-8")
        payload = "\n".join(e.replace("\n", " ") for e in events) + "\n"
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                ["vector", "--quiet", "--config", str(path)],  # noqa: S607
                input=payload,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return SimulationResult(available=False, detail="vector simulation timed out")

    result = SimulationResult()
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue

        result.total += 1
        decision = row.get("decision")
        if decision == "drop":
            result.dropped += 1
            rule_id = row.get("rule_id")
            if rule_id:
                result.per_rule[rule_id] = result.per_rule.get(rule_id, 0) + 1
        elif decision == "forward_parse_error":
            result.parse_errors += 1
            result.forwarded += 1
        else:
            result.forwarded += 1

    if result.total == 0:
        result.available = False
        result.detail = (proc.stderr or "vector produced no decisions").strip()[:500]

    return result
