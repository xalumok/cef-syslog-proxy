"""Validate generated Vector configuration and VRL.

D-44 requires this as a gate, in CI and again before any bundle is activated. A config that
does not validate never reaches a node.

Two checks are needed, and finding that out cost a debugging session worth recording:

``vector validate`` checks the config structure only. **It does not compile VRL.** A remap
transform whose program references an undefined variable passes ``vector validate`` cleanly
and then fails at startup in the topology builder. On a node that means Vector refuses to
start, the last known good config keeps running, and the operator sees a rollout that
silently did nothing.

``vector vrl -p <program> -i <event>`` does compile the program, and exits 70 on a compile
error. So the gate runs both: structure through ``validate``, semantics through ``vrl``.

**And a compile check is still not enough.** ``vector vrl`` exits **0** on a runtime error: it
prints the message on the failing event's output line and carries on. A program that aborts on
every non-CEF event therefore passes a naive exit-code check cleanly. That is exactly how the
``find`` null bug shipped, and it is why this module now runs the program over a corpus that
covers every input shape and inspects the output line by line. One well-formed JSON object per
input event means no event aborted the program.

Keep the corpus honest. It is the only thing standing between a runtime abort and a node.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

#: Every input shape the data plane accepts. A program must run to completion on all of them.
#:
#: Compilation alone is checked by any one of these. The rest are here for the runtime pass:
#: each parser path through the prelude has to be exercised, because the failure mode this
#: catches is a branch that only executes for one kind of input.
_PROBE_CORPUS: Final[tuple[str, ...]] = (
    # CEF carried in a syslog frame, the common production shape.
    "<134>Jul 30 12:00:00 host CEF:0|v|p|1|1|Name|5|eventid=1",
    # A bare CEF datagram with no syslog header (D-14).
    "CEF:0|v|p|1|1|Name|5|eventid=1 filterhostname=web-01",
    # RFC 3164 with no CEF payload. This is the shape that found the `find` bug.
    "<134>Jul 30 12:00:00 web-01 sshd[1234]: Failed password for bob",
    # RFC 5424 with no CEF payload.
    "<165>1 2026-07-30T12:00:00Z web-01 myapp 8710 ID47 - a message",
    # Parses as neither. Must still reach the D-18 fail-open path without aborting.
    "this is not syslog and definitely not CEF",
)


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    output: str
    skipped: bool = False
    """True when the vector binary is absent, so the check could not run."""

    stage: str = ""
    """Which check failed: "config", "vrl", or "runtime"."""


def vector_available() -> bool:
    return shutil.which("vector") is not None


def _run(argv: list[str], *, stdin: str | None = None, timeout: float) -> tuple[int, str, str]:
    """Run a command, returning the exit code, stdout, and stderr separately.

    Separately matters: the runtime check reads stdout as data, one JSON event per line, and
    Vector writes its startup log to stderr. Combining them would make every run look like it
    emitted a malformed event.
    """
    proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
        argv,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def _check_runtime_output(stdout: str, expected: int) -> ValidationResult:
    """Verify the program ran to completion on every probe event.

    ``vector vrl`` writes one line per input event: a JSON object when the program finished,
    or a bare error message such as ``can't compare null >= integer`` when it aborted. So a
    line that is not JSON is a runtime abort, and the exit code will not tell you.
    """
    lines = [line for line in stdout.splitlines() if line.strip()]
    if len(lines) != expected:
        return ValidationResult(
            ok=False,
            output=f"expected {expected} output events, got {len(lines)}:\n{stdout}",
            stage="runtime",
        )

    for probe, line in zip(_PROBE_CORPUS, lines, strict=True):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return ValidationResult(
                ok=False,
                output=f"program aborted at runtime on {probe!r}: {line}",
                stage="runtime",
            )
        # The program's last statement assigns `.ss`, so its value is what gets printed. No
        # decision key means the program finished without deciding, which is also a failure.
        if not isinstance(event, dict) or "decision" not in event:
            return ValidationResult(
                ok=False,
                output=f"program produced no decision for {probe!r}: {line}",
                stage="runtime",
            )

    return ValidationResult(ok=True, output=f"{expected} probe events ran to completion")


def validate_vrl(program: str, *, timeout: float = 30.0) -> ValidationResult:
    """Compile a VRL program and run it over the probe corpus.

    Catches undefined variables at compile time and aborting branches at run time. The second
    half needs the corpus: a branch that only executes for one input shape is invisible to a
    single probe event.
    """
    if not vector_available():
        return ValidationResult(ok=True, output="vector binary not found", skipped=True)

    with tempfile.TemporaryDirectory() as tmp:
        program_path = Path(tmp) / "program.vrl"
        input_path = Path(tmp) / "events.json"
        program_path.write_text(program, encoding="utf-8")
        input_path.write_text(
            "".join(json.dumps({"message": m}) + "\n" for m in _PROBE_CORPUS),
            encoding="utf-8",
        )
        try:
            code, stdout, stderr = _run(
                ["vector", "vrl", "-p", str(program_path), "-i", str(input_path)],
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(ok=False, output="vector vrl timed out", stage="vrl")

    # A non-zero exit is a compile error. Vector exits 70 for those.
    if code != 0:
        return ValidationResult(ok=False, output=(stdout + "\n" + stderr).strip(), stage="vrl")

    return _check_runtime_output(stdout, len(_PROBE_CORPUS))


def validate_config(
    toml_text: str, *, vrl_program: str | None = None, timeout: float = 30.0
) -> ValidationResult:
    """Validate a full configuration.

    Pass ``vrl_program`` to also compile the remap program. Callers that have it should
    always pass it: without it, this only proves the TOML is well formed.
    """
    if not vector_available():
        return ValidationResult(ok=True, output="vector binary not found", skipped=True)

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "vector.toml"
        path.write_text(toml_text, encoding="utf-8")
        try:
            code, stdout, stderr = _run(
                ["vector", "validate", "--no-environment", str(path)], timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return ValidationResult(ok=False, output="vector validate timed out", stage="config")

    output = (stdout + "\n" + stderr).strip()
    if code != 0:
        return ValidationResult(ok=False, output=output, stage="config")

    if vrl_program is not None:
        return validate_vrl(vrl_program, timeout=timeout)

    return ValidationResult(ok=True, output=output)
