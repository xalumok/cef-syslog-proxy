"""Kernel-level UDP drop counters.

D-24 exists because application counters lie. Under burst, the kernel discards datagrams in
the socket receive buffer before the application ever sees them. A harness that counts only
what it received would report zero loss while thousands of events vanished, which is the
most dangerous class of bug this system can have.

So the harness reads the operating system's own counters and reports them separately.
"""

from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UdpCounters:
    """A point-in-time snapshot of kernel UDP statistics."""

    receive_buffer_errors: int | None = None
    """Datagrams dropped because the socket receive buffer was full. The number that matters."""

    in_errors: int | None = None
    received: int | None = None
    source: str = "unavailable"

    def delta(self, earlier: UdpCounters) -> UdpCounters:
        def diff(a: int | None, b: int | None) -> int | None:
            return None if a is None or b is None else a - b

        return UdpCounters(
            receive_buffer_errors=diff(self.receive_buffer_errors, earlier.receive_buffer_errors),
            in_errors=diff(self.in_errors, earlier.in_errors),
            received=diff(self.received, earlier.received),
            source=self.source,
        )

    @property
    def available(self) -> bool:
        return self.receive_buffer_errors is not None


def _read_linux() -> UdpCounters:
    """Parse /proc/net/snmp, which carries system-wide UDP statistics."""
    path = Path("/proc/net/snmp")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return UdpCounters()

    header: list[str] | None = None
    for line in lines:
        if not line.startswith("Udp:"):
            continue
        fields = line.split()[1:]
        if header is None:
            header = fields
            continue
        values = dict(zip(header, (int(f) for f in fields), strict=False))
        return UdpCounters(
            receive_buffer_errors=values.get("RcvbufErrors"),
            in_errors=values.get("InErrors"),
            received=values.get("InDatagrams"),
            source="/proc/net/snmp",
        )
    return UdpCounters()


_MACOS_DROPPED = re.compile(r"(\d+)\s+dropped due to full socket buffers")
_MACOS_RECEIVED = re.compile(r"(\d+)\s+datagrams received")
_MACOS_BAD = re.compile(r"(\d+)\s+with bad checksum")


def _read_macos() -> UdpCounters:
    """Parse `netstat -s -p udp`, which is the closest macOS equivalent."""
    if shutil.which("netstat") is None:
        return UdpCounters()
    try:
        proc = subprocess.run(
            ["netstat", "-s", "-p", "udp"],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return UdpCounters()

    text = proc.stdout
    dropped = _MACOS_DROPPED.search(text)
    received = _MACOS_RECEIVED.search(text)
    bad = _MACOS_BAD.search(text)
    if dropped is None:
        return UdpCounters()

    return UdpCounters(
        receive_buffer_errors=int(dropped.group(1)),
        in_errors=int(bad.group(1)) if bad else None,
        received=int(received.group(1)) if received else None,
        source="netstat -s -p udp",
    )


def read_udp_counters() -> UdpCounters:
    """Read kernel UDP counters, or an unavailable snapshot on unsupported platforms.

    These are system-wide, not per-socket. On a busy machine other traffic contributes, so
    treat the delta as an upper bound on what this test lost. On a quiet host it is exact.
    """
    system = platform.system()
    if system == "Linux":
        return _read_linux()
    if system == "Darwin":
        return _read_macos()
    return UdpCounters()


def max_socket_buffer() -> int | None:
    """The largest SO_RCVBUF the kernel will grant, when discoverable.

    Useful context for a loss report: if the harness asked for 32 MB and the kernel capped it
    at 256 KB, that explains the drops and the fix is a sysctl rather than the code.
    """
    path = Path("/proc/sys/net/core/rmem_max")
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        pass

    if platform.system() == "Darwin" and shutil.which("sysctl"):
        try:
            proc = subprocess.run(
                ["sysctl", "-n", "kern.ipc.maxsockbuf"],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return int(proc.stdout.strip())
        except (subprocess.SubprocessError, OSError, ValueError):
            return None
    return None
