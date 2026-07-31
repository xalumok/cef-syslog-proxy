"""Throughput and latency harness for the D-21 targets.

D-21 budgets 20,000 EPS sustained, 100,000 in a burst, and under one millisecond of *added*
p99 latency. "Added" is the important word, so this harness measures twice:

* **baseline**: sender to receiver directly, with no proxy in the path
* **proxy**: sender to Vector to receiver

Added latency is the difference. That is the only honest way to report it, because the
absolute number is dominated by Python's own send and receive cost, which the proxy is not
responsible for.

Loss is reported from two independent sources: what the receiver counted, and what the kernel
says it discarded (D-24). A harness that trusted only its own counter would report zero loss
while the socket buffer overflowed.
"""

from __future__ import annotations

import contextlib
import multiprocessing as mp
import socket
import statistics
import time
from dataclasses import dataclass, field
from multiprocessing.queues import Queue as MPQueue
from multiprocessing.synchronize import Event as MPEvent

from sixthsense.cefgen.main import make_event
from sixthsense.perf.counters import UdpCounters, read_udp_counters

#: Marker carrying the send timestamp. It rides in a CEF extension, so it survives the proxy
#: unchanged: forwarded bytes are identical to received bytes (D-15).
TS_KEY = b" perfts="

DEFAULT_RCVBUF = 32 * 1024 * 1024


@dataclass
class RunResult:
    label: str
    sent: int = 0
    received: int = 0
    dropped_by_rule: int = 0
    """Counted from the drop-audit sink.

    Without this the harness reports correct filtering as packet loss, which is exactly the
    wrong conclusion: it would make a working rule look like a capacity problem.
    """

    duration_s: float = 0.0
    latencies_us: list[float] = field(default_factory=list)
    kernel: UdpCounters = field(default_factory=UdpCounters)
    requested_rcvbuf: int = 0
    actual_rcvbuf: int = 0

    @property
    def send_rate(self) -> float:
        return self.sent / self.duration_s if self.duration_s else 0.0

    @property
    def receive_rate(self) -> float:
        return self.received / self.duration_s if self.duration_s else 0.0

    @property
    def accounted(self) -> int:
        """Events the proxy demonstrably handled: forwarded plus deliberately dropped."""
        return self.received + self.dropped_by_rule

    @property
    def throughput(self) -> float:
        """Events processed per second, whatever the decision was."""
        return self.accounted / self.duration_s if self.duration_s else 0.0

    @property
    def lost(self) -> int:
        return max(0, self.sent - self.accounted)

    @property
    def loss_pct(self) -> float:
        return (self.lost / self.sent * 100.0) if self.sent else 0.0

    def percentile(self, p: float) -> float:
        if not self.latencies_us:
            return float("nan")
        ordered = sorted(self.latencies_us)
        index = min(len(ordered) - 1, round(p / 100.0 * (len(ordered) - 1)))
        return ordered[index]

    @property
    def p50(self) -> float:
        return self.percentile(50)

    @property
    def p99(self) -> float:
        return self.percentile(99)

    @property
    def mean_us(self) -> float:
        return statistics.fmean(self.latencies_us) if self.latencies_us else float("nan")


def build_payloads(count: int, *, adversarial_share: float = 0.0) -> list[bytes]:
    """Pre-serialize the events.

    Generation happens up front so the send loop measures the network path rather than string
    formatting. At 100,000 EPS the difference is the whole result.
    """
    import random

    rng = random.Random(20260731)  # noqa: S311 - reproducible test data
    payloads: list[bytes] = []
    for _ in range(count):
        event = make_event(adversarial=rng.random() < adversarial_share)
        payloads.append(event.encode("utf-8") + TS_KEY)
    return payloads


def _receiver(
    port: int,
    ready: MPEvent,
    stop: MPEvent,
    out: MPQueue[dict[str, object]],
    sample_every: int,
    rcvbuf: int,
) -> None:
    """Count datagrams and sample latency. Runs in its own process to avoid the GIL."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    with contextlib.suppress(OSError):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.5)

    buffer = bytearray(65535)
    count = 0
    latencies: list[float] = []
    first_ns = 0
    last_ns = 0

    ready.set()
    while not stop.is_set():
        try:
            nbytes = sock.recv_into(buffer)
        except TimeoutError:
            continue
        except OSError:
            break

        now = time.time_ns()
        count += 1
        if first_ns == 0:
            first_ns = now
        last_ns = now

        if count % sample_every == 0:
            view = bytes(buffer[:nbytes])
            marker = view.rfind(TS_KEY)
            if marker >= 0:
                raw = view[marker + len(TS_KEY) :].split(b" ", 1)[0]
                with contextlib.suppress(ValueError):
                    latencies.append((now - int(raw)) / 1000.0)

    sock.close()
    out.put(
        {
            "count": count,
            "latencies": latencies,
            "first_ns": first_ns,
            "last_ns": last_ns,
            "actual_rcvbuf": actual,
        }
    )


def _sender(payloads: list[bytes], target: tuple[str, int], rate: int) -> tuple[int, float]:
    """Send payloads at approximately ``rate`` per second.

    A ``rate`` of 0 means send as fast as the machine allows.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)

    sendto = sock.sendto
    now_ns = time.time_ns
    perf = time.perf_counter

    sent = 0
    start = perf()

    if rate <= 0:
        for payload in payloads:
            sendto(payload + str(now_ns()).encode("ascii"), target)
            sent += 1
    else:
        interval = 1.0 / rate
        deadline = start
        for payload in payloads:
            deadline += interval
            slack = deadline - perf()
            if slack > 0.0005:
                time.sleep(slack)
            elif slack > 0:
                while perf() < deadline:
                    pass
            sendto(payload + str(now_ns()).encode("ascii"), target)
            sent += 1

    elapsed = perf() - start
    sock.close()
    return sent, elapsed


def _sender_worker(
    args: tuple[list[bytes], tuple[str, int], int, MPQueue[tuple[int, float]]],
) -> None:
    payloads, target, rate, out = args
    out.put(_sender(payloads, target, rate))


def run(
    *,
    label: str,
    target_host: str,
    target_port: int,
    listen_port: int,
    targets: list[tuple[str, int]] | None = None,
    count: int,
    rate: int,
    senders: int = 1,
    sample_every: int = 20,
    rcvbuf: int = DEFAULT_RCVBUF,
    settle_s: float = 2.0,
    adversarial_share: float = 0.0,
    audit_port: int | None = None,
) -> RunResult:
    """Run one measurement.

    ``target_port`` is where events are sent: the proxy's ingress for a proxy run, or the
    receiver itself for a baseline run. ``listen_port`` is always where the receiver binds.

    Pass ``targets`` to spread senders across several ingress ports, which models a load
    balancer in front of several proxy processes. Sender *i* uses ``targets[i % len]``.

    Pass ``audit_port`` to also count drop-audit records. Without it, every event a rule
    correctly drops is indistinguishable from an event the proxy lost.
    """
    endpoints = targets or [(target_host, target_port)]
    per_sender = max(1, count // senders)
    payload_sets = [
        build_payloads(per_sender, adversarial_share=adversarial_share) for _ in range(senders)
    ]

    ctx = mp.get_context("spawn")
    ready = ctx.Event()
    stop = ctx.Event()
    results: MPQueue[dict[str, object]] = ctx.Queue()

    receiver = ctx.Process(
        target=_receiver,
        args=(listen_port, ready, stop, results, sample_every, rcvbuf),
        daemon=True,
    )
    receiver.start()
    if not ready.wait(timeout=10):
        stop.set()
        receiver.join(timeout=5)
        raise RuntimeError("receiver did not start")

    audit_proc = None
    audit_results: MPQueue[dict[str, object]] | None = None
    if audit_port is not None:
        audit_ready = ctx.Event()
        audit_results = ctx.Queue()
        audit_proc = ctx.Process(
            target=_receiver,
            # sample_every is huge: audit records carry no send timestamp, so latency
            # sampling on this socket would only cost cycles.
            args=(audit_port, audit_ready, stop, audit_results, 10**9, rcvbuf),
            daemon=True,
        )
        audit_proc.start()
        audit_ready.wait(timeout=10)

    before = read_udp_counters()

    if senders == 1:
        # In-process for the common case: one less spawn, and one less thing to get wrong.
        sent, elapsed = _sender(payload_sets[0], endpoints[0], rate)
    else:
        # Several processes, because one Python process cannot saturate the burst target.
        # Each is given the full per-sender rate, so the aggregate is rate * senders.
        send_queue: MPQueue[tuple[int, float]] = ctx.Queue()
        procs = [
            ctx.Process(
                target=_sender_worker,
                args=((payload_sets[i], endpoints[i % len(endpoints)], rate, send_queue),),
                daemon=True,
            )
            for i in range(senders)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=300)
        totals = [send_queue.get(timeout=10) for _ in range(senders)]
        sent = sum(t[0] for t in totals)
        elapsed = max(t[1] for t in totals)

    time.sleep(settle_s)
    after = read_udp_counters()

    stop.set()
    receiver.join(timeout=10)
    payload: dict[str, object] = results.get(timeout=10) if not results.empty() else {}
    if receiver.is_alive():
        receiver.terminate()

    dropped = 0
    if audit_proc is not None and audit_results is not None:
        audit_proc.join(timeout=10)
        if not audit_results.empty():
            dropped = int(str(audit_results.get(timeout=10).get("count", 0)))
        if audit_proc.is_alive():
            audit_proc.terminate()

    raw_latencies = payload.get("latencies", [])
    latencies = [float(x) for x in raw_latencies] if isinstance(raw_latencies, list) else []

    return RunResult(
        label=label,
        sent=sent,
        received=int(str(payload.get("count", 0))),
        dropped_by_rule=dropped,
        duration_s=elapsed,
        latencies_us=latencies,
        kernel=after.delta(before),
        requested_rcvbuf=rcvbuf,
        actual_rcvbuf=int(str(payload.get("actual_rcvbuf", 0))),
    )
