"""ssperf: measure throughput and added latency against the D-21 targets.

Runs a baseline (sender straight to receiver) and a proxy run (sender to Vector to receiver),
then reports the difference. The proxy is only responsible for the difference.

    ssperf --rate 20000 --seconds 10        # sustained target
    ssperf --rate 0 --count 200000          # burst: send as fast as possible
    ssperf --skip-proxy                     # how fast can this machine even send?

The harness starts its own Vector using the config from the current rule chain, so what it
measures is the configuration that would actually run.
"""

from __future__ import annotations

import argparse
import math
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from sixthsense.compiler.vector_config import VectorSettings, render_toml
from sixthsense.models.rule import Action, Condition, Operator, Rule, RuleChain
from sixthsense.perf.counters import max_socket_buffer, read_udp_counters
from sixthsense.perf.harness import RunResult, run

# D-21.
TARGET_SUSTAINED_EPS = 20_000
TARGET_BURST_EPS = 100_000
TARGET_ADDED_P99_US = 1_000.0


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def demo_chain() -> RuleChain:
    """A representative chain: a few rules, a mix of operator costs.

    An empty chain would flatter the result. This is closer to what a real deployment runs.
    """
    return RuleChain(
        default_action=Action.FORWARD,
        rules=[
            Rule(
                id="perf-scanner",
                name="scanner",
                order=0,
                action=Action.DROP,
                conditions=[
                    Condition(field="filterhostname", operator=Operator.EQ, value="scanner01")
                ],
            ),
            Rule(
                id="perf-lab",
                name="lab subnet",
                order=1,
                action=Action.DROP,
                conditions=[
                    Condition(field="filteripaddress", operator=Operator.CIDR, value="10.42.0.0/16")
                ],
            ),
            Rule(
                id="perf-sev",
                name="low severity noise",
                order=2,
                action=Action.DROP,
                conditions=[
                    Condition(field="severity", operator=Operator.LT, value=1),
                    Condition(field="filtertype", operator=Operator.IN, value=["dlp", "av"]),
                ],
            ),
        ],
    )


def start_vector(
    ingest_port: int,
    forward_port: int,
    audit_port: int,
    rcvbuf: int,
    threads: int | None = None,
    chain: RuleChain | None = None,
) -> tuple[subprocess.Popen[bytes], tempfile.TemporaryDirectory[str]]:
    settings = VectorSettings(
        listen_address=f"127.0.0.1:{ingest_port}",
        elk_address=f"127.0.0.1:{forward_port}",
        drop_audit_address=f"127.0.0.1:{audit_port}",
        # Point the tail sink at a closed port. The control plane is not in the data path,
        # and the measurement should not depend on it being up.
        control_plane_url="http://127.0.0.1:1",
        receive_buffer_bytes=rcvbuf,
    )
    text = render_toml(chain or demo_chain(), settings, chain_version=0)
    text = text.replace('address = "0.0.0.0:9598"', f'address = "127.0.0.1:{free_port()}"')

    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / "vector.toml"
    path.write_text(text, encoding="utf-8")

    argv = ["vector", "--quiet", "--config", str(path)]
    if threads is not None:
        # Vector defaults to one worker thread per core. Constraining it is how you model a
        # CPU-limited deployment: it is the same knob as a Kubernetes CPU limit.
        argv += ["--threads", str(threads)]

    proc = subprocess.Popen(  # noqa: S603 - fixed argv, shell=False
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, tmp


def wait_for_vector(ingest_port: int, forward_port: int, timeout: float = 30.0) -> bool:
    """Probe until an event makes it through, so the run never races startup."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", forward_port))
    listener.settimeout(0.5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe = b"<134>Jul 31 12:00:00 readyhost CEF:0|v|p|1|1|Ready|5|eventid=1"

    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            sender.sendto(probe, ("127.0.0.1", ingest_port))
            try:
                listener.recv(65535)
                return True
            except TimeoutError:
                continue
        return False
    finally:
        listener.close()
        sender.close()


def fmt_us(value: float) -> str:
    return "n/a" if math.isnan(value) else f"{value:,.0f} us"


def report(result: RunResult) -> None:
    print(f"\n  {result.label}")
    print(f"    sent          {result.sent:>10,}  at {result.send_rate:>10,.0f} EPS")
    print(f"    forwarded     {result.received:>10,}  at {result.receive_rate:>10,.0f} EPS")
    if result.dropped_by_rule:
        print(
            f"    dropped       {result.dropped_by_rule:>10,}  by rule "
            "(counted from the audit sink)"
        )
    print(f"    processed     {result.accounted:>10,}  at {result.throughput:>10,.0f} EPS")
    print(f"    lost          {result.lost:>10,}  ({result.loss_pct:.3f}%)")
    print(
        f"    latency       p50 {fmt_us(result.p50)}   p99 {fmt_us(result.p99)}"
        f"   mean {fmt_us(result.mean_us)}   (n={len(result.latencies_us):,})"
    )
    if result.actual_rcvbuf:
        granted = result.actual_rcvbuf
        note = ""
        if granted < result.requested_rcvbuf // 2:
            note = "  <-- kernel capped this; raise net.core.rmem_max"
        print(f"    SO_RCVBUF     requested {result.requested_rcvbuf:,}, got {granted:,}{note}")

    kernel = result.kernel
    if kernel.available:
        print(
            f"    kernel drops  {kernel.receive_buffer_errors:>10,}  "
            f"(receive buffer overflow, system-wide, via {kernel.source})"
        )
    else:
        # Saying so is important. A silent absence would read as "zero", which is the exact
        # failure D-24 exists to prevent.
        print("    kernel drops  unavailable on this platform (see D-24)")


def verdict(baseline: RunResult | None, proxy: RunResult | None, rate: int) -> int:
    print("\n" + "=" * 74)
    print("  Verdict against D-21")
    print("=" * 74)

    if proxy is None:
        print("  Proxy run skipped, so there is nothing to judge.")
        return 0

    ok = True

    achieved = proxy.throughput
    target = rate if rate > 0 else TARGET_BURST_EPS
    label = "sustained" if rate > 0 else "burst"
    meets = achieved >= target * 0.95
    ok &= meets
    print(
        f"  {'PASS' if meets else 'FAIL'}  {label} throughput: "
        f"{achieved:,.0f} EPS against a {target:,} EPS target"
    )

    lossless = proxy.loss_pct < 0.1
    ok &= lossless
    print(
        f"  {'PASS' if lossless else 'FAIL'}  loss through the proxy: "
        f"{proxy.loss_pct:.3f}% ({proxy.lost:,} events)"
    )

    if baseline is not None and proxy.latencies_us and baseline.latencies_us:
        added = proxy.p99 - baseline.p99
        within = added < TARGET_ADDED_P99_US
        ok &= within
        print(
            f"  {'PASS' if within else 'FAIL'}  added p99 latency: {added:,.0f} us "
            f"(proxy {proxy.p99:,.0f} minus baseline {baseline.p99:,.0f}), "
            f"budget {TARGET_ADDED_P99_US:,.0f} us"
        )
    else:
        print("  ----  added latency: no baseline, so nothing to subtract")

    if proxy.kernel.available and (proxy.kernel.receive_buffer_errors or 0) > 0:
        print(
            f"  WARN  the kernel discarded {proxy.kernel.receive_buffer_errors:,} datagrams "
            "during this run. Application counters alone would not have shown this."
        )

    print("=" * 74)
    return 0 if ok else 1


def run_scale_sweep(args: argparse.Namespace, total: int) -> int:
    """Sweep Vector thread counts and report how throughput scales.

    This is the number that sizes a deployment. A single figure from one machine tells you
    nothing about what to provision; a curve tells you where the knee is and whether adding
    cores still buys anything.
    """
    thread_counts = [int(t) for t in args.scale.split(",") if t.strip()]
    rows: list[tuple[int, float, float, float, int]] = []

    print("\n" + "=" * 74)
    print("  Scaling sweep")
    print("=" * 74)

    for threads in thread_counts:
        ingest, forward, audit = free_port(), free_port(), free_port()
        proc, tmp = start_vector(ingest, forward, audit, args.rcvbuf, threads)
        try:
            if not wait_for_vector(ingest, forward):
                print(f"  {threads} threads: vector did not become ready")
                continue
            result = run(
                label=f"{threads} thread(s)",
                target_host="127.0.0.1",
                target_port=ingest,
                listen_port=forward,
                count=total,
                rate=args.rate,
                senders=args.senders,
                sample_every=args.sample_every,
                rcvbuf=args.rcvbuf,
                audit_port=audit,
            )
            rows.append(
                (
                    threads,
                    result.throughput,
                    result.loss_pct,
                    result.p99,
                    result.kernel.receive_buffer_errors or 0,
                )
            )
            print(
                f"  {threads:>2} threads  {result.throughput:>9,.0f} EPS  "
                f"loss {result.loss_pct:>6.2f}%  p99 {result.p99:>8,.0f} us  "
                f"kernel drops {result.kernel.receive_buffer_errors or 0:>8,}"
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            tmp.cleanup()

    if len(rows) >= 2:
        print("\n  Scaling relative to the smallest configuration measured:")
        base_threads, base_eps = rows[0][0], rows[0][1]
        for threads, eps, _, _, _ in rows:
            factor = eps / base_eps if base_eps else 0.0
            cores = threads / base_threads if base_threads else 1.0
            efficiency = (factor / cores * 100.0) if cores else 0.0
            print(
                f"  {threads:>2} threads  {factor:>5.2f}x throughput  "
                f"for {cores:>4.1f}x the cores  ({efficiency:>5.1f}% scaling efficiency)"
            )
        print("\n  Read the efficiency column, not the throughput column. Below roughly 70%,")
        print("  more cores on one node are worth less than another node.")

    print("=" * 74)
    return 0


def synthetic_chain(count: int) -> RuleChain:
    """Build ``count`` rules that deliberately match nothing.

    Non-matching is the point. With first-match-wins, a rule that matches early stops
    evaluation, so a chain of matching rules would measure how fast we can short-circuit.
    A chain that matches nothing forces every event through every condition, which is the
    worst case and the only number worth sizing against.

    Operators are cycled so the mix reflects a real chain rather than the cheapest one.
    """
    rules: list[Rule] = []
    for i in range(count):
        kind = i % 6
        if kind == 0:
            cond = Condition(field="filterhostname", operator=Operator.EQ, value=f"absent-host-{i}")
        elif kind == 1:
            cond = Condition(field="name", operator=Operator.CONTAINS, value=f"zzq-{i}")
        elif kind == 2:
            # TEST-NET-3. cefgen only emits 10.x addresses, so this never matches.
            cond = Condition(
                field="filteripaddress", operator=Operator.CIDR, value="203.0.113.0/24"
            )
        elif kind == 3:
            cond = Condition(field="severity", operator=Operator.GT, value=999)
        elif kind == 4:
            cond = Condition(field="name", operator=Operator.GLOB, value=f"zzq*{i}*")
        else:
            cond = Condition(
                field="filtertype", operator=Operator.IN, value=[f"absent-{i}", f"gone-{i}"]
            )
        rules.append(
            Rule(
                id=f"perf-{i:04d}",
                name=f"synthetic {i}",
                order=i,
                action=Action.DROP,
                conditions=[cond],
            )
        )
    return RuleChain(default_action=Action.FORWARD, rules=rules)


def run_rules_sweep(args: argparse.Namespace, total: int) -> int:
    """Sweep rule-chain length and report the cost of rule evaluation.

    D-22 assumes roughly 100 rules evaluated as a linear if/else chain, and says to benchmark
    so you know when linear stops being adequate. This is that benchmark.
    """
    counts = [int(c) for c in args.rules_sweep.split(",") if c.strip()]
    rows: list[tuple[int, float, float, int]] = []

    print("\n" + "=" * 78)
    print("  Rule-count sweep: no rule matches, so every event traverses the whole chain")
    print("=" * 78)

    for rule_count in counts:
        ingest, forward, audit = free_port(), free_port(), free_port()
        proc, tmp = start_vector(
            ingest, forward, audit, args.rcvbuf, args.vector_threads, synthetic_chain(rule_count)
        )
        try:
            if not wait_for_vector(ingest, forward):
                print(f"  {rule_count} rules: vector did not become ready")
                continue
            result = run(
                label=f"{rule_count} rules",
                target_host="127.0.0.1",
                target_port=ingest,
                listen_port=forward,
                count=total,
                rate=args.rate,
                senders=args.senders,
                sample_every=args.sample_every,
                rcvbuf=args.rcvbuf,
                audit_port=audit,
            )
            rows.append((rule_count, result.throughput, result.loss_pct, result.dropped_by_rule))
            print(
                f"  {rule_count:>4} rules  {result.throughput:>9,.0f} EPS  "
                f"loss {result.loss_pct:>6.2f}%  dropped-by-rule {result.dropped_by_rule:>6,}  "
                f"p99 {result.p99:>9,.0f} us"
            )
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            tmp.cleanup()

    if any(r[3] for r in rows):
        print("\n  WARNING: a synthetic rule matched. The sweep is no longer worst case.")

    if len(rows) >= 2:
        print("\n  Throughput relative to the shortest chain measured:")
        base_count, base_eps = rows[0][0], rows[0][1]
        for rule_count, eps, _, _ in rows:
            factor = eps / base_eps if base_eps else 0.0
            print(
                f"  {rule_count:>4} rules  {factor:>5.2f}x  "
                f"({(factor - 1) * 100:+.1f}% against {base_count} rules)"
            )
    print("=" * 78)
    return 0


def run_workers_sweep(args: argparse.Namespace, total: int) -> int:
    """Sweep the number of Vector processes and report how throughput scales.

    Vector's socket source does not expose SO_REUSEPORT, so several processes cannot share
    one port and let the kernel distribute datagrams. Each worker therefore binds its own
    ingress port and senders spread across them, which is precisely the production topology:
    several proxy nodes behind a load balancer.

    Emitters are deliberately not the constraint. Each worker gets its own sender process, and
    a single sender process was measured at roughly 160,000 EPS, so the load generator has
    ample headroom over anything the proxy achieves.
    """
    worker_counts = [int(w) for w in args.workers_sweep.split(",") if w.strip()]
    rows: list[tuple[int, float, float, float, int]] = []

    print("\n" + "=" * 78)
    print("  Worker sweep: separate Vector processes, senders spread across them")
    print("=" * 78)

    for workers in worker_counts:
        forward, audit = free_port(), free_port()
        procs: list[subprocess.Popen[bytes]] = []
        tmps: list[tempfile.TemporaryDirectory[str]] = []
        ingress: list[tuple[str, int]] = []

        try:
            for _ in range(workers):
                ingest = free_port()
                proc, tmp = start_vector(ingest, forward, audit, args.rcvbuf, args.vector_threads)
                procs.append(proc)
                tmps.append(tmp)
                ingress.append(("127.0.0.1", ingest))

            ready = all(wait_for_vector(port, forward) for _, port in ingress)
            if not ready:
                print(f"  {workers} workers: at least one did not become ready")
                continue

            senders = max(args.senders, workers)
            result = run(
                label=f"{workers} worker(s)",
                target_host="127.0.0.1",
                target_port=ingress[0][1],
                listen_port=forward,
                targets=ingress,
                count=total,
                rate=args.rate,
                senders=senders,
                sample_every=args.sample_every,
                rcvbuf=args.rcvbuf,
                audit_port=audit,
            )
            rows.append(
                (
                    workers,
                    result.throughput,
                    result.loss_pct,
                    result.p99,
                    result.kernel.receive_buffer_errors or 0,
                )
            )
            print(
                f"  {workers:>2} workers ({senders} senders)  {result.throughput:>9,.0f} EPS  "
                f"loss {result.loss_pct:>6.2f}%  p99 {result.p99:>9,.0f} us  "
                f"kernel drops {result.kernel.receive_buffer_errors or 0:>8,}"
            )
        finally:
            for proc in procs:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            for tmp in tmps:
                tmp.cleanup()

    if len(rows) >= 2:
        print("\n  Scaling relative to the smallest configuration measured:")
        base_workers, base_eps = rows[0][0], rows[0][1]
        for workers, eps, _, _, _ in rows:
            factor = eps / base_eps if base_eps else 0.0
            scale = workers / base_workers if base_workers else 1.0
            efficiency = (factor / scale * 100.0) if scale else 0.0
            print(
                f"  {workers:>2} workers  {factor:>5.2f}x throughput  "
                f"for {scale:>4.1f}x the processes  ({efficiency:>5.1f}% scaling efficiency)"
            )
    print("=" * 78)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="ssperf", description="throughput and latency harness")
    parser.add_argument(
        "--rate",
        type=int,
        default=TARGET_SUSTAINED_EPS,
        help="events per second per sender, 0 for as fast as possible",
    )
    parser.add_argument(
        "--seconds", type=float, default=10.0, help="how long to run, when --rate is set"
    )
    parser.add_argument("--count", type=int, default=0, help="total events, overrides --seconds")
    parser.add_argument(
        "--senders",
        type=int,
        default=1,
        help="sender processes; one Python process cannot reach the burst target",
    )
    parser.add_argument(
        "--sample-every", type=int, default=20, help="latency-sample one event in N"
    )
    parser.add_argument("--rcvbuf", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--adversarial-share", type=float, default=0.0)
    parser.add_argument(
        "--vector-threads",
        type=int,
        default=None,
        help="limit Vector worker threads; models a CPU-limited deployment",
    )
    parser.add_argument(
        "--scale",
        type=str,
        default=None,
        help="comma-separated thread counts to sweep, for example 1,2,4,8",
    )
    parser.add_argument(
        "--rules-sweep",
        type=str,
        default=None,
        help="comma-separated rule counts to sweep, for example 1,10,50,100",
    )
    parser.add_argument(
        "--workers-sweep",
        type=str,
        default=None,
        help="comma-separated Vector process counts to sweep, for example 1,2,4",
    )
    parser.add_argument("--skip-baseline", action="store_true")
    parser.add_argument("--skip-proxy", action="store_true")
    args = parser.parse_args()

    count = args.count or (int(args.rate * args.seconds) if args.rate > 0 else TARGET_BURST_EPS)
    per_sender = max(1, count // max(1, args.senders))
    total = per_sender * args.senders

    print("=" * 74)
    print("  sixthsense throughput harness")
    print("=" * 74)
    print(f"  events        {total:,} ({per_sender:,} per sender x {args.senders})")
    print(
        f"  pacing        {args.rate:,} EPS per sender" if args.rate else "  pacing        unpaced"
    )
    rmem = max_socket_buffer()
    print(f"  kernel rmem   {rmem:,}" if rmem else "  kernel rmem   unknown")
    counters = read_udp_counters()
    print(f"  udp counters  {counters.source}")

    if args.rules_sweep:
        if shutil.which("vector") is None:
            print("\n  vector not on PATH; run 'make vector' first.")
            return 1
        return run_rules_sweep(args, total)

    if args.workers_sweep:
        if shutil.which("vector") is None:
            print("\n  vector not on PATH; run 'make vector' first.")
            return 1
        return run_workers_sweep(args, total)

    if args.scale:
        if shutil.which("vector") is None:
            print("\n  vector not on PATH; run 'make vector' first.")
            return 1
        return run_scale_sweep(args, total)

    baseline: RunResult | None = None
    proxy: RunResult | None = None

    if not args.skip_baseline:
        port = free_port()
        baseline = run(
            label="baseline (no proxy in the path)",
            target_host="127.0.0.1",
            target_port=port,
            listen_port=port,
            count=total,
            rate=args.rate,
            senders=args.senders,
            sample_every=args.sample_every,
            rcvbuf=args.rcvbuf,
            adversarial_share=args.adversarial_share,
        )
        report(baseline)

    if not args.skip_proxy:
        if shutil.which("vector") is None:
            print("\n  vector not on PATH; run 'make vector' first. Skipping the proxy run.")
        else:
            ingest = free_port()
            forward = free_port()
            audit = free_port()
            proc, tmp = start_vector(ingest, forward, audit, args.rcvbuf, args.vector_threads)
            try:
                if not wait_for_vector(ingest, forward):
                    print("\n  vector did not become ready")
                    return 1
                proxy = run(
                    label="through the proxy (vector, 3 rules)",
                    target_host="127.0.0.1",
                    target_port=ingest,
                    listen_port=forward,
                    count=total,
                    rate=args.rate,
                    senders=args.senders,
                    sample_every=args.sample_every,
                    rcvbuf=args.rcvbuf,
                    adversarial_share=args.adversarial_share,
                    audit_port=audit,
                )
                report(proxy)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                tmp.cleanup()

    return verdict(baseline, proxy, args.rate)


if __name__ == "__main__":
    sys.exit(main())
