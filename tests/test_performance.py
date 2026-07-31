"""Throughput regression gate.

This runs at a modest rate that any machine handles, including a shared CI runner. It is a
regression detector, not a capacity measurement: it catches a change that makes the proxy
lose events or adds a millisecond of latency, and it says nothing about whether the D-21
targets are met.

Measure capacity with `make perf` on hardware you actually intend to deploy on. A shared CI
runner cannot produce a trustworthy 20,000 EPS number, and pretending otherwise would put a
figure in a report that nobody should rely on.
"""

from __future__ import annotations

import shutil

import pytest

from sixthsense.perf.harness import run
from sixthsense.perf.main import free_port, start_vector, wait_for_vector

pytestmark = pytest.mark.skipif(shutil.which("vector") is None, reason="vector binary not on PATH")

RATE = 2_000
SECONDS = 2
COUNT = RATE * SECONDS

#: Deliberately loose. CI runners are noisy, and a tight bound here would produce flaky
#: failures that teach people to ignore the gate. `make perf` is where the real number lives.
MAX_ADDED_P99_US = 5_000.0


@pytest.fixture(scope="module")
def proxy_ports():
    ingest, forward, audit = free_port(), free_port(), free_port()
    proc, tmp = start_vector(ingest, forward, audit, 8 * 1024 * 1024)
    try:
        if not wait_for_vector(ingest, forward):
            pytest.fail("vector did not become ready")
        yield ingest, forward, audit
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        tmp.cleanup()


@pytest.fixture(scope="module")
def baseline():
    port = free_port()
    return run(
        label="baseline",
        target_host="127.0.0.1",
        target_port=port,
        listen_port=port,
        count=COUNT,
        rate=RATE,
    )


@pytest.fixture(scope="module")
def through_proxy(proxy_ports):
    ingest, forward, audit = proxy_ports
    return run(
        label="proxy",
        target_host="127.0.0.1",
        target_port=ingest,
        listen_port=forward,
        count=COUNT,
        rate=RATE,
        audit_port=audit,
    )


def test_baseline_is_lossless(baseline) -> None:
    """If the harness itself loses events, nothing else it reports means anything."""
    assert baseline.lost == 0, f"harness lost {baseline.lost} of {baseline.sent}"


def test_proxy_accounts_for_every_event(through_proxy) -> None:
    """Forwarded plus dropped must equal sent.

    Counting drops separately matters: without the audit sink, a rule doing its job is
    indistinguishable from the proxy losing events, and the wrong conclusion is expensive.
    """
    result = through_proxy
    assert result.accounted == result.sent, (
        f"sent {result.sent}, accounted {result.accounted} "
        f"(forwarded {result.received}, dropped {result.dropped_by_rule}), "
        f"lost {result.lost}"
    )


def test_proxy_drops_only_what_the_rules_say(through_proxy) -> None:
    """The demo chain matches a real share of generated traffic, so drops are expected."""
    result = through_proxy
    assert result.dropped_by_rule > 0, "no drops at all suggests the rules stopped matching"
    assert result.received > 0, "everything was dropped, which suggests a compiler bug"


def test_kernel_reports_no_buffer_overflow(through_proxy) -> None:
    """D-24: application counters alone would report zero loss while the kernel discarded."""
    kernel = through_proxy.kernel
    if not kernel.available:
        pytest.skip("kernel UDP counters unavailable on this platform")
    assert (kernel.receive_buffer_errors or 0) == 0, (
        f"kernel discarded {kernel.receive_buffer_errors} datagrams at {RATE} EPS"
    )


def test_added_latency_is_bounded(baseline, through_proxy) -> None:
    """Regression bound on latency the proxy adds, not total latency."""
    if not baseline.latencies_us or not through_proxy.latencies_us:
        pytest.skip("no latency samples")
    added = through_proxy.p99 - baseline.p99
    assert added < MAX_ADDED_P99_US, (
        f"added p99 {added:,.0f} us exceeds {MAX_ADDED_P99_US:,.0f} us "
        f"(proxy {through_proxy.p99:,.0f}, baseline {baseline.p99:,.0f})"
    )
