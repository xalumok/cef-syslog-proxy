"""End-to-end tests against a real Vector process.

These are the tests that prove the design works rather than merely compiles. They are
skipped when Vector is not installed, and CI installs it so they always run there.

What they establish:

* The generated VRL is valid and Vector accepts it.
* Rules actually drop and forward the events they claim to.
* D-15 holds on the wire: forwarded bytes are identical to received bytes.
* D-18 holds: unparseable input is forwarded, not dropped.
* D-28 holds: a config reload does not lose packets.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from sixthsense.compiler.compiler import compile_or_raise
from sixthsense.compiler.vector_config import VectorSettings, render_toml
from sixthsense.models.rule import Action, Condition, Operator, Rule, RuleChain

pytestmark = pytest.mark.skipif(shutil.which("vector") is None, reason="vector binary not on PATH")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TailReceiver:
    """Captures what the node posts to the control plane's decision intake.

    The other tests point the tail sink at a closed port, which proves the data path does not
    depend on the control plane. These tests need the opposite: to see exactly what arrives.
    """

    def __init__(self) -> None:
        self._records: list[dict] = []
        self._lock = threading.Lock()
        records, lock = self._records, self._lock

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # the name is fixed by BaseHTTPRequestHandler
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)
                with lock:
                    records.extend(json.loads(body))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *_: object) -> None:
                return  # keep pytest output readable

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_port}"

    def __enter__(self) -> TailReceiver:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def records(self) -> list[dict]:
        with self._lock:
            return list(self._records)

    def reset(self) -> None:
        with self._lock:
            self._records.clear()

    def wait_for(self, count: int, timeout: float = 8.0) -> list[dict]:
        """Wait for at least `count` records, then settle to catch any duplicate."""
        deadline = time.time() + timeout
        while time.time() < deadline and len(self.records()) < count:
            time.sleep(0.2)
        # The batch timeout is 2 s, so a duplicate on a second batch needs waiting out.
        time.sleep(3.0)
        return self.records()


class Harness:
    """Runs Vector with a generated config and captures both output sinks."""

    def __enter__(self) -> Harness:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()

    def __init__(self, chain: RuleChain, control_plane_url: str = "http://127.0.0.1:1") -> None:
        self.ingest_port = free_port()
        self.elk_port = free_port()
        self.audit_port = free_port()
        self.metrics_port = free_port()

        self.elk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.elk.bind(("127.0.0.1", self.elk_port))
        self.elk.settimeout(0.5)

        self.audit = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.audit.bind(("127.0.0.1", self.audit_port))
        self.audit.settimeout(0.5)

        settings = VectorSettings(
            listen_address=f"127.0.0.1:{self.ingest_port}",
            elk_address=f"127.0.0.1:{self.elk_port}",
            drop_audit_address=f"127.0.0.1:{self.audit_port}",
            # Defaults to a closed port, which proves the data path does not depend on the
            # control plane being reachable. Tests that inspect what the node posts pass a
            # real receiver instead.
            control_plane_url=control_plane_url,
        )
        self.tmp = tempfile.TemporaryDirectory()
        self.config_path = Path(self.tmp.name) / "vector.toml"
        text = render_toml(chain, settings, chain_version=1)
        text = text.replace(
            'address = "0.0.0.0:9598"',
            f'address = "127.0.0.1:{self.metrics_port}"',
        )
        self.config_path.write_text(text, encoding="utf-8")
        self.proc: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        self.proc = subprocess.Popen(
            ["vector", "--quiet", "--config", str(self.config_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait_ready()

    def _wait_ready(self, timeout: float = 25.0) -> None:
        """Send probes until one comes back, so tests never race Vector's startup."""
        deadline = time.time() + timeout
        probe = "<134>Jul 30 12:00:00 readyhost CEF:0|v|p|1|1|Ready|1|eventid=1"
        while time.time() < deadline:
            self.send(probe)
            try:
                self.elk.recv(65536)
                return
            except TimeoutError:
                continue
            except OSError:
                continue
        raise RuntimeError("vector did not become ready")

    def send(self, message: str) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(message.encode("utf-8"), ("127.0.0.1", self.ingest_port))

    def drain(self, sock: socket.socket, settle: float = 1.0) -> list[bytes]:
        out: list[bytes] = []
        deadline = time.time() + settle
        while time.time() < deadline:
            try:
                out.append(sock.recv(65536))
                deadline = time.time() + 0.3
            except (TimeoutError, OSError):
                continue
        return out

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.elk.close()
        self.audit.close()
        self.tmp.cleanup()


def cef(
    host: str = "web-01",
    severity: int = 9,
    name: str = "Port scan",
    ip: str = "10.1.2.3",
) -> str:
    return (
        f"<134>Jul 30 12:00:00 {host} CEF:0|SixthSense|Gen|1.0|100|{name}|{severity}|"
        f"eventid=42 filterhostname={host} filteripaddress={ip} filtertype=ids"
    )


@pytest.fixture
def chain() -> RuleChain:
    return RuleChain(
        default_action=Action.FORWARD,
        rules=[
            Rule(
                id="r-scanner",
                name="scanner",
                order=0,
                action=Action.DROP,
                conditions=[
                    Condition(field="filterhostname", operator=Operator.EQ, value="scanner01")
                ],
            ),
            Rule(
                id="r-lab",
                name="lab subnet",
                order=1,
                action=Action.DROP,
                retain_payload=True,
                conditions=[
                    Condition(field="filteripaddress", operator=Operator.CIDR, value="10.42.0.0/16")
                ],
            ),
            # D-14: a rule on a plain syslog field, matching no CEF event. The CEF events
            # above carry syslog.appname "CEF", because parse_syslog reads the marker as the
            # tag, so this rule cannot affect them.
            Rule(
                id="r-noisy",
                name="noisy daemon",
                order=2,
                action=Action.DROP,
                conditions=[
                    Condition(field="syslog.appname", operator=Operator.EQ, value="noisyd")
                ],
            ),
        ],
    )


def syslog3164(appname: str = "sshd", host: str = "web-01", message: str = "hello") -> str:
    return f"<134>Jul 30 12:00:00 {host} {appname}[1234]: {message}"


def syslog5424(appname: str = "myapp", host: str = "web-01") -> str:
    return f"<165>1 2026-07-30T12:00:00Z {host} {appname} 8710 ID47 - structured message"


@pytest.fixture
def harness(chain: RuleChain):
    h = Harness(chain)
    h.start()
    yield h
    h.stop()


class TestFiltering:
    def test_matching_event_is_dropped(self, harness: Harness) -> None:
        harness.drain(harness.elk, settle=0.4)
        harness.send(cef(host="scanner01"))
        assert harness.drain(harness.elk, settle=1.2) == []

    def test_non_matching_event_is_forwarded(self, harness: Harness) -> None:
        harness.drain(harness.elk, settle=0.4)
        harness.send(cef(host="web-01"))
        received = harness.drain(harness.elk, settle=1.5)
        assert len(received) == 1

    def test_cidr_rule_drops_lab_subnet(self, harness: Harness) -> None:
        harness.drain(harness.elk, settle=0.4)
        harness.send(cef(host="web-01", ip="10.42.7.9"))
        assert harness.drain(harness.elk, settle=1.2) == []

    def test_case_insensitive_matching(self, harness: Harness) -> None:
        """D-07: host name capitalization varies by source and must not defeat a rule."""
        harness.drain(harness.elk, settle=0.4)
        harness.send(cef(host="SCANNER01"))
        assert harness.drain(harness.elk, settle=1.2) == []


class TestSyslogFiltering:
    """D-14: rules match plain syslog, not only CEF.

    Every one of these fails if the decide program aborts before the rule branches, which is
    what a null `find` result used to do on any event without a CEF marker.
    """

    def test_syslog_rule_drops_matching_event(self, harness: Harness) -> None:
        harness.drain(harness.elk, settle=0.4)
        harness.send(syslog3164(appname="noisyd"))
        assert harness.drain(harness.elk, settle=1.2) == []

    def test_syslog_rule_forwards_non_matching_event(self, harness: Harness) -> None:
        harness.drain(harness.elk, settle=0.4)
        harness.send(syslog3164(appname="sshd"))
        assert len(harness.drain(harness.elk, settle=1.5)) == 1

    def test_rfc5424_is_matchable_too(self, harness: Harness) -> None:
        harness.drain(harness.elk, settle=0.4)
        harness.send(syslog5424(appname="noisyd"))
        assert harness.drain(harness.elk, settle=1.2) == []

    def test_syslog_drop_produces_an_audit_record_naming_the_host(self, harness: Harness) -> None:
        """D-02: a syslog drop has to be as accountable as a CEF drop.

        The host comes from syslog.hostname, since filterhostname is a CEF extension key and
        a plain syslog event has none. Without that fallback this record is blank.
        """
        harness.drain(harness.audit, settle=0.4)
        harness.send(syslog3164(appname="noisyd", host="db-07"))
        records = harness.drain(harness.audit, settle=1.5)
        assert len(records) == 1
        flat = records[0].replace(b" ", b"")
        assert b'"rule_id":"r-noisy"' in flat
        assert b'"host":"db-07"' in flat

    def test_cef_rules_still_match_after_namespacing(self, harness: Harness) -> None:
        """Regression guard. CEF fields stayed at the top level so no rule had to migrate."""
        harness.drain(harness.elk, settle=0.4)
        harness.send(cef(host="scanner01"))
        assert harness.drain(harness.elk, settle=1.2) == []


class TestDecisionLabels:
    """Assert the decision each input shape produces.

    The wire cannot show this. The ELK sink emits `.message` verbatim by design (D-15), and a
    forwarded parse error never reaches the audit sink, so `.ss` is invisible downstream.
    Running the program directly is the only way to assert the label, and the label is what
    D-18 actually promises: forwarded *and counted*.
    """

    def _decide(self, chain: RuleChain, message: str) -> dict:
        import json

        program = compile_or_raise(chain)
        with tempfile.TemporaryDirectory() as tmp:
            prog = Path(tmp) / "p.vrl"
            events = Path(tmp) / "e.json"
            prog.write_text(program, encoding="utf-8")
            events.write_text(json.dumps({"message": message}) + "\n", encoding="utf-8")
            out = subprocess.run(
                ["vector", "vrl", "-p", str(prog), "-i", str(events)],
                capture_output=True,
                text=True,
                check=False,
            )
        line = out.stdout.strip()
        assert line, f"program produced no output: {out.stderr}"
        return json.loads(line)

    def test_garbage_is_labelled_a_parse_error(self, chain: RuleChain) -> None:
        ss = self._decide(chain, "this is not syslog and definitely not CEF")
        assert ss["decision"] == "forward_parse_error"
        assert ss["reason"] == "parse_error"
        assert ss["parse_ok"] is False

    def test_plain_syslog_is_parsed_not_a_parse_error(self, chain: RuleChain) -> None:
        """The bug this guards: a readable syslog line reported as unparseable.

        It forwarded either way, so nothing looked broken, while every syslog rule was
        silently skipped and the event never appeared in the decision counts.
        """
        ss = self._decide(chain, syslog3164(appname="sshd"))
        assert ss["parse_ok"] is True
        assert ss["syslog_ok"] is True
        assert ss["cef_ok"] is False
        assert ss["decision"] == "forward"
        assert ss["reason"] == "default"

    def test_syslog_rule_match_is_labelled_a_rule_decision(self, chain: RuleChain) -> None:
        ss = self._decide(chain, syslog3164(appname="noisyd"))
        assert ss["decision"] == "drop"
        assert ss["reason"] == "rule"
        assert ss["rule_id"] == "r-noisy"

    def test_cef_still_reports_both_parsers(self, chain: RuleChain) -> None:
        """CEF normally arrives inside a syslog frame, so both parsers succeed."""
        ss = self._decide(chain, cef(host="web-01"))
        assert ss["cef_ok"] is True
        assert ss["syslog_ok"] is True
        assert ss["severity"] == "9"  # CEF header, not the syslog severity word


class TestDecisionSampling:
    """Every drop reaches the control plane exactly once.

    The tail path feeds the live view and the persisted sample the impact preview reads, so a
    duplicate here does not just look wrong: it doubles the projected drop share an analyst
    uses to decide whether a rule is safe, and the D-27 confirmation fires on that number.
    """

    def test_a_dropped_event_is_reported_once(self, chain: RuleChain) -> None:
        """`exclude` on the sample transform means "bypass sampling", not "discard".

        Adding a second filter transform for drops therefore double-counted every one.
        """
        with TailReceiver() as tail, Harness(chain, control_plane_url=tail.url) as harness:
            harness.drain(harness.elk, settle=0.4)
            tail.reset()
            harness.send(syslog3164(appname="noisyd"))
            records = tail.wait_for(1, timeout=8.0)

        # Count only drops. A sampled forward from the readiness probe can still be in flight,
        # and it is not what this test is about.
        drops = [r for r in records if r["decision"] == "drop"]
        assert len(drops) == 1, f"expected one drop record, got {len(drops)}: {drops}"
        assert drops[0]["rule_id"] == "r-noisy"

    def test_forwarded_events_are_sampled_not_streamed(self, chain: RuleChain) -> None:
        """The other half of the same setting: non-drops must not all arrive.

        If they did, the control plane would be receiving event-rate traffic, which is the
        one thing this architecture will not do.
        """
        with TailReceiver() as tail, Harness(chain, control_plane_url=tail.url) as harness:
            harness.drain(harness.elk, settle=0.4)
            tail.reset()
            for _ in range(60):
                harness.send(syslog3164(appname="quiet"))
            time.sleep(4.0)
            forwarded = [r for r in tail.records() if r["decision"] != "drop"]

        assert len(forwarded) < 60, "forwarded events are reaching the control plane unsampled"


class TestByteFidelity:
    def test_forwarded_bytes_are_identical(self, harness: Harness) -> None:
        """D-15: the whole cutover safety argument rests on this."""
        harness.drain(harness.elk, settle=0.4)
        original = cef(host="web-01", name="Odd = chars | here")
        harness.send(original)
        received = harness.drain(harness.elk, settle=1.5)
        assert len(received) == 1
        assert received[0].decode("utf-8") == original


class TestFailOpen:
    def test_unparseable_input_is_forwarded(self, harness: Harness) -> None:
        """D-18: a parser failure must never silently discard a security event."""
        harness.drain(harness.elk, settle=0.4)
        garbage = "this is not syslog and definitely not CEF"
        harness.send(garbage)
        received = harness.drain(harness.elk, settle=1.5)
        assert len(received) == 1
        assert received[0].decode("utf-8") == garbage

    def test_control_plane_being_down_does_not_stop_forwarding(self, harness: Harness) -> None:
        """The tail sink points at a closed port. Events must still flow."""
        harness.drain(harness.elk, settle=0.4)
        for _ in range(5):
            harness.send(cef(host="web-01"))
        assert len(harness.drain(harness.elk, settle=2.0)) == 5


class TestDropAudit:
    def test_drop_produces_an_audit_record(self, harness: Harness) -> None:
        """D-02: every drop is accounted for."""
        harness.drain(harness.audit, settle=0.4)
        harness.send(cef(host="scanner01"))
        records = harness.drain(harness.audit, settle=1.5)
        assert len(records) == 1
        assert b'"rule_id":"r-scanner"' in records[0].replace(b" ", b"")

    def test_retain_payload_includes_the_event(self, harness: Harness) -> None:
        harness.drain(harness.audit, settle=0.4)
        harness.send(cef(host="web-01", ip="10.42.1.1"))
        records = harness.drain(harness.audit, settle=1.5)
        assert len(records) == 1
        assert b'"raw"' in records[0]

    def test_no_payload_when_not_retained(self, harness: Harness) -> None:
        harness.drain(harness.audit, settle=0.4)
        harness.send(cef(host="scanner01"))
        records = harness.drain(harness.audit, settle=1.5)
        assert len(records) == 1
        assert b'"raw"' not in records[0]


class TestReload:
    def test_reload_does_not_lose_packets(self, chain: RuleChain) -> None:
        """D-28, asserted rather than assumed.

        Vector rebuilds only changed components, so the UDP source should stay bound
        across a reload. This sends continuously, reloads mid-stream, and checks that
        nothing sent before or after the reload went missing.
        """
        harness = Harness(chain)
        harness.start()
        try:
            harness.drain(harness.elk, settle=0.4)

            # Change only the transform, leaving the source untouched.
            new_chain = RuleChain(
                default_action=Action.FORWARD,
                rules=[
                    Rule(
                        id="r-other",
                        name="other",
                        order=0,
                        action=Action.DROP,
                        conditions=[
                            Condition(field="filterhostname", operator=Operator.EQ, value="nothing")
                        ],
                    )
                ],
            )
            settings = VectorSettings(
                listen_address=f"127.0.0.1:{harness.ingest_port}",
                elk_address=f"127.0.0.1:{harness.elk_port}",
                drop_audit_address=f"127.0.0.1:{harness.audit_port}",
                control_plane_url="http://127.0.0.1:1",
            )
            text = render_toml(new_chain, settings, chain_version=2)
            text = text.replace(
                'address = "0.0.0.0:9598"', f'address = "127.0.0.1:{harness.metrics_port}"'
            )

            sent = 0
            for i in range(40):
                harness.send(cef(host="web-01", name=f"evt-{i}"))
                sent += 1
                if i == 15:
                    harness.config_path.write_text(text, encoding="utf-8")
                    assert harness.proc is not None
                    harness.proc.send_signal(__import__("signal").SIGHUP)
                time.sleep(0.02)

            received = harness.drain(harness.elk, settle=3.0)
            # UDP on loopback under a light load should not lose anything. If this proves
            # flaky in CI, the correct response is to investigate, not to loosen it: the
            # entire hot-reload design depends on this holding.
            assert len(received) == sent, f"sent {sent}, received {len(received)}"
        finally:
            harness.stop()
