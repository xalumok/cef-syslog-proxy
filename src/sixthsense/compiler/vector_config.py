"""Render a complete Vector configuration around the compiled VRL.

TOML is produced with ``tomli_w`` rather than string templating, so the VRL program is
escaped by a library that understands TOML rather than by us. That closes the second half of
the injection surface: the encoder makes the VRL safe, and this makes the embedding safe.
"""

from __future__ import annotations

from typing import Any

import tomli_w

from sixthsense.compiler.compiler import compile_or_raise
from sixthsense.compiler.encoder import encode_string
from sixthsense.models.rule import RuleChain

#: Vector 0.51.0 is the floor. Earlier versions do not reload transforms that reference
#: external VRL files on SIGHUP, which D-28 depends on.
MIN_VECTOR_VERSION = "0.51.0"


class VectorSettings:
    """Node-side settings that are not part of the rule chain."""

    def __init__(
        self,
        *,
        listen_address: str = "0.0.0.0:5514",
        elk_address: str = "127.0.0.1:5140",
        drop_audit_address: str = "127.0.0.1:5141",
        control_plane_url: str = "http://127.0.0.1:8000",
        receive_buffer_bytes: int = 26_214_400,
        max_length: int = 65_536,
        sample_rate: int = 100,
        node_id: str = "node-1",
    ) -> None:
        self.listen_address = listen_address
        self.elk_address = elk_address
        self.drop_audit_address = drop_audit_address
        self.control_plane_url = control_plane_url
        self.receive_buffer_bytes = receive_buffer_bytes
        self.max_length = max_length
        self.sample_rate = sample_rate
        self.node_id = node_id


_AUDIT_VRL = """\
# Build the drop audit record (D-02). Metadata always; the full event only when the rule
# that matched opted in with retain_payload.
retain = .ss.retain == true
original = to_string(.message) ?? ""

. = {
    "@timestamp": .ss.ts,
    "decision": .ss.decision,
    "reason": .ss.reason,
    "rule_id": .ss.rule_id,
    "rule_version": .ss.rule_version,
    "chain_version": .ss.chain_version,
    "event_id": .ss.event_id,
    "severity": .ss.severity,
    "host": .ss.host,
    "name": .ss.name,
    "node": %(node_id)s,
}

if retain {
    .raw = original
}
"""

_SAMPLE_VRL = """\
# Compact record for the live view. Vector samples before this runs, so the control plane
# never sees event-rate traffic (D-37).
. = {
    "ts": .ss.ts,
    "decision": .ss.decision,
    "reason": .ss.reason,
    "rule_id": .ss.rule_id,
    "rule_version": .ss.rule_version,
    "event_id": .ss.event_id,
    "node": %(node_id)s,
    # Which parser produced the fields. Without this the live view cannot explain why a rule
    # did not match: a CEF rule against a plain syslog event looks identical to a bad rule.
    "cef_ok": .ss.cef_ok,
    "syslog_ok": .ss.syslog_ok,
    "fields": {
        "severity": .ss.severity,
        "filterhostname": .ss.host,
        "name": .ss.name,
    },
    "raw": to_string(.message) ?? "",
}
"""


def build_config(
    chain: RuleChain,
    settings: VectorSettings,
    *,
    chain_version: int = 0,
) -> dict[str, Any]:
    """Build the Vector topology as a plain dict, ready for TOML serialization."""
    host, _, port = settings.listen_address.rpartition(":")

    decide_vrl = compile_or_raise(chain, chain_version=chain_version)

    # node_id lands inside a generated VRL program, so it goes through the encoder like any
    # other value. It is operator-supplied rather than analyst-supplied, but the invariant is
    # that nothing reaches VRL except through encoder.py, and an unquoted node name with a
    # quote in it would break the data plane rather than one rule.
    node_id = encode_string(settings.node_id)

    config: dict[str, Any] = {
        "sources": {
            "ingest": {
                "type": "socket",
                "mode": "udp",
                "address": settings.listen_address,
                # D-17: 64 KB, the maximum UDP payload. Do not assume the classic 1024.
                "max_length": settings.max_length,
                # D-24: without this the kernel silently discards under burst.
                "receive_buffer_bytes": settings.receive_buffer_bytes,
                "decoding": {"codec": "bytes"},
            }
        },
        "transforms": {
            "decide": {
                "type": "remap",
                "inputs": ["ingest"],
                # Never abort on error: a VRL runtime failure must not drop an event.
                "drop_on_error": False,
                "drop_on_abort": False,
                "source": decide_vrl,
            },
            "split": {
                "type": "route",
                "inputs": ["decide"],
                "route": {
                    # forward and forward_parse_error both go to ELK (D-01, D-18).
                    "forward": '.ss.decision != "drop"',
                    "dropped": '.ss.decision == "drop"',
                },
            },
            "audit": {
                "type": "remap",
                "inputs": ["split.dropped"],
                "drop_on_error": False,
                "source": _AUDIT_VRL % {"node_id": node_id},
            },
            "tail_sample": {
                "type": "sample",
                "inputs": ["decide"],
                "rate": settings.sample_rate,
                # `exclude` means "bypass sampling", not "discard". Matching events always
                # pass through, which is what keeps every drop in the live view: they are
                # rare and they are the ones an analyst needs to see.
                #
                # This is the whole drop path. An earlier version added a second `filter`
                # transform for drops and fed both into `tail`, on the assumption that
                # `exclude` dropped them. It does not, so every drop was counted twice: once
                # here and once through the filter. That inflated the live view and, worse,
                # the persisted sample the impact preview reads, so the projected drop share
                # was roughly double the truth and the D-27 confirmation fired on it.
                "exclude": '.ss.decision == "drop"',
            },
            "tail": {
                "type": "remap",
                "inputs": ["tail_sample"],
                "drop_on_error": False,
                "source": _SAMPLE_VRL % {"node_id": node_id},
            },
        },
        "sinks": {
            "elk": {
                "type": "socket",
                "mode": "udp",
                # `_unmatched` is wired here deliberately. The two routes above are already
                # exhaustive, so it should always be empty. But if a future edit ever makes
                # them non-exhaustive, an unmatched event gets forwarded rather than
                # silently discarded. Fail open at the routing layer too (D-01).
                "inputs": ["split.forward", "split._unmatched"],
                "address": settings.elk_address,
                # D-15: emit .message verbatim. No re-serialization, no added fields.
                "encoding": {"codec": "text"},
            },
            "drop_audit": {
                "type": "socket",
                "mode": "udp",
                "inputs": ["audit"],
                "address": settings.drop_audit_address,
                "encoding": {"codec": "json"},
            },
            "control_plane_tail": {
                "type": "http",
                "inputs": ["tail"],
                "uri": f"{settings.control_plane_url}/api/decisions/intake",
                "method": "post",
                "encoding": {"codec": "json"},
                "batch": {"max_events": 50, "timeout_secs": 2},
                # The control plane is not in the data path. If it is down, drop the
                # samples and keep forwarding events.
                "request": {"retry_attempts": 1, "timeout_secs": 5},
                "buffer": {"type": "memory", "max_events": 500, "when_full": "drop_newest"},
            },
            "metrics": {
                "type": "prometheus_exporter",
                "inputs": ["decide"],
                "address": "0.0.0.0:9598",
            },
        },
    }

    if not host:
        raise ValueError(f"listen_address must include a host: {settings.listen_address!r}")
    if not port.isdigit():
        raise ValueError(f"listen_address must end in a port: {settings.listen_address!r}")

    return config


def render_toml(
    chain: RuleChain,
    settings: VectorSettings,
    *,
    chain_version: int = 0,
) -> str:
    """Render the full Vector config as TOML text."""
    config = build_config(chain, settings, chain_version=chain_version)
    return tomli_w.dumps(config)
