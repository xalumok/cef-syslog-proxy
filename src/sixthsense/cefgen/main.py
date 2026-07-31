"""cefgen: synthetic and adversarial CEF traffic.

Two jobs, per D-45:

* Generate realistic events so the prototype can be exercised end to end.
* Generate adversarial events that target the parsing edges the research flagged, in
  particular unescaped ``=`` in extension values, which is an open bug in Vector's
  ``parse_cef`` and the exact shape that produces a wrong filter decision rather than a
  crash.

It doubles as the load harness for the D-21 rate targets and the D-28 reload test.
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from datetime import UTC, datetime

HOSTS = ["scanner01", "web-prod-01", "db-prod-02", "LAB-HOST-9", "vpn-edge-1"]
TYPES = ["ids", "av", "dlp", "fw", "auth"]
NAMES = [
    "Port scan detected",
    "Malware signature match",
    "Policy violation",
    "Failed authentication",
    "Suspicious outbound connection",
]

#: Values chosen to break naive parsers. Every one of these is legal CEF.
ADVERSARIAL_NAMES = [
    r"Query string in name?a=1&b=2",
    r"Pipe \| inside header",
    r"Backslash \\ at end",
    r"Equals = unescaped in value",
    r"Escaped \= equals in value",
    r"Newline \n literal",
    "Unicode ☃ snowman",
    "A" * 900,
]


def cef_escape_header(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|")


def cef_escape_extension(value: str) -> str:
    return value.replace("\\", "\\\\").replace("=", "\\=")


def make_event(
    *,
    adversarial: bool = False,
    host: str | None = None,
    severity: int | None = None,
    escape_extensions: bool = True,
) -> str:
    """Build one syslog-framed CEF event."""
    rng = random.Random()  # noqa: S311 - test data, not cryptography
    host = host or rng.choice(HOSTS)
    severity = severity if severity is not None else rng.randint(0, 10)
    name = rng.choice(ADVERSARIAL_NAMES if adversarial else NAMES)
    ip = f"10.{rng.randint(0, 60)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    now = datetime.now(UTC)

    header = "|".join(
        [
            "CEF:0",
            "SixthSense",
            "Generator",
            "1.0",
            str(rng.randint(1000, 9999)),
            cef_escape_header(name),
            str(severity),
        ]
    )

    esc = cef_escape_extension if escape_extensions else (lambda v: v)
    extension = " ".join(
        [
            f"eventid={rng.randint(100000, 999999)}",
            f"filterhostname={esc(host)}",
            f"filterid={rng.randint(1, 40)}",
            f"filteripaddress={ip}",
            f"filternodename=node-{rng.randint(1, 6)}",
            f"filterpriority={rng.randint(1, 5)}",
            f"filtertype={rng.choice(TYPES)}",
            f"notificationtime={int(now.timestamp() * 1000)}",
        ]
    )

    timestamp = now.strftime("%b %d %H:%M:%S")
    return f"<134>{timestamp} {host} CEF: {header}|{extension}"


def send(
    target: str,
    count: int,
    rate: int,
    *,
    adversarial_share: float = 0.0,
    unescaped_share: float = 0.0,
) -> tuple[int, float]:
    """Send ``count`` events to ``host:port`` over UDP at approximately ``rate`` per second."""
    host, _, port = target.rpartition(":")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (host, int(port))

    rng = random.Random(1234)  # noqa: S311 - reproducible test data
    interval = 1.0 / rate if rate > 0 else 0.0
    sent = 0
    start = time.perf_counter()
    next_at = start

    for _ in range(count):
        event = make_event(
            adversarial=rng.random() < adversarial_share,
            escape_extensions=rng.random() >= unescaped_share,
        )
        sock.sendto(event.encode("utf-8"), addr)
        sent += 1
        if interval:
            next_at += interval
            delay = next_at - time.perf_counter()
            if delay > 0:
                time.sleep(delay)

    elapsed = time.perf_counter() - start
    sock.close()
    return sent, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(prog="cefgen", description="CEF traffic generator")
    sub = parser.add_subparsers(dest="command", required=True)

    p_print = sub.add_parser("print", help="write events to stdout")
    p_print.add_argument("-n", "--count", type=int, default=10)
    p_print.add_argument("--adversarial", action="store_true")
    p_print.add_argument(
        "--unescaped",
        action="store_true",
        help="omit CEF extension escaping, reproducing the parse_cef '=' bug shape",
    )

    p_send = sub.add_parser("send", help="send events over UDP")
    p_send.add_argument("target", help="host:port")
    p_send.add_argument("-n", "--count", type=int, default=1000)
    p_send.add_argument("-r", "--rate", type=int, default=1000, help="events per second, 0 = max")
    p_send.add_argument("--adversarial-share", type=float, default=0.0)
    p_send.add_argument("--unescaped-share", type=float, default=0.0)

    args = parser.parse_args()

    if args.command == "print":
        for _ in range(args.count):
            print(
                make_event(
                    adversarial=args.adversarial,
                    escape_extensions=not args.unescaped,
                )
            )
        return 0

    sent, elapsed = send(
        args.target,
        args.count,
        args.rate,
        adversarial_share=args.adversarial_share,
        unescaped_share=args.unescaped_share,
    )
    achieved = sent / elapsed if elapsed else 0.0
    print(f"sent {sent} events in {elapsed:.2f}s ({achieved:,.0f} EPS)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
