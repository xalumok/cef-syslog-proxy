# sixthsense

A filtering proxy for CEF and syslog security events. It sits between a detection source and an
ELK stack, and it drops the events you don't want to store.

```
[detection source] --CEF/syslog over UDP--> [sixthsense] --> [ELK receiver]
```

Security analysts write filter rules in a web app. The system turns those rules into
configuration for a fast data plane, and it records every event it drops.

## Contents

- [What problem this solves](#what-problem-this-solves)
- [How the system is built](#how-the-system-is-built)
- [Rules for the reader: the eight promises](#rules-for-the-reader-the-eight-promises)
- [How the proxy behaves](#how-the-proxy-behaves)
- [How a rule reaches production](#how-a-rule-reaches-production)
- [Security](#security)
- [Performance and sizing](#performance-and-sizing)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)
- [What is not built](#what-is-not-built)
- [Requirements](#requirements)

## What problem this solves

The original task was to build a proxy that filters CEF events by field value. Research showed
that this kind of product already exists. It's called a telemetry pipeline, and at least six
mature tools can receive UDP, parse CEF, filter, and forward.

But one thing was missing from every open-source option:

> An open-source proxy with a **rule interface for analysts** and an **audit record of every
> dropped event**. Open-source tools are driven by config files. The tools with a UI are
> commercial.

So this project builds the missing part and reuses the rest.

- **The data plane is Vector.** Vector is a Rust binary. It receives the packets, parses them,
  applies the rules, and forwards the events.
- **The control plane is Python and React.** It stores the rules, turns them into Vector
  configuration, keeps the audit log, and serves the web app.

There's a hard technical reason for this split, not only a stylistic one. The required stack is
Python, and CPython can't process packets one by one at 20,000 events per second with a p99
latency below 1 ms. The global interpreter lock, object allocation, and garbage collection pauses
all work against it. So Python does what Python is good at: an API, a data model, a compiler, and
a web app.

The full comparison, including the case for not building this at all, is in
[research-prior-art.md](ai_artifacts/research-prior-art.md).

## How the system is built

Two parts, with a strict boundary between them.

```
                         Control plane (ssctl)
                     Python, FastAPI, SQLite, React
                                  |
              config bundle (pull) |  ^ sampled decisions (1 in 100)
                                  v  |
  [detection source] --UDP--> [ Vector + ssagent ] --> [ ELK: alerts index ]
                                                   \-> [ ELK: drop-audit index ]
```

| Part | What it is | What it does |
|---|---|---|
| **Vector** | A pinned Rust binary | Handles all event traffic. Never written by you. |
| **`ssagent`** | A small Python process on each node, about 200 lines | Downloads the config bundle, checks the checksum, writes the file, and tells Vector to reload. |
| **`ssctl`** | Python, FastAPI, SQLite, and the built React app | Rule editing, compiling, publishing, the audit log, the simulator, and the live view. |

**The most important property: the control plane is never in the event path.** If `ssctl` is
down, the nodes keep forwarding events from their cached config, for as long as needed. Losing
the web app must never lose an event.

Everything else follows from that idea. Sampling happens on the node, not in Python. The live
view drops frames instead of slowing the event path. A node that has never seen a config starts
in forward-everything mode.

## Rules for the reader: the eight promises

These are the properties that must stay true. Each one has a test that fails if you break it.
If you change code here, read this list first.

| # | Promise | Why it matters |
|---|---|---|
| 1 | The original event bytes are never changed | ELK receives exactly what the detection source sent, so cutover is safe |
| 2 | **Fail open everywhere** | Any failure forwards the event. Too much data is better than a missing security event. |
| 3 | Every event shape reaches a decision | CEF, bare CEF, RFC 3164, RFC 5424, and unparseable text all get a result |
| 4 | No event traffic goes through Python | Python can't handle that rate |
| 5 | The control plane is never in the data path | Nodes run from cached config when it's unreachable |
| 6 | No user value is ever put into code by string formatting | A rule value is untrusted input to a code generator |
| 7 | Rules are never deleted, and the audit log is append-only | You must be able to prove what was dropped and who changed what |
| 8 | Permissions are checked on the server, never in React | The UI hides buttons for convenience; the server makes them unreachable |

## How the proxy behaves

| Situation | What happens | Why |
|---|---|---|
| No rule matches the event | Forward | Fail open |
| The event is CEF, or plain syslog | Rules are checked either way | Both formats work. Syslog fields live under a `syslog.` prefix. |
| Neither parser can read the event | Forward, count it, and store a sample | A parse failure is usually a bug in the proxy, not a bad event |
| An event is dropped | Write an audit record with the rule ID and version | You must be able to prove what was discarded |
| The control plane is down | Nodes keep forwarding from cached config | Losing the UI must never lose an event |
| A browser can't keep up with the live view | The browser drops frames | A UI tab must never slow down the event path |
| A rule change is published | Compile, validate, checksum, write, reload | No packet loss during reload, which CI checks |

### Why syslog fields have their own prefix

The two parsers disagree about common field names. CEF `severity` is a number from 0 to 10 where
higher is worse. Syslog `severity` is a word, on an inverted scale. So syslog fields go under
`syslog.`, and CEF fields stay at the top level:

```
severity          -> "9"        (CEF header)
filterhostname    -> "web-01"   (CEF extension)
syslog.severity   -> "info"     (syslog)
syslog.appname    -> "sshd"
```

In a rule, a dot in a **field name** is a path separator. A dot in a **value** is a normal
character.

## How a rule reaches production

There are two delivery paths in this project, not one. The second one is the dangerous one,
because an analyst clicking Save changes production in seconds, with no pull request and no
review.

1. **Author.** An analyst writes the rule in the UI. The role `rule-editor` or higher is required.
2. **Validate the schema.** A Pydantic model rejects a malformed rule.
3. **Compile.** The rule becomes VRL, the language Vector uses. Every value passes through one
   encoder module.
4. **Check the generated program three times.** Check the config structure, compile the program,
   and then run it over a set of probe events. Each probe event must produce one valid decision.
5. **Preview the impact.** Run the rule against stored real traffic and show the projected drop
   share. Above 5%, the UI asks for confirmation.
6. **Soak in shadow mode.** The proxy evaluates the rule and records what it would drop, but
   forwards everything.
7. **Publish.** The bundle is versioned and checksummed.
8. **Activate.** The node verifies the checksum, writes the file, reloads Vector, and keeps the
   last known good config.
9. **Watch.** Alert if the forward rate falls by more than half within five minutes.
10. **Revert.** One click restores the previous bundle.

Each of these steps replaces a control that normal code gets for free from CI. The details are in
[devsecops.md](ai_artifacts/devsecops.md).

**Automatic rollback is deliberately not built.** It flaps, it fights the operator, and it can
hide the real problem. A page plus a one-click revert takes about 30 seconds and keeps a person
in the decision.

## Security

### The highest-risk code

`src/sixthsense/compiler/` turns web-form input into executable configuration. An analyst typing
a quote character into a rule value is a code-injection path into the data plane.

Every user value reaches the generated program through one module,
[`compiler/encoder.py`](src/sixthsense/compiler/encoder.py), which applies six layers of
protection: type checking, string escaping, decimal-only number formatting, path splitting,
regular expression escaping, and TOML encoding by library.

The property test that states the goal best: **two different user values produce byte-identical
code once the literal contents are removed.** A value that could change the shape of the program
would, by definition, be executing.

### Roles

Permissions are enforced in FastAPI dependencies.

| Action | Minimum role |
|---|---|
| Read rules, bundles, audit records, and decision metadata | `viewer` |
| See event contents in the live view | `rule-editor` (redacted for `viewer` on the server) |
| Create, edit, or disable rules; publish; roll back | `rule-editor` |
| Change the default action or chain-wide shadow mode | `admin` |

Turning the whole system to fail-closed is intentionally not a two-click operation.

### Before you bind a public interface

Two settings are guarded in code rather than in documentation, because "the development default
reached production" is the failure they exist to prevent. The control plane refuses to start on a
non-loopback `SS_BIND_HOST` if either is left at its default.

| Setting | What to do |
|---|---|
| `SS_JWT_SECRET` | Set a random value of at least 32 bytes, for example `openssl rand -hex 32`. The default is published in this repository, so anyone who reads the source can sign an admin token. |
| `SS_DEV_AUTH_BYPASS` | Leave it off. It skips authentication and works only on loopback. |

### Supply chain

A third-party Rust binary sits in a security data path, so it gets the same treatment as code.
Pin Vector by digest, include it in the SBOM, and run the full pipeline on every version bump.
Containers run as non-root with a read-only root filesystem and no extra capabilities.

## Performance and sizing

Measured with `make perf` on an Apple silicon laptop, where the load generator competes with the
proxy for the same cores. Treat the numbers as a floor.

| Target | Result |
|---|---|
| 20,000 events per second, sustained | **Met.** Zero loss, zero kernel drops. |
| Added p99 latency under 1 ms | **Met.** 376 microseconds added. |
| 100,000 events per second, burst | **Met with four worker processes.** Zero loss. |

Three findings that decide how you size a deployment:

1. **Scale out, not up.** Four processes give 4.17 times the throughput of one. Eight threads in
   one process give 1.05 times. UDP ingest is serialized because one socket has one reader, so
   more threads don't help. Give each process two cores.
2. **Latency is the early warning, not throughput.** Throughput stays flat until the worker
   saturates, and then it collapses. p99 latency grows long before that. Alert on p99.
3. **Rule count is free until it isn't, and the limit is compile time.** Vector needs 1 second to
   compile 100 rules, 4 seconds for 200, and 16 seconds for 400. Our own compiler takes 1.7
   milliseconds for 400. The practical ceiling is 200 to 300 rules per worker.

Suggested starting point: **two CPUs and 1 GB of memory per worker, one worker per 30,000 events
per second of peak, and `net.core.rmem_max` at 32 MB or more.** Size so that n−1 workers carry
the full load. Every overload measured here was a socket buffer overflow, not a CPU shortage, so
tune the buffer before you add hardware.

Measure on your own hardware before you commit. Full tables are in
[architecture.md](ai_artifacts/architecture.md).

## Quick start

```bash
make setup                      # venv, Python dependencies, npm install
make vector                     # download the pinned Vector binary into .tools/
export PATH="$PWD/.tools:$PATH"

make demo                       # seed a database with example rules and a user
SS_DATABASE_URL="sqlite+pysqlite:///./demo.db" make dev
```

Open http://127.0.0.1:8000 and sign in as `analyst` / `demo1234`.

Then send some events from another terminal:

```bash
.venv/bin/cefgen send 127.0.0.1:5514 -n 500 -r 100
```

Or run the whole stack, including a fake ELK receiver that prints what it receives:

```bash
docker compose up --build
docker compose exec control ssctl adduser analyst --role rule-editor --password demo1234
```

## Commands

```bash
make check      # lint, types, unit and property tests
make e2e        # end-to-end tests against real Vector (run make vector first)
make security   # bandit and pip-audit
make compile    # print the Vector config the current rules produce
make perf       # measure throughput and added latency
make try        # run the whole stack locally and send traffic through it
```

Run `make help` for the full list.

## Repository layout

```
src/sixthsense/
  models/rule.py        The rule schema. Everything else derives from this.
  compiler/encoder.py   The injection boundary. Read this first.
  compiler/compiler.py  Turns the rule chain into VRL.
  compiler/validate.py  Runs vector validate AND vector vrl. You need both.
  services/             Rule storage, bundle publishing, and simulation.
  api/                  FastAPI routes and role checks.
  agent/main.py         ssagent: fetch config, verify, write, signal.
  cefgen/main.py        Generates normal and adversarial CEF traffic.
ui/                     React and TypeScript, built into the control plane image.
tests/                  Unit, property, API, and end-to-end tests.
ai_artifacts/           Research, decisions, architecture, and DevSecOps.
```

## Documentation

| Document | What it covers |
|---|---|
| [research-prior-art.md](ai_artifacts/research-prior-art.md) | Whether to build this at all, and what already exists |
| [open-questions.md](ai_artifacts/open-questions.md) | 53 questions, the options, and the reasoning behind each default |
| [decisions.md](ai_artifacts/decisions.md) | Every decision, with rationale and revisit triggers |
| [architecture.md](ai_artifacts/architecture.md) | System shape, the generated VRL, and measured performance |
| [devsecops.md](ai_artifacts/devsecops.md) | The two pipelines: code, and rules |
| [agentic-tooling.md](ai_artifacts/agentic-tooling.md) | Where AI assistance helped, and where it was wrong |
| [glossary.md](ai_artifacts/glossary.md) | Terms and writing conventions |
| [CLAUDE.md](CLAUDE.md) | Working rules for anyone, human or agent, editing this code |

### The lesson that cost the most time

Every real bug in this project was found by **running** the software, not by reading it. The worst
one: `vector validate` doesn't compile VRL, and `vector vrl` returns exit code 0 even when the
program crashes on every event. A broken program passed both checks, every rule silently stopped
matching, and nothing looked wrong, because fail-open kept the events flowing.

The general rule: **an exit code tells you a program compiled, not that it works on your inputs.**
If you generate an artifact that another program consumes, run that program before you believe the
artifact is correct.

## What is not built

Stated plainly, rather than shipped as a stub:

- **OpenID Connect.** Local accounts work fully. The auth layer is structured for OIDC, but
  shipping untested auth code is worse than shipping none.
- **Deduplication, storm suppression, and time-based rules.** These need a stateful engine and a
  different design.
- **Multiple destinations.** The rule action is modeled as a named output, so adding one is
  configuration rather than a rewrite.
- **A regular expression operator.** `glob` and `contains` cover the realistic cases without the
  denial-of-service risk.
- **Keeping a CEF extension key that collides with a header key.** Vector's `parse_cef` returns a
  flat map and the header value wins, so the extension is gone before the compiler sees it. D-09
  assumed otherwise, and this is recorded as a known gap.
- **A separate network listener for the decision intake endpoint.** It shares a port with the
  admin API. The boundary is network segmentation.
- **Alembic migrations, YAML rule export, and source IP allow-listing.** Each is a decision that
  was written as delivered and is not. They're listed under "Known gaps" in
  [decisions.md](ai_artifacts/decisions.md).

Still unmeasured: p99 latency at saturation. That needs hardware where the load generator isn't
competing with the proxy.

## Requirements

Python 3.12 or later, Node.js 20 or later to build the UI, and Vector 0.51.0 or later. The Vector
version floor is real: earlier releases don't reload transforms that reference external VRL files.

**Vector is needed on the control plane too**, not only on the nodes. Publishing compiles the
rules and then runs the generated program before storing it, so without the binary there's no
gate. Both container images include it. If you develop without it, publishing fails with a clear
message. You can set `SS_REQUIRE_VECTOR_ON_PUBLISH=false` to publish anyway, and accept that
nothing has validated the result.
