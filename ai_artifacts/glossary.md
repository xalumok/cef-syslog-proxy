# Glossary and terminology

**Status:** Reference · **Owner:** Yurii · **Date:** July 30, 2026
**Stack:** Python backend, React frontend · **Style:** Microsoft Writing Style Guide
**Audience:** people and software agents

Every document in this directory uses the terms on this page. Each term has one meaning, and each
meaning has one term. If you're writing or updating a document here, use these words rather than
synonyms.

## Project terms

| Term | Meaning |
|---|---|
| **event** | One CEF or syslog record. The proxy receives events and decides what to do with each one. Don't call it a message, a log line, or an alert. |
| **field namespace** | Where a field lives in the parsed event. CEF fields sit at the top level; syslog fields sit under `syslog.`, because both parsers produce a `severity` and the two aren't the same scale. |
| **detection source** | The system that creates events and sends them to the proxy. |
| **proxy** | The complete system this project builds. It receives, filters, and forwards events. |
| **proxy node** | One running instance of the data plane: a Vector process plus an `ssagent` process. |
| **data plane** | The part that handles events. Vector, always. Python never appears here. |
| **control plane** | The part that manages rules. Python and React. It never handles event-rate traffic. |
| **rule** | One instruction, made up of conditions and an action. |
| **condition** | One test against one field of an event. |
| **action** | What the proxy does with an event: `forward` or `drop`. |
| **rule chain** | The ordered list of all rules. |
| **forward** | The proxy sends the event to ELK. |
| **drop** | The proxy doesn't send the event to ELK. |
| **fail open** | When the proxy can't decide, it forwards the event. |
| **fail closed** | When the proxy can't decide, it drops the event. |
| **shadow mode** | The proxy evaluates every rule and records the results, but forwards everything and drops nothing. |
| **hot reload** | The proxy loads new rules without restarting and without losing events. |
| **drop audit record** | A record showing that the proxy dropped an event and which rule caused it. |
| **bundle** | A versioned, checksummed set of compiled Vector config that `ssctl` publishes and `ssagent` fetches. |
| **compiler** | The Python component that turns rules into VRL. The highest-risk code in the project. See D-44. |
| **cutover** | The change that puts the proxy into the live path for the first time. |
| **`ssctl`** | The control plane: FastAPI, SQLite, and a built React app. |
| **`ssagent`** | The small Python process on each proxy node. It fetches bundles and tells Vector to reload. |
| **`cefgen`** | The Python CLI that generates test events. |

## Abbreviations

Spell out each of these on first use in a document, then use the short form.

| Short form | Full form | Meaning |
|---|---|---|
| **CEF** | Common Event Format | A text format for security events, created by ArcSight. |
| **ELK** | Elasticsearch, Logstash, Kibana | The stack that stores and displays the events. |
| **SIEM** | security information and event management | A system that collects and analyzes security events. ELK is one. |
| **SOC** | security operations center | The team that reads the events. |
| **UDP** | User Datagram Protocol | A fast network protocol that doesn't confirm delivery. |
| **TCP** | Transmission Control Protocol | A network protocol that confirms delivery, at some cost in speed. |
| **TLS** | Transport Layer Security | The protocol that encrypts network traffic. |
| **CIDR** | Classless Inter-Domain Routing | A notation for a range of IP addresses. |
| **RFC** | Request for Comments | A published internet standard. |
| **EPS** | events per second | The event rate. |
| **UI** | user interface | The React app a person uses. |
| **API** | application programming interface | The FastAPI interface other software uses. |
| **SPA** | single-page application | The React build that `ssctl` serves as static files. |
| **GIL** | global interpreter lock | The CPython lock that caps single-process throughput. It's why the data plane isn't Python. |
| **HA** | high availability | The system keeps running when one part fails. |
| **VRL** | Vector Remap Language | The language Vector uses to process events, and what the compiler emits. |
| **PII** | personally identifiable information | Data that identifies a person. |
| **RBAC** | role-based access control | Users get permissions from their role. |
| **ACL** | access control list | A network rule that allows or blocks traffic. |
| **SAST** | static application security testing | Tooling that finds security problems in source code. |
| **SCA** | software composition analysis | Tooling that finds security problems in dependencies. |
| **SBOM** | software bill of materials | A list of every component in a product. |
| **CI** | continuous integration | The system that builds and tests code automatically. |
| **p99** | 99th percentile | 99 of every 100 measurements fall below this value. |

## Stack reference

| Layer | Choice | Notes |
|---|---|---|
| Data plane | Vector, pinned | Rust, single static binary. See D-00 for why it isn't Python. |
| Backend | Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, uvicorn | Managed with `uv` |
| Database | SQLite, WAL mode | PostgreSQL is a config change plus a migration if it's ever needed |
| Frontend | React with TypeScript, built by Vite | Node.js is a build-time dependency only, never a runtime one |
| Lint and types | `ruff`, `mypy --strict`, `eslint` | `mypy --strict` is mandatory on the compiler |
| Security scanning | `bandit`, Semgrep, `pip-audit`, `osv-scanner`, Trivy, Gitleaks | See D-43 |
| Testing | `pytest`, Hypothesis, Atheris | Hypothesis fuzzes the compiler. See D-44. |
| Supply chain | Syft for SBOMs, Cosign for signing | |

## Style conventions

These documents follow the [Microsoft Writing Style Guide](https://learn.microsoft.com/style-guide/welcome/).
The conventions that come up most often here:

- **Get to the point first.** Lead with the conclusion, then explain it.
- **Write like a person.** Contractions are fine. Stiff formality isn't clearer, just slower.
- **Use second person.** Write "you can configure this," not "the user can configure this."
- **Use active voice and present tense.**
- **Keep sentences short**, and put one idea in each.
- **Use sentence case for headings**, with no trailing period.
- **Use US English:** behavior, normalize, authorization, license, center, analyze.
- **Use the serial comma.**
- **Spell out Latin abbreviations:** "for example" rather than "e.g.," and "that is" rather
  than "i.e."
- **Spell out numbers one through nine**, and use numerals for 10 and above.
- **Avoid "simply," "easy," and "just."** They tell readers how to feel about difficulty, and
  they're often wrong.
- **Use alerts** (`> [!NOTE]`, `> [!IMPORTANT]`, `> [!WARNING]`) rather than bold paragraphs for
  callouts.

## Document map

| Document | Purpose | Status |
|---|---|---|
| [initial_task.md](../initial_task.md) | The original task | Input |
| [open-questions.md](open-questions.md) | The questions, the options, and the reasoning | Resolved |
| [research-prior-art.md](research-prior-art.md) | Existing products and the supporting evidence | Complete |
| [decisions.md](decisions.md) | Every decision | Current |
| [devsecops.md](devsecops.md) | Pipelines, gates, supply chain, and hardening | Current |
| [glossary.md](glossary.md) | This page | Current |
