# Prior art and technology research: does this already exist?

**Status:** Complete · **Owner:** Yurii · **Date:** July 30, 2026
**Feeds:** the "research the technology and document the What/Why" deliverable in [initial_task.md](../initial_task.md)
**Related:** [open-questions.md](open-questions.md) · **Terms:** [glossary.md](glossary.md)
**Outcome:** the recommendation below was adopted. See [decisions.md](decisions.md), D-00.
**Stack:** Python backend, React frontend · **Style:** Microsoft Writing Style Guide

## The headline finding

Yes, this is a solved problem, and it has a name. The task describes a **telemetry pipeline**,
which is Gartner's term. The security-focused variant is increasingly called a **security data
pipeline platform**. Filtering CEF and syslog in flight between a detection source and a SIEM is
the canonical use case for that whole category, not an edge case.

Two data points on how mature it is:

- Gartner projects that **40% of log telemetry will pass through a telemetry pipeline product by
  2026**, up from under 10% in 2022
  ([Gartner Peer Insights](https://www.gartner.com/reviews/market/telemetry-pipelines)).
- The category consolidated hard over the past year. **CrowdStrike acquired Onum for about $290
  million**, and **SentinelOne acquired Observo AI for about $225 million**
  ([Software Analyst market guide](https://softwareanalyst.substack.com/p/market-guide-2025-the-rise-of-security)).

So the honest framing for design review isn't "how do we build this." It's **why build this, when
at least eight mature products already do the data-plane job.** The recommendation section answers
that, and the answer is narrower and more interesting than "build the whole proxy."

> [!IMPORTANT]
> Here's the one thing I couldn't find off the shelf: an open-source, self-hostable CEF and syslog
> filtering proxy with an **analyst-facing UI for rule management** and an **auditable record of
> what it dropped**. Every open-source option is config-file driven. Every UI-driven option is
> commercial. That gap is the actual product.

## What I searched for and didn't find

Negative results shape the design, so they're worth stating:

| Searched for | Result |
|---|---|
| A dedicated "CEF filtering proxy" product | **Doesn't exist as a category.** CEF filtering is a feature of general log pipelines, never a standalone product. |
| An open-source syslog filter with a rule-management UI | **Not found.** The web UIs that exist, including [rsyslog-webui](https://github.com/tinylama/rsyslog-webui), [sloggo](https://github.com/phare/sloggo), and [visualsyslog](https://github.com/MaxBelkov/visualsyslog), are log viewers rather than rule editors. The only UI-driven syslog-ng is the commercial [syslog-ng Store Box appliance](https://www.syslog-ng.com/community/b/blog/posts/web-interfaces-for-your-syslog-server-an-overview). |
| A production-grade syslog pipeline written in Python | **Not found, and that's informative.** Every serious option is C, C++, Rust, Go, or the JVM. See "How the stack narrows the field." |
| The specific field names in the task | **No match in any published CEF dictionary.** This matters, and the findings section explains why. |

## The candidate landscape

### Tier 1: classic syslog relays, already in this topology

**rsyslog** and **syslog-ng** are the default answer, and both have done this since the late
1990s. Both are written in C, both do content-based filtering, and both already sit in the
source-to-relay-to-collector shape the task describes.

The most directly relevant prior art is
[Laurie Rhodes' rsyslog CEF filtering config for Microsoft Sentinel](https://laurierhodes.info/node/151).
That's someone solving precisely this problem, filtering CEF by field value before it reaches the
SIEM, using rsyslog's `mmfields` module to split on the pipe delimiter and then forwarding
conditionally.

It's also a useful cautionary tale. The author notes that:

- CEF's flexible whitespace handling makes "a simple regex query unworkable" under POSIX regular
  expressions without lookahead.
- The config runs to about **130 field mappings** and carries a "complex configuration maintenance
  burden."
- The queue caps at 50,000 messages before it starts dropping.
- You should comment out unused CEF properties "to save CPU and parsing."

The takeaway: the data plane is entirely achievable with rsyslog. The problem is the maintenance
burden of expressing analyst intent as rsyslog config, which is the same conclusion as the
headline finding.

### Tier 2: modern pipeline agents

**[Vector](https://vector.dev)**, written in Rust, owned by Datadog, and licensed under MPL-2.0,
is the strongest open-source fit:

- A `syslog` source with `mode: udp`, handling both RFC 3164 and RFC 5424.
- A **`parse_cef` VRL function**, added in [v0.25.0](https://vector.dev/releases/0.25.0/) and built
  specifically for ArcSight CEF.
- A **CEF encoder** added in [v0.43.0](https://vector.dev/releases/0.43.0/), so it can re-emit CEF.
- `filter`, `sample`, and `route` transforms, plus Elasticsearch, socket, and HTTP sinks.
- A single static binary with no runtime dependency, which matters when the alternative would be
  putting a Python interpreter on the event path.

On paper that's a complete implementation of the task's data plane in about 30 lines of TOML.

**OpenTelemetry Collector** has a `syslog` receiver covering RFC 3164 and RFC 5424 over TCP and
UDP, a `filter` processor, and a `routing` connector. But **CEF support is still an open issue**
([contrib#37442](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37442)),
so you'd hand-roll CEF parsing in an operator chain. Strategically appealing given the ecosystem,
but tactically immature for CEF specifically.

**Fluent Bit** and **NXLog** both parse CEF natively and both are viable. NXLog's
[`xm_cef`](https://docs.nxlog.co/agent/current/xm/cef.html) module is the more complete
implementation, but the capable edition is commercial.

### Tier 3: filter at the destination, which ELK can already do

Since the destination is ELK, the lowest-friction option is to not build a proxy at all:

- **Logstash** has a maintained
  [`logstash-codec-cef`](https://github.com/logstash-plugins/logstash-codec-cef) that works
  directly on the `syslog` or `udp` input, plus conditionals and `drop {}`. Elastic even publishes
  a [reference CEF pipeline](https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/cef/logstash/pipeline/logstash.conf).
- **Elastic Agent and Filebeat** have a
  [CEF integration](https://www.elastic.co/docs/reference/integrations/cef) and a
  [`decode_cef` processor](https://www.elastic.co/docs/reference/beats/filebeat/processor-decode-cef)
  implementing ArcSight CEF spec v25, which combines with `drop_event`.

The catch: filtering at the destination still sends the traffic across the network and still hits
the receiver. If the motivation is ingest volume, license cost, or load on ELK, destination-side
filtering doesn't deliver any of it. **Confirm this before anything else** (Q-38). If the goal is
just "analysts want fewer noisy events in Kibana," a Logstash conditional is a one-day change and
this project shouldn't exist.

### Tier 4: commercial pipeline platforms

**Cribl Stream** leads the market. Cribl, Apica, BindPlane OP, Onum, and DataBahn are the top five
by [PeerSpot](https://www.peerspot.com/categories/observability-pipeline-software) user ranking as
of February 2026, with Cribl rated 8.6. It has the UI-driven rule management that the open-source
tier lacks, which is exactly the gap in the headline finding. **Tenzir** is worth a mention as the
security-specific open-core entrant, with OCSF, ASIM, and ECS schema mapping built in.

If procurement is viable, **Cribl is the closest thing to an off-the-shelf answer to the literal
task**, and an honest what-and-why document has to say so.

### Tier 5: SIEM vendor connectors

Everyone in this space converges on the same advice, which is to filter as early as possible:

- **Microsoft Sentinel** filters CEF through Azure Monitor Agent Data Collection Rules
  ([docs](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama)).
- **ArcSight SmartConnectors** have built-in filter conditions
  ([SmartConnector guide](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-25.1/pdfdoc/SmartConnInstallandUserGuide/SmartConnInstallandUserGuide.pdf)).
- **Splunk Connect for Syslog** is a syslog-ng-based reference implementation with a
  [dedicated CEF source](https://splunk.github.io/splunk-connect-for-syslog/3.14.1/sources/base/cef/).
  It's Splunk-bound, but the architecture pattern is worth copying wholesale.

## How the candidates compare against the requirements

| | rsyslog / syslog-ng | Vector | OTel Collector | Logstash (at ELK) | Cribl Stream | Build in Python |
|---|---|---|---|---|---|---|
| UDP syslog ingest | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ see below |
| CEF parsing | ⚠️ manual | ✅ `parse_cef` | ❌ open issue | ✅ codec | ✅ | ✅ (we own the bugs) |
| Filter on field values | ✅ | ✅ VRL | ✅ | ✅ | ✅ | ✅ |
| Filters before the network hop | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ |
| **Meets the D-21 rate targets** | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Analyst-facing rule UI** | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Per-drop audit trail** | ⚠️ DIY | ⚠️ DIY | ⚠️ DIY | ⚠️ DIY | ✅ | ✅ |
| Rule simulation | ❌ | ⚠️ offline | ❌ | ⚠️ offline | ✅ | ✅ |
| Hot reload without packet loss | ⚠️ | ✅ | ✅ | ⚠️ | ✅ | ✅ |
| License cost | free | free | free | free | **paid** | engineering time |
| Matches the mandated stack | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

Two things stand out. The bolded UI and audit rows show that **the data plane is commodity and the
control plane isn't**, which is the core finding. The bolded rate row shows the second finding,
which is new since the stack was confirmed.

## How the stack narrows the field

The mandated stack is Python for the backend and JavaScript with React for the frontend. That
changes the shape of the recommendation.

Every production-grade syslog pipeline in the landscape above is written in C, C++, Rust, Go, or
the JVM. Not one of the serious options is written in Python, and that isn't an accident. Per-packet
UDP processing at tens of thousands of events per second is exactly the workload CPython handles
worst:

- The global interpreter lock caps single-process throughput regardless of core count.
- Per-object allocation and reference counting add overhead on every field of every event.
- Garbage collection pauses land directly in the p99 latency that D-21 budgets at under a
  millisecond.

You can push back on all three with `uvloop`, `SO_REUSEPORT`, and a process pool per core. Teams do
run Python network services at meaningful rates. But the ceiling arrives early, the tail latency
stays poor, and the engineering effort goes into fighting the runtime rather than building the
thing that doesn't exist yet.

**The practical consequence: writing the data plane in the mandated stack isn't viable at the D-21
targets.** So delegating the data plane isn't a compromise forced by laziness. It's the correct
reading of the constraint, and it's what makes Option B the right answer rather than merely the
convenient one.

Python is genuinely good at the other half. The control plane is a CRUD API, a compiler, a data
model, and a web application, and Python is a strong choice for all four. Pydantic in particular
earns its place twice, since it validates the rule schema and generates the JSON Schema that the
agent-readable spec needs.

## Findings that change the design

### The field names aren't standard CEF, and that's a real constraint

`filterhostname`, `filterid`, `filteripaddress`, `filternodename`, `filterpriority`, `filtertype`,
and `notificationtime` appear in no published CEF dictionary I could find. Not
[ArcSight's](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors/pdfdoc/arcsight-cef-syslog/arcsight-cef-syslog.pdf),
not [Microsoft's CEF-to-CommonSecurityLog mapping](https://learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping),
and not Elastic's, Fortinet's, Palo Alto's, or Trend Micro's.

They're custom extension keys from a vendor or an in-house detection source. That has two
consequences:

1. **Schema-bound tooling degrades.** Sentinel's `CommonSecurityLog` and Elastic's ECS mapping
   only map known CEF keys, so these would land unmapped or in a catch-all. A **schema-agnostic**
   engine that treats the event as a map of names to values is the right call, which is what Q-04
   already assumed. Now there's evidence for it.
2. **It escalates Q-08 to a blocker.** Nobody can tell you the value domain of `filterpriority`
   from documentation, because there isn't any. Only a sample capture or the name of the emitting
   product will settle whether priority 1 is most or least urgent, and getting that backward
   inverts every threshold rule.

**Action:** ask which product emits these events. It's a one-line question with a large payoff.

### CEF parsing is a known trap, and mature tools still get it wrong

This is the finding I'd most want in design review, because it's the difference between "parsing
is easy" and "parsing is where this project fails."

- **Vector.** [vrl#784](https://github.com/vectordotdev/vrl/issues/784) records that `parse_cef`
  breaks when an extension value contains an unescaped `=`. See also
  [#23943](https://github.com/vectordotdev/vector/issues/23943) on escaping generally. A real-world
  trigger is a `name` or URL field containing a query string.
- **Logstash.** [logstash-input-syslog#76](https://github.com/logstash-plugins/logstash-input-syslog/issues/76)
  records that when you use the CEF codec with the syslog input, `event.severity` silently becomes
  the **syslog priority** rather than the **CEF header severity**. Those are two different numbers
  on different scales, sharing one field name.
- **rsyslog.** Per the Sentinel write-up above, CEF's whitespace rules defeat naive regular
  expressions outright.

This independently confirms both Q-19, which called for an escaping-aware parser rather than
`split()`, and Q-09, on the header-versus-extension `severity` collision. The Logstash bug is
exactly the Q-09 failure mode occurring in production software.

The failure mode is the dangerous kind. **A misparsed event doesn't crash. It produces a wrong
filter decision.** A severity field silently carrying the wrong scale means threshold rules quietly
match the wrong events.

There's a Python-specific corollary. The obvious instinct on a Python team is to reach for a
`pycef`-style library or write a quick parser with `re`. Don't. Any Python CEF parser you adopt has
the same escaping bugs as Vector's, plus far less production exposure, and it would sit on the
event path where Python is weakest. Using Vector's parser and keeping a conformance corpus in CI is
both faster and more correct.

### On UDP, the industry says don't, with one interesting exception

[Cribl's syslog reference architecture](https://docs.cribl.io/reference-architectures/reference-arch-syslog/)
recommends TCP with TLS as the default and treats UDP as an exception for senders that can't do
better. But it notes a genuine counter-argument: for a **single very high-volume sender above 300
GB per day**, UDP is preferable, because its statelessness lets each datagram go to a different
worker. TCP instead pins one sender to one connection and one core. Cribl even builds a special TCP
load-balancing mode to work around that pinning.

The same source confirms something that supports **Q-24** directly: "UDP requires Linux system
tuning, [because] default buffers are typically insufficient for sizable traffic volumes." Kernel
drop accounting isn't optional polish. The market leader documents it as a standard failure mode.

Cribl's HA guidance also answers **Q-25** ready-made: run two nodes and preferably three, size them
so the survivors carry full load, and disable load balancer session stickiness.

### Everyone agrees: filter as early as possible

Microsoft, Elastic, Splunk, Cribl, and ManageEngine all independently give the same advice, which
is to filter at the source or the first relay. That validates the proxy's position in the
architecture. It also means you should deploy the proxy as close to the detection source as the
network allows, rather than next to ELK.

## What this means for the build

The research reframes the task. The data plane, meaning receive UDP, parse CEF, evaluate rules, and
forward, is a commodity that at least six mature tools already provide, two of them free. What
nobody ships in open source is the control plane: **an analyst-usable rule UI, an auditable record
of what was dropped and why, and a way to test a rule before it discards events.**

Here are three options, in the order I'd defend them.

### Option B, recommended: a control plane over a proven data plane

Build the differentiated part in Python and React, and delegate the commodity part to Vector. That
means a rule model, a UI, an audit log, and a simulator that compiles analyst-authored rules into
VRL and manages hot reload.

- **For.** It puts Python where Python is strong and keeps it off the event path entirely. It
  avoids reimplementing a CEF parser that mature projects still have open bugs against. It inherits
  Vector's performance, buffering, and sink ecosystem. The code you write is the code that doesn't
  already exist, and it's the smallest surface where correctness is safety-critical.
- **Against.** You take on an operational dependency on a third-party binary, debugging spans two
  processes, the rule model is constrained to what VRL expresses, and the compile step needs its
  own correctness tests. That last one is a real cost: it creates the injection surface documented
  in D-44.

### Option C: build the whole proxy from scratch

This was the credible fallback before the stack was confirmed. **In Python it no longer is.**

- **For.** Total control over the audit trail and drop behavior, one artifact to deploy, and no
  third-party runtime. That last point matters if the environment is disconnected or has a
  no-new-runtime policy.
- **Against.** Python can't meet the D-21 targets for per-packet UDP work, as the stack section
  explains. You'd also own the CEF parser and its bugs, and everything Vector gives you free
  becomes your backlog. Choosing Option C in practice means choosing a different language for the
  data plane, which contradicts the stated stack. If the environment genuinely forbids a
  third-party binary, that's the conversation to have, and it's a stack conversation rather than an
  architecture one.

### Option A: configure syslog-ng or Vector and build nothing

- **For.** Days rather than weeks, and no new code to maintain.
- **Against.** It fails the analyst-usability and audit requirements that appear to be the actual
  motivation. Rules become engineer-edited config, which is presumably what the organization
  already has.

### Recommendation

**Choose Option B.** The stack constraint removes Option C as a realistic fallback, so the fallback
is now Option A, meaning build nothing and accept config-file rules.

Either way, establish Q-38 first, because it's the real motivation. If it turns out to be "reduce
noise in Kibana," the correct deliverable is a Logstash conditional and a recommendation not to
build this at all.

I'd rather deliver that recommendation than a well-built proxy nobody needed. Recommending against
the build is a legitimate outcome of a research phase, and design review should treat it as one.

> [!NOTE]
> **On prototype scope.** The task explicitly says to build a prototype, so there will be one
> either way. Option B means building the part that doesn't already exist and demonstrating it end
> to end against a real data plane, which is a better demonstration than a from-scratch UDP
> listener that wouldn't survive its own load test.

## Effect on the open questions

| Question | Change |
|---|---|
| Q-04, schema-flexible fields | **Confirmed.** Non-standard keys make schema-agnostic matching mandatory rather than optional. |
| Q-08, field value domains | **Escalated to a blocker.** The fields are undocumented, so only a capture or the product name resolves it. |
| Q-09, header versus extension severity | **Confirmed as a real bug class.** Logstash ships this bug today. |
| Q-19, CEF escaping | **Confirmed.** Vector has open escaping bugs, so naive parsing isn't viable, and a Python reimplementation would be worse. |
| Q-21, throughput | **Now a constraint on the architecture, not just a target.** It's what rules out a Python data plane. |
| Q-24, kernel UDP buffer loss | **Confirmed.** Cribl documents it as a standard failure mode. |
| Q-25, HA topology | **Answered.** Adopt Cribl's pattern: three nodes, stickiness disabled, sized for n−1. |
| Q-38, build versus buy | **Reframed.** The question is no longer build or buy. It's which layer to build. |
| Q-39, mandated stack | **Answered by the organization.** Python and React, which is what makes the layer split necessary rather than merely tidy. |
| **New: Q-51** | Can the organization procure a commercial pipeline such as Cribl, or is open source or in-house mandated? This determines whether Options A through C are even the right menu. |
| **New: Q-52** | Which product emits these events? It resolves Q-08 instantly and tells you whether a vendor connector already filters at the source. |
| **New: Q-53** | Is the driver ingest cost, ELK load, analyst noise, or network volume? Each points at a different layer, and one of them makes this project unnecessary. |

## Sources

- [Gartner: Telemetry Pipelines market](https://www.gartner.com/reviews/market/telemetry-pipelines)
- [Software Analyst: Market Guide 2025, The Rise of Security Data Pipelines](https://softwareanalyst.substack.com/p/market-guide-2025-the-rise-of-security)
- [PeerSpot: Observability Pipeline Software 2026](https://www.peerspot.com/categories/observability-pipeline-software)
- [Cribl: Syslog to Cribl Stream reference architecture](https://docs.cribl.io/reference-architectures/reference-arch-syslog/)
- [Laurie Rhodes: Filtering Common Event Format at source for Microsoft Sentinel](https://laurierhodes.info/node/151)
- [Microsoft Learn: Ingest syslog and CEF messages to Sentinel via AMA](https://learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama)
- [Microsoft Learn: CEF key to CommonSecurityLog field mapping](https://learn.microsoft.com/en-us/azure/sentinel/cef-name-mapping)
- Vector: [v0.25.0 release notes for `parse_cef`](https://vector.dev/releases/0.25.0/), [v0.43.0 for the CEF encoder](https://vector.dev/releases/0.43.0/), and [VRL examples](https://vector.dev/docs/reference/vrl/examples/)
- Vector issues: [vrl#784 on unescaped `=`](https://github.com/vectordotdev/vrl/issues/784), [vector#23943 on escaping](https://github.com/vectordotdev/vector/issues/23943), and [vector#17332 on the CEF codec](https://github.com/vectordotdev/vector/issues/17332)
- [OpenTelemetry contrib#37442: CEF over syslog support](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues/37442)
- [logstash-plugins/logstash-codec-cef](https://github.com/logstash-plugins/logstash-codec-cef) and [logstash-input-syslog#76 on the severity collision](https://github.com/logstash-plugins/logstash-input-syslog/issues/76)
- Elastic: [CEF integration](https://www.elastic.co/docs/reference/integrations/cef) and [the decode_cef processor](https://www.elastic.co/docs/reference/beats/filebeat/processor-decode-cef)
- [Splunk Connect for Syslog: CEF source](https://splunk.github.io/splunk-connect-for-syslog/3.14.1/sources/base/cef/)
- [NXLog: xm_cef module](https://docs.nxlog.co/agent/current/xm/cef.html)
- [Micro Focus: ArcSight SmartConnector installation and user guide](https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-25.1/pdfdoc/SmartConnInstallandUserGuide/SmartConnInstallandUserGuide.pdf)
- [syslog-ng: web interfaces overview](https://www.syslog-ng.com/community/b/blog/posts/web-interfaces-for-your-syslog-server-an-overview)
- [ManageEngine: syslog forwarding best practices](https://www.manageengine.com/products/eventlog/logging-guide/syslog/syslog-forwarding.html)
- [NXLog: Logstash alternatives for security operations in 2026](https://nxlog.co/news-and-blog/posts/logstash-alternatives-and-competitors)
