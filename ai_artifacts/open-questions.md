# Open questions: CEF and syslog filtering proxy

**Status:** Resolved. See [decisions.md](decisions.md).
**Owner:** Yurii · **Date:** July 30, 2026
**Input:** [initial_task.md](../initial_task.md) · **Evidence:** [research-prior-art.md](research-prior-art.md)
**Stack:** Python backend, React frontend · **Terms:** [glossary.md](glossary.md)
**Style:** Microsoft Writing Style Guide

> [!NOTE]
> Read this document for background, not for current state. Every question here has an answer in
> [decisions.md](decisions.md). This document records what was uncertain, what the options were,
> and why each default made sense.

## How to read this document

The task puts a proxy into a live security alerting path:

```
[detection source] --CEF/syslog over UDP--> [proxy: filter] --> [ELK receiver]
```

Adding a component to that path creates a new single point of failure for security events. Most
of the questions below exist because a wrong default there drops events without telling anyone.

Each question has four parts:

- **Q-nn.** The question.
- **Why it matters.** What changes in the design when the answer changes.
- **Options.** The realistic answers.
- **Working assumption.** What gets built if no one answers.

None of these questions block the work. Every question has a working assumption, so the prototype
moves forward either way. Those assumptions are what this document really delivers. They're the
agreement worth signing off, and each one is cheap to reverse.

A red circle (🔴) marks a question that's expensive to get wrong. Answer those before the
architecture document is final.

> [!IMPORTANT]
> One question has since been answered by the organization rather than by this analysis. The stack
> is **Python for the backend and JavaScript with React for the frontend** (Q-39). That answer
> propagates further than it looks, because it removes a from-scratch proxy as a viable fallback.
> See Q-21 and Q-38.

## The 10 questions that change the architecture

| # | Question | Easy to reverse? |
|---|---|---|
| Q-01 | Does the proxy fail open or fail closed when nothing matches? | No. It's a policy call with audit consequences. |
| Q-02 | Can the proxy drop a security event without keeping a record? | No. It drives storage, compliance, and the data model. |
| Q-05 | Allow-list, deny-list, or ordered rule chain? | Partly. The rule schema is hard to migrate. |
| Q-13 | Does the outbound side have to stay UDP syslog? | No. It decides whether delivery guarantees are possible. |
| Q-16 | Does anything downstream depend on the packet's source IP address? | No. The proxy replaces it by default. |
| Q-21 | What's the peak rate in EPS, and the latency budget? | No. Combined with the stack, it decides which layers you can build at all. |
| Q-25 | Can the proxy be a single point of failure, or does it need HA on day one? | No. UDP and HA are hard to combine. |
| Q-30 | Is the UI or Git the source of truth for rules? | No. Two writers need a merge story. |
| Q-38 | Build a proxy, or configure Vector, Cribl, Logstash, or syslog-ng? | No. This is the build-or-buy decision. |
| Q-45 | Does "test generation" mean synthetic CEF traffic or AI-written tests? | Yes, but it changes the demo. |

## Filtering behavior

### Q-01 🔴 What happens to an event that matches no rule?

**Why it matters.** This is the highest-consequence decision in the system. Fail open, and a
misconfigured proxy floods ELK. Fail closed, and a misconfigured proxy discards security events
quietly. No one notices until the next incident review.

**Options.**

- Forward by default. Rules subtract.
- Drop by default. Rules admit.
- Make it configurable, and show the active mode at startup and in the UI.

**Working assumption.** Forward by default. On a security alerting path, too much data beats a
missed event. The default stays configurable, but the config key is required and there's no
implicit fallback, so someone always chooses the mode deliberately.

### Q-02 🔴 Can you recover an event after the proxy drops it?

**Why it matters.** An auditor will ask you to prove the proxy discarded nothing relevant to an
incident. If the dropped events are gone, you can't. This decides whether you need a quarantine
store and how long it keeps data.

**Options.**

- The drop is final. Keep only a counter.
- Record metadata only: event ID, rule ID, and timestamp.
- Write the full event to a separate quarantine index with its own retention.

**Working assumption.** Metadata by default, with full retention available per rule
(`on_drop: quarantine`). Metadata keeps the volume manageable and still preserves the audit trail.
High-risk rules can opt into keeping the whole event.

### Q-03 Does the proxy only forward and drop, or can it modify events?

**Why it matters.** Enrichment often makes the ELK experience better. Examples include tagging the
matched rule ID, adding the original source IP address, and normalizing timestamps. But enrichment
turns the proxy from a filter into a transformer. That means a much larger test surface and a risk
of breaking existing ELK dashboards.

**Options.**

- Pass bytes through unchanged.
- Pass through and add annotation fields.
- Support full transformation and redaction.

**Working assumption.** Pass through plus annotation, with annotation **off by default**. Existing
ELK parsing stays untouched until someone turns annotation on.

### Q-04 Are the 10 listed fields the complete set, or a subset?

**Why it matters.** If new fields can show up, the rule engine has to accept any field name rather
than a fixed structure. Retrofitting that later means migrating the rule schema.

**Options.**

- Exactly these 10, fixed.
- These 10 plus any other CEF extension key.
- These 10 plus the CEF header fields.

**Working assumption.** These 10 plus any other extension key. The engine treats each event as a
map of names to values. The UI shows the 10 known fields first and offers an "other field" option.

### Q-05 🔴 How do rules combine?

**Why it matters.** This sets the config schema, the UI, and how quickly someone can understand
the system during an incident.

**Options.**

- A flat allow-list.
- A flat deny-list.
- An ordered chain where the first match wins, and each rule carries a `forward` or `drop` action.
  This is the model firewalls use.
- A full boolean expression language.

**Working assumption.** An ordered chain, first match wins. It covers both allow-list and
deny-list styles, SOC engineers already know it from firewalls, and rule order is explicit rather
than emergent. Conditions inside a rule combine with AND. To express OR, write a second rule or
use set membership (`in [...]`).

### Q-06 Which comparison operators do you need?

**Why it matters.** `filteripaddress` needs CIDR matching. `severity` and `filterpriority` need
numeric comparison. `name` probably needs a substring or pattern match. Regular expressions on a
hot path are a denial-of-service risk because some patterns backtrack for a long time, so they
need a guard.

**Options.** Equality, case-insensitive equality, set membership, starts with, ends with, contains,
glob, regular expression, CIDR, the four numeric comparisons, range, exists, and doesn't exist.

**Working assumption.** Ship all of these except unrestricted regular expressions. If you keep
regular expressions, limit the pattern size and set a per-event time budget, or use an engine like
RE2 that can't backtrack. Confirm whether analysts actually need them. If they don't, dropping
them removes a whole class of risk.

### Q-07 Do comparisons respect case by default?

**Why it matters.** Different detection sources write host names with different capitalization. A
case-sensitive default produces rules that fail to match, and nobody notices.

**Working assumption.** Ignore case by default for string fields, with `case_sensitive: true`
available per condition. Field names also ignore case.

### Q-08 What values does each field hold, and in what format?

**Why it matters.** You can't write comparison operators without this. `severity` might be a
number from 0 to 10, a word like `Low` or `Very-High`, or a vendor-specific integer.
`filterpriority` is just as unclear: does priority 1 mean most urgent or least urgent? Getting the
sort direction backward inverts every threshold rule.

You need sample values for `severity`, `filterpriority`, `filtertype`, `filterid`, and `eventid`.
You also need the exact encoding of `notificationtime`, including the time zone. It could be
seconds since 1970, milliseconds since 1970, `MMM dd yyyy HH:mm:ss`, or ISO 8601.

**Options.** Someone writes a schema document, or someone captures about 1,000 real events with
the sensitive data removed. The capture is far more useful.

**Working assumption.** `severity` is a CEF-standard integer from 0 to 10, with the standard words
also accepted. `filterpriority` is an integer where **lower means more urgent**.
`notificationtime` is milliseconds since 1970. All three are marked as assumptions in the code and
covered by tests that fail loudly if a real sample disagrees.

### Q-09 Is `severity` a CEF header field or an extension key? What about `name`?

**Why it matters.** CEF defines `Name` and `Severity` in the pipe-delimited header:
`CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|extensions`. The task lists them next to
eight extension-style keys. If they're header fields, the parser reads them by position. If
they're extension keys with the same names, one event can carry two values for one name, and you
have to decide which one wins.

**Working assumption.** They're header fields. The parser exposes header fields under reserved
names. If a colliding extension key shows up, the parser keeps both: `severity` for the header and
`ext.severity` for the extension. It never discards one silently.

> [!NOTE]
> **The second half of this assumption turned out to be unbuildable**, which makes it the most
> useful entry in this document. Vector's `parse_cef` returns a flat map and the header wins, so
> the extension value is discarded inside the parser before any of our code runs. Keeping both
> would mean writing our own CEF header splitter, which is the work Q-38 decided to delegate.
>
> The header half holds. The collision half is recorded as a known gap in D-09. Worth noting
> that no amount of analysis at this stage would have caught it: it needed the parser to be run.

### Q-10 Do you need deduplication, throttling, or storm handling?

**Why it matters.** "Filter" sometimes means "stop the same event from firing 40,000 times." That
feature needs state: time windows, counters, memory bounds, and cardinality limits. It's a
completely different engine from stateless field matching.

**Working assumption.** Out of scope for version 1, which does stateless matching only. The
architecture document flags this as the most likely version 2 feature, and the rule schema leaves
room for it.

### Q-11 Do you need time-based or maintenance-window rules?

**Why it matters.** "Suppress these events during the Sunday patch window" is a common real
requirement, and it needs a scheduler and a time zone policy.

**Working assumption.** Out of scope for version 1. Rules evaluate the same way at all times.

### Q-12 Does the proxy send to multiple destinations, or just one ELK receiver?

**Why it matters.** "Forward based on filter criteria" describes one destination, but the next
request is predictable: "also send severity 8 and above to PagerDuty." Multiple destinations turn
the rule action from a boolean into a target list and introduce partial failures.

**Working assumption.** One destination in version 1, but model the rule action as a **named
output** from day one. Then adding an output is config, not a rewrite.

## Transport and wire format

### Q-13 🔴 Does the outbound side have to stay UDP syslog?

**Why it matters.** This decides whether delivery guarantees are possible at all. UDP in and UDP
out means the proxy can never promise to keep every event, and you can't answer "did the proxy
drop it or did the network?" TCP or HTTP output lets you buffer, retry, and report loss precisely.

**Options.**

- UDP out, with no change to the ELK receiver.
- TCP syslog (RFC 6587).
- TLS syslog (RFC 5425).
- Straight to the Elasticsearch `_bulk` API or a Logstash HTTP input.

**Working assumption.** UDP out, so you can install the proxy without touching ELK. The output
sits behind an interface, so the other three are extra implementations rather than a redesign. The
architecture document recommends TLS syslog.

### Q-14 Which syslog format is on the wire, RFC 3164 or RFC 5424?

**Why it matters.** The CEF payload sits in the syslog message body, so the parser has to know
where the header ends. RFC 5424 has structured data and a version digit. RFC 3164 is an informal
format whose timestamp has no year and no time zone.

**Working assumption.** Accept both and detect automatically. If the text after the priority value
starts with `1 `, treat it as RFC 5424. Otherwise treat it as RFC 3164. If the packet starts with
`CEF:`, treat the whole datagram as CEF. A traffic capture (Q-08) settles this immediately.

### Q-15 Does the proxy keep the original syslog header or build a new one?

**Why it matters.** If the ELK pipeline reads the syslog timestamp, host name, or priority,
rebuilding the header changes what lands in the index. That's a subtle break, and you'd find it
late.

**Working assumption.** Keep the original bytes exactly. The proxy forwards the datagram it
received. Parsing informs the decision only, and the proxy never re-serializes. This also proves
the proxy changes no content.

### Q-16 🔴 Does anything downstream depend on the packet's source IP address?

**Why it matters.** Once the proxy is in place, every packet reaches ELK from the proxy's address.
If Logstash or Elasticsearch uses source IP for routing, tenancy, index selection, or attribution,
inserting the proxy breaks it. The symptom is distinctive: ELK suddenly attributes every event to
one host.

**Options.**

- Nothing depends on it, because `filterhostname` and `filteripaddress` carry the truth.
- Something does, so you need transparent proxying (`IP_TRANSPARENT`).
- Add an observed-source field and update the ELK pipeline.

**Working assumption.** Nothing depends on it, but verify this against the real Logstash config as
a pre-cutover check. It's cheap to verify and expensive to discover late.

### Q-17 What's the maximum event size, and does the source truncate?

**Why it matters.** Classic syslog over UDP caps at 1,024 bytes and many stacks truncate there. A
truncated CEF event won't parse and lands on the malformed path. Larger datagrams need a bigger
receive buffer.

**Working assumption.** Use a 64-KB receive buffer, which is the maximum UDP payload, and don't
assume 1,024. Count truncation-shaped parse failures separately from other parse failures so you
can tell the difference in production.

### Q-18 What happens to input the proxy can't parse?

**Why it matters.** A filter that can't parse an event can't decide about it. Dropping it loses a
security event silently. Forwarding it defeats the filter.

**Options.**

- Forward it unchanged, which is fail open.
- Drop it and count it.
- Route it to a dead-letter destination.

**Working assumption.** Forward it, count it, and log a rate-limited sample at WARN. This matches
Q-01. Unparseable input is far more often a parser bug than a bad event, and forwarding keeps the
failure visible instead of hiding it.

### Q-19 Does CEF escaping apply, and how strictly?

**Why it matters.** CEF escapes `\|` and `\\` in the header, and `\=`, `\\`, `\n`, and `\r` in
extension values. A parser that splits naively on `=` or `|` misreads any event with an `=` inside
a value. A `name` field containing a URL query string is a common trigger. A misparsed event
produces a wrong filter decision, which is worse than a crash because nothing surfaces it.

**Working assumption.** Use a parser that follows the spec and handles escaping, and keep a
conformance corpus that generates adversarial values and confirms the parser reads each one
correctly. Writing that parser in Python would be both slower and no more correct than reusing a
maintained one, so prefer reuse. See the research document for the evidence.

### Q-20 One detection source or several? Do you need IPv6?

**Why it matters.** Several sources might need different rule sets, and then you have to identify
each source from the packet source IP address, the syslog host name, or `filterhostname`. All
three can disagree.

**Working assumption.** Support several sources with one global rule chain in version 1. Rules can
match on source-identifying fields to get per-source behavior. Listen on both IPv4 and IPv6.

## Scale, performance, and availability

### Q-21 🔴 What are the sustained and peak event rates, and the latency budget?

**Why it matters.** This decides the concurrency model, whether a simple loop can evaluate rules,
and whether you need lock-free config swaps. 500 EPS and 500,000 EPS are different products. Peak
matters more than average, because an event storm is exactly when the proxy must not fail and
exactly when it's under the most load. It also helps to know the worst known burst, such as a
network scan.

Combined with the mandated Python backend, this question does more than size the system. It
decides which layers you can build at all. CPython can't do per-packet UDP work at tens of
thousands of events per second with sub-millisecond p99 latency, so whatever number lands here has
to be handled by something other than Python.

**Working assumption.** Target 20,000 EPS sustained and 100,000 EPS in a burst, adding less than
one millisecond at p99, on a single node. State it plainly so someone can contradict it. The
prototype ships a load harness that measures the real number.

### Q-22 How many rules, and how often do they change?

**Why it matters.** A linear scan handles 20 rules. 5,000 rules need indexing by field and
short-circuit evaluation. Change frequency decides whether hot reload is optional or required.

**Working assumption.** Around 100 rules, changing daily to weekly. Use a linear scan over a
compiled rule set, and benchmark the evaluation path so you know when it stops being adequate.

### Q-23 What happens when the ELK receiver is slow or unavailable?

**Why it matters.** With UDP output the proxy can't detect this at all and will transmit into a
black hole. With TCP or HTTP output you have to choose: buffer in memory up to a bound and then
drop, spill to disk and accept disk pressure, or apply backpressure. Backpressure is impossible
here, because UDP input has none. The kernel just discards packets.

**Working assumption.** Use a bounded in-memory queue with a documented depth, drop oldest first,
and raise a metric and an alert on any drop. Skip disk spooling in version 1 and revisit it with
Q-13.

### Q-24 Do you monitor kernel-level UDP buffer loss?

**Why it matters.** During a burst, packets are lost in the socket buffer before the application
ever sees them. Without exporting the `/proc/net/udp` drop counters and setting `SO_RCVBUF`
properly, the proxy reports zero events dropped while losing thousands. That's the most dangerous
class of bug this system can have.

**Working assumption.** Yes, it's in scope. Size `SO_RCVBUF` explicitly and publish a metric
sourced from the kernel counters, not just application counters. This is a headline item in the
observability design.

### Q-25 🔴 Do you need high availability, and how much downtime is acceptable?

**Why it matters.** The proxy becomes the only path for security events. UDP makes HA awkward
because there's no connection affinity. Your options are a load balancer that mustn't become the
new single point of failure, a floating IP address with VRRP or keepalived, anycast, or sending to
two proxies and accepting duplicates in ELK.

**Options.**

- One node, where a restart of a few minutes is acceptable.
- Active/passive with a virtual IP address.
- Active/active, with duplicates removed downstream.

**Working assumption.** One node for the prototype. The architecture document recommends
active/passive for production and notes that both nodes need identical configuration.

### Q-26 Where does this run: hardware, VM, container, Kubernetes, or a disconnected network?

**Why it matters.** It constrains base images and secret delivery. It decides whether you can use
`CAP_NET_BIND_SERVICE`, whether CI runners can reach the internet to scan dependencies, and how
config is mounted and reloaded.

**Working assumption.** Container images, with Docker Compose for the prototype and Kubernetes for
production, running as a non-root user with a read-only root file system. Assume the network isn't
disconnected from the internet. A disconnected network would change the DevSecOps answer
significantly, and it would also reopen Q-38, since it's one of the few conditions that makes a
third-party data plane binary unacceptable.

## Rule configuration and change management

### Q-27 Who writes rules: SOC analysts or platform engineers?

**Why it matters.** It decides whether the main interface is a YAML file in a pull request or a
guided UI with validation and pickers. It also decides how hard the UI has to work to prevent
dangerous mistakes, such as a rule that drops far more than intended.

**Working assumption.** SOC analysts, who aren't engineers. The UI is the main interface. It
validates each rule, previews the effect, and asks for confirmation when a rule would drop a large
share of traffic.

### Q-28 Do rules have to reload without dropping packets?

**Why it matters.** Restarting a UDP listener loses every packet in flight. If rules change
several times a day, restart-to-apply becomes a steady source of lost events.

**Working assumption.** Yes, hot reload is required. Compile rules off the hot path and swap them
atomically. Never close the listening socket.

### Q-29 Do rules need a dry run before they go live?

**Why it matters.** "What would this rule have done to yesterday's traffic?" is the single feature
that stops a bad rule from quietly discarding events. It's also much easier to build in from the
start than to add later.

**Working assumption.** In scope, and treated as a core feature rather than a nice-to-have. Offer
shadow mode globally and per rule, where the proxy evaluates, counts, and logs but forwards
everything. Also support offline replay against a captured sample.

### Q-30 🔴 Is the UI or Git the source of truth for rules?

**Why it matters.** If both can write, you need conflict resolution. In practice you get drift and
an argument during the next incident. Decide this rather than leaving it open.

**Options.**

- The UI is authoritative, a database stores the rules, and changes export for audit.
- Git is authoritative, and the UI is read-only with a "propose a change" action that opens a pull
  request.
- The UI writes a file that an operator commits, which guarantees drift.

**Working assumption.** The UI is authoritative, with an append-only change log and one-click
export and rollback. That matches the audience in Q-27. Git-first is the better answer if the
organization already runs GitOps, so confirm it, because it reshapes the backend.

### Q-31 What audit trail do rule changes need?

**Why it matters.** Changing a filter rule changes which security telemetry you keep, and most
compliance regimes treat that as an auditable action. You need the actor, the timestamp, the
before-and-after difference, and a log nobody can alter.

**Working assumption.** Record every change with actor, timestamp, and full difference in an
append-only log that ships off the box. Never hard-delete a rule. Disable it instead.

### Q-32 Do you need multi-tenancy?

**Why it matters.** Separate rule sets per team change the data model and the authorization model,
and both are painful to retrofit.

**Working assumption.** No. One tenant, one rule chain.

## User interface

### Q-33 What's the UI for, in priority order?

**Why it matters.** "UI with detailed logging" could mean a rule editor, a live event view, an
operational dashboard, or a search interface. Four features built poorly are worse than one built
well.

**Options.** Rule management, a live view of decisions, throughput and drop metrics, searchable
decision history, and rule simulation.

**Working assumption.** In order: rule management with validation, a live decision view, metrics
and health, then rule simulation. ELK already stores the long-term history, so the UI doesn't
duplicate it.

### Q-34 What authentication and authorization does the UI need?

**Why it matters.** A UI with no authentication that can drop security events is itself a control
failure. Single sign-on is also often a multi-week dependency on another team, so raise it early.

**Options.** OpenID Connect or SAML single sign-on, LDAP or Active Directory, local accounts,
mutual TLS, or no authentication with network isolation only.

**Working assumption.** Pluggable authentication with OpenID Connect as the production mode. The
prototype ships local accounts plus a clearly labeled development bypass that can't be enabled
when the app binds a non-loopback interface. Roles are `viewer`, `rule-editor`, and `admin`,
enforced on the server rather than in the browser.

### Q-35 Is the UI on a management network or generally reachable?

**Why it matters.** It affects TLS requirements, whether the admin API is exposed, and the threat
model.

**Working assumption.** A management network, with TLS still required. The admin API binds on a
separate listener from the data path, so compromising the UI doesn't let someone reconfigure
ingress.

### Q-36 Does the live view show event contents, and who can see them?

**Why it matters.** Event payloads can carry host names, user names, IP addresses, file paths, and
sometimes credentials in command lines. A live view is an exfiltration surface and may need the
same access controls as the SIEM.

**Working assumption.** `rule-editor` and `admin` see contents. `viewer` sees metadata and counts.
Field-level redaction is configurable and applied on the server, so the browser never receives
what the role can't see. Confirm whether events can contain personal or regulated data, and harden
further if they can.

### Q-37 How does the live view sample, and does it touch the data path?

**Why it matters.** Streaming 20,000 EPS to a browser isn't viable. A naive implementation also
lets a browser apply backpressure to the forwarding path, and a browser tab causing event loss is
unacceptable. With a Python backend there's a second reason to care: the backend can't absorb
event-rate traffic either, so sampling has to happen before the backend sees anything.

**Working assumption.** Sample at the node, not in the backend. The backend holds a bounded ring
buffer and pushes to browsers over WebSocket. The whole path is strictly non-blocking. If the
browser can't keep up, the browser drops frames. The proxy never does.

## Build or buy

### Q-38 🔴 Why build this instead of configuring an existing tool?

**Why it matters.** Vector, Cribl Stream, Logstash, syslog-ng, rsyslog, and Fluent Bit all already
ingest syslog over UDP and route conditionally. The task asks you to research the technology and
document the what and why, so an honest answer starts here. If a known constraint rules those
tools out, it should shape the design rather than surface during review.

**Likely reasons, all needing confirmation.** Analysts who aren't engineers need to edit rules in
a purpose-built UI. License cost or procurement friction blocks the commercial options. The
network is disconnected. Policy forbids a new heavyweight runtime on that host. Generic tools
don't record what they dropped. The organization standardized on one of these tools elsewhere and
doesn't want it here.

**Working assumption.** Build the control plane only, and delegate the data plane. The analyst UI
and per-drop auditability are the differentiators, and they're also the only parts the mandated
Python stack can deliver at the required rates. The architecture document includes a comparison
table and states plainly when "just use Vector" is the right answer. Recommending that you don't
build this is a legitimate outcome.

### Q-39 Are there mandated language, framework, or runtime standards?

> [!IMPORTANT]
> **Answered by the organization on July 30, 2026: Python for the backend, JavaScript and React
> for the frontend.** This is now an input, not an open question.

**Why it mattered.** A prototype in a language the team can't maintain is a dead prototype. But
the answer turned out to constrain more than maintainability. Every production-grade syslog
pipeline in the landscape is written in C, C++, Rust, Go, or the JVM, and none in Python. That
isn't a coincidence: per-packet UDP work at the Q-21 rates is close to the worst case for CPython,
between the global interpreter lock, per-object allocation, and garbage collection pauses landing
in the p99 budget.

**What it changes.** The layer split stops being a matter of taste. Python goes where Python is
strong, which is the API, the rule model, the compiler, and the web application. Event-rate work
goes to a data plane built for it. A from-scratch proxy is no longer a credible fallback, so the
fallback is now "build nothing and use config files."

**One open sub-question.** You specified JavaScript. The decision register picks TypeScript, since
it's a superset and the rule schema is complex enough to benefit. That's flagged in D-39 and it's
a one-word change if you'd rather stay with plain JavaScript.

## Security and DevSecOps

### Q-40 What's the threat model for the ingress port?

**Why it matters.** Syslog over UDP is unauthenticated and easy to spoof. An attacker who can
reach the port can inject fabricated events, flood the port to cause buffer loss that masks a real
attack, or craft events that match a broad drop rule and hide themselves. That last one is the
interesting case: the filter becomes a way to evade detection, and the design document should say
so.

**Options.** A network ACL only, a source IP allow-list in the proxy, per-source rate limiting, or
TLS syslog with client certificates, which requires changing the detection source.

**Working assumption.** The network ACL is the primary control. The proxy adds source IP
allow-listing and per-source rate limiting as defense in depth. Document them as defense in depth
rather than authentication, because spoofed UDP defeats an IP allow-list.

### Q-41 Do you need encryption in transit, and on which leg?

**Why it matters.** Event content is sensitive. The source-to-proxy leg may be fixed if the
detection source only speaks UDP. The proxy-to-ELK leg is yours to choose.

**Working assumption.** Plaintext UDP inbound, constrained by the source. TLS available and
recommended outbound. Record the residual risk and the compensating control, which is network
segmentation.

### Q-42 Which compliance regimes apply?

**Why it matters.** SOC 2, PCI DSS, HIPAA, and FedRAMP each impose requirements on audit logging,
retention, cryptography, and change control, and all of them are cheaper to design in than to
retrofit. PCI DSS has explicit requirements about not losing security event data.

**Working assumption.** SOC 2-style controls as a baseline: audit trail, access control, and
change management. Ask before assuming FIPS or FedRAMP. FIPS constrains which cryptography
libraries you can use, and it's more disruptive on a Python stack than on a compiled one.

### Q-43 What DevSecOps toolchain exists, and what's mandated?

**Why it matters.** The task asks for the preferred DevSecOps approach, but preferences that match
an existing organizational standard beat preferences in the abstract. You need the CI platform,
the mandated SAST, SCA, secret, and container scanners, the artifact registry, the signing and
SBOM policy, and whether CI runners have internet access.

**Working assumption.** Present a tool-agnostic pipeline: lint, type check, unit test, SAST, SCA,
build, SBOM, container scan, sign, integration and fuzz test, deploy. Give concrete examples for
the Python and JavaScript stack, and name a swappable equivalent for each stage.

### Q-44 Does the parser need fuzzing, and is a security review a release gate?

**Why it matters.** Whatever parses untrusted bytes from the network is the highest-risk code in
the system and the obvious target for a coverage-guided fuzzer.

**Working assumption.** Yes, but note where the risk actually sits. If you delegate parsing to a
mature data plane, the highest-risk code you own becomes the rule compiler, because it turns
analyst input into executable configuration. Fuzz that, keep a parser conformance corpus for the
delegated component, and gate production releases on a documented security review.

## Deliverables and agent tooling

### Q-45 🔴 What does "build a prototype with test generation" mean?

**Why it matters.** It's genuinely ambiguous, and the two readings produce different demos.

**Options.**

- A synthetic CEF event generator: a traffic and load tool that produces realistic and adversarial
  events.
- Tests written by an AI agent, demonstrating an agentic workflow.
- Both.

**Working assumption.** Both, since they complement each other and each is modest. Build a
`cefgen` traffic tool, and document an agent-driven workflow for writing and maintaining the test
suite. One condition matters: someone reviews every generated test. Generated tests are never
trusted unreviewed.

### Q-46 How complete does the prototype need to be?

**Why it matters.** "Prototype" ranges from a throwaway demo to the first commit of the real
product, and the difference is roughly five times the effort.

**Options.**

- Demo quality, illustrating the design.
- A production-track skeleton with real structure, tests, CI, and some features.
- A feature-complete version 1.

**Working assumption.** A production-track skeleton: a narrow but genuinely production-shaped
slice with a correct rule model, a working compiler, hot reload, metrics, a UI with rule
management and a live view, tests, and CI. List the non-goals rather than half-building features.

### Q-47 Who reads the documents, and in what form?

**Why it matters.** The task asks for ".md design files for human consumption, agent consumption
or a combination of both," which is itself a question about the audience.

**Options.** Narrative documents with diagrams, machine-readable specs an agent can implement
from, or both with links between them.

**Working assumption.** Both, cross-linked. For people: a readme, an architecture document,
decision records, and Mermaid diagrams, which GitHub renders without extra tooling. For agents: a
`CLAUDE.md` file, a machine-readable rule schema, and structured test fixtures. Generate the
schema from the same models the application validates against, so the agent-readable spec can't
drift from the implementation.

### Q-48 What evidence about agent tooling does the reviewer expect?

**Why it matters.** "Highlight what agentic tools are used and/or preferred" could mean a written
section, a demonstrated workflow, or a harness someone else can run.

**Options.** A section on tooling choices, commit-level evidence of AI-assisted development, or a
runnable agent workflow in the repository.

**Working assumption.** All three, lightly. Write a tooling section, set the repository up for
agent-assisted work with a `CLAUDE.md` file and task-scoped skills, and include honest notes on
where AI assistance worked and where it needed correcting. The rule compiler and the security
model are where it's least reliable.

### Q-49 What's the timebox, and what's being assessed?

**Why it matters.** It sets the balance between depth and breadth. If the assessment weights
architecture and DevSecOps thinking, keep the prototype narrow. If it weights working code,
tighten the documents.

**Working assumption.** Documentation and reasoning carry at least as much weight as code, which
is why this document exists. Scope the prototype to Q-46.

### Q-50 Is there a cutover expectation, or is this a new deployment?

**Why it matters.** Inserting the proxy into a live alerting path is the riskiest moment in this
system's life, and a design that ignores cutover is incomplete.

**Working assumption.** Include a cutover plan in the architecture document. Run the proxy in
shadow mode first, forwarding everything while evaluating rules and logging what it would have
dropped. Compare event counts against the pre-insertion baseline for an agreed soak period, then
enable enforcement. Document a single-step rollback: point the detection source back at ELK.

## Decision log

[decisions.md](decisions.md) now answers every question from Q-01 to Q-53 and supersedes the
working assumptions above. This document stays as the record of what was uncertain and why. The
10 highest-cost questions resolved this way:

| Q | Answer | Decision | Date | Effect on the design |
|---|---|---|---|---|
| Q-01 | Fail open, with a required `default_action` key | D-01 | 2026-07-30 | Also sets malformed-input behavior (D-18) |
| Q-02 | Metadata audit record for every drop, full retention per rule | D-02 | 2026-07-30 | Adds a `drop-audit` output and index |
| Q-05 | Ordered chain, first match wins | D-05 | 2026-07-30 | Fixes the rule schema and the VRL structure |
| Q-13 | UDP output in version 1, behind an interface | D-13 | 2026-07-30 | ELK needs no change. No disk spooling (D-23) |
| Q-16 | Assume no source IP dependency, and verify before cutover | D-16 | 2026-07-30 | Removes transparent proxying from scope |
| Q-21 | 20,000 EPS sustained, 100,000 burst, under 1 ms at p99 | D-21 | 2026-07-30 | Handled entirely by Vector. No event-rate traffic reaches Python. |
| Q-25 | Stateless nodes, one node in version 1, documented active/passive | D-25 | 2026-07-30 | HA becomes deployment config, not application code |
| Q-30 | The UI is the source of truth, with YAML export and rollback | D-30 | 2026-07-30 | SQLite through SQLAlchemy, plus an append-only change log |
| Q-38 | Build the control plane only (Option B) | D-00 | 2026-07-30 | The primary architecture decision, reinforced by the stack |
| Q-45 | Both `cefgen` and agent-assisted test generation | D-45 | 2026-07-30 | Two deliverables, both shipped complete |

**Q-53 is now answered.** The driver is analyst noise reduction plus ELK ingest load, confirmed on
July 30, 2026. Filtering therefore has to happen before the network hop, which is what justifies
building a proxy rather than writing a Logstash conditional. See D-53.

Four decisions still carry a flag (⚑) in the register. They're decided and being built against,
but they're business calls rather than engineering ones, so raise them first in review:

- **D-08.** What the field values mean.
- **D-39.** TypeScript instead of plain JavaScript, which is the one place the register deviates
  from the stated stack.
- **D-51.** Can the organization buy a commercial product?
- **D-52.** Which product emits these events?

## The three most useful answers

You can proceed without answers, but three would help more than the rest:

1. **A capture of a few thousand real events**, with sensitive data removed. It answers Q-04,
   Q-08, Q-09, Q-14, Q-17, and Q-19 at once, and it's worth more than any schema documentation.
2. **The peak rate in EPS** (Q-21). It now carries more weight than it did, because it's what
   rules a Python data plane in or out.
3. **A decision on fail open versus fail closed, and on whether drops must be recoverable**
   (Q-01 and Q-02). Those are policy calls, not engineering ones.

The working assumptions above cover everything else.
