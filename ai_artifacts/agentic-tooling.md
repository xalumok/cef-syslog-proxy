# Agentic tooling: what was used, what worked, what did not

**Status:** Complete · **Owner:** Yurii · **Date:** July 31, 2026
**Answers:** "Highlight what agentic tools are used and/or preferred" from [initial_task.md](../initial_task.md)
**Style:** Microsoft Writing Style Guide

## Summary

This project was built with Claude Code driving an agentic loop: read the task, research the
domain, write documents, write code, run it, and fix what broke. The interesting content of this
page is not the tool list. It is **where the agent was reliable and where it was not**, because
that determines where you put review effort.

The short version: the agent was strong at breadth, structure, and documentation, and weakest at
exactly the two places the design flags as highest risk. Every significant bug in this codebase
was found by running the software, not by reading it.

## Tools used

| Tool | Used for | Verdict |
|---|---|---|
| Claude Code | The whole loop: research, docs, code, test, debug | The web search phase changed the architecture. Worth more than the code generation. |
| Web search and fetch | Prior-art research, Vector and Logstash bug reports | Found the open `parse_cef` escaping bugs and the Logstash severity collision, which reshaped D-19 and D-09 |
| Hypothesis | Property-based fuzzing of the compiler | The right tool. Found the encoder bug described below. |
| Real Vector, run in a loop | Verifying generated VRL | Where every real bug surfaced |
| `mypy --strict` on the compiler | Narrowing the injection surface | Caught one genuine type-narrowing gap the tests missed |

## Where the agent was reliable

- **Breadth of research.** The prior-art survey covered six product tiers, found the telemetry
  pipeline category, and surfaced specific GitHub issues. Doing that by hand would have taken a
  day.
- **Structure and consistency.** Fifty-three decisions, cross-referenced across five documents,
  with IDs that stayed consistent through three rewrites and a stack change.
- **Boilerplate that follows a stated pattern.** The SQLAlchemy models, the FastAPI routes, and
  the React pages were largely right the first time.
- **Applying a decision consistently.** Once "the control plane is never in the data path" was
  written down, it propagated correctly into the sink buffer settings, the agent's failure
  handling, and the entrypoint's forward-everything fallback.

## Where the agent was not reliable

This is the section worth reading.

### It wrote confident, wrong VRL

The first compiled program had three separate errors: an unnecessary error coalescing operation,
variables assigned only inside `if` blocks and then referenced outside, and a fallible predicate
in a numeric comparison. All three looked plausible. None of them compile.

VRL is niche enough that the model's prior is weak, and it produces syntactically reasonable code
with the wrong semantics. **Anything generated in a niche configuration language needs to be run,
not reviewed.**

### It asserted an unverified claim in a design document

D-28 originally stated that Vector "rebuilds only changed components, so the UDP source stays
bound." That was a plausible inference presented as fact. It turned out to be *partly* true, and
only checking it revealed a version floor nobody had identified: reloading transforms that use
external VRL files needs Vector 0.51.0 or later.

The correction pattern that worked: ask "what did I assert but not verify?" and then verify it.
That question found the load-bearing assumption in a 250-line decision register.

### It wrote a security check that did not check anything

`glob_to_regex` originally emitted a literal `'` as the character class `[']`, with a confident
comment explaining that this prevented the quote from terminating the VRL raw string. It does
not. `[']` contains a quote and terminates the literal exactly as a bare quote would.

The bug was caught by a *different* defense: `encode_regex_literal` rejects any regex containing
a quote. Defense in depth worked, and the reasoning behind the first layer was simply wrong.

**The lesson: a confident comment explaining why something is safe is not evidence that it is.**

### It wrote tests that passed for the wrong reason

Four test failures in this build were bugs in the tests, not the code:

- A property asserting `value not in output`, which is trivially false when the value is `"`.
- An `else if` count that included the enforcement block.
- Two tests parsing TOML by string-splitting rather than with `tomllib`.

Each looked reasonable. The instinct to "fix the code until the test passes" would have made the
code worse in at least one case.

## The workflow that actually worked

1. **Research before deciding.** The web search phase changed the architecture from "build a
   proxy" to "build a control plane." That was the highest-value hour in the project.
2. **Write the decisions down with IDs before writing code.** Every module docstring cites the
   decision it implements. When the stack changed from Go to Python, the decision register made
   the blast radius obvious.
3. **Build the riskiest thing first and run it immediately.** The encoder and compiler came
   before the API, the UI, and the deployment. Three of the four significant bugs were in them.
4. **Fix the code, not the test, until you have established which is wrong.** Two of the bugs
   here were real code bugs found by tests; four were test bugs found by code.
5. **Run the real dependency.** Every VRL bug was invisible until Vector ran. `vector validate`
   passing was actively misleading.

## Making this repository agent-friendly

Choices made so another agent can pick this up cold:

- **[`CLAUDE.md`](../CLAUDE.md)** states the invariants that must not be broken, the commands to
  run, and where the risk is concentrated.
- **Decision IDs in docstrings.** Reading `compiler.py` tells you which decision each choice
  implements, so a change can be traced to the reasoning behind it.
- **A machine-readable schema.** Pydantic generates JSON Schema at `/openapi.json`, so the
  agent-readable spec cannot drift from the implementation. That was a real benefit of the Python
  stack, not a consolation.
- **Tests that state intent.** `test_message_is_never_mutated` and
  `test_forwarded_bytes_are_identical` name the property, so an agent that breaks D-15 gets told
  what it broke rather than a diff.
- **Comments explaining why, not what.** `?? false` has four lines above it explaining that VRL
  rejects fallible predicates. Without that, the next agent removes it as redundant.

## Recommendations

**Use agents for:** prior-art research, documentation structure, boilerplate that follows a
stated pattern, test scaffolding, and applying a decision consistently across many files.

**Do not trust agents for, without running the code:** configuration languages, security
boundary reasoning, and any claim about third-party behavior that has not been executed.

**The rule that would have prevented every bug in this build:** if a generated artifact is
consumed by another program (VRL by Vector, TOML by Vector, SQL by SQLite), run that program
before believing the artifact is correct. Reading it is not enough, and neither is a validator
that turns out to check something else.
