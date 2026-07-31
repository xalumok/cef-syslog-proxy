# Working in this repository

Guidance for agents and for anyone picking this up cold. Read
[ai_artifacts/architecture.md](ai_artifacts/architecture.md) for the full picture.

## What this is

A control plane for a CEF and syslog filtering proxy. Python and React compile analyst-authored
rules into Vector configuration. **Vector is the data plane. Python never touches event-rate
traffic.**

## Invariants that must not break

Each one has a test. If you break one, a test will tell you which.

1. **`.message` is never mutated.** Parsing goes into a scratch variable `ev`. The socket sink
   emits the original bytes, so ELK receives byte-identical input. `test_forwarded_bytes_are_identical`
2. **Fail open everywhere.** No rule match, parse failure, or route miss forwards the event.
   `test_unparseable_input_is_forwarded`
   Forwarding is necessary but not sufficient: an event has to be *labelled* correctly too, or a
   program that crashed looks exactly like one that decided. `TestDecisionLabels`
3. **Every event shape reaches a decision.** CEF, bare CEF, RFC 3164, RFC 5424, and garbage all
   run the chain to completion. `TestSyslogFiltering`, `test_a_runtime_abort_is_caught`
4. **No event-rate traffic in Python.** Vector samples at the node. Any change routing events
   through the control plane is a design regression. `test_tail_sink_drops_rather_than_blocks`
5. **The control plane is never in the data path.** Nodes run from cached config when it is
   unreachable. `test_control_plane_being_down_does_not_stop_forwarding`
6. **No user value is ever interpolated into VRL.** Everything goes through
   `compiler/encoder.py`. `test_user_values_cannot_change_code_structure`
7. **Rules are never hard deleted, and the audit log is append-only.**
   `test_delete_disables_and_never_removes`, `test_audit_has_no_write_endpoint`
8. **Authorization is enforced server-side**, in FastAPI dependencies, never in React.
   `TestRoleEnforcement`

## Where the risk is

`src/sixthsense/compiler/` is the highest-risk code in the project. It turns web-form input into
executable configuration for the data plane. It gets `mypy --strict`, Hypothesis fuzzing, and
review attention out of proportion to its size.

Rules for editing it:

- Never use f-strings, `%`, `.format()`, or `+` on user data to build VRL.
- Every value goes through `encode()`, `encode_string()`, `encode_path()`, or
  `encode_regex_literal()`.
- Any change needs a Hypothesis case in `tests/test_compiler_properties.py`.
- Run `make e2e` after any compiler change. Unit tests do not catch invalid VRL.
- A dot in a field name is a path separator, so `syslog.appname` is two segments. A dot in a
  *value* is an ordinary character. Only `encode_path` splits.
- If you touch `_PRELUDE`, extend the probe corpus in `compiler/validate.py` to cover any new
  branch. The corpus is the only thing that catches a branch which aborts at runtime.

## Commands

```bash
make setup      # venv, Python deps, npm install
make vector     # download pinned Vector into .tools/
make check      # lint, types, unit and property tests
make e2e        # end-to-end against real Vector
make compile    # print the Vector config the current rules produce
```

## Facts about Vector that cost debugging time

Verified against 0.51.0. Do not re-derive these.

- **`vector validate` does not compile VRL.** It checks config structure only. A program with an
  undefined variable passes it and then fails at startup. Use `vector vrl -p <program> -i <event>`,
  which exits 70 on a compile error. Both run in `compiler/validate.py`.
- **`vector vrl` exits 0 on a *runtime* error.** It prints the message on that event's output line
  and moves on, so an exit-code check reports success for a program that aborts on every non-CEF
  event. The gate runs a probe corpus and requires one well-formed JSON event out per event in.
- **VRL scopes assignments to their block.** A variable first assigned inside an `if` is undefined
  afterward. Initialize everything before branching.
- **`find` is typed `integer` but returns `null` when the needle is absent.** So `marker >= 0`
  compiles as an infallible integer comparison and then fails at runtime. This one is worse than
  the others, because the type checker is actively misleading rather than merely strict.
- **Two null guards. Which one you need depends on what the checker believes**, and they look
  contradictory until you see that:
  - The checker *knows* it is fallible, as with `to_float(x) ?? null` compared against a number.
    VRL rejects the fallible predicate at compile time. Coalesce with `?? false`. An
    `x != null &&` guard does not help, because the type checker cannot narrow through it.
  - The checker *wrongly believes* it is infallible, as with `find`. Here `?? false` is rejected
    as an "unnecessary error coalescing operation" (E651), and `x != null && ...` is the only
    form that both compiles and guards.
- **`parse_syslog` consumes `CEF:` as the syslog tag**, so the message body it returns starts at
  `0|Vendor|...` and is not valid CEF. The compiler falls back to finding `CEF:` in the raw bytes.
  Without this, every rule silently stops matching while events keep flowing.
- **`parse_cef` returns a flat map and the header wins.** Given a colliding extension key, the
  extension value is gone before your code runs, so D-09's `ext.severity` cannot be implemented on
  top of it. Verified: `name=EXT_NAME severity=EXT_SEV` alongside header `HEADER_NAME|9` yields
  only the header values.
- **`??` coalesces errors, not nulls.** `get` on a missing key returns null rather than failing,
  so `get(a) ?? get(b)` yields null instead of trying `b`. Fall back with an explicit check.
- **`exclude` on the `sample` transform means "bypass sampling", not "discard".** Matching events
  always pass through. Adding a second `filter` for the same condition double-counts them.
- **`?? ` on an infallible expression is an error**, not a no-op. Do not add it defensively.
- **Vector 0.51.0 is the floor.** Earlier versions do not reload transforms that reference
  external VRL files on SIGHUP, which D-28 depends on.

## Conventions

- Prose follows the Microsoft Writing Style Guide: sentence-case headings, US English, second
  person, contractions fine, serial comma.
- Cite decision IDs (D-01, D-44) in docstrings and comments. The register is
  [ai_artifacts/decisions.md](ai_artifacts/decisions.md).
- Comments explain why, not what. The `?? false` in the numeric comparison has four lines above it
  because without them the next reader deletes it.
- Do not add a feature partly. Non-goals are listed explicitly in the decision register.
