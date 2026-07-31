"""Compile a rule chain into VRL.

The generated program never mutates ``.message`` (D-15). It parses into a scratch variable,
decides, and writes its verdict under ``.ss``. The socket sink then emits ``.message``
unchanged, so ELK receives byte-identical input.

Evaluation order mirrors the rule chain exactly: first match wins (D-05).

Both wire formats are matchable (D-14). CEF fields sit at the top of the scratch variable and
syslog fields nest under ``syslog``, so ``severity`` and ``syslog.severity`` stay distinct
despite meaning different things on different scales.
"""

from __future__ import annotations

from sixthsense.compiler.encoder import (
    EncodeError,
    encode,
    encode_comment,
    encode_path,
    encode_regex_literal,
    encode_string,
    glob_to_regex,
)
from sixthsense.models.rule import (
    Condition,
    Operator,
    Rule,
    RuleChain,
)

INDENT = "    "


class CompileError(ValueError):
    """The chain could not be compiled."""


def _value_expr(field: str) -> str:
    """VRL expression yielding the field's value, or null when absent.

    Always parenthesized. ``??`` binds loosely, so an unparenthesized coalesce next to a
    comparison parses as ``x ?? (null != null)`` rather than ``(x ?? null) != null``.
    """
    return f"(get(ev, {encode_path(field)}) ?? null)"


def _text_expr(field: str) -> str:
    """Parenthesized VRL expression yielding the field as a string, empty when absent."""
    return f'(to_string({_value_expr(field)}) ?? "")'


def _number_expr(field: str) -> str:
    """Parenthesized VRL expression yielding the field as a float, null when not numeric."""
    return f"(to_float({_value_expr(field)}) ?? null)"


def _string_operand(field: str, *, case_sensitive: bool) -> str:
    expr = _text_expr(field)
    if not case_sensitive:
        expr = f"downcase({expr})"
    return expr


def _literal_operand(value: object, *, case_sensitive: bool) -> str:
    # Fold the case conversion at compile time. Emitting downcase("Foo") would be correct but
    # it puts noise in the config that operators read during incidents.
    if not case_sensitive and isinstance(value, str):
        return encode(value.lower())
    return encode(value)


def compile_condition(cond: Condition) -> str:
    """Compile one condition into a boolean VRL expression.

    Every user-controlled value in the output has passed through the encoder.
    """
    op = cond.operator
    field = cond.field
    ci = cond.case_sensitive

    if op is Operator.EXISTS:
        return f"({_value_expr(field)} != null)"
    if op is Operator.NOT_EXISTS:
        return f"({_value_expr(field)} == null)"

    if op in (Operator.EQ, Operator.NE):
        if isinstance(cond.value, str):
            left = _string_operand(field, case_sensitive=ci)
            right = _literal_operand(cond.value, case_sensitive=ci)
        else:
            left = _value_expr(field)
            right = encode(cond.value)
        sign = "==" if op is Operator.EQ else "!="
        return f"({left} {sign} {right})"

    if op in (Operator.IN, Operator.NOT_IN):
        if not isinstance(cond.value, list):
            raise CompileError(f"operator '{op}' requires a list")
        all_strings = all(isinstance(v, str) for v in cond.value)
        if all_strings:
            left = _string_operand(field, case_sensitive=ci)
            items = [_literal_operand(v, case_sensitive=ci) for v in cond.value]
            right = "[" + ", ".join(items) + "]"
        else:
            left = _value_expr(field)
            right = encode(cond.value)
        expr = f"includes({right}, {left})"
        return f"({expr})" if op is Operator.IN else f"(!{expr})"

    if op in (Operator.CONTAINS, Operator.STARTS_WITH, Operator.ENDS_WITH):
        if not isinstance(cond.value, str):
            raise CompileError(f"operator '{op}' requires a string")
        left = _text_expr(field)
        needle = encode_string(cond.value)
        fn = {
            Operator.CONTAINS: "contains",
            Operator.STARTS_WITH: "starts_with",
            Operator.ENDS_WITH: "ends_with",
        }[op]
        return f"({fn}({left}, {needle}, case_sensitive: {'true' if ci else 'false'}))"

    if op is Operator.GLOB:
        if not isinstance(cond.value, str):
            raise CompileError("operator 'glob' requires a string")
        regex = glob_to_regex(cond.value, case_insensitive=not ci)
        left = _text_expr(field)
        return f"(match({left}, {encode_regex_literal(regex)}))"

    if op is Operator.CIDR:
        if not isinstance(cond.value, str):
            raise CompileError("operator 'cidr' requires a string")
        left = _text_expr(field)
        return f"(ip_cidr_contains({encode_string(cond.value)}, {left}) ?? false)"

    if op in (Operator.LT, Operator.LTE, Operator.GT, Operator.GTE):
        # Narrow positively rather than excluding str and None. The model validator already
        # rejects the other shapes, but the compiler must not depend on that: it is the last
        # thing standing between a rule and executable configuration.
        if isinstance(cond.value, bool) or not isinstance(cond.value, int | float):
            raise CompileError(f"operator '{op}' requires a number")
        # Coerce the field to a float so "7" and 7 compare the same way.
        #
        # The trailing `?? false` is required, not defensive. Comparing null against a
        # number is a runtime error in VRL, and VRL rejects a fallible predicate at compile
        # time. An `x != null &&` guard does not help: the type checker cannot narrow
        # through it. So the comparison is allowed to fail and the failure means "no match",
        # which is the semantics we want for a missing or non-numeric field.
        left = _number_expr(field)
        sign = {
            Operator.LT: "<",
            Operator.LTE: "<=",
            Operator.GT: ">",
            Operator.GTE: ">=",
        }[op]
        right = encode(float(cond.value))
        return f"(({left} {sign} {right}) ?? false)"

    raise CompileError(f"unsupported operator: {op}")


def compile_rule_predicate(rule: Rule) -> str:
    """Compile a rule's conditions into a single boolean expression (AND across all)."""
    if not rule.conditions:
        raise CompileError(f"rule {rule.id} has no conditions")
    parts = [compile_condition(c) for c in rule.conditions]
    return " && ".join(parts)


_PRELUDE = """\
# Generated by sixthsense. Do not edit by hand.
# Any change here is overwritten on the next bundle publish.

raw = to_string(.message) ?? ""

# Every variable is initialized before the branches below. VRL scopes assignments to the
# block they appear in, so a variable first assigned inside an if is undefined afterwards.
ev = {}
parse_ok = false
syslog_ok = false
cef_ok = false
body = raw
decision = "forward"
reason = "default"

parsed, perr = parse_syslog(raw)
if perr == null {
    syslog_ok = true
    body = to_string(get(parsed, ["message"]) ?? raw) ?? raw
}

cef, cerr = parse_cef(body)

# Fall back to locating the CEF marker in the raw datagram.
#
# This is not defensive coding, it is the common case. `parse_syslog` treats "CEF:" as the
# syslog tag and strips it, so the message body it hands back starts at "0|Vendor|..." and
# is no longer valid CEF. Parsing from the marker in the original bytes recovers it.
if cerr != null {
    marker = find(raw, "CEF:")
    # The `marker != null` guard is load-bearing. `find` is typed as returning an integer but
    # returns null at runtime when the needle is absent, so `marker >= 0` compiles as an
    # infallible integer comparison and then fails at runtime on every non-CEF event. The
    # program aborts here, before any rule branch, and `.ss` is never assigned.
    #
    # `(marker >= 0) ?? false` does not work: VRL rejects it with E651, because the type
    # checker believes the comparison cannot fail. Short-circuiting is the only form that
    # both compiles and guards, so do not simplify this back.
    if marker != null && marker >= 0 {
        cef, cerr = parse_cef(slice!(raw, marker))
    }
}

if cerr == null {
    ev = cef
    cef_ok = true
}

# D-07: field names match case-insensitively, so normalize once here rather than at every
# comparison site.
ev = map_keys(ev) -> |k| { downcase(k) }

# Syslog fields live in their own namespace rather than merged flat (D-14).
#
# Merging them would put two different things under one name. `severity` is a CEF header
# integer from 0 to 10 where higher is worse, and a syslog severity word like "info" or
# "err". One rule cannot mean both, and a flat merge silently picks whichever parser ran
# last. Nesting makes `severity` and `syslog.severity` two fields an analyst can tell apart.
#
# CEF fields deliberately stay at the top level. All ten of the known field names are CEF
# extension keys, so moving them would break every existing rule.
#
# map_keys is not recursive, so this subtree is downcased on the way in.
if syslog_ok {
    ev = set!(ev, ["syslog"], map_keys(parsed) -> |k| { downcase(k) })
}

# D-18 means "neither parser could read it", not "it was not CEF". A plain syslog line is
# parsed input and its rules must be enforced.
parse_ok = syslog_ok || cef_ok

matched_id = null
matched_version = null
matched_action = null
matched_shadow = false
matched_retain = false
"""


#: Summary fields carried on every decision, for the drop audit and the live view.
#:
#: Each one reads the CEF field first and falls back to the syslog equivalent, so a syslog
#: drop still names a host. Without the fallback the audit record for a syslog event is blank
#: in every column that matters, which undercuts D-02's "prove what was discarded".
#:
#: The fallback is an explicit emptiness check rather than a `??` chain. `??` coalesces
#: errors, not nulls, and `get` on a missing key returns null rather than failing, so
#: `get(a) ?? get(b)` yields null instead of trying b.
_METADATA: tuple[str, ...] = (
    'ss_event_id = to_string(get(ev, ["eventid"]) ?? "") ?? ""',
    'if ss_event_id == "" { ss_event_id = to_string(get(ev, ["syslog", "msgid"]) ?? "") ?? "" }',
    'ss_severity = to_string(get(ev, ["severity"]) ?? "") ?? ""',
    'if ss_severity == "" { ss_severity = to_string(get(ev, ["syslog", "severity"]) ?? "") ?? "" }',
    'ss_host = to_string(get(ev, ["filterhostname"]) ?? "") ?? ""',
    'if ss_host == "" { ss_host = to_string(get(ev, ["syslog", "hostname"]) ?? "") ?? "" }',
    'ss_name = to_string(get(ev, ["name"]) ?? "") ?? ""',
    'if ss_name == "" { ss_name = to_string(get(ev, ["syslog", "appname"]) ?? "") ?? "" }',
)


def _emit_rule_branch(rule: Rule, first: bool) -> list[str]:
    keyword = "if" if first else "} else if"
    lines: list[str] = []
    if rule.description:
        lines.append(encode_comment(f"{rule.id}: {rule.description}"))
    else:
        lines.append(encode_comment(f"{rule.id}: {rule.name}"))
    lines.append(f"{keyword} {compile_rule_predicate(rule)} {{")
    lines.append(f"{INDENT}matched_id = {encode_string(rule.id)}")
    lines.append(f"{INDENT}matched_version = {encode(rule.version)}")
    lines.append(f"{INDENT}matched_action = {encode_string(rule.action.value)}")
    lines.append(f"{INDENT}matched_shadow = {'true' if rule.shadow else 'false'}")
    lines.append(f"{INDENT}matched_retain = {'true' if rule.retain_payload else 'false'}")
    return lines


def compile_chain(chain: RuleChain, *, chain_version: int = 0) -> str:
    """Compile a whole chain into a VRL program.

    Returns VRL that sets ``.ss`` on every event. ``.message`` is left untouched.
    """
    active = chain.active()

    lines: list[str] = [_PRELUDE]

    if active:
        for index, rule in enumerate(active):
            lines.extend(_emit_rule_branch(rule, first=index == 0))
        lines.append("}")
    lines.append("")

    # Enforcement. Kept separate from matching so shadow mode cannot change which rule the
    # audit trail reports (D-29).
    default_action = encode_string(chain.default_action.value)
    chain_shadow = "true" if chain.shadow_mode else "false"

    lines.append("shadow_chain = " + chain_shadow)
    lines.append("")
    lines.append("if !parse_ok {")
    lines.append(f"{INDENT}# D-18: unparseable input is forwarded, counted, and sampled.")
    lines.append(f'{INDENT}decision = "forward_parse_error"')
    lines.append(f'{INDENT}reason = "parse_error"')
    lines.append("} else if matched_id == null {")
    lines.append(f"{INDENT}# D-01: no rule matched, so the chain default applies.")
    lines.append(f"{INDENT}decision = {default_action}")
    lines.append(f'{INDENT}reason = "default"')
    lines.append("} else if matched_shadow || shadow_chain {")
    lines.append(f"{INDENT}# D-29: record the match, enforce nothing.")
    lines.append(f'{INDENT}decision = "forward"')
    lines.append(f'{INDENT}reason = "shadow"')
    lines.append("} else {")
    lines.append(f"{INDENT}decision = matched_action")
    lines.append(f'{INDENT}reason = "rule"')
    lines.append("}")
    lines.append("")
    lines.extend(_METADATA)
    lines.append("")
    lines.append(".ss = {")
    lines.append(f'{INDENT}"chain_version": {encode(chain_version)},')
    lines.append(f'{INDENT}"decision": decision,')
    lines.append(f'{INDENT}"reason": reason,')
    lines.append(f'{INDENT}"rule_id": matched_id,')
    lines.append(f'{INDENT}"rule_version": matched_version,')
    lines.append(f'{INDENT}"retain": matched_retain,')
    lines.append(f'{INDENT}"parse_ok": parse_ok,')
    lines.append(f'{INDENT}"cef_ok": cef_ok,')
    lines.append(f'{INDENT}"syslog_ok": syslog_ok,')
    lines.append(f'{INDENT}"ts": to_string(now()),')
    lines.append(f'{INDENT}"event_id": ss_event_id,')
    lines.append(f'{INDENT}"severity": ss_severity,')
    lines.append(f'{INDENT}"host": ss_host,')
    lines.append(f'{INDENT}"name": ss_name,')
    lines.append("}")

    return "\n".join(lines) + "\n"


def compile_or_raise(chain: RuleChain, *, chain_version: int = 0) -> str:
    """Compile, converting encoder failures into :class:`CompileError`."""
    try:
        return compile_chain(chain, chain_version=chain_version)
    except EncodeError as exc:
        raise CompileError(f"encoding failed: {exc}") from exc
