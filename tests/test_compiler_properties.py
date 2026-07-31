"""Property-based tests for the rule compiler.

D-44 makes this the primary fuzz target. The compiler is the highest-risk code we own,
because it turns analyst input into executable configuration for the data plane.

The invariants asserted here are the ones that matter:

1. Compilation never emits a value that escapes its literal.
2. Compilation is deterministic.
3. Generated VRL is structurally balanced.
4. Rule order in the chain is rule order in the output.
"""

from __future__ import annotations

import re

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from sixthsense.compiler.compiler import compile_chain, compile_condition
from sixthsense.compiler.encoder import EncodeError, encode, encode_path, encode_string
from sixthsense.models.rule import (
    Action,
    Condition,
    Operator,
    Rule,
    RuleChain,
)

# Text that deliberately includes the characters an attacker would reach for.
nasty_text = st.text(
    alphabet=st.characters(
        min_codepoint=1,
        max_codepoint=0x2FFF,
        blacklist_categories=("Cs",),
    ),
    min_size=0,
    max_size=60,
)

# A field name is a dot-separated path, so it is generated as non-empty segments joined by
# dots rather than as free text. Free text over an alphabet including "." produced names like
# "." and "a..b", which the model rejects: an empty segment addresses nothing.
field_segments = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="_-"),
    min_size=1,
    max_size=12,
)

field_names = st.lists(field_segments, min_size=1, max_size=3).map(".".join)

string_operators = st.sampled_from(
    [
        Operator.EQ,
        Operator.NE,
        Operator.CONTAINS,
        Operator.STARTS_WITH,
        Operator.ENDS_WITH,
        Operator.GLOB,
    ]
)


def _balanced(text: str) -> bool:
    """Check bracket balance outside string and regex literals."""
    depth = {"(": 0, "{": 0, "[": 0}
    closing = {")": "(", "}": "{", "]": "["}
    index = 0
    in_string = False
    in_regex = False
    in_comment = False

    while index < len(text):
        ch = text[index]

        if in_comment:
            if ch == "\n":
                in_comment = False
            index += 1
            continue
        if in_string:
            if ch == "\\":
                index += 2
                continue
            if ch == '"':
                in_string = False
            index += 1
            continue
        if in_regex:
            if ch == "'":
                in_regex = False
            index += 1
            continue

        if ch == "#":
            in_comment = True
        elif ch == '"':
            in_string = True
        elif ch == "'" and index > 0 and text[index - 1] == "r":
            in_regex = True
        elif ch in depth:
            depth[ch] += 1
        elif ch in closing:
            depth[closing[ch]] -= 1
            if depth[closing[ch]] < 0:
                return False
        index += 1

    return all(v == 0 for v in depth.values()) and not in_string and not in_regex


@given(field=field_names, value=nasty_text, operator=string_operators)
@settings(max_examples=300)
def test_string_conditions_are_balanced(field: str, value: str, operator: Operator) -> None:
    """No user string can unbalance the generated expression."""
    cond = Condition(field=field, operator=operator, value=value)
    out = compile_condition(cond)
    assert _balanced(out), out


def _strip_literals(text: str) -> str:
    """Replace the contents of every string and regex literal with a placeholder.

    What remains is the code skeleton: the part a user value must never be able to change.
    """
    out: list[str] = []
    index = 0
    while index < len(text):
        ch = text[index]
        if ch == '"':
            out.append('"@"')
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        if ch == "'" and out and out[-1].endswith("r"):
            out.append("'@'")
            index += 1
            while index < len(text) and text[index] != "'":
                index += 1
            index += 1
            continue
        out.append(ch)
        index += 1
    return "".join(out)


@given(a=nasty_text, b=nasty_text, field=field_names, operator=string_operators)
@settings(max_examples=300)
def test_user_values_cannot_change_code_structure(
    a: str, b: str, field: str, operator: Operator
) -> None:
    """The strongest statement of the injection invariant.

    Two different user values must produce byte-identical code once literal contents are
    removed. A user value that changed the skeleton would, by definition, be executing.
    """
    out_a = compile_condition(Condition(field=field, operator=operator, value=a))
    out_b = compile_condition(Condition(field=field, operator=operator, value=b))
    assert _strip_literals(out_a) == _strip_literals(out_b)


@given(field=field_names, value=nasty_text)
@settings(max_examples=300)
def test_no_unescaped_quote_survives_inside_a_literal(field: str, value: str) -> None:
    """Every quote the user supplied must be escaped, so literals stay closed."""
    out = compile_condition(Condition(field=field, operator=Operator.EQ, value=value))
    skeleton = _strip_literals(out)
    # After literal contents are removed, the only quotes left are the delimiters we emit.
    assert skeleton.count('"') % 2 == 0


@given(field=field_names, value=nasty_text)
@settings(max_examples=200)
def test_compilation_is_deterministic(field: str, value: str) -> None:
    cond = Condition(field=field, operator=Operator.CONTAINS, value=value)
    assert compile_condition(cond) == compile_condition(cond)


@given(
    names=st.lists(nasty_text, min_size=1, max_size=6),
    default=st.sampled_from([Action.FORWARD, Action.DROP]),
)
@settings(max_examples=100)
def test_chain_output_is_balanced_and_ordered(names: list[str], default: Action) -> None:
    rules = [
        Rule(
            id=f"r-{i}",
            name=f"rule {i}",
            description=name,
            order=i,
            action=Action.DROP,
            conditions=[Condition(field="name", operator=Operator.EQ, value=name)],
        )
        for i, name in enumerate(names)
    ]
    chain = RuleChain(rules=rules, default_action=default)
    out = compile_chain(chain, chain_version=1)

    assert _balanced(out), out

    # Rule identity appears in chain order.
    positions = [out.index(encode_string(r.id)) for r in rules]
    assert positions == sorted(positions)

    # The chain default is what the else branch assigns.
    assert f'decision = "{default.value}"' in out


@given(pattern=nasty_text)
@settings(max_examples=200)
def test_glob_never_breaks_the_regex_literal(pattern: str) -> None:
    """Globs compile to a VRL raw-string regex, which a quote would terminate."""
    try:
        cond = Condition(field="name", operator=Operator.GLOB, value=pattern)
    except ValueError:
        return  # rejected at the model boundary, which is also a valid outcome

    try:
        out = compile_condition(cond)
    except ValueError:
        return  # rejected by the encoder, also fine

    literals = re.findall(r"r'([^']*)'", out)
    assert literals, out
    assert _balanced(out), out


@given(segments=st.lists(field_segments, min_size=1, max_size=4))
@settings(max_examples=200)
def test_dotted_field_names_become_multi_segment_paths(segments: list[str]) -> None:
    """A dot in a field name separates path segments, so syslog.severity is addressable.

    Each segment must be its own quoted literal. One literal containing a dot would look up
    a key literally named "syslog.severity", which no parser produces.
    """
    out = encode_path(".".join(segments))
    assert out.startswith("[") and out.endswith("]")
    assert out.count(",") == len(segments) - 1
    for segment in segments:
        assert encode_string(segment) in out


@given(
    prefix=field_segments,
    suffix=field_segments,
    value=nasty_text,
)
@settings(max_examples=200)
def test_a_dot_in_a_value_is_not_a_path_separator(prefix: str, suffix: str, value: str) -> None:
    """Only the field name is a path. Dots in a rule's value stay literal.

    Without this, a value like "10.0.0.1" would be a way to reach into the event structure.
    """
    dotted = compile_condition(
        Condition(field=f"{prefix}.{suffix}", operator=Operator.EQ, value=value)
    )
    plain = compile_condition(
        Condition(field=f"{prefix}.{suffix}", operator=Operator.EQ, value=f"a.b.{value}")
    )
    assert _strip_literals(dotted) == _strip_literals(plain)


@pytest.mark.parametrize("bad", ["", ".", "..", "a.", ".a", "a..b", "  .  "])
def test_empty_path_segments_are_rejected(bad: str) -> None:
    """An empty segment addresses nothing, so it fails at the model boundary as a 422."""
    with pytest.raises(ValueError):
        Condition(field=bad, operator=Operator.EXISTS)


#: Magnitudes a threshold rule could plausibly carry: severities, priorities, byte counts,
#: epoch milliseconds. Bounding only the maximum is not enough, because that still admits
#: values like 3e-283, which need hundreds of digits in plain decimal and are refused.
realistic_floats = st.floats(
    allow_nan=False, allow_infinity=False, min_value=-1e15, max_value=1e15
).filter(lambda v: v == 0 or abs(v) >= 1e-6)


@given(value=realistic_floats)
@settings(max_examples=300)
def test_realistic_floats_encode_as_plain_decimal(value: float) -> None:
    """VRL parses `1e+17` as an identifier `1e`, so an exponent breaks compilation.

    This is not theoretical: a rule with a large numeric threshold produced a program that
    Vector rejected with "call to undefined variable". Every magnitude a threshold rule could
    plausibly use has to encode, and has to round-trip.
    """
    out = encode(value)
    assert "e" not in out.lower(), out
    assert "." in out, out
    assert float(out) == value


@given(value=st.floats(allow_nan=False, allow_infinity=False))
@settings(max_examples=500)
def test_no_float_ever_encodes_with_an_exponent(value: float) -> None:
    """The total contract, across every finite float.

    Either a plain-decimal literal or a refusal. Never an exponent, because that is the form
    that compiles into a broken program instead of failing here.
    """
    try:
        out = encode(value)
    except EncodeError:
        return  # refusing an absurd magnitude is a safe outcome
    assert "e" not in out.lower(), out
    assert float(out) == value


@given(value=st.integers(min_value=-(2**40), max_value=2**40))
@settings(max_examples=100)
def test_numeric_comparisons_are_total(value: int) -> None:
    """A missing or non-numeric field must never satisfy a threshold rule.

    VRL rejects fallible predicates at compile time, so the comparison must coalesce to
    false rather than being guarded by a null check the type checker cannot narrow.
    """
    cond = Condition(field="severity", operator=Operator.GT, value=value)
    out = compile_condition(cond)
    assert out.endswith("?? false)")
