"""Typed encoding of user values into VRL literals.

This module is the injection boundary (D-44). Analyst-authored rule values reach the data
plane through here and nowhere else.

Rules for anyone editing this file:

1. Never build VRL with f-strings, ``%``, ``str.format``, or ``+`` on user data. Every user
   value goes through :func:`encode` or :func:`encode_glob_regex`.
2. Only the types in :data:`ALLOWED` may be encoded. Anything else raises.
3. Every change here needs a Hypothesis case in ``tests/test_compiler_properties.py``.

The functions here are pure and total: given an accepted input they always return a valid
VRL literal, and given anything else they raise :class:`EncodeError`.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Final

ALLOWED: Final = (str, bool, int, float)

#: Characters that VRL string literals define an escape for.
_SIMPLE_ESCAPES: Final[dict[str, str]] = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}

#: Regex metacharacters that must be escaped when a glob is translated.
_REGEX_META: Final[frozenset[str]] = frozenset(".^$+()[]{}|\\*?")

MAX_STRING_LEN: Final[int] = 4096
MAX_LIST_LEN: Final[int] = 1024

#: Longest plain-decimal float literal we will emit. See :func:`encode_number`.
#:
#: Generous on purpose. A float carries up to 17 significant digits, so a small magnitude
#: needs its exponent in leading zeros on top of those: 1e-59 is 77 characters. This covers
#: roughly 1e-108 through 1e127, which is far outside any real threshold, while still
#: refusing the denormals that would need a thousand digits.
MAX_NUMBER_LITERAL_LEN: Final[int] = 128


class EncodeError(ValueError):
    """A value could not be safely encoded as VRL."""


def encode_string(value: str) -> str:
    """Encode a Python string as a double-quoted VRL string literal.

    Control characters that have no simple escape become ``\\u{..}``, so the output is
    always printable ASCII plus any non-control Unicode the input carried.
    """
    if len(value) > MAX_STRING_LEN:
        raise EncodeError(f"string too long: {len(value)} > {MAX_STRING_LEN}")

    out: list[str] = ['"']
    for ch in value:
        escape = _SIMPLE_ESCAPES.get(ch)
        if escape is not None:
            out.append(escape)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def encode_number(value: int | float) -> str:
    """Encode an int or float as a VRL numeric literal.

    Floats are written in plain decimal, never in scientific notation. ``repr`` is not usable
    here: it produces ``1e+17``, and VRL parses that as an identifier ``1e`` followed by
    ``+17``, so the generated program fails to compile with "call to undefined variable".

    ``Decimal(repr(value))`` keeps the shortest round-tripping digits that ``repr`` picked,
    and formatting with ``f`` renders them without an exponent.
    """
    if isinstance(value, bool):  # bool is a subclass of int; caught earlier, belt and braces
        raise EncodeError("bool is not a number")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise EncodeError(f"non-finite float: {value}")
        text = format(Decimal(repr(value)), "f")
        if len(text) > MAX_NUMBER_LITERAL_LEN:
            # Only reachable for magnitudes past roughly 1e64 or below 1e-64, where plain
            # decimal needs hundreds of digits. No real threshold rule lives out there, and
            # emitting a 300-character literal would be worse than refusing.
            raise EncodeError(f"number needs too many digits in plain decimal: {value!r}")
        # A VRL float literal needs the decimal point. Without it, 1e17 renders as the
        # integer 100000000000000000 and the comparison changes type.
        if "." not in text:
            text += ".0"
        return text
    if not (-(2**63) <= value < 2**63):
        raise EncodeError(f"integer out of range: {value}")
    return str(value)


def encode(value: object) -> str:
    """Encode a scalar or a list of scalars as a VRL literal.

    This is the only sanctioned path from user data into generated VRL.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return encode_string(value)
    if isinstance(value, int | float):
        return encode_number(value)
    if isinstance(value, list):
        if len(value) > MAX_LIST_LEN:
            raise EncodeError(f"list too long: {len(value)} > {MAX_LIST_LEN}")
        return "[" + ", ".join(encode(item) for item in value) + "]"
    raise EncodeError(f"cannot encode type {type(value).__name__}")


def encode_path(field: str) -> str:
    """Encode a field name as a VRL path segment list, for use with ``get``.

    Dynamic field names cannot be written as static VRL paths, so the compiler always goes
    through ``get(ev, [<name>])``. That keeps one code path for every field and avoids
    guessing which names are safe identifiers.

    A dot separates path segments, so ``syslog.appname`` becomes ``["syslog", "appname"]``.
    That is what lets syslog fields live in their own namespace without colliding with the
    CEF field of the same name. Dots are therefore reserved and cannot appear in a segment.

    Only the *field name* is a path. Dots inside a rule's value are ordinary characters and
    go through :func:`encode_string` untouched.
    """
    if not field:
        raise EncodeError("empty field name")
    if len(field) > 256:
        raise EncodeError(f"field name too long: {len(field)}")

    segments = field.split(".")
    if any(not segment for segment in segments):
        raise EncodeError(f"empty path segment in field name: {field!r}")

    return "[" + ", ".join(encode_string(segment) for segment in segments) + "]"


def glob_to_regex(pattern: str, *, case_insensitive: bool) -> str:
    """Translate a glob into an anchored regular expression.

    D-06 bans a user-facing regular expression operator, but ``glob`` still compiles down to
    one. That is safe for two reasons that do not hold for analyst-written expressions:

    * We generate the expression, so it contains only ``.*`` and ``.`` as metacharacters.
    * Vector's regular expression engine is the Rust ``regex`` crate, which is finite
      automaton based and runs in linear time. It cannot backtrack catastrophically.

    A literal ``'`` is emitted as the hex escape ``\\x27``. It cannot be emitted as a bare
    quote or inside a character class, because either form would terminate the surrounding
    VRL raw-string literal and let the rest of the pattern escape into code.
    """
    if len(pattern) > 512:
        raise EncodeError(f"glob too long: {len(pattern)}")

    out: list[str] = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        elif ch == "'":
            out.append("\\x27")
        elif ch in _REGEX_META:
            out.append("\\" + ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            # Same treatment as the quote: emit a hex escape rather than the character.
            # A raw newline would terminate the regex literal, and rejecting outright would
            # make glob the only operator that cannot carry a control character.
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    out.append("$")

    prefix = "(?i)" if case_insensitive else ""
    return prefix + "".join(out)


def encode_regex_literal(regex: str) -> str:
    """Wrap an already-safe regular expression as a VRL raw-string regex literal.

    Only accepts output from :func:`glob_to_regex`. The single-quote check is a second line
    of defense: :func:`glob_to_regex` never emits one, and if it ever did, this raises rather
    than producing a literal that breaks out of its own quoting.
    """
    if "'" in regex:
        raise EncodeError("regex literal may not contain a single quote")
    if "\n" in regex or "\r" in regex:
        raise EncodeError("regex literal may not contain a newline")
    return "r'" + regex + "'"


def encode_comment(text: str) -> str:
    """Encode text for a generated VRL comment.

    Newlines would end the comment and let the remainder be parsed as code, so they are
    replaced rather than escaped.
    """
    flat = text.replace("\r", " ").replace("\n", " ")
    if len(flat) > 200:
        flat = flat[:197] + "..."
    return "# " + flat
