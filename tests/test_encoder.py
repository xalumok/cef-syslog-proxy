"""Unit tests for the VRL value encoder, the injection boundary."""

from __future__ import annotations

import pytest

from sixthsense.compiler.encoder import (
    EncodeError,
    encode,
    encode_comment,
    encode_path,
    encode_regex_literal,
    encode_string,
    glob_to_regex,
)


class TestEncodeString:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("plain", '"plain"'),
            ('has "quotes"', '"has \\"quotes\\""'),
            ("back\\slash", '"back\\\\slash"'),
            ("line\nbreak", '"line\\nbreak"'),
            ("tab\there", '"tab\\there"'),
            ("carriage\rreturn", '"carriage\\rreturn"'),
            ("unicode ☃", '"unicode ☃"'),
        ],
    )
    def test_escapes(self, value: str, expected: str) -> None:
        assert encode_string(value) == expected

    def test_control_characters_become_hex_escapes(self) -> None:
        assert encode_string("\x00\x1f\x7f") == '"\\u{0}\\u{1f}\\u{7f}"'

    def test_length_limit(self) -> None:
        with pytest.raises(EncodeError, match="too long"):
            encode_string("x" * 5000)

    @pytest.mark.parametrize(
        "payload",
        [
            '" or true or "',
            '"; . = {}; "',
            '"\n. = {}\n"',
            'x" } else { . = {} } if true {"',
        ],
    )
    def test_injection_attempts_stay_inside_the_literal(self, payload: str) -> None:
        """Every quote and newline in the payload must be escaped.

        The encoded form always starts and ends with a quote and contains no unescaped
        quote or raw newline in between, so it cannot terminate its own literal.
        """
        encoded = encode_string(payload)
        assert encoded.startswith('"')
        assert encoded.endswith('"')
        body = encoded[1:-1]
        assert "\n" not in body
        assert _unescaped_quote_count(body) == 0


def _unescaped_quote_count(body: str) -> int:
    count = 0
    index = 0
    while index < len(body):
        if body[index] == "\\":
            index += 2
            continue
        if body[index] == '"':
            count += 1
        index += 1
    return count


class TestEncodeScalars:
    def test_bool_before_int(self) -> None:
        # bool is a subclass of int in Python. Getting this order wrong emits 1 for True,
        # which silently changes rule semantics.
        assert encode(True) == "true"
        assert encode(False) == "false"

    def test_ints_and_floats(self) -> None:
        assert encode(42) == "42"
        assert encode(-7) == "-7"
        assert encode(1.5) == "1.5"

    def test_rejects_non_finite(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(EncodeError):
                encode(value)

    def test_rejects_unknown_types(self) -> None:
        for value in (None, {"a": 1}, object(), b"bytes"):
            with pytest.raises(EncodeError):
                encode(value)

    def test_lists(self) -> None:
        assert encode(["a", 1, True]) == '["a", 1, true]'

    def test_list_length_limit(self) -> None:
        with pytest.raises(EncodeError, match="too long"):
            encode(["x"] * 2000)


class TestEncodePath:
    def test_basic(self) -> None:
        assert encode_path("severity") == '["severity"]'

    def test_quotes_in_field_name_are_escaped(self) -> None:
        assert encode_path('a"b') == '["a\\"b"]'

    def test_rejects_empty(self) -> None:
        with pytest.raises(EncodeError):
            encode_path("")


class TestGlob:
    def test_wildcards(self) -> None:
        assert glob_to_regex("a*b?c", case_insensitive=False) == "^a.*b.c$"

    def test_case_insensitive_prefix(self) -> None:
        assert glob_to_regex("x", case_insensitive=True).startswith("(?i)")

    def test_metacharacters_escaped(self) -> None:
        assert glob_to_regex("a.b+c", case_insensitive=False) == r"^a\.b\+c$"

    def test_single_quote_becomes_hex_escape(self) -> None:
        """A bare quote, or one inside a character class, would end the VRL raw string."""
        regex = glob_to_regex("it's", case_insensitive=False)
        assert "'" not in regex
        assert r"\x27" in regex
        # And it must survive the literal wrapper, which rejects any quote.
        assert encode_regex_literal(regex).startswith("r'")

    def test_control_characters_become_hex_escapes(self) -> None:
        """A raw newline would terminate the VRL raw-string regex literal."""
        regex = glob_to_regex("a\nb\x00c", case_insensitive=False)
        assert "\n" not in regex
        assert "\x00" not in regex
        assert r"\x0a" in regex
        assert r"\x00" in regex
        encode_regex_literal(regex)  # must not raise


class TestRegexLiteral:
    def test_rejects_quote(self) -> None:
        with pytest.raises(EncodeError, match="single quote"):
            encode_regex_literal("has'quote")

    def test_rejects_newline(self) -> None:
        with pytest.raises(EncodeError, match="newline"):
            encode_regex_literal("has\nnewline")


class TestComment:
    def test_newlines_removed(self) -> None:
        """A newline in a comment would end it and let the rest parse as code."""
        encoded = encode_comment("first\nsecond")
        assert "\n" not in encoded
        assert encoded.startswith("# ")

    def test_truncates(self) -> None:
        assert len(encode_comment("x" * 500)) <= 202
