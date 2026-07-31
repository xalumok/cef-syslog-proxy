"""Tests for the publish gate.

D-44 makes this a release gate, so the gate itself needs tests. Two of its three checks were
added because the previous version passed a program that broke the data plane:

* ``vector validate`` does not compile VRL.
* ``vector vrl`` compiles, but exits 0 on a runtime error.

The second one is why these tests exist. A gate that only reads the exit code reports success
on a program that aborts on every non-CEF event.
"""

from __future__ import annotations

import shutil

import pytest

from sixthsense.compiler.compiler import compile_or_raise
from sixthsense.compiler.validate import _PROBE_CORPUS, validate_vrl
from sixthsense.models.rule import Action, Condition, Operator, Rule, RuleChain

pytestmark = pytest.mark.skipif(shutil.which("vector") is None, reason="vector binary not on PATH")


@pytest.fixture
def chain() -> RuleChain:
    return RuleChain(
        rules=[
            Rule(
                id="r-1",
                name="scanner",
                order=0,
                action=Action.DROP,
                conditions=[
                    Condition(field="filterhostname", operator=Operator.EQ, value="scanner01")
                ],
            )
        ]
    )


def test_the_current_compiler_passes_the_gate(chain: RuleChain) -> None:
    result = validate_vrl(compile_or_raise(chain))
    assert result.ok, result.output
    assert not result.skipped


def test_a_compile_error_is_caught(chain: RuleChain) -> None:
    """The original check: an undefined variable. Vector exits 70 for this."""
    program = compile_or_raise(chain) + "\n.x = undefined_variable_name\n"
    result = validate_vrl(program)
    assert not result.ok
    assert result.stage == "vrl"


def test_a_runtime_abort_is_caught(chain: RuleChain) -> None:
    """The check that was missing, expressed as the bug that motivated it.

    `find` is typed as returning an integer but returns null when the needle is absent, so
    this comparison compiles and then aborts on every event without a CEF marker. Vector
    still exits 0, so only inspecting the output catches it.
    """
    program = compile_or_raise(chain).replace(
        "if marker != null && marker >= 0 {", "if marker >= 0 {"
    )
    assert "if marker >= 0 {" in program, "the prelude changed; update this test"

    result = validate_vrl(program)
    assert not result.ok, "a program that aborts on non-CEF input must not pass the gate"
    assert result.stage == "runtime"


def test_a_program_that_never_decides_is_caught(chain: RuleChain) -> None:
    """Running to completion is not enough. The program has to produce a decision."""
    result = validate_vrl('.  = { "not_a_decision": true }')
    assert not result.ok
    assert result.stage == "runtime"


def test_the_corpus_covers_every_parser_path() -> None:
    """The corpus is the gate's coverage. Shrinking it silently weakens every publish.

    Each shape reaches a different branch of the prelude, and the `find` bug was invisible to
    all of them except the two with no CEF marker.
    """
    assert any("CEF:" in probe and probe.startswith("<") for probe in _PROBE_CORPUS)
    assert any(probe.startswith("CEF:") for probe in _PROBE_CORPUS)
    assert any(probe.startswith("<134>") and "CEF:" not in probe for probe in _PROBE_CORPUS)
    assert any(probe.startswith("<165>1 ") and "CEF:" not in probe for probe in _PROBE_CORPUS)
    assert any(not probe.startswith("<") and "CEF:" not in probe for probe in _PROBE_CORPUS)
