"""Golden-path tests: fixed rules, fixed expectations, asserted output.

These catch semantic drift. A compiler refactor that quietly changes which events match
would pass the property tests, because balanced output is still balanced. Only pinned
expectations catch it.
"""

from __future__ import annotations

import pytest

from sixthsense.compiler.compiler import compile_chain, compile_condition
from sixthsense.compiler.vector_config import VectorSettings, render_toml
from sixthsense.models.rule import (
    Action,
    Condition,
    Operator,
    Rule,
    RuleChain,
)


def cond(field: str, operator: Operator, value: object = None, **kw: object) -> Condition:
    return Condition(field=field, operator=operator, value=value, **kw)  # type: ignore[arg-type]


class TestOperatorOutput:
    def test_eq_folds_case_at_compile_time(self) -> None:
        out = compile_condition(cond("Host", Operator.EQ, "PROD-01"))
        assert '"prod-01"' in out
        assert 'downcase("PROD-01")' not in out

    def test_eq_case_sensitive_preserves_value(self) -> None:
        out = compile_condition(cond("host", Operator.EQ, "PROD-01", case_sensitive=True))
        assert '"PROD-01"' in out
        assert "downcase" not in out

    def test_numeric_guards_null(self) -> None:
        """A missing or non-numeric field must never satisfy a threshold rule.

        VRL rejects a fallible predicate at compile time, and comparing null to a number is
        fallible. The `?? false` makes the comparison total and means "no match".
        """
        out = compile_condition(cond("severity", Operator.GTE, 7))
        assert "to_float" in out
        assert out.endswith("?? false)")
        assert "7.0" in out

    def test_cidr_argument_order(self) -> None:
        out = compile_condition(cond("filteripaddress", Operator.CIDR, "10.0.0.0/8"))
        assert out.startswith('(ip_cidr_contains("10.0.0.0/8"')

    def test_exists(self) -> None:
        assert compile_condition(cond("x", Operator.EXISTS)) == '((get(ev, ["x"]) ?? null) != null)'

    def test_not_in_is_negated_includes(self) -> None:
        out = compile_condition(cond("t", Operator.NOT_IN, ["a", "b"]))
        assert out.startswith("(!includes(")

    def test_field_name_is_lowercased_by_the_model(self) -> None:
        out = compile_condition(cond("FilterHostName", Operator.EXISTS))
        assert '["filterhostname"]' in out


class TestChainSemantics:
    @pytest.fixture
    def chain(self) -> RuleChain:
        return RuleChain(
            default_action=Action.FORWARD,
            rules=[
                Rule(
                    id="r-first",
                    name="first",
                    order=0,
                    action=Action.DROP,
                    conditions=[cond("severity", Operator.LT, 3)],
                ),
                Rule(
                    id="r-second",
                    name="second",
                    order=1,
                    action=Action.FORWARD,
                    conditions=[cond("filtertype", Operator.EQ, "ids")],
                ),
                Rule(
                    id="r-disabled",
                    name="disabled",
                    order=2,
                    enabled=False,
                    action=Action.DROP,
                    conditions=[cond("name", Operator.CONTAINS, "noise")],
                ),
            ],
        )

    def test_first_match_wins_structure(self, chain: RuleChain) -> None:
        out = compile_chain(chain)
        assert out.index('"r-first"') < out.index('"r-second"')
        # Count only in the matching section. The enforcement block below it has its own
        # else-if chain, which is why this splits rather than counting the whole program.
        matching = out.split("shadow_chain =")[0]
        assert matching.count("} else if") == 1  # two active rules means one else-if

    def test_disabled_rules_are_absent(self, chain: RuleChain) -> None:
        assert '"r-disabled"' not in compile_chain(chain)

    def test_default_action_is_explicit(self, chain: RuleChain) -> None:
        assert 'decision = "forward"' in compile_chain(chain)

    def test_fail_closed_default_compiles(self) -> None:
        chain = RuleChain(default_action=Action.DROP, rules=[])
        out = compile_chain(chain)
        assert 'decision = "drop"' in out

    def test_parse_failure_forwards(self, chain: RuleChain) -> None:
        """D-18: unparseable input is forwarded, not dropped."""
        out = compile_chain(chain)
        assert "if !parse_ok {" in out
        index = out.index("if !parse_ok {")
        branch = out[index : index + 250]
        assert 'decision = "forward_parse_error"' in branch

    def test_shadow_rule_records_but_does_not_enforce(self) -> None:
        chain = RuleChain(
            rules=[
                Rule(
                    id="r-shadow",
                    name="shadow",
                    order=0,
                    action=Action.DROP,
                    shadow=True,
                    conditions=[cond("severity", Operator.LT, 3)],
                )
            ]
        )
        out = compile_chain(chain)
        assert "matched_shadow = true" in out
        assert "matched_shadow || shadow_chain" in out
        assert 'reason = "shadow"' in out

    def test_empty_chain_compiles(self) -> None:
        out = compile_chain(RuleChain(rules=[]))
        assert "matched_id == null" in out
        assert "} else if" not in out.split("shadow_chain")[0]

    def test_message_is_never_mutated(self, chain: RuleChain) -> None:
        """D-15: the proxy forwards the bytes it received."""
        out = compile_chain(chain)
        assert ".message =" not in out
        assert "del(.message)" not in out


class TestVectorConfig:
    def test_topology_shape(self) -> None:
        chain = RuleChain(
            rules=[
                Rule(
                    id="r-x",
                    name="x",
                    order=0,
                    action=Action.DROP,
                    conditions=[cond("severity", Operator.LT, 2)],
                )
            ]
        )
        toml_text = render_toml(chain, VectorSettings(), chain_version=3)

        assert "[sources.ingest]" in toml_text
        assert "receive_buffer_bytes" in toml_text  # D-24
        assert "[sinks.elk]" in toml_text
        assert "[sinks.drop_audit]" in toml_text
        assert "[sinks.control_plane_tail]" in toml_text
        assert "[sinks.metrics]" in toml_text

    def test_elk_sink_emits_text_not_json(self) -> None:
        """D-15 again, at the sink: re-serializing would change what ELK indexes."""
        import tomllib

        parsed = tomllib.loads(render_toml(RuleChain(rules=[]), VectorSettings()))
        assert parsed["sinks"]["elk"]["encoding"]["codec"] == "text"

    def test_tail_sink_drops_rather_than_blocks(self) -> None:
        """The control plane must never apply backpressure to the data plane."""
        import tomllib

        parsed = tomllib.loads(render_toml(RuleChain(rules=[]), VectorSettings()))
        assert parsed["sinks"]["control_plane_tail"]["buffer"]["when_full"] == "drop_newest"

    def test_ingest_buffer_is_sized(self) -> None:
        """D-24: the kernel discards silently without this."""
        import tomllib

        parsed = tomllib.loads(render_toml(RuleChain(rules=[]), VectorSettings()))
        source = parsed["sources"]["ingest"]
        assert source["receive_buffer_bytes"] > 1_000_000
        assert source["max_length"] == 65_536  # D-17, not the classic 1024

    def test_quotes_in_rule_values_survive_toml_embedding(self) -> None:
        chain = RuleChain(
            rules=[
                Rule(
                    id="r-quote",
                    name="quote",
                    order=0,
                    action=Action.DROP,
                    conditions=[cond("name", Operator.EQ, 'say "hi"\nnewline')],
                )
            ]
        )
        toml_text = render_toml(chain, VectorSettings())
        # tomli_w owns the TOML escaping; we only assert the round trip is intact.
        import tomllib

        parsed = tomllib.loads(toml_text)
        source = parsed["transforms"]["decide"]["source"]
        assert '\\"hi\\"' in source
        assert "\\n" in source
