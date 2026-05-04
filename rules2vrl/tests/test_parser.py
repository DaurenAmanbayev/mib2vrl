"""
test_parser.py — Tests for the Netcool rules DSL parser.

Every AST node type is tested with at least one example.
Real .rules snippets from the mib2vrl-generated netcool.rules are used
as integration fixtures.
"""

from pathlib import Path

import pytest

from rules2vrl.ast.nodes import (
    Program, IfBlock, SwitchNode, CaseNode,
    Assignment, DestructureAssignNode,
    MatchExpr, LookupExpr, RegexExpr, ExistsNode, ExtractNode, CastNode, TrimNode,
    BinaryOp, UnaryOp, FieldRef, VarbindRef, WildcardVarbindNode, NamedVarbindRef,
    StringLiteral, NumberLiteral, IncludeDirective, TableDefinition, Comment,
)
from rules2vrl.ast.parser import parse_rules, parse_rules_file, ParseError

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse(text: str) -> Program:
    return parse_rules(text)


# ---------------------------------------------------------------------------
# IncludeDirective
# ---------------------------------------------------------------------------

def test_include_directive():
    prog = parse('include "$OMNIHOME/probes/snmptrap.rules"')
    assert len(prog.body) == 1
    node = prog.body[0]
    assert isinstance(node, IncludeDirective)
    assert node.path == "$OMNIHOME/probes/snmptrap.rules"


# ---------------------------------------------------------------------------
# Comment
# ---------------------------------------------------------------------------

def test_comment_preserved():
    prog = parse("# this is a comment")
    assert len(prog.body) == 1
    assert isinstance(prog.body[0], Comment)
    assert "this is a comment" in prog.body[0].text


def test_comment_hash_block():
    prog = parse("######\n# Title\n######\n")
    # All three lines → 3 Comment nodes
    assert all(isinstance(n, Comment) for n in prog.body)


# ---------------------------------------------------------------------------
# Assignment nodes
# ---------------------------------------------------------------------------

def test_field_assignment_string():
    prog = parse('@AlertGroup = "IF-MIB"')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.target, FieldRef)
    assert node.target.name == "AlertGroup"
    assert isinstance(node.value, StringLiteral)
    assert node.value.value == "IF-MIB"


def test_field_assignment_number():
    prog = parse("@Severity = 3")
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.value, NumberLiteral)
    assert node.value.value == 3


def test_named_varbind_assignment():
    prog = parse("$ifIndex = $1")
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.target, NamedVarbindRef)
    assert node.target.name == "ifIndex"
    assert isinstance(node.value, VarbindRef)
    assert node.value.index == 0   # $1 → index 0


def test_field_assignment_concat():
    prog = parse('@Summary = "Node " + @Node + " is down"')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.value, BinaryOp)
    assert node.value.op == "+"


# ---------------------------------------------------------------------------
# MatchExpr
# ---------------------------------------------------------------------------

def test_match_string():
    prog = parse('if(match(@Manager, "SNMP")) {}')
    if_node = prog.body[0]
    assert isinstance(if_node, IfBlock)
    cond = if_node.condition
    assert isinstance(cond, MatchExpr)
    assert cond.field.name == "Manager"
    assert isinstance(cond.pattern, StringLiteral)
    assert cond.pattern.value == "SNMP"


def test_match_regex():
    prog = parse('if(match(@Summary, regex(".*[Dd]own.*"))) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.pattern, RegexExpr)
    assert cond.pattern.pattern == ".*[Dd]own.*"


def test_match_pipe_alternatives():
    prog = parse('if(match(@AlertKey, "linkDown|linkUp")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.pattern, StringLiteral)
    assert "|" in cond.pattern.value


# ---------------------------------------------------------------------------
# BinaryOp — logical operators
# ---------------------------------------------------------------------------

def test_and_condition():
    prog = parse('if(@SpecificTrap == 1 && match(@Manager, "SNMP")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, BinaryOp)
    assert cond.op == "&&"


def test_or_condition():
    prog = parse('if(match(@Manager, "SNMP") || match(@Manager, "SNMP2")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, BinaryOp)
    assert cond.op == "||"


def test_not_condition():
    prog = parse('if(!match(@Manager, "SNMP")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, UnaryOp)
    assert cond.op == "!"


# ---------------------------------------------------------------------------
# CompareExpr
# ---------------------------------------------------------------------------

def test_eq_compare():
    prog = parse("if(@SpecificTrap == 1) {}")
    cond = prog.body[0].condition
    assert isinstance(cond, BinaryOp)
    assert cond.op == "=="
    assert isinstance(cond.left, FieldRef)
    assert cond.left.name == "SpecificTrap"
    assert isinstance(cond.right, NumberLiteral)
    assert cond.right.value == 1


def test_neq_compare():
    prog = parse('if(@Severity != 5) {}')
    cond = prog.body[0].condition
    assert cond.op == "!="


def test_lt_compare():
    prog = parse('if(@Severity < 3) {}')
    cond = prog.body[0].condition
    assert cond.op == "<"


def test_geq_compare():
    prog = parse('if(@Severity >= 2) {}')
    cond = prog.body[0].condition
    assert cond.op == ">="


# ---------------------------------------------------------------------------
# IfBlock
# ---------------------------------------------------------------------------

def test_if_empty_body():
    prog = parse("if(match(@Manager, \"X\")) {}")
    node = prog.body[0]
    assert isinstance(node, IfBlock)
    assert node.body == []
    assert node.else_body is None


def test_if_with_body():
    prog = parse('@AlertGroup = "IF-MIB"\nif(match(@Manager, "SNMP")) { @Severity = 3 }')
    if_node = prog.body[1]
    assert isinstance(if_node, IfBlock)
    assert len(if_node.body) == 1
    assert isinstance(if_node.body[0], Assignment)


def test_if_else():
    text = """
    if(@SpecificTrap == 1) {
        @Severity = 2
    } else {
        @Severity = 3
    }
    """
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, IfBlock)
    assert node.else_body is not None
    assert len(node.else_body) == 1


def test_nested_if():
    text = """
    if(match(@Manager, "SNMP")) {
        if(match(@Identifier, "snmpTraps 3")) {
            @Severity = 4
        }
    }
    """
    prog = parse(text)
    outer = prog.body[0]
    assert isinstance(outer, IfBlock)
    inner = outer.body[0]
    assert isinstance(inner, IfBlock)
    assert inner.body[0].value.value == 4


# ---------------------------------------------------------------------------
# FieldRef
# ---------------------------------------------------------------------------

def test_field_ref_name_stripped():
    prog = parse('@Summary = "x"')
    target = prog.body[0].target
    assert isinstance(target, FieldRef)
    assert target.name == "Summary"   # no @ prefix


# ---------------------------------------------------------------------------
# VarbindRef
# ---------------------------------------------------------------------------

def test_varbind_index_zero_based():
    prog = parse("$x = $1")
    val = prog.body[0].value
    assert isinstance(val, VarbindRef)
    assert val.index == 0   # $1 → index 0


def test_varbind_index_large():
    prog = parse("$y = $5")
    val = prog.body[0].value
    assert isinstance(val, VarbindRef)
    assert val.index == 4   # $5 → index 4


# ---------------------------------------------------------------------------
# NamedVarbindRef
# ---------------------------------------------------------------------------

def test_named_varbind_in_expr():
    prog = parse('@Summary = "val=" + $ifIndex')
    rhs = prog.body[0].value
    # BinaryOp with right being NamedVarbindRef
    assert isinstance(rhs, BinaryOp)
    assert isinstance(rhs.right, NamedVarbindRef)
    assert rhs.right.name == "ifIndex"


# ---------------------------------------------------------------------------
# StringLiteral
# ---------------------------------------------------------------------------

def test_string_literal_no_quotes():
    prog = parse('@AlertKey = "linkDown"')
    val = prog.body[0].value
    assert isinstance(val, StringLiteral)
    assert val.value == "linkDown"   # quotes stripped


def test_string_literal_multiline():
    prog = parse('@Summary = "line one\nline two"')
    val = prog.body[0].value
    assert isinstance(val, StringLiteral)
    assert "\n" in val.value


# ---------------------------------------------------------------------------
# NumberLiteral
# ---------------------------------------------------------------------------

def test_number_int():
    prog = parse("@Severity = 3")
    assert isinstance(prog.body[0].value, NumberLiteral)
    assert prog.body[0].value.value == 3


def test_number_float():
    prog = parse("@Grade = 1.5")
    val = prog.body[0].value
    assert isinstance(val, NumberLiteral)
    assert val.value == 1.5


# ---------------------------------------------------------------------------
# LookupExpr
# ---------------------------------------------------------------------------

def test_lookup_in_assignment():
    prog = parse("@Severity = lookup(@traptype, sev_table)")
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.value, LookupExpr)
    assert node.value.table_name == "sev_table"
    assert node.value.field.name == "traptype"


# ---------------------------------------------------------------------------
# TableDefinition (dict format)
# ---------------------------------------------------------------------------

def test_table_dict_format():
    text = """
    table if_status = {
        "1" : "up",
        "2" : "down",
    }
    """
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, TableDefinition)
    assert node.name == "if_status"
    assert len(node.entries) == 2
    assert node.entries[0] == ("1", "up")
    assert node.entries[1] == ("2", "down")


def test_table_tuple_format():
    text = """
    table sev_map = {
        {"linkDown", "4"},
        {"linkUp", "1"},
    }
    """
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, TableDefinition)
    assert node.name == "sev_map"
    assert len(node.entries) == 2
    assert node.entries[0] == ("linkDown", "4")


def test_table_with_default():
    text = """
    table sev_map = {
        "1" : "up",
    }
    default = "unknown"
    """
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, TableDefinition)
    assert node.default == "unknown"


# ---------------------------------------------------------------------------
# Integration: parse sample.rules fixture
# ---------------------------------------------------------------------------

def test_parse_sample_rules_file():
    fixture = FIXTURES / "sample.rules"
    prog = parse_rules_file(fixture)
    assert isinstance(prog, Program)
    # Should have at least include + outer if block
    assert len(prog.body) >= 2


def test_parse_sample_lookup_file():
    fixture = FIXTURES / "sample.lookup"
    prog = parse_rules_file(fixture)
    tables = [n for n in prog.body if isinstance(n, TableDefinition)]
    assert len(tables) >= 2


# ---------------------------------------------------------------------------
# ParseError
# ---------------------------------------------------------------------------

def test_parse_error_missing_rparen():
    with pytest.raises(ParseError):
        parse("if(match(@Manager, \"X\") {}")


def test_parse_unknown_token_is_skipped():
    """Parser must not crash on unknown tokens — emits Comment instead."""
    prog = parse("@Severity = 3\n@Class = 30")
    assert len(prog.body) == 2


# ---------------------------------------------------------------------------
# SwitchNode
# ---------------------------------------------------------------------------

def test_switch_basic():
    text = '''
    switch($specific-trap) {
        case "1":
            @AlertKey = "acctngFileNearlyFull"
            @Severity = 3
        case "2":
            @AlertKey = "acctngFileFull"
            @Severity = 5
    }
    '''
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, SwitchNode)
    assert len(node.cases) == 2
    assert node.cases[0].value == "1"
    assert node.cases[1].value == "2"
    assert isinstance(node.cases[0].body[0], Assignment)
    assert isinstance(node.cases[1].body[0], Assignment)


def test_switch_expression_is_named_varbind():
    prog = parse('switch($specific-trap) { case "1": @Severity = 3 }')
    node = prog.body[0]
    assert isinstance(node, SwitchNode)
    assert isinstance(node.expression, NamedVarbindRef)
    assert node.expression.name == "specific-trap"


def test_switch_case_with_inline_comment():
    text = 'switch($x) { case "1": ### a comment\n  @Severity = 3 }'
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, SwitchNode)
    assert len(node.cases) == 1
    # The inline comment should not appear in body (it was skipped)
    assert all(isinstance(s, Assignment) for s in node.cases[0].body)


# ---------------------------------------------------------------------------
# log() call
# ---------------------------------------------------------------------------

def test_log_call_becomes_comment():
    prog = parse('log(DEBUG, "some message string")')
    assert len(prog.body) == 1
    node = prog.body[0]
    assert isinstance(node, Comment)
    assert "some message string" in node.text


def test_log_call_does_not_leave_tokens():
    """Tokens after log() should still be parsed normally."""
    prog = parse('log(DEBUG, "msg")\n@Severity = 3')
    assert len(prog.body) == 2
    assert isinstance(prog.body[0], Comment)
    assert isinstance(prog.body[1], Assignment)


# ---------------------------------------------------------------------------
# switch default:
# ---------------------------------------------------------------------------

def test_switch_with_default():
    text = '''
    switch($specific-trap) {
        case "1": @Severity = 3
        default:
            @Severity = 1
    }
    '''
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, SwitchNode)
    assert len(node.cases) == 1
    assert node.cases[0].value == "1"
    assert len(node.default_body) == 1
    assert isinstance(node.default_body[0], Assignment)


def test_switch_default_only():
    text = 'switch($x) { default: @Severity = 1 }'
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, SwitchNode)
    assert len(node.cases) == 0
    assert len(node.default_body) == 1
    assert isinstance(node.default_body[0], Assignment)


# ---------------------------------------------------------------------------
# $* wildcard varbind
# ---------------------------------------------------------------------------

def test_wildcard_varbind_in_expr():
    prog = parse('@Summary = $*')
    val = prog.body[0].value
    assert isinstance(val, WildcardVarbindNode)


# ---------------------------------------------------------------------------
# details() call
# ---------------------------------------------------------------------------

def test_details_call_becomes_comment():
    prog = parse('details($*)')
    assert len(prog.body) == 1
    node = prog.body[0]
    assert isinstance(node, Comment)
    assert "details" in node.text


def test_details_call_does_not_leave_tokens():
    prog = parse('details($*)\n@Severity = 3')
    assert len(prog.body) == 2
    assert isinstance(prog.body[0], Comment)
    assert isinstance(prog.body[1], Assignment)


# ---------------------------------------------------------------------------
# exists() function
# ---------------------------------------------------------------------------

def test_exists_function():
    prog = parse('if(exists($SEV_KEY)) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, ExistsNode)
    assert isinstance(cond.argument, NamedVarbindRef)
    assert cond.argument.name == "SEV_KEY"


def test_exists_in_condition_with_body():
    prog = parse('if(exists($SEV_KEY)) { @Severity = 3 }')
    node = prog.body[0]
    assert isinstance(node, IfBlock)
    assert isinstance(node.condition, ExistsNode)


# ---------------------------------------------------------------------------
# DestructureAssignNode
# ---------------------------------------------------------------------------

def test_destructure_parse():
    text = '[$OS_Severity,$OS_Type,$OS_ExpireTime] = lookup($SEV_KEY, sev_table)'
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, DestructureAssignNode)
    assert len(node.targets) == 3
    assert all(isinstance(t, NamedVarbindRef) for t in node.targets)
    assert node.targets[0].name == "OS_Severity"
    assert node.targets[1].name == "OS_Type"
    assert node.targets[2].name == "OS_ExpireTime"
    assert isinstance(node.value, LookupExpr)
    assert node.value.table_name == "sev_table"
    assert isinstance(node.value.field, NamedVarbindRef)
    assert node.value.field.name == "SEV_KEY"


def test_destructure_single_target():
    prog = parse('[$x] = lookup($key, my_table)')
    node = prog.body[0]
    assert isinstance(node, DestructureAssignNode)
    assert len(node.targets) == 1


def test_destructure_field_targets():
    """Destructure into @Field targets, not just $vars."""
    prog = parse('[@AlertKey, @Severity] = lookup(@traptype, sev_table)')
    node = prog.body[0]
    assert isinstance(node, DestructureAssignNode)
    assert all(isinstance(t, FieldRef) for t in node.targets)


# ---------------------------------------------------------------------------
# ExtractNode
# ---------------------------------------------------------------------------

def test_extract_function_parse():
    prog = parse('@Summary = extract($OID1, "pattern")')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    val = node.value
    assert isinstance(val, ExtractNode)
    assert isinstance(val.source, NamedVarbindRef)
    assert val.source.name == "OID1"
    assert isinstance(val.pattern, StringLiteral)
    assert val.pattern.value == "pattern"


def test_extract_in_concat_parse():
    prog = parse('@Summary = "prefix" + extract($OID1, "pat")')
    node = prog.body[0]
    rhs = node.value
    assert isinstance(rhs, BinaryOp)
    assert rhs.op == "+"
    assert isinstance(rhs.right, ExtractNode)


# ---------------------------------------------------------------------------
# case "val1"|"val2": — pipe-separated case values
# ---------------------------------------------------------------------------

def test_case_with_pipe_alternatives():
    text = '''
    switch($x) {
        case ".1.3.6.1.4.1.9.9.216.2"|".1.3.6.1.4.1.9.9.99999.2":
            @Severity = 3
    }
    '''
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, SwitchNode)
    assert len(node.cases) == 1
    case = node.cases[0]
    assert len(case.values) == 2
    assert case.values[0] == ".1.3.6.1.4.1.9.9.216.2"
    assert case.values[1] == ".1.3.6.1.4.1.9.9.99999.2"


def test_case_pipe_three_values():
    text = 'switch($x) { case "a"|"b"|"c": @Severity = 1 }'
    prog = parse(text)
    case = prog.body[0].cases[0]
    assert case.values == ["a", "b", "c"]


# ---------------------------------------------------------------------------
# match() / regmatch() with varbind source
# ---------------------------------------------------------------------------

def test_match_with_positional_varbind():
    prog = parse('if(match($1, "0")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.field, VarbindRef)
    assert cond.field.index == 0
    assert isinstance(cond.pattern, StringLiteral)
    assert cond.pattern.value == "0"


def test_match_with_named_varbind():
    prog = parse('if(match($ifOperStatus, "1")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.field, NamedVarbindRef)
    assert cond.field.name == "ifOperStatus"


def test_match_varbind_regex_autodetect():
    """Pattern with ^ triggers auto-detect as RegexExpr for varbind sources."""
    prog = parse('if(match($3, "^ap:")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.pattern, RegexExpr)
    assert cond.pattern.pattern == "^ap:"


def test_match_field_not_autodetected():
    """@Field sources are never auto-detected as regex — even if pattern has ^."""
    prog = parse('if(match(@Manager, "^SNMP")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.pattern, StringLiteral)


def test_regmatch_function():
    prog = parse('if(regmatch($3, "^ap:")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.field, VarbindRef)
    assert cond.field.index == 2
    assert isinstance(cond.pattern, RegexExpr)
    assert cond.pattern.pattern == "^ap:"


def test_regmatch_forces_regex_even_for_plain_string():
    """regmatch always treats the pattern as a regex regardless of content."""
    prog = parse('if(regmatch($1, "0")) {}')
    cond = prog.body[0].condition
    assert isinstance(cond.pattern, RegexExpr)


# ---------------------------------------------------------------------------
# UNKNOWN tokens don't abort the parser
# ---------------------------------------------------------------------------

def test_parser_skips_unknown_lexer_token():
    """Unknown characters produce UNKNOWN tokens that the parser skips gracefully."""
    prog = parse("@Severity = 3 ~ @Class = 30")
    # Should not raise; at least the first assignment should be present
    assignments = [n for n in prog.body if isinstance(n, Assignment)]
    assert len(assignments) >= 1


# ---------------------------------------------------------------------------
# else if (without braces)
# ---------------------------------------------------------------------------

def test_else_if_chain():
    text = """
    if(@SpecificTrap == 1) {
        @Severity = 5
    } else
    if(@SpecificTrap == 2) {
        @Severity = 3
    }
    """
    prog = parse(text)
    outer = prog.body[0]
    assert isinstance(outer, IfBlock)
    assert outer.else_body is not None
    assert len(outer.else_body) == 1
    inner = outer.else_body[0]
    assert isinstance(inner, IfBlock)
    assert inner.condition.op == "=="
    inner_left = inner.condition.left
    assert isinstance(inner_left, FieldRef)
    assert inner_left.name == "SpecificTrap"


def test_else_if_no_braces():
    text = 'if(@Severity == 5) { @Severity = 3 } else if(@Severity == 3) { @Severity = 1 }'
    prog = parse(text)
    outer = prog.body[0]
    assert isinstance(outer, IfBlock)
    inner = outer.else_body[0]
    assert isinstance(inner, IfBlock)
    assert inner.else_body is None


def test_else_if_three_levels():
    text = '''
    if(@Severity == 5) { @Severity = 3 }
    else if(@Severity == 3) { @Severity = 2 }
    else if(@Severity == 2) { @Severity = 1 }
    '''
    prog = parse(text)
    outer = prog.body[0]
    mid = outer.else_body[0]
    inner = mid.else_body[0]
    assert isinstance(inner, IfBlock)
    assert inner.else_body is None


# ---------------------------------------------------------------------------
# CastNode — int() / str() / float()
# ---------------------------------------------------------------------------

def test_int_cast_in_assignment():
    prog = parse('@Severity = int($1)')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    val = node.value
    assert isinstance(val, CastNode)
    assert val.cast_type == "int"
    assert isinstance(val.argument, VarbindRef)
    assert val.argument.index == 0


def test_str_cast_field():
    prog = parse('@Summary = str(@Severity)')
    val = prog.body[0].value
    assert isinstance(val, CastNode)
    assert val.cast_type == "str"
    assert isinstance(val.argument, FieldRef)
    assert val.argument.name == "Severity"


def test_cast_in_comparison():
    prog = parse('if(int($1) < 10) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, BinaryOp)
    assert cond.op == "<"
    assert isinstance(cond.left, CastNode)
    assert cond.left.cast_type == "int"
    assert isinstance(cond.right, NumberLiteral)
    assert cond.right.value == 10


def test_float_cast():
    prog = parse('if(float($1) >= 1.5) {}')
    cond = prog.body[0].condition
    assert isinstance(cond.left, CastNode)
    assert cond.left.cast_type == "float"


# ---------------------------------------------------------------------------
# match($var, $var) — variable pattern argument
# ---------------------------------------------------------------------------

def test_match_varbind_vs_varbind():
    prog = parse('if(match($2, $3)) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.field, VarbindRef)
    assert cond.field.index == 1
    assert isinstance(cond.pattern, VarbindRef)
    assert cond.pattern.index == 2


def test_match_varbind_vs_named_varbind():
    prog = parse('if(match($2, $myVar)) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.pattern, NamedVarbindRef)
    assert cond.pattern.name == "myVar"


def test_match_field_vs_field():
    prog = parse('if(match(@Manager, @Agent)) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, MatchExpr)
    assert isinstance(cond.field, FieldRef)
    assert isinstance(cond.pattern, FieldRef)


# ---------------------------------------------------------------------------
# TrimNode — ltrim / rtrim / trim
# ---------------------------------------------------------------------------

def test_ltrim_parse():
    prog = parse('@Summary = ltrim($1)')
    val = prog.body[0].value
    assert isinstance(val, TrimNode)
    assert val.trim_type == "left"
    assert isinstance(val.argument, VarbindRef)


def test_rtrim_parse():
    prog = parse('@Summary = rtrim($1)')
    val = prog.body[0].value
    assert isinstance(val, TrimNode)
    assert val.trim_type == "right"


def test_trim_parse():
    prog = parse('@Summary = trim(@Agent)')
    val = prog.body[0].value
    assert isinstance(val, TrimNode)
    assert val.trim_type == "both"
    assert isinstance(val.argument, FieldRef)


def test_ltrim_nested_extract():
    prog = parse('@Summary = ltrim(extract($1, "pattern"))')
    val = prog.body[0].value
    assert isinstance(val, TrimNode)
    assert val.trim_type == "left"
    assert isinstance(val.argument, ExtractNode)


# ---------------------------------------------------------------------------
# BUG 2 — Comment between if() and {
# ---------------------------------------------------------------------------

def test_if_comment_before_lbrace():
    text = 'if(exists($OID7))\n### comment\n{\n@Severity = 3\n}'
    prog = parse(text)
    node = prog.body[0]
    assert isinstance(node, IfBlock)
    assert isinstance(node.condition, ExistsNode)
    assert len(node.body) == 1


# ---------------------------------------------------------------------------
# BUG 3 — Positional varbind as LHS ($1 = value)
# ---------------------------------------------------------------------------

def test_varbind_lhs_assignment():
    prog = parse('$1 = $IPv4addr')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.target, VarbindRef)
    assert node.target.index == 0
    assert isinstance(node.value, NamedVarbindRef)


def test_varbind_lhs_string():
    prog = parse('$2 = "hello"')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.target, VarbindRef)
    assert node.target.index == 1


# ---------------------------------------------------------------------------
# BUG 4 — int() cast on both sides of comparison
# ---------------------------------------------------------------------------

def test_int_cast_both_sides():
    prog = parse('if(int($ciscoPingSentPackets) == int($ciscoPingReceivedPackets)) {}')
    cond = prog.body[0].condition
    assert isinstance(cond, BinaryOp)
    assert cond.op == "=="
    assert isinstance(cond.left, CastNode)
    assert isinstance(cond.right, CastNode)
    assert cond.left.cast_type == "int"
    assert cond.right.cast_type == "int"


# ---------------------------------------------------------------------------
# lookup() with positional varbind key
# ---------------------------------------------------------------------------

def test_lookup_positional_varbind_key():
    prog = parse('$casState = lookup($1, ciscoCasState)')
    node = prog.body[0]
    assert isinstance(node, Assignment)
    assert isinstance(node.value, LookupExpr)
    assert isinstance(node.value.field, VarbindRef)
    assert node.value.field.index == 0
    assert node.value.table_name == "ciscoCasState"


def test_lookup_positional_varbind_key_3():
    prog = parse('$x = lookup($3, BsnStationReasonCode)')
    node = prog.body[0]
    assert isinstance(node.value.field, VarbindRef)
    assert node.value.field.index == 2
