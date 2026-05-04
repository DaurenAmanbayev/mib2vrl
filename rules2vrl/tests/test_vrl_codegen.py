"""
test_vrl_codegen.py — Tests for AST → VRL code generation.

Every codegen translation rule from  is tested.
"""

from pathlib import Path

import pytest

from rules2vrl.ast.parser import parse_rules
from rules2vrl.codegen.vrl_codegen import VrlCodegen, generate_vrl

FIXTURES = Path(__file__).parent / "fixtures"


def gen(text: str) -> str:
    """Parse Netcool rules text and return generated VRL."""
    prog = parse_rules(text)
    return generate_vrl(prog)


# ---------------------------------------------------------------------------
# Field assignment
# ---------------------------------------------------------------------------

def test_field_assignment_string():
    vrl = gen('@AlertGroup = "IF-MIB"')
    assert '.alert_group = "IF-MIB"' in vrl


def test_field_assignment_number():
    vrl = gen("@Severity = 3")
    assert ".severity = 3" in vrl


def test_field_assignment_integer_from_float():
    """NumberLiterals with no fractional part render as integers."""
    vrl = gen("@Grade = 1.0")
    assert ".grade = 1" in vrl


def test_field_assignment_class():
    """@Class maps to ._class (reserved word avoidance)."""
    vrl = gen("@Class = 30")
    assert "._class = 30" in vrl


# ---------------------------------------------------------------------------
# String concatenation
# ---------------------------------------------------------------------------

def test_string_concat_field():
    vrl = gen('@Summary = @Agent + ": down"')
    assert '.summary = .agent + ": down"' in vrl


def test_string_concat_varbind():
    vrl = gen('@Summary = "prefix " + $1')
    assert '.summary = "prefix " + .varbinds[0]' in vrl


def test_string_concat_named_varbind():
    vrl = gen('@Summary = "val=" + $ifIndex')
    assert '.summary = "val=" + _ifIndex' in vrl


def test_multipart_concat():
    vrl = gen('@Summary = "Node " + @Node + " interface " + $ifIndex')
    assert ".summary" in vrl
    assert ".node" in vrl
    assert "_ifIndex" in vrl


# ---------------------------------------------------------------------------
# Varbind references
# ---------------------------------------------------------------------------

def test_varbind_dollar_one():
    vrl = gen("$x = $1")
    assert "_x = .varbinds[0]" in vrl


def test_varbind_dollar_three():
    vrl = gen("$z = $3")
    assert "_z = .varbinds[2]" in vrl


def test_varbind_dollar_ten():
    vrl = gen("$w = $10")
    assert "_w = .varbinds[9]" in vrl


# ---------------------------------------------------------------------------
# Field ref mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field,vrl_field", [
    ("@Agent",       ".agent"),
    ("@AlertGroup",  ".alert_group"),
    ("@AlertKey",    ".alert_key"),
    ("@Summary",     ".summary"),
    ("@Severity",    ".severity"),
    ("@Node",        ".node"),
    ("@NodeAlias",   ".node_alias"),
    ("@Manager",     ".manager"),
    ("@Identifier",  ".identifier"),
])
def test_field_ref_in_assignment(field: str, vrl_field: str):
    vrl = gen(f'{field} = "x"')
    assert f'{vrl_field} = "x"' in vrl


# ---------------------------------------------------------------------------
# match() → VRL conditions
# ---------------------------------------------------------------------------

def test_match_exact_string():
    vrl = gen('if(match(@Manager, "SNMP")) { @Severity = 3 }')
    assert '.manager == "SNMP"' in vrl


def test_match_pipe_alternatives():
    vrl = gen('if(match(@AlertKey, "linkDown|linkUp")) {}')
    assert '.alert_key == "linkDown"' in vrl
    assert '.alert_key == "linkUp"' in vrl
    assert "||" in vrl


def test_match_regex():
    vrl = gen('if(match(@Summary, regex(".*[Dd]own.*"))) {}')
    assert "match(.summary, r'.*[Dd]own.*')" in vrl


def test_match_wildcard_prefix():
    vrl = gen('if(match(@Node, "host*")) {}')
    assert 'starts_with(.node, "host")' in vrl


def test_match_wildcard_suffix():
    vrl = gen('if(match(@Node, "*host")) {}')
    assert 'ends_with(.node, "host")' in vrl


def test_match_wildcard_contains():
    vrl = gen('if(match(@Summary, "*down*")) {}')
    assert 'contains(.summary, "down")' in vrl


def test_match_wildcard_any():
    vrl = gen('if(match(@Manager, "*")) {}')
    assert "is_string(.manager)" in vrl


# ---------------------------------------------------------------------------
# Logical operators
# ---------------------------------------------------------------------------

def test_and_operator():
    vrl = gen('if(@SpecificTrap == 1 && match(@Manager, "SNMP")) {}')
    assert "&&" in vrl


def test_or_operator():
    vrl = gen('if(match(@Manager, "SNMP") || match(@Manager, "SNMP2")) {}')
    assert "||" in vrl


def test_not_operator():
    vrl = gen('if(!match(@Manager, "SNMP")) {}')
    assert "!" in vrl


# ---------------------------------------------------------------------------
# Comparison operators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("op", ["==", "!=", "<", ">", "<=", ">="])
def test_comparison_operator(op: str):
    vrl = gen(f'if(@Severity {op} 3) {{}}')
    assert op in vrl


# ---------------------------------------------------------------------------
# if/else
# ---------------------------------------------------------------------------

def test_if_block():
    vrl = gen('if(match(@Manager, "SNMP")) { @Severity = 3 }')
    assert "if " in vrl
    assert "{" in vrl
    assert ".severity = 3" in vrl


def test_else_block():
    vrl = gen("""
    if(@SpecificTrap == 1) {
        @Severity = 2
    } else {
        @Severity = 3
    }
    """)
    assert "} else {" in vrl


def test_nested_if():
    vrl = gen("""
    if(match(@Manager, "SNMP")) {
        if(match(@Identifier, "snmpTraps 3")) {
            @Severity = 4
        }
    }
    """)
    lines = vrl.split("\n")
    # Inner if should be indented more than outer
    outer_if = next(i for i, l in enumerate(lines) if "if " in l)
    inner_if = next(
        i for i, l in enumerate(lines[outer_if + 1:], outer_if + 1)
        if "if " in l
    )
    outer_indent = len(lines[outer_if]) - len(lines[outer_if].lstrip())
    inner_indent = len(lines[inner_if]) - len(lines[inner_if].lstrip())
    assert inner_indent > outer_indent


# ---------------------------------------------------------------------------
# Lookup table
# ---------------------------------------------------------------------------

def test_lookup_assignment():
    vrl = gen("@Severity = lookup(@traptype, sev_table)")
    assert 'get_enrichment_table_record("sev_table"' in vrl
    assert '"key": .traptype' in vrl
    assert "if _err == null" in vrl


# ---------------------------------------------------------------------------
# Include directive
# ---------------------------------------------------------------------------

def test_include_becomes_comment():
    vrl = gen('include "$OMNIHOME/probes/snmptrap.rules"')
    assert "include" in vrl
    assert "#" in vrl


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

def test_comment_preserved():
    vrl = gen("# This is a comment")
    assert "# This is a comment" in vrl


def test_todo_comment_for_unknown():
    """Unknown constructs should produce TODO comments, not exceptions."""
    prog_text = "@Summary = lookup(@traptype, sev_table)"
    vrl = gen(prog_text)
    # Should not raise; lookup gets a TODO if unrecognized or renders correctly
    assert vrl  # non-empty


# ---------------------------------------------------------------------------
# VRL tail dot
# ---------------------------------------------------------------------------

def test_vrl_ends_with_dot():
    vrl = gen('@Severity = 3')
    stripped = vrl.rstrip("\n")
    assert stripped.endswith(".")


# ---------------------------------------------------------------------------
# Integration: generate VRL from sample.rules fixture
# ---------------------------------------------------------------------------

def test_generate_from_sample_rules():
    fixture = FIXTURES / "sample.rules"
    from rules2vrl.ast.parser import parse_rules_file
    prog = parse_rules_file(fixture)
    codegen = VrlCodegen()
    vrl = codegen.generate(prog)

    # Core expected translations
    assert '.manager == "SNMP"' in vrl
    assert '.identifier == "snmpTraps 3"' in vrl
    assert '.alert_group = "IF-MIB"' in vrl
    assert '.alert_key = "linkDown"' in vrl
    assert ".severity = 3" in vrl
    assert "._class = 30" in vrl
    assert "_ifIndex = .varbinds[0]" in vrl
    assert "_ifAdminStatus = .varbinds[1]" in vrl

    # Regex match
    assert "match(.summary, r'.*[Dd]own.*')" in vrl

    # Multi-alternative
    assert ".alert_key" in vrl
    assert "||" in vrl

    # Concat
    assert '.node' in vrl


# ---------------------------------------------------------------------------
# VrlCodegen options
# ---------------------------------------------------------------------------

def test_include_todos_false():
    prog = parse_rules('include "$OMNIHOME/probes/snmptrap.rules"')
    vrl = VrlCodegen(include_todos=False).generate(prog)
    # With include_todos=False, TODO comments should be suppressed
    # The include still generates a regular comment (not a TODO)
    assert "include" in vrl


def test_indent_size():
    vrl = gen('if(match(@Manager, "SNMP")) { @Severity = 3 }')
    # Default indent is 4 spaces
    assert "    .severity" in vrl


# ---------------------------------------------------------------------------
# switch/case → if/else-if chain
# ---------------------------------------------------------------------------

def test_switch_single_case():
    vrl = gen('switch($specific-trap) { case "1": @Severity = 3 }')
    assert '_specific_trap == "1"' in vrl
    assert ".severity = 3" in vrl


def test_switch_multiple_cases():
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
    vrl = gen(text)
    assert '_specific_trap == "1"' in vrl
    assert '.alert_key = "acctngFileNearlyFull"' in vrl
    assert ".severity = 3" in vrl
    assert "} else if" in vrl
    assert '_specific_trap == "2"' in vrl
    assert '.alert_key = "acctngFileFull"' in vrl
    assert ".severity = 5" in vrl


def test_switch_closes_brace():
    vrl = gen('switch($x) { case "1": @Severity = 3 }')
    # Ensure there's a closing brace for the if block
    assert vrl.count("{") == vrl.count("}")


# ---------------------------------------------------------------------------
# log() → VRL comment
# ---------------------------------------------------------------------------

def test_log_call_becomes_vrl_comment():
    vrl = gen('log(DEBUG, "some message string")')
    assert "# log:" in vrl
    assert "some message string" in vrl


# ---------------------------------------------------------------------------
# switch default: → else block
# ---------------------------------------------------------------------------

def test_switch_with_default():
    text = '''
    switch($specific-trap) {
        case "1": @Severity = 3
        default:
            @Severity = 1
    }
    '''
    vrl = gen(text)
    assert '_specific_trap == "1"' in vrl
    assert ".severity = 3" in vrl
    assert "} else {" in vrl
    assert ".severity = 1" in vrl


def test_switch_with_default_brace_balance():
    text = 'switch($x) { case "1": @Severity = 3 default: @Severity = 1 }'
    vrl = gen(text)
    assert vrl.count("{") == vrl.count("}")


def test_switch_default_only_emits_flat():
    """A switch with only a default: emits the body without an if wrapper."""
    vrl = gen('switch($x) { default: @Severity = 1 }')
    assert ".severity = 1" in vrl


# ---------------------------------------------------------------------------
# $* wildcard varbind → .varbinds
# ---------------------------------------------------------------------------

def test_wildcard_varbind_in_expression():
    vrl = gen('@Summary = $*')
    assert '.summary = .varbinds' in vrl


# ---------------------------------------------------------------------------
# details($*) → comment
# ---------------------------------------------------------------------------

def test_details_call_becomes_comment():
    vrl = gen('details($*)')
    assert "# details:" in vrl


# ---------------------------------------------------------------------------
# exists() → VRL exists()
# ---------------------------------------------------------------------------

def test_exists_in_if_condition():
    vrl = gen('if(exists($SEV_KEY)) { @Severity = 3 }')
    assert "exists(_SEV_KEY)" in vrl
    assert ".severity = 3" in vrl


# ---------------------------------------------------------------------------
# DestructureAssignNode → indexed array access block
# ---------------------------------------------------------------------------

def test_destructure_codegen():
    text = '[$OS_Severity,$OS_Type,$OS_ExpireTime] = lookup($SEV_KEY, sev_table)'
    vrl = gen(text)
    assert 'get_enrichment_table_record("sev_table"' in vrl
    assert '"key": _SEV_KEY' in vrl
    assert "_lookup_result != null" in vrl
    assert "_OS_Severity = _lookup_result[0]" in vrl
    assert "_OS_Type = _lookup_result[1]" in vrl
    assert "_OS_ExpireTime = _lookup_result[2]" in vrl


def test_destructure_brace_balance():
    vrl = gen('[$x,$y] = lookup($key, t)')
    assert vrl.count("{") == vrl.count("}")


def test_destructure_with_hyphened_table():
    """Table names with hyphens (real Cisco pattern) are preserved verbatim."""
    text = '[$OS_Sev] = lookup($SEV_KEY, cisco-ACL-MIB_sev)'
    vrl = gen(text)
    assert 'get_enrichment_table_record("cisco-ACL-MIB_sev"' in vrl


# ---------------------------------------------------------------------------
# ExtractNode → capture()[0] ?? ""
# ---------------------------------------------------------------------------

def test_extract_function_codegen():
    vrl = gen(r'@Summary = extract($OID1, "\.([0-9]+)$")')
    assert "capture(_OID1" in vrl
    assert r"r'\.([0-9]+)$'" in vrl
    assert '[0] ?? ""' in vrl


def test_extract_in_concatenation():
    vrl = gen('@OS_LocalPriObj = "prefix" + extract($OID1, "pattern")')
    assert ".os_local_pri_obj" in vrl
    assert "capture(_OID1" in vrl
    assert "r'pattern'" in vrl
    assert '[0] ?? ""' in vrl


def test_extract_field_source():
    """extract() with an @Field source."""
    vrl = gen('@Summary = extract(@AlertKey, "pat")')
    assert "capture(.alert_key" in vrl


# ---------------------------------------------------------------------------
# case "val1"|"val2": — OR condition in switch
# ---------------------------------------------------------------------------

def test_case_with_pipe_alternatives():
    text = '''
    switch($x) {
        case ".1.3.6.1.4.1.9.9.216.2"|".1.3.6.1.4.1.9.9.99999.2":
            @Severity = 3
    }
    '''
    vrl = gen(text)
    assert '_x == ".1.3.6.1.4.1.9.9.216.2"' in vrl
    assert '_x == ".1.3.6.1.4.1.9.9.99999.2"' in vrl
    assert "||" in vrl
    assert ".severity = 3" in vrl


def test_case_pipe_codegen_brace_balance():
    vrl = gen('switch($x) { case "a"|"b": @Severity = 1 }')
    assert vrl.count("{") == vrl.count("}")


def test_case_single_value_unchanged():
    """Single-value cases still emit simple == condition."""
    vrl = gen('switch($x) { case "1": @Severity = 3 }')
    assert '_x == "1"' in vrl
    assert "||" not in vrl


# ---------------------------------------------------------------------------
# match() / regmatch() with varbind sources
# ---------------------------------------------------------------------------

def test_match_with_varbind_argument():
    vrl = gen('if(match($1, "0")) { @Severity = 1 }')
    assert ".varbinds[0] == \"0\"" in vrl


def test_match_varbind_pipe_alternatives():
    vrl = gen('if(match($1, "up|down")) { @Severity = 1 }')
    assert '.varbinds[0] == "up"' in vrl
    assert '.varbinds[0] == "down"' in vrl
    assert "||" in vrl


def test_regmatch_function():
    vrl = gen('if(regmatch($3, "^ap:")) { @Severity = 2 }')
    assert "match(.varbinds[2], r'^ap:')" in vrl


def test_match_varbind_regex_autodetect():
    vrl = gen('if(match($1, "^prefix")) { @Severity = 3 }')
    assert "match(.varbinds[0], r'^prefix')" in vrl


def test_match_named_varbind_literal():
    vrl = gen('if(match($ifOperStatus, "1")) {}')
    assert '_ifOperStatus == "1"' in vrl


# ---------------------------------------------------------------------------
# Unknown character resilience (FIX 3)
# ---------------------------------------------------------------------------

def test_unknown_char_does_not_abort_codegen():
    """Rules with stray unknown chars produce VRL output, not exceptions."""
    vrl = gen("@Severity = 3 ~ @Class = 30")
    assert ".severity" in vrl  # first assignment present


# ---------------------------------------------------------------------------
# Arithmetic operators (*, -, /)
# ---------------------------------------------------------------------------

def test_multiplication():
    vrl = gen('@Grade = int($1) * 4294967296')
    assert "to_int!(.varbinds[0]) * 4294967296" in vrl


def test_subtraction():
    vrl = gen('@Diff = int($1) - int($2)')
    assert "to_int!(.varbinds[0]) - to_int!(.varbinds[1])" in vrl


def test_bitwise_amp_emits_todo():
    vrl = gen('$x = int($2) & 2')
    assert "TODO" in vrl
    assert "bitwise" in vrl


# ---------------------------------------------------------------------------
# substr() function call
# ---------------------------------------------------------------------------

def test_substr_static_args():
    vrl = gen('@Summary = substr($HexVal, 1, 5)')
    assert "slice!(_HexVal, 1, 6)" in vrl


# ---------------------------------------------------------------------------
# switch with comment before brace
# ---------------------------------------------------------------------------

def test_switch_comment_before_brace():
    text = 'switch($x) ### comment\n{ case "1": @Severity = 3 }'
    vrl = gen(text)
    assert ".severity = 3" in vrl


# ---------------------------------------------------------------------------
# else with comment before if or brace
# ---------------------------------------------------------------------------

def test_else_comment_before_brace():
    text = 'if(@Severity == 5) { @Severity = 3 } else ### comment\n{ @Severity = 1 }'
    vrl = gen(text)
    assert "} else {" in vrl
    assert ".severity = 1" in vrl


# ---------------------------------------------------------------------------
# $3_hex named varbind (digit-prefixed)
# ---------------------------------------------------------------------------

def test_digit_prefixed_named_varbind():
    vrl = gen('if(exists($3_hex)) { @Severity = 3 }')
    assert "exists(_3_hex)" in vrl


# ---------------------------------------------------------------------------
# lookup($N, table) — positional varbind key
# ---------------------------------------------------------------------------

def test_lookup_positional_varbind_key():
    vrl = gen('$x = lookup($3, myTable)')
    assert 'get_enrichment_table_record("myTable"' in vrl
    assert '"key": .varbinds[2]' in vrl


# ---------------------------------------------------------------------------
# else if (without braces) → compact } else if in VRL
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
    vrl = gen(text)
    assert "} else if" in vrl
    assert ".severity = 5" in vrl
    assert ".severity = 3" in vrl


def test_else_if_no_braces():
    vrl = gen('if(@Severity == 5) { @Severity = 3 } else if(@Severity == 3) { @Severity = 1 }')
    assert "} else if" in vrl
    assert vrl.count("{") == vrl.count("}")


def test_else_if_three_levels_brace_balance():
    text = '''
    if(@Severity == 5) { @Severity = 3 }
    else if(@Severity == 3) { @Severity = 2 }
    else if(@Severity == 2) { @Severity = 1 }
    '''
    vrl = gen(text)
    assert vrl.count("{") == vrl.count("}")
    assert vrl.count("} else if") == 2


def test_else_if_with_final_else():
    text = """
    if(@Severity == 5) { @Severity = 3 }
    else if(@Severity == 3) { @Severity = 2 }
    else { @Severity = 1 }
    """
    vrl = gen(text)
    assert "} else if" in vrl
    assert "} else {" in vrl
    assert vrl.count("{") == vrl.count("}")


# ---------------------------------------------------------------------------
# CastNode — int() / str() / float()
# ---------------------------------------------------------------------------

def test_int_cast_varbind():
    vrl = gen('@Severity = int($1)')
    assert "to_int!(.varbinds[0])" in vrl


def test_str_cast_field():
    vrl = gen('@Summary = str(@Severity)')
    assert "to_string!(.severity)" in vrl


def test_float_cast():
    vrl = gen('@Grade = float($1)')
    assert "to_float!(.varbinds[0])" in vrl


def test_cast_in_comparison():
    vrl = gen('if(int($1) < 10) { @Severity = 3 }')
    assert "to_int!(.varbinds[0]) < 10" in vrl
    assert ".severity = 3" in vrl


# ---------------------------------------------------------------------------
# match($var, $var) — variable pattern → equality
# ---------------------------------------------------------------------------

def test_match_varbind_vs_varbind():
    vrl = gen('if(match($2, $3)) {}')
    assert ".varbinds[1] == .varbinds[2]" in vrl


def test_match_varbind_vs_named_varbind():
    vrl = gen('if(match($2, $myVar)) {}')
    assert ".varbinds[1] == _myVar" in vrl


# ---------------------------------------------------------------------------
# TrimNode — ltrim / rtrim / trim
# ---------------------------------------------------------------------------

def test_ltrim():
    vrl = gen('@Summary = ltrim($1)')
    assert 'strip_whitespace(.varbinds[0], "left")' in vrl


def test_rtrim():
    vrl = gen('@Summary = rtrim($1)')
    assert 'strip_whitespace(.varbinds[0], "right")' in vrl


def test_trim_codegen():
    vrl = gen('@Summary = trim(@Agent)')
    assert "strip_whitespace(.agent)" in vrl


def test_ltrim_nested_extract():
    vrl = gen('@Summary = ltrim(extract($OID1, "pattern"))')
    assert 'strip_whitespace(capture(_OID1' in vrl


# ---------------------------------------------------------------------------
# BUG 2 — Comment between if() and {
# ---------------------------------------------------------------------------

def test_if_comment_before_lbrace():
    vrl = gen('if(exists($OID7))\n### comment\n{\n@Severity = 3\n}')
    assert "exists(_OID7)" in vrl
    assert ".severity = 3" in vrl


# ---------------------------------------------------------------------------
# BUG 3 — Positional varbind as LHS ($1 = value)
# ---------------------------------------------------------------------------

def test_varbind_lhs_assignment():
    vrl = gen('$1 = $IPv4addr')
    assert ".varbinds[0] = _IPv4addr" in vrl


# ---------------------------------------------------------------------------
# BUG 4 — int() cast on both sides of comparison
# ---------------------------------------------------------------------------

def test_int_cast_both_sides_comparison():
    vrl = gen('if(int($ciscoPingSentPackets) == int($ciscoPingReceivedPackets)) {}')
    assert "to_int!(_ciscoPingSentPackets) == to_int!(_ciscoPingReceivedPackets)" in vrl
