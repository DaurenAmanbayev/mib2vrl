"""
test_lexer.py — Tests for the Netcool rules DSL lexer.

Every TokenType is tested with at least one representative example.
"""

import pytest

from rules2vrl.lexer.tokens import TokenType
from rules2vrl.lexer.lexer import Token, LexerError, tokenize


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def tok_types(text: str) -> list[TokenType]:
    """Return token types (excluding EOF) for text."""
    return [t.type for t in tokenize(text) if t.type != TokenType.EOF]


def tok_values(text: str) -> list[str]:
    return [t.value for t in tokenize(text) if t.type != TokenType.EOF]


# ---------------------------------------------------------------------------
# Keywords
# ---------------------------------------------------------------------------

def test_keyword_if():
    assert tok_types("if") == [TokenType.IF]

def test_keyword_else():
    assert tok_types("else") == [TokenType.ELSE]

def test_keyword_match():
    assert tok_types("match") == [TokenType.MATCH]

def test_keyword_lookup():
    assert tok_types("lookup") == [TokenType.LOOKUP]

def test_keyword_regex():
    assert tok_types("regex") == [TokenType.REGEX]

def test_keyword_include():
    assert tok_types("include") == [TokenType.INCLUDE]

def test_keyword_table():
    assert tok_types("table") == [TokenType.TABLE]

def test_keyword_default():
    assert tok_types("default") == [TokenType.DEFAULT]

def test_keyword_switch():
    assert tok_types("switch") == [TokenType.SWITCH]

def test_keyword_case():
    assert tok_types("case") == [TokenType.CASE]


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

def test_and_operator():
    assert tok_types("&&") == [TokenType.AND]

def test_or_operator():
    assert tok_types("||") == [TokenType.OR]

def test_not_operator():
    assert tok_types("!") == [TokenType.NOT]

def test_eq_operator():
    assert tok_types("==") == [TokenType.EQ]

def test_neq_operator():
    assert tok_types("!=") == [TokenType.NEQ]

def test_leq_operator():
    assert tok_types("<=") == [TokenType.LEQ]

def test_geq_operator():
    assert tok_types(">=") == [TokenType.GEQ]

def test_assign_operator():
    assert tok_types("=") == [TokenType.ASSIGN]

def test_lt_operator():
    assert tok_types("<") == [TokenType.LT]

def test_gt_operator():
    assert tok_types(">") == [TokenType.GT]

def test_plus_operator():
    assert tok_types("+") == [TokenType.PLUS]

def test_assign_not_confused_with_eq():
    """Single = must not be tokenized as == even when adjacent tokens are =."""
    tokens = tok_types("= =")
    assert tokens == [TokenType.ASSIGN, TokenType.ASSIGN]

def test_eq_two_chars():
    tokens = tok_types("==")
    assert tokens == [TokenType.EQ]


# ---------------------------------------------------------------------------
# Delimiters
# ---------------------------------------------------------------------------

def test_braces():
    assert tok_types("{}") == [TokenType.LBRACE, TokenType.RBRACE]

def test_lbracket_rbracket_tokens():
    assert tok_types("[]") == [TokenType.LBRACKET, TokenType.RBRACKET]

def test_brackets_in_context():
    types = tok_types("[$x,$y]")
    assert types[0] == TokenType.LBRACKET
    assert types[-1] == TokenType.RBRACKET

def test_parens():
    assert tok_types("()") == [TokenType.LPAREN, TokenType.RPAREN]

def test_comma():
    assert tok_types(",") == [TokenType.COMMA]

def test_semicolon():
    assert tok_types(";") == [TokenType.SEMICOLON]

def test_colon():
    assert tok_types(":") == [TokenType.COLON]


# ---------------------------------------------------------------------------
# Literals
# ---------------------------------------------------------------------------

def test_string_simple():
    tokens = tokenize('"hello"')
    t = tokens[0]
    assert t.type == TokenType.STRING
    assert t.value == '"hello"'

def test_string_with_spaces():
    toks = tok_types('"hello world"')
    assert toks == [TokenType.STRING]

def test_string_multiline():
    text = '"line one\nline two"'
    toks = tok_types(text)
    assert toks == [TokenType.STRING]

def test_string_with_escape():
    text = r'"line with \"quote\""'
    toks = tok_types(text)
    assert toks == [TokenType.STRING]

def test_number_integer():
    tokens = tokenize("42")
    assert tokens[0].type == TokenType.NUMBER
    assert tokens[0].value == "42"

def test_number_float():
    tokens = tokenize("3.14")
    assert tokens[0].type == TokenType.NUMBER
    assert tokens[0].value == "3.14"

def test_number_zero():
    assert tok_types("0") == [TokenType.NUMBER]


# ---------------------------------------------------------------------------
# References
# ---------------------------------------------------------------------------

def test_field_ref():
    tokens = tokenize("@Manager")
    assert tokens[0].type == TokenType.FIELD
    assert tokens[0].value == "@Manager"

def test_field_ref_underscore():
    tokens = tokenize("@AlertKey")
    assert tokens[0].type == TokenType.FIELD

def test_varbind_one():
    tokens = tokenize("$1")
    assert tokens[0].type == TokenType.VARBIND
    assert tokens[0].value == "$1"

def test_varbind_large():
    tokens = tokenize("$23")
    assert tokens[0].type == TokenType.VARBIND
    assert tokens[0].value == "$23"

def test_named_varbind():
    tokens = tokenize("$ifIndex")
    assert tokens[0].type == TokenType.NAMED_VARBIND
    assert tokens[0].value == "$ifIndex"

def test_named_varbind_underscore():
    tokens = tokenize("$my_var")
    assert tokens[0].type == TokenType.NAMED_VARBIND

def test_named_varbind_with_hyphen():
    tokens = tokenize("$specific-trap")
    assert tokens[0].type == TokenType.NAMED_VARBIND
    assert tokens[0].value == "$specific-trap"

def test_varbind_wildcard_token():
    tokens = tokenize("$*")
    assert tokens[0].type == TokenType.VARBIND_WILDCARD
    assert tokens[0].value == "$*"

def test_varbind_wildcard_not_named_varbind():
    """$* must not be swallowed by NAMED_VARBIND or split into $ + *."""
    types = [t.type for t in tokenize("$*") if t.type != TokenType.EOF]
    assert types == [TokenType.VARBIND_WILDCARD]


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------

def test_ident_simple():
    tokens = tokenize("sev_table")
    assert tokens[0].type == TokenType.IDENT

def test_ident_with_hyphen():
    tokens = tokenize("snmp-trap")
    assert tokens[0].type == TokenType.IDENT

def test_ident_with_hyphen_middle():
    tokens = tokenize("Alert-Group")
    assert tokens[0].type == TokenType.IDENT
    assert tokens[0].value == "Alert-Group"

def test_field_with_hyphen():
    tokens = tokenize("@Alert-Group")
    assert tokens[0].type == TokenType.FIELD
    assert tokens[0].value == "@Alert-Group"

def test_ident_not_keyword():
    tokens = tokenize("manager_name")
    assert tokens[0].type == TokenType.IDENT


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------

def test_comment_single():
    tokens = tokenize("# this is a comment")
    assert tokens[0].type == TokenType.COMMENT

def test_comment_hash_sequence():
    text = "##############################\n# real comment\n"
    types = tok_types(text)
    assert all(t == TokenType.COMMENT for t in types)

def test_comment_inline():
    text = "@Severity = 3 # set severity"
    types = tok_types(text)
    assert TokenType.COMMENT in types


# ---------------------------------------------------------------------------
# Line tracking
# ---------------------------------------------------------------------------

def test_line_numbers():
    text = "if\n(\n@Manager\n)"
    tokens = [t for t in tokenize(text) if t.type != TokenType.EOF]
    lines = [t.line for t in tokens]
    assert lines == [1, 2, 3, 4]


# ---------------------------------------------------------------------------
# Whitespace handling
# ---------------------------------------------------------------------------

def test_whitespace_skipped():
    types = tok_types("  \t  \n  ")
    assert types == []

def test_mixed_whitespace():
    types = tok_types("if  (  @Manager  ==  \"SNMP\"  )")
    assert types == [
        TokenType.IF, TokenType.LPAREN,
        TokenType.FIELD, TokenType.EQ, TokenType.STRING,
        TokenType.RPAREN,
    ]


# ---------------------------------------------------------------------------
# Real rules snippets
# ---------------------------------------------------------------------------

def test_field_assignment_snippet():
    text = '@AlertGroup = "IF-MIB"'
    types = tok_types(text)
    assert types == [TokenType.FIELD, TokenType.ASSIGN, TokenType.STRING]

def test_if_match_snippet():
    text = 'if(match(@Identifier, "snmpTraps 3"))'
    types = tok_types(text)
    assert types == [
        TokenType.IF, TokenType.LPAREN,
        TokenType.MATCH, TokenType.LPAREN,
        TokenType.FIELD, TokenType.COMMA, TokenType.STRING,
        TokenType.RPAREN, TokenType.RPAREN,
    ]

def test_varbind_assignment_snippet():
    text = "$ifIndex = $1"
    types = tok_types(text)
    assert types == [TokenType.NAMED_VARBIND, TokenType.ASSIGN, TokenType.VARBIND]

def test_include_snippet():
    text = 'include "$OMNIHOME/probes/solaris2/include/snmptrap.rules"'
    types = tok_types(text)
    assert types == [TokenType.INCLUDE, TokenType.STRING]

def test_regex_match_snippet():
    text = 'match(@Summary, regex(".*[Dd]own.*"))'
    types = tok_types(text)
    assert types == [
        TokenType.MATCH, TokenType.LPAREN,
        TokenType.FIELD, TokenType.COMMA,
        TokenType.REGEX, TokenType.LPAREN, TokenType.STRING, TokenType.RPAREN,
        TokenType.RPAREN,
    ]

def test_severity_number():
    text = "@Severity = 3"
    values = tok_values(text)
    assert values == ["@Severity", "=", "3"]

def test_eof_token():
    tokens = tokenize("")
    assert tokens[-1].type == TokenType.EOF


# ---------------------------------------------------------------------------
# PIPE token
# ---------------------------------------------------------------------------

def test_pipe_single():
    assert tok_types("|") == [TokenType.PIPE]

def test_pipe_not_confused_with_or():
    """Single | must be PIPE; double || must be OR."""
    types = tok_types("| ||")
    assert types == [TokenType.PIPE, TokenType.OR]

def test_pipe_between_strings():
    types = tok_types('"a"|"b"')
    assert types == [TokenType.STRING, TokenType.PIPE, TokenType.STRING]


# ---------------------------------------------------------------------------
# UNKNOWN token (lexer resilience)
# ---------------------------------------------------------------------------

def test_unknown_char_emits_unknown_token():
    """Unrecognised characters produce UNKNOWN tokens, not exceptions."""
    tokens = tokenize("@Severity = 3 ~ 1")
    types = [t.type for t in tokens if t.type != TokenType.EOF]
    assert TokenType.UNKNOWN in types

def test_unknown_char_does_not_abort():
    """Lexer continues after an unknown character."""
    tokens = tokenize("~ @Severity = 3")
    field_tok = next((t for t in tokens if t.type == TokenType.FIELD), None)
    assert field_tok is not None
    assert field_tok.value == "@Severity"
