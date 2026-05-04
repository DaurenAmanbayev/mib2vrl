"""
lexer.py — Tokenizer for the Netcool probe rules DSL.

Reads .rules text and returns a list of Token objects.
Uses a single compiled master regex with named groups so that each
alternative maps directly to a TokenType without a dispatch table.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from rules2vrl.lexer.tokens import TokenType


@dataclass(frozen=True)
class Token:
    """A single lexical token."""
    type: TokenType
    value: str
    line: int
    col: int

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, line={self.line})"


class LexerError(Exception):
    pass


# ---------------------------------------------------------------------------
# Master regex
# Groups must be ordered by specificity: longer/more-specific patterns first.
# ---------------------------------------------------------------------------

_MASTER_RE = re.compile(
    r'(?P<WHITESPACE>[ \t\r\n]+)'
    r'|(?P<COMMENT>#[^\n]*)'
    r'|(?P<STRING>"(?:[^"\\]|\\.|\n)*?")'   # multiline strings (non-greedy)
    r'|(?P<AND>&&)'
    r'|(?P<OR>\|\|)'
    r'|(?P<PIPE>\|)'
    r'|(?P<EQ>==)'
    r'|(?P<NEQ>!=)'
    r'|(?P<LEQ><=)'
    r'|(?P<GEQ>>=)'
    r'|(?P<ASSIGN>=)'
    r'|(?P<LT><)'
    r'|(?P<GT>>)'
    r'|(?P<NOT>!)'
    r'|(?P<PLUS>\+)'
    r'|(?P<MINUS>-)'
    r'|(?P<STAR>\*)'
    r'|(?P<SLASH>/)'
    r'|(?P<PERCENT>%)'
    r'|(?P<AMP>&)'
    r'|(?P<LBRACE>\{)'
    r'|(?P<RBRACE>\})'
    r'|(?P<LBRACKET>\[)'
    r'|(?P<RBRACKET>\])'
    r'|(?P<LPAREN>\()'
    r'|(?P<RPAREN>\))'
    r'|(?P<COMMA>,)'
    r'|(?P<SEMICOLON>;)'
    r'|(?P<COLON>:)'
    r'|(?P<FIELD>@[a-zA-Z_][a-zA-Z0-9_-]*)'
    r'|(?P<VARBIND_WILDCARD>\$\*)'
    r'|(?P<NAMED_VARBIND>\$(?:[0-9]+[a-zA-Z_]|[a-zA-Z_])[a-zA-Z0-9_-]*)'
    r'|(?P<VARBIND>\$[0-9]+)'
    r'|(?P<NUMBER>[0-9]+(?:\.[0-9]+)?)'
    r'|(?P<IDENT>[a-zA-Z_][a-zA-Z0-9_\-]*)',
    re.DOTALL,
)

_KEYWORDS: dict[str, TokenType] = {
    "if":      TokenType.IF,
    "else":    TokenType.ELSE,
    "match":   TokenType.MATCH,
    "lookup":  TokenType.LOOKUP,
    "regex":   TokenType.REGEX,
    "include": TokenType.INCLUDE,
    "table":   TokenType.TABLE,
    "default": TokenType.DEFAULT,
    "switch":  TokenType.SWITCH,
    "case":    TokenType.CASE,
}

# Map group name → TokenType (None means skip/whitespace)
_GROUP_TO_TYPE: dict[str, TokenType | None] = {
    "WHITESPACE":    None,
    "COMMENT":       TokenType.COMMENT,
    "STRING":        TokenType.STRING,
    "AND":           TokenType.AND,
    "OR":            TokenType.OR,
    "PIPE":          TokenType.PIPE,
    "EQ":            TokenType.EQ,
    "NEQ":           TokenType.NEQ,
    "LEQ":           TokenType.LEQ,
    "GEQ":           TokenType.GEQ,
    "ASSIGN":        TokenType.ASSIGN,
    "LT":            TokenType.LT,
    "GT":            TokenType.GT,
    "NOT":           TokenType.NOT,
    "PLUS":          TokenType.PLUS,
    "MINUS":         TokenType.MINUS,
    "STAR":          TokenType.STAR,
    "SLASH":         TokenType.SLASH,
    "PERCENT":       TokenType.PERCENT,
    "AMP":           TokenType.AMP,
    "LBRACE":        TokenType.LBRACE,
    "RBRACE":        TokenType.RBRACE,
    "LBRACKET":      TokenType.LBRACKET,
    "RBRACKET":      TokenType.RBRACKET,
    "LPAREN":        TokenType.LPAREN,
    "RPAREN":        TokenType.RPAREN,
    "COMMA":         TokenType.COMMA,
    "SEMICOLON":     TokenType.SEMICOLON,
    "COLON":         TokenType.COLON,
    "FIELD":            TokenType.FIELD,
    "VARBIND_WILDCARD": TokenType.VARBIND_WILDCARD,
    "VARBIND":          TokenType.VARBIND,
    "NAMED_VARBIND":    TokenType.NAMED_VARBIND,
    "NUMBER":        TokenType.NUMBER,
    "IDENT":         TokenType.IDENT,
}


def tokenize(text: str, source: str = "<input>") -> list[Token]:
    """
    Tokenize Netcool rules text.

    Returns a list of Token objects ending with a single EOF token.
    Raises LexerError on characters that cannot be matched.
    """
    tokens: list[Token] = []
    pos = 0
    line = 1
    line_start = 0
    length = len(text)

    while pos < length:
        m = _MASTER_RE.match(text, pos)
        if m is None:
            col = pos - line_start + 1
            char = text[pos]
            tokens.append(Token(type=TokenType.UNKNOWN, value=char, line=line, col=col))
            pos += 1
            continue

        group_name = m.lastgroup
        assert group_name is not None
        value = m.group()
        col = pos - line_start + 1
        tok_line = line

        # Advance line tracking before moving pos
        newlines = value.count("\n")
        if newlines:
            line += newlines
            line_start = pos + value.rfind("\n") + 1

        pos = m.end()

        ttype = _GROUP_TO_TYPE[group_name]
        if ttype is None:
            continue  # whitespace

        if ttype == TokenType.IDENT:
            ttype = _KEYWORDS.get(value, TokenType.IDENT)

        tokens.append(Token(type=ttype, value=value, line=tok_line, col=col))

    tokens.append(Token(type=TokenType.EOF, value="", line=line, col=0))
    return tokens
