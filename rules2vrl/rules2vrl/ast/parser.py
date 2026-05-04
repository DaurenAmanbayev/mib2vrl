"""
parser.py — Recursive-descent parser for the Netcool probe rules DSL.

Token stream → AST.

Grammar (informal):
  program         := statement* EOF
  statement       := include_stmt
                   | if_stmt
                   | switch_stmt
                   | assignment_stmt
                   | table_stmt          (in .lookup files)
                   | default_stmt        (in .lookup files)
                   | log_call            (skipped → comment)
                   | details_call        (skipped → comment)
                   | comment_stmt
  include_stmt    := INCLUDE STRING
  if_stmt         := IF LPAREN condition RPAREN LBRACE statement* RBRACE
                     (ELSE LBRACE statement* RBRACE)?
  assignment_stmt := (FIELD | NAMED_VARBIND) ASSIGN expr
  destructure_stmt := LBRACKET (NAMED_VARBIND | FIELD) (COMMA (NAMED_VARBIND | FIELD))* RBRACKET ASSIGN expr
  table_stmt      := TABLE IDENT ASSIGN LBRACE table_entry* RBRACE
  table_entry     := LBRACE? STRING COMMA value RBRACE? COMMA?   (tuple fmt)
                   | STRING COLON value COMMA?                    (dict fmt)
  default_stmt    := DEFAULT ASSIGN value
  condition       := or_cond
  or_cond         := and_cond (OR and_cond)*
  and_cond        := not_cond (AND not_cond)*
  not_cond        := NOT not_cond | primary_cond
  primary_cond    := LPAREN condition RPAREN
                   | match_expr
                   | compare_expr
  match_expr      := MATCH LPAREN FIELD COMMA match_pattern RPAREN
  match_pattern   := STRING | REGEX LPAREN STRING RPAREN
  compare_expr    := (FIELD | VARBIND | NAMED_VARBIND) compare_op primary
  compare_op      := EQ | NEQ | LT | GT | LEQ | GEQ
  expr            := addend (PLUS addend)*
  addend          := FIELD | VARBIND | NAMED_VARBIND | STRING | NUMBER
                   | lookup_expr | LPAREN expr RPAREN
  lookup_expr     := LOOKUP LPAREN FIELD COMMA IDENT RPAREN
  comment_stmt    := COMMENT
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from rules2vrl.lexer.tokens import TokenType
from rules2vrl.lexer.lexer import Token, tokenize
from rules2vrl.ast.nodes import (
    Node, Program, IfBlock, SwitchNode, CaseNode,
    Assignment, DestructureAssignNode,
    MatchExpr, LookupExpr, RegexExpr, ExistsNode, ExtractNode, CastNode, TrimNode, FunctionCallNode,
    BinaryOp, UnaryOp, FieldRef, VarbindRef, WildcardVarbindNode, NamedVarbindRef,
    StringLiteral, NumberLiteral, IncludeDirective, TableDefinition, Comment,
)

logger = logging.getLogger(__name__)


class ParseError(Exception):
    pass


class Parser:
    """
    Recursive-descent parser for the Netcool rules DSL.

    Instantiate with a token list (from tokenize()), then call parse().
    Unknown constructs are skipped with a WARNING log and a Comment node
    in the AST so that the codegen can emit a TODO comment instead of
    aborting.
    """

    def __init__(self, tokens: list[Token], source: str = "<input>") -> None:
        self._tokens = tokens
        self._pos = 0
        self._source = source

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def parse(self) -> Program:
        """Parse a complete rules file, returning the root Program node."""
        body = self._parse_statements(stop_at=None)
        self._expect(TokenType.EOF)
        return Program(body=body, source_file=self._source)

    # ------------------------------------------------------------------
    # Statement dispatch
    # ------------------------------------------------------------------

    def _parse_statements(self, stop_at: TokenType | None) -> list[Node]:
        """Parse statements until stop_at token type (or EOF)."""
        stmts: list[Node] = []
        while True:
            tok = self._peek()
            if tok.type == TokenType.EOF:
                break
            if stop_at is not None and tok.type == stop_at:
                break
            stmt = self._parse_statement()
            if stmt is not None:
                stmts.append(stmt)
        return stmts

    def _parse_statement(self) -> Node | None:
        """Parse a single statement. Returns None for whitespace-only."""
        tok = self._peek()

        match tok.type:
            case TokenType.COMMENT:
                return self._parse_comment()
            case TokenType.INCLUDE:
                return self._parse_include()
            case TokenType.IF:
                return self._parse_if()
            case TokenType.SWITCH:
                return self._parse_switch()
            case TokenType.TABLE:
                return self._parse_table()
            case TokenType.DEFAULT:
                return self._parse_default_stmt()
            case TokenType.LBRACKET:
                return self._parse_destructure_assign()
            case TokenType.FIELD:
                return self._parse_assignment_or_compare()
            case TokenType.NAMED_VARBIND:
                return self._parse_named_varbind_assignment()
            case TokenType.VARBIND:
                return self._parse_varbind_assignment_or_skip()
            case TokenType.IDENT:
                if tok.value == "log":
                    return self._parse_log_call()
                if tok.value == "details":
                    return self._parse_details_call()
                # Unknown IDENT in statement position — skip with warning
                self._advance()
                logger.warning(
                    "%s:%d: unexpected IDENT %r in statement position — skipped",
                    self._source, tok.line, tok.value,
                )
                return Comment(
                    text=f"TODO: unsupported construct: {tok.value}",
                    line=tok.line,
                )
            case _:
                # Unknown token in statement position — skip with warning
                self._advance()
                logger.warning(
                    "%s:%d: unexpected token %s %r — skipped",
                    self._source, tok.line, tok.type.name, tok.value,
                )
                return Comment(
                    text=f"TODO: unsupported construct: {tok.value}",
                    line=tok.line,
                )

    # ------------------------------------------------------------------
    # Individual statement parsers
    # ------------------------------------------------------------------

    def _parse_comment(self) -> Comment:
        tok = self._advance()
        return Comment(text=tok.value[1:].strip(), line=tok.line)

    def _parse_include(self) -> IncludeDirective:
        """include "path/to/file.rules" """
        tok = self._advance()  # consume INCLUDE
        path_tok = self._expect(TokenType.STRING)
        path = _strip_quotes(path_tok.value)
        return IncludeDirective(path=path, line=tok.line)

    def _parse_if(self) -> IfBlock:
        """if (condition) { body } [else { else_body }]"""
        tok = self._advance()  # consume IF
        self._expect(TokenType.LPAREN)
        condition = self._parse_condition()
        self._expect(TokenType.RPAREN)
        # Allow comments between ) and { (real Cisco rules use this pattern)
        while self._peek().type == TokenType.COMMENT:
            self._advance()
        self._expect(TokenType.LBRACE)
        body = self._parse_statements(stop_at=TokenType.RBRACE)
        self._expect(TokenType.RBRACE)

        else_body: list[Node] | None = None
        if self._peek().type == TokenType.ELSE:
            self._advance()  # consume ELSE
            # Skip comments between else and the opening brace or if keyword
            while self._peek().type == TokenType.COMMENT:
                self._advance()
            if self._peek().type == TokenType.IF:
                # else if (...) { ... } — no braces around the nested if
                else_body = [self._parse_if()]
            else:
                self._expect(TokenType.LBRACE)
                else_body = self._parse_statements(stop_at=TokenType.RBRACE)
                self._expect(TokenType.RBRACE)

        return IfBlock(condition=condition, body=body, else_body=else_body, line=tok.line)

    def _parse_assignment_or_compare(self) -> Node:
        """@Field = expr"""
        field_tok = self._advance()  # consume FIELD
        field = FieldRef(name=field_tok.value[1:], line=field_tok.line)

        if self._peek().type == TokenType.ASSIGN:
            self._advance()  # consume =
            value = self._parse_expr()
            return Assignment(target=field, value=value, line=field_tok.line)

        # Bare field ref in statement position (e.g., stray @Field) — skip
        logger.warning(
            "%s:%d: bare field ref %r in statement position — skipped",
            self._source, field_tok.line, field_tok.value,
        )
        return Comment(
            text=f"TODO: unsupported construct: {field_tok.value}",
            line=field_tok.line,
        )

    def _parse_varbind_assignment_or_skip(self) -> Node:
        """$N = expr  (positional varbind as assignment target) or bare $N (skip)."""
        tok = self._advance()  # consume VARBIND
        if self._peek().type == TokenType.ASSIGN:
            self._advance()  # consume =
            ref = VarbindRef(index=int(tok.value[1:]) - 1, line=tok.line)
            value = self._parse_expr()
            return Assignment(target=ref, value=value, line=tok.line)
        logger.warning(
            "%s:%d: bare varbind ref %r in statement position — skipped",
            self._source, tok.line, tok.value,
        )
        return Comment(text=f"TODO: unsupported construct: {tok.value}", line=tok.line)

    def _parse_named_varbind_assignment(self) -> Assignment:
        """$name = expr"""
        tok = self._advance()  # consume NAMED_VARBIND
        ref = NamedVarbindRef(name=tok.value[1:], line=tok.line)
        self._expect(TokenType.ASSIGN)
        value = self._parse_expr()
        return Assignment(target=ref, value=value, line=tok.line)

    def _parse_destructure_assign(self) -> DestructureAssignNode:
        """[$var1, $var2, ...] = expr — multi-value destructuring."""
        tok = self._advance()  # consume LBRACKET
        targets: list[Node] = []
        while self._peek().type not in (TokenType.RBRACKET, TokenType.EOF):
            t = self._peek()
            if t.type == TokenType.NAMED_VARBIND:
                self._advance()
                targets.append(NamedVarbindRef(name=t.value[1:], line=t.line))
            elif t.type == TokenType.FIELD:
                self._advance()
                targets.append(FieldRef(name=t.value[1:], line=t.line))
            elif t.type == TokenType.COMMA:
                self._advance()
            else:
                self._advance()  # skip unexpected tokens inside brackets
        self._expect(TokenType.RBRACKET)
        self._expect(TokenType.ASSIGN)
        value = self._parse_expr()
        return DestructureAssignNode(targets=targets, value=value, line=tok.line)

    def _parse_table(self) -> TableDefinition:
        """table NAME = { entries... }"""
        tok = self._advance()  # TABLE
        name_tok = self._expect(TokenType.IDENT)
        self._expect(TokenType.ASSIGN)
        while self._peek().type == TokenType.COMMENT:
            self._advance()
        self._expect(TokenType.LBRACE)

        entries: list[tuple[str, str]] = []
        while self._peek().type not in (TokenType.RBRACE, TokenType.EOF):
            t = self._peek()
            if t.type == TokenType.COMMENT:
                self._advance()
                continue
            # Two table entry formats:
            #  {"key", value},    (tuple format)
            #  "key" : value,     (dict format from )
            if t.type == TokenType.LBRACE:
                self._advance()  # {
                key_tok = self._expect(TokenType.STRING)
                self._expect(TokenType.COMMA)
                val = self._parse_primary()
                # Optional closing brace
                if self._peek().type == TokenType.RBRACE:
                    self._advance()
            elif t.type == TokenType.STRING:
                key_tok = self._advance()
                if self._peek().type == TokenType.COMMA:
                    self._advance()  # flat tuple: "key", value (no per-entry braces)
                else:
                    self._expect(TokenType.COLON)
                val = self._parse_primary()
            else:
                self._advance()
                continue

            key = _strip_quotes(key_tok.value)
            entries.append((key, _node_to_raw(val)))
            # Optional trailing comma
            if self._peek().type == TokenType.COMMA:
                self._advance()

        self._expect(TokenType.RBRACE)

        # Optional default = value line immediately after
        default: str | None = None
        if self._peek().type == TokenType.DEFAULT:
            self._advance()
            self._expect(TokenType.ASSIGN)
            dval = self._parse_primary()
            default = _node_to_raw(dval)

        return TableDefinition(name=name_tok.value, entries=entries, default=default, line=tok.line)

    def _parse_default_stmt(self) -> Comment:
        """default = value  (standalone, outside table block)"""
        tok = self._advance()
        self._expect(TokenType.ASSIGN)
        val = self._parse_primary()
        return Comment(text=f"default = {_node_to_raw(val)}", line=tok.line)

    def _parse_switch(self) -> SwitchNode:
        """switch(expr) { case "val": statements ... [default: statements] }"""
        tok = self._advance()  # consume SWITCH
        self._expect(TokenType.LPAREN)
        expr = self._parse_primary()
        self._expect(TokenType.RPAREN)
        # Skip comments between switch expression and opening brace
        while self._peek().type == TokenType.COMMENT:
            self._advance()
        self._expect(TokenType.LBRACE)

        _SWITCH_STOP = (TokenType.CASE, TokenType.DEFAULT, TokenType.RBRACE, TokenType.EOF)

        cases: list[CaseNode] = []
        default_body: list[Node] = []

        while self._peek().type not in (TokenType.RBRACE, TokenType.EOF):
            t = self._peek()
            if t.type == TokenType.COMMENT:
                self._advance()
                continue
            if t.type == TokenType.CASE:
                self._advance()  # consume CASE
                val_tok = self._expect(TokenType.STRING)
                case_values = [_strip_quotes(val_tok.value)]
                # Collect pipe-separated alternatives: case "a"|"b":
                while self._peek().type == TokenType.PIPE:
                    self._advance()  # consume PIPE
                    alt_tok = self._expect(TokenType.STRING)
                    case_values.append(_strip_quotes(alt_tok.value))
                self._expect(TokenType.COLON)
                # Skip inline comments following the colon (e.g., ### note)
                while self._peek().type == TokenType.COMMENT:
                    self._advance()
                # Parse body until next case arm or closing brace
                body: list[Node] = []
                while self._peek().type not in _SWITCH_STOP:
                    stmt = self._parse_statement()
                    if stmt is not None:
                        body.append(stmt)
                cases.append(CaseNode(values=case_values, body=body))
            elif t.type == TokenType.DEFAULT:
                self._advance()  # consume DEFAULT
                self._expect(TokenType.COLON)
                while self._peek().type == TokenType.COMMENT:
                    self._advance()
                while self._peek().type not in _SWITCH_STOP:
                    stmt = self._parse_statement()
                    if stmt is not None:
                        default_body.append(stmt)
            else:
                self._advance()  # skip unexpected token

        self._expect(TokenType.RBRACE)
        return SwitchNode(expression=expr, cases=cases, default_body=default_body, line=tok.line)

    def _parse_log_call(self) -> Comment:
        """log(LEVEL, "message") — consume and emit a comment."""
        tok = self._advance()  # consume 'log' IDENT
        self._expect(TokenType.LPAREN)
        # Consume all tokens until the matching RPAREN, grabbing the first STRING
        msg: str | None = None
        depth = 1
        while depth > 0 and self._peek().type != TokenType.EOF:
            t = self._peek()
            if t.type == TokenType.LPAREN:
                depth += 1
                self._advance()
            elif t.type == TokenType.RPAREN:
                depth -= 1
                if depth == 0:
                    break
                self._advance()
            elif t.type == TokenType.STRING and msg is None:
                msg = _strip_quotes(t.value)
                self._advance()
            else:
                self._advance()
        self._expect(TokenType.RPAREN)
        text = f'log: "{msg}"' if msg is not None else "log: (call)"
        return Comment(text=text, line=tok.line)

    def _parse_details_call(self) -> Comment:
        """details($*) — consume entire call and emit a comment."""
        tok = self._advance()  # consume 'details' IDENT
        self._expect(TokenType.LPAREN)
        depth = 1
        while depth > 0 and self._peek().type != TokenType.EOF:
            t = self._peek()
            if t.type == TokenType.LPAREN:
                depth += 1
                self._advance()
            elif t.type == TokenType.RPAREN:
                depth -= 1
                if depth == 0:
                    break
                self._advance()
            else:
                self._advance()
        self._expect(TokenType.RPAREN)
        return Comment(text="details: all varbinds", line=tok.line)

    def _parse_exists_expr(self) -> ExistsNode:
        """exists(expr) — field/variable existence check."""
        tok = self._advance()  # consume 'exists' IDENT
        self._expect(TokenType.LPAREN)
        arg = self._parse_primary()
        self._expect(TokenType.RPAREN)
        return ExistsNode(argument=arg, line=tok.line)

    def _parse_extract_expr(self) -> ExtractNode:
        """extract(source, "pattern") — regex first-capture-group extraction."""
        tok = self._advance()  # consume 'extract' IDENT
        self._expect(TokenType.LPAREN)
        source = self._parse_primary()
        self._expect(TokenType.COMMA)
        pattern = self._parse_primary()
        self._expect(TokenType.RPAREN)
        return ExtractNode(source=source, pattern=pattern, line=tok.line)

    def _parse_cast_expr(self) -> CastNode:
        """int(expr) / str(expr) / float(expr) — type-cast expression."""
        tok = self._advance()  # consume int/str/float IDENT
        self._expect(TokenType.LPAREN)
        arg = self._parse_addend()
        self._expect(TokenType.RPAREN)
        return CastNode(cast_type=tok.value, argument=arg, line=tok.line)

    def _parse_function_call(self) -> FunctionCallNode:
        """Generic multi-arg function call: name(arg1, arg2, ...)"""
        tok = self._advance()  # consume IDENT (function name)
        self._expect(TokenType.LPAREN)
        args: list[Node] = []
        while self._peek().type not in (TokenType.RPAREN, TokenType.EOF):
            if self._peek().type == TokenType.COMMA:
                self._advance()
                continue
            args.append(self._parse_addend())
        self._expect(TokenType.RPAREN)
        return FunctionCallNode(name=tok.value, args=args, line=tok.line)

    def _parse_trim_expr(self) -> TrimNode:
        """ltrim(expr) / rtrim(expr) / trim(expr) — whitespace trimming."""
        tok = self._advance()  # consume ltrim/rtrim/trim IDENT
        trim_map = {"ltrim": "left", "rtrim": "right", "trim": "both"}
        trim_type = trim_map[tok.value]
        self._expect(TokenType.LPAREN)
        arg = self._parse_addend()
        self._expect(TokenType.RPAREN)
        return TrimNode(trim_type=trim_type, argument=arg, line=tok.line)

    # ------------------------------------------------------------------
    # Condition / expression parsers
    # ------------------------------------------------------------------

    def _parse_condition(self) -> Node:
        return self._parse_or()

    def _parse_or(self) -> Node:
        left = self._parse_and()
        while self._peek().type == TokenType.OR:
            op_tok = self._advance()
            right = self._parse_and()
            left = BinaryOp(op="||", left=left, right=right, line=op_tok.line)
        return left

    def _parse_and(self) -> Node:
        left = self._parse_not()
        while self._peek().type == TokenType.AND:
            op_tok = self._advance()
            right = self._parse_not()
            left = BinaryOp(op="&&", left=left, right=right, line=op_tok.line)
        return left

    def _parse_not(self) -> Node:
        if self._peek().type == TokenType.NOT:
            op_tok = self._advance()
            operand = self._parse_not()
            return UnaryOp(op="!", operand=operand, line=op_tok.line)
        return self._parse_primary_condition()

    def _parse_primary_condition(self) -> Node:
        tok = self._peek()

        if tok.type == TokenType.LPAREN:
            self._advance()
            cond = self._parse_condition()
            self._expect(TokenType.RPAREN)
            return cond

        if tok.type == TokenType.MATCH:
            return self._parse_match_expr()

        if tok.type == TokenType.IDENT and tok.value == "regmatch":
            return self._parse_match_expr(force_regex=True)

        if tok.type == TokenType.IDENT and tok.value == "exists":
            return self._parse_exists_expr()

        if tok.type == TokenType.IDENT and tok.value in ("int", "str", "float"):
            lhs = self._parse_cast_expr()
            compare_ops = {
                TokenType.EQ, TokenType.NEQ,
                TokenType.LT, TokenType.GT,
                TokenType.LEQ, TokenType.GEQ,
            }
            if self._peek().type in compare_ops:
                op_tok = self._advance()
                rhs = self._parse_addend()  # allows cast on RHS too
                return BinaryOp(op=op_tok.value, left=lhs, right=rhs, line=op_tok.line)
            return lhs

        # Generic IDENT(args) function call in condition position (e.g. len($x) > 10)
        if tok.type == TokenType.IDENT and self._peek_ahead(1).type == TokenType.LPAREN:
            lhs = self._parse_function_call()
            compare_ops = {
                TokenType.EQ, TokenType.NEQ,
                TokenType.LT, TokenType.GT,
                TokenType.LEQ, TokenType.GEQ,
            }
            if self._peek().type in compare_ops:
                op_tok = self._advance()
                rhs = self._parse_addend()
                return BinaryOp(op=op_tok.value, left=lhs, right=rhs, line=op_tok.line)
            return lhs

        # compare_expr: (FIELD | VARBIND | NAMED_VARBIND) compare_op value
        if tok.type in (TokenType.FIELD, TokenType.VARBIND, TokenType.NAMED_VARBIND):
            return self._parse_compare_or_atom()

        # Fallback — log and return a comment node
        self._advance()
        logger.warning(
            "%s:%d: unexpected token %s in condition — skipped",
            self._source, tok.line, tok.type.name,
        )
        return Comment(text=f"TODO: unsupported condition token: {tok.value}", line=tok.line)

    def _parse_compare_or_atom(self) -> Node:
        """FIELD/VARBIND compare_op value, or bare atom."""
        tok = self._advance()
        lhs = _tok_to_atom(tok)

        compare_ops = {
            TokenType.EQ, TokenType.NEQ,
            TokenType.LT, TokenType.GT,
            TokenType.LEQ, TokenType.GEQ,
        }
        if self._peek().type in compare_ops:
            op_tok = self._advance()
            rhs = self._parse_addend()  # allows cast functions on RHS
            return BinaryOp(op=op_tok.value, left=lhs, right=rhs, line=tok.line)

        return lhs

    def _parse_match_expr(self, force_regex: bool = False) -> MatchExpr:
        """
        match(@Field, "pattern") or match(@Field, regex("pat"))
        match($N, "literal")     or regmatch($N, "regex")
        """
        tok = self._advance()  # MATCH keyword or regmatch IDENT
        self._expect(TokenType.LPAREN)

        src_tok = self._peek()
        if src_tok.type == TokenType.FIELD:
            self._advance()
            source: Node = FieldRef(name=src_tok.value[1:], line=src_tok.line)
        elif src_tok.type == TokenType.VARBIND:
            self._advance()
            source = VarbindRef(index=int(src_tok.value[1:]) - 1, line=src_tok.line)
        elif src_tok.type == TokenType.NAMED_VARBIND:
            self._advance()
            source = NamedVarbindRef(name=src_tok.value[1:], line=src_tok.line)
        else:
            raise ParseError(
                f"{self._source}:{src_tok.line}: "
                f"match() source must be @Field, $N, or $name, got {src_tok.type.name} {src_tok.value!r}"
            )

        self._expect(TokenType.COMMA)

        if self._peek().type == TokenType.REGEX:
            pattern: Node = self._parse_regex_expr()
        elif self._peek().type in (TokenType.VARBIND, TokenType.NAMED_VARBIND, TokenType.FIELD):
            # Variable pattern: match($2, $3), match($2, $var), match($2, @Field)
            pat_tok = self._advance()
            pattern = _tok_to_atom(pat_tok)
        else:
            pat_tok = self._expect(TokenType.STRING)
            pat_str = _strip_quotes(pat_tok.value)
            if force_regex or (
                not isinstance(source, FieldRef)
                and _looks_like_regex(pat_str)
            ):
                pattern = RegexExpr(pattern=pat_str, line=pat_tok.line)
            else:
                pattern = StringLiteral(value=pat_str, line=pat_tok.line)

        self._expect(TokenType.RPAREN)
        return MatchExpr(field=source, pattern=pattern, line=tok.line)

    def _parse_regex_expr(self) -> RegexExpr:
        """regex("pattern")"""
        tok = self._advance()  # REGEX
        self._expect(TokenType.LPAREN)
        pat_tok = self._expect(TokenType.STRING)
        self._expect(TokenType.RPAREN)
        return RegexExpr(pattern=_strip_quotes(pat_tok.value), line=tok.line)

    # ------------------------------------------------------------------
    # Expression
    # ------------------------------------------------------------------

    def _parse_expr(self) -> Node:
        """Additive: term (PLUS | MINUS term)*"""
        left = self._parse_term()
        while self._peek().type in (TokenType.PLUS, TokenType.MINUS):
            op_tok = self._advance()
            right = self._parse_term()
            left = BinaryOp(op=op_tok.value, left=left, right=right, line=op_tok.line)
        return left

    def _parse_term(self) -> Node:
        """Multiplicative/bitwise: addend (STAR | SLASH | PERCENT | AMP addend)*"""
        left = self._parse_addend()
        while self._peek().type in (TokenType.STAR, TokenType.SLASH, TokenType.PERCENT, TokenType.AMP):
            op_tok = self._advance()
            right = self._parse_addend()
            left = BinaryOp(op=op_tok.value, left=left, right=right, line=op_tok.line)
        return left

    def _parse_addend(self) -> Node:
        """addend := FIELD | VARBIND | NAMED_VARBIND | STRING | NUMBER | lookup_expr | extract_expr | (expr)"""
        tok = self._peek()

        if tok.type == TokenType.LOOKUP:
            return self._parse_lookup_expr()

        if tok.type == TokenType.IDENT and tok.value == "extract":
            return self._parse_extract_expr()

        if tok.type == TokenType.IDENT and tok.value in ("int", "str", "float"):
            return self._parse_cast_expr()

        if tok.type == TokenType.IDENT and tok.value in ("ltrim", "rtrim", "trim"):
            return self._parse_trim_expr()

        if tok.type == TokenType.IDENT and self._peek_ahead(1).type == TokenType.LPAREN:
            return self._parse_function_call()

        if tok.type == TokenType.LPAREN:
            self._advance()
            expr = self._parse_expr()
            self._expect(TokenType.RPAREN)
            return expr

        return self._parse_primary()

    def _parse_primary(self) -> Node:
        """Single-token leaf node."""
        tok = self._advance()
        return _tok_to_primary(tok)

    def _parse_lookup_expr(self) -> LookupExpr:
        """lookup(@field, table_name), lookup($name, table_name), or lookup($N, table_name)"""
        tok = self._advance()  # LOOKUP
        self._expect(TokenType.LPAREN)
        key_tok = self._peek()
        if key_tok.type == TokenType.FIELD:
            self._advance()
            key_node: Node = FieldRef(name=key_tok.value[1:], line=key_tok.line)
        elif key_tok.type == TokenType.NAMED_VARBIND:
            self._advance()
            key_node = NamedVarbindRef(name=key_tok.value[1:], line=key_tok.line)
        elif key_tok.type == TokenType.VARBIND:
            self._advance()
            key_node = VarbindRef(index=int(key_tok.value[1:]) - 1, line=key_tok.line)
        else:
            raise ParseError(
                f"{self._source}:{key_tok.line}: "
                f"lookup() key must be @Field, $name, or $N, got {key_tok.type.name} {key_tok.value!r}"
            )
        self._expect(TokenType.COMMA)
        name_tok = self._expect(TokenType.IDENT)
        self._expect(TokenType.RPAREN)
        return LookupExpr(field=key_node, table_name=name_tok.value, line=tok.line)

    # ------------------------------------------------------------------
    # Token stream helpers
    # ------------------------------------------------------------------

    def _peek(self) -> Token:
        return self._tokens[self._pos]

    def _peek_ahead(self, offset: int) -> Token:
        """Peek at a token offset positions ahead (0 = current)."""
        idx = min(self._pos + offset, len(self._tokens) - 1)
        return self._tokens[idx]

    def _advance(self) -> Token:
        tok = self._tokens[self._pos]
        if tok.type != TokenType.EOF:
            self._pos += 1
        return tok

    def _expect(self, ttype: TokenType) -> Token:
        tok = self._advance()
        if tok.type != ttype:
            raise ParseError(
                f"{self._source}:{tok.line}:{tok.col}: "
                f"expected {ttype.name}, got {tok.type.name} {tok.value!r}"
            )
        return tok


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Characters that strongly suggest a pattern is a regex rather than a plain literal.
# Excludes | (pipe alternatives) and * (wildcards) which have their own meaning.
_REGEX_HINT_CHARS = frozenset(r'^$.[\\+?()')


def _looks_like_regex(pat: str) -> bool:
    """Return True if pat contains characters that indicate a regex pattern."""
    return bool(set(pat) & _REGEX_HINT_CHARS)


def _strip_quotes(s: str) -> str:
    """Remove surrounding double quotes from a STRING token value."""
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1]
    return s


def _tok_to_atom(tok: Token) -> Node:
    """Convert a FIELD/VARBIND/NAMED_VARBIND token to an AST leaf."""
    match tok.type:
        case TokenType.FIELD:
            return FieldRef(name=tok.value[1:], line=tok.line)
        case TokenType.VARBIND:
            return VarbindRef(index=int(tok.value[1:]) - 1, line=tok.line)
        case TokenType.VARBIND_WILDCARD:
            return WildcardVarbindNode(line=tok.line)
        case TokenType.NAMED_VARBIND:
            return NamedVarbindRef(name=tok.value[1:], line=tok.line)
        case _:
            return Comment(text=f"TODO: unexpected atom {tok.value!r}", line=tok.line)


def _tok_to_primary(tok: Token) -> Node:
    """Convert any leaf token to an AST node."""
    match tok.type:
        case TokenType.FIELD:
            return FieldRef(name=tok.value[1:], line=tok.line)
        case TokenType.VARBIND:
            return VarbindRef(index=int(tok.value[1:]) - 1, line=tok.line)
        case TokenType.VARBIND_WILDCARD:
            return WildcardVarbindNode(line=tok.line)
        case TokenType.NAMED_VARBIND:
            return NamedVarbindRef(name=tok.value[1:], line=tok.line)
        case TokenType.STRING:
            return StringLiteral(value=_strip_quotes(tok.value), line=tok.line)
        case TokenType.NUMBER:
            raw = tok.value
            val: int | float = float(raw) if "." in raw else int(raw)
            return NumberLiteral(value=val, line=tok.line)
        case _:
            return Comment(text=f"TODO: unexpected primary {tok.value!r}", line=tok.line)


def _node_to_raw(node: Node) -> str:
    """Extract raw string representation from a simple leaf node."""
    match node:
        case StringLiteral(value=v):
            return v
        case NumberLiteral(value=v):
            return str(v)
        case FieldRef(name=n):
            return f"@{n}"
        case VarbindRef(index=i):
            return f"${i + 1}"
        case NamedVarbindRef(name=n):
            return f"${n}"
        case _:
            return str(node)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def parse_rules(text: str, source: str = "<input>") -> Program:
    """Tokenize and parse a Netcool rules text, returning the Program AST."""
    tokens = tokenize(text, source=source)
    return Parser(tokens, source=source).parse()


def parse_rules_file(
    path: str | Path,
    include_paths: list[Path] | None = None,
) -> Program:
    """
    Read and parse a .rules file.

    Encoding: UTF-8 with latin-1 fallback (same as mib2vrl).
    include_paths is reserved for future include resolution.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = p.read_text(encoding="latin-1")
        logger.info("latin-1 fallback: %s", p)
    return parse_rules(text, source=str(p))
