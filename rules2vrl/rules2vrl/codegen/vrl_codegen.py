"""
vrl_codegen.py — AST → VRL source code generator.

Translates Netcool DSL constructs (assignments, conditionals, lookups,
regex matches, includes) to their VRL equivalents.

Unsupported constructs emit a VRL comment:
    # TODO: unsupported construct: <original netcool text>
and log at WARNING level so that translation is never silently incomplete.
"""

from __future__ import annotations

import logging
import re

from rules2vrl.ast.nodes import (
    Node, Program, IfBlock, SwitchNode,
    Assignment, DestructureAssignNode,
    MatchExpr, LookupExpr, RegexExpr, ExistsNode, ExtractNode, CastNode, TrimNode, FunctionCallNode,
    BinaryOp, UnaryOp, FieldRef, VarbindRef, WildcardVarbindNode, NamedVarbindRef,
    StringLiteral, NumberLiteral, IncludeDirective, TableDefinition, Comment,
)
from rules2vrl.codegen.field_mapper import (
    field_to_vrl, varbind_to_vrl, named_varbind_to_vrl,
)
from rules2vrl.codegen.lookup_converter import lookup_vrl_snippet

logger = logging.getLogger(__name__)


class VrlCodegen:
    """
    Walks an AST produced by Parser and emits VRL source code.

    Usage:
        gen = VrlCodegen()
        vrl_source = gen.generate(program)
    """

    def __init__(
        self,
        include_todos: bool = True,
        indent_size: int = 4,
    ) -> None:
        self._include_todos = include_todos
        self._indent = " " * indent_size

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def generate(self, program: Program) -> str:
        """Generate VRL source for a complete Program."""
        lines: list[str] = []
        self._emit_stmts(program.body, lines, depth=0)
        # VRL remap must end with '.' to return the modified event
        if lines and lines[-1].strip() != ".":
            lines.append("")
            lines.append("# Return the modified event")
            lines.append(".")
        return "\n".join(lines) + "\n"

    # ------------------------------------------------------------------
    # Statement emitters
    # ------------------------------------------------------------------

    def _emit_stmts(self, stmts: list[Node], out: list[str], depth: int) -> None:
        for stmt in stmts:
            self._emit_stmt(stmt, out, depth)

    def _emit_stmt(self, node: Node, out: list[str], depth: int) -> None:
        pad = self._indent * depth

        match node:
            case Comment(text=text):
                if text.startswith("TODO:"):
                    if self._include_todos:
                        out.append(f"{pad}# {text}")
                else:
                    out.append(f"{pad}# {text}")

            case IncludeDirective(path=path):
                # Include files are inlined at a higher layer; here we emit
                # a comment so the output is traceable.
                out.append(f"{pad}# include {path!r}  (resolved by converter)")

            case TableDefinition():
                # Tables belong in lookup_converter; ignore inside codegen
                pass

            case Assignment():
                self._emit_assignment(node, out, depth)

            case DestructureAssignNode():
                self._emit_destructure(node, out, depth)

            case IfBlock():
                self._emit_if(node, out, depth)

            case SwitchNode():
                self._emit_switch(node, out, depth)

            case _:
                # Any other node in statement position is unexpected
                raw = self._expr(node)
                if self._include_todos:
                    out.append(f"{pad}# TODO: unsupported construct: {raw}")
                logger.warning("Unsupported node in statement position: %s", type(node).__name__)

    def _emit_assignment(self, node: Assignment, out: list[str], depth: int) -> None:
        pad = self._indent * depth

        # LHS
        match node.target:
            case FieldRef(name=name):
                lhs = field_to_vrl(f"@{name}")
            case NamedVarbindRef(name=name):
                lhs = named_varbind_to_vrl(name)
            case VarbindRef(index=idx):
                lhs = varbind_to_vrl(idx)
            case _:
                lhs = "# unknown_lhs"

        # RHS — special handling for LookupExpr on the right side
        match node.value:
            case LookupExpr(field=f, table_name=tbl):
                key_vrl = self._expr(f)
                snippet = lookup_vrl_snippet(tbl, key_vrl, lhs, indent=pad)
                out.append(snippet)
                return

            case _:
                rhs = self._expr(node.value)

        out.append(f"{pad}{lhs} = {rhs}")

    def _emit_if(self, node: IfBlock, out: list[str], depth: int) -> None:
        self._emit_if_chain(node, out, depth, is_first=True)

    def _emit_if_chain(self, node: IfBlock, out: list[str], depth: int, is_first: bool) -> None:
        """Recursively emit an if / else-if / else chain.

        When else_body contains exactly one IfBlock (produced by parsing
        ``else if`` without braces), we emit compact ``} else if cond {``
        rather than a nested ``} else { if cond { } }``.
        """
        pad = self._indent * depth
        cond = self._expr(node.condition)
        keyword = "if" if is_first else "} else if"
        out.append(f"{pad}{keyword} {cond} {{")
        self._emit_stmts(node.body, out, depth + 1)

        if node.else_body is None:
            out.append(f"{pad}}}")
        elif len(node.else_body) == 1 and isinstance(node.else_body[0], IfBlock):
            # Compact else-if — recurse without an extra nesting level
            self._emit_if_chain(node.else_body[0], out, depth, is_first=False)
        else:
            out.append(f"{pad}}} else {{")
            self._emit_stmts(node.else_body, out, depth + 1)
            out.append(f"{pad}}}")

    def _emit_destructure(self, node: DestructureAssignNode, out: list[str], depth: int) -> None:
        """Translate [$v1,$v2,...] = lookup(key, table) to indexed array accesses."""
        pad = self._indent * depth
        inner = self._indent * (depth + 1)

        if isinstance(node.value, LookupExpr):
            f = node.value.field
            tbl = node.value.table_name
            key_vrl = self._expr(f)
            out.append(
                f'{pad}_lookup_result = get_enrichment_table_record("{tbl}", {{"key": {key_vrl}}})'
            )
            out.append(f"{pad}if _lookup_result != null {{")
            for i, target in enumerate(node.targets):
                target_vrl = self._expr(target)
                out.append(f"{inner}{target_vrl} = _lookup_result[{i}] ?? null")
            out.append(f"{pad}}}")
        else:
            rhs = self._expr(node.value)
            if self._include_todos:
                out.append(f"{pad}# TODO: destructure: {rhs}")
            logger.warning("Unsupported RHS in destructure: %s", type(node.value).__name__)

    def _emit_switch(self, node: SwitchNode, out: list[str], depth: int) -> None:
        """Translate switch/case to an if/else-if chain with optional else."""
        pad = self._indent * depth
        expr_vrl = self._expr(node.expression)
        for i, case in enumerate(node.cases):
            keyword = "if" if i == 0 else "} else if"
            parts = [f'{expr_vrl} == "{v.replace(chr(34), chr(92)+chr(34))}"' for v in case.values]
            cond = " || ".join(parts)
            out.append(f'{pad}{keyword} {cond} {{')
            self._emit_stmts(case.body, out, depth + 1)
        if node.cases:
            if node.default_body:
                out.append(f"{pad}}} else {{")
                self._emit_stmts(node.default_body, out, depth + 1)
            out.append(f"{pad}}}")
        elif node.default_body:
            # default-only switch — emit body flat (no wrapping if block needed)
            self._emit_stmts(node.default_body, out, depth)

    # ------------------------------------------------------------------
    # Expression emitter (returns a VRL expression string)
    # ------------------------------------------------------------------

    def _expr(self, node: Node) -> str:
        match node:
            case FieldRef(name=name):
                return field_to_vrl(f"@{name}")

            case VarbindRef(index=idx):
                return varbind_to_vrl(idx)

            case WildcardVarbindNode():
                return ".varbinds"

            case NamedVarbindRef(name=name):
                return named_varbind_to_vrl(name)

            case ExistsNode(argument=arg):
                return f"exists({self._expr(arg)})"

            case ExtractNode(source=src, pattern=pat):
                src_vrl = self._expr(src)
                if isinstance(pat, StringLiteral):
                    escaped = pat.value.replace("'", "\\'")
                    return f"capture({src_vrl}, r'{escaped}')[0] ?? \"\""
                pat_vrl = self._expr(pat)
                return f"capture({src_vrl}, {pat_vrl})[0] ?? \"\""

            case StringLiteral(value=val):
                # Escape any double quotes inside, wrap in double quotes
                escaped = val.replace('"', '\\"')
                return f'"{escaped}"'

            case NumberLiteral(value=val):
                if isinstance(val, float) and val == int(val):
                    return str(int(val))
                return str(val)

            case BinaryOp(op=op, left=left, right=right):
                return self._emit_binop(op, left, right)

            case UnaryOp(op="!", operand=operand):
                inner = self._expr(operand)
                # Add parens around complex inner expressions
                if isinstance(operand, BinaryOp):
                    inner = f"({inner})"
                return f"!{inner}"

            case MatchExpr():
                return self._emit_match(node)

            case LookupExpr(field=f, table_name=tbl):
                # In expression context, inline the call (no assignment target)
                key_vrl = self._expr(f)
                return f'get_enrichment_table_record("{tbl}", {{"key": {key_vrl}}})'

            case CastNode(cast_type=ct, argument=arg):
                arg_vrl = self._expr(arg)
                vrl_fn = {"int": "to_int!", "str": "to_string!", "float": "to_float!"}[ct]
                return f"{vrl_fn}({arg_vrl})"

            case TrimNode(trim_type=tt, argument=arg):
                arg_vrl = self._expr(arg)
                if tt == "both":
                    return f"strip_whitespace({arg_vrl})"
                return f'strip_whitespace({arg_vrl}, "{tt}")'

            case FunctionCallNode(name=fn, args=args):
                return self._emit_function_call(fn, args)

            case RegexExpr(pattern=pat):
                # Escape any single quotes inside the pattern
                escaped = pat.replace("'", "\\'")
                return f"r'{escaped}'"

            case Comment(text=text):
                if self._include_todos:
                    return f"null  # TODO: unsupported construct: {text}"
                return "null"

            case _:
                logger.warning("Unknown expression node type: %s", type(node).__name__)
                return f"null  # TODO: unknown node {type(node).__name__}"

    def _emit_function_call(self, name: str, args: list) -> str:
        """Translate a generic multi-arg function call to VRL."""
        match name:
            case "len":
                if len(args) == 1:
                    return f"length({self._expr(args[0])})"
                args_vrl = ", ".join(self._expr(a) for a in args)
                return f"length({args_vrl})"

            case "substr":
                # substr(s, start, length) → slice!(s, start, start+length)
                if len(args) == 3:
                    s = self._expr(args[0])
                    start = self._expr(args[1])
                    length = self._expr(args[2])
                    # If both are integer literals, compute end statically
                    from rules2vrl.ast.nodes import NumberLiteral
                    if isinstance(args[1], NumberLiteral) and isinstance(args[2], NumberLiteral):
                        end = int(args[1].value) + int(args[2].value)
                        return f"slice!({s}, {start}, {end})"
                    return f"slice!({s}, to_int!({start}), to_int!({start}) + to_int!({length}))"
                args_vrl = ", ".join(self._expr(a) for a in args)
                return f"null  # TODO: substr({args_vrl})"

            case _:
                args_vrl = ", ".join(self._expr(a) for a in args)
                if self._include_todos:
                    return f"null  # TODO: unsupported function {name!r}({args_vrl})"
                return "null"

    def _emit_binop(self, op: str, left: Node, right: Node) -> str:
        """Emit a binary operation, with special handling for match patterns."""
        # Operators with no VRL equivalent — emit TODO
        _NO_VRL = {"&", ">>", "<<", "^"}
        if op in _NO_VRL:
            l_str = self._expr(left)
            r_str = self._expr(right)
            return f"null  # TODO: bitwise op {op!r} not supported in VRL ({l_str} {op} {r_str})"

        # Map Netcool/arithmetic operators to VRL
        vrl_op = {"&&": "&&", "||": "||",
                   "+": "+", "-": "-", "*": "*", "/": "/", "%": "%",
                   "==": "==", "!=": "!=",
                   "<": "<", ">": ">", "<=": "<=", ">=": ">="}[op]

        l_str = self._expr(left)
        r_str = self._expr(right)

        # Wrap sub-expressions in parens for || and && to preserve precedence
        if op in ("&&", "||"):
            if isinstance(left, BinaryOp) and left.op in ("||", "&&") and left.op != op:
                l_str = f"({l_str})"
            if isinstance(right, BinaryOp) and right.op in ("||", "&&") and right.op != op:
                r_str = f"({r_str})"

        return f"{l_str} {vrl_op} {r_str}"

    def _emit_match(self, node: MatchExpr) -> str:
        """
        Translate match(@Field, pattern) or match($N, pattern) to VRL.

        match(@F, "str1|str2")       → .f == "str1" || .f == "str2"
        match(@F, "exact")           → .f == "exact"
        match(@F, "wild*")           → starts_with(.f, "wild")
        match(@F, regex("pattern"))  → match(.f, r'pattern')
        match($N, "literal")         → .varbinds[N-1] == "literal"
        match($N, "a|b")             → .varbinds[N-1] == "a" || .varbinds[N-1] == "b"
        regmatch($N, "pat")          → match(.varbinds[N-1], r'pat')  (pattern=RegexExpr)
        """
        source_vrl = self._expr(node.field)
        line = getattr(node.field, "line", 0)

        match node.pattern:
            case RegexExpr(pattern=pat):
                escaped = pat.replace("'", "\\'")
                return f"match({source_vrl}, r'{escaped}')"

            case StringLiteral(value=val):
                return self._emit_string_match(source_vrl, val, line)

            case _:
                # VarbindRef / NamedVarbindRef / FieldRef pattern → direct equality
                pat_vrl = self._expr(node.pattern)
                return f"{source_vrl} == {pat_vrl}"

    def _emit_string_match(self, field_vrl: str, pattern: str, line: int) -> str:
        """
        Convert a string match pattern.

        Pipe-separated alternatives → OR chain.
        Wildcard * → string_contains / starts_with / ends_with approximation.
        Plain string → equality.
        """
        # Split on | for alternatives
        alts = [a.strip() for a in pattern.split("|") if a.strip()]

        if len(alts) > 1:
            parts = [self._single_match(field_vrl, alt, line) for alt in alts]
            return " || ".join(parts)

        return self._single_match(field_vrl, pattern, line)

    def _single_match(self, field_vrl: str, pattern: str, line: int) -> str:
        """Translate a single string match pattern to a VRL expression."""
        # Wildcard patterns: *text, text*, *text* → VRL string functions
        if "*" in pattern:
            if pattern == "*":
                return f"is_string({field_vrl})"
            if pattern.startswith("*") and pattern.endswith("*") and pattern.count("*") == 2:
                inner = pattern[1:-1]
                return f'contains({field_vrl}, "{inner}")'
            if pattern.startswith("*"):
                suffix = pattern[1:]
                return f'ends_with({field_vrl}, "{suffix}")'
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                return f'starts_with({field_vrl}, "{prefix}")'
            # Multiple wildcards — fall back to regex
            escaped = re.escape(pattern).replace(r"\*", ".*")
            logger.warning("line %d: complex wildcard %r → regex approximation", line, pattern)
            return f"match({field_vrl}, r'^{escaped}$')"

        # Plain equality
        escaped = pattern.replace('"', '\\"')
        return f'{field_vrl} == "{escaped}"'


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def generate_vrl(program: Program, **kwargs) -> str:
    """Convenience wrapper: parse + generate in one call."""
    return VrlCodegen(**kwargs).generate(program)
