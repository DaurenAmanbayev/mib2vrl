"""
nodes.py — AST node dataclasses for the Netcool probe rules DSL.

Each node mirrors a grammatical construct in the DSL (assignments,
conditionals, lookups, regular expressions, and control flow).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Union


# ---------------------------------------------------------------------------
# Forward-declared union type for all AST nodes
# ---------------------------------------------------------------------------

Node = Union[
    "Program",
    "IfBlock",
    "SwitchNode",
    "Assignment",
    "DestructureAssignNode",
    "MatchExpr",
    "LookupExpr",
    "RegexExpr",
    "ExistsNode",
    "ExtractNode",
    "CastNode",
    "TrimNode",
    "FunctionCallNode",
    "BinaryOp",
    "UnaryOp",
    "FieldRef",
    "VarbindRef",
    "WildcardVarbindNode",
    "NamedVarbindRef",
    "StringLiteral",
    "NumberLiteral",
    "IncludeDirective",
    "TableDefinition",
    "Comment",
]


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

@dataclass
class Program:
    """Root node containing all top-level statements."""
    body: list[Node]
    source_file: str = ""


# ---------------------------------------------------------------------------
# Control flow
# ---------------------------------------------------------------------------

@dataclass
class IfBlock:
    """
    if (condition) { body } [else { else_body }]

    Handles arbitrarily nested if/else blocks as found in Netcool rules.
    """
    condition: Node
    body: list[Node]
    else_body: list[Node] | None = None
    line: int = 0


# ---------------------------------------------------------------------------
# Control flow — switch/case
# ---------------------------------------------------------------------------

@dataclass
class CaseNode:
    """A single case arm inside a SwitchNode."""
    values: list       # list[str] — one or more pipe-separated case literals (quotes stripped)
    body: list         # list[Node] — assignments in this case

    @property
    def value(self) -> str:
        """Backward-compat: return first value for single-value cases."""
        return self.values[0] if self.values else ""


@dataclass
class SwitchNode:
    """
    switch(expr) { case "val": statements ... [default: statements] }

    Translates to an if/else-if chain in VRL, with an optional else block
    for the default arm.
    """
    expression: object  # Node — the variable being switched on
    cases: list         # list[CaseNode]
    default_body: list = field(default_factory=list)  # list[Node]
    line: int = 0


# ---------------------------------------------------------------------------
# Assignments
# ---------------------------------------------------------------------------

@dataclass
class Assignment:
    """
    @Field = expr   — Netcool field assignment
    $name  = expr   — named varbind intermediate variable

    target is either a FieldRef or a NamedVarbindRef.
    """
    target: Union["FieldRef", "NamedVarbindRef"]
    value: Node
    line: int = 0


@dataclass
class DestructureAssignNode:
    """
    [$var1, $var2, ...] = lookup(key, table)

    Multi-value destructuring assignment.  Translates to a
    get_enrichment_table_record() call followed by indexed array accesses.
    """
    targets: list   # list[NamedVarbindRef | FieldRef]
    value: object   # Node — typically a LookupExpr
    line: int = 0


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------

@dataclass
class MatchExpr:
    """
    match(@Field, "string")
    match(@Field, regex("pattern"))
    match(@Field, "str1|str2")  — pipe-separated alternatives
    match($N, "literal")        — varbind source
    regmatch($N, "regex")       — always-regex varbind source
    """
    field: object   # FieldRef | VarbindRef | NamedVarbindRef
    pattern: Node   # StringLiteral | RegexExpr
    line: int = 0


@dataclass
class LookupExpr:
    """
    lookup(@field, table_name)  or  lookup($name, table_name)

    Translates to get_enrichment_table_record() in VRL.
    field may be a FieldRef or a NamedVarbindRef.
    """
    field: object   # FieldRef | NamedVarbindRef
    table_name: str
    line: int = 0


@dataclass
class RegexExpr:
    """
    regex("pattern")

    The pattern string is used as-is inside VRL r'...' literals.
    """
    pattern: str
    line: int = 0


@dataclass
class BinaryOp:
    """
    left op right

    op is one of: &&, ||, +, ==, !=, <, >, <=, >=
    """
    op: str
    left: Node
    right: Node
    line: int = 0


@dataclass
class UnaryOp:
    """
    !operand
    """
    op: str
    operand: Node
    line: int = 0


# ---------------------------------------------------------------------------
# Leaf nodes
# ---------------------------------------------------------------------------

@dataclass
class FieldRef:
    """
    @FieldName

    name is stored without the leading @.
    Mapped to VRL .field_name via NETCOOL_TO_VRL in field_mapper.py.
    """
    name: str      # without @
    line: int = 0


@dataclass
class VarbindRef:
    """
    $N — numeric positional varbind reference.

    index is 0-based (converted from 1-based $N at parse time).
    Translates to .varbinds[index] in VRL.
    """
    index: int     # 0-based
    line: int = 0


@dataclass
class NamedVarbindRef:
    """
    $name — named intermediate varbind variable.

    name is stored without the leading $.
    Translates to _name (local variable) in VRL.
    """
    name: str      # without $
    line: int = 0


@dataclass
class WildcardVarbindNode:
    """$* — reference to the entire varbinds array. Translates to .varbinds in VRL."""
    line: int = 0


# ---------------------------------------------------------------------------
# Function-call expressions
# ---------------------------------------------------------------------------

@dataclass
class ExistsNode:
    """
    exists(expr)

    Netcool field/variable existence check.
    Translates to VRL exists(expr).
    """
    argument: object  # Node
    line: int = 0


@dataclass
class ExtractNode:
    """
    extract(source, "regex_pattern")

    Extracts the first capture group from source using the regex pattern.
    Translates to VRL: capture(source, r'pattern')[0] ?? ""
    """
    source: object   # Node — the string/variable to search
    pattern: object  # Node — regex pattern (typically StringLiteral)
    line: int = 0


@dataclass
class CastNode:
    """
    int(expr) / str(expr) / float(expr) — type-cast functions.

    Translates to VRL: to_int!(expr), to_string!(expr), to_float!(expr).
    """
    cast_type: str   # "int" | "str" | "float"
    argument: object  # Node
    line: int = 0


@dataclass
class FunctionCallNode:
    """
    Generic multi-argument function call for DSL functions without a dedicated node.

    Examples: substr(s, start, len), sprintf(fmt, arg1, ...)

    Codegen handles known names specially; unknown names emit TODO.
    """
    name: str
    args: list   # list[Node]
    line: int = 0


@dataclass
class TrimNode:
    """
    ltrim(expr) / rtrim(expr) / trim(expr) — whitespace trimming.

    Translates to VRL: strip_whitespace(expr, "left"|"right") or strip_whitespace(expr).
    """
    trim_type: str   # "left" | "right" | "both"
    argument: object  # Node
    line: int = 0


@dataclass
class StringLiteral:
    """
    "text"

    value is the string content with surrounding quotes stripped and
    escape sequences left intact (VRL handles them the same way).
    """
    value: str
    line: int = 0


@dataclass
class NumberLiteral:
    """Integer or float literal."""
    value: int | float
    line: int = 0


# ---------------------------------------------------------------------------
# Directives
# ---------------------------------------------------------------------------

@dataclass
class IncludeDirective:
    """
    include "path/to/file.rules"

    path is the raw string as written in the rules file.
    Resolution is handled by the codegen layer.
    """
    path: str
    line: int = 0


@dataclass
class TableDefinition:
    """
    table name = {
        "key1" : value1,
        "key2" : value2,
    }
    [default = value]

    Used in .lookup and .severity files.
    entries is a list of (key_str, raw_value_str) pairs.
    """
    name: str
    entries: list[tuple[str, str]]
    default: str | None = None
    line: int = 0


@dataclass
class Comment:
    """# comment text (preserved for context in generated output)."""
    text: str
    line: int = 0
