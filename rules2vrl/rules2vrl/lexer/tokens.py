"""tokens.py — Token type enum for the Netcool probe rules DSL."""

from enum import Enum, auto


class TokenType(Enum):
    # Keywords
    IF = auto()
    ELSE = auto()
    MATCH = auto()
    LOOKUP = auto()
    REGEX = auto()
    INCLUDE = auto()
    TABLE = auto()
    DEFAULT = auto()
    SWITCH = auto()
    CASE = auto()

    # Logical operators
    AND = auto()       # &&
    OR = auto()        # ||
    NOT = auto()       # !

    # Comparison operators (== must come before =)
    EQ = auto()        # ==
    NEQ = auto()       # !=
    LEQ = auto()       # <=
    GEQ = auto()       # >=
    LT = auto()        # <
    GT = auto()        # >

    # Assignment and arithmetic
    ASSIGN = auto()    # =  (single, after == checked)
    PLUS = auto()      # +
    MINUS = auto()     # -
    STAR = auto()      # *  (multiplication; $* is VARBIND_WILDCARD)
    SLASH = auto()     # /
    PERCENT = auto()   # %
    AMP = auto()       # &  (bitwise AND — no VRL equivalent, emits TODO)

    # Delimiters
    LBRACE = auto()    # {
    RBRACE = auto()    # }
    LBRACKET = auto()  # [
    RBRACKET = auto()  # ]
    LPAREN = auto()    # (
    RPAREN = auto()    # )
    COMMA = auto()     # ,
    SEMICOLON = auto() # ;
    COLON = auto()     # :

    # Literals
    STRING = auto()    # "..."  (may span multiple lines)
    NUMBER = auto()    # 123 or 3.14

    # References
    FIELD = auto()                # @Identifier
    VARBIND = auto()              # $1, $2 … $N  (all-digit suffix)
    VARBIND_WILDCARD = auto()     # $*           (all-varbinds wildcard)
    NAMED_VARBIND = auto()        # $name         (letter/underscore suffix)

    # General identifier (table names, etc.)
    IDENT = auto()

    # Single-char punctuation
    PIPE = auto()      # | (standalone, after || already matched)

    # Pass-through / ignored
    COMMENT = auto()   # # rest of line
    UNKNOWN = auto()   # unrecognised character — skipped by parser
    EOF = auto()
