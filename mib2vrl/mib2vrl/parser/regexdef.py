"""
regexdef.py — Regex patterns for parsing ASN.1 MIB files.

Implements pattern matching for standard MIB constructs defined in:
- RFC 2578 (SNMPv2-SMI)
- RFC 2579 (SNMPv2-TC)
- RFC 2580 (SNMPv2-CONF)
- RFC 1212 (OBJECT-TYPE macro, SNMPv1)
- RFC 1215 (TRAP-TYPE macro, SNMPv1)

Flag translations from Python re module:
  re.DOTALL      — dot matches newline
  re.MULTILINE   — ^ and $ match line boundaries
  re.IGNORECASE  — case-insensitive matching
"""

import re
from typing import Optional

# ---------------------------------------------------------------------------
# Object-type matchers
# ---------------------------------------------------------------------------

# obj_V1TC — matches V1 textual conventions
obj_V1TC = re.compile(
    r'^((?!DEFINITIONS)(\S+)\s*::=\s*(?!(?:TEXTUAL-CONVENTION)|(?:[0-9]))'
    r'((?:\[.*?\]\s*)?(?:[^{(\s]+[^\n\S]*){1,2}'
    r'(?:(?:\s*{.*?})|(?:\s*\(.*?(?:\(.*?\))?\)))))',
    re.DOTALL
)

# obj_V2TC — matches V2 textual conventions; minimum match: "TEXTUAL-CONVENTION"
obj_V2TC = re.compile(
    r'^((\S+)\s*::=\s*TEXTUAL-CONVENTION.*?\n\s*SYNTAX\s*'
    r'((?:\[.*?\]\s*)?(?:[^{(\s]+[^\n\S]*){1,2}'
    r'(?:\s*(?:{.*?})|(?:\s*\(.*?(?:\(.*?\))?\)))))',
    re.DOTALL
)
obj_V2TC_MIN = "TEXTUAL-CONVENTION"

# obj_OBJECTTYPE — minimum match: "OBJECT-TYPE"
obj_OBJECTTYPE = re.compile(
    r'^(\S+)\s+OBJECT-TYPE(.*?)::=\s*\{\s*([^{]+)\s*\}$',
    re.DOTALL
)
obj_OBJECTTYPE_MIN = "OBJECT-TYPE"

# obj_OBJECTIDENTIFIER — minimum match: "IDENTIFIER"
obj_OBJECTIDENTIFIER = re.compile(
    r'^(\S+)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_OBJECTIDENTIFIER_MIN = "IDENTIFIER"

# obj_OBJECTIDENTITY — minimum match: "OBJECT-IDENTITY"
obj_OBJECTIDENTITY = re.compile(
    r'^(\S+)\s+OBJECT-IDENTITY(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_OBJECTIDENTITY_MIN = "OBJECT-IDENTITY"

# obj_OBJECTGROUP — minimum match: "OBJECT-GROUP"
obj_OBJECTGROUP = re.compile(
    r'^(\S+)\s+OBJECT-GROUP(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_OBJECTGROUP_MIN = "OBJECT-GROUP"

# obj_OBJECTCLASS — minimum match: "OBJECT-CLASS"
obj_OBJECTCLASS = re.compile(
    r'^(\S+)\s+OBJECT-CLASS(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_OBJECTCLASS_MIN = "OBJECT-CLASS"

# obj_MODULEIDENTITY — minimum match: "MODULE-IDENTITY"
obj_MODULEIDENTITY = re.compile(
    r'^(\S+)\s+MODULE-IDENTITY(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_MODULEIDENTITY_MIN = "MODULE-IDENTITY"

# obj_MODULECOMPLIANCE — minimum match: "MODULE-COMPLIANCE"
obj_MODULECOMPLIANCE = re.compile(
    r'^(\S+)\s+MODULE-COMPLIANCE(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_MODULECOMPLIANCE_MIN = "MODULE-COMPLIANCE"

# obj_AGENTCAPABILITIES — minimum match: "AGENT-CAPABILITIES"
obj_AGENTCAPABILITIES = re.compile(
    r'^(\S+)\s+AGENT-CAPABILITIES(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_AGENTCAPABILITIES_MIN = "AGENT-CAPABILITIES"

# obj_NOTIFICATIONTYPE — minimum match: "NOTIFICATION-TYPE"
obj_NOTIFICATIONTYPE = re.compile(
    r'^(\S+)\s+NOTIFICATION-TYPE(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_NOTIFICATIONTYPE_MIN = "NOTIFICATION-TYPE"

# obj_NOTIFICATIONGROUP — minimum match: "NOTIFICATION-GROUP"
obj_NOTIFICATIONGROUP = re.compile(
    r'^(\S+)\s+NOTIFICATION-GROUP(.*?)::=\s*\{\s*([^{]+)\s*\}',
    re.DOTALL
)
obj_NOTIFICATIONGROUP_MIN = "NOTIFICATION-GROUP"

# obj_TRAPTYPE — minimum match: "TRAP-TYPE"
obj_TRAPTYPE = re.compile(
    r'^(\S+)\s+TRAP-TYPE\s+(.*?)\s*::=\s*([0-9]+)',
    re.DOTALL
)
obj_TRAPTYPE_MIN = "TRAP-TYPE"

# obj_MACRO — minimum match: "MACRO"
obj_MACRO = re.compile(
    r'((\S+)\s+MACRO\s*::=\s*BEGIN(.*?)\n\s*END)',
    re.DOTALL
)
obj_MACRO_MIN = "MACRO"

# ---------------------------------------------------------------------------
# Name matchers
# ---------------------------------------------------------------------------

# name_OBJECTNAME
name_OBJECTNAME = re.compile(r'^[a-z]+[a-zA-Z0-9-]*$')

# name_TCNAME
name_TCNAME = re.compile(r'^[A-Z]+[a-zA-Z0-9-]+(?:\s+.*)?$', re.MULTILINE)

# name_TCNAME_COMPRESSED
name_TCNAME_COMPRESSED = re.compile(r'^([A-Z]+[a-zA-Z0-9-]+)(\(.*\))?$', re.MULTILINE)

# ---------------------------------------------------------------------------
# Syntax matchers
# ---------------------------------------------------------------------------

# syntax_INTEGER
syntax_INTEGER = re.compile(
    r'^(?:\[APPLICATION\s+[0-9]+\]\s+)?(?:IMPLICIT\s+)?INTEGER\s*(?:[\(\{].*?[\}\)])?$',
    re.DOTALL
)

# syntax_COUNTER
syntax_COUNTER = re.compile(r'^COUNTER\s?', re.MULTILINE)

# syntax_GAUGE
syntax_GAUGE = re.compile(r'^GAUGE\s?', re.MULTILINE)

# syntax_IPADDRESS
syntax_IPADDRESS = re.compile(r'^IpAddress\s?', re.MULTILINE)

# syntax_NETWORKADDRESS
syntax_NETWORKADDRESS = re.compile(r'^NetworkAddress\s?', re.MULTILINE)

# syntax_OCTETSTRING
syntax_OCTETSTRING = re.compile(r'^OCTET\s+STRING\s?(?:\({1,2}.*?\){1,2})?', re.MULTILINE)

# syntax_OPAQUE
syntax_OPAQUE = re.compile(r'^OPAQUE\s?', re.MULTILINE)

# syntax_SEQUENCEOF
syntax_SEQUENCEOF = re.compile(r'^SEQUENCE OF\s+(\S+)?', re.DOTALL | re.MULTILINE)

# syntax_SEQUENCE
syntax_SEQUENCE = re.compile(r'^SEQUENCE\s*(?:\{(.*?)\})?', re.DOTALL | re.MULTILINE)

# syntax_CHOICE
syntax_CHOICE = re.compile(r'^CHOICE\s?\{(.*?)\}', re.DOTALL | re.MULTILINE)

# syntax_TIMETICKS
syntax_TIMETICKS = re.compile(r'^TIMETICKS\s?', re.MULTILINE)

# syntax_OBJECTIDENTIFIER
syntax_OBJECTIDENTIFIER = re.compile(r'^OBJECT\s+IDENTIFIER\s?', re.MULTILINE)

# syntax_BITS
syntax_BITS = re.compile(r'^BITS\s*\{(.*?)\}', re.DOTALL | re.MULTILINE)

# syntax_ANY
syntax_ANY = re.compile(r'ANY', re.DOTALL)

# syntax_SEQUENCE_ELEMENT
syntax_SEQUENCE_ELEMENT = re.compile(r'^(\S+)\s+(.*)$', re.DOTALL | re.MULTILINE)

# syntax_OCTETSTRING_SIZE
syntax_OCTETSTRING_SIZE = re.compile(
    r'^\s*OCTET STRING\s+\(\s*SIZE\s*\(([0-9-]+)\.\.([0-9-]+)\)\)$'
)

# syntax_INTEGER_TAGS
syntax_INTEGER_TAGS = re.compile(
    r'^(.*?)(?:\[(\S+)\s+([0-9]+)\]\s+)?(.*?)(?:(IMPLICIT)\s+)?(.*?)$'
)

# syntax_INTEGER_PLAIN
syntax_INTEGER_PLAIN = re.compile(r'^\s*INTEGER\s*$')

# syntax_INTEGER_ENUM
syntax_INTEGER_ENUM = re.compile(r'^\s*INTEGER\s*\{(.*?)\}\s*$', re.DOTALL)

# syntax_INTEGER_RANGE_DECIMAL
syntax_INTEGER_RANGE_DECIMAL = re.compile(
    r'^\s*INTEGER\s+\(([0-9-]+)\.\.([0-9-]+)\)$', re.DOTALL
)

# syntax_INTEGER_RANGE_HEX
syntax_INTEGER_RANGE_HEX = re.compile(
    r"^INTEGER\s*\(([0-9a-fA-F-]+)\.\.'([0-9a-fA-F-]+)'([hH])$", re.DOTALL
)

# syntax_INTEGER_ENUMERATED_VALUES
syntax_INTEGER_ENUMERATED_VALUES = re.compile(r'^(.*?)\((\s*[0-9\-]+\s*)\)$')

# syntax_INTEGER_BITS
syntax_INTEGER_BITS = re.compile(r'BITS\s*\{(.*?)\}\s*$', re.DOTALL)

# syntax_INTEGER_BIT_VALUES
syntax_INTEGER_BIT_VALUES = re.compile(r'^(.*?)\(([0-9]+)\)$')

# ---------------------------------------------------------------------------
# Part matchers (field extractors inside object bodies)
# ---------------------------------------------------------------------------

# part_DISPLAYHINT — minimum match: "DISPLAY-HINT"
part_DISPLAYHINT = re.compile(r'DISPLAY-HINT\s+"([^"]+)"', re.DOTALL)
part_DISPLAYHINT_MIN = "DISPLAY-HINT"

# part_STATUS — minimum match: "STATUS"
part_STATUS = re.compile(r'STATUS\s+(\S+)', re.DOTALL)
part_STATUS_MIN = "STATUS"

# part_DESCRIPTION — minimum match: "DESCRIPTION"
part_DESCRIPTION = re.compile(r'DESCRIPTION\s+"([^"]*)"', re.DOTALL)
part_DESCRIPTION_MIN = "DESCRIPTION"

# part_REFERENCE — minimum match: "REFERENCE"
part_REFERENCE = re.compile(r'REFERENCE\s+"([^"]*)"', re.DOTALL)
part_REFERENCE_MIN = "REFERENCE"

# part_SYNTAX — minimum match: "SYNTAX"
part_SYNTAX = re.compile(
    r'\s*SYNTAX\s+(\S+(?:\s+(?:OF\s+\S+|STRING|IDENTIFIER)?)?\s*'
    r'(?:(?:\{.*?\})|(?:\(.*?(?:\(.*?\))?\)))?)',
    re.DOTALL
)
part_SYNTAX_MIN = "SYNTAX"

# part_WRITESYNTAX — minimum match: "WRITE-SYNTAX"
part_WRITESYNTAX = re.compile(
    r'\s*WRITE-SYNTAX\s+((?:[^{(\s]+[^\n\S]*){1,2}'
    r'(?:\s*(?:\{.*?\})|(?:\(.*?(?:\(.*?\))?\))|(\S+))?)',
    re.DOTALL
)
part_WRITESYNTAX_MIN = "WRITE-SYNTAX"

# part_ACCESS — minimum match: "ACCESS"
part_ACCESS = re.compile(r'\s+ACCESS\s+(\S+)', re.DOTALL)
part_ACCESS_MIN = "ACCESS"

# part_MAXACCESS — minimum match: "MAX-ACCESS"
part_MAXACCESS = re.compile(r'MAX-ACCESS\s+(\S+)', re.DOTALL)
part_MAXACCESS_MIN = "MAX-ACCESS"

# part_MINACCESS — minimum match: "MIN-ACCESS"
part_MINACCESS = re.compile(r'MIN-ACCESS\s+(\S+)', re.DOTALL)
part_MINACCESS_MIN = "MIN-ACCESS"

# part_VARIABLES — minimum match: "VARIABLES"
part_VARIABLES = re.compile(r'VARIABLES\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_VARIABLES_MIN = "VARIABLES"

# part_NOTIFICATIONS — minimum match: "NOTIFICATIONS"
part_NOTIFICATIONS = re.compile(r'NOTIFICATIONS\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_NOTIFICATIONS_MIN = "NOTIFICATIONS"

# part_OBJECTS — minimum match: "OBJECTS"
part_OBJECTS = re.compile(r'OBJECTS\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_OBJECTS_MIN = "OBJECTS"

# part_DEFVAL — minimum match: "DEFVAL"
part_DEFVAL = re.compile(r'DEFVAL\s*\{\s*(.+?)\s*\}', re.DOTALL)
part_DEFVAL_MIN = "DEFVAL"

# part_INDEX — no minimum match
part_INDEX = re.compile(r'(INDEX|AUGMENTS)\s*\{\s*([^}]+)\s*\}')

# part_ENTERPRISE — minimum match: "ENTERPRISE"
part_ENTERPRISE = re.compile(r'ENTERPRISE\s+\{?\s*(\S+)\s*\}?', re.DOTALL)
part_ENTERPRISE_MIN = "ENTERPRISE"

# part_UNITS — minimum match: "UNITS"
part_UNITS = re.compile(r'UNITS\s+"([^"]+)"', re.DOTALL)
part_UNITS_MIN = "UNITS"

# part_REVISION — minimum match: "REVISION"
part_REVISION = re.compile(r'REVISION\s+(.*)\s*::=', re.DOTALL)
part_REVISION_MIN = "REVISION"

# part_ANCESTORS — no minimum match
part_ANCESTORS = re.compile(r'::=\s*\{(.*?)\}', re.DOTALL)

# part_SUBCLASSOF — minimum match: "SUBCLASS"
part_SUBCLASSOF = re.compile(r'SUBCLASS\s+OF\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_SUBCLASSOF_MIN = "SUBCLASS"

# part_SUPERIORS — minimum match: "SUPERIORS"
part_SUPERIORS = re.compile(r'SUPERIORS\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_SUPERIORS_MIN = "SUPERIORS"

# part_NAMES — minimum match: "NAMES"
part_NAMES = re.compile(r'NAMES\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_NAMES_MIN = "NAMES"

# part_CONTAINS — minimum match: "CONTAINS"
part_CONTAINS = re.compile(r'CONTAINS\s+\{\s*([^\}]+)\s*\}', re.DOTALL)
part_CONTAINS_MIN = "CONTAINS"

# part_LASTUPDATED — minimum match: "LAST-UPDATED"
part_LASTUPDATED = re.compile(r'LAST-UPDATED\s+"([^"]*)"', re.DOTALL)
part_LASTUPDATED_MIN = "LAST-UPDATED"

# part_CONTACTINFO — minimum match: "CONTACT-INFO"
part_CONTACTINFO = re.compile(r'CONTACT-INFO\s+"([^"]*)"', re.DOTALL)
part_CONTACTINFO_MIN = "CONTACT-INFO"

# part_ORGANIZATION — minimum match: "ORGANIZATION"
part_ORGANIZATION = re.compile(r'ORGANIZATION\s+"([^"]*)"', re.DOTALL)
part_ORGANIZATION_MIN = "ORGANIZATION"

# part_MODULE
part_MODULE = re.compile(r'(.*)(MODULE\s+([^\n]+)?.*)', re.DOTALL)

# part_MANDATORYGROUPS — minimum match: "MANDATORY-GROUPS"
part_MANDATORYGROUPS = re.compile(
    r'MANDATORY-GROUPS\s+\{\s*([^\}]+)\s*\}\s+(.*)$', re.DOTALL
)
part_MANDATORYGROUPS_MIN = "MANDATORY-GROUPS"

# part_GROUP — minimum match: "GROUP"
part_GROUP = re.compile(
    r'GROUP\s+(\S+)DESCRIPTION\s+"([^"]*)"\s+(.*)', re.DOTALL
)
part_GROUP_MIN = "GROUP"

# part_COMPLIANCEOBJECT — minimum match: "OBJECT"
part_COMPLIANCEOBJECT = re.compile(
    r'(.*)OBJECT\s+(\S+)(.*?)DESCRIPTION\s+"(.*?)"\s*$', re.DOTALL
)
part_COMPLIANCEOBJECT_MIN = "OBJECT"

# part_PRODUCTRELEASE — minimum match: "PRODUCT-RELEASE"
part_PRODUCTRELEASE = re.compile(r'PRODUCT-RELEASE\s+"([^"]*)"', re.DOTALL)
part_PRODUCTRELEASE_MIN = "PRODUCT-RELEASE"

# part_SUPPORTS — minimum match: "SUPPORTS"
part_SUPPORTS = re.compile(
    r'(.*)\s+SUPPORTS\s+(\S+)\s+INCLUDES\s+\{([^\}]*)\}\s+(.*?)$', re.DOTALL
)
part_SUPPORTS_MIN = "SUPPORTS"

# part_VARIATION
part_VARIATION = re.compile(r'(.*)(VARIATION\s+(\S+).*)$', re.DOTALL)

# part_NOTIFICATIONVARIATION — minimum match: "VARIATION"
part_NOTIFICATIONVARIATION = re.compile(
    r'VARIATION\s+(\S+)(?:\s+ACCESS\s+(\S+))?\s+DESCRIPTION\s+"[^"]*"', re.DOTALL
)
part_NOTIFICATIONVARIATION_MIN = "VARIATION"

# part_CREATIONREQUIRES — minimum match: "CREATION-REQUIRES"
part_CREATIONREQUIRES = re.compile(r'CREATION-REQUIRES\s*\{\s*(.+?)\s*\}', re.DOTALL)
part_CREATIONREQUIRES_MIN = "CREATION-REQUIRES"

# ---------------------------------------------------------------------------
# MIB-level pipeline regexes
# ---------------------------------------------------------------------------

# mib_EXTRACT_MIB — splits file into named MIBs
MIB_REGEX = r'((\S+)\s*(?:\{[^}]*\})*\s+DEFINITIONS\s*::=\s*BEGIN(.*?)\n\s*END[\s\n]?)'
mib_EXTRACT_MIB = re.compile(MIB_REGEX, re.DOTALL)

# mib_EXTRACT_IMPORTS_SECTION
mib_EXTRACT_IMPORTS_SECTION = re.compile(r'IMPORTS\s+(.*?);', re.DOTALL)

# mib_IMPORTS
mib_IMPORTS = re.compile(r'^(.*?)\s+FROM\s+(\S+)(.*)$', re.DOTALL)

# mib_EXTRACT_EXPORTS_SECTION
mib_EXTRACT_EXPORTS_SECTION = re.compile(r'(EXPORTS\s+(.*?);)', re.DOTALL)

# mib_REPLACE_STRING — protects quoted string literals before comment stripping
mib_REPLACE_STRING = re.compile(r'(^(?:[^-\n"]|-(?!-))*?)("[^"]*")', re.MULTILINE)

# mib_RESTORE_STRING
mib_RESTORE_STRING = re.compile(r'\[\[STRING\.([0-9]+)\]\]', re.DOTALL)

# mib_EXTRACT_COMMENT — removes -- comments
mib_EXTRACT_COMMENT = re.compile(r'(-{2}.*?)(\n)', re.DOTALL)

# mib_REPLACE_MACRO
mib_REPLACE_MACRO = re.compile(
    r'((\S+)\s+MACRO\s*::=\s*BEGIN.*?\n\s*END)', re.DOTALL
)

# mib_RESTORE_MACRO
mib_RESTORE_MACRO = re.compile(r'\[\[MACRO\.([0-9]+)\]\]', re.DOTALL)

# mib_EXTRACT_MACRO — substitution that removes all macros
mib_EXTRACT_MACRO = re.compile(r'\S+\s+MACRO\s*::=\s*BEGIN.*?\n\s*END', re.DOTALL)

# mib_EXTRACT_TC_V1
mib_EXTRACT_TC_V1 = re.compile(
    r'\s+((?!DEFINITIONS)(\S+)\s*::=\s*(?!(?:TEXTUAL-CONVENTION)|(?:[0-9]))'
    r'((?:\[.*?\]\s*)?(?:[^{(\s]+[^\n\S]*){1,2}'
    r'(?:(?:\s*\{.*?\})|(?:\s*\(.*?(?:\(.*?\))?\)))))',
    re.DOTALL
)

# mib_EXTRACT_TC_V2
mib_EXTRACT_TC_V2 = re.compile(
    r'((\S+)\s*::=\s*TEXTUAL-CONVENTION.*?\n\s*SYNTAX\s*'
    r'((?:\[.*?\]\s*)?(?:[^{(\s]+[^\n\S]*){1,2}'
    r'(?:\s*(?:\{.*?\})|(?:\s*\(.*?(?:\(.*?\)\s*)?\)))))',
    re.DOTALL
)

# mib_EXTRACT_TRAPTYPE
mib_EXTRACT_TRAPTYPE = re.compile(
    r'(\S+\s+TRAP-TYPE[^(::=)]+\s*::=\s*[0-9]+)', re.DOTALL
)

# mib_EXTRACT_OBJECTS
mib_EXTRACT_OBJECTS = re.compile(
    r'((?!SYNTAX)\S+\s+'
    r'(OBJECT-TYPE|OBJECT\s+IDENTIFIER|OBJECT-GROUP|OBJECT-IDENTITY'
    r'|MODULE-COMPLIANCE|MODULE-IDENTITY|NOTIFICATION-TYPE'
    r'|NOTIFICATION-GROUP|AGENT-CAPABILITIES)'
    r'\s*.*?\s*::=\s*\{\s*.*?\s*\})',
    re.DOTALL
)

# ---------------------------------------------------------------------------
# OID regexes
# ---------------------------------------------------------------------------

# oid_LEAF — pure digit string
oid_LEAF = re.compile(r'^([0-9]+)$')

# oid_NULL — "0 0"
oid_NULL = re.compile(r'^0\s+0$')

# oid_V1TOV2 — "name number number"
oid_V1TOV2 = re.compile(r'^(\S+)(\s+[0-9]+)(\s+[0-9]+)$')

# oid_SPACESEPARATED — space-separated digits only
oid_SPACESEPARATED = re.compile(r'^([0-9 ]+)$')

# oid_DOTSEPARATED — dot-separated digits only
oid_DOTSEPARATED = re.compile(r'^([0-9\.]+)$')

# oid_MIXED — name(n) followed by more components
oid_MIXED = re.compile(
    r'^([^\s\(]+)(?:\([0-9]+\))?\s+([^\s\(]+(?:\([0-9]+\))\s+.*)$', re.DOTALL
)

# oid_MIXED_LONG — name followed by number then more
oid_MIXED_LONG = re.compile(r'^(\S+)(\s+[0-9]+)(\s+.*)$', re.DOTALL)

# oid_NORMAL — "name number"
oid_NORMAL = re.compile(r'^([^\s\(]+)(?:\([0-9]+\))?\s+([0-9]+)$')

# oid_ENTERPRISE — single non-space token (no parens, no spaces)
oid_ENTERPRISE = re.compile(r'^([^ \(\)]+)$')

# oid_FULLYQUALIFIED — all components are name(n)
oid_FULLYQUALIFIED = re.compile(
    r'^([^\s\(]+)(?:\([0-9]+\))?((?:\s*\S+\([0-9]+\))+)$'
)

# oid_FULLYQUALIFIED_NODE — single "name(n)"
oid_FULLYQUALIFIED_NODE = re.compile(r'^([^\s\(]+)(?:\(([0-9]+)\))$')

# ---------------------------------------------------------------------------
# Helper functions mirroring RegexDef static methods
# ---------------------------------------------------------------------------

_string_store: dict[str, str] = {}
_macro_store: dict[str, str] = {}
_string_counter: int = 0
_macro_counter: int = 0


def _reset_stores() -> None:
    """Reset thread-local replacement stores (call after each MIB parse)."""
    global _string_store, _macro_store, _string_counter, _macro_counter
    _string_store = {}
    _macro_store = {}
    _string_counter = 0
    _macro_counter = 0


def remove_comments(text: str) -> str:
    """RegexDef.RemoveComments — strips -- ... newline comment sequences."""
    # s/(-{2}.*?)(\n)/\n/gs
    return re.sub(r'--.*?(\n)', r'\1', text, flags=re.DOTALL)


def replace_strings(text: str) -> str:
    """RegexDef.ReplaceStrings — replaces "quoted strings" with [[STRING.N]] tokens."""
    global _string_counter, _string_store

    def replacer(m: re.Match) -> str:
        global _string_counter
        prefix = m.group(1)
        quoted = m.group(2)
        _string_counter += 1
        token = f"[[STRING.{_string_counter}]]"
        _string_store[str(_string_counter)] = quoted
        return prefix + token

    # Java pattern: /(^(?:[^-\n"]|-(?!-))*?)("[^"]*")/m
    # Matches: prefix (no double-quote, no newline, allow single - but not --)
    # then a double-quoted string; [^"] = negated char class (not a space+caret+quote)
    #
    # The pattern anchors at ^ (MULTILINE), so one re.sub pass replaces the first
    # quoted string on each line.  A second pass is only needed for the rare case
    # of multiple quoted strings on the same line.  This is O(N × max_per_line)
    # instead of the former O(N × total_strings) caused by count=1.
    pattern = re.compile(r'(^(?:[^-\n"]|-(?!-))*?)("[^"]*")', re.MULTILINE)
    result = text
    while True:
        new = pattern.sub(replacer, result)
        if new == result:
            break
        result = new
    return result


def restore_strings(text: str) -> str:
    """RegexDef.RestoreStrings — restores [[STRING.N]] tokens to original strings."""
    def replacer(m: re.Match) -> str:
        key = m.group(1)
        return _string_store.get(key, m.group(0))

    return mib_RESTORE_STRING.sub(replacer, text)


def replace_macros(text: str) -> str:
    """RegexDef.ReplaceMacros — replaces MACRO definitions with [[MACRO.N]] tokens."""
    global _macro_counter, _macro_store

    def replacer(m: re.Match) -> str:
        global _macro_counter
        _macro_counter += 1
        token = f"[[MACRO.{_macro_counter}]]"
        _macro_store[str(_macro_counter)] = m.group(1)
        return token

    return mib_REPLACE_MACRO.sub(replacer, text)


def restore_macros(text: str) -> str:
    """RegexDef.RestoreMacros — restores [[MACRO.N]] tokens."""
    def replacer(m: re.Match) -> str:
        key = m.group(1)
        return _macro_store.get(key, m.group(0))

    return mib_RESTORE_MACRO.sub(replacer, text)


def extract_macros(text: str) -> str:
    """RegexDef.ExtractMacros — removes all MACRO definitions."""
    return mib_EXTRACT_MACRO.sub("", text)


def _fast_module_sections(text: str) -> list[str]:
    """
    Line-by-line scan for DEFINITIONS::=BEGIN / END boundaries.

    Returns a list of text slices, each containing one MIB module.
    Uses the last blank line before DEFINITIONS as the section start so
    multi-line module headers (rare) are captured correctly.

    Called only for files > 10 000 lines; avoids running the full regex
    pipeline on the entire file when modules can be processed individually.
    """
    sections: list[str] = []
    in_module = False
    start_pos = 0
    last_blank_end = 0   # char position after the most recent blank line
    pos = 0

    for line in text.splitlines(keepends=True):
        stripped = line.rstrip('\r\n').strip()
        if not in_module:
            if not stripped:
                last_blank_end = pos + len(line)
            elif 'DEFINITIONS' in line and 'BEGIN' in line:
                in_module = True
                start_pos = last_blank_end
        else:
            if stripped == 'END' or (
                stripped.startswith('END') and len(stripped) > 3 and stripped[3] in ' \t\r-'
            ):
                end_pos = pos + len(line)
                sections.append(text[start_pos:end_pos])
                in_module = False
                last_blank_end = end_pos
        pos += len(line)

    return sections


def _split_mibs_section(text: str) -> dict[str, str]:
    """Core split pipeline for a single text section (one or few modules)."""
    _reset_stores()
    work = replace_strings(text)
    work = remove_comments(work)
    work = replace_macros(work)

    mibs: dict[str, str] = {}
    for m in mib_EXTRACT_MIB.finditer(work):
        mib_name = m.group(2).strip()
        mibs[mib_name] = m.group(1)

    for name in list(mibs.keys()):
        body = restore_macros(mibs[name])
        body = restore_strings(body)
        mibs[name] = body

    _reset_stores()
    return mibs


def split_mibs(text: str) -> dict[str, str]:
    """
    RegexDef.SplitMibs — splits a multi-MIB file into {mib_name: mib_body}.

    Mirrors the Java pipeline:
      1. ReplaceStrings
      2. RemoveComments
      3. ReplaceMacros
      4. ExtractMibs (regex extract)
      5. RestoreMacros + RestoreStrings on each extracted body

    For files > 10 000 lines a fast line-based pre-scan splits the text into
    per-module sections first, so every expensive regex sees only one module's
    worth of text instead of the entire file.
    """
    if text.count('\n') > 10_000:
        sections = _fast_module_sections(text)
        if sections:
            mibs: dict[str, str] = {}
            for section in sections:
                mibs.update(_split_mibs_section(section))
            if mibs:
                return mibs
        # Fall through if the pre-scan found nothing (unusual MIB layout)

    return _split_mibs_section(text)


def extract_imports(text: str) -> tuple[str, list[tuple[str, str]]]:
    """
    RegexDef.ExtractImports — extracts IMPORTS section.

    Returns (remaining_text, [(object_name, mib_module), ...]).
    """
    imports: list[tuple[str, str]] = {}

    def replacer(m: re.Match) -> str:
        imports_text = m.group(1)
        # Each line: "SymbolA, SymbolB FROM ModuleName"
        for chunk in re.split(r'\s+FROM\s+', imports_text.strip()):
            pass  # handled below
        return ""

    remaining = mib_EXTRACT_IMPORTS_SECTION.sub(replacer, text, count=1)

    # Re-parse properly
    result: list[tuple[str, str]] = []
    for m in mib_EXTRACT_IMPORTS_SECTION.finditer(text):
        imports_text = m.group(1)
        # Parse "sym, sym, ... FROM ModuleName" blocks separated by commas+FROM
        # mib_IMPORTS: /^(.*?)\s+FROM\s+(\S+)(.*)$/s
        current = imports_text.strip()
        while True:
            im = mib_IMPORTS.match(current)
            if not im:
                break
            objects_raw = im.group(1)
            mib_name = im.group(2).strip().rstrip(";,")
            rest = im.group(3).strip() if im.group(3) else ""
            for obj in objects_raw.split(","):
                obj = obj.strip()
                if obj:
                    result.append((obj, mib_name))
            current = rest
            if not current:
                break

    remaining = mib_EXTRACT_IMPORTS_SECTION.sub("", text, count=1)
    return remaining, result


def extract_exports(text: str) -> tuple[str, list[str]]:
    """
    RegexDef.ExtractExports — extracts EXPORTS section.

    Returns (remaining_text, [export_name, ...]).
    """
    exports: list[str] = []
    m = mib_EXTRACT_EXPORTS_SECTION.search(text)
    if m:
        exports_text = m.group(2)
        for name in exports_text.split(","):
            name = name.strip()
            if name:
                exports.append(name)
        remaining = mib_EXTRACT_EXPORTS_SECTION.sub("", text, count=1)
    else:
        remaining = text
    return remaining, exports


def extract_trap_types(text: str) -> tuple[str, list[str]]:
    """
    RegexDef.ExtractTrapTypes — extracts TRAP-TYPE object blocks.

    Returns (remaining_text, [trap_block, ...]).
    """
    blocks: list[str] = []
    for m in mib_EXTRACT_TRAPTYPE.finditer(text):
        blocks.append(m.group(1))
    remaining = mib_EXTRACT_TRAPTYPE.sub("", text)
    return remaining, blocks


def extract_objects(text: str) -> tuple[str, list[str]]:
    """
    RegexDef.ExtractObjects — extracts all named MIB object blocks.

    Returns (remaining_text, [object_block, ...]).
    """
    blocks: list[str] = []
    for m in mib_EXTRACT_OBJECTS.finditer(text):
        blocks.append(m.group(1))
    remaining = mib_EXTRACT_OBJECTS.sub("", text)
    return remaining, blocks


def extract_v1_tcs(text: str) -> tuple[str, list[str]]:
    """
    RegexDef.ExtractV1Tcs — extracts v1 TEXTUAL-CONVENTION definitions.

    Returns (remaining_text, [tc_block, ...]).
    """
    blocks: list[str] = []
    for m in mib_EXTRACT_TC_V1.finditer(text):
        blocks.append(m.group(1))
    remaining = mib_EXTRACT_TC_V1.sub("", text)
    return remaining, blocks


def extract_v2_tcs(text: str) -> tuple[str, list[str]]:
    """
    RegexDef.ExtractV2Tcs — extracts v2 TEXTUAL-CONVENTION definitions.

    Returns (remaining_text, [tc_block, ...]).
    """
    blocks: list[str] = []
    for m in mib_EXTRACT_TC_V2.finditer(text):
        blocks.append(m.group(1))
    remaining = mib_EXTRACT_TC_V2.sub("", text)
    return remaining, blocks


def search_and_match(pattern: re.Pattern, text: str, count: int) -> Optional[list[Optional[str]]]:
    """
    Mimic RegexDef.searchAndMatch(text, count) — returns list of up to `count`
    groups (1-indexed), trimmed, or None if no match.
    """
    m = pattern.search(text)
    if m is None:
        return None
    groups = m.groups()
    result: list[Optional[str]] = []
    for i in range(count):
        val = groups[i] if i < len(groups) else None
        result.append(val.strip() if val is not None else None)
    return result


def matches(pattern: re.Pattern, text: str, minimum: Optional[str] = None) -> bool:
    """Mimic RegexDef.matches() with optional minimum-match fast-reject."""
    if minimum and minimum not in text:
        return False
    return pattern.search(text) is not None
