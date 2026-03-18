"""GraphQL taxonomy-driven mutator.

Targets GraphQL parsing and validation differentials across libraries:
  G1  Depth bombing            → deeply nested fields (friends{friends{...}})
  G2  Directive injection      → @skip/@include with edge-case args
  G3  Enum case confusion      → ADMIN vs admin vs Admin vs UNKNOWN
  G4  Fragment manipulation    → circular fragments, type condition swaps
  G5  Alias flooding           → many aliases for same field
  G6  Introspection injection  → __schema, __type, __typename insertion
  G7  Operation type swaps     → query↔mutation↔subscription
  G8  Variable type confusion  → wrong types, missing required, extra vars
  G9  Comment/whitespace       → unusual whitespace, comments in odd places
  G10 String injection         → special chars in string values
"""

from __future__ import annotations

import logging
import random
import re
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 16384

# Strategy weights: (name, weight, function_name)
_STRATEGIES = [
    ("depth_bomb", 12, "_mutate_depth_bomb"),
    ("directive_inject", 12, "_mutate_directive_inject"),
    ("enum_case", 15, "_mutate_enum_case"),
    ("fragment_manip", 10, "_mutate_fragment"),
    ("alias_flood", 8, "_mutate_alias_flood"),
    ("introspection_inject", 10, "_mutate_introspection"),
    ("operation_swap", 8, "_mutate_operation_swap"),
    ("variable_confusion", 10, "_mutate_variable_confusion"),
    ("whitespace_comment", 8, "_mutate_whitespace"),
    ("string_inject", 7, "_mutate_string_inject"),
]


class GraphqlMutator:
    """Domain-specific GraphQL mutator."""

    name = "graphql"

    def __init__(self, seed: int | None = None):
        self._rng = random.Random(seed)
        self._weights = [w for _, w, _ in _STRATEGIES]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        raw = inp.data.decode("utf-8", errors="replace")

        # Pick strategy by weight
        strategy = self._rng.choices(_STRATEGIES, weights=self._weights, k=1)[0]
        strategy_name, _, method_name = strategy

        try:
            mutated = getattr(self, method_name)(raw)
        except Exception:
            mutated = raw

        if not mutated or len(mutated) > MAX_OUTPUT_SIZE:
            mutated = raw

        metadata = dict(inp.metadata) if inp.metadata else {}
        metadata["graphql_strategy"] = strategy_name

        return Input(data=mutated.encode("utf-8", errors="replace"), metadata=metadata)

    # ── G1: Depth bomb ────────────────────────────────────────────────

    def _mutate_depth_bomb(self, raw: str) -> str:
        depth = self._rng.choice([5, 10, 20, 50, 100, 200, 500])
        field = self._rng.choice(["friends", "posts"])

        if field == "friends":
            inner = "id name"
            for _ in range(depth):
                inner = f"id name friends {{ {inner} }}"
            return f'{{ user(id: "1") {{ {inner} }} }}'
        else:
            # posts don't self-reference, but nested comments→post→author→posts chain
            inner = "id title"
            for _ in range(min(depth, 50)):
                inner = f"id title author {{ name posts {{ {inner} }} }}"
            return f'{{ user(id: "1") {{ posts {{ {inner} }} }} }}'

    # ── G2: Directive injection ───────────────────────────────────────

    def _mutate_directive_inject(self, raw: str) -> str:
        directives = [
            "@skip(if: true)",
            "@skip(if: false)",
            "@include(if: true)",
            "@include(if: false)",
            "@skip(if: null)",
            "@include(if: null)",
            "@skip(if: 0)",
            "@skip(if: 1)",
            '@skip(if: "true")',
            "@skip",
            "@include",
            "@deprecated",
            "@deprecated(reason: \"test\")",
            "@skip(if: true) @include(if: true)",
            "@skip(if: true) @skip(if: false)",
            "@unknown",
            "@custom(arg: 42)",
        ]
        directive = self._rng.choice(directives)

        # Insert after a field name
        lines = raw.split("\n")
        field_keywords = ["name", "email", "role", "id", "title", "status", "score"]
        candidates = []
        for i, line in enumerate(lines):
            stripped = line.strip()
            for kw in field_keywords:
                if stripped == kw or stripped.startswith(kw + " "):
                    candidates.append((i, kw))

        if candidates:
            idx, kw = self._rng.choice(candidates)
            lines[idx] = lines[idx].replace(kw, f"{kw} {directive}", 1)
            return "\n".join(lines)

        # Fallback: wrap entire query with directive on operation
        if raw.strip().startswith("query"):
            return raw.replace("{", f"{directive} {{", 1)
        return raw + f"\n# directive: {directive}"

    # ── G3: Enum case confusion ───────────────────────────────────────

    def _mutate_enum_case(self, raw: str) -> str:
        enum_map = {
            "ADMIN": ["admin", "Admin", "aDmIn", "ADMIN", "SUPERADMIN", "root"],
            "USER": ["user", "User", "uSeR", "USER", "MEMBER", "normal"],
            "GUEST": ["guest", "Guest", "GUEST", "anonymous", "ANON"],
            "ACTIVE": ["active", "Active", "ACTIVE", "enabled"],
            "SUSPENDED": ["suspended", "Suspended", "BANNED"],
            "DELETED": ["deleted", "Deleted", "REMOVED"],
        }

        for original, variants in enum_map.items():
            if original in raw:
                replacement = self._rng.choice(variants)
                return raw.replace(original, replacement, 1)

        # Inject enum usage if not present
        role = self._rng.choice(["admin", "SUPERADMIN", "Root", "0", '""', "null", "true"])
        return f'mutation {{ updateUser(id: "1", role: {role}) {{ id role }} }}'

    # ── G4: Fragment manipulation ─────────────────────────────────────

    def _mutate_fragment(self, raw: str) -> str:
        mutations = [
            # Circular fragment reference
            "fragment A on User { ...B }\nfragment B on User { ...A }",
            # Type condition swap
            "fragment WrongType on Post { id name role }",
            # Fragment on wrong type for union
            "fragment SearchFrag on SearchResult { ... on User { id title } }",
            # Unused fragment
            raw + "\nfragment Unused on User { id name }",
            # Duplicate fragment names
            raw + "\nfragment F on User { id }\nfragment F on Post { id }",
            # Fragment spread without definition
            '{ user(id: "1") { ...NonExistent } }',
            # Inline fragment without type condition
            '{ user(id: "1") { ... { name role } } }',
        ]
        return self._rng.choice(mutations)

    # ── G5: Alias flooding ────────────────────────────────────────────

    def _mutate_alias_flood(self, raw: str) -> str:
        count = self._rng.choice([5, 10, 50, 100])
        fields = []
        for i in range(count):
            fields.append(f'a{i}: user(id: "{i}") {{ id name }}')
        return "query AliasFlood {\n  " + "\n  ".join(fields) + "\n}"

    # ── G6: Introspection injection ───────────────────────────────────

    def _mutate_introspection(self, raw: str) -> str:
        injections = [
            '{ __schema { types { name kind } } }',
            '{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }',
            '{ __type(name: "User") { name fields { name type { name kind } } } }',
            '{ __type(name: "__Schema") { name } }',
            '{ user(id: "1") { id __typename } }',
            '{ __schema { directives { name locations args { name } } } }',
            # Mixed: introspection alongside normal query
            '{ user(id: "1") { id name } __schema { types { name } } }',
        ]
        return self._rng.choice(injections)

    # ── G7: Operation type swap ───────────────────────────────────────

    def _mutate_operation_swap(self, raw: str) -> str:
        ops = ["query", "mutation", "subscription"]
        for op in ops:
            if raw.strip().startswith(op):
                new_op = self._rng.choice([o for o in ops if o != op])
                return raw.replace(op, new_op, 1)

        # Shorthand to named
        if raw.strip().startswith("{"):
            op = self._rng.choice(ops)
            return f"{op} Op " + raw

        return raw

    # ── G8: Variable type confusion ───────────────────────────────────

    def _mutate_variable_confusion(self, raw: str) -> str:
        mutations = [
            # Wrong type for variable
            'query ($id: String!) { user(id: $id) { id name } }',
            'query ($id: Int!) { user(id: $id) { id name } }',
            'query ($role: String) { users(filter: { role: $role }) { id } }',
            # Required vs optional
            'query ($id: ID) { user(id: $id) { id name } }',
            'query ($limit: Int!) { user(id: "1") { posts(limit: $limit) { id } } }',
            # Default value confusion
            'query ($role: Role = SUPERADMIN) { users(filter: { role: $role }) { id } }',
            'query ($limit: Int = -1) { user(id: "1") { posts(limit: $limit) { id } } }',
            'query ($limit: Int = null) { user(id: "1") { posts(limit: $limit) { id } } }',
            # Extra unused variable
            'query ($id: ID!, $unused: String) { user(id: $id) { id name } }',
            # List coercion
            'query ($tags: String) { users(filter: { tags: $tags }) { id } }',
            'query ($tags: [String]!) { users(filter: { tags: $tags }) { id } }',
        ]
        return self._rng.choice(mutations)

    # ── G9: Whitespace/comment injection ──────────────────────────────

    def _mutate_whitespace(self, raw: str) -> str:
        mutations = [
            # Unusual whitespace
            lambda r: r.replace(" ", "\t"),
            lambda r: r.replace(" ", "  \t  "),
            lambda r: r.replace("\n", "\r\n"),
            # Comments in various places
            lambda r: r.replace("{", "# comment\n{", 1),
            lambda r: r.replace("}", "# inline comment\n}", 1),
            lambda r: "# leading comment\n" + r,
            lambda r: r + "\n# trailing comment",
            # BOM
            lambda r: "\ufeff" + r,
            # Unicode spaces
            lambda r: r.replace(" ", "\u00a0", 1),  # non-breaking space
            lambda r: r.replace(" ", "\u2003", 1),   # em space
        ]
        mutation = self._rng.choice(mutations)
        return mutation(raw)

    # ── G10: String value injection ───────────────────────────────────

    def _mutate_string_inject(self, raw: str) -> str:
        payloads = [
            '<script>alert(1)</script>',
            '"; DROP TABLE users; --',
            '\\u0000null\\u0000',
            'a' * 10000,
            '../../../etc/passwd',
            '{{template_injection}}',
            '${env.SECRET}',
            '\n\r\t',
            '\\',
            '"escaped\\"quote"',
        ]
        payload = self._rng.choice(payloads)

        # Replace a string value
        if '"' in raw:
            strings = re.findall(r'"([^"]*)"', raw)
            if strings:
                target = self._rng.choice(strings)
                return raw.replace(f'"{target}"', f'"{payload}"', 1)

        return f'{{ user(id: "{payload}") {{ id name }} }}'
