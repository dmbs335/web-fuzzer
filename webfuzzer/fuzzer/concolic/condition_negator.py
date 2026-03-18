"""AST-based condition semantic parser and negation engine.

Parses Python if-conditions from source AST, understands what they check,
and generates concrete mutation directives to flip the branch.

This is the core of real concolic execution: instead of keyword matching
("namespace found → try namespace perturbation"), we parse the actual
condition semantics and generate precise negation mutations.

Example:
    Condition: ``len(references) != 1``
    Parse: CompareLen(target="references", op="!=", value=1)
    Negate: SetCount(target="references", count=1)
    → generate XML with exactly 1 Reference element

    Condition: ``x509_data is not None``
    Parse: IsNotNone(target="x509_data")
    Negate: Remove(target="x509_data")
    → remove X509Data element from input
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class MutationDirective:
    """Concrete mutation instruction generated from condition negation.

    Unlike the keyword-based system that says "try namespace perturbation",
    this gives specific instructions like "set Reference count to 1" or
    "remove X509Data element".
    """

    action: str  # "set_count", "remove", "add", "set_value", "set_attr", "toggle"
    target: str  # XML element/attribute name (e.g., "Reference", "x509_data")
    value: Any = None  # target value (e.g., 1 for set_count, "none" for set_value)
    context: str = ""  # human-readable description


# ── XML name resolution ─────────────────────────────────────────
# Maps Python variable names commonly used in SAML/XML code to XML elements

_VAR_TO_XML: dict[str, str] = {
    # signxml
    "references": "ds:Reference",
    "reference": "ds:Reference",
    "verify_results": "ds:Reference",
    "x509_data": "ds:X509Data",
    "x509_cert": "ds:X509Certificate",
    "key_value": "ds:KeyValue",
    "key_info": "ds:KeyInfo",
    "transforms_node": "ds:Transforms",
    "transform": "ds:Transform",
    "signature_node": "ds:Signature",
    "signature": "ds:Signature",
    "signed_info": "ds:SignedInfo",
    "digest_alg": "ds:DigestMethod@Algorithm",
    "signature_alg": "ds:SignatureMethod@Algorithm",
    "c14n_algorithm": "ds:CanonicalizationMethod@Algorithm",
    "algorithm": "Algorithm",
    "inclusive_namespaces": "ec:InclusiveNamespaces",
    "id_attribute": "ID",
    # python3-saml
    "assertions": "saml:Assertion",
    "assertion": "saml:Assertion",
    "signed_elements": "saml:Assertion",
    "signature_nodes": "ds:Signature",
    "conditions_nodes": "saml:Conditions",
    "audience_nodes": "saml:Audience",
    "audience_restriction": "saml:AudienceRestriction",
    "issuers": "saml:Issuer",
    "issuer": "saml:Issuer",
    "name_id_node": "saml:NameID",
    "nameid_data": "saml:NameID",
    "subject_nodes": "saml:Subject",
    "not_on_or_after": "NotOnOrAfter",
    "not_before": "NotBefore",
    "nb_attr": "NotBefore",
    "nooa_attr": "NotOnOrAfter",
    # JWT (for Python JWT libs)
    "payload": "payload",
    "header": "header",
    "algorithms": "alg",
    "key": "key",
    "audience": "aud",
    "issuer_claim": "iss",
}

_ALGORITHM_VALUES: dict[str, list[str]] = {
    "sha1": [
        "http://www.w3.org/2000/09/xmldsig#sha1",
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    ],
    "sha256": [
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    ],
    "exc-c14n": [
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    ],
}


class ConditionNegator:
    """Parse Python AST conditions and generate negation mutations.

    Given a source-level condition string from an if-statement,
    produces MutationDirectives that would flip the branch.
    """

    def negate(self, condition_source: str, file: str = "", line: int = 0) -> list[MutationDirective]:
        """Parse a condition and return mutation directives to negate it.

        Handles both Python and JavaScript condition syntax.
        Returns empty list if condition is not parseable or not input-dependent.
        """
        # Try Python AST first
        try:
            tree = ast.parse(condition_source, mode="eval")
            result = self._negate_node(tree.body)
            if result:
                return result
        except SyntaxError:
            pass

        # Fallback: regex-based JS pattern matching
        return self._negate_js_patterns(condition_source)

    def _negate_node(self, node: ast.expr) -> list[MutationDirective]:
        """Recursively negate an AST expression node."""
        # Pattern: X is None / X is not None
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            op = node.ops[0]
            right = node.comparators[0]

            # X is None → add X; X is not None → remove X
            if isinstance(op, ast.Is) and isinstance(right, ast.Constant) and right.value is None:
                target = self._resolve_target(node.left)
                if target:
                    return [MutationDirective("remove", target, context=f"negate: {target} is None → remove {target}")]

            if isinstance(op, ast.IsNot) and isinstance(right, ast.Constant) and right.value is None:
                target = self._resolve_target(node.left)
                if target:
                    return [MutationDirective("add", target, context=f"negate: {target} is not None → ensure absent")]

            # len(X) == N → set count != N; len(X) != N → set count = N
            if isinstance(node.left, ast.Call) and self._is_len_call(node.left):
                inner = node.left.args[0] if node.left.args else None
                target = self._resolve_target(inner) if inner else None
                if target and isinstance(right, ast.Constant) and isinstance(right.value, int):
                    n = right.value
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        # len(X) == N → make len != N; len(X) != N → make len = N
                        if isinstance(op, ast.Eq):
                            # Need count != N: try 0, N-1, N+1
                            directives = []
                            if n > 0:
                                directives.append(MutationDirective("set_count", target, 0, f"negate: len({target})!={n} → remove all"))
                            directives.append(MutationDirective("set_count", target, n + 1, f"negate: len({target})!={n} → add extra"))
                            return directives
                        else:  # NotEq
                            return [MutationDirective("set_count", target, n, f"negate: len({target})=={n} → set exactly {n}")]

                    if isinstance(op, (ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
                        # len(X) > N → make len <= N
                        if isinstance(op, ast.Gt):
                            return [MutationDirective("set_count", target, n, f"negate: len({target})<={n}")]
                        if isinstance(op, ast.GtE):
                            return [MutationDirective("set_count", target, max(n - 1, 0), f"negate: len({target})<{n}")]
                        if isinstance(op, ast.Lt):
                            return [MutationDirective("set_count", target, n, f"negate: len({target})>={n}")]
                        if isinstance(op, ast.LtE):
                            return [MutationDirective("set_count", target, n + 1, f"negate: len({target})>{n}")]

            # X == "value" → set X to different value; X != "value" → set X = value
            if isinstance(right, ast.Constant) and isinstance(right.value, str):
                target = self._resolve_target(node.left)
                if target:
                    val = right.value
                    if isinstance(op, ast.Eq):
                        return [MutationDirective("set_value", target, f"NOT_{val}", f"negate: {target}!='{val}'")]
                    if isinstance(op, ast.NotEq):
                        return [MutationDirective("set_value", target, val, f"negate: {target}=='{val}'")]

            # X.startswith("prefix") in a Compare context is handled below

        # Pattern: X.startswith("Y") → make X not start with Y
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method == "startswith" and node.args:
                target = self._resolve_target(node.func.value)
                arg = node.args[0]
                if target and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    prefix = arg.value
                    return [MutationDirective("set_value", target, f"NOPE_{prefix}", f"negate: {target} not startswith '{prefix}'")]

            if method == "endswith" and node.args:
                target = self._resolve_target(node.func.value)
                arg = node.args[0]
                if target and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    suffix = arg.value
                    return [MutationDirective("set_value", target, f"nope", f"negate: {target} not endswith '{suffix}'")]

        # Pattern: not X → add/ensure X
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            inner_directives = self._negate_node(node.operand)
            # Flip: if inner says "remove", we say "add", etc.
            flipped = []
            for d in inner_directives:
                if d.action == "remove":
                    flipped.append(MutationDirective("add", d.target, d.value, f"double-negate: add {d.target}"))
                elif d.action == "add":
                    flipped.append(MutationDirective("remove", d.target, d.value, f"double-negate: remove {d.target}"))
                else:
                    flipped.append(d)
            return flipped if flipped else []

        # Pattern: X and Y → negate either X or Y
        if isinstance(node, ast.BoolOp):
            # For AND: negate any one operand; for OR: negate all
            if isinstance(node.op, ast.And):
                for operand in node.values:
                    directives = self._negate_node(operand)
                    if directives:
                        return directives  # negating one is sufficient
            elif isinstance(node.op, ast.Or):
                all_directives = []
                for operand in node.values:
                    all_directives.extend(self._negate_node(operand))
                return all_directives

        # Pattern: X in Y (membership)
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.In, ast.NotIn)):
            target = self._resolve_target(node.left)
            if target:
                if isinstance(node.ops[0], ast.In):
                    return [MutationDirective("set_value", target, "UNKNOWN_VALUE", f"negate: {target} not in collection")]
                else:
                    # Try to extract a value from the collection
                    return [MutationDirective("toggle", target, context=f"negate: {target} in collection")]

        return []

    def _resolve_target(self, node: ast.expr | None) -> str | None:
        """Resolve a Python AST node to an XML element/attribute name."""
        if node is None:
            return None

        if isinstance(node, ast.Name):
            return _VAR_TO_XML.get(node.id, node.id)

        if isinstance(node, ast.Attribute):
            # self.config.X → ignore config
            if isinstance(node.value, ast.Attribute) and node.value.attr == "config":
                return None
            # X.Y → try Y as target
            return _VAR_TO_XML.get(node.attr, node.attr)

        if isinstance(node, ast.Subscript):
            return self._resolve_target(node.value)

        return None

    @staticmethod
    def _is_len_call(node: ast.Call) -> bool:
        """Check if this is a len() call."""
        return isinstance(node.func, ast.Name) and node.func.id == "len"


    # ── JS pattern matching (for conditions that don't parse as Python) ──

    def _negate_js_patterns(self, condition: str) -> list[MutationDirective]:
        """Regex-based negation for JavaScript/TypeScript conditions."""
        directives: list[MutationDirective] = []
        cond = condition.strip()

        # Pattern: X != null / X !== null / X == null / X === null
        m = re.match(r"(\w[\w.]*)\s*(!==?|===?)\s*null\b", cond)
        if m:
            var_name = m.group(1)
            op = m.group(2)
            target = _VAR_TO_XML.get(var_name.split(".")[-1], var_name.split(".")[-1])
            if "!" in op:  # != null → present check → negate: remove
                return [MutationDirective("remove", target, context=f"JS negate: {var_name} != null → remove")]
            else:  # == null → absent check → negate: add
                return [MutationDirective("add", target, context=f"JS negate: {var_name} == null → add")]

        # Pattern: X.length > N / X.length === N / X.length !== N
        m = re.match(r"(\w[\w.]*?)\.length\s*([><=!]+)\s*(\d+)", cond)
        if m:
            var_name = m.group(1)
            op = m.group(2)
            n = int(m.group(3))
            target = _VAR_TO_XML.get(var_name.split(".")[-1], var_name.split(".")[-1])
            if op in ("===", "=="):
                return [MutationDirective("set_count", target, n + 1, f"JS negate: {var_name}.length != {n}")]
            elif op in ("!==", "!="):
                return [MutationDirective("set_count", target, n, f"JS negate: {var_name}.length == {n}")]
            elif op == ">":
                return [MutationDirective("set_count", target, n, f"JS negate: {var_name}.length <= {n}")]
            elif op == ">=":
                return [MutationDirective("set_count", target, max(n - 1, 0), f"JS negate: {var_name}.length < {n}")]
            elif op == "<":
                return [MutationDirective("set_count", target, n, f"JS negate: {var_name}.length >= {n}")]

        # Pattern: X.includes("Y") / X.indexOf("Y") >= 0
        m = re.match(r"(\w[\w.]*?)\.includes\(['\"]([^'\"]*)['\"]", cond)
        if m:
            target = _VAR_TO_XML.get(m.group(1).split(".")[-1], m.group(1).split(".")[-1])
            return [MutationDirective("set_value", target, "NO_MATCH", f"JS negate: not includes '{m.group(2)}'")]

        # Pattern: X.startsWith("Y")
        m = re.match(r"(\w[\w.]*?)\.startsWith\(['\"]([^'\"]*)['\"]", cond)
        if m:
            target = _VAR_TO_XML.get(m.group(1).split(".")[-1], m.group(1).split(".")[-1])
            return [MutationDirective("set_value", target, f"NOPE_{m.group(2)}", f"JS negate: not startsWith '{m.group(2)}'")]

        # Pattern: X === "value" / X !== "value"
        m = re.match(r"(\w[\w.]*?)\s*(!==?|===?)\s*['\"]([^'\"]*)['\"]", cond)
        if m:
            var_name = m.group(1)
            op = m.group(2)
            val = m.group(3)
            target = _VAR_TO_XML.get(var_name.split(".")[-1], var_name.split(".")[-1])
            if "!" in op:
                return [MutationDirective("set_value", target, val, f"JS negate: {var_name} == '{val}'")]
            else:
                return [MutationDirective("set_value", target, f"NOT_{val}", f"JS negate: {var_name} != '{val}'")]

        # Pattern: !X (truthiness check)
        m = re.match(r"^!(\w[\w.]*)$", cond)
        if m:
            target = _VAR_TO_XML.get(m.group(1).split(".")[-1], m.group(1).split(".")[-1])
            return [MutationDirective("add", target, context=f"JS negate: !{m.group(1)} → ensure present")]

        # Pattern: just a variable name (truthiness)
        m = re.match(r"^(\w[\w.]*)$", cond)
        if m:
            target = _VAR_TO_XML.get(m.group(1).split(".")[-1], m.group(1).split(".")[-1])
            return [MutationDirective("remove", target, context=f"JS negate: {m.group(1)} → ensure absent")]

        # Pattern: X && Y (negate first resolvable operand)
        if "&&" in cond:
            parts = cond.split("&&", 1)
            for part in parts:
                d = self._negate_js_patterns(part.strip())
                if d:
                    return d

        # Pattern: X || Y (need to negate both)
        if "||" in cond:
            parts = cond.split("||")
            all_d: list[MutationDirective] = []
            for part in parts:
                d = self._negate_js_patterns(part.strip())
                all_d.extend(d)
            return all_d

        return directives


def negate_condition(condition_source: str) -> list[MutationDirective]:
    """Convenience function: parse + negate a condition string."""
    return ConditionNegator().negate(condition_source)
