"""Python-specific static analyzer using the ast module.

Analyzes Python JWT/SAML libraries to extract:
- Security checkpoint presence (regex + AST)
- Error-swallowing patterns (AST)
- Conditional bypass patterns (AST)
- Taint paths from attacker-controlled header fields (AST)
"""

from __future__ import annotations

import ast
import importlib
import os
import re
from pathlib import Path
from typing import Any

from webfuzzer.guidance.analyzers.base import BaseAnalyzer, LibraryTarget
from webfuzzer.guidance.profile import (
    BypassSeed,
    CheckpointStatus,
    ErrorSwallow,
    GuidanceProfile,
    TaintPath,
)
from webfuzzer.guidance.spec import ProtocolSpec


class PythonAnalyzer(BaseAnalyzer):
    """Analyze Python libraries using ast module."""

    def _resolve_library(self, target: LibraryTarget) -> bool:
        """Locate the library via importlib."""
        # Map library names to import names
        import_map = {
            "pyjwt": "jwt",
            "python-jose": "jose",
            "jwcrypto": "jwcrypto",
            "authlib": "authlib",
            "python3-saml": "onelogin.saml2",
            "signxml": "signxml",
        }
        import_name = import_map.get(target.name, target.name)

        try:
            mod = importlib.import_module(import_name)
        except ImportError:
            return False

        target.package_root = str(Path(mod.__file__).parent)

        # Resolve version
        try:
            target.version = getattr(mod, "__version__", "")
            if not target.version:
                from importlib.metadata import version as get_ver
                target.version = get_ver(
                    import_name.split(".")[0]
                    if "." in import_name
                    else import_name
                )
        except Exception:
            target.version = "?"

        # Validate source files exist
        valid = []
        for f in target.source_paths:
            full = os.path.join(target.package_root, f)
            if os.path.isfile(full):
                valid.append(f)
        target.source_paths = valid
        return bool(valid)

    def _read_sources(self, target: LibraryTarget) -> dict[str, str]:
        """Read all source files into memory."""
        sources: dict[str, str] = {}
        for rel_path in target.source_paths:
            full_path = os.path.join(target.package_root, rel_path)
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    sources[rel_path] = f.read()
            except OSError:
                continue
        return sources

    def _detect_checkpoints(
        self, target: LibraryTarget,
    ) -> dict[str, CheckpointStatus]:
        """Detect security checkpoints via regex pattern matching."""
        sources = self._read_sources(target)
        results: dict[str, CheckpointStatus] = {}

        for cp_name, checkpoint in self.spec.checkpoints.items():
            found = False
            location = ""

            for filename, source in sources.items():
                for pattern in checkpoint.detection_patterns:
                    m = re.search(pattern, source, re.IGNORECASE)
                    if m:
                        line_no = source[:m.start()].count("\n") + 1
                        found = True
                        location = f"{filename}:{line_no}"
                        break
                if found:
                    break

            results[cp_name] = CheckpointStatus(
                name=cp_name,
                present=found,
                location=location,
            )

        return results

    def _detect_error_swallowing(
        self, target: LibraryTarget,
    ) -> list[ErrorSwallow]:
        """Find except blocks that swallow errors."""
        sources = self._read_sources(target)
        findings: list[ErrorSwallow] = []

        for filename, source in sources.items():
            try:
                tree = ast.parse(source, filename=filename)
            except SyntaxError:
                continue

            detector = _ErrorSwallowVisitor(filename)
            detector.visit(tree)
            findings.extend(detector.findings)

        return findings

    def _detect_conditional_bypasses(
        self, target: LibraryTarget,
    ) -> list[dict[str, Any]]:
        """Find security checks guarded by options/flags."""
        sources = self._read_sources(target)
        bypasses: list[dict[str, Any]] = []

        for filename, source in sources.items():
            try:
                tree = ast.parse(source, filename=filename)
            except SyntaxError:
                continue

            detector = _ConditionalBypassVisitor(
                filename, source, self.spec,
            )
            detector.visit(tree)
            bypasses.extend(detector.bypasses)

        return bypasses

    def _extract_taint_paths(
        self, target: LibraryTarget,
    ) -> list[TaintPath]:
        """Extract taint paths: attacker field → branch decision.

        Scans for patterns like:
            header["alg"]  → used in if/match
            header.get("crit") → used in if/match
            options.get("verify_*") → guards a checkpoint
        """
        sources = self._read_sources(target)
        paths: list[TaintPath] = []

        # Map spec's taint sources to regex patterns
        field_patterns: dict[str, list[str]] = {}
        for af in self.spec.attacker_controlled:
            field_name = af.field  # e.g. "header.alg"
            short_name = field_name.split(".")[-1]  # "alg"
            field_patterns[field_name] = [
                rf"""['\"]({short_name})['\"]""",
                rf"""\b{short_name}\b""",
            ]

        for filename, source in sources.items():
            try:
                tree = ast.parse(source, filename=filename)
            except SyntaxError:
                continue

            visitor = _TaintPathVisitor(
                filename, source, field_patterns, self.spec,
            )
            visitor.visit(tree)
            paths.extend(visitor.paths)

        return paths


# ── AST Visitors ──


class _ErrorSwallowVisitor(ast.NodeVisitor):
    """Find except blocks that swallow errors in verification paths."""

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[ErrorSwallow] = []
        self._func_stack: list[str] = []
        self._class_stack: list[str] = []

    def _qname(self, name: str) -> str:
        prefix = ".".join(self._class_stack)
        return f"{prefix}.{name}" if prefix else name

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_stack.append(self._qname(node.name))
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        body = node.body
        func_ctx = self._func_stack[-1] if self._func_stack else "<module>"

        # Get exception type name
        exc_type = "bare"
        if node.type is None:
            exc_type = "bare"
        elif isinstance(node.type, ast.Name):
            exc_type = node.type.id
        elif isinstance(node.type, ast.Attribute):
            exc_type = node.type.attr

        # Skip import errors (not security-relevant)
        if exc_type == "ImportError":
            self.generic_visit(node)
            return

        is_swallow = False
        pattern = ""

        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, ast.Pass):
                is_swallow = True
                pattern = f"except {exc_type}: pass"
            elif isinstance(stmt, ast.Return):
                if stmt.value is None:
                    is_swallow = True
                    pattern = f"except {exc_type}: return None"
                elif isinstance(stmt.value, ast.Constant) and stmt.value.value is False:
                    is_swallow = True
                    pattern = f"except {exc_type}: return False"

        if is_swallow:
            self.findings.append(ErrorSwallow(
                location=f"{self.filename}:{node.lineno}",
                pattern=pattern,
                in_function=func_ctx,
                swallows=f"exception in {func_ctx}",
            ))

        self.generic_visit(node)


class _ConditionalBypassVisitor(ast.NodeVisitor):
    """Find security checks guarded by option flags."""

    OPTION_PATTERNS = [
        r'options\s*[\.\[\(].*?verify',
        r'defaults\s*[\.\[\(].*?verify',
        r'verify_signature\b',
        r'\bverify\b\s*[:\)]',
    ]

    # Map option keywords to checkpoint names
    OPTION_TO_CHECKPOINT = {
        "verify_signature": "sig_verify",
        "verify_exp": "exp_check",
        "verify_nbf": "nbf_check",
        "verify_aud": "aud_check",
        "verify_iss": "iss_check",
        "verify_iat": "exp_check",  # close enough
        "verify": "sig_verify",
    }

    def __init__(self, filename: str, source: str, spec: ProtocolSpec):
        self.filename = filename
        self.source_lines = source.splitlines()
        self.spec = spec
        self.bypasses: list[dict[str, Any]] = []
        self._func_stack: list[str] = []
        self._class_stack: list[str] = []

    def _qname(self, name: str) -> str:
        prefix = ".".join(self._class_stack)
        return f"{prefix}.{name}" if prefix else name

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_stack.append(self._qname(node.name))
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        if node.lineno > len(self.source_lines):
            self.generic_visit(node)
            return

        cond_text = self.source_lines[node.lineno - 1].strip()

        for pat in self.OPTION_PATTERNS:
            if re.search(pat, cond_text, re.IGNORECASE):
                # Determine which checkpoint this guards
                checkpoint = None
                for opt_key, cp_name in self.OPTION_TO_CHECKPOINT.items():
                    if opt_key in cond_text.lower():
                        checkpoint = cp_name
                        break

                func_ctx = self._func_stack[-1] if self._func_stack else "<module>"
                self.bypasses.append({
                    "checkpoint": checkpoint,
                    "condition": cond_text,
                    "location": f"{self.filename}:{node.lineno}",
                    "function": func_ctx,
                })
                break

        self.generic_visit(node)


class _TaintPathVisitor(ast.NodeVisitor):
    """Find where attacker-controlled fields influence branch decisions."""

    def __init__(
        self,
        filename: str,
        source: str,
        field_patterns: dict[str, list[str]],
        spec: ProtocolSpec,
    ):
        self.filename = filename
        self.source_lines = source.splitlines()
        self.field_patterns = field_patterns
        self.spec = spec
        self.paths: list[TaintPath] = []
        self._func_stack: list[str] = []
        self._class_stack: list[str] = []
        self._seen: set[tuple[str, str]] = set()

    def _qname(self, name: str) -> str:
        prefix = ".".join(self._class_stack)
        return f"{prefix}.{name}" if prefix else name

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._class_stack.append(node.name)
        self.generic_visit(node)
        self._class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._func_stack.append(self._qname(node.name))
        self.generic_visit(node)
        self._func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_If(self, node: ast.If) -> None:
        """Check if an if-condition references attacker-controlled fields."""
        if node.lineno > len(self.source_lines):
            self.generic_visit(node)
            return

        cond_text = self.source_lines[node.lineno - 1].strip()

        for field_name, patterns in self.field_patterns.items():
            for pat in patterns:
                if re.search(pat, cond_text, re.IGNORECASE):
                    key = (field_name, f"{self.filename}:{node.lineno}")
                    if key in self._seen:
                        break
                    self._seen.add(key)

                    # Find which checkpoints are reachable inside this branch
                    reachable = self._find_checkpoints_in_body(node.body)
                    func_ctx = (
                        self._func_stack[-1] if self._func_stack else "<module>"
                    )

                    self.paths.append(TaintPath(
                        source=field_name,
                        influences_branch=f"{self.filename}:{node.lineno}",
                        determines=f"branch in {func_ctx}: {cond_text[:80]}",
                        reachable_checkpoints=reachable,
                    ))
                    break

        self.generic_visit(node)

    def _find_checkpoints_in_body(self, body: list[ast.stmt]) -> list[str]:
        """Scan a code block for checkpoint-related function calls."""
        found: list[str] = []
        for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
            if isinstance(stmt, ast.Call):
                callee = _callee_name(stmt)
                if callee:
                    callee_lower = callee.lower()
                    for cp_name, checkpoint in self.spec.checkpoints.items():
                        for pattern in checkpoint.detection_patterns:
                            # Use simple substring match (patterns are short)
                            clean = pattern.replace("\\s*", "").replace("\\(", "(")
                            if clean.strip("'\"").lower() in callee_lower:
                                if cp_name not in found:
                                    found.append(cp_name)
                                break
        return found


def _callee_name(node: ast.Call) -> str | None:
    """Extract callee name from a Call node."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parts = []
        obj = func.value
        while isinstance(obj, ast.Attribute):
            parts.append(obj.attr)
            obj = obj.value
        if isinstance(obj, ast.Name):
            parts.append(obj.id)
        parts.reverse()
        parts.append(func.attr)
        return ".".join(parts)
    return None


# ── Library definitions for convenience ──

JWT_PYTHON_LIBRARIES = [
    LibraryTarget(
        name="pyjwt",
        language="python",
        source_paths=["api_jwt.py", "api_jws.py", "algorithms.py", "utils.py"],
        entry_points=["PyJWT.decode", "PyJWS.decode_complete"],
    ),
    LibraryTarget(
        name="python-jose",
        language="python",
        source_paths=["jwt.py", "jws.py", "jwk.py", "utils.py"],
        entry_points=["decode", "verify"],
    ),
    LibraryTarget(
        name="jwcrypto",
        language="python",
        source_paths=["jwt.py", "jws.py", "jwa.py", "common.py"],
        entry_points=["JWT.deserialize", "JWS.verify"],
    ),
    LibraryTarget(
        name="authlib",
        language="python",
        source_paths=[
            os.path.join("jose", "rfc7519", "jwt.py"),
            os.path.join("jose", "rfc7515", "jws.py"),
            os.path.join("jose", "rfc7519", "claims.py"),
            os.path.join("jose", "errors.py"),
        ],
        entry_points=["JsonWebToken.decode", "JsonWebSignature.deserialize_compact"],
    ),
]

SAML_PYTHON_LIBRARIES = [
    LibraryTarget(
        name="python3-saml",
        language="python",
        source_paths=[
            "response.py",
            "utils.py",
            "xml_utils.py",
        ],
        entry_points=["OneLogin_Saml2_Response.is_valid"],
    ),
    LibraryTarget(
        name="signxml",
        language="python",
        source_paths=[
            "verifier.py",
            "processor.py",
            "util.py",
        ],
        entry_points=["XMLVerifier.verify"],
    ),
]
