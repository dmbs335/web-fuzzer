"""Frontier branch extraction: find uncovered branches adjacent to covered code.

A "frontier branch" is a branch point (if/elif/else/except/case) where:
  - The code immediately before or after is covered (was executed)
  - The branch itself was NOT executed

These are the most promising targets for mutation: the fuzzer almost reached
this code, and a slightly different input might cross the branch.
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

from .source_resolver import SourceResolver

logger = logging.getLogger(__name__)

# ── Security keyword scoring ──────────────────────────────────────

SECURITY_KEYWORDS: dict[float, list[str]] = {
    3.0: [
        "signature", "verify", "validate", "authenticate", "authorize",
        "decrypt", "hmac", "digest", "certificate", "trust", "sanitize",
        "escape", "bypass", "inject", "allow_list", "deny_list", "block",
    ],
    2.0: [
        "parse", "decode", "normalize", "canonicalize", "resolve",
        "redirect", "origin", "domain", "host", "scheme", "path",
        "header", "cookie", "token", "claim", "assertion", "scope",
        "allow", "deny", "reject", "forbidden", "permission",
        "grant", "revoke", "expire", "audience", "issuer", "subject",
    ],
    1.0: [
        "error", "exception", "fallback", "default", "empty", "null",
        "overflow", "truncat", "length", "limit", "max", "min",
        "encode", "format", "convert", "strip", "split", "join",
    ],
}


def _security_score(condition: str, context: str, function_name: str) -> tuple[float, list[str]]:
    """Score 0.0-1.0 based on security keyword density.

    Returns (score, matched_keywords).
    """
    text = f"{condition} {function_name} {context}".lower()
    matched = []
    raw_score = 0.0
    for weight, keywords in SECURITY_KEYWORDS.items():
        for kw in keywords:
            if kw in text:
                raw_score += weight
                matched.append(kw)
    score = min(1.0, raw_score / 10.0)
    return score, matched


@dataclass
class ReachingInput:
    """Full context for an input that reached near a frontier branch."""

    input_id: str
    input_data: str  # full input as string
    output: dict  # target's parsed JSON output for this input
    covered_lines_in_file: list[int]  # which lines this input covered in the frontier's file


@dataclass
class FrontierBranch:
    """A branch point at the edge of covered code."""

    file: str  # source file path (resolved)
    file_basename: str  # just the filename
    line: int  # branch line number
    condition: str  # condition expression text
    context: str  # ±N lines of source with line numbers
    context_start: int  # first line number in context
    context_end: int  # last line number in context
    function_source: str  # full function source code (or "" if unavailable)
    function_start: int  # function start line
    function_end: int  # function end line
    branch_type: str  # "if" | "elif" | "else" | "except" | "match_case"
    function_name: str  # enclosing function name
    class_name: str  # enclosing class name (or "")
    adjacent_covered: list[int]  # nearby lines that ARE covered
    security_score: float  # 0.0-1.0
    security_keywords: list[str]  # matched keywords
    reaching_inputs: list[str]  # input_ids that covered adjacent lines
    reaching_input_details: list[ReachingInput]  # full data for reaching inputs
    target_name: str  # which target this frontier belongs to


class FrontierExtractor:
    """Extract frontier branches from coverage data + source AST."""

    def __init__(
        self,
        source_resolver: SourceResolver,
        context_radius: int = 15,
    ) -> None:
        self.resolver = source_resolver
        self.context_radius = context_radius
        # Optional tree-sitter for JS/TS
        self._ts_extractor = None

    def extract(
        self,
        target_name: str,
        global_covered: dict[str, set[int]],
        per_input: list | None = None,
    ) -> list[FrontierBranch]:
        """Find frontier branches for one target.

        Args:
            target_name: Name of the target (for reporting).
            global_covered: {filename: {lineno, ...}} — all lines ever covered.
            per_input: Optional list of InputCoverage for reaching_inputs tracking.
        """
        frontiers: list[FrontierBranch] = []

        for filename, covered_lines in global_covered.items():
            # Resolve to full path
            filepath = self.resolver.resolve(filename)
            if filepath is None:
                logger.debug("Cannot resolve source: %s", filename)
                continue

            # Extract branch points from source
            ext = filepath.suffix.lower()
            if ext == ".py":
                branches = self._extract_python_branches(filepath)
            elif ext in (".js", ".mjs", ".cjs", ".ts"):
                branches = self._extract_js_branches(filepath)
            else:
                continue

            # Filter to frontier: branch NOT covered, but adjacent code IS
            for branch_info in branches:
                branch_line = branch_info["line"]
                # Check: is this branch NOT covered?
                if branch_line in covered_lines:
                    continue

                # Check: is adjacent code covered?
                adjacent = []
                for offset in range(-3, 4):
                    neighbor = branch_line + offset
                    if neighbor != branch_line and neighbor in covered_lines:
                        adjacent.append(neighbor)

                if not adjacent:
                    continue

                # Get source context
                context, ctx_start, ctx_end = self.resolver.get_context(
                    filepath, branch_line, self.context_radius
                )

                # Score security relevance
                score, keywords = _security_score(
                    branch_info["condition"],
                    context,
                    branch_info["function"],
                )

                # Find reaching inputs with full details
                reaching_ids = []
                reaching_details = []
                if per_input:
                    for ic in per_input:
                        ic_lines = ic.covered_lines.get(filename, set())
                        if ic_lines & set(adjacent):
                            reaching_ids.append(ic.input_id)
                            if len(reaching_details) < 5:  # cap details at 5
                                try:
                                    input_str = ic.input_data.decode("utf-8", errors="replace")
                                except Exception:
                                    input_str = repr(ic.input_data[:500])
                                reaching_details.append(ReachingInput(
                                    input_id=ic.input_id,
                                    input_data=input_str,
                                    output=ic.output,
                                    covered_lines_in_file=sorted(ic_lines),
                                ))

                # Get full function source
                func_result = self.resolver.get_function_source(filepath, branch_line)
                func_source = ""
                func_start = 0
                func_end = 0
                if func_result:
                    func_source, func_start, func_end = func_result

                frontiers.append(FrontierBranch(
                    file=str(filepath),
                    file_basename=filepath.name,
                    line=branch_line,
                    condition=branch_info["condition"],
                    context=context,
                    context_start=ctx_start,
                    context_end=ctx_end,
                    function_source=func_source,
                    function_start=func_start,
                    function_end=func_end,
                    branch_type=branch_info["type"],
                    function_name=branch_info["function"],
                    class_name=branch_info.get("class", ""),
                    adjacent_covered=sorted(adjacent),
                    security_score=score,
                    security_keywords=keywords,
                    reaching_inputs=reaching_ids[:20],
                    reaching_input_details=reaching_details,
                    target_name=target_name,
                ))

        # Sort by security score descending
        frontiers.sort(key=lambda f: (-f.security_score, f.file, f.line))
        return frontiers

    def _extract_python_branches(self, filepath: Path) -> list[dict]:
        """Extract all branch points from a Python source file using ast."""
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, str(filepath))
        except (SyntaxError, OSError):
            return []

        branches = []
        # Build function/class context map
        context = _PythonContextVisitor()
        context.visit(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                try:
                    cond = ast.unparse(node.test)
                except Exception:
                    cond = "<unparseable>"
                if self._is_trivial_python(cond):
                    continue
                func, cls = context.get_context(node.lineno)
                branches.append({
                    "line": node.lineno,
                    "condition": cond[:300],
                    "type": "if",
                    "function": func,
                    "class": cls,
                })
                # Also track elif/else branches
                for handler in node.orelse:
                    if isinstance(handler, ast.If):
                        try:
                            elif_cond = ast.unparse(handler.test)
                        except Exception:
                            elif_cond = "<unparseable>"
                        branches.append({
                            "line": handler.lineno,
                            "condition": elif_cond[:300],
                            "type": "elif",
                            "function": func,
                            "class": cls,
                        })
                    else:
                        branches.append({
                            "line": handler.lineno,
                            "condition": "(else)",
                            "type": "else",
                            "function": func,
                            "class": cls,
                        })

            elif isinstance(node, ast.ExceptHandler):
                exc_type = ""
                if node.type:
                    try:
                        exc_type = ast.unparse(node.type)
                    except Exception:
                        exc_type = "Exception"
                func, cls = context.get_context(node.lineno)
                branches.append({
                    "line": node.lineno,
                    "condition": f"except {exc_type}" if exc_type else "except",
                    "type": "except",
                    "function": func,
                    "class": cls,
                })

            elif isinstance(node, ast.match_case):
                try:
                    pattern = ast.unparse(node.pattern)
                except Exception:
                    pattern = "<pattern>"
                func, cls = context.get_context(node.lineno)
                branches.append({
                    "line": node.lineno,
                    "condition": f"case {pattern}",
                    "type": "match_case",
                    "function": func,
                    "class": cls,
                })

        return branches

    def _extract_js_branches(self, filepath: Path) -> list[dict]:
        """Extract branch points from JS/TS source using tree-sitter or regex fallback."""
        # Try tree-sitter first
        if self._ts_extractor is None:
            try:
                from ..fuzzer.concolic.ts_analyzer import TreeSitterBranchExtractor
                self._ts_extractor = TreeSitterBranchExtractor()
            except ImportError:
                self._ts_extractor = False  # mark as unavailable

        if self._ts_extractor:
            extracted = self._ts_extractor.analyze_file(str(filepath))
            return [
                {
                    "line": b.line_start,
                    "condition": b.condition_source,
                    "type": "if",
                    "function": "",
                    "class": "",
                }
                for b in extracted
            ]

        # Regex fallback for basic if-condition extraction
        return self._extract_js_branches_regex(filepath)

    def _extract_js_branches_regex(self, filepath: Path) -> list[dict]:
        """Simple regex-based JS branch extraction (fallback)."""
        import re
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        branches = []
        # Match: if (...) or else if (...)
        pattern = re.compile(r"^(\s*)(else\s+)?if\s*\((.+?)\)\s*\{?", re.MULTILINE)
        for match in pattern.finditer(source):
            lineno = source[:match.start()].count("\n") + 1
            cond = match.group(3).strip()
            btype = "elif" if match.group(2) else "if"
            branches.append({
                "line": lineno,
                "condition": cond[:300],
                "type": btype,
                "function": "",
                "class": "",
            })

        return branches

    @staticmethod
    def _is_trivial_python(condition: str) -> bool:
        """Filter out conditions that are not input-dependent."""
        trivial = [
            "TYPE_CHECKING", "__name__", "sys.version", "sys.platform",
            "os.environ", "os.name", "PY2", "PY3", "six.",
            "WINDOWS", "LINUX", "MACOS",
        ]
        return any(t in condition for t in trivial)


class _PythonContextVisitor(ast.NodeVisitor):
    """Build a line → (function, class) context map for Python AST."""

    def __init__(self) -> None:
        self._ranges: list[tuple[int, int, str, str]] = []
        self._current_class = ""

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        end = node.end_lineno or node.lineno
        self._ranges.append((node.lineno, end, node.name, self._current_class))
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def get_context(self, lineno: int) -> tuple[str, str]:
        """Return (function_name, class_name) for a line number."""
        best_func = "<module>"
        best_cls = ""
        best_size = float("inf")
        for start, end, func, cls in self._ranges:
            if start <= lineno <= end:
                size = end - start
                if size < best_size:
                    best_size = size
                    best_func = func
                    best_cls = cls
        return best_func, best_cls
