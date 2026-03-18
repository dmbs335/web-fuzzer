"""Resolve library module paths to source file locations.

Maps the (basename, lineno) tuples from _covered_lines to full filesystem
paths so we can read source code for frontier branch analysis.
"""

from __future__ import annotations

import importlib.util
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class SourceResolver:
    """Resolve coverage filenames to actual source file paths."""

    def __init__(
        self,
        node_modules_dir: str = "targets/node_modules",
        extra_search_dirs: list[str] | None = None,
    ) -> None:
        self._node_modules_dir = node_modules_dir
        self._extra_dirs = extra_search_dirs or []
        # Cache: basename → full path
        self._cache: dict[str, Path | None] = {}
        # Pre-built index: basename → [full_paths] for node_modules
        self._node_index: dict[str, list[Path]] = {}
        self._python_site_packages: str | None = None
        self._indexed = False

    def resolve(self, filename: str) -> Path | None:
        """Resolve a filename (from _covered_lines) to a full Path.

        filename can be:
          - basename only: "utils.py", "purify.mjs"
          - relative path: "onelogin/saml2/utils.py"
          - full path: "C:/Python312/Lib/site-packages/onelogin/saml2/utils.py"
        """
        if filename in self._cache:
            return self._cache[filename]

        result = self._do_resolve(filename)
        self._cache[filename] = result
        return result

    def get_source_lines(self, filepath: Path) -> list[str]:
        """Read source file and return lines (1-indexed via list[0] = '')."""
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
            return [""] + text.splitlines()  # 1-indexed: lines[1] = first line
        except (OSError, UnicodeDecodeError):
            return [""]

    def get_context(
        self, filepath: Path, line: int, radius: int = 15
    ) -> tuple[str, int, int]:
        """Extract ±radius lines around target line.

        Returns (context_text, start_line, end_line) where context_text
        has line numbers prefixed.
        """
        lines = self.get_source_lines(filepath)
        if line < 1 or line >= len(lines):
            return ("", 0, 0)

        start = max(1, line - radius)
        end = min(len(lines) - 1, line + radius)
        width = len(str(end))

        parts = []
        for i in range(start, end + 1):
            prefix = "→" if i == line else " "
            parts.append(f"{prefix} {i:>{width}}: {lines[i]}")

        return ("\n".join(parts), start, end)

    def get_function_source(
        self, filepath: Path, line: int
    ) -> tuple[str, int, int] | None:
        """Extract the full function/method source containing the given line.

        Returns (function_source_with_line_numbers, start_line, end_line)
        or None if function boundaries cannot be determined.
        """
        ext = filepath.suffix.lower()
        if ext == ".py":
            return self._get_python_function_source(filepath, line)
        elif ext in (".js", ".mjs", ".cjs", ".ts"):
            return self._get_js_function_source(filepath, line)
        return None

    def _get_python_function_source(
        self, filepath: Path, line: int
    ) -> tuple[str, int, int] | None:
        """Extract Python function source using AST."""
        import ast
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, str(filepath))
        except (SyntaxError, OSError):
            return None

        lines = [""] + source.splitlines()

        # Find the innermost function containing this line
        best = None
        best_size = float("inf")
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = node.end_lineno or node.lineno
                if node.lineno <= line <= end:
                    size = end - node.lineno
                    if size < best_size:
                        best_size = size
                        best = (node.lineno, end)

        if best is None:
            return None

        start, end = best
        # Cap at 150 lines to avoid huge outputs
        if end - start > 150:
            # Show function header + area around target line
            header_end = min(start + 10, end)
            area_start = max(start, line - 20)
            area_end = min(end, line + 20)

            width = len(str(end))
            parts = []
            for i in range(start, header_end + 1):
                prefix = "→" if i == line else " "
                parts.append(f"{prefix} {i:>{width}}: {lines[i]}")
            if area_start > header_end + 1:
                parts.append(f"  {'':>{width}}  ... ({area_start - header_end - 1} lines omitted)")
            for i in range(max(area_start, header_end + 1), area_end + 1):
                prefix = "→" if i == line else " "
                parts.append(f"{prefix} {i:>{width}}: {lines[i]}")
            if area_end < end:
                parts.append(f"  {'':>{width}}  ... ({end - area_end} lines to end of function)")
            return ("\n".join(parts), start, end)

        width = len(str(end))
        parts = []
        for i in range(start, min(end + 1, len(lines))):
            prefix = "→" if i == line else " "
            parts.append(f"{prefix} {i:>{width}}: {lines[i]}")
        return ("\n".join(parts), start, end)

    def _get_js_function_source(
        self, filepath: Path, line: int
    ) -> tuple[str, int, int] | None:
        """Extract JS function source using brace matching (heuristic)."""
        try:
            source = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

        lines = [""] + source.splitlines()
        if line < 1 or line >= len(lines):
            return None

        # Walk backwards to find function start
        func_start = None
        import re
        func_pat = re.compile(
            r"(function\s+\w+|(?:async\s+)?(?:\w+\.)*\w+\s*[:=]\s*(?:async\s+)?function|"
            r"(?:async\s+)?\w+\s*\([^)]*\)\s*\{|(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?\()"
        )
        for i in range(line, 0, -1):
            if func_pat.search(lines[i]):
                func_start = i
                break

        if func_start is None:
            # Fallback: show ±30 lines
            return self.get_context(filepath, line, 30)

        # Walk forward counting braces to find end
        brace_count = 0
        func_end = func_start
        started = False
        for i in range(func_start, len(lines)):
            for ch in lines[i]:
                if ch == "{":
                    brace_count += 1
                    started = True
                elif ch == "}":
                    brace_count -= 1
            if started and brace_count <= 0:
                func_end = i
                break

        if func_end - func_start > 150:
            return self.get_context(filepath, line, 30)

        width = len(str(func_end))
        parts = []
        for i in range(func_start, min(func_end + 1, len(lines))):
            prefix = "→" if i == line else " "
            parts.append(f"{prefix} {i:>{width}}: {lines[i]}")
        return ("\n".join(parts), func_start, func_end)

    def _do_resolve(self, filename: str) -> Path | None:
        # 1. Already a full path?
        p = Path(filename)
        if p.is_absolute() and p.exists():
            return p

        # 2. Try Python module resolution for relative paths like "onelogin/saml2/utils.py"
        if "/" in filename and filename.endswith(".py"):
            result = self._resolve_python_relative(filename)
            if result:
                return result

        # 3. Try Python basename search
        basename = os.path.basename(filename)
        if basename.endswith(".py"):
            result = self._resolve_python_basename(basename, filename)
            if result:
                return result
            # 3b. Stdlib deep search (for basenames like "cookies.py")
            result = self._resolve_python_stdlib(basename)
            if result:
                return result

        # 4. Try Node.js module resolution
        if basename.endswith((".js", ".mjs", ".cjs", ".ts")):
            result = self._resolve_node(basename, filename)
            if result:
                return result

        # 5. Search extra dirs
        for d in self._extra_dirs:
            for root, _, files in os.walk(d):
                if basename in files:
                    return Path(root) / basename

        return None

    def _resolve_python_relative(self, relpath: str) -> Path | None:
        """Resolve 'onelogin/saml2/utils.py' → site-packages path."""
        site_dir = self._get_python_site_packages()
        if site_dir:
            candidate = Path(site_dir) / relpath
            if candidate.exists():
                return candidate
        # Also try stdlib
        import sys
        for p in sys.path:
            candidate = Path(p) / relpath
            if candidate.exists():
                return candidate
        return None

    def _resolve_python_basename(self, basename: str, original: str) -> Path | None:
        """Resolve Python file by module name inference."""
        # Try to infer module from path: "onelogin/saml2/utils.py" → "onelogin.saml2.utils"
        if "/" in original:
            module_dotted = original.replace("/", ".").removesuffix(".py")
        else:
            module_dotted = basename.removesuffix(".py")

        # Try importlib
        try:
            spec = importlib.util.find_spec(module_dotted)
            if spec and spec.origin:
                p = Path(spec.origin)
                if p.exists():
                    return p
        except (ModuleNotFoundError, ValueError):
            pass

        # Brute-force site-packages search
        site_dir = self._get_python_site_packages()
        if site_dir:
            for root, _, files in os.walk(site_dir):
                if basename in files:
                    candidate = Path(root) / basename
                    # Prefer matching the full relative path if given
                    if "/" in original:
                        if original in str(candidate).replace("\\", "/"):
                            return candidate
                    else:
                        return candidate
        return None

    def _resolve_python_stdlib(self, basename: str) -> Path | None:
        """Search stdlib for a Python file by basename (e.g., cookies.py → http/cookies.py)."""
        import sysconfig
        stdlib_dir = sysconfig.get_path("stdlib")
        if not stdlib_dir or not os.path.isdir(stdlib_dir):
            return None
        for root, _, files in os.walk(stdlib_dir):
            # Skip __pycache__ and test dirs
            if "__pycache__" in root or "test" in os.path.basename(root).lower():
                continue
            if basename in files:
                return Path(root) / basename
        return None

    def _resolve_node(self, basename: str, original: str) -> Path | None:
        """Resolve Node.js source file."""
        if not self._indexed:
            self._build_node_index()

        # If we have the full relative path (e.g., node_modules/dompurify/src/purify.mjs)
        if "node_modules/" in original:
            # Strip up to node_modules/
            rel = original.split("node_modules/", 1)[1]
            candidate = Path(self._node_modules_dir) / rel
            if candidate.exists():
                return candidate

        # Basename lookup
        candidates = self._node_index.get(basename, [])
        if len(candidates) == 1:
            return candidates[0]
        if len(candidates) > 1:
            # Prefer src/ over dist/
            for c in candidates:
                if "/src/" in str(c).replace("\\", "/"):
                    return c
            return candidates[0]

        return None

    def _build_node_index(self) -> None:
        """Walk node_modules once and index by basename."""
        self._indexed = True
        nm_path = Path(self._node_modules_dir)
        if not nm_path.is_dir():
            return

        for root, dirs, files in os.walk(nm_path):
            # Skip deeply nested node_modules (transitive deps)
            rel = os.path.relpath(root, nm_path)
            if rel.count("node_modules") > 0:
                dirs.clear()
                continue
            for fn in files:
                if fn.endswith((".js", ".mjs", ".cjs", ".ts")):
                    full = Path(root) / fn
                    self._node_index.setdefault(fn, []).append(full)

    def _get_python_site_packages(self) -> str | None:
        """Find the primary site-packages directory."""
        if self._python_site_packages is not None:
            return self._python_site_packages

        import site
        dirs = site.getsitepackages() if hasattr(site, "getsitepackages") else []
        for d in dirs:
            if os.path.isdir(d):
                self._python_site_packages = d
                return d

        # Fallback: search sys.path
        import sys
        for p in sys.path:
            if "site-packages" in p and os.path.isdir(p):
                self._python_site_packages = p
                return p

        return None
