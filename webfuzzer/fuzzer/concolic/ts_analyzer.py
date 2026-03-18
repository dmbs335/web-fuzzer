"""Multi-language AST branch extractor using tree-sitter.

Supports Python, JavaScript, Java, Go, Ruby, PHP, Rust.
Extracts if-conditions from any source file and maps them to
input properties using the same pattern as ast_analyzer.py.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from .ast_analyzer import (
    ExtractedBranch,
    _CATEGORY_KEYWORDS,
    _INPUT_PROPERTY_PATTERNS,
)

logger = logging.getLogger(__name__)

# ── Language support ─────────────────────────────────────────────

_LANG_CACHE: dict[str, Any] = {}

# Maps file extension → (grammar_module, language_name, if_node_type, condition_field)
_LANG_CONFIG: dict[str, tuple[str, str, list[str], str | None]] = {
    ".py": ("tree_sitter_python", "python", ["if_statement"], "condition"),
    ".js": ("tree_sitter_javascript", "javascript", ["if_statement"], "condition"),
    ".ts": ("tree_sitter_javascript", "javascript", ["if_statement"], "condition"),
    ".java": ("tree_sitter_java", "java", ["if_statement"], "condition"),
    ".go": ("tree_sitter_go", "go", ["if_statement"], "condition"),
    ".rb": ("tree_sitter_ruby", "ruby", ["if", "unless"], "condition"),
    ".php": ("tree_sitter_php", "php", ["if_statement"], "condition"),
    ".rs": ("tree_sitter_rust", "rust", ["if_expression"], "condition"),
}


def _get_parser(ext: str):
    """Get or create a tree-sitter parser for the given file extension."""
    if ext in _LANG_CACHE:
        return _LANG_CACHE[ext]

    config = _LANG_CONFIG.get(ext)
    if config is None:
        return None

    module_name, lang_name, if_types, cond_field = config

    try:
        from tree_sitter import Language, Parser
        import importlib
        grammar_mod = importlib.import_module(module_name)
        language = Language(grammar_mod.language())
        parser = Parser(language)
        result = (parser, if_types, cond_field)
        _LANG_CACHE[ext] = result
        return result
    except (ImportError, Exception) as e:
        logger.debug("Cannot load tree-sitter for %s: %s", ext, e)
        _LANG_CACHE[ext] = None
        return None


def _iter_nodes(node, type_names: list[str]):
    """Recursively yield all nodes matching any of the given types."""
    if node.type in type_names:
        yield node
    for child in node.children:
        yield from _iter_nodes(child, type_names)


class TreeSitterBranchExtractor:
    """Multi-language branch condition extractor using tree-sitter.

    Same output format (ExtractedBranch) as ast_analyzer.AstBranchExtractor,
    so DynamicBranchDB can use either interchangeably.
    """

    def analyze_file(
        self,
        filepath: str,
        library_name: str = "",
    ) -> list[ExtractedBranch]:
        """Extract if-conditions from a single source file."""
        ext = os.path.splitext(filepath)[1].lower()
        parser_info = _get_parser(ext)
        if parser_info is None:
            return []

        parser, if_types, cond_field = parser_info

        try:
            with open(filepath, "rb") as f:
                source = f.read()
        except (OSError, IOError):
            return []

        tree = parser.parse(source)
        filename = os.path.basename(filepath)
        branches: list[ExtractedBranch] = []

        for if_node in _iter_nodes(tree.root_node, if_types):
            # Extract condition text
            cond_node = if_node.child_by_field_name(cond_field) if cond_field else None
            if cond_node is None:
                # Fallback: first child after keyword
                for child in if_node.children:
                    if child.type not in ("if", "else", "{", "}", "(", ")", ":", "unless"):
                        cond_node = child
                        break

            if cond_node is None:
                continue

            cond_text = cond_node.text.decode("utf-8", errors="replace").strip()
            # Strip outer parentheses if present
            if cond_text.startswith("(") and cond_text.endswith(")"):
                cond_text = cond_text[1:-1].strip()

            if not cond_text or len(cond_text) > 300:
                continue

            if self._is_trivial(cond_text):
                continue

            properties = self._detect_properties(cond_text)
            category = self._categorize(cond_text)

            if category in ("config", "type_check") and not properties:
                continue

            branches.append(
                ExtractedBranch(
                    library=library_name,
                    file=filename,
                    file_path=filepath,
                    line_start=cond_node.start_point[0] + 1,
                    line_end=cond_node.end_point[0] + 1,
                    condition_source=cond_text[:200],
                    condition_ast=if_node.type,
                    input_properties=frozenset(properties),
                    category=category,
                    negatable=bool(properties),
                )
            )

        return branches

    def analyze_directory(
        self,
        directory: str,
        library_name: str = "",
        extensions: list[str] | None = None,
        max_files: int = 50,
    ) -> list[ExtractedBranch]:
        """Analyze all supported source files in a directory."""
        if extensions is None:
            extensions = list(_LANG_CONFIG.keys())

        branches: list[ExtractedBranch] = []
        file_count = 0

        for root, _, filenames in os.walk(directory):
            # Skip test/vendor dirs
            basename = os.path.basename(root).lower()
            if basename in ("test", "tests", "__tests__", "node_modules",
                            "__pycache__", "vendor", "fixtures", "examples",
                            "dist", "build", ".git"):
                continue

            for fn in filenames:
                ext = os.path.splitext(fn)[1].lower()
                if ext not in extensions:
                    continue

                filepath = os.path.join(root, fn)
                try:
                    file_branches = self.analyze_file(filepath, library_name)
                    branches.extend(file_branches)
                except Exception as e:
                    logger.debug("Failed to analyze %s: %s", filepath, e)

                file_count += 1
                if file_count >= max_files:
                    return branches

        return branches

    def analyze_node_module(
        self,
        module_name: str,
        base_dir: str = "targets/node_modules",
    ) -> list[ExtractedBranch]:
        """Analyze a Node.js module from node_modules."""
        module_dir = os.path.join(base_dir, module_name)
        if not os.path.isdir(module_dir):
            # Try scoped packages: @scope/name → base_dir/@scope/name
            for root, dirs, _ in os.walk(base_dir):
                for d in dirs:
                    if d == module_name or d.endswith("/" + module_name):
                        module_dir = os.path.join(root, d)
                        break
                break

        if not os.path.isdir(module_dir):
            logger.warning("Node module not found: %s in %s", module_name, base_dir)
            return []

        return self.analyze_directory(
            module_dir,
            library_name=module_name,
            extensions=[".js", ".ts"],
        )

    # ── Property detection (reuses patterns from ast_analyzer) ────

    @staticmethod
    def _detect_properties(condition: str) -> set[str]:
        props: set[str] = set()
        condition_lower = condition.lower()
        for pattern, prop_names in _INPUT_PROPERTY_PATTERNS.items():
            if pattern.lower() in condition_lower:
                props.update(prop_names)
        return props

    @staticmethod
    def _categorize(condition: str) -> str:
        condition_lower = condition.lower()
        scores: dict[str, int] = {}
        for category, keywords in _CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw.lower() in condition_lower)
            if score > 0:
                scores[category] = score
        if not scores:
            return "unknown"
        return max(scores, key=scores.get)

    @staticmethod
    def _is_trivial(condition: str) -> bool:
        trivial = [
            "TYPE_CHECKING", "__name__", "process.env", "typeof window",
            "typeof module", "typeof exports", "typeof define",
            "require.main", "__dirname",
        ]
        return any(t in condition for t in trivial)


def supported_extensions() -> list[str]:
    """Return list of supported file extensions."""
    return list(_LANG_CONFIG.keys())
