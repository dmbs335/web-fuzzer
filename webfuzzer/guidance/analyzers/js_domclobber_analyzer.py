"""DOM Clobbering gadget analyzer — orchestrates AST parsing, PDG construction,
taint propagation, and gadget scoring across JavaScript codebases.

Usage:
    analyzer = DomClobberAnalyzer()
    results = analyzer.analyze_directory("path/to/js/files")
    for gadget in results.gadgets:
        print(f"[{gadget.score:.0f}] {gadget.source.property_name} → {gadget.sink.sink_type}")
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from .js_ast_parser import ClobberSink, ClobberSource, FileIndex, JSParser, Guard
from .js_framework_patterns import ALL_FRAMEWORK_PROPERTIES, match_property
from .js_gadget_scorer import deduplicate_gadgets, score_all_gadgets
from .js_pdg_builder import PDGBuilder, PropertyDependencyGraph, NodeKind
from .js_taint_tracker import Gadget, TaintTracker

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    gadgets: list[Gadget]
    total_sources: int = 0
    total_sinks: int = 0
    total_files: int = 0
    files_with_sources: int = 0
    files_with_sinks: int = 0
    file_index: FileIndex | None = None

    def summary(self) -> str:
        critical = sum(1 for g in self.gadgets if g.score >= 70)
        high = sum(1 for g in self.gadgets if 50 <= g.score < 70)
        medium = sum(1 for g in self.gadgets if 30 <= g.score < 50)
        low = sum(1 for g in self.gadgets if g.score < 30)
        return (f"Files: {self.total_files} ({self.files_with_sources} with sources, "
                f"{self.files_with_sinks} with sinks)\n"
                f"Sources: {self.total_sources}, Sinks: {self.total_sinks}\n"
                f"Gadgets: {len(self.gadgets)} "
                f"(Critical: {critical}, High: {high}, Medium: {medium}, Low: {low})")


class DomClobberAnalyzer:
    """Main analyzer — orchestrates the full analysis pipeline."""

    def __init__(self, min_score: float = 0.0):
        self._parser = JSParser()
        self._file_index = FileIndex()
        self._min_score = min_score

    def analyze_file(self, path: str, content: str | None = None) -> list[Gadget]:
        """Analyze a single JavaScript file for DOM Clobbering gadgets."""
        if content is None:
            content = Path(path).read_text(encoding="utf-8", errors="replace")

        file_id = self._file_index.add_file(path, content)

        # Phase 1: Parse + scope analysis
        parse_result = self._parser.parse_file(content, file_id)
        sources = self._parser.find_sources(parse_result.tree, parse_result.scope_tree, file_id)
        sinks = self._parser.find_sinks(parse_result.tree, parse_result.scope_tree, file_id)
        guards = self._parser.find_guards(parse_result.tree, file_id)

        if not sources or not sinks:
            return []

        # Apply guards to sources
        self._apply_guards(sources, guards)

        logger.debug("File %s: %d sources, %d sinks", path, len(sources), len(sinks))

        # Phase 2: Build PDG
        builder = PDGBuilder()
        pdg = builder.build(parse_result)

        # Phase 3: Map sources/sinks to PDG nodes
        source_node_map = self._map_sources_to_pdg(sources, pdg)
        sink_node_map = self._map_sinks_to_pdg(sinks, pdg)

        # Phase 4: Taint propagation
        tracker = TaintTracker(pdg, sources, sinks, source_node_map, sink_node_map)
        gadgets = tracker.propagate()

        # Phase 5: Score + dedup
        gadgets = score_all_gadgets(gadgets)
        gadgets = deduplicate_gadgets(gadgets)

        if self._min_score > 0:
            gadgets = [g for g in gadgets if g.score >= self._min_score]

        return gadgets

    def analyze_directory(self, directory: str, extensions: tuple[str, ...] = ('.js', '.mjs', '.cjs')) -> AnalysisResult:
        """Analyze all JavaScript files in a directory."""
        result = AnalysisResult(gadgets=[], file_index=self._file_index)
        dir_path = Path(directory)

        if not dir_path.exists():
            logger.error("Directory not found: %s", directory)
            return result

        js_files = []
        for ext in extensions:
            js_files.extend(dir_path.rglob(f"*{ext}"))

        # Skip node_modules, .min.js, vendor
        js_files = [f for f in js_files if not self._should_skip(f)]
        js_files.sort()

        result.total_files = len(js_files)
        logger.info("Analyzing %d JS files in %s", len(js_files), directory)

        all_sources = 0
        all_sinks = 0

        for path in js_files:
            try:
                content = path.read_text(encoding="utf-8", errors="replace")

                # Quick pre-filter: skip files without any potential sources
                if not self._has_potential_sources(content):
                    continue

                gadgets = self.analyze_file(str(path), content)

                if gadgets:
                    result.gadgets.extend(gadgets)
                    result.files_with_sinks += 1

                # Count for stats
                file_id = self._file_index._path_to_id.get(str(path), -1)
                if file_id >= 0:
                    parse_result = self._parser.parse_file(content, file_id)
                    src_count = len(self._parser.find_sources(parse_result.tree, parse_result.scope_tree, file_id))
                    sink_count = len(self._parser.find_sinks(parse_result.tree, parse_result.scope_tree, file_id))
                    all_sources += src_count
                    all_sinks += sink_count
                    if src_count > 0:
                        result.files_with_sources += 1

            except Exception as e:
                logger.warning("Error analyzing %s: %s", path, e)
                continue

        result.total_sources = all_sources
        result.total_sinks = all_sinks

        # Global dedup + re-score
        result.gadgets = score_all_gadgets(result.gadgets)
        result.gadgets = deduplicate_gadgets(result.gadgets)

        if self._min_score > 0:
            result.gadgets = [g for g in result.gadgets if g.score >= self._min_score]

        logger.info("Analysis complete: %s", result.summary())
        return result

    def _should_skip(self, path: Path) -> bool:
        parts = path.parts
        skip_dirs = {'node_modules', '.git', 'vendor', 'bower_components', 'dist', 'build', '__pycache__'}
        if any(p in skip_dirs for p in parts):
            return True
        name = path.name
        if name.endswith('.min.js') or name.endswith('.bundle.js'):
            return True
        # Skip very large files (likely bundles)
        try:
            if path.stat().st_size > 2_000_000:  # 2MB
                logger.debug("Skipping large file: %s", path)
                return True
        except OSError:
            return True
        return False

    def _has_potential_sources(self, content: str) -> bool:
        """Quick regex pre-filter: does file contain any potential clobber sources?"""
        import re
        if re.search(r'window\.\w+|document\.\w+|globalThis\.\w+|self\.\w+', content):
            return True
        for prop in ALL_FRAMEWORK_PROPERTIES:
            if prop in content:
                return True
        return False

    def _apply_guards(self, sources: list[ClobberSource], guards: list[Guard]):
        """Mark sources as guarded if a matching guard exists."""
        guard_names = {g.checked_name for g in guards}
        for src in sources:
            if src.property_name in guard_names:
                src.guarded = True

    def _map_sources_to_pdg(self, sources, pdg) -> dict:
        """Map source property names to their PDG node IDs."""
        result = {}
        for src in sources:
            for node in pdg.nodes.values():
                if node.kind in (NodeKind.GLOBAL_ACCESS, NodeKind.PROPERTY_ACCESS):
                    if src.property_name in node.id.name:
                        result[src.property_name] = node.id
                        break
        return result

    def _map_sinks_to_pdg(self, sinks, pdg) -> dict:
        """Map sink types to their PDG node IDs."""
        result = {}
        for sink in sinks:
            for node in pdg.nodes.values():
                if sink.sink_type in node.id.name:
                    result[sink.sink_type] = node.id
                    break
        return result
