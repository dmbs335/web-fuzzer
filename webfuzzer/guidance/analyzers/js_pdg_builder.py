"""Property Dependency Graph (PDG) builder for JavaScript.

Constructs a data-flow graph from tree-sitter AST nodes,
capturing variable assignments, property accesses, function calls,
and return values.  Used for interprocedural taint tracking.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Iterator

from .js_ast_parser import ClobberSource, ClobberSink, Location, ParseResult, ScopeTree

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enum types
# ---------------------------------------------------------------------------

class NodeKind(Enum):
    VARIABLE = auto()
    PARAMETER = auto()
    PROPERTY_ACCESS = auto()
    RETURN_VALUE = auto()
    CALL_RESULT = auto()
    LITERAL = auto()
    GLOBAL_ACCESS = auto()
    THIS_ACCESS = auto()
    COMPUTED_ACCESS = auto()
    DESTRUCTURED = auto()
    SPREAD = auto()
    TEMPLATE_EXPR = auto()
    BINARY_EXPR = auto()


class EdgeKind(Enum):
    ASSIGN = auto()
    PROP_READ = auto()
    PROP_WRITE = auto()
    ARG_PASS = auto()
    RETURN_FLOW = auto()
    CONCAT = auto()
    TEMPLATE = auto()
    TERNARY = auto()
    OR_DEFAULT = auto()
    NULLISH = auto()
    OPTIONAL_CHAIN = auto()
    SPREAD = auto()
    DESTRUCTURE = auto()
    CALLBACK_ITEM = auto()
    COMPUTED_READ = auto()


# ---------------------------------------------------------------------------
# Node / Edge data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class PDGNodeId:
    scope_id: int
    name: str
    file_id: int
    line: int
    col: int

    def __repr__(self) -> str:
        return f"<{self.name}@{self.file_id}:{self.line}:{self.col}>"


@dataclass(slots=True)
class PDGNode:
    id: PDGNodeId
    kind: NodeKind
    access_chain: tuple[str, ...] = ()
    is_undeclared: bool = False


@dataclass(frozen=True, slots=True)
class PDGEdge:
    src: PDGNodeId
    dst: PDGNodeId
    kind: EdgeKind
    param_index: int = -1
    line: int = 0
    col: int = 0


@dataclass
class CallSite:
    caller_scope_id: int
    callee_name: str
    args: list[PDGNodeId]
    result_node: PDGNodeId | None
    location: Location


# ---------------------------------------------------------------------------
# PropertyDependencyGraph
# ---------------------------------------------------------------------------

class PropertyDependencyGraph:
    """Adjacency-list based PDG for memory efficiency."""

    def __init__(self) -> None:
        self.nodes: dict[PDGNodeId, PDGNode] = {}
        self.forward_edges: dict[PDGNodeId, list[PDGEdge]] = defaultdict(list)
        self.backward_edges: dict[PDGNodeId, list[PDGEdge]] = defaultdict(list)
        self.call_sites: list[CallSite] = []
        self.functions: dict[str, list[PDGNodeId]] = defaultdict(list)  # fn_name -> param nodes
        self._string_intern: dict[str, str] = {}

    def _intern(self, s: str) -> str:
        if s not in self._string_intern:
            self._string_intern[s] = s
        return self._string_intern[s]

    def add_node(self, node: PDGNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: PDGEdge) -> None:
        self.forward_edges[edge.src].append(edge)
        self.backward_edges[edge.dst].append(edge)

    def successors(self, nid: PDGNodeId) -> list[PDGEdge]:
        return self.forward_edges.get(nid, [])

    def predecessors(self, nid: PDGNodeId) -> list[PDGEdge]:
        return self.backward_edges.get(nid, [])

    def nodes_by_kind(self, kind: NodeKind) -> Iterator[PDGNode]:
        for node in self.nodes.values():
            if node.kind == kind:
                yield node

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(edges) for edges in self.forward_edges.values())


# ---------------------------------------------------------------------------
# PDGBuilder
# ---------------------------------------------------------------------------

class PDGBuilder:
    """Build PropertyDependencyGraph from tree-sitter AST."""

    def __init__(self) -> None:
        self._pdg = PropertyDependencyGraph()
        self._current_scope_id = 0
        self._current_file_id = 0

    def build(self, parse_result: ParseResult) -> PropertyDependencyGraph:
        """Build PDG from a parsed JavaScript file."""
        self._pdg = PropertyDependencyGraph()
        self._current_file_id = parse_result.file_id

        if parse_result.tree is None:
            logger.debug("No tree-sitter AST available, returning empty PDG")
            return self._pdg

        self._walk(parse_result.tree.root_node, parse_result.scope_tree)
        self._resolve_calls(parse_result.scope_tree)

        logger.debug(
            "PDG built: %d nodes, %d edges, %d call sites",
            self._pdg.node_count,
            self._pdg.edge_count,
            len(self._pdg.call_sites),
        )
        return self._pdg

    # -- AST walk -----------------------------------------------------------

    def _walk(self, node: object, scope_tree: ScopeTree) -> None:
        """Walk AST and build PDG nodes + edges."""
        ntype = node.type

        if ntype == "variable_declarator":
            self._handle_variable_declarator(node, scope_tree)
        elif ntype == "assignment_expression":
            self._handle_assignment(node, scope_tree)
        elif ntype == "call_expression":
            self._handle_call(node, scope_tree)
        elif ntype == "return_statement":
            self._handle_return(node, scope_tree)
        elif ntype == "binary_expression":
            self._handle_binary(node, scope_tree)
        elif ntype == "template_string":
            self._handle_template(node, scope_tree)
        elif ntype == "spread_element":
            self._handle_spread(node, scope_tree)
        elif ntype in ("function_declaration", "function_expression", "arrow_function", "method_definition"):
            self._handle_function_def(node, scope_tree)
        elif ntype in ("for_in_statement", "for_of_statement"):
            self._handle_for_in_of(node, scope_tree)
        elif ntype == "augmented_assignment_expression":
            self._handle_augmented_assignment(node, scope_tree)
        elif ntype == "ternary_expression":
            self._handle_ternary(node, scope_tree)

        # Recurse into children
        for child in node.children:
            self._walk(child, scope_tree)

    # -- handlers -----------------------------------------------------------

    def _handle_variable_declarator(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: let x = expr, const {a,b} = expr, var [x,y] = expr"""
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if not name_node or not value_node:
            return

        # Simple identifier
        if name_node.type == "identifier":
            var_id = self._make_node_id(name_node, scope_tree)
            self._pdg.add_node(PDGNode(id=var_id, kind=NodeKind.VARIABLE))

            val_id = self._expr_node_id(value_node, scope_tree)
            if val_id:
                self._pdg.add_edge(PDGEdge(
                    src=val_id, dst=var_id, kind=EdgeKind.ASSIGN,
                    line=node.start_point[0] + 1, col=node.start_point[1],
                ))

        # Destructuring pattern
        elif name_node.type in ("object_pattern", "array_pattern"):
            self._handle_destructure(name_node, value_node, scope_tree)

    def _handle_destructure(
        self, pattern_node: object, value_node: object, scope_tree: ScopeTree
    ) -> None:
        """Handle destructuring assignment/declaration."""
        val_id = self._expr_node_id(value_node, scope_tree)
        if val_id is None:
            return

        for child in pattern_node.named_children:
            target_name: str | None = None
            target_node: object | None = None

            if child.type == "identifier":
                target_name = child.text.decode()
                target_node = child
            elif child.type == "shorthand_property_identifier_pattern":
                target_name = child.text.decode()
                target_node = child
            elif child.type == "pair_pattern":
                v = child.child_by_field_name("value")
                if v and v.type == "identifier":
                    target_name = v.text.decode()
                    target_node = v
                elif v and v.type == "assignment_pattern":
                    left = v.child_by_field_name("left")
                    if left and left.type == "identifier":
                        target_name = left.text.decode()
                        target_node = left
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                if left and left.type == "identifier":
                    target_name = left.text.decode()
                    target_node = left
            elif child.type == "rest_pattern":
                arg = child.named_children[0] if child.named_children else None
                if arg and arg.type == "identifier":
                    target_name = arg.text.decode()
                    target_node = arg

            if target_name and target_node:
                nid = self._make_node_id(target_node, scope_tree)
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.DESTRUCTURED))
                self._pdg.add_edge(PDGEdge(
                    src=val_id, dst=nid, kind=EdgeKind.DESTRUCTURE,
                    line=target_node.start_point[0] + 1, col=target_node.start_point[1],
                ))

    def _handle_assignment(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: x = expr, obj.prop = expr"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            return

        left_id = self._expr_node_id(left, scope_tree)
        right_id = self._expr_node_id(right, scope_tree)

        if left_id and right_id:
            kind = EdgeKind.PROP_WRITE if left.type == "member_expression" else EdgeKind.ASSIGN
            self._pdg.add_edge(PDGEdge(
                src=right_id, dst=left_id, kind=kind,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

    def _handle_augmented_assignment(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: x += expr, x ||= expr, etc."""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            return

        left_id = self._expr_node_id(left, scope_tree)
        right_id = self._expr_node_id(right, scope_tree)

        if left_id and right_id:
            op_node = node.child_by_field_name("operator")
            op_text = op_node.text.decode() if op_node and hasattr(op_node, "text") else "+="

            if op_text in ("+=",):
                edge_kind = EdgeKind.CONCAT
            elif op_text in ("||=",):
                edge_kind = EdgeKind.OR_DEFAULT
            elif op_text in ("??=",):
                edge_kind = EdgeKind.NULLISH
            else:
                edge_kind = EdgeKind.ASSIGN

            self._pdg.add_edge(PDGEdge(
                src=right_id, dst=left_id, kind=edge_kind,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

    def _handle_call(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: f(x, y), obj.method(args)"""
        fn_node = node.child_by_field_name("function")
        args_node = node.child_by_field_name("arguments")
        if not fn_node:
            return

        # Determine function name
        fn_name: str | None = None
        if fn_node.type == "identifier":
            fn_name = fn_node.text.decode()
        elif fn_node.type == "member_expression":
            prop = fn_node.child_by_field_name("property")
            fn_name = prop.text.decode() if prop else None

        # Create CALL_RESULT node
        result_id = self._make_node_id(node, scope_tree, suffix="_result")
        self._pdg.add_node(PDGNode(id=result_id, kind=NodeKind.CALL_RESULT))

        # Collect argument node ids
        arg_ids: list[PDGNodeId] = []
        if args_node:
            for arg in args_node.named_children:
                arg_id = self._expr_node_id(arg, scope_tree)
                if arg_id:
                    arg_ids.append(arg_id)

        # Record call site for later interprocedural resolution
        self._pdg.call_sites.append(CallSite(
            caller_scope_id=self._scope_at_byte(scope_tree, node.start_byte),
            callee_name=fn_name or "_anonymous",
            args=arg_ids,
            result_node=result_id,
            location=Location(
                self._current_file_id,
                node.start_point[0] + 1,
                node.start_point[1],
            ),
        ))

    def _handle_return(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: return expr"""
        # The returned expression is the first named child (if present)
        expr = node.named_children[0] if node.named_children else None
        if expr is None:
            return

        ret_id = self._make_node_id(node, scope_tree, suffix="_ret")
        self._pdg.add_node(PDGNode(id=ret_id, kind=NodeKind.RETURN_VALUE))

        expr_id = self._expr_node_id(expr, scope_tree)
        if expr_id:
            self._pdg.add_edge(PDGEdge(
                src=expr_id, dst=ret_id, kind=EdgeKind.RETURN_FLOW,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

        # Link return node to enclosing function for interprocedural flow
        scope_id = self._scope_at_byte(scope_tree, node.start_byte)
        scope = scope_tree.scopes[scope_id]
        # Walk up to find the function scope
        while scope.kind not in ("function", "arrow", "global", "module") and scope.parent_id is not None:
            scope = scope_tree.scopes[scope.parent_id]
        if scope.function_name:
            fn_name = self._pdg._intern(scope.function_name)
            # We store return nodes so _resolve_calls can wire RETURN_FLOW -> CALL_RESULT
            key = f"__return__{fn_name}"
            self._pdg.functions[key].append(ret_id)

    def _handle_binary(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: x + y, x || y, x ?? y"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            return

        # Determine operator
        op_text = ""
        for child in node.children:
            if child.is_named is False and child.type not in (left.type, right.type):
                op_text = child.type
                break

        left_id = self._expr_node_id(left, scope_tree)
        right_id = self._expr_node_id(right, scope_tree)

        result_id = self._make_node_id(node, scope_tree, suffix="_binop")
        self._pdg.add_node(PDGNode(id=result_id, kind=NodeKind.BINARY_EXPR))

        if left_id:
            if op_text == "||":
                self._pdg.add_edge(PDGEdge(
                    src=left_id, dst=result_id, kind=EdgeKind.OR_DEFAULT,
                    line=node.start_point[0] + 1, col=node.start_point[1],
                ))
            elif op_text == "??":
                self._pdg.add_edge(PDGEdge(
                    src=left_id, dst=result_id, kind=EdgeKind.NULLISH,
                    line=node.start_point[0] + 1, col=node.start_point[1],
                ))
            elif op_text == "+":
                self._pdg.add_edge(PDGEdge(
                    src=left_id, dst=result_id, kind=EdgeKind.CONCAT,
                    line=node.start_point[0] + 1, col=node.start_point[1],
                ))
            # Comparison / arithmetic operators: no taint propagation

        if right_id and op_text == "+":
            self._pdg.add_edge(PDGEdge(
                src=right_id, dst=result_id, kind=EdgeKind.CONCAT,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))
        elif right_id and op_text == "||":
            self._pdg.add_edge(PDGEdge(
                src=right_id, dst=result_id, kind=EdgeKind.OR_DEFAULT,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))
        elif right_id and op_text == "??":
            self._pdg.add_edge(PDGEdge(
                src=right_id, dst=result_id, kind=EdgeKind.NULLISH,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

    def _handle_ternary(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: cond ? a : b"""
        consequence = node.child_by_field_name("consequence")
        alternative = node.child_by_field_name("alternative")
        if not consequence or not alternative:
            return

        result_id = self._make_node_id(node, scope_tree, suffix="_ternary")
        self._pdg.add_node(PDGNode(id=result_id, kind=NodeKind.BINARY_EXPR))

        cons_id = self._expr_node_id(consequence, scope_tree)
        alt_id = self._expr_node_id(alternative, scope_tree)

        if cons_id:
            self._pdg.add_edge(PDGEdge(
                src=cons_id, dst=result_id, kind=EdgeKind.TERNARY,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))
        if alt_id:
            self._pdg.add_edge(PDGEdge(
                src=alt_id, dst=result_id, kind=EdgeKind.TERNARY,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

    def _handle_template(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: `prefix ${expr} suffix`"""
        nid = self._make_node_id(node, scope_tree, suffix="_tmpl")
        self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.TEMPLATE_EXPR))

        for child in node.named_children:
            if child.type == "template_substitution":
                sub_expr = child.named_children[0] if child.named_children else None
                if sub_expr:
                    sub_id = self._expr_node_id(sub_expr, scope_tree)
                    if sub_id:
                        self._pdg.add_edge(PDGEdge(
                            src=sub_id, dst=nid, kind=EdgeKind.TEMPLATE,
                            line=child.start_point[0] + 1, col=child.start_point[1],
                        ))

    def _handle_spread(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: ...x"""
        if not node.named_children:
            return
        arg = node.named_children[0]
        arg_id = self._expr_node_id(arg, scope_tree)
        if arg_id:
            spread_id = self._make_node_id(node, scope_tree, suffix="_spread")
            self._pdg.add_node(PDGNode(id=spread_id, kind=NodeKind.SPREAD))
            self._pdg.add_edge(PDGEdge(
                src=arg_id, dst=spread_id, kind=EdgeKind.SPREAD,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

    def _handle_function_def(self, node: object, scope_tree: ScopeTree) -> None:
        """Register function parameters in the PDG for interprocedural linking."""
        name_node = node.child_by_field_name("name")
        params_node = node.child_by_field_name("parameters")

        fn_name: str | None = None
        if name_node and name_node.type == "identifier":
            fn_name = name_node.text.decode()
        elif node.parent and node.parent.type == "variable_declarator":
            # const foo = function() {} or const foo = () => {}
            vd_name = node.parent.child_by_field_name("name")
            if vd_name and vd_name.type == "identifier":
                fn_name = vd_name.text.decode()
        elif node.parent and node.parent.type == "pair":
            # { foo: function() {} }
            key = node.parent.child_by_field_name("key")
            if key:
                fn_name = key.text.decode()

        if not params_node or not fn_name:
            return

        fn_name_interned = self._pdg._intern(fn_name)
        param_ids: list[PDGNodeId] = []

        for param in params_node.named_children:
            if param.type == "identifier":
                pid = self._make_node_id(param, scope_tree)
                self._pdg.add_node(PDGNode(id=pid, kind=NodeKind.PARAMETER))
                param_ids.append(pid)
            elif param.type == "assignment_pattern":
                left = param.child_by_field_name("left")
                if left and left.type == "identifier":
                    pid = self._make_node_id(left, scope_tree)
                    self._pdg.add_node(PDGNode(id=pid, kind=NodeKind.PARAMETER))
                    param_ids.append(pid)
                    # Wire default value
                    right = param.child_by_field_name("right")
                    if right:
                        def_id = self._expr_node_id(right, scope_tree)
                        if def_id:
                            self._pdg.add_edge(PDGEdge(
                                src=def_id, dst=pid, kind=EdgeKind.OR_DEFAULT,
                                line=param.start_point[0] + 1, col=param.start_point[1],
                            ))
            elif param.type == "rest_pattern":
                arg = param.named_children[0] if param.named_children else None
                if arg and arg.type == "identifier":
                    pid = self._make_node_id(arg, scope_tree)
                    self._pdg.add_node(PDGNode(id=pid, kind=NodeKind.PARAMETER))
                    param_ids.append(pid)

        self._pdg.functions[fn_name_interned] = param_ids

    def _handle_for_in_of(self, node: object, scope_tree: ScopeTree) -> None:
        """Handle: for (const x of iterable) / for (let k in obj)"""
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            return

        # The left side may be a variable_declaration or an identifier
        target_node: object | None = None
        if left.type in ("variable_declaration", "lexical_declaration"):
            for child in left.named_children:
                if child.type == "variable_declarator":
                    name = child.child_by_field_name("name")
                    if name and name.type == "identifier":
                        target_node = name
                        break
        elif left.type == "identifier":
            target_node = left

        if target_node is None:
            return

        iter_id = self._expr_node_id(right, scope_tree)
        if iter_id:
            item_id = self._make_node_id(target_node, scope_tree)
            self._pdg.add_node(PDGNode(id=item_id, kind=NodeKind.VARIABLE))
            self._pdg.add_edge(PDGEdge(
                src=iter_id, dst=item_id, kind=EdgeKind.CALLBACK_ITEM,
                line=node.start_point[0] + 1, col=node.start_point[1],
            ))

    # -- interprocedural resolution -----------------------------------------

    def _resolve_calls(self, scope_tree: ScopeTree) -> None:
        """Wire up interprocedural edges.

        For each call site, connect:
          1. Argument nodes --> callee parameter nodes (ARG_PASS)
          2. Callee return nodes --> call result node (RETURN_FLOW)
        """
        for call_site in self._pdg.call_sites:
            callee = call_site.callee_name

            # Wire ARG_PASS edges
            if callee in self._pdg.functions:
                param_nodes = self._pdg.functions[callee]
                for i, arg_id in enumerate(call_site.args):
                    if i < len(param_nodes):
                        self._pdg.add_edge(PDGEdge(
                            src=arg_id, dst=param_nodes[i],
                            kind=EdgeKind.ARG_PASS, param_index=i,
                            line=call_site.location.line, col=call_site.location.col,
                        ))

            # Wire RETURN_FLOW edges
            ret_key = f"__return__{callee}"
            if ret_key in self._pdg.functions and call_site.result_node:
                for ret_node_id in self._pdg.functions[ret_key]:
                    self._pdg.add_edge(PDGEdge(
                        src=ret_node_id, dst=call_site.result_node,
                        kind=EdgeKind.RETURN_FLOW,
                        line=call_site.location.line, col=call_site.location.col,
                    ))

    # -- node-id helpers ----------------------------------------------------

    def _make_node_id(self, ts_node: object, scope_tree: ScopeTree, suffix: str = "") -> PDGNodeId:
        """Create PDGNodeId from a tree-sitter node."""
        raw_name = ts_node.text.decode()
        # Truncate very long names (e.g. template strings)
        name = raw_name[:100] + suffix
        scope_id = self._scope_at_byte(scope_tree, ts_node.start_byte)
        return PDGNodeId(
            scope_id=scope_id,
            name=self._pdg._intern(name),
            file_id=self._current_file_id,
            line=ts_node.start_point[0] + 1,
            col=ts_node.start_point[1],
        )

    def _expr_node_id(self, node: object, scope_tree: ScopeTree) -> PDGNodeId | None:
        """Get or create a PDGNodeId for an expression node."""
        if node.type == "identifier":
            name = node.text.decode()
            nid = self._make_node_id(node, scope_tree)
            scope_id = self._scope_at_byte(scope_tree, node.start_byte)
            is_undeclared = scope_tree.is_undeclared_global(name, scope_id)
            kind = NodeKind.GLOBAL_ACCESS if is_undeclared else NodeKind.VARIABLE
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=kind, is_undeclared=is_undeclared))
            return nid

        elif node.type == "member_expression":
            obj = node.child_by_field_name("object")
            prop = node.child_by_field_name("property")
            if obj and prop:
                nid = self._make_node_id(node, scope_tree)
                chain = self._build_access_chain(node)
                if nid not in self._pdg.nodes:
                    self._pdg.add_node(PDGNode(
                        id=nid, kind=NodeKind.PROPERTY_ACCESS, access_chain=chain,
                    ))
                # Add PROP_READ edge from object
                obj_id = self._expr_node_id(obj, scope_tree)
                if obj_id:
                    self._pdg.add_edge(PDGEdge(
                        src=obj_id, dst=nid, kind=EdgeKind.PROP_READ,
                        line=node.start_point[0] + 1, col=node.start_point[1],
                    ))
                return nid

        elif node.type == "subscript_expression":
            obj = node.child_by_field_name("object")
            index = node.child_by_field_name("index")
            if obj:
                nid = self._make_node_id(node, scope_tree, suffix="_comp")
                if nid not in self._pdg.nodes:
                    self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.COMPUTED_ACCESS))
                obj_id = self._expr_node_id(obj, scope_tree)
                if obj_id:
                    self._pdg.add_edge(PDGEdge(
                        src=obj_id, dst=nid, kind=EdgeKind.COMPUTED_READ,
                        line=node.start_point[0] + 1, col=node.start_point[1],
                    ))
                return nid

        elif node.type == "call_expression":
            # Return a CALL_RESULT node; the call itself is handled by _handle_call
            nid = self._make_node_id(node, scope_tree, suffix="_result")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.CALL_RESULT))
            return nid

        elif node.type in ("string", "string_fragment", "number", "true", "false", "null", "undefined"):
            nid = self._make_node_id(node, scope_tree, suffix="_lit")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.LITERAL))
            return nid

        elif node.type == "template_string":
            nid = self._make_node_id(node, scope_tree, suffix="_tmpl")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.TEMPLATE_EXPR))
            # Add TEMPLATE edges from each substitution
            for child in node.named_children:
                if child.type == "template_substitution":
                    sub_expr = child.named_children[0] if child.named_children else None
                    if sub_expr:
                        sub_id = self._expr_node_id(sub_expr, scope_tree)
                        if sub_id:
                            self._pdg.add_edge(PDGEdge(
                                src=sub_id, dst=nid, kind=EdgeKind.TEMPLATE,
                            ))
            return nid

        elif node.type == "this":
            nid = self._make_node_id(node, scope_tree)
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.THIS_ACCESS))
            return nid

        elif node.type == "parenthesized_expression":
            # Unwrap parentheses
            if node.named_children:
                return self._expr_node_id(node.named_children[0], scope_tree)

        elif node.type == "binary_expression":
            # The _handle_binary call during _walk creates the result node;
            # here we just return its ID so it can be used in edges.
            nid = self._make_node_id(node, scope_tree, suffix="_binop")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.BINARY_EXPR))
            return nid

        elif node.type == "ternary_expression":
            nid = self._make_node_id(node, scope_tree, suffix="_ternary")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.BINARY_EXPR))
            return nid

        elif node.type == "await_expression":
            if node.named_children:
                return self._expr_node_id(node.named_children[0], scope_tree)

        elif node.type == "assignment_expression":
            # The result of an assignment is the right-hand side
            right = node.child_by_field_name("right")
            if right:
                return self._expr_node_id(right, scope_tree)

        elif node.type == "array":
            # Array literal -- create a node that spreads from all elements
            nid = self._make_node_id(node, scope_tree, suffix="_arr")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.LITERAL))
            return nid

        elif node.type == "object":
            nid = self._make_node_id(node, scope_tree, suffix="_obj")
            if nid not in self._pdg.nodes:
                self._pdg.add_node(PDGNode(id=nid, kind=NodeKind.LITERAL))
            return nid

        return None

    def _build_access_chain(self, member_expr_node: object) -> tuple[str, ...]:
        """Build property access chain: window.config.baseUrl -> ('window', 'config', 'baseUrl')"""
        chain: list[str] = []
        node = member_expr_node
        while node and node.type == "member_expression":
            prop = node.child_by_field_name("property")
            if prop:
                chain.append(prop.text.decode())
            node = node.child_by_field_name("object")
        if node and node.type == "identifier":
            chain.append(node.text.decode())
        chain.reverse()
        return tuple(chain)

    def _scope_at_byte(self, scope_tree: ScopeTree, byte_offset: int) -> int:
        """Find innermost scope containing byte_offset."""
        best = 0
        best_span = float("inf")
        for scope in scope_tree.scopes:
            if scope.start_byte <= byte_offset <= scope.end_byte:
                span = scope.end_byte - scope.start_byte
                if span < best_span:
                    best = scope.id
                    best_span = span
        return best
