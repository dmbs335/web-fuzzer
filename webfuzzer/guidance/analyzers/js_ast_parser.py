"""JavaScript AST parser and scope analyzer using tree-sitter.

Provides:
- ScopeTree: variable declaration tracking and scope chain resolution
- Source/sink identification via tree-sitter queries
- FileIndex: tracks files for incremental analysis
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Location:
    file_id: int
    line: int
    col: int
    end_line: int = 0
    end_col: int = 0


@dataclass(frozen=True)
class Declaration:
    name: str
    kind: str              # "var", "let", "const", "function", "class", "param", "import", "catch"
    scope_id: int
    location: Location
    hoisted: bool = False  # var/function are hoisted


@dataclass
class Scope:
    id: int
    parent_id: int | None
    kind: str              # "global", "function", "block", "class", "module", "arrow"
    declarations: dict[str, Declaration] = field(default_factory=dict)
    children: list[int] = field(default_factory=list)
    start_byte: int = 0
    end_byte: int = 0
    function_name: str | None = None


# ---------------------------------------------------------------------------
# ScopeTree
# ---------------------------------------------------------------------------

class ScopeTree:
    """Built from tree-sitter AST.  Resolves variable references to declarations."""

    def __init__(self) -> None:
        self.scopes: list[Scope] = []
        self._scope_stack: list[int] = []

    def push_scope(
        self,
        kind: str,
        start_byte: int,
        end_byte: int,
        fn_name: str | None = None,
    ) -> int:
        """Create a new scope, push onto stack.  Returns scope id."""
        sid = len(self.scopes)
        parent = self._scope_stack[-1] if self._scope_stack else None
        scope = Scope(
            id=sid,
            parent_id=parent,
            kind=kind,
            start_byte=start_byte,
            end_byte=end_byte,
            function_name=fn_name,
        )
        self.scopes.append(scope)
        if parent is not None:
            self.scopes[parent].children.append(sid)
        self._scope_stack.append(sid)
        return sid

    def pop_scope(self) -> None:
        """Pop current scope."""
        if self._scope_stack:
            self._scope_stack.pop()

    def current_scope_id(self) -> int:
        """Return current (innermost) scope id."""
        return self._scope_stack[-1] if self._scope_stack else 0

    def add_declaration(self, name: str, kind: str, location: Location) -> None:
        """Add a declaration to the current scope.

        For ``var`` and ``function`` declarations the binding is hoisted to the
        nearest enclosing *function* (or global) scope.
        """
        hoisted = kind in ("var", "function")
        target_id = self.current_scope_id()

        if hoisted:
            # Walk up until we find a function/global/module scope
            sid = target_id
            while sid is not None:
                s = self.scopes[sid]
                if s.kind in ("function", "global", "module", "arrow"):
                    target_id = sid
                    break
                sid = s.parent_id

        decl = Declaration(
            name=name,
            kind=kind,
            scope_id=target_id,
            location=location,
            hoisted=hoisted,
        )
        self.scopes[target_id].declarations[name] = decl

    def resolve(self, name: str, from_scope_id: int) -> Declaration | None:
        """Walk up scope chain to resolve a name.  Returns ``None`` if undeclared."""
        scope = self.scopes[from_scope_id]
        while True:
            if name in scope.declarations:
                return scope.declarations[name]
            if scope.parent_id is None:
                return None
            scope = self.scopes[scope.parent_id]

    def is_undeclared_global(self, name: str, from_scope_id: int) -> bool:
        """True if *name* is not declared in any enclosing scope."""
        return self.resolve(name, from_scope_id) is None


# ---------------------------------------------------------------------------
# FileIndex
# ---------------------------------------------------------------------------

class FileIndex:
    """Track files for analysis with content hashing."""

    def __init__(self) -> None:
        self.files: list[str] = []               # path list
        self.hashes: dict[int, str] = {}          # file_id -> content hash
        self._path_to_id: dict[str, int] = {}

    def add_file(self, path: str, content: str) -> int:
        """Register a file, return file_id."""
        if path in self._path_to_id:
            fid = self._path_to_id[path]
        else:
            fid = len(self.files)
            self.files.append(path)
            self._path_to_id[path] = fid
        self.hashes[fid] = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return fid

    def needs_reanalysis(self, path: str, content: str) -> bool:
        """Check if file has changed since last analysis."""
        fid = self._path_to_id.get(path)
        if fid is None:
            return True
        new_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return self.hashes.get(fid) != new_hash


# ---------------------------------------------------------------------------
# Source / sink / guard data classes
# ---------------------------------------------------------------------------

@dataclass
class ClobberSource:
    property_name: str
    access_pattern: str      # "window.config", "document.cookie", "bare:ga"
    location: Location
    priority: int            # 1=certain, 2=likely, 3=possible, 4=indirect
    chain_depth: int         # 1 for X, 2 for X.Y
    guarded: bool
    scope_id: int
    access_chain: tuple[str, ...] = ()


@dataclass
class ClobberSink:
    sink_type: str           # "innerHTML", "eval", "script.src", etc.
    location: Location
    severity: str            # "CRITICAL", "HIGH", "MEDIUM"
    scope_id: int
    node_id: object = None   # PDGNodeId (set later by PDG builder)


@dataclass
class Guard:
    kind: str                # "typeof_check", "optional_chain", "or_default", "nullish_coalescing"
    checked_name: str        # the variable being guarded
    location: Location


@dataclass
class ParseResult:
    tree: object             # tree-sitter Tree (or None for regex fallback)
    scope_tree: ScopeTree
    file_id: int
    sources: list[ClobberSource] = field(default_factory=list)
    sinks: list[ClobberSink] = field(default_factory=list)
    guards: list[Guard] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constant tables
# ---------------------------------------------------------------------------

# Properties that are safe to access on window/document (not clobberable targets)
_SAFE_PROPS = frozenset({
    "addEventListener", "removeEventListener", "setTimeout", "setInterval",
    "clearTimeout", "clearInterval", "requestAnimationFrame", "cancelAnimationFrame",
    "Promise", "Symbol", "Map", "Set", "WeakMap", "WeakSet",
    "Array", "Object", "String", "Number", "Boolean", "RegExp", "Date",
    "Math", "JSON", "Intl", "Reflect", "Proxy", "Error",
    "console", "performance", "navigator", "history", "screen",
    "innerWidth", "innerHeight", "outerWidth", "outerHeight",
    "scrollX", "scrollY", "pageXOffset", "pageYOffset",
    "alert", "confirm", "prompt", "print", "close", "focus", "blur",
    "atob", "btoa", "encodeURI", "decodeURI", "encodeURIComponent", "decodeURIComponent",
    "parseInt", "parseFloat", "isNaN", "isFinite", "undefined", "NaN", "Infinity",
    "prototype", "constructor", "__proto__",
    "length", "name", "arguments", "caller", "callee",
})

# Known safe global names that should not be flagged as clobberable
_KNOWN_GLOBALS = frozenset({
    "undefined", "NaN", "Infinity", "null", "true", "false",
    "Math", "JSON", "console", "performance",
    "Array", "Object", "String", "Number", "Boolean", "Function",
    "RegExp", "Date", "Error", "TypeError", "RangeError", "SyntaxError",
    "Promise", "Symbol", "Map", "Set", "WeakMap", "WeakSet",
    "Proxy", "Reflect", "Intl", "ArrayBuffer", "DataView",
    "Int8Array", "Uint8Array", "Float32Array", "Float64Array",
    "setTimeout", "setInterval", "clearTimeout", "clearInterval",
    "requestAnimationFrame", "cancelAnimationFrame",
    "fetch", "XMLHttpRequest", "WebSocket", "EventSource",
    "URL", "URLSearchParams", "Headers", "Request", "Response",
    "Blob", "File", "FileReader", "FormData",
    "Event", "CustomEvent", "MessageEvent",
    "document", "window", "globalThis", "self", "this",
    "navigator", "history", "location", "screen",
    "alert", "confirm", "prompt",
    "require", "module", "exports", "__dirname", "__filename",
    "process", "Buffer", "global",
})

# JS keywords that appear as identifier nodes but are not references
_JS_KEYWORDS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "break",
    "continue", "return", "throw", "try", "catch", "finally",
    "new", "delete", "typeof", "void", "in", "instanceof", "of",
    "class", "extends", "super", "import", "export", "default",
    "async", "await", "yield", "let", "const", "var", "function",
    "with", "debugger", "enum",
})

# Sink patterns: (method / property name) -> (sink_type, severity)
_SINK_TABLE: dict[str, tuple[str, str]] = {
    "innerHTML": ("innerHTML", "CRITICAL"),
    "outerHTML": ("outerHTML", "CRITICAL"),
    "eval": ("eval", "CRITICAL"),
    "Function": ("Function_constructor", "CRITICAL"),
    "write": ("document.write", "HIGH"),
    "writeln": ("document.writeln", "HIGH"),
    "src": ("element.src", "HIGH"),
    "href": ("element.href", "HIGH"),
    "action": ("form.action", "HIGH"),
    "assign": ("location.assign", "HIGH"),
    "replace": ("location.replace", "HIGH"),
    "open": ("window.open", "MEDIUM"),
    "insertAdjacentHTML": ("insertAdjacentHTML", "CRITICAL"),
    "html": ("jQuery.html", "CRITICAL"),
    "append": ("jQuery.append", "HIGH"),
    "prepend": ("jQuery.prepend", "HIGH"),
    "after": ("jQuery.after", "HIGH"),
    "before": ("jQuery.before", "HIGH"),
    "setRequestHeader": ("XHR.setRequestHeader", "MEDIUM"),
}

_LOCATION_PROPS = frozenset({"assign", "replace", "href"})


# ---------------------------------------------------------------------------
# Scope-creating node types
# ---------------------------------------------------------------------------

_SCOPE_CREATORS = {
    "program": "global",
    "function_declaration": "function",
    "function_expression": "function",
    "arrow_function": "arrow",
    "method_definition": "function",
    "class_declaration": "class",
    "class_expression": "class",
    "for_statement": "block",
    "for_in_statement": "block",
    "for_of_statement": "block",
    "while_statement": "block",
    "do_statement": "block",
    "if_statement": "block",
    "switch_statement": "block",
    "catch_clause": "block",
    "block": "block",
}


# ---------------------------------------------------------------------------
# JSParser
# ---------------------------------------------------------------------------

class JSParser:
    """Parse JavaScript files and build ScopeTree."""

    def __init__(self) -> None:
        self._parser = None
        self._language = None
        self._setup_parser()

    # -- initialisation -----------------------------------------------------

    def _setup_parser(self) -> None:
        """Initialize tree-sitter parser with JavaScript language."""
        try:
            import tree_sitter_javascript as tsjs
            from tree_sitter import Language, Parser

            self._language = Language(tsjs.language())
            self._parser = Parser(self._language)
            logger.debug("tree-sitter JavaScript parser initialised")
        except ImportError:
            logger.warning(
                "tree-sitter-javascript not installed, using regex fallback"
            )
            self._parser = None

    # -- public API ---------------------------------------------------------

    def parse_file(self, content: str, file_id: int) -> ParseResult:
        """Parse JS content and return AST + ScopeTree."""
        if self._parser is None:
            return self._regex_fallback(content, file_id)

        tree = self._parser.parse(content.encode("utf-8"))
        scope_tree = ScopeTree()

        # Build scope tree by walking the AST
        self._build_scopes(tree.root_node, scope_tree, file_id)

        result = ParseResult(tree=tree, scope_tree=scope_tree, file_id=file_id)
        result.sources = self.find_sources(tree, scope_tree, file_id)
        result.sinks = self.find_sinks(tree, scope_tree, file_id)
        result.guards = self.find_guards(tree, file_id)
        return result

    # -- scope building -----------------------------------------------------

    def _build_scopes(self, node: object, scope_tree: ScopeTree, file_id: int) -> None:
        """Recursively walk AST to build scope tree."""
        ntype = node.type

        # Determine whether this node creates a new scope
        scope_kind = _SCOPE_CREATORS.get(ntype)
        pushed = False

        if scope_kind is not None:
            # For block scopes inside functions we only push if the block
            # itself isn't the *body* of a function (already has a scope).
            if scope_kind == "block" and ntype == "block":
                parent_type = node.parent.type if node.parent else ""
                if parent_type in (
                    "function_declaration",
                    "function_expression",
                    "arrow_function",
                    "method_definition",
                ):
                    # The function scope already covers this block; skip.
                    scope_kind = None

            if scope_kind is not None:
                fn_name = self._extract_function_name(node) if scope_kind in ("function", "arrow") else None
                scope_tree.push_scope(scope_kind, node.start_byte, node.end_byte, fn_name=fn_name)
                pushed = True

        # Handle declarations
        self._collect_declarations(node, scope_tree, file_id)

        # Recurse into children
        for child in node.children:
            self._build_scopes(child, scope_tree, file_id)

        if pushed:
            scope_tree.pop_scope()

    def _extract_function_name(self, node: object) -> str | None:
        """Extract function name from a function_declaration / expression / arrow."""
        name_node = node.child_by_field_name("name")
        if name_node:
            return name_node.text.decode()
        # For arrow functions assigned to a variable, the name comes from the
        # parent variable_declarator; we don't resolve that here.
        return None

    def _collect_declarations(self, node: object, scope_tree: ScopeTree, file_id: int) -> None:
        """Register declarations found at *node*."""
        ntype = node.type

        # -- function_declaration: name hoisted to parent scope ---------------
        if ntype == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                loc = self._loc(name_node, file_id)
                # Hoist to enclosing function/global scope (add_declaration handles it)
                scope_tree.add_declaration(name_node.text.decode(), "function", loc)

            # Parameters go into the NEW function scope (pushed above)
            params_node = node.child_by_field_name("parameters")
            if params_node:
                self._collect_params(params_node, scope_tree, file_id)

        # -- function_expression / arrow_function: params only ---------------
        elif ntype in ("function_expression", "arrow_function", "method_definition"):
            params_node = node.child_by_field_name("parameters")
            if params_node:
                self._collect_params(params_node, scope_tree, file_id)

        # -- variable_declaration / lexical_declaration ----------------------
        elif ntype == "variable_declaration":
            kind = "var"
            for child in node.named_children:
                if child.type == "variable_declarator":
                    self._declare_variable_declarator(child, kind, scope_tree, file_id)

        elif ntype == "lexical_declaration":
            # Determine let vs const from the first child token
            kind = "let"
            for child in node.children:
                if child.type in ("let", "const"):
                    kind = child.type
                    break
            for child in node.named_children:
                if child.type == "variable_declarator":
                    self._declare_variable_declarator(child, kind, scope_tree, file_id)

        # -- class_declaration -----------------------------------------------
        elif ntype == "class_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                loc = self._loc(name_node, file_id)
                scope_tree.add_declaration(name_node.text.decode(), "class", loc)

        # -- import_statement ------------------------------------------------
        elif ntype == "import_statement":
            for child in node.named_children:
                if child.type == "import_clause":
                    self._collect_import_clause(child, scope_tree, file_id)

        # -- catch_clause parameter ------------------------------------------
        elif ntype == "catch_clause":
            param = node.child_by_field_name("parameter")
            if param and param.type == "identifier":
                loc = self._loc(param, file_id)
                scope_tree.add_declaration(param.text.decode(), "catch", loc)

        # -- for_in_statement / for_of_statement left binding ----------------
        elif ntype in ("for_in_statement", "for_of_statement"):
            left = node.child_by_field_name("left")
            if left and left.type == "identifier":
                loc = self._loc(left, file_id)
                scope_tree.add_declaration(left.text.decode(), "var", loc)
            elif left and left.type in ("variable_declaration", "lexical_declaration"):
                self._collect_declarations(left, scope_tree, file_id)

    def _declare_variable_declarator(
        self, node: object, kind: str, scope_tree: ScopeTree, file_id: int
    ) -> None:
        """Handle a single variable_declarator node, including destructuring."""
        name_node = node.child_by_field_name("name")
        if name_node is None:
            return

        if name_node.type == "identifier":
            loc = self._loc(name_node, file_id)
            scope_tree.add_declaration(name_node.text.decode(), kind, loc)
        elif name_node.type == "object_pattern":
            self._collect_destructure_pattern(name_node, kind, scope_tree, file_id)
        elif name_node.type == "array_pattern":
            self._collect_destructure_pattern(name_node, kind, scope_tree, file_id)

    def _collect_destructure_pattern(
        self, node: object, kind: str, scope_tree: ScopeTree, file_id: int
    ) -> None:
        """Recursively collect names from destructuring patterns."""
        for child in node.named_children:
            if child.type == "identifier":
                loc = self._loc(child, file_id)
                scope_tree.add_declaration(child.text.decode(), kind, loc)
            elif child.type == "shorthand_property_identifier_pattern":
                loc = self._loc(child, file_id)
                scope_tree.add_declaration(child.text.decode(), kind, loc)
            elif child.type == "pair_pattern":
                value_node = child.child_by_field_name("value")
                if value_node:
                    if value_node.type == "identifier":
                        loc = self._loc(value_node, file_id)
                        scope_tree.add_declaration(value_node.text.decode(), kind, loc)
                    elif value_node.type in ("object_pattern", "array_pattern"):
                        self._collect_destructure_pattern(value_node, kind, scope_tree, file_id)
                    elif value_node.type == "assignment_pattern":
                        left = value_node.child_by_field_name("left")
                        if left and left.type == "identifier":
                            loc = self._loc(left, file_id)
                            scope_tree.add_declaration(left.text.decode(), kind, loc)
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                if left:
                    if left.type == "identifier":
                        loc = self._loc(left, file_id)
                        scope_tree.add_declaration(left.text.decode(), kind, loc)
                    elif left.type in ("object_pattern", "array_pattern"):
                        self._collect_destructure_pattern(left, kind, scope_tree, file_id)
            elif child.type == "rest_pattern":
                arg = child.named_children[0] if child.named_children else None
                if arg and arg.type == "identifier":
                    loc = self._loc(arg, file_id)
                    scope_tree.add_declaration(arg.text.decode(), kind, loc)
            elif child.type in ("object_pattern", "array_pattern"):
                self._collect_destructure_pattern(child, kind, scope_tree, file_id)

    def _collect_params(self, params_node: object, scope_tree: ScopeTree, file_id: int) -> None:
        """Collect formal parameters into the current (function) scope."""
        for child in params_node.named_children:
            if child.type == "identifier":
                loc = self._loc(child, file_id)
                scope_tree.add_declaration(child.text.decode(), "param", loc)
            elif child.type == "assignment_pattern":
                left = child.child_by_field_name("left")
                if left and left.type == "identifier":
                    loc = self._loc(left, file_id)
                    scope_tree.add_declaration(left.text.decode(), "param", loc)
                elif left and left.type in ("object_pattern", "array_pattern"):
                    self._collect_destructure_pattern(left, "param", scope_tree, file_id)
            elif child.type in ("object_pattern", "array_pattern"):
                self._collect_destructure_pattern(child, "param", scope_tree, file_id)
            elif child.type == "rest_pattern":
                arg = child.named_children[0] if child.named_children else None
                if arg and arg.type == "identifier":
                    loc = self._loc(arg, file_id)
                    scope_tree.add_declaration(arg.text.decode(), "param", loc)

    def _collect_import_clause(self, node: object, scope_tree: ScopeTree, file_id: int) -> None:
        """Collect imported names from import clause."""
        for child in node.named_children:
            if child.type == "identifier":
                loc = self._loc(child, file_id)
                scope_tree.add_declaration(child.text.decode(), "import", loc)
            elif child.type == "namespace_import":
                name = child.child_by_field_name("name") or (
                    child.named_children[0] if child.named_children else None
                )
                if name and name.type == "identifier":
                    loc = self._loc(name, file_id)
                    scope_tree.add_declaration(name.text.decode(), "import", loc)
            elif child.type == "named_imports":
                for spec in child.named_children:
                    if spec.type == "import_specifier":
                        alias = spec.child_by_field_name("alias")
                        if alias and alias.type == "identifier":
                            loc = self._loc(alias, file_id)
                            scope_tree.add_declaration(alias.text.decode(), "import", loc)
                        else:
                            name_node = spec.child_by_field_name("name")
                            if name_node and name_node.type == "identifier":
                                loc = self._loc(name_node, file_id)
                                scope_tree.add_declaration(name_node.text.decode(), "import", loc)

    # -- source / sink / guard finding --------------------------------------
    # Uses recursive AST walking (compatible with tree-sitter v0.25+).

    def find_sources(
        self, tree: object, scope_tree: ScopeTree, file_id: int
    ) -> list[ClobberSource]:
        """Find DOM clobbering sources via AST walk."""
        sources: list[ClobberSource] = []
        if tree is None:
            return sources

        def visit(node: object) -> None:
            if node.type == "member_expression":
                obj = node.child_by_field_name("object")
                prop = node.child_by_field_name("property")
                if obj and prop:
                    # P1: window.X / document.X / globalThis.X / self.X
                    if obj.type == "identifier" and prop.type == "property_identifier":
                        obj_text = obj.text.decode()
                        if obj_text in ("window", "document", "globalThis", "self"):
                            prop_text = prop.text.decode()
                            if prop_text not in _SAFE_PROPS:
                                loc = self._loc(prop, file_id)
                                scope_id = self._scope_at_byte(scope_tree, prop.start_byte)
                                sources.append(ClobberSource(
                                    property_name=prop_text,
                                    access_pattern=f"{obj_text}.{prop_text}",
                                    location=loc, priority=1, chain_depth=1,
                                    guarded=False, scope_id=scope_id,
                                    access_chain=(obj_text, prop_text),
                                ))
                    # P3: this.X in global scope
                    elif obj.type == "this" and prop.type == "property_identifier":
                        scope_id = self._scope_at_byte(scope_tree, obj.start_byte)
                        scope = scope_tree.scopes[scope_id]
                        if scope.kind in ("global", "module"):
                            prop_text = prop.text.decode()
                            if prop_text not in _SAFE_PROPS:
                                loc = self._loc(prop, file_id)
                                sources.append(ClobberSource(
                                    property_name=prop_text,
                                    access_pattern=f"this.{prop_text}",
                                    location=loc, priority=3, chain_depth=1,
                                    guarded=False, scope_id=scope_id,
                                    access_chain=("this", prop_text),
                                ))

            elif node.type == "identifier":
                # P2: bare globals — identifiers not declared in any scope
                name = node.text.decode()
                if name in _JS_KEYWORDS or name in _KNOWN_GLOBALS:
                    pass
                else:
                    parent = node.parent
                    skip = False
                    if parent and parent.type == "member_expression":
                        obj_field = parent.child_by_field_name("object")
                        if obj_field is None or obj_field.id != node.id:
                            skip = True  # property side of member_expression
                    if parent and parent.type in (
                        "variable_declarator", "function_declaration",
                        "class_declaration", "import_specifier",
                        "formal_parameters",
                        "shorthand_property_identifier_pattern",
                        "property_identifier",
                    ):
                        skip = True
                    if not skip:
                        scope_id = self._scope_at_byte(scope_tree, node.start_byte)
                        if scope_tree.is_undeclared_global(name, scope_id):
                            loc = self._loc(node, file_id)
                            sources.append(ClobberSource(
                                property_name=name,
                                access_pattern=f"bare:{name}",
                                location=loc, priority=2, chain_depth=1,
                                guarded=False, scope_id=scope_id,
                                access_chain=(name,),
                            ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return sources

    def find_sinks(
        self, tree: object, scope_tree: ScopeTree, file_id: int
    ) -> list[ClobberSink]:
        """Find dangerous sinks via AST walk."""
        sinks: list[ClobberSink] = []
        if tree is None:
            return sinks

        def visit(node: object) -> None:
            if node.type == "assignment_expression":
                left = node.child_by_field_name("left")
                if left and left.type == "member_expression":
                    prop = left.child_by_field_name("property")
                    if prop and prop.type == "property_identifier":
                        prop_text = prop.text.decode()
                        if prop_text in _SINK_TABLE:
                            sink_type, severity = _SINK_TABLE[prop_text]
                            loc = self._loc(prop, file_id)
                            scope_id = self._scope_at_byte(scope_tree, prop.start_byte)
                            sinks.append(ClobberSink(
                                sink_type=sink_type, location=loc,
                                severity=severity, scope_id=scope_id,
                            ))

            elif node.type == "call_expression":
                fn = node.child_by_field_name("function")
                if fn:
                    callee_name: str | None = None
                    if fn.type == "identifier":
                        callee_name = fn.text.decode()
                    elif fn.type == "member_expression":
                        prop = fn.child_by_field_name("property")
                        callee_name = prop.text.decode() if prop else None
                    elif fn.type == "import":
                        # Dynamic import()
                        loc = self._loc(fn, file_id)
                        scope_id = self._scope_at_byte(scope_tree, fn.start_byte)
                        sinks.append(ClobberSink(
                            sink_type="dynamic_import", location=loc,
                            severity="HIGH", scope_id=scope_id,
                        ))

                    if callee_name and callee_name in _SINK_TABLE:
                        sink_type, severity = _SINK_TABLE[callee_name]
                        loc = self._loc(fn, file_id)
                        scope_id = self._scope_at_byte(scope_tree, fn.start_byte)
                        sinks.append(ClobberSink(
                            sink_type=sink_type, location=loc,
                            severity=severity, scope_id=scope_id,
                        ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return sinks

    def find_guards(self, tree: object, file_id: int) -> list[Guard]:
        """Find typeof checks, optional chaining, || defaults, ?? operators via AST walk."""
        guards: list[Guard] = []
        if tree is None:
            return guards

        def visit(node: object) -> None:
            if node.type == "unary_expression":
                # typeof check: typeof X
                op = node.child_by_field_name("operator")
                arg = node.child_by_field_name("argument")
                if op and op.text.decode() == "typeof" and arg and arg.type == "identifier":
                    loc = self._loc(arg, file_id)
                    guards.append(Guard(
                        kind="typeof_check", checked_name=arg.text.decode(), location=loc,
                    ))

            elif node.type == "optional_chain_expression":
                checked = self._leftmost_identifier(node)
                if checked:
                    loc = self._loc(node, file_id)
                    guards.append(Guard(
                        kind="optional_chain", checked_name=checked, location=loc,
                    ))

            elif node.type == "binary_expression":
                op = node.child_by_field_name("operator")
                if op:
                    op_text = op.text.decode()
                    if op_text == "||":
                        left = node.child_by_field_name("left")
                        if left:
                            checked = self._leftmost_identifier(left)
                            if checked:
                                loc = self._loc(left, file_id)
                                guards.append(Guard(
                                    kind="or_default", checked_name=checked, location=loc,
                                ))
                    elif op_text == "??":
                        left = node.child_by_field_name("left")
                        if left:
                            checked = self._leftmost_identifier(left)
                            if checked:
                                loc = self._loc(left, file_id)
                                guards.append(Guard(
                                    kind="nullish_coalescing", checked_name=checked, location=loc,
                                ))

            for child in node.children:
                visit(child)

        visit(tree.root_node)
        return guards

    # -- helpers ------------------------------------------------------------

    def _scope_at_byte(self, scope_tree: ScopeTree, byte_offset: int) -> int:
        """Find the innermost scope containing *byte_offset*."""
        best = 0
        best_span = float("inf")
        for scope in scope_tree.scopes:
            if scope.start_byte <= byte_offset <= scope.end_byte:
                span = scope.end_byte - scope.start_byte
                if span < best_span:
                    best = scope.id
                    best_span = span
        return best

    def _loc(self, ts_node: object, file_id: int) -> Location:
        """Create a Location from a tree-sitter node."""
        return Location(
            file_id=file_id,
            line=ts_node.start_point[0] + 1,
            col=ts_node.start_point[1],
            end_line=ts_node.end_point[0] + 1,
            end_col=ts_node.end_point[1],
        )

    def _leftmost_identifier(self, node: object) -> str | None:
        """Walk down the leftmost branch of an expression to find the root identifier."""
        cur = node
        while cur:
            if cur.type == "identifier":
                return cur.text.decode()
            if cur.type == "member_expression":
                cur = cur.child_by_field_name("object")
            elif cur.type == "call_expression":
                cur = cur.child_by_field_name("function")
            elif cur.type == "subscript_expression":
                cur = cur.child_by_field_name("object")
            else:
                break
        return None

    # -- regex fallback -----------------------------------------------------

    def _regex_fallback(self, content: str, file_id: int) -> ParseResult:
        """Fallback parser using regex when tree-sitter is unavailable."""
        scope_tree = ScopeTree()
        scope_tree.push_scope("global", 0, len(content.encode("utf-8")))

        result = ParseResult(tree=None, scope_tree=scope_tree, file_id=file_id)

        lines = content.split("\n")

        # Regex patterns for sources
        re_member = re.compile(
            r"\b(window|document|globalThis|self)\s*\.\s*([a-zA-Z_$][a-zA-Z0-9_$]*)"
        )
        re_bare_eval = re.compile(r"\beval\s*\(")
        re_innerhtml = re.compile(r"\.innerHTML\s*=")
        re_outerhtml = re.compile(r"\.outerHTML\s*=")
        re_doc_write = re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")
        re_src_assign = re.compile(r"\.\s*src\s*=")
        re_href_assign = re.compile(r"\.\s*href\s*=")
        re_insert_adj = re.compile(r"\.insertAdjacentHTML\s*\(")
        re_jquery_html = re.compile(r"\$\([^)]*\)\s*\.html\s*\(")

        for line_no, line in enumerate(lines, start=1):
            # Sources
            for m in re_member.finditer(line):
                obj, prop = m.group(1), m.group(2)
                if prop in _SAFE_PROPS:
                    continue
                loc = Location(file_id, line_no, m.start(2), line_no, m.end(2))
                result.sources.append(ClobberSource(
                    property_name=prop,
                    access_pattern=f"{obj}.{prop}",
                    location=loc,
                    priority=1,
                    chain_depth=1,
                    guarded=False,
                    scope_id=0,
                    access_chain=(obj, prop),
                ))

            # Sinks
            if re_bare_eval.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="eval", location=loc, severity="CRITICAL", scope_id=0,
                ))
            if re_innerhtml.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="innerHTML", location=loc, severity="CRITICAL", scope_id=0,
                ))
            if re_outerhtml.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="outerHTML", location=loc, severity="CRITICAL", scope_id=0,
                ))
            if re_doc_write.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="document.write", location=loc, severity="HIGH", scope_id=0,
                ))
            if re_src_assign.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="element.src", location=loc, severity="HIGH", scope_id=0,
                ))
            if re_href_assign.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="element.href", location=loc, severity="HIGH", scope_id=0,
                ))
            if re_insert_adj.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="insertAdjacentHTML", location=loc, severity="CRITICAL", scope_id=0,
                ))
            if re_jquery_html.search(line):
                loc = Location(file_id, line_no, 0)
                result.sinks.append(ClobberSink(
                    sink_type="jQuery.html", location=loc, severity="CRITICAL", scope_id=0,
                ))

        scope_tree.pop_scope()
        return result
