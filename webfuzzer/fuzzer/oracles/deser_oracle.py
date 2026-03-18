"""Java deserialization single-target security oracle.

Detects high-signal anomalies in one deserialization implementation's output:
  - Dangerous sink reached (cmd_exec, jndi_lookup, script_exec)
  - Filter bypassed (decision=ALLOWED when dangerous classes present)

Uses the `sinks_hit` array from DeserTarget to check ALL reached sinks,
not just the primary `sink_reached` field.
"""

from __future__ import annotations

import hashlib
import json

from ..protocols import ExecutionResult, Finding, Input, Severity


def _trigger_family(class_name: str) -> str:
    """Normalize entry class to a trigger family bucket for dedup.

    HashMap/LinkedHashMap/ConcurrentHashMap → 'hash_trigger' (hashCode)
    PriorityQueue → 'compare_trigger' (Comparator.compare)
    TreeMap/TreeSet/TreeBag → 'tree_trigger' (Comparable.compareTo)
    HashSet/LinkedHashSet → 'hashset_trigger' (hashCode via HashMap)
    Hashtable → 'hashtable_trigger'
    BadAttributeValueExpException → 'tostring_trigger'
    Others → short class name
    """
    short = class_name.rsplit(".", 1)[-1] if class_name else ""
    low = short.lower()
    if low in ("hashmap", "linkedhashmap", "concurrenthashmap"):
        return "hash_trigger"
    if low in ("priorityqueue",):
        return "compare_trigger"
    if low in ("treemap", "treeset", "treebag", "treebidimap"):
        return "tree_trigger"
    if low in ("hashset", "linkedhashset"):
        return "hashset_trigger"
    if low in ("hashtable",):
        return "hashtable_trigger"
    if low in ("badattributevalueexpexception",):
        return "tostring_trigger"
    return short or "_unknown_"


def _sink_family(all_sinks: set[str]) -> str:
    """Normalize sinks to a canonical key for dedup."""
    if not all_sinks:
        return "no_sink"
    # Sort by priority, join
    ordered = []
    for s in ("cmd_exec", "jndi_lookup", "script_exec", "class_load",
              "file_write", "network", "reflection", "thread_spawn"):
        if s in all_sinks:
            ordered.append(s)
    # Include any unknown sinks
    for s in sorted(all_sinks):
        if s not in ordered:
            ordered.append(s)
    return "+".join(ordered)


_SINK_CLASSES = {
    # ── CC / Generic gadget classes ──
    "InvokerTransformer": "invoker",
    "InstantiateTransformer": "instantiate",
    "TemplatesImpl": "templates",
    "ChainedTransformer": "chained",
    "ConstantTransformer": "constant",
    "TransformingComparator": "transforming_comparator",
    "EventHandler": "event_handler",
    "AnnotationInvocationHandler": "annotation_handler",
    "BeanComparator": "bean_comparator",
    "PropertyUtils": "property_utils",
    "MethodInvokeTypeProvider": "method_invoke",
    "MarshalledObject": "marshalled_obj",
    # ── Direct sinks (process/script/classloader) ──
    "ProcessBuilder": "process",
    "Runtime": "runtime",
    "URLClassLoader": "classloader",
    "ScriptEngine": "script",
    # ── JNDI sinks ──
    "JdbcRowSetImpl": "jdbc_jndi",
    "JtaTransactionManager": "jta_jndi",
    "InitialContext": "jndi_direct",
    "ForeignOpaqueReference": "foreign_opaque",
    "RMIConnector": "rmi_jndi",           # connect() → findRMIServerJNDI() → InitialContext.lookup()
    "JMXConnector": "jmx_jndi",           # interface for RMI/JNDI-based JMX connections
    "RegistryContext": "registry_jndi",    # com.sun.jndi.rmi.registry — direct RMI registry lookup
    "LdapCtx": "ldap_jndi",               # com.sun.jndi.ldap — LDAP JNDI context
    "DestinationImpl": "jms_jndi",         # weblogic.jms — getConnection() (transient but detectable)
    # ── WebLogic-specific bridge/comparator classes ──
    "SQLComparator": "sql_comparator",     # weblogic.jdbc.rowset — casts to Map, calls get(colName)
    "InvertibleComparator": "invertible_comparator",  # BEA Spring — wrapper, confirmed in WL9 chain
    "CompoundComparator": "compound_comparator",      # BEA Spring — wrapper, confirmed in WL11 chain
    "BeanMap": "bean_map",                 # commons-beanutils — Map proxy for getter invocation
    # ── Spring / BeanFactory sinks ──
    "AbstractBeanFactoryBasedTargetSource": "spring_bean_factory",  # getTarget() → getBean()
    "SimpleBeanTargetSource": "spring_bean_factory",
    "LazyInitTargetSource": "spring_bean_factory",
}

_GENERIC = frozenset({
    "String", "Object", "Integer", "Number", "Boolean", "Long", "Short",
    "Byte", "Float", "Double", "Character", "Class",
    "LinkedHashMap", "HashMap", "TreeMap",
})

_BRIDGE_FAMILIES = {
    "LazyMap": "lazy_map", "LazySortedMap": "lazy_map",
    "TransformedMap": "transformed_map", "TransformedSortedMap": "transformed_map",
    "PredicatedMap": "predicated_map", "PredicatedSortedMap": "predicated_map",
    "DefaultedMap": "defaulted_map",
    "TiedMapEntry": "tied_entry",
    "MultiValueMap": "multi_value",
    "MultiKeyMap": "multi_key",
    "ListOrderedMap": "list_ordered",
    "DualHashBidiMap": "bidi_map", "DualTreeBidiMap": "bidi_map",
    "DualLinkedHashBidiMap": "bidi_map",
    "PatriciaTrie": "trie", "UnmodifiableTrie": "trie",
    "UnmodifiableMap": "unmodifiable", "UnmodifiableSortedMap": "unmodifiable",
    "UnmodifiableOrderedMap": "unmodifiable",
    "FixedSizeMap": "fixed_size", "FixedSizeSortedMap": "fixed_size",
    "ReferenceMap": "reference_map", "ReferenceIdentityMap": "reference_map",
    "PassiveExpiringMap": "passive_expiring",
    "HashSet": "hashset_inner",
    "ComparableComparator": "comparator", "NullComparator": "comparator",
    "BooleanComparator": "comparator", "ReverseComparator": "comparator",
    # WebLogic / BEA Spring comparators
    "SQLComparator": "wl_comparator",
    "InvertibleComparator": "spring_comparator",
    "CompoundComparator": "spring_comparator",
    "StringKeyAnalyzer": "key_analyzer", "KeyAnalyzer": "key_analyzer",
    # Plain map implementations -> single bucket
    "CaseInsensitiveMap": "map_impl", "LRUMap": "map_impl",
    "HashedMap": "map_impl", "Flat3Map": "map_impl",
    "LinkedMap": "map_impl", "SingletonMap": "map_impl",
    "SequencedHashMap": "map_impl", "IdentityMap": "map_impl",
    "FastHashMap": "map_impl", "FastTreeMap": "map_impl",
    "MultiHashMap": "map_impl",
    # Filler transformers (ignored in bridge selection)
    "NOPTransformer": "_filler_", "CloneTransformer": "_filler_",
    "ExceptionTransformer": "_filler_", "StringValueTransformer": "_filler_",
    "PredicateTransformer": "_filler_", "ClosureTransformer": "_filler_",
    "SwitchTransformer": "_filler_", "FactoryTransformer": "_filler_",
}


def _sink_mechanism(chain_classes: list[str]) -> str:
    """Extract canonical sink mechanism from chain classes."""
    mechs = []
    for c in chain_classes:
        short = c.rsplit(".", 1)[-1] if c else ""
        if short in _SINK_CLASSES:
            mechs.append(_SINK_CLASSES[short])
    return "+".join(sorted(set(mechs))) if mechs else "_none_"


def _bridge_family(chain_classes: list[str]) -> str:
    """Primary bridge class family for chains without recognized sink mechanism."""
    for c in chain_classes[1:]:
        short = c.rsplit(".", 1)[-1] if c else ""
        if short.endswith(";") or short.startswith("[") or short in _GENERIC:
            continue
        fam = _BRIDGE_FAMILIES.get(short)
        if fam and fam != "_filler_":
            return fam
        if fam is None:
            return short  # unknown class = keep as-is for novel chain detection
    return "_direct_"


def _chain_hash(parsed: dict, all_sinks: set[str]) -> str:
    """Dedup: trigger_family + sink_mechanism [+ bridge_family] + sink_family + filter.

    Dedup granularity:
      - trigger_family: HashMap류/PriorityQueue류 등 readObject 진입점 그룹
      - sink_mechanism: 체인의 핵심 gadget 클래스 (InvokerTransformer 등)
      - bridge_family: mechanism이 없을 때만 bridge 클래스로 구분 (과도 collapse 방지)
      - sink_family: 도달한 sink 종류 조합
      - filter_decision: 필터 허용/거부

    Same trigger→mechanism→sink = same finding.
    When no recognized mechanism class, bridge_family prevents over-collapsing
    genuinely different chains (e.g. LazyMap vs TiedMapEntry paths).
    """
    chain_classes = parsed.get("chain_classes") or []
    entry_class = chain_classes[0] if chain_classes else ""

    mechanism = _sink_mechanism(chain_classes)
    bridge = _bridge_family(chain_classes) if mechanism == "_none_" else ""

    parts = [
        _trigger_family(entry_class),
        mechanism,
        bridge,
        _sink_family(all_sinks),
        str(parsed.get("filter_decision") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


def _parse_deser_output(stdout: bytes) -> dict | None:
    """Parse JSON output from a deserialization target."""
    if not stdout:
        return None
    try:
        data = json.loads(stdout.strip())
        if isinstance(data, dict) and (
            "deserialized" in data
            or "sink_reached" in data
            or "filter_decision" in data
        ):
            return data
    except (json.JSONDecodeError, UnicodeDecodeError):
        pass
    return None


# Sinks ordered by severity (highest first)
_CRITICAL_SINKS = frozenset({"cmd_exec", "jndi_lookup", "script_exec"})
_HIGH_SINKS = frozenset({"file_write", "file_read", "network"})
# class_load and reflection fire during normal JVM class resolution —
# only interesting when combined with an actionable sink.
_NOISE_ONLY_SINKS = frozenset({"class_load", "reflection", "thread_spawn"})

# Priority order for sink selection
_SINK_PRIORITY = [
    "cmd_exec", "jndi_lookup", "script_exec",
    "file_write", "network", "class_load",
    "thread_spawn", "reflection",
]


def _get_all_sinks(parsed: dict) -> set[str]:
    """Extract all sinks from parsed output, using sinks_hit array if available."""
    sinks = set()
    # Prefer sinks_hit array (full set)
    sinks_hit = parsed.get("sinks_hit")
    if isinstance(sinks_hit, list):
        sinks.update(s.lower() if isinstance(s, str) else s for s in sinks_hit)
    # Fallback: check boolean fields
    if parsed.get("process_spawned"):
        sinks.add("cmd_exec")
    if parsed.get("jndi_lookup"):
        sinks.add("jndi_lookup")
    if parsed.get("script_executed"):
        sinks.add("script_exec")
    if parsed.get("file_accessed"):
        sinks.add("file_write")
    if parsed.get("network_connected"):
        sinks.add("network")
    if parsed.get("class_loaded"):
        sinks.add("class_load")
    if parsed.get("thread_spawned"):
        sinks.add("thread_spawn")
    # Also include sink_reached
    sr = parsed.get("sink_reached")
    if sr:
        sinks.add(sr.lower() if isinstance(sr, str) else sr)
    return sinks


def _best_sink(sinks: set[str]) -> str | None:
    """Return the highest-priority sink from the set."""
    for s in _SINK_PRIORITY:
        if s in sinks:
            return s
    # Unknown sink category
    return next(iter(sinks)) if sinks else None


class DeserOracle:
    """Single-target Java deserialization security oracle."""

    name = "deser"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        if result.exit_code != 0:
            return None

        parsed = _parse_deser_output(result.stdout)
        if parsed is None:
            return None

        deserialized = parsed.get("deserialized")
        all_sinks = _get_all_sinks(parsed)

        # If a critical/high sink was reached during readObject() (even if
        # deserialization threw an exception afterwards), that's still a finding.
        # Many real gadget chains trigger sinks mid-readObject and then fail.
        critical_or_high = all_sinks & (_CRITICAL_SINKS | _HIGH_SINKS)
        if deserialized is not True and not critical_or_high:
            return None
        if not all_sinks:
            # No sinks reached — check filter bypass without sink
            filter_decision = str(parsed.get("filter_decision") or "").upper()
            if filter_decision == "ALLOWED":
                return Finding(
                    title="Deser: filter allowed deserialization (no sink)",
                    severity=Severity.MEDIUM,
                    input=inp,
                    result=result,
                    oracle_name=self.name,
                    metadata={
                        "category": "filter_allowed_no_sink",
                        "filter_decision": filter_decision,
                        "chain_classes": parsed.get("chain_classes"),
                        "diff_pattern_hash": _chain_hash(parsed, set()),
                    },
                )
            return None

        best = _best_sink(all_sinks)
        critical_sinks = all_sinks & _CRITICAL_SINKS
        high_sinks = all_sinks & _HIGH_SINKS

        common_meta = {
            "sink_reached": best,
            "all_sinks": sorted(all_sinks),
            "chain_classes": parsed.get("chain_classes"),
            "sink_depth": parsed.get("sink_depth"),
            "chain_class_hash": parsed.get("chain_class_hash"),
            "diff_pattern_hash": _chain_hash(parsed, all_sinks),
        }

        # Critical sink reached
        if critical_sinks:
            return Finding(
                title=f"Deser: critical sink {best!r} reached",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    **common_meta,
                    "category": "critical_sink",
                    "critical_sinks": sorted(critical_sinks),
                },
            )

        # High-severity sink reached
        if high_sinks:
            return Finding(
                title=f"Deser: high-risk sink {best!r} reached",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    **common_meta,
                    "category": "high_sink",
                    "high_sinks": sorted(high_sinks),
                },
            )

        # Noise-only sinks (class_load, reflection, thread_spawn) —
        # these fire during normal JVM class resolution and are not
        # actionable without a real sink.  Suppress entirely.
        if all_sinks <= _NOISE_ONLY_SINKS:
            return None

        # Filter bypass with actionable sink
        filter_decision = str(parsed.get("filter_decision") or "").upper()
        if filter_decision == "ALLOWED":
            return Finding(
                title=f"Deser: filter allowed deserialization reaching sink {best!r}",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name=self.name,
                metadata={
                    **common_meta,
                    "category": "filter_allowed_sink",
                    "filter_decision": filter_decision,
                },
            )

        # Other sinks — medium
        return Finding(
            title=f"Deser: sink {best!r} reached during deserialization",
            severity=Severity.MEDIUM,
            input=inp,
            result=result,
            oracle_name=self.name,
            metadata={
                **common_meta,
                "category": "other_sink",
            },
        )
