"""Java deserialization domain plugin for property-learning concolic layer.

Extracts ~50 structural properties from Java serialized binary streams
(0xACED0005...) and maps them to targeted mutations via the existing
DeserBinaryMutator strategies.

Properties capture:
- Stream structure: size, class count, string count, nesting depth
- Trigger class taxonomy: collection type (Map/Set/Queue/List)
- Gadget class taxonomy: transformer, comparator, invocation handler, etc.
- Sink indicators: dangerous method names, JNDI URLs, bean properties
- Chain topology: class diversity, package distribution, proxy presence

The PropertyGuidedCoordinator learns which properties correlate with
different server responses (OK/RST/TIMEOUT) and focuses mutation on
the highest-MI properties.
"""

from __future__ import annotations

import math
import random
import struct
from collections import Counter
from typing import Any

from ..property_vector import PropertyVector
from ..domain_plugin import DomainPlugin

# ── Stream constants (mirrored from deser_binary_mutator) ────────

STREAM_MAGIC = b"\xac\xed"
TC_CLASSDESC = 0x72
TC_STRING = 0x74
TC_OBJECT = 0x73
TC_NULL = 0x70
TC_ARRAY = 0x75
TC_REFERENCE = 0x71
TC_ENDBLOCKDATA = 0x78
TC_BLOCKDATA = 0x77
TC_PROXYCLASSDESC = 0x7D

# ── Property definitions ─────────────────────────────────────────

NUM_DESER_PROPERTIES = 50

DESER_PROPERTY_NAMES: tuple[str, ...] = (
    # ── Stream structure (0-7) ──
    "stream_size",               # 0  total bytes (normalized)
    "class_count",               # 1  number of TC_CLASSDESC entries
    "string_count",              # 2  number of TC_STRING entries
    "object_count",              # 3  TC_OBJECT count
    "array_count",               # 4  TC_ARRAY count
    "reference_count",           # 5  TC_REFERENCE count
    "proxy_count",               # 6  TC_PROXYCLASSDESC count
    "blockdata_count",           # 7  TC_BLOCKDATA count
    # ── Trigger class taxonomy (8-15) ──
    "has_hashmap",               # 8  HashMap / LinkedHashMap / ConcurrentHashMap
    "has_hashset",               # 9  HashSet / LinkedHashSet
    "has_priorityqueue",         # 10 PriorityQueue / ConcurrentLinkedQueue
    "has_treemap",               # 11 TreeMap / TreeSet (comparator trigger)
    "has_hashtable",             # 12 Hashtable
    "has_badattr",               # 13 BadAttributeValueExpException (toString trigger)
    "has_eventhandler",          # 14 EventHandler (InvocationHandler, JDK-only)
    "has_proxy",                 # 15 java.lang.reflect.Proxy
    # ── Gadget class taxonomy (16-27) ──
    "has_transformer",           # 16 CC InvokerTransformer / ChainedTransformer / ConstantTransformer
    "has_comparator",            # 17 BeanComparator / TransformingComparator / Hazelcast orderings
    "has_lazymap",               # 18 LazyMap / TiedMapEntry
    "has_templates_impl",        # 19 TemplatesImpl (bytecode sink)
    "has_jdbc_rowset",           # 20 JdbcRowSetImpl (JNDI sink)
    "has_eclipselink",           # 21 EclipseLink MethodAttributeAccessor
    "has_hibernate",             # 22 Hibernate GetterMethodImpl / ComponentType / TypedValue
    "has_rome",                  # 23 ROME ObjectBean / ToStringBean / EqualsBean
    "has_vaadin",                # 24 Vaadin NestedMethodProperty / MethodProperty
    "has_hazelcast",             # 25 Hazelcast repackaged Guava orderings
    "has_jeus_repackaged",       # 26 com.sun.org.apache.commons.* (JEUS-specific)
    "has_annotation_handler",    # 27 AnnotationInvocationHandler
    # ── Sink indicators (28-34) ──
    "has_dangerous_method",      # 28 exec/start/invoke/lookup/...
    "has_jndi_url",              # 29 ldap:// rmi:// dns:// in strings
    "has_bean_property",         # 30 outputProperties/databaseMetaData/...
    "dangerous_method_count",    # 31 count of dangerous method occurrences
    "jndi_url_count",            # 32 count of JNDI URLs
    "has_runtime_class",         # 33 java.lang.Runtime / ProcessBuilder
    "has_initial_context",       # 34 javax.naming.InitialContext
    # ── Chain topology (35-44) ──
    "unique_package_count",      # 35 number of distinct top-level packages
    "class_diversity",           # 36 Shannon entropy of class names
    "avg_classname_length",      # 37 average class name length (normalized)
    "max_nesting_depth",         # 38 estimated object nesting depth
    "has_cc3_classes",           # 39 org.apache.commons.collections.*
    "has_cc4_classes",           # 40 org.apache.commons.collections4.*
    "has_jdk_only",              # 41 all classes are java.* / javax.* / sun.* / com.sun.*
    "serialver_entropy",         # 42 entropy of serialVersionUID bytes
    "string_to_class_ratio",     # 43 TC_STRING count / TC_CLASSDESC count
    "total_string_bytes",        # 44 total bytes in all string values (normalized)
    # ── Advanced indicators (45-49) ──
    "has_method_invoke",         # 45 java.lang.reflect.Method references
    "has_constructor_ref",       # 46 java.lang.reflect.Constructor references
    "has_classloader_ref",       # 47 ClassLoader / URLClassLoader references
    "has_scripting",             # 48 ScriptEngine / javax.script references
    "has_rmi",                   # 49 RMI UnicastRef / RemoteObject references
)

assert len(DESER_PROPERTY_NAMES) == NUM_DESER_PROPERTIES

# ── Class taxonomy sets ──────────────────────────────────────────

_HASHMAP_CLASSES = frozenset({
    "java.util.HashMap", "java.util.LinkedHashMap",
    "java.util.concurrent.ConcurrentHashMap",
})
_HASHSET_CLASSES = frozenset({
    "java.util.HashSet", "java.util.LinkedHashSet",
})
_PQ_CLASSES = frozenset({
    "java.util.PriorityQueue", "java.util.concurrent.PriorityBlockingQueue",
    "java.util.concurrent.ConcurrentLinkedQueue",
})
_TREEMAP_CLASSES = frozenset({
    "java.util.TreeMap", "java.util.TreeSet",
})
_TRANSFORMER_CLASSES = frozenset({
    "org.apache.commons.collections.functors.InvokerTransformer",
    "org.apache.commons.collections4.functors.InvokerTransformer",
    "org.apache.commons.collections.functors.ChainedTransformer",
    "org.apache.commons.collections4.functors.ChainedTransformer",
    "org.apache.commons.collections.functors.ConstantTransformer",
    "org.apache.commons.collections4.functors.ConstantTransformer",
    "org.apache.commons.collections.functors.InstantiateTransformer",
    "org.apache.commons.collections4.functors.InstantiateTransformer",
})
_COMPARATOR_CLASSES = frozenset({
    "org.apache.commons.beanutils.BeanComparator",
    "com.sun.org.apache.commons.beanutils.BeanComparator",
    "org.apache.commons.collections4.comparators.TransformingComparator",
    "com.hazelcast.com.google.common.collect.ByFunctionOrdering",
    "com.hazelcast.com.google.common.collect.UsingToStringOrdering",
    "com.hazelcast.com.google.common.collect.NaturalOrdering",
    "com.hazelcast.com.google.common.collect.ComparatorOrdering",
    "jersey.repackaged.com.google.common.collect.ByFunctionOrdering",
    "org.eclipse.persistence.internal.helper.DescriptorCompare",
})
_LAZYMAP_CLASSES = frozenset({
    "org.apache.commons.collections.map.LazyMap",
    "org.apache.commons.collections4.map.LazyMap",
    "org.apache.commons.collections.keyvalue.TiedMapEntry",
    "org.apache.commons.collections4.keyvalue.TiedMapEntry",
})
_TEMPLATES_CLASSES = frozenset({
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "org.apache.xalan.xsltc.trax.TemplatesImpl",
})
_JDBC_CLASSES = frozenset({
    "com.sun.rowset.JdbcRowSetImpl",
})
_ECLIPSELINK_CLASSES = frozenset({
    "org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor",
    "org.eclipse.persistence.internal.descriptors.InstanceVariableAttributeAccessor",
    "org.eclipse.persistence.mappings.DirectToFieldMapping",
    "org.eclipse.persistence.mappings.TransformationMapping",
})
_HIBERNATE_CLASSES = frozenset({
    "org.hibernate.property.access.spi.GetterMethodImpl",
    "org.hibernate.type.ComponentType",
    "org.hibernate.engine.spi.TypedValue",
    "org.hibernate.tuple.component.AbstractComponentTuplizer",
})
_ROME_CLASSES = frozenset({
    "com.sun.syndication.feed.impl.ObjectBean",
    "com.sun.syndication.feed.impl.ToStringBean",
    "com.sun.syndication.feed.impl.EqualsBean",
})
_VAADIN_CLASSES = frozenset({
    "com.vaadin.data.util.NestedMethodProperty",
    "com.vaadin.data.util.MethodProperty",
})
_HAZELCAST_CLASSES = frozenset({
    "com.hazelcast.com.google.common.collect.ByFunctionOrdering",
    "com.hazelcast.com.google.common.collect.UsingToStringOrdering",
    "com.hazelcast.com.google.common.collect.NaturalOrdering",
    "com.hazelcast.com.google.common.collect.ReverseOrdering",
    "com.hazelcast.com.google.common.collect.NullsFirstOrdering",
    "com.hazelcast.com.google.common.collect.CompoundOrdering",
    "com.hazelcast.com.google.common.collect.ComparatorOrdering",
    "com.hazelcast.function.ComparatorEx",
})
_RMI_CLASSES = frozenset({
    "java.rmi.server.RemoteObjectInvocationHandler",
    "java.rmi.server.RemoteObject",
    "java.rmi.server.UnicastRef",
    "sun.rmi.server.UnicastRef",
})

_DANGEROUS_METHODS = frozenset({
    "exec", "start", "invoke", "lookup", "doLookup", "eval",
    "getRuntime", "getMethod", "getDeclaredMethod", "forName",
    "newInstance", "loadClass", "defineClass",
    "getOutputProperties", "newTransformer", "getDatabaseMetaData",
    "execute", "connect",
})
_BEAN_PROPERTIES = frozenset({
    "outputProperties", "databaseMetaData", "connection",
    "class", "templateContent", "stylesheetDOM",
})
_JDK_PREFIXES = ("java.", "javax.", "sun.", "com.sun.")


# ── Stream parsing helpers ───────────────────────────────────────

def _find_classnames(data: bytes) -> list[str]:
    """Extract class names from TC_CLASSDESC entries."""
    results: list[str] = []
    i = 4  # skip magic + version
    while i < len(data) - 3:
        if data[i] == TC_CLASSDESC:
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 256 and i + 3 + str_len <= len(data):
                try:
                    s = data[i + 3:i + 3 + str_len].decode("utf-8")
                    if "." in s and len(s) > 4:
                        results.append(s)
                except UnicodeDecodeError:
                    pass
        i += 1
    return results


def _find_strings(data: bytes) -> list[str]:
    """Extract TC_STRING values."""
    results: list[str] = []
    i = 4
    while i < len(data) - 3:
        if data[i] == TC_STRING:
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 1024 and i + 3 + str_len <= len(data):
                try:
                    s = data[i + 3:i + 3 + str_len].decode("utf-8")
                    if s.isprintable():
                        results.append(s)
                except UnicodeDecodeError:
                    pass
        i += 1
    return results


def _count_tc(data: bytes, tc_byte: int) -> int:
    """Count occurrences of a TC marker byte."""
    count = 0
    for i in range(4, len(data)):
        if data[i] == tc_byte:
            count += 1
    return count


def _shannon_entropy(values: list[str]) -> float:
    """Shannon entropy of a string list, normalized to [0, 1]."""
    if not values:
        return 0.0
    counts = Counter(values)
    total = len(values)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    max_entropy = math.log2(max(len(counts), 1)) if len(counts) > 1 else 1.0
    return min(entropy / max(max_entropy, 1e-9), 1.0)


def _estimate_nesting(data: bytes) -> int:
    """Estimate object nesting depth from TC_OBJECT / TC_ENDBLOCKDATA pairs."""
    depth = 0
    max_depth = 0
    for i in range(4, len(data)):
        if data[i] == TC_OBJECT:
            depth += 1
            max_depth = max(max_depth, depth)
        elif data[i] == TC_ENDBLOCKDATA:
            depth = max(depth - 1, 0)
    return max_depth


def _serialver_entropy(data: bytes) -> float:
    """Entropy of serialVersionUID bytes (after each TC_CLASSDESC + classname)."""
    uid_bytes = bytearray()
    i = 4
    while i < len(data) - 12:
        if data[i] == TC_CLASSDESC:
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 256 and i + 3 + str_len + 8 <= len(data):
                uid_bytes.extend(data[i + 3 + str_len:i + 3 + str_len + 8])
            i += max(3 + str_len, 1)
            continue
        i += 1
    if not uid_bytes:
        return 0.0
    counts = Counter(uid_bytes)
    total = len(uid_bytes)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        if p > 0:
            entropy -= p * math.log2(p)
    return min(entropy / 8.0, 1.0)  # max entropy for bytes = 8 bits


# ── Main extraction ──────────────────────────────────────────────

def _extract_properties(data: bytes) -> tuple[float, ...]:
    """Extract NUM_DESER_PROPERTIES float values from serialized stream."""
    v = [0.0] * NUM_DESER_PROPERTIES

    if len(data) < 4 or data[:2] != STREAM_MAGIC:
        return tuple(v)

    classnames = _find_classnames(data)
    strings = _find_strings(data)
    classname_set = frozenset(classnames)
    all_text = classnames + strings

    # ── Stream structure (0-7) ──
    v[0] = min(len(data) / 10000.0, 1.0)
    v[1] = min(len(classnames) / 20.0, 1.0)
    v[2] = min(len(strings) / 30.0, 1.0)
    v[3] = min(_count_tc(data, TC_OBJECT) / 15.0, 1.0)
    v[4] = min(_count_tc(data, TC_ARRAY) / 10.0, 1.0)
    v[5] = min(_count_tc(data, TC_REFERENCE) / 20.0, 1.0)
    v[6] = min(_count_tc(data, TC_PROXYCLASSDESC) / 5.0, 1.0)
    v[7] = min(_count_tc(data, TC_BLOCKDATA) / 10.0, 1.0)

    # ── Trigger class taxonomy (8-15) ──
    v[8] = 1.0 if classname_set & _HASHMAP_CLASSES else 0.0
    v[9] = 1.0 if classname_set & _HASHSET_CLASSES else 0.0
    v[10] = 1.0 if classname_set & _PQ_CLASSES else 0.0
    v[11] = 1.0 if classname_set & _TREEMAP_CLASSES else 0.0
    v[12] = 1.0 if any("Hashtable" in c for c in classnames) else 0.0
    v[13] = 1.0 if any("BadAttributeValueExpException" in c for c in classnames) else 0.0
    v[14] = 1.0 if any("EventHandler" in c for c in classnames) else 0.0
    v[15] = 1.0 if any("java.lang.reflect.Proxy" in c for c in classnames) else 0.0

    # ── Gadget class taxonomy (16-27) ──
    v[16] = 1.0 if classname_set & _TRANSFORMER_CLASSES else 0.0
    v[17] = 1.0 if classname_set & _COMPARATOR_CLASSES else 0.0
    v[18] = 1.0 if classname_set & _LAZYMAP_CLASSES else 0.0
    v[19] = 1.0 if classname_set & _TEMPLATES_CLASSES else 0.0
    v[20] = 1.0 if classname_set & _JDBC_CLASSES else 0.0
    v[21] = 1.0 if classname_set & _ECLIPSELINK_CLASSES else 0.0
    v[22] = 1.0 if classname_set & _HIBERNATE_CLASSES else 0.0
    v[23] = 1.0 if classname_set & _ROME_CLASSES else 0.0
    v[24] = 1.0 if classname_set & _VAADIN_CLASSES else 0.0
    v[25] = 1.0 if classname_set & _HAZELCAST_CLASSES else 0.0
    v[26] = 1.0 if any("com.sun.org.apache.commons" in c for c in classnames) else 0.0
    v[27] = 1.0 if any("AnnotationInvocationHandler" in c for c in classnames) else 0.0

    # ── Sink indicators (28-34) ──
    dangerous_count = 0
    jndi_count = 0
    for s in all_text:
        if s in _DANGEROUS_METHODS:
            dangerous_count += 1
        if s in _BEAN_PROPERTIES:
            dangerous_count += 1
        if any(proto in s for proto in ("ldap://", "rmi://", "dns://", "iiop://")):
            jndi_count += 1
    v[28] = 1.0 if dangerous_count > 0 else 0.0
    v[29] = 1.0 if jndi_count > 0 else 0.0
    v[30] = 1.0 if any(s in _BEAN_PROPERTIES for s in all_text) else 0.0
    v[31] = min(dangerous_count / 10.0, 1.0)
    v[32] = min(jndi_count / 5.0, 1.0)
    v[33] = 1.0 if any(c in ("java.lang.Runtime", "java.lang.ProcessBuilder") for c in classnames) else 0.0
    v[34] = 1.0 if any("InitialContext" in c for c in classnames) else 0.0

    # ── Chain topology (35-44) ──
    if classnames:
        packages = [c.rsplit(".", 1)[0].split(".")[0] if "." in c else c for c in classnames]
        top_packages = set()
        for c in classnames:
            parts = c.split(".")
            if len(parts) >= 2:
                top_packages.add(parts[0] + "." + parts[1])
        v[35] = min(len(top_packages) / 10.0, 1.0)
        v[36] = _shannon_entropy(classnames)
        v[37] = min(sum(len(c) for c in classnames) / (len(classnames) * 60.0), 1.0)
    v[38] = min(_estimate_nesting(data) / 10.0, 1.0)
    v[39] = 1.0 if any(c.startswith("org.apache.commons.collections.") and
                        not c.startswith("org.apache.commons.collections4.") for c in classnames) else 0.0
    v[40] = 1.0 if any(c.startswith("org.apache.commons.collections4.") for c in classnames) else 0.0
    v[41] = 1.0 if classnames and all(
        any(c.startswith(p) for p in _JDK_PREFIXES) for c in classnames
    ) else 0.0
    v[42] = _serialver_entropy(data)
    v[43] = min(len(strings) / max(len(classnames), 1), 1.0)
    total_str_bytes = sum(len(s.encode("utf-8", errors="replace")) for s in strings)
    v[44] = min(total_str_bytes / 2000.0, 1.0)

    # ── Advanced indicators (45-49) ──
    all_text_joined = " ".join(all_text)
    v[45] = 1.0 if "java.lang.reflect.Method" in all_text_joined else 0.0
    v[46] = 1.0 if "java.lang.reflect.Constructor" in all_text_joined else 0.0
    v[47] = 1.0 if any("ClassLoader" in s for s in all_text) else 0.0
    v[48] = 1.0 if any("javax.script" in s or "ScriptEngine" in s for s in all_text) else 0.0
    v[49] = 1.0 if classname_set & _RMI_CLASSES else 0.0

    return tuple(v)


# ── Perturbation functions ───────────────────────────────────────
# Each takes (data, rng) and returns list[bytes].
# These reuse parsing utilities from deser_binary_mutator.

def _import_mutator_utils():
    """Lazy import of deser_binary_mutator utilities."""
    from ...mutators.deser_binary_mutator import (
        _find_classnames as find_cn_tuples,
        _find_all_strings as find_str_tuples,
        _replace_string_at,
        _find_serialver_offsets,
        ROOT_COLLECTION_SWAPS,
        GADGET_CLASS_SWAPS,
        METHOD_NAMES,
        JNDI_URLS,
        BEAN_PROPERTIES,
    )
    return (find_cn_tuples, find_str_tuples, _replace_string_at,
            _find_serialver_offsets, ROOT_COLLECTION_SWAPS,
            GADGET_CLASS_SWAPS, METHOD_NAMES, JNDI_URLS, BEAN_PROPERTIES)


def _perturb_root_swap(data: bytes, rng: random.Random) -> list[bytes]:
    """Swap root collection class (HashMap→ConcurrentHashMap etc.)."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, ROOT_SWAPS, _, _, _, _ = utils
    results: list[bytes] = []
    for offset, slen, name in find_cn(data):
        if name in ROOT_SWAPS:
            for alt in ROOT_SWAPS[name]:
                results.append(replace_at(data, offset, slen, alt))
    return results


def _perturb_gadget_swap(data: bytes, rng: random.Random) -> list[bytes]:
    """Swap gadget class to same-interface alternative."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, GADGET_SWAPS, _, _, _ = utils
    results: list[bytes] = []
    for offset, slen, name in find_cn(data):
        if name in GADGET_SWAPS:
            alt = rng.choice(GADGET_SWAPS[name])
            results.append(replace_at(data, offset, slen, alt))
    return results[:3]  # cap to avoid explosion


def _perturb_method_inject(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject dangerous method name into string fields."""
    utils = _import_mutator_utils()
    _, find_str, replace_at, _, _, _, METHODS, _, _ = utils
    results: list[bytes] = []
    strs = find_str(data)
    if not strs:
        return results
    offset, slen, _ = rng.choice(strs)
    method = rng.choice(METHODS)
    results.append(replace_at(data, offset, slen, method))
    return results


def _perturb_jndi_inject(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject JNDI URL into string fields."""
    utils = _import_mutator_utils()
    _, find_str, replace_at, _, _, _, _, JNDI, _ = utils
    results: list[bytes] = []
    strs = find_str(data)
    if not strs:
        return results
    offset, slen, _ = rng.choice(strs)
    url = rng.choice(JNDI)
    results.append(replace_at(data, offset, slen, url))
    return results


def _perturb_bean_property(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject bean property name into string fields."""
    utils = _import_mutator_utils()
    _, find_str, replace_at, _, _, _, _, _, BEANS = utils
    results: list[bytes] = []
    strs = find_str(data)
    if not strs:
        return results
    offset, slen, _ = rng.choice(strs)
    prop = rng.choice(BEANS)
    results.append(replace_at(data, offset, slen, prop))
    return results


def _perturb_serialver(data: bytes, rng: random.Random) -> list[bytes]:
    """Flip bits in serialVersionUID to bypass version checks."""
    utils = _import_mutator_utils()
    _, _, _, find_sv, _, _, _, _, _ = utils
    offsets = find_sv(data)
    if not offsets:
        return []
    off = rng.choice(offsets)
    bit_pos = rng.randint(0, 63)
    byte_idx = off + (bit_pos // 8)
    if byte_idx >= len(data):
        return []
    mutated = bytearray(data)
    mutated[byte_idx] ^= (1 << (bit_pos % 8))
    return [bytes(mutated)]


def _perturb_add_transformer(data: bytes, rng: random.Random) -> list[bytes]:
    """Swap non-transformer class to a transformer class (inject new gadget link)."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    transformers = [
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "org.apache.commons.collections.functors.ChainedTransformer",
        "org.apache.commons.collections4.functors.ConstantTransformer",
    ]
    entries = find_cn(data)
    # Find a non-transformer class to replace
    candidates = [(o, l, n) for o, l, n in entries
                  if n not in _TRANSFORMER_CLASSES and n not in _HASHMAP_CLASSES
                  and n not in _HASHSET_CLASSES and n not in _PQ_CLASSES
                  and n not in _TREEMAP_CLASSES]
    if not candidates:
        return []
    offset, slen, _ = rng.choice(candidates)
    return [replace_at(data, offset, slen, rng.choice(transformers))]


def _perturb_add_comparator(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject a comparator class."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    comparators = [
        "org.apache.commons.beanutils.BeanComparator",
        "com.sun.org.apache.commons.beanutils.BeanComparator",
        "com.hazelcast.com.google.common.collect.ByFunctionOrdering",
        "com.hazelcast.com.google.common.collect.UsingToStringOrdering",
        "org.apache.commons.collections4.comparators.TransformingComparator",
    ]
    entries = find_cn(data)
    candidates = [(o, l, n) for o, l, n in entries
                  if n not in _COMPARATOR_CLASSES and n not in _HASHMAP_CLASSES]
    if not candidates:
        return []
    offset, slen, _ = rng.choice(candidates)
    return [replace_at(data, offset, slen, rng.choice(comparators))]


def _perturb_add_sink(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject a sink class (TemplatesImpl, JdbcRowSetImpl, etc.)."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    sinks = [
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "com.sun.rowset.JdbcRowSetImpl",
        "javax.naming.InitialContext",
    ]
    entries = find_cn(data)
    if not entries:
        return []
    offset, slen, _ = rng.choice(entries)
    return [replace_at(data, offset, slen, rng.choice(sinks))]


def _perturb_eventhandler(data: bytes, rng: random.Random) -> list[bytes]:
    """Swap InvocationHandler to EventHandler (JDK-only chain)."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    results: list[bytes] = []
    for offset, slen, name in find_cn(data):
        if "InvocationHandler" in name or "AnnotationInvocationHandler" in name:
            results.append(replace_at(data, offset, slen, "java.beans.EventHandler"))
    return results


def _perturb_eclipselink_chain(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject EclipseLink MethodAttributeAccessor chain."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    entries = find_cn(data)
    candidates = [(o, l, n) for o, l, n in entries
                  if n not in _ECLIPSELINK_CLASSES and n not in _HASHMAP_CLASSES]
    if not candidates:
        return []
    offset, slen, _ = rng.choice(candidates)
    return [replace_at(data, offset, slen,
            "org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor")]


def _perturb_hibernate_chain(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject Hibernate gadget class."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    hibernate = [
        "org.hibernate.property.access.spi.GetterMethodImpl",
        "org.hibernate.type.ComponentType",
        "org.hibernate.engine.spi.TypedValue",
    ]
    entries = find_cn(data)
    candidates = [(o, l, n) for o, l, n in entries
                  if n not in _HIBERNATE_CLASSES and n not in _HASHMAP_CLASSES]
    if not candidates:
        return []
    offset, slen, _ = rng.choice(candidates)
    return [replace_at(data, offset, slen, rng.choice(hibernate))]


def _perturb_rome_chain(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject ROME ObjectBean/ToStringBean chain."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    rome = [
        "com.sun.syndication.feed.impl.ObjectBean",
        "com.sun.syndication.feed.impl.ToStringBean",
        "com.sun.syndication.feed.impl.EqualsBean",
    ]
    entries = find_cn(data)
    candidates = [(o, l, n) for o, l, n in entries
                  if n not in _ROME_CLASSES and n not in _HASHMAP_CLASSES]
    if not candidates:
        return []
    offset, slen, _ = rng.choice(candidates)
    return [replace_at(data, offset, slen, rng.choice(rome))]


def _perturb_jdk_only(data: bytes, rng: random.Random) -> list[bytes]:
    """Replace all non-JDK classes with JDK equivalents (pure JDK chain attempt)."""
    utils = _import_mutator_utils()
    find_cn, _, replace_at, _, _, _, _, _, _ = utils
    jdk_alts = [
        "java.beans.EventHandler",
        "javax.management.BadAttributeValueExpException",
        "java.lang.reflect.Proxy",
        "java.util.concurrent.ConcurrentHashMap",
    ]
    entries = find_cn(data)
    result = data
    changed = False
    for offset, slen, name in entries:
        if not any(name.startswith(p) for p in _JDK_PREFIXES):
            alt = rng.choice(jdk_alts)
            result = replace_at(result, offset, slen, alt)
            changed = True
            break  # one swap per call to keep stream valid
    return [result] if changed else []


# ── Perturbation registry ────────────────────────────────────────
# Maps property indices to perturbation functions.
# When MI is high for property X, the coordinator calls perturb(data, X, rng)
# which dispatches to the registered functions.

_DESER_PERTURBATIONS: dict[int, list] = {
    # Stream structure
    0: [_perturb_root_swap],                   # stream_size → try different root
    1: [_perturb_gadget_swap],                 # class_count → swap gadget
    2: [_perturb_method_inject, _perturb_jndi_inject],  # string_count → inject strings
    # Trigger classes
    8: [_perturb_root_swap],                   # has_hashmap → swap trigger
    9: [_perturb_root_swap],                   # has_hashset → swap trigger
    10: [_perturb_root_swap],                  # has_priorityqueue → swap trigger
    11: [_perturb_root_swap],                  # has_treemap → swap trigger
    13: [_perturb_gadget_swap],                # has_badattr → swap gadget
    14: [_perturb_eventhandler],               # has_eventhandler → inject EH
    15: [_perturb_eventhandler],               # has_proxy → inject EH
    # Gadget classes
    16: [_perturb_add_transformer],            # has_transformer → inject
    17: [_perturb_add_comparator],             # has_comparator → inject
    18: [_perturb_gadget_swap],                # has_lazymap → swap
    19: [_perturb_add_sink],                   # has_templates_impl → inject sink
    20: [_perturb_add_sink, _perturb_jndi_inject],  # has_jdbc_rowset → JNDI
    21: [_perturb_eclipselink_chain],          # has_eclipselink
    22: [_perturb_hibernate_chain],            # has_hibernate
    23: [_perturb_rome_chain],                 # has_rome
    25: [_perturb_gadget_swap],                # has_hazelcast → swap ordering
    26: [_perturb_gadget_swap],                # has_jeus_repackaged
    27: [_perturb_eventhandler],               # has_annotation_handler → swap to EH
    # Sink indicators
    28: [_perturb_method_inject],              # has_dangerous_method → inject more
    29: [_perturb_jndi_inject],                # has_jndi_url → inject more URLs
    30: [_perturb_bean_property],              # has_bean_property → inject
    31: [_perturb_method_inject],              # dangerous_method_count
    32: [_perturb_jndi_inject],                # jndi_url_count
    33: [_perturb_method_inject],              # has_runtime_class
    34: [_perturb_jndi_inject],                # has_initial_context
    # Chain topology
    35: [_perturb_gadget_swap],                # unique_package_count → diversify
    36: [_perturb_gadget_swap, _perturb_root_swap],  # class_diversity
    39: [_perturb_gadget_swap],                # has_cc3_classes → swap to cc4
    40: [_perturb_gadget_swap],                # has_cc4_classes → swap to cc3
    41: [_perturb_jdk_only],                   # has_jdk_only → force JDK chain
    42: [_perturb_serialver],                  # serialver_entropy
    # Advanced
    45: [_perturb_method_inject],              # has_method_invoke
    49: [_perturb_gadget_swap],                # has_rmi → swap RMI gadgets
}


# ── Plugin class ─────────────────────────────────────────────────

class DeserPlugin(DomainPlugin):
    """Java deserialization property extraction and perturbation plugin.

    Extracts 50 structural properties from Java serialized binary streams
    and maps them to targeted mutation strategies.
    """

    def extract(self, data: bytes) -> PropertyVector:
        return PropertyVector(_extract_properties(data))

    @property
    def property_names(self) -> tuple[str, ...]:
        return DESER_PROPERTY_NAMES

    @property
    def num_properties(self) -> int:
        return NUM_DESER_PROPERTIES

    def perturb(self, data: bytes, prop_idx: int, rng: random.Random) -> list[bytes]:
        fn_list = _DESER_PERTURBATIONS.get(prop_idx, [])
        results: list[bytes] = []
        for fn in fn_list:
            try:
                mutated = fn(data, rng)
                results.extend(m for m in mutated if m and m != data)
            except Exception:
                pass
        return results

    @property
    def excluded_output_fields(self) -> frozenset[str]:
        return frozenset({
            "duration_ms",
            "response_hex",  # raw hex is too noisy for divergence
            "protocol",      # always differs between CWDP/JMXMP targets
            "handshake_len", # JMXMP-specific field
        })

    @property
    def mutation_name_to_prop_index(self) -> dict[str, int]:
        return {
            "classname_swap": 1,
            "root_swap": 8,
            "method_inject": 28,
            "jndi_inject": 29,
            "property_inject": 30,
            "serialver_mutate": 42,
            "cross_splice": 36,
            "string_havoc": 2,
        }
