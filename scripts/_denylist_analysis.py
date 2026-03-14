#!/usr/bin/env python3
"""Cross-reference fuzzer findings with WebLogic ClassFilter denylist and known CVEs."""
import sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# WebLogic ClassFilter denylist — EXTRACTED FROM ACTUAL BYTECODE
# Source: javap decompilation of WebLogicFilterConfig.class from:
#   - 12.2.1.3: wlthint3client.jar (7 entries total)
#   - 14.1.1.0: com.bea.core.utils.jar (25 entries total)
# Combined with public CVE research (Y4er, Badcode, A-Team Oracle)

# === VERIFIED: Extracted from WebLogic 14.1.1.0 WebLogicFilterConfig bytecode ===

# DEFAULT_BLACKLIST_PACKAGES (15 entries, package-level wildcards)
VERIFIED_BLACKLIST_PACKAGES = [
    "org.apache.commons.collections.functors",
    "com.sun.org.apache.xalan.internal.xsltc.trax",
    "javassist",
    "java.rmi.activation",
    "sun.rmi.server",
    "org.jboss.interceptor.builder",
    "org.jboss.interceptor.reader",
    "org.jboss.interceptor.proxy",
    "org.jboss.interceptor.spi.metadata",
    "org.jboss.interceptor.spi.model",
    # BEA Spring: ONLY specific subpackages, NOT wildcard on whole namespace!
    "com.bea.core.repackaged.springframework.aop.aspectj",
    "com.bea.core.repackaged.springframework.aop.aspectj.annotation",
    "com.bea.core.repackaged.springframework.aop.aspectj.autoproxy",
    "com.bea.core.repackaged.springframework.beans.factory.support",
    "org.python.core",
]

# DEFAULT_BLACKLIST_CLASSES (10 entries, exact class matches)
VERIFIED_BLACKLIST_CLASSES = [
    "org.codehaus.groovy.runtime.ConvertedClosure",
    "org.codehaus.groovy.runtime.ConversionHandler",
    "org.codehaus.groovy.runtime.MethodClosure",
    "org.springframework.transaction.support.AbstractPlatformTransactionManager",
    "java.rmi.server.UnicastRemoteObject",
    "java.rmi.server.RemoteObjectInvocationHandler",
    "com.bea.core.repackaged.springframework.transaction.support.AbstractPlatformTransactionManager",
    "java.rmi.server.RemoteObject",
    "com.tangosol.coherence.rest.util.extractor.MvelExtractor",
    "java.lang.Runtime",
]

# DEFAULT_WLS_ONLY_BLACKLIST_CLASSES (1 entry)
VERIFIED_WLS_ONLY_CLASSES = [
    "com.tangosol.util.extractor.ReflectionExtractor",
]

# Combined for lookup
KNOWN_DENYLIST = set(VERIFIED_BLACKLIST_CLASSES + VERIFIED_WLS_ONLY_CLASSES)

# Additional classes blocked by runtime patches (not in default config, but added via PSU)
# These are from CVE writeups and public research
KNOWN_DENYLIST.update({
    # Post CVE-2016-0638
    "weblogic.jms.common.StreamMessageImpl",
    # Post CVE-2016-3510
    "weblogic.corba.utils.MarshalledObject",
    # Post CVE-2017-3248
    "java.rmi.registry.Registry",
    # Post CVE-2018-2628
    "sun.rmi.server.UnicastRef",
    "sun.rmi.transport.DGCImpl_Stub",
    # Post CVE-2018-2893
    "sun.rmi.server.UnicastRef2",
    # Post CVE-2020-2555
    "com.tangosol.util.filter.LimitFilter",
    "com.tangosol.util.extractor.ChainedExtractor",
    # Post CVE-2020-2883
    "com.tangosol.util.extractor.UniversalExtractor",
    "com.tangosol.util.extractor.MvelExtractor",
    "com.tangosol.internal.util.SimpleBinaryEntry",
    "com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager",
    # Post CVE-2020-14756
    "oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor",
    # Post CVE-2021-2394
    "oracle.eclipselink.coherence.integrated.internal.querying.FilterExtractor",
    "com.tangosol.util.extractor.AbstractExtractor",
    "com.tangosol.util.filter.ExtractorFilter",
    # Post CVE-2023-21839
    "weblogic.jndi.internal.ForeignOpaqueReference",
})

# VERIFIED wildcard patterns (from bytecode extraction)
WILDCARD_PATTERNS = [p + "." for p in VERIFIED_BLACKLIST_PACKAGES]

# RESOLVED: BEA Spring is NOT a full wildcard.
# Only specific subpackages are blocked:
#   - aop.aspectj (+ annotation, autoproxy)
#   - beans.factory.support
#   - transaction.support.AbstractPlatformTransactionManager (single class)
# The following are CONFIRMED NOT BLOCKED:
#   - com.bea.core.repackaged.springframework.util.comparator.*
#   - com.bea.core.repackaged.springframework.aop.target.*
#   - com.bea.core.repackaged.springframework.aop.interceptor.*
UNCERTAIN_WILDCARDS = []  # All resolved!

FUZZER_CHAINS = [
    {
        "id": "#1", "name": "BufferingConfig$Queue -> JNDI",
        "classes": ["weblogic.wsee.jaxws.buffer.BufferingConfig$Queue"],
        "sink": "InitialContext.lookup",
        "cve": "None known",
        "notes": "WSEE buffer subsystem - never appeared in public WebLogic CVE research"
    },
    {
        "id": "#2", "name": "SQLComparator -> JdbcRowSetImpl -> SSRF/JNDI",
        "classes": ["weblogic.jdbc.rowset.SQLComparator", "com.sun.rowset.JdbcRowSetImpl"],
        "sink": "JdbcRowSetImpl.getDatabaseMetaData",
        "cve": "None known",
        "notes": "WL-native Comparator as PriorityQueue entry. JdbcRowSetImpl blocked in JDK 8u191+, but SQLComparator itself is novel"
    },
    {
        "id": "#3", "name": "ExposeInvocationInterceptor -> ProxyDesc.readResolve",
        "classes": ["com.bea.core.repackaged.springframework.aop.interceptor.ExposeInvocationInterceptor"],
        "sink": "ProxyDesc.readResolve",
        "cve": "None known",
        "notes": "BEA Spring AOP class - uncertain if wildcard covers it"
    },
    {
        "id": "#4", "name": "WebLogicAttribute$NullObject -> Thread.start",
        "classes": ["weblogic.management.internal.WebLogicAttribute$NullObject"],
        "sink": "Thread.start",
        "cve": "None known",
        "notes": "Management-internal class, never in public research. Thread.start is unusual sink"
    },
    {
        "id": "#5", "name": "EmptyTargetSource -> ProxyDesc.readResolve",
        "classes": ["com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource"],
        "sink": "ProxyDesc.readResolve",
        "cve": "None known",
        "notes": "BEA Spring AOP - uncertain wildcard"
    },
    {
        "id": "#8", "name": "SQLComparator -> CC1 chain -> JNDI",
        "classes": [
            "weblogic.jdbc.rowset.SQLComparator",
            "org.apache.commons.collections.keyvalue.TiedMapEntry",
            "org.apache.commons.collections.map.LazyMap",
            "org.apache.commons.collections.functors.ChainedTransformer",
            "org.apache.commons.collections.functors.InvokerTransformer",
        ],
        "sink": "InitialContext.lookup",
        "cve": "None known (novel entry point, but CC functors are blocked)",
        "notes": "SQLComparator is novel entry but chain uses blocked CC functors"
    },
    {
        "id": "#9", "name": "CompoundComparator -> TransformingComparator -> InvokerTransformer -> RCE",
        "classes": [
            "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
            "org.apache.commons.collections4.comparators.TransformingComparator",
            "org.apache.commons.collections4.functors.InvokerTransformer",
        ],
        "sink": "Runtime.exec",
        "cve": "CVE-2020-2883",
        "notes": "Known chain - CompoundComparator documented by Y4er"
    },
    {
        "id": "#10", "name": "WeakFastHashMap -> CC -> RCE",
        "classes": [
            "org.apache.commons.beanutils.WeakFastHashMap",
            "org.apache.commons.collections.functors.InvokerTransformer",
        ],
        "sink": "Runtime.exec",
        "cve": "None known",
        "notes": "Novel entry point via commons-beanutils WeakFastHashMap, but CC functors blocked"
    },
    {
        "id": "#14", "name": "BasicDynaBean+BooleanComparator+ProxyDesc+EmptyTargetSource (pure WL 5-class)",
        "classes": [
            "org.apache.commons.beanutils.BasicDynaBean",
            "com.bea.core.repackaged.springframework.util.comparator.BooleanComparator",
            "weblogic.iiop.ProxyDesc",
            "com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource",
        ],
        "sink": "FileOutputStream.write",
        "cve": "None known",
        "notes": "NO CC functors. Pure WL/BEA chain. Most interesting if BEA wildcard absent"
    },
    {
        "id": "#15", "name": "BasicDynaBean+SQLComparator+CompoundComparator+MarshalledObject (4 WL)",
        "classes": [
            "org.apache.commons.beanutils.BasicDynaBean",
            "weblogic.jdbc.rowset.SQLComparator",
            "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
            "com.sun.rowset.JdbcRowSetImpl",
            "weblogic.corba.utils.MarshalledObject",
        ],
        "sink": "FileOutputStream.write",
        "cve": "None known",
        "notes": "MarshalledObject blocked since CVE-2016-3510. CompoundComparator may be blocked post-2020-2883"
    },
    {
        "id": "#16", "name": "CompoundComparator -> InvokerTransformer -> RCE (short)",
        "classes": [
            "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
            "org.apache.commons.collections4.functors.InvokerTransformer",
        ],
        "sink": "Runtime.exec",
        "cve": "CVE-2020-2883 variant",
        "notes": "Known pattern, both classes blocked"
    },
    {
        "id": "#18", "name": "InvertibleComparator -> JdbcRowSetImpl -> ClassLoader.loadClass",
        "classes": [
            "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator",
            "com.sun.rowset.JdbcRowSetImpl",
        ],
        "sink": "ClassLoader.loadClass",
        "cve": "None known",
        "notes": "Novel comparator + unusual ClassLoader sink. BEA wildcard uncertain"
    },
    {
        "id": "#19", "name": "BeanMap$1 -> CC -> RCE",
        "classes": [
            "org.apache.commons.beanutils.BeanMap$1",
            "org.apache.commons.collections.functors.InvokerTransformer",
        ],
        "sink": "Runtime.exec",
        "cve": "None known",
        "notes": "Novel entry via anonymous inner class of BeanMap, but CC functors blocked"
    },
    {
        "id": "#22", "name": "WrapDynaClass$2 -> CC -> JNDI",
        "classes": [
            "org.apache.commons.beanutils.WrapDynaClass$2",
            "org.apache.commons.collections.functors.InvokerTransformer",
        ],
        "sink": "InitialContext.doLookup",
        "cve": "None known",
        "notes": "Novel entry via DynaClass anonymous class, but CC functors blocked"
    },
    {
        "id": "#25", "name": "CompoundComparator+ExposeInvocationInterceptor -> SSRF",
        "classes": [
            "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator",
            "com.bea.core.repackaged.springframework.aop.interceptor.ExposeInvocationInterceptor",
            "com.sun.rowset.JdbcRowSetImpl",
        ],
        "sink": "FileOutputStream.write",
        "cve": "None known",
        "notes": "Multi-BEA-Spring chain. CompoundComparator likely blocked, but interesting topology"
    },
    {
        "id": "#26", "name": "EmptyTargetSource+MarshalledObject+SQLComparator+ProxyDesc (4 WL)",
        "classes": [
            "com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource",
            "weblogic.corba.utils.MarshalledObject",
            "weblogic.jdbc.rowset.SQLComparator",
            "weblogic.iiop.ProxyDesc",
        ],
        "sink": "FileOutputStream.write",
        "cve": "None known",
        "notes": "MarshalledObject blocked. But other 3 classes may not be"
    },
]


def classify(chain):
    blocked = []
    unblocked = []
    uncertain = []

    for cls in chain["classes"]:
        if cls in KNOWN_DENYLIST:
            blocked.append(cls.split(".")[-1])
            continue
        wc_match = False
        for pat in WILDCARD_PATTERNS:
            if cls.startswith(pat):
                blocked.append(f"{cls.split('.')[-1]} (wc)")
                wc_match = True
                break
        if wc_match:
            continue
        for pat in UNCERTAIN_WILDCARDS:
            if cls.startswith(pat):
                uncertain.append(cls.split(".")[-1])
                wc_match = True
                break
        if not wc_match:
            unblocked.append(cls.split(".")[-1])

    return blocked, unblocked, uncertain


print("=" * 110)
print("  WebLogic Deserialization Chain Analysis — CVE Cross-Reference & Denylist Status")
print("=" * 110)

tiers = {"TIER 1 (NOVEL + LIKELY UNBLOCKED)": [], "TIER 2 (NOVEL + UNCERTAIN)": [],
         "TIER 3 (NOVEL but PARTIALLY BLOCKED)": [], "TIER 4 (KNOWN CVE / FULLY BLOCKED)": []}

for chain in FUZZER_CHAINS:
    blocked, unblocked, uncertain = classify(chain)
    has_known_cve = "CVE-" in chain["cve"]

    if has_known_cve or (blocked and not unblocked and not uncertain):
        tier = "TIER 4 (KNOWN CVE / FULLY BLOCKED)"
    elif not blocked and not uncertain:
        tier = "TIER 1 (NOVEL + LIKELY UNBLOCKED)"
    elif not blocked and uncertain:
        tier = "TIER 2 (NOVEL + UNCERTAIN)"
    else:
        tier = "TIER 3 (NOVEL but PARTIALLY BLOCKED)"

    tiers[tier].append((chain, blocked, unblocked, uncertain))

for tier_name, items in tiers.items():
    if not items:
        continue
    print(f"\n{'─' * 110}")
    print(f"  {tier_name} ({len(items)} chains)")
    print(f"{'─' * 110}")

    for chain, blocked, unblocked, uncertain in items:
        print(f"\n  {chain['id']:6s} {chain['name']}")
        print(f"         Sink: {chain['sink']}")
        print(f"         CVE:  {chain['cve']}")
        if blocked:
            print(f"         BLOCKED:   {', '.join(blocked)}")
        if unblocked:
            print(f"         UNBLOCKED: {', '.join(unblocked)}")
        if uncertain:
            print(f"         UNCERTAIN: {', '.join(uncertain)} (BEA Spring wildcard?)")
        print(f"         Notes: {chain['notes']}")

print(f"\n{'=' * 110}")
print("  VERDICT SUMMARY")
print(f"{'=' * 110}")
for tier_name, items in tiers.items():
    print(f"  {tier_name}: {len(items)}")

print(f"""
  KEY FINDING (RESOLVED):
  BEA Spring wildcard question is ANSWERED by bytecode extraction from WL 14.1.1.0.

  com.bea.core.repackaged.springframework.* is NOT a blanket wildcard.
  Only 4 specific subpackages are blocked:
    - aop.aspectj (+ .annotation, .autoproxy)
    - beans.factory.support
  And 1 specific class:
    - transaction.support.AbstractPlatformTransactionManager

  CONFIRMED NOT BLOCKED (our chain classes):
    - util.comparator.CompoundComparator     (WL11, WL12)
    - util.comparator.InvertibleComparator   (WL9)
    - util.comparator.BooleanComparator      (WL10)
    - aop.target.EmptyTargetSource           (WL10)

  Also NOT BLOCKED:
    - weblogic.wsee.jaxws.buffer.BufferingConfig$Queue  (WL6)
    - weblogic.jdbc.rowset.SQLComparator                (WL7)
    - weblogic.management.internal.WebLogicAttribute$NullObject (WL8)

  BLOCKED:
    - java.lang.Runtime                      (WL12 -- Runtime.exec sink)
    - org.apache.commons.collections.functors.* (CC functor chains)
    - weblogic.corba.utils.MarshalledObject  (WL11 -- 2nd-order deser)

  RECOMMENDED NEXT STEPS:
  1. Verify WL6-WL10 against live WebLogic 14.1.1.0 container
  2. WL6 (BufferingConfig$Queue -> JNDI) is highest priority -- completely unblocked
  3. WL7 (SQLComparator -> JNDI) is second priority -- novel WL-native comparator
  4. WL10 (pure 5-class, no CC) most interesting architecturally
""")
