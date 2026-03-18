package iocd;

import iocd.ClassDatabase.*;
import iocd.GadgetGraph.*;
import org.objectweb.asm.Opcodes;

import java.util.*;

/**
 * Core IOCD analysis: discovers gadget links by analyzing dispatch methods.
 *
 * A class C is a gadget link if:
 * 1. C is Serializable
 * 2. C implements a dispatchable interface (Comparator, Transformer, etc.)
 *    OR overrides hashCode/toString/equals
 * 3. C's dispatch method reads a field F via GETFIELD
 * 4. The dispatch method calls a virtual/interface method ON F's value (not as argument)
 * 5. F's declared type is a dispatchable interface → BRIDGE
 *    OR F's dispatch reaches a sink → SINK terminal
 */
public class LinkAnalyzer {

    // ── Dispatchable interface → method mapping ──────────────────

    private static final Map<String, List<String>> DISPATCH_INTERFACES = new LinkedHashMap<>();
    static {
        // JDK
        DISPATCH_INTERFACES.put("java.util.Comparator", List.of("compare"));
        DISPATCH_INTERFACES.put("java.util.Map", List.of("get", "put", "containsKey"));
        DISPATCH_INTERFACES.put("java.util.Map$Entry", List.of("getValue", "getKey"));
        DISPATCH_INTERFACES.put("java.lang.reflect.InvocationHandler", List.of("invoke"));
        DISPATCH_INTERFACES.put("java.lang.Comparable", List.of("compareTo"));
        DISPATCH_INTERFACES.put("java.lang.Iterable", List.of("iterator"));
        DISPATCH_INTERFACES.put("java.lang.Runnable", List.of("run"));
        DISPATCH_INTERFACES.put("java.util.concurrent.Callable", List.of("call"));
        DISPATCH_INTERFACES.put("javax.xml.transform.Templates", List.of("newTransformer", "getOutputProperties"));

        // Commons Collections 3
        DISPATCH_INTERFACES.put("org.apache.commons.collections.Transformer", List.of("transform"));
        DISPATCH_INTERFACES.put("org.apache.commons.collections.Closure", List.of("execute"));
        DISPATCH_INTERFACES.put("org.apache.commons.collections.Factory", List.of("create"));
        DISPATCH_INTERFACES.put("org.apache.commons.collections.Predicate", List.of("evaluate"));

        // Commons Collections 4
        DISPATCH_INTERFACES.put("org.apache.commons.collections4.Transformer", List.of("transform"));
        DISPATCH_INTERFACES.put("org.apache.commons.collections4.Closure", List.of("execute"));
        DISPATCH_INTERFACES.put("org.apache.commons.collections4.Factory", List.of("create"));

        // Groovy
        DISPATCH_INTERFACES.put("groovy.lang.Closure", List.of("call"));
        DISPATCH_INTERFACES.put("groovy.lang.GroovyObject", List.of("invokeMethod"));

        // Vaadin
        DISPATCH_INTERFACES.put("com.vaadin.data.Property", List.of("getValue"));

        // Hibernate
        DISPATCH_INTERFACES.put("org.hibernate.type.Type", List.of("getHashCode", "isEqual"));

        // BeanShell
        DISPATCH_INTERFACES.put("bsh.This", List.of("invokeMethod"));

        // Spring
        DISPATCH_INTERFACES.put("org.springframework.beans.factory.ObjectFactory", List.of("getObject"));
    }

    // Implicit dispatch methods (called by JDK on any object)
    private static final Set<String> IMPLICIT_DISPATCH = Set.of("hashCode", "toString", "equals");

    // Methods that are ALWAYS called ON the receiver object (0-arg or receiver-based)
    // These are safe to associate with Object-typed fields.
    private static final Set<String> RECEIVER_ONLY_METHODS = Set.of(
        "hashCode", "toString", "equals", "compareTo",
        "iterator", "run", "call", "clone",
        "getOutputProperties", "newTransformer", "getValue", "getKey",
        "getDatabaseMetaData", "connect", "setAutoCommit"
    );

    // Known non-bridge fields: fields that are passed as arguments, not dispatched on
    private static final Map<String, Set<String>> NON_BRIDGE_FIELDS = Map.of(
        "org.apache.commons.collections.keyvalue.TiedMapEntry", Set.of("key"),
        "org.apache.commons.collections4.keyvalue.TiedMapEntry", Set.of("key"),
        "org.apache.commons.beanutils.BeanComparator", Set.of("property"),
        "org.apache.commons.collections.functors.InvokerTransformer", Set.of("iMethodName", "iParamTypes", "iArgs"),
        "org.apache.commons.collections4.functors.InvokerTransformer", Set.of("iMethodName", "iParamTypes", "iArgs"),
        "org.apache.commons.collections.functors.ConstantTransformer", Set.of("iConstant"),
        "org.apache.commons.collections4.functors.ConstantTransformer", Set.of("iConstant")
    );

    // ── Analysis ─────────────────────────────────────────────────

    /**
     * Find all gadget links in the class database.
     * Populates the graph with nodes and edges.
     */
    public void analyze(ClassDatabase db, SinkRegistry sinks, GadgetGraph graph) {
        // Phase 1: discover nodes from scanned classes
        for (ClassInfo ci : db.allClasses()) {
            if (!ci.serializable) continue;
            if (ci.isInterface()) continue;

            List<DispatchCandidate> candidates = getDispatchCandidates(ci, db);
            if (candidates.isEmpty()) continue;

            for (DispatchCandidate dc : candidates) {
                MethodInfo mi = resolveMethod(ci, dc.methodName, db);
                if (mi == null) continue;

                Set<BridgeField> bridges = findBridgeFields(ci, mi, db);
                boolean reachesSink = sinks.methodReachesSink(ci.name, dc.methodName);

                if (bridges.isEmpty() && !reachesSink) continue;

                GadgetNode node = graph.getOrCreateNode(ci.name);
                node.dispatchMethod = dc.methodName;
                node.dispatchInterfaces.add(dc.interfaceName != null ? dc.interfaceName : "(implicit)");

                for (BridgeField bf : bridges) {
                    node.bridges.put(bf.fieldName, bf);
                }

                if (reachesSink) {
                    SinkInfo si = sinks.getClassSink(ci.name);
                    node.sinkInfo = si;
                    node.role = bridges.isEmpty() ? NodeRole.SINK : NodeRole.LINK_AND_SINK;
                } else {
                    if (node.role != NodeRole.LINK_AND_SINK && node.role != NodeRole.SINK) {
                        node.role = NodeRole.LINK;
                    }
                }
            }
        }

        // Phase 2: add hardcoded JDK sink nodes (not in scanned JARs)
        addJdkSinkNodes(graph);

        // Phase 3: build edges
        buildEdges(db, graph);
    }

    /**
     * Add JDK sink nodes and hardcoded reflection-bridge patterns.
     *
     * Some gadget classes use reflection to dispatch (BeanComparator calls
     * PropertyUtils.getProperty, ToStringBean calls all getters via reflection).
     * These can't be detected by bytecode GETFIELD+INVOKEVIRTUAL analysis,
     * so we hardcode them.
     */
    private void addJdkSinkNodes(GadgetGraph graph) {
        // ── JDK Sink Nodes (not in scanned JARs) ──

        // TemplatesImpl — class_load sink (getOutputProperties/newTransformer)
        GadgetNode templates = graph.getOrCreateNode(
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl");
        templates.role = NodeRole.SINK;
        templates.dispatchMethod = "getOutputProperties";
        templates.dispatchInterfaces.add("javax.xml.transform.Templates");
        templates.dispatchInterfaces.add("(bean-getter)");
        templates.sinkInfo = new SinkInfo("class_load", "TemplatesImpl.getOutputProperties", "getOutputProperties");

        // JdbcRowSetImpl — jndi_lookup sink
        GadgetNode jdbc = graph.getOrCreateNode("com.sun.rowset.JdbcRowSetImpl");
        jdbc.role = NodeRole.SINK;
        jdbc.dispatchMethod = "getDatabaseMetaData";
        jdbc.dispatchInterfaces.add("javax.sql.RowSet");
        jdbc.dispatchInterfaces.add("(bean-getter)");
        jdbc.sinkInfo = new SinkInfo("jndi_lookup", "JdbcRowSetImpl.getDatabaseMetaData", "getDatabaseMetaData");

        // ── Reflection-Bridge Patterns ──
        // These classes use reflection to call getters on their field objects.
        // The bridge is: field._obj/instance → any bean getter → sink

        // ── Reflection-bridge classes ──
        // These classes use reflection to call getters on their field objects.
        // They may not appear in the graph from phase 1 (no GETFIELD→INVOKEVIRTUAL
        // pattern and cross-class sink calls), so we use getOrCreateNode().

        // BeanComparator: compare() calls PropertyUtils.getProperty(obj, property)
        addReflectionBridge(graph, "org.apache.commons.beanutils.BeanComparator",
            "compare", "java.util.Comparator", "_bean_target");

        // ToStringBean: toString() calls all getters on _obj via reflection
        addReflectionBridge(graph, "com.sun.syndication.feed.impl.ToStringBean",
            "toString", null, "_obj");

        // Vaadin MethodProperty: getValue() calls getter via reflection on instance
        addReflectionBridge(graph, "com.vaadin.data.util.MethodProperty",
            "getValue", "com.vaadin.data.Property", "instance");

        // Vaadin NestedMethodProperty: getValue() calls getter chain via reflection
        addReflectionBridge(graph, "com.vaadin.data.util.NestedMethodProperty",
            "getValue", "com.vaadin.data.Property", "instance");

        // Hibernate GetterMethodImpl: get() calls getter via reflection
        addReflectionBridge(graph, "org.hibernate.property.access.spi.GetterMethodImpl",
            "get", null, "_target");
    }

    /**
     * Add a reflection-bridge gadget node. These classes dispatch to an arbitrary
     * bean getter via reflection (PropertyUtils, BeanIntrospector, etc.) so
     * bytecode analysis can't detect the bridge. We hardcode them and connect
     * via the synthetic "(bean-getter)" bridge type.
     */
    private void addReflectionBridge(GadgetGraph graph, String className,
                                     String dispatchMethod, String dispatchInterface,
                                     String bridgeFieldName) {
        GadgetNode node = graph.getOrCreateNode(className);
        node.dispatchMethod = dispatchMethod;
        if (dispatchInterface != null) {
            node.dispatchInterfaces.add(dispatchInterface);
        }
        node.dispatchInterfaces.add("(implicit)");
        node.bridges.put(bridgeFieldName,
            new BridgeField(bridgeFieldName, "(bean-getter)", "getOutputProperties"));
        // At minimum a LINK; upgrade from SINK if it was already a sink
        if (node.role == NodeRole.SINK) {
            node.role = NodeRole.LINK_AND_SINK;
        } else if (node.role == null || node.role == NodeRole.SOURCE) {
            node.role = NodeRole.LINK;
        }
    }

    // ── Internal helpers ─────────────────────────────────────────

    private static class DispatchCandidate {
        final String interfaceName;
        final String methodName;

        DispatchCandidate(String interfaceName, String methodName) {
            this.interfaceName = interfaceName;
            this.methodName = methodName;
        }
    }

    private List<DispatchCandidate> getDispatchCandidates(ClassInfo ci, ClassDatabase db) {
        List<DispatchCandidate> candidates = new ArrayList<>();

        for (String iface : ci.allInterfaces) {
            List<String> methods = DISPATCH_INTERFACES.get(iface);
            if (methods != null) {
                for (String method : methods) {
                    candidates.add(new DispatchCandidate(iface, method));
                }
            }
        }

        for (String methodName : IMPLICIT_DISPATCH) {
            MethodInfo mi = ci.getMethod(methodName);
            if (mi != null && !ci.name.equals("java.lang.Object")) {
                candidates.add(new DispatchCandidate(null, methodName));
            }
        }

        // Check getter methods (bean property pattern) — only for known gadget libraries
        if (isGadgetLibraryClass(ci.name)) {
            for (var entry : ci.methods.entrySet()) {
                MethodInfo mi = entry.getValue();
                if (mi.name.startsWith("get") && mi.name.length() > 3
                    && mi.descriptor.startsWith("()") && !mi.descriptor.equals("()V")
                    && (mi.access & Opcodes.ACC_PUBLIC) != 0) {
                    candidates.add(new DispatchCandidate(null, mi.name));
                }
            }
        }

        return candidates;
    }

    private MethodInfo resolveMethod(ClassInfo ci, String methodName, ClassDatabase db) {
        MethodInfo mi = ci.getMethod(methodName);
        if (mi != null) return mi;

        String sup = ci.superName;
        while (sup != null && !sup.equals("java/lang/Object")) {
            ClassInfo supInfo = db.get(sup.replace('/', '.'));
            if (supInfo != null) {
                mi = supInfo.getMethod(methodName);
                if (mi != null) return mi;
                sup = supInfo.superName;
            } else {
                break;
            }
        }
        return null;
    }

    /**
     * Analyze a dispatch method for bridge fields.
     *
     * Key improvement: only consider a field as a bridge if the virtual call
     * owner matches the field's declared type (the field is the RECEIVER).
     * Object-typed fields are only bridges for receiver-only methods.
     */
    private Set<BridgeField> findBridgeFields(ClassInfo ci, MethodInfo mi, ClassDatabase db) {
        Set<BridgeField> bridges = new LinkedHashSet<>();

        // Get known non-bridge fields for this class
        Set<String> excluded = NON_BRIDGE_FIELDS.getOrDefault(ci.name, Collections.emptySet());

        // Collect field reads in this method
        Set<String> readFields = new LinkedHashSet<>();
        for (ClassDatabase.FieldRead fr : mi.fieldReads) {
            if (!excluded.contains(fr.name)) {
                readFields.add(fr.name);
            }
        }

        if (readFields.isEmpty()) return bridges;

        for (String fieldName : readFields) {
            FieldInfo fi = ci.fields.get(fieldName);
            if (fi == null || fi.isStatic() || fi.isTransient()) continue;

            // Skip primitives and arrays
            if (!fi.descriptor.startsWith("L")) continue;

            String fieldTypeInternal = fi.descriptor.substring(1, fi.descriptor.length() - 1);
            String fieldTypeFqcn = fi.typeName();
            boolean isObjectField = fieldTypeInternal.equals("java/lang/Object");

            for (ClassDatabase.CallSite cs : mi.callSites) {
                if (cs.opcode != Opcodes.INVOKEVIRTUAL && cs.opcode != Opcodes.INVOKEINTERFACE) continue;

                // For Object-typed fields: only match receiver-only methods
                if (isObjectField) {
                    if (!RECEIVER_ONLY_METHODS.contains(cs.name)) continue;
                    // The call must be on Object or a supertype
                    bridges.add(new BridgeField(fieldName, fieldTypeFqcn, cs.name));
                    break;
                }

                // For typed fields: call owner must match the field's declared type
                boolean match = cs.owner.equals(fieldTypeInternal)
                    || isSubtypeOf(fieldTypeInternal, cs.owner, db);

                if (match) {
                    String dispatchedMethod = cs.name;

                    // Verify the field type is dispatchable (has implementors or is a known interface)
                    Set<String> impls = db.getSerializableImplementors(fieldTypeFqcn);
                    if (impls.isEmpty()) {
                        ClassInfo fieldClass = db.get(fieldTypeFqcn);
                        if (fieldClass == null || !fieldClass.serializable) continue;
                    }

                    bridges.add(new BridgeField(fieldName, fieldTypeFqcn, dispatchedMethod));
                    break;
                }
            }
        }

        return bridges;
    }

    private boolean isSubtypeOf(String childInternal, String parentInternal, ClassDatabase db) {
        String childDot = childInternal.replace('/', '.');
        ClassInfo ci = db.get(childDot);
        if (ci == null) return false;
        return ci.allInterfaces.contains(parentInternal.replace('/', '.'));
    }

    /**
     * Build edges in the graph.
     * Connects each node's bridge fields to nodes implementing the bridge type.
     */
    private void buildEdges(ClassDatabase db, GadgetGraph graph) {
        for (GadgetNode node : new ArrayList<>(graph.getAllNodes())) {
            for (BridgeField bridge : node.bridges.values()) {
                String bridgeType = bridge.fieldType;

                Set<String> impls;
                if (bridgeType.equals("(bean-getter)")) {
                    // Synthetic bridge: connect to all nodes that accept bean-getter dispatch
                    // (TemplatesImpl, JdbcRowSetImpl, and any future JDK sink nodes)
                    impls = new LinkedHashSet<>();
                    for (GadgetNode target : graph.getAllNodes()) {
                        if (target != node && target.dispatchInterfaces.contains("(bean-getter)")) {
                            impls.add(target.className);
                        }
                    }
                } else if (bridgeType.equals("java.lang.Object")) {
                    // For Object fields, connect to nodes that override the dispatched method
                    impls = new LinkedHashSet<>();
                    for (GadgetNode target : graph.getAllNodes()) {
                        if (target == node) continue;
                        ClassInfo tci = db.get(target.className);
                        if (tci != null && tci.getMethod(bridge.dispatchedMethod) != null) {
                            impls.add(target.className);
                        }
                    }
                    // Also connect to hardcoded JDK sink nodes
                    for (GadgetNode target : graph.getAllNodes()) {
                        if (target.role == NodeRole.SINK && target != node
                            && target.dispatchMethod != null
                            && target.dispatchMethod.equals(bridge.dispatchedMethod)) {
                            impls.add(target.className);
                        }
                    }
                } else {
                    impls = db.getSerializableImplementors(bridgeType);
                    // Also include the type itself
                    ClassInfo fieldClass = db.get(bridgeType);
                    if (fieldClass != null && fieldClass.serializable
                        && !fieldClass.isInterface() && !fieldClass.isAbstract()) {
                        impls = new LinkedHashSet<>(impls);
                        impls.add(bridgeType);
                    }
                    // Connect to JDK sink nodes matching the interface
                    for (GadgetNode target : graph.getAllNodes()) {
                        if (target.role == NodeRole.SINK && target != node
                            && target.dispatchInterfaces.contains(bridgeType)) {
                            impls = new LinkedHashSet<>(impls);
                            impls.add(target.className);
                        }
                    }
                }

                // Fan-out limit
                if (impls.size() > 50) {
                    impls = prioritizeGadgetClasses(impls, 50);
                }

                for (String impl : impls) {
                    GadgetNode target = graph.getNode(impl);
                    if (target != null && target != node) {
                        graph.addEdge(node, target, bridge.fieldName, bridgeType);
                    }
                }
            }
        }
    }

    private Set<String> prioritizeGadgetClasses(Set<String> classes, int limit) {
        List<String> gadget = new ArrayList<>();
        List<String> other = new ArrayList<>();

        for (String cls : classes) {
            if (isGadgetLibraryClass(cls)) {
                gadget.add(cls);
            } else {
                other.add(cls);
            }
        }

        Set<String> result = new LinkedHashSet<>(gadget);
        for (String cls : other) {
            if (result.size() >= limit) break;
            result.add(cls);
        }
        return result;
    }

    private boolean isGadgetLibraryClass(String fqcn) {
        return fqcn.startsWith("org.apache.commons.collections")
            || fqcn.startsWith("org.apache.commons.beanutils")
            || fqcn.startsWith("com.sun.syndication") || fqcn.startsWith("rome.")
            || fqcn.startsWith("groovy.") || fqcn.startsWith("org.codehaus.groovy")
            || fqcn.startsWith("org.hibernate")
            || fqcn.startsWith("bsh.")
            || fqcn.startsWith("org.springframework")
            || fqcn.startsWith("com.vaadin")
            || fqcn.startsWith("com.sun.rowset")
            || fqcn.startsWith("com.sun.org.apache.xalan");
    }
}
