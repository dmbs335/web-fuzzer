package iocd;

import java.util.*;

/**
 * Gadget graph data structures and graph construction.
 *
 * Nodes represent classes that participate in gadget chains:
 * - SOURCE: root trigger classes (HashMap, PriorityQueue, etc.)
 * - LINK: intermediate classes that bridge dispatch → field → dispatch
 * - SINK: classes that reach dangerous operations
 * - LINK_AND_SINK: classes that both bridge and reach sinks
 *
 * Edges represent bridge fields: "this class reads field F of type I,
 * then dispatches a virtual call on that field."
 */
public class GadgetGraph {

    // ── Data structures ──────────────────────────────────────────

    public enum NodeRole { SOURCE, LINK, SINK, LINK_AND_SINK }

    public static class BridgeField {
        public final String fieldName;
        public final String fieldType;        // FQCN of the field's declared type (interface/class)
        public final String dispatchedMethod; // method called on this field (e.g. "transform", "compare")

        public BridgeField(String fieldName, String fieldType, String dispatchedMethod) {
            this.fieldName = fieldName;
            this.fieldType = fieldType;
            this.dispatchedMethod = dispatchedMethod;
        }

        @Override
        public String toString() {
            return fieldName + ":" + fieldType + "→" + dispatchedMethod;
        }
    }

    public static class SinkInfo {
        public final String sinkCategory;    // "cmd_exec", "jndi_lookup", etc.
        public final String sinkMethod;      // "Runtime.exec", "InitialContext.lookup"
        public final String viaMethod;       // the method in this class that reaches the sink

        public SinkInfo(String sinkCategory, String sinkMethod, String viaMethod) {
            this.sinkCategory = sinkCategory;
            this.sinkMethod = sinkMethod;
            this.viaMethod = viaMethod;
        }
    }

    public static class GadgetNode {
        public final String className;       // FQCN
        public NodeRole role;
        public String dispatchMethod;        // method that the previous link calls on this class
        public final Set<String> dispatchInterfaces = new LinkedHashSet<>(); // interfaces exposing this class
        public final Map<String, BridgeField> bridges = new LinkedHashMap<>(); // fieldName → bridge
        public SinkInfo sinkInfo;            // non-null if this node reaches a sink

        public GadgetNode(String className) {
            this.className = className;
            this.role = NodeRole.LINK;
        }

        public boolean isSink() {
            return role == NodeRole.SINK || role == NodeRole.LINK_AND_SINK;
        }

        public boolean isLink() {
            return role == NodeRole.LINK || role == NodeRole.LINK_AND_SINK;
        }

        @Override
        public String toString() {
            return className + "[" + role + "]";
        }
    }

    public static class GadgetEdge {
        public final GadgetNode from;
        public final GadgetNode to;
        public final String bridgeFieldName;
        public final String bridgeInterface;

        public GadgetEdge(GadgetNode from, GadgetNode to, String bridgeFieldName, String bridgeInterface) {
            this.from = from;
            this.to = to;
            this.bridgeFieldName = bridgeFieldName;
            this.bridgeInterface = bridgeInterface;
        }
    }

    public static class SourceDescriptor {
        public final String className;
        public final String entryMethod;      // "readObject"
        public final String dispatchMethod;   // "hashCode", "compare", "toString"
        public final String dispatchInterface; // "java.util.Comparator" or null (for hashCode/toString)

        public SourceDescriptor(String className, String entryMethod,
                                String dispatchMethod, String dispatchInterface) {
            this.className = className;
            this.entryMethod = entryMethod;
            this.dispatchMethod = dispatchMethod;
            this.dispatchInterface = dispatchInterface;
        }
    }

    // ── Graph state ──────────────────────────────────────────────

    private final List<SourceDescriptor> sources = new ArrayList<>();
    private final Map<String, GadgetNode> nodeByClass = new LinkedHashMap<>();
    private final Map<String, List<GadgetEdge>> outEdges = new HashMap<>();

    // ── Construction ─────────────────────────────────────────────

    public void addSource(SourceDescriptor source) {
        sources.add(source);
    }

    public GadgetNode getOrCreateNode(String className) {
        return nodeByClass.computeIfAbsent(className, GadgetNode::new);
    }

    public void addEdge(GadgetNode from, GadgetNode to, String bridgeFieldName, String bridgeInterface) {
        GadgetEdge edge = new GadgetEdge(from, to, bridgeFieldName, bridgeInterface);
        outEdges.computeIfAbsent(from.className, k -> new ArrayList<>()).add(edge);
    }

    // ── Query ────────────────────────────────────────────────────

    public List<SourceDescriptor> getSources() { return sources; }

    public Collection<GadgetNode> getAllNodes() { return nodeByClass.values(); }

    public GadgetNode getNode(String className) { return nodeByClass.get(className); }

    public List<GadgetEdge> getOutEdges(GadgetNode node) {
        return outEdges.getOrDefault(node.className, Collections.emptyList());
    }

    /** Get all nodes that implement a given interface and are Serializable. */
    public List<GadgetNode> getNodesForInterface(String interfaceFqcn, ClassDatabase db) {
        List<GadgetNode> result = new ArrayList<>();
        Set<String> impls = db.getSerializableImplementors(interfaceFqcn);
        for (String impl : impls) {
            GadgetNode node = nodeByClass.get(impl);
            if (node != null) {
                result.add(node);
            }
        }
        // For synthetic bridge types (e.g., "(bean-getter)") or when DB has no entries,
        // also check nodes whose dispatchInterfaces contain this type.
        // This handles hardcoded JDK sink nodes not in scanned JARs.
        if (result.isEmpty() || interfaceFqcn.startsWith("(")) {
            Set<String> seen = new HashSet<>();
            for (GadgetNode n : result) seen.add(n.className);
            for (GadgetNode node : nodeByClass.values()) {
                if (!seen.contains(node.className) && node.dispatchInterfaces.contains(interfaceFqcn)) {
                    result.add(node);
                }
            }
        }
        return result;
    }

    /** Get all nodes that override a given method (hashCode, toString, equals). */
    public List<GadgetNode> getNodesWithOverride(String methodName, ClassDatabase db) {
        List<GadgetNode> result = new ArrayList<>();
        for (GadgetNode node : nodeByClass.values()) {
            ClassDatabase.ClassInfo ci = db.get(node.className);
            if (ci != null && ci.getMethod(methodName) != null) {
                result.add(node);
            }
        }
        return result;
    }

    // ── Stats ────────────────────────────────────────────────────

    public int nodeCount() { return nodeByClass.size(); }

    public int edgeCount() {
        int count = 0;
        for (var edges : outEdges.values()) count += edges.size();
        return count;
    }

    public int sinkCount() {
        int count = 0;
        for (GadgetNode n : nodeByClass.values()) {
            if (n.isSink()) count++;
        }
        return count;
    }

    public int linkCount() {
        int count = 0;
        for (GadgetNode n : nodeByClass.values()) {
            if (n.isLink()) count++;
        }
        return count;
    }
}
