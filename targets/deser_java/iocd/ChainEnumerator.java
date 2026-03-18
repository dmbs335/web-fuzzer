package iocd;

import iocd.GadgetGraph.*;

import java.util.*;

/**
 * Enumerates valid gadget chains via DFS from sources to sinks.
 *
 * A valid chain is: Source → Link₁ → Link₂ → ... → Sink
 * where each link connects via a bridge field to the next.
 *
 * Pruning:
 * - Max depth (default 10)
 * - No cycles (same class cannot appear twice in a chain)
 * - Fan-out limit per interface (handled by LinkAnalyzer edge construction)
 * - Dedup by structural hash
 */
public class ChainEnumerator {

    // ── Chain representation ─────────────────────────────────────

    public static class ChainLink {
        public final GadgetNode node;
        public final String bridgeFieldName;  // field in previous link that references this node
        public final String bridgeInterface;  // type of that field

        public ChainLink(GadgetNode node, String bridgeFieldName, String bridgeInterface) {
            this.node = node;
            this.bridgeFieldName = bridgeFieldName;
            this.bridgeInterface = bridgeInterface;
        }
    }

    public static class GadgetChain {
        public final SourceDescriptor source;
        public final List<ChainLink> links;
        public final String sinkCategory;
        public final String sinkMethod;

        public GadgetChain(SourceDescriptor source, List<ChainLink> links,
                           String sinkCategory, String sinkMethod) {
            this.source = source;
            this.links = links;
            this.sinkCategory = sinkCategory;
            this.sinkMethod = sinkMethod;
        }

        /** Structural hash for dedup. */
        public String hash() {
            StringBuilder sb = new StringBuilder();
            sb.append(source.className).append('|');
            sb.append(source.dispatchMethod).append('|');
            List<String> classNames = new ArrayList<>();
            for (ChainLink link : links) {
                classNames.add(link.node.className);
            }
            Collections.sort(classNames);
            for (String cn : classNames) {
                sb.append(cn).append(',');
            }
            sb.append('|').append(sinkCategory);
            return sb.toString();
        }

        /** Ordered hash (preserves link order, for more unique chains). */
        public String orderedHash() {
            StringBuilder sb = new StringBuilder();
            sb.append(source.className).append('|');
            for (ChainLink link : links) {
                sb.append(link.node.className).append(',');
            }
            sb.append('|').append(sinkCategory);
            return sb.toString();
        }

        public int depth() { return links.size(); }
    }

    // ── Configuration ────────────────────────────────────────────

    private final GadgetGraph graph;
    private final ClassDatabase db;
    private final int maxDepth;
    private final int maxChains;

    public ChainEnumerator(GadgetGraph graph, ClassDatabase db, int maxDepth, int maxChains) {
        this.graph = graph;
        this.db = db;
        this.maxDepth = maxDepth;
        this.maxChains = maxChains;
    }

    // ── Enumeration ──────────────────────────────────────────────

    public List<GadgetChain> enumerate() {
        List<GadgetChain> chains = new ArrayList<>();
        Set<String> seenHashes = new HashSet<>();

        for (SourceDescriptor source : graph.getSources()) {
            if (chains.size() >= maxChains) break;

            // Get candidate first links based on source dispatch
            List<GadgetNode> firstLinks = getFirstLinks(source);

            for (GadgetNode firstNode : firstLinks) {
                if (chains.size() >= maxChains) break;

                // Start DFS from this first link
                List<ChainLink> path = new ArrayList<>();
                Set<String> visited = new HashSet<>();

                ChainLink firstLink = new ChainLink(firstNode, null,
                    source.dispatchInterface != null ? source.dispatchInterface : "(root)");
                path.add(firstLink);
                visited.add(firstNode.className);

                dfs(source, firstNode, path, visited, chains, seenHashes, 1);

                path.remove(path.size() - 1);
                visited.remove(firstNode.className);
            }
        }

        // Sort by depth (shorter chains first — they're more likely to work)
        chains.sort(Comparator.comparingInt(GadgetChain::depth));

        return chains;
    }

    // Max consecutive nodes of the same bridge interface type (prevents Map→Map→Map→...)
    private static final int MAX_CONSECUTIVE_SAME_TYPE = 1;

    private void dfs(SourceDescriptor source, GadgetNode current,
                     List<ChainLink> path, Set<String> visited,
                     List<GadgetChain> results, Set<String> seenHashes, int depth) {
        if (results.size() >= maxChains) return;
        if (depth > maxDepth) return;

        // If current is a sink, emit chain
        if (current.isSink() && current.sinkInfo != null) {
            GadgetChain chain = new GadgetChain(
                source, new ArrayList<>(path),
                current.sinkInfo.sinkCategory,
                current.sinkInfo.sinkMethod
            );
            String hash = chain.orderedHash();
            if (seenHashes.add(hash)) {
                results.add(chain);
            }
        }

        // Continue exploring through bridges (even if current is a sink+link)
        if (current.isLink()) {
            for (BridgeField bridge : current.bridges.values()) {
                // Check consecutive same-type limit:
                // If the bridge type equals the current node's incoming bridge type,
                // count how many consecutive nodes share this type
                int consecutiveSameType = countConsecutiveSameType(path, bridge.fieldType);
                if (consecutiveSameType >= MAX_CONSECUTIVE_SAME_TYPE) continue;

                List<GadgetNode> targets = getTargetNodes(bridge);

                for (GadgetNode next : targets) {
                    if (visited.contains(next.className)) continue;
                    if (results.size() >= maxChains) return;

                    ChainLink link = new ChainLink(next, bridge.fieldName, bridge.fieldType);
                    path.add(link);
                    visited.add(next.className);

                    dfs(source, next, path, visited, results, seenHashes, depth + 1);

                    path.remove(path.size() - 1);
                    visited.remove(next.className);
                }
            }
        }
    }

    /** Count how many of the last N links in path entered via the same bridge interface. */
    private int countConsecutiveSameType(List<ChainLink> path, String bridgeType) {
        int count = 0;
        for (int i = path.size() - 1; i >= 0; i--) {
            ChainLink cl = path.get(i);
            if (cl.bridgeInterface != null && cl.bridgeInterface.equals(bridgeType)) {
                count++;
            } else {
                break;
            }
        }
        return count;
    }

    // ── Helpers ───────────────────────────────────────────────────

    private List<GadgetNode> getFirstLinks(SourceDescriptor source) {
        List<GadgetNode> candidates = new ArrayList<>();

        if (source.dispatchInterface != null) {
            // Interface-specific dispatch (e.g., Comparator.compare)
            candidates = graph.getNodesForInterface(source.dispatchInterface, db);
        } else {
            // Implicit dispatch (hashCode, toString, equals) → any node with that override
            candidates = graph.getNodesWithOverride(source.dispatchMethod, db);
        }

        // Limit fan-out from source
        if (candidates.size() > 100) {
            candidates = prioritize(candidates, 100);
        }

        return candidates;
    }

    private List<GadgetNode> getTargetNodes(BridgeField bridge) {
        String bridgeType = bridge.fieldType;

        List<GadgetNode> targets = new ArrayList<>();
        if (bridgeType.equals("java.lang.Object")) {
            // Object-typed: get nodes that override the dispatched method
            targets = graph.getNodesWithOverride(bridge.dispatchedMethod, db);
        } else {
            targets = graph.getNodesForInterface(bridgeType, db);
            // Also check the type itself
            GadgetNode direct = graph.getNode(bridgeType);
            if (direct != null && !targets.contains(direct)) {
                targets = new ArrayList<>(targets);
                targets.add(direct);
            }
        }

        if (targets.size() > 30) {
            targets = prioritize(targets, 30);
        }

        return targets;
    }

    /** Prioritize gadget library nodes over generic ones. */
    private List<GadgetNode> prioritize(List<GadgetNode> nodes, int limit) {
        List<GadgetNode> gadget = new ArrayList<>();
        List<GadgetNode> other = new ArrayList<>();

        for (GadgetNode n : nodes) {
            if (isGadgetClass(n.className)) {
                gadget.add(n);
            } else {
                other.add(n);
            }
        }

        List<GadgetNode> result = new ArrayList<>(gadget);
        for (GadgetNode n : other) {
            if (result.size() >= limit) break;
            result.add(n);
        }
        return result;
    }

    private boolean isGadgetClass(String fqcn) {
        return fqcn.startsWith("org.apache.commons.collections")
            || fqcn.startsWith("org.apache.commons.beanutils")
            || fqcn.startsWith("com.sun.syndication") || fqcn.startsWith("rome.")
            || fqcn.startsWith("groovy.") || fqcn.startsWith("org.codehaus.groovy")
            || fqcn.startsWith("org.hibernate")
            || fqcn.startsWith("bsh.")
            || fqcn.startsWith("org.springframework")
            || fqcn.startsWith("com.vaadin");
    }
}
