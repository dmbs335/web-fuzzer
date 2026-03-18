package iocd;

import com.google.gson.*;
import iocd.ChainEnumerator.*;
import iocd.GadgetGraph.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Converts discovered GadgetChains to IR JSON files compatible with DeserTarget.
 *
 * Also emits metadata files:
 * - _type_hierarchy.json: discovered interface → implementations mapping
 * - _field_contracts.json: discovered field types per class
 * - _stats.json: analysis statistics
 */
public class IREmitter {

    private final Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    // ── Chain → IR JSON ──────────────────────────────────────────

    public JsonObject emitChain(GadgetChain chain) {
        JsonObject ir = new JsonObject();

        // chain_type
        ir.addProperty("chain_type", inferChainType(chain));

        // root_class
        ir.addProperty("root_class", chain.source.className);

        // root_trigger
        ir.addProperty("root_trigger", buildTriggerString(chain));

        // links
        JsonArray links = new JsonArray();
        for (int i = 0; i < chain.links.size(); i++) {
            ChainLink cl = chain.links.get(i);
            JsonObject linkObj = new JsonObject();
            linkObj.addProperty("class", cl.node.className);

            // Build bridge $ref links: only for ACTUAL bridge fields in the chain
            Map<String, Integer> bridgeLinks = new LinkedHashMap<>();

            // Find which bridge field connects this node to the next node in the chain
            if (cl.node.isLink() && i + 1 < chain.links.size()) {
                ChainLink nextCl = chain.links.get(i + 1);
                // The next link entered via a specific bridge field
                if (nextCl.bridgeFieldName != null) {
                    bridgeLinks.put(nextCl.bridgeFieldName, i + 1);
                } else {
                    // Fallback: find the bridge field that matches the next link's type
                    for (BridgeField bf : cl.node.bridges.values()) {
                        if (implementsInterface(nextCl.node, bf.fieldType)
                            || (nextCl.bridgeInterface != null
                                && nextCl.bridgeInterface.equals(bf.fieldType))) {
                            bridgeLinks.put(bf.fieldName, i + 1);
                            break;
                        }
                    }
                }
            }

            JsonObject overrides = FieldOverrideTemplates.getOverrides(cl.node.className, bridgeLinks);
            linkObj.add("field_overrides", overrides);
            links.add(linkObj);
        }
        ir.add("links", links);

        // sink_method
        ir.addProperty("sink_method", chain.sinkMethod != null ? chain.sinkMethod : chain.sinkCategory);

        // IOCD metadata
        JsonObject meta = new JsonObject();
        meta.addProperty("auto_generated", true);
        meta.addProperty("chain_depth", chain.depth());
        meta.addProperty("sink_category", chain.sinkCategory);
        ir.add("_iocd_meta", meta);

        return ir;
    }

    private boolean implementsInterface(GadgetNode node, String iface) {
        return node.dispatchInterfaces.contains(iface);
    }

    // ── Chain type inference ─────────────────────────────────────

    private String inferChainType(GadgetChain chain) {
        Set<String> classes = new HashSet<>();
        for (ChainLink cl : chain.links) {
            classes.add(cl.node.className);
        }

        // Check for known patterns
        if (classes.stream().anyMatch(c -> c.contains("Transformer"))) {
            return "transform_chain";
        }
        if (classes.stream().anyMatch(c -> c.contains("Comparator") || c.contains("BeanComparator"))) {
            return "comparator_chain";
        }
        if (classes.stream().anyMatch(c -> c.contains("InvocationHandler") || c.contains("EventHandler"))) {
            return "proxy_chain";
        }
        if (classes.stream().anyMatch(c -> c.contains("ToStringBean") || c.contains("ObjectBean"))) {
            return "tostring_chain";
        }
        if (classes.stream().anyMatch(c -> c.contains("EqualsBean"))) {
            return "bean_chain";
        }
        if (classes.stream().anyMatch(c -> c.contains("Closure") || c.contains("GString"))) {
            return "closure_chain";
        }
        if (chain.sinkCategory != null && chain.sinkCategory.equals("jndi_lookup")) {
            return "jndi_chain";
        }
        if (chain.source.dispatchMethod.equals("hashCode")) {
            return "hashcode_chain";
        }
        if (chain.source.dispatchMethod.equals("compare")) {
            return "comparator_chain";
        }
        if (chain.source.dispatchMethod.equals("toString")) {
            return "tostring_chain";
        }
        return "generic_chain";
    }

    private String buildTriggerString(GadgetChain chain) {
        StringBuilder sb = new StringBuilder();
        sb.append(chain.source.entryMethod).append("→");

        // Add dispatch path
        switch (chain.source.dispatchMethod) {
            case "hashCode":
                sb.append("hash→hashCode");
                break;
            case "compare":
                sb.append("heapify→comparator.compare");
                break;
            case "toString":
                sb.append("val.toString");
                break;
            default:
                sb.append(chain.source.dispatchMethod);
        }

        // Add intermediate links
        for (ChainLink cl : chain.links) {
            if (cl.node.isLink() && !cl.node.bridges.isEmpty()) {
                BridgeField first = cl.node.bridges.values().iterator().next();
                sb.append("→").append(first.dispatchedMethod);
            }
        }

        // Add sink
        if (chain.sinkMethod != null) {
            sb.append("→").append(chain.sinkMethod);
        }

        return sb.toString();
    }

    // ── File output ──────────────────────────────────────────────

    /**
     * Write all chains as IR JSON files to the output directory.
     * Returns the number of files written.
     */
    public int writeChains(List<GadgetChain> chains, Path outputDir) throws IOException {
        Files.createDirectories(outputDir);

        int written = 0;
        for (int i = 0; i < chains.size(); i++) {
            GadgetChain chain = chains.get(i);
            JsonObject ir = emitChain(chain);

            String filename = String.format("iocd_%03d_%s_%s.json",
                i, sanitize(chain.sinkCategory), sanitize(shortClassName(chain.links)));
            Path outFile = outputDir.resolve(filename);

            try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile.toFile()), StandardCharsets.UTF_8)) {
                gson.toJson(ir, w);
            }
            written++;
        }
        return written;
    }

    /**
     * Write type hierarchy metadata.
     */
    public void writeTypeHierarchy(Map<String, Set<String>> hierarchy, Path outputDir) throws IOException {
        Path outFile = outputDir.resolve("_type_hierarchy.json");
        JsonObject obj = new JsonObject();
        for (var entry : hierarchy.entrySet()) {
            JsonArray arr = new JsonArray();
            for (String impl : entry.getValue()) arr.add(impl);
            obj.add(entry.getKey(), arr);
        }
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile.toFile()), StandardCharsets.UTF_8)) {
            gson.toJson(obj, w);
        }
    }

    /**
     * Write field contracts metadata.
     */
    public void writeFieldContracts(ClassDatabase db, Path outputDir) throws IOException {
        Path outFile = outputDir.resolve("_field_contracts.json");
        JsonObject obj = new JsonObject();

        for (ClassDatabase.ClassInfo ci : db.allClasses()) {
            if (!ci.serializable || ci.isInterface()) continue;
            if (ci.fields.isEmpty()) continue;

            JsonObject fields = new JsonObject();
            for (ClassDatabase.FieldInfo fi : ci.fields.values()) {
                if (fi.isStatic() || fi.isTransient()) continue;
                fields.addProperty(fi.name, fi.typeName());
            }
            if (fields.size() > 0) {
                obj.add(ci.name, fields);
            }
        }

        try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile.toFile()), StandardCharsets.UTF_8)) {
            gson.toJson(obj, w);
        }
    }

    /**
     * Write analysis statistics.
     */
    public void writeStats(int classCount, int serializableCount, int sourceCount,
                           int sinkCount, int linkCount, int edgeCount, int chainCount,
                           long elapsedMs, Path outputDir) throws IOException {
        Path outFile = outputDir.resolve("_stats.json");
        JsonObject obj = new JsonObject();
        obj.addProperty("classes_scanned", classCount);
        obj.addProperty("serializable_classes", serializableCount);
        obj.addProperty("sources", sourceCount);
        obj.addProperty("sinks", sinkCount);
        obj.addProperty("links", linkCount);
        obj.addProperty("edges", edgeCount);
        obj.addProperty("chains_emitted", chainCount);
        obj.addProperty("elapsed_ms", elapsedMs);
        try (Writer w = new OutputStreamWriter(new FileOutputStream(outFile.toFile()), StandardCharsets.UTF_8)) {
            gson.toJson(obj, w);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private String sanitize(String s) {
        if (s == null) return "unknown";
        return s.replaceAll("[^a-zA-Z0-9_]", "_").toLowerCase();
    }

    private String shortClassName(List<ChainLink> links) {
        if (links.isEmpty()) return "empty";
        // Use last link's simple class name
        String last = links.get(links.size() - 1).node.className;
        int dot = last.lastIndexOf('.');
        return dot >= 0 ? last.substring(dot + 1) : last;
    }
}
