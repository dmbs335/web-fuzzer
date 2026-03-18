package iocd;

import iocd.ClassDatabase.ClassInfo;
import iocd.ClassDatabase.MethodInfo;
import iocd.ClassDatabase.CallSite;
import iocd.GadgetGraph.SinkInfo;

import java.util.*;

/**
 * Identifies classes and methods that reach dangerous operations (sinks).
 *
 * Three levels:
 * 1. Direct sinks: hardcoded dangerous JDK methods (Runtime.exec, JNDI lookup, etc.)
 * 2. Indirect sinks: hardcoded methods that internally call direct sinks (TemplatesImpl, JdbcRowSetImpl)
 * 3. Dynamic sinks: library methods discovered to call direct/indirect sinks (1-depth intra-class)
 */
public class SinkRegistry {

    // ── Direct sinks (JDK dangerous methods) ─────────────────────

    // key: "owner.methodName" (internal slash form) → sink category
    private static final Map<String, String> DIRECT_SINKS = new LinkedHashMap<>();
    static {
        // Command execution
        DIRECT_SINKS.put("java/lang/Runtime.exec", "cmd_exec");
        DIRECT_SINKS.put("java/lang/ProcessBuilder.start", "cmd_exec");

        // JNDI
        DIRECT_SINKS.put("javax/naming/InitialContext.lookup", "jndi_lookup");
        DIRECT_SINKS.put("javax/naming/Context.lookup", "jndi_lookup");
        DIRECT_SINKS.put("javax/naming/InitialContext.doLookup", "jndi_lookup");

        // Reflection
        DIRECT_SINKS.put("java/lang/reflect/Method.invoke", "reflection");

        // Script
        DIRECT_SINKS.put("javax/script/ScriptEngine.eval", "script_exec");

        // Network
        DIRECT_SINKS.put("java/net/URL.openConnection", "network");
        DIRECT_SINKS.put("java/net/Socket.<init>", "network");

        // File write
        DIRECT_SINKS.put("java/io/FileOutputStream.<init>", "file_write");

        // Class loading
        DIRECT_SINKS.put("java/lang/ClassLoader.loadClass", "class_load");
        DIRECT_SINKS.put("java/lang/ClassLoader.defineClass", "class_load");
        DIRECT_SINKS.put("java/net/URLClassLoader.newInstance", "class_load");

        // Thread
        DIRECT_SINKS.put("java/lang/Thread.start", "thread_spawn");
    }

    // ── Indirect sinks (known wrappers around direct sinks) ──────

    private static final Map<String, String[]> INDIRECT_SINKS = new LinkedHashMap<>();
    static {
        // [method_key] → [category, human-readable sink name]
        INDIRECT_SINKS.put("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.getOutputProperties",
            new String[]{"class_load", "TemplatesImpl.getOutputProperties"});
        INDIRECT_SINKS.put("com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl.newTransformer",
            new String[]{"class_load", "TemplatesImpl.newTransformer"});
        INDIRECT_SINKS.put("com/sun/rowset/JdbcRowSetImpl.getDatabaseMetaData",
            new String[]{"jndi_lookup", "JdbcRowSetImpl.getDatabaseMetaData"});
        INDIRECT_SINKS.put("com/sun/rowset/JdbcRowSetImpl.connect",
            new String[]{"jndi_lookup", "JdbcRowSetImpl.connect"});
        INDIRECT_SINKS.put("com/sun/rowset/JdbcRowSetImpl.setAutoCommit",
            new String[]{"jndi_lookup", "JdbcRowSetImpl.setAutoCommit"});
    }

    // ── Results ──────────────────────────────────────────────────

    // className (FQCN) → SinkInfo
    private final Map<String, SinkInfo> classSinks = new LinkedHashMap<>();

    // className.methodName → sink category (for LinkAnalyzer to check)
    private final Map<String, String> methodSinks = new LinkedHashMap<>();

    // ── Analysis ─────────────────────────────────────────────────

    /**
     * Find all classes that contain methods reaching sinks.
     * Must be called after ClassDatabase.resolveHierarchy().
     */
    public void findSinks(ClassDatabase db) {
        for (ClassInfo ci : db.allClasses()) {
            if (!ci.serializable) continue;

            for (MethodInfo mi : ci.methods.values()) {
                String sinkCat = checkMethodForSinks(mi, ci, db);
                if (sinkCat != null) {
                    String sinkMethod = inferSinkMethod(mi, sinkCat);
                    String methodKey = ci.name + "." + mi.name;
                    methodSinks.put(methodKey, sinkCat);

                    // Only record the first (highest priority) sink per class
                    if (!classSinks.containsKey(ci.name)) {
                        classSinks.put(ci.name, new SinkInfo(sinkCat, sinkMethod, mi.name));
                    }
                }
            }
        }
    }

    private String checkMethodForSinks(MethodInfo mi, ClassInfo ci, ClassDatabase db) {
        for (CallSite cs : mi.callSites) {
            String key = cs.owner + "." + cs.name;

            // Check direct sinks
            String directCat = DIRECT_SINKS.get(key);
            if (directCat != null) return directCat;

            // Check indirect sinks
            String[] indirect = INDIRECT_SINKS.get(key);
            if (indirect != null) return indirect[0];

            // 1-depth intra-class: if calling another method in same class, check that method
            if (cs.owner.equals(ci.internalName)) {
                String subMethodKey = cs.name + cs.desc;
                MethodInfo subMethod = ci.methods.get(subMethodKey);
                if (subMethod != null) {
                    for (CallSite subCs : subMethod.callSites) {
                        String subKey = subCs.owner + "." + subCs.name;
                        String subCat = DIRECT_SINKS.get(subKey);
                        if (subCat != null) return subCat;
                        String[] subIndirect = INDIRECT_SINKS.get(subKey);
                        if (subIndirect != null) return subIndirect[0];
                    }
                }
            }
        }
        return null;
    }

    private String inferSinkMethod(MethodInfo mi, String sinkCat) {
        // Try to find the specific sink call
        for (CallSite cs : mi.callSites) {
            String key = cs.owner + "." + cs.name;
            if (DIRECT_SINKS.containsKey(key)) {
                String ownerSimple = cs.owner.substring(cs.owner.lastIndexOf('/') + 1);
                return ownerSimple + "." + cs.name;
            }
            String[] indirect = INDIRECT_SINKS.get(key);
            if (indirect != null) return indirect[1];
        }
        return sinkCat; // fallback
    }

    // ── Query ────────────────────────────────────────────────────

    public SinkInfo getClassSink(String fqcn) {
        return classSinks.get(fqcn);
    }

    public boolean isClassSink(String fqcn) {
        return classSinks.containsKey(fqcn);
    }

    /** Check if a specific method in a class reaches a sink. */
    public String getMethodSinkCategory(String classFqcn, String methodName) {
        return methodSinks.get(classFqcn + "." + methodName);
    }

    public boolean methodReachesSink(String classFqcn, String methodName) {
        return methodSinks.containsKey(classFqcn + "." + methodName);
    }

    public Map<String, SinkInfo> allClassSinks() {
        return Collections.unmodifiableMap(classSinks);
    }

    public int size() { return classSinks.size(); }
}
