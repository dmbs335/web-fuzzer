/**
 * Java Agent for sink instrumentation during deserialization fuzzing.
 *
 * Intercepts dangerous method calls (Runtime.exec, JNDI lookup, etc.)
 * and records them to a thread-local tracker WITHOUT executing them.
 * Dangerous sinks are blocked by returning default values immediately.
 *
 * Usage: java -javaagent:deser_agent.jar ...
 */

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;

public class DeserAgent implements ClassFileTransformer {

    // ── Sink registry ────────────────────────────────────────────
    // Maps "owner/name/descriptor" → sink category
    private static final Map<String, String> SINK_METHODS = new HashMap<>();
    static {
        // Command execution
        SINK_METHODS.put("java/lang/Runtime/exec/(Ljava/lang/String;)Ljava/lang/Process;", "cmd_exec");
        SINK_METHODS.put("java/lang/Runtime/exec/([Ljava/lang/String;)Ljava/lang/Process;", "cmd_exec");
        SINK_METHODS.put("java/lang/Runtime/exec/(Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;", "cmd_exec");
        SINK_METHODS.put("java/lang/Runtime/exec/([Ljava/lang/String;[Ljava/lang/String;Ljava/io/File;)Ljava/lang/Process;", "cmd_exec");
        SINK_METHODS.put("java/lang/ProcessBuilder/start/()Ljava/lang/Process;", "cmd_exec");

        // JNDI
        SINK_METHODS.put("javax/naming/InitialContext/lookup/(Ljava/lang/String;)Ljava/lang/Object;", "jndi_lookup");
        SINK_METHODS.put("javax/naming/Context/lookup/(Ljava/lang/String;)Ljava/lang/Object;", "jndi_lookup");

        // Reflection
        SINK_METHODS.put("java/lang/reflect/Method/invoke/(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", "reflection");

        // Class loading — NOT instrumented for live server agents (ClassLoader
        // instrumentation causes circular dependency during JEUS bootstrap).
        // Use TemplatesImpl.newTransformer reflective sink instead.
        // SINK_METHODS.put("java/lang/ClassLoader/loadClass/(Ljava/lang/String;)Ljava/lang/Class;", "class_load");
        // SINK_METHODS.put("java/net/URLClassLoader/newInstance/([Ljava/net/URL;)Ljava/net/URLClassLoader;", "class_load");

        // Network
        SINK_METHODS.put("java/net/URL/openConnection/()Ljava/net/URLConnection;", "network");
        SINK_METHODS.put("java/net/URL/openStream/()Ljava/io/InputStream;", "network");
        SINK_METHODS.put("java/net/Socket/<init>/(Ljava/lang/String;I)V", "network");
        SINK_METHODS.put("java/net/InetAddress/getByName/(Ljava/lang/String;)Ljava/net/InetAddress;", "network");
        SINK_METHODS.put("java/net/InetAddress/getAllByName/(Ljava/lang/String;)[Ljava/net/InetAddress;", "network");

        // File I/O
        SINK_METHODS.put("java/io/FileOutputStream/<init>/(Ljava/lang/String;)V", "file_write");
        SINK_METHODS.put("java/io/FileOutputStream/<init>/(Ljava/io/File;)V", "file_write");
        SINK_METHODS.put("java/io/FileWriter/<init>/(Ljava/lang/String;)V", "file_write");
        SINK_METHODS.put("java/io/FileInputStream/<init>/(Ljava/lang/String;)V", "file_read");
        SINK_METHODS.put("java/io/FileReader/<init>/(Ljava/lang/String;)V", "file_read");

        // Script execution
        SINK_METHODS.put("javax/script/ScriptEngine/eval/(Ljava/lang/String;)Ljava/lang/Object;", "script_exec");
        SINK_METHODS.put("javax/script/ScriptEngine/eval/(Ljava/io/Reader;)Ljava/lang/Object;", "script_exec");

        // Thread creation — disabled for live server agents (Thread.start
        // instrumentation interferes with server thread pool management).
        // SINK_METHODS.put("java/lang/Thread/start/()V", "thread_spawn");
    }

    // ── Reflective sink lookup ──────────────────────────────────
    // When Method.invoke is called, check if the target method is a known sink.
    // This catches chains like InvokerTransformer → Method.invoke → Runtime.exec.
    private static final Map<String, String> REFLECTIVE_SINKS = new HashMap<>();
    static {
        REFLECTIVE_SINKS.put("java.lang.Runtime/exec", "cmd_exec");
        REFLECTIVE_SINKS.put("java.lang.ProcessBuilder/start", "cmd_exec");
        REFLECTIVE_SINKS.put("javax.naming.InitialContext/lookup", "jndi_lookup");
        REFLECTIVE_SINKS.put("javax.naming.Context/lookup", "jndi_lookup");
        REFLECTIVE_SINKS.put("javax.script.ScriptEngine/eval", "script_exec");
        REFLECTIVE_SINKS.put("java.net.URL/openConnection", "network");
        REFLECTIVE_SINKS.put("java.net.URL/openStream", "network");
        REFLECTIVE_SINKS.put("java.net.InetAddress/getByName", "network");
        REFLECTIVE_SINKS.put("java.net.InetAddress/getAllByName", "network");
        REFLECTIVE_SINKS.put("java.net.Socket/<init>", "network");
        REFLECTIVE_SINKS.put("java.io.FileOutputStream/<init>", "file_write");
        REFLECTIVE_SINKS.put("java.io.FileWriter/<init>", "file_write");
        REFLECTIVE_SINKS.put("java.io.FileInputStream/<init>", "file_read");
        REFLECTIVE_SINKS.put("java.io.FileReader/<init>", "file_read");
        REFLECTIVE_SINKS.put("java.lang.Thread/start", "thread_spawn");
        // JNDI via JDBC RowSet
        REFLECTIVE_SINKS.put("com.sun.rowset.JdbcRowSetImpl/getDatabaseMetaData", "jndi_lookup");
        REFLECTIVE_SINKS.put("com.sun.rowset.JdbcRowSetImpl/setAutoCommit", "jndi_lookup");
        // TemplatesImpl bytecode loading
        REFLECTIVE_SINKS.put("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl/getOutputProperties", "class_load");
        REFLECTIVE_SINKS.put("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl/newTransformer", "class_load");
    }

    /** Called from instrumented Method.invoke to track reflective sink dispatch. */
    public static void recordReflectiveSink(java.lang.reflect.Method method) {
        String key = method.getDeclaringClass().getName() + "/" + method.getName();
        String category = REFLECTIVE_SINKS.get(key);
        if (category != null) {
            SINKS_HIT.get().add(category);
            INVOCATION_LOG.get().add(category + ":reflect:" + key);
        }
    }

    // Categories where execution is BLOCKED (record + return default)
    // reflection and class_load are NOT blocked — needed for normal JVM operation
    // network, file_read, file_write are NOT blocked for live server agents:
    //   URL.openConnection is used by URLClassLoader internally — blocking it
    //   causes NPE in LauncherHelper.checkAndLoadMain. These are record-only.
    private static final Set<String> BLOCKED_CATEGORIES = new HashSet<>();
    static {
        BLOCKED_CATEGORIES.add("cmd_exec");
        BLOCKED_CATEGORIES.add("jndi_lookup");
        BLOCKED_CATEGORIES.add("script_exec");
        // BLOCKED_CATEGORIES.add("network");    // record-only (URLClassLoader needs URL.openConnection)
        // BLOCKED_CATEGORIES.add("file_write");  // record-only (JVM reads config files)
        // BLOCKED_CATEGORIES.add("file_read");   // record-only
        // BLOCKED_CATEGORIES.add("thread_spawn"); // already removed from SINK_METHODS
    }

    // ── Thread-local sink tracking ──────────────────────────────
    // Populated during deserialization, read by DeserTarget after each run.
    private static final ThreadLocal<Set<String>> SINKS_HIT = ThreadLocal.withInitial(LinkedHashSet::new);
    private static final ThreadLocal<List<String>> INVOCATION_LOG = ThreadLocal.withInitial(ArrayList::new);

    public static void resetTracking() {
        SINKS_HIT.get().clear();
        INVOCATION_LOG.get().clear();
    }

    public static Set<String> getSinksHit() {
        return Collections.unmodifiableSet(SINKS_HIT.get());
    }

    public static List<String> getInvocationLog() {
        return Collections.unmodifiableList(INVOCATION_LOG.get());
    }

    /** Called by instrumented sink methods. */
    public static void recordSink(String category, String detail) {
        SINKS_HIT.get().add(category);
        INVOCATION_LOG.get().add(category + ":" + detail);
    }

    // ── Agent entry point ───────────────────────────────────────

    public static void premain(String agentArgs, Instrumentation inst) {
        System.err.println("[DeserAgent] loading, retransformable=" + inst.isRetransformClassesSupported());
        inst.addTransformer(new DeserAgent(), true);

        // Re-instrument JDK classes that are already loaded before agent premain.
        // Without this, Runtime.exec/ProcessBuilder.start etc. are never intercepted.
        Class<?>[] retransformTargets = {
            java.lang.Runtime.class,
            java.lang.ProcessBuilder.class,
            java.lang.reflect.Method.class,
            // java.lang.ClassLoader.class,  // disabled for live server
            // java.lang.Thread.class,       // disabled for live server
            java.net.InetAddress.class,
            java.net.URL.class,
        };
        for (Class<?> clz : retransformTargets) {
            try {
                inst.retransformClasses(clz);
                System.err.println("[DeserAgent] instrumented: " + clz.getName());
            } catch (Exception e) {
                System.err.println("[DeserAgent] WARN: could not instrument " + clz.getName() + ": " + e);
            }
        }
        System.err.println("[DeserAgent] ready (" + SINK_METHODS.size() + " sink signatures, "
            + BLOCKED_CATEGORIES.size() + " blocked)");
    }

    // ── ClassFileTransformer ────────────────────────────────────

    // Only instrument JDK/library classes that contain sinks
    private static final Set<String> TARGET_CLASSES = new HashSet<>();
    static {
        TARGET_CLASSES.add("java/lang/Runtime");
        TARGET_CLASSES.add("java/lang/ProcessBuilder");
        TARGET_CLASSES.add("javax/naming/InitialContext");
        TARGET_CLASSES.add("java/lang/reflect/Method");
        // TARGET_CLASSES.add("java/lang/ClassLoader");  // disabled for live server
        // TARGET_CLASSES.add("java/net/URLClassLoader"); // disabled for live server
        TARGET_CLASSES.add("java/net/URL");
        TARGET_CLASSES.add("java/net/Socket");
        TARGET_CLASSES.add("java/net/InetAddress");
        TARGET_CLASSES.add("java/io/FileOutputStream");
        TARGET_CLASSES.add("java/io/FileWriter");
        TARGET_CLASSES.add("java/io/FileInputStream");
        TARGET_CLASSES.add("java/io/FileReader");
        TARGET_CLASSES.add("javax/script/ScriptEngine");
        // TARGET_CLASSES.add("java/lang/Thread");  // disabled for live server
    }

    @Override
    public byte[] transform(ClassLoader loader, String className,
            Class<?> classBeingRedefined, ProtectionDomain protectionDomain,
            byte[] classfileBuffer) {
        if (className == null || !TARGET_CLASSES.contains(className)) {
            return null; // Don't transform
        }
        try {
            ClassReader cr = new ClassReader(classfileBuffer);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
            cr.accept(new SinkClassVisitor(cw, className), ClassReader.EXPAND_FRAMES);
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[DeserAgent] Failed to instrument " + className + ": " + e);
            return null;
        }
    }

    // ── ASM Visitors ────────────────────────────────────────────

    static class SinkClassVisitor extends ClassVisitor {
        private final String className;

        SinkClassVisitor(ClassVisitor cv, String className) {
            super(Opcodes.ASM9, cv);
            this.className = className;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            String key = className + "/" + name + "/" + descriptor;
            String sinkCategory = SINK_METHODS.get(key);
            if (sinkCategory != null) {
                boolean block = BLOCKED_CATEGORIES.contains(sinkCategory)
                    && !"<init>".equals(name);  // Can't return early from constructors
                return new SinkMethodAdvice(mv, access, name, descriptor, sinkCategory, key, block);
            }
            return mv;
        }
    }

    static class SinkMethodAdvice extends AdviceAdapter {
        private final String sinkCategory;
        private final String detail;
        private final boolean block;
        private final String methodDesc;

        SinkMethodAdvice(MethodVisitor mv, int access, String name, String desc,
                String sinkCategory, String detail, boolean block) {
            super(Opcodes.ASM9, mv, access, name, desc);
            this.sinkCategory = sinkCategory;
            this.detail = detail;
            this.block = block;
            this.methodDesc = desc;
        }

        @Override
        protected void onMethodEnter() {
            // Insert: DeserAgent.recordSink(category, detail)
            mv.visitLdcInsn(sinkCategory);
            mv.visitLdcInsn(detail);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                "DeserAgent", "recordSink",
                "(Ljava/lang/String;Ljava/lang/String;)V", false);

            // For Method.invoke: also check if the target method is a sink
            // ALOAD 0 = 'this' = the Method object being invoked
            if (sinkCategory.equals("reflection")) {
                mv.visitVarInsn(Opcodes.ALOAD, 0);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                    "DeserAgent", "recordReflectiveSink",
                    "(Ljava/lang/reflect/Method;)V", false);
            }

            // Block dangerous sinks: return default value immediately
            if (block) {
                Type returnType = Type.getReturnType(methodDesc);
                switch (returnType.getSort()) {
                    case Type.VOID:
                        mv.visitInsn(Opcodes.RETURN);
                        break;
                    case Type.OBJECT:
                    case Type.ARRAY:
                        mv.visitInsn(Opcodes.ACONST_NULL);
                        mv.visitInsn(Opcodes.ARETURN);
                        break;
                    case Type.BOOLEAN:
                    case Type.BYTE:
                    case Type.CHAR:
                    case Type.SHORT:
                    case Type.INT:
                        mv.visitInsn(Opcodes.ICONST_0);
                        mv.visitInsn(Opcodes.IRETURN);
                        break;
                    case Type.LONG:
                        mv.visitInsn(Opcodes.LCONST_0);
                        mv.visitInsn(Opcodes.LRETURN);
                        break;
                    case Type.FLOAT:
                        mv.visitInsn(Opcodes.FCONST_0);
                        mv.visitInsn(Opcodes.FRETURN);
                        break;
                    case Type.DOUBLE:
                        mv.visitInsn(Opcodes.DCONST_0);
                        mv.visitInsn(Opcodes.DRETURN);
                        break;
                }
            }
        }
    }
}
