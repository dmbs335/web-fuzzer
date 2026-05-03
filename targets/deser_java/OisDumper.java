/**
 * Lightweight javaagent that hooks ObjectInputStream.readObject()
 * to dump DeserAgent's sink tracking state to a shared file.
 *
 * Designed to be chained with deser_agent.jar on JEUS 8.5:
 *   -javaagent:deser_agent.jar -javaagent:ois_dumper.jar
 *
 * After each readObject() call (success or exception), writes the
 * agent's sinks_hit and invocation_log to /tmp/oob/agent_cov.json,
 * then resets tracking for the next call.
 */

import java.io.*;
import java.lang.instrument.*;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;
import java.util.*;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;

public class OisDumper implements ClassFileTransformer {

    private static final String DUMP_PATH = "/tmp/oob/agent_cov.json";

    // Reflection handles to DeserAgent (resolved lazily)
    private static volatile Method mGetSinks;
    private static volatile Method mGetLog;
    private static volatile Method mReset;
    private static volatile boolean resolved = false;

    private static void resolveAgent() {
        if (resolved) return;
        try {
            Class<?> agent = Class.forName("DeserAgent");
            mGetSinks = agent.getMethod("getSinksHit");
            mGetLog = agent.getMethod("getInvocationLog");
            mReset = agent.getMethod("resetTracking");
            resolved = true;
            System.err.println("[OisDumper] resolved DeserAgent methods");
        } catch (Exception e) {
            System.err.println("[OisDumper] WARN: DeserAgent not found: " + e);
        }
    }

    /** Called from instrumented ObjectInputStream.readObject() finally block. */
    @SuppressWarnings("unchecked")
    public static void dumpAndReset() {
        resolveAgent();
        if (!resolved) return;
        try {
            Set<String> sinks = (Set<String>) mGetSinks.invoke(null);
            List<String> log = (List<String>) mGetLog.invoke(null);

            if (sinks.isEmpty() && log.isEmpty()) {
                // No sinks hit — write minimal marker
                writeFile("{\"deserialized\":true,\"sink_reached\":\"none\"}");
            } else {
                StringBuilder sb = new StringBuilder(256);
                sb.append("{\"deserialized\":true");

                // sinks_hit array
                sb.append(",\"sinks_hit\":[");
                int i = 0;
                String topSink = "none";
                for (String s : sinks) {
                    if (i > 0) sb.append(',');
                    sb.append('"').append(escape(s)).append('"');
                    topSink = s;  // last = highest priority (LinkedHashSet order)
                    i++;
                }
                sb.append(']');

                // sink_reached = highest priority sink
                sb.append(",\"sink_reached\":\"").append(escape(topSink)).append('"');

                // danger indicators as booleans
                for (String cat : new String[]{
                    "cmd_exec", "jndi_lookup", "class_loaded",
                    "file_accessed", "network_connected", "script_exec", "thread_spawn"
                }) {
                    // Map agent categories to coverage collector field names
                    String field = cat;
                    if ("cmd_exec".equals(cat)) field = "process_spawned";
                    else if ("network".equals(cat)) field = "network_connected";
                    else if ("file_write".equals(cat) || "file_read".equals(cat)) field = "file_accessed";
                    else if ("thread_spawn".equals(cat)) field = "thread_created";
                    sb.append(",\"").append(field).append("\":").append(sinks.contains(cat));
                }

                // method_invocations array
                sb.append(",\"method_invocations\":[");
                i = 0;
                for (String m : log) {
                    if (i > 0) sb.append(',');
                    sb.append('"').append(escape(m)).append('"');
                    i++;
                    if (i >= 50) break;  // cap to avoid huge files
                }
                sb.append(']');

                // chain classes from invocation log (unique class names)
                Set<String> classes = new LinkedHashSet<>();
                for (String m : log) {
                    int colon = m.indexOf(':');
                    if (colon < 0 || colon + 1 >= m.length()) continue;
                    String rest = m.substring(colon + 1);

                    if (rest.startsWith("reflect:")) {
                        // "reflect:java.lang.Runtime/exec" → "java.lang.Runtime"
                        String key = rest.substring(8);
                        int slash = key.indexOf('/');
                        if (slash > 0) {
                            classes.add(key.substring(0, slash));
                        }
                    } else {
                        // "java/lang/reflect/Method/invoke/(Ljava/lang/..." → "java.lang.reflect.Method"
                        // Format: owner/methodName/(descriptor) — strip trailing / and method name
                        int paren = rest.indexOf('(');
                        if (paren > 0) {
                            String beforeDesc = rest.substring(0, paren);
                            // Strip trailing '/' between methodName and descriptor
                            while (beforeDesc.endsWith("/")) {
                                beforeDesc = beforeDesc.substring(0, beforeDesc.length() - 1);
                            }
                            // "java/lang/reflect/Method/invoke" — last '/' separates owner from method
                            int lastSlash = beforeDesc.lastIndexOf('/');
                            if (lastSlash > 0) {
                                classes.add(beforeDesc.substring(0, lastSlash).replace('/', '.'));
                            }
                        }
                    }
                }
                if (!classes.isEmpty()) {
                    sb.append(",\"chain_classes\":[");
                    i = 0;
                    for (String c : classes) {
                        if (i > 0) sb.append(',');
                        sb.append('"').append(escape(c)).append('"');
                        i++;
                    }
                    sb.append(']');
                }

                sb.append(",\"readObject_calls\":").append(log.size());
                sb.append('}');
                writeFile(sb.toString());
            }

            mReset.invoke(null);
        } catch (Exception e) {
            // Silently ignore — don't crash JEUS
        }
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void writeFile(String json) {
        try (FileWriter fw = new FileWriter(DUMP_PATH, false)) {
            fw.write(json);
            fw.flush();
        } catch (IOException e) {
            // Ignore — oob dir may not exist yet
        }
    }

    // ── Agent entry ───────────────────────────────────────────

    public static void premain(String args, Instrumentation inst) {
        System.err.println("[OisDumper] loading — will hook ObjectInputStream.readObject()");
        inst.addTransformer(new OisDumper(), true);

        // OIS is already loaded at premain time — retransform it
        try {
            inst.retransformClasses(java.io.ObjectInputStream.class);
            System.err.println("[OisDumper] instrumented ObjectInputStream");
        } catch (Exception e) {
            System.err.println("[OisDumper] WARN: could not retransform OIS: " + e);
        }
    }

    // ── Transformer ───────────────────────────────────────────

    @Override
    public byte[] transform(ClassLoader loader, String className,
                            Class<?> redef, ProtectionDomain pd, byte[] bytecode) {
        if (!"java/io/ObjectInputStream".equals(className)) return null;
        try {
            ClassReader cr = new ClassReader(bytecode);
            ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
            cr.accept(new OisVisitor(cw), ClassReader.EXPAND_FRAMES);
            System.err.println("[OisDumper] ObjectInputStream bytecode rewritten");
            return cw.toByteArray();
        } catch (Exception e) {
            System.err.println("[OisDumper] transform failed: " + e);
            return null;
        }
    }

    // ── ASM visitors ──────────────────────────────────────────

    static class OisVisitor extends ClassVisitor {
        OisVisitor(ClassVisitor cv) { super(Opcodes.ASM9, cv); }

        @Override
        public MethodVisitor visitMethod(int access, String name, String desc,
                                         String sig, String[] excs) {
            MethodVisitor mv = super.visitMethod(access, name, desc, sig, excs);
            // Hook readObject() and readUnshared() — both call readObject0 internally
            if ("readObject".equals(name) && "()Ljava/lang/Object;".equals(desc)) {
                return new ReadObjectAdvice(mv, access, name, desc);
            }
            return mv;
        }
    }

    static class ReadObjectAdvice extends AdviceAdapter {
        ReadObjectAdvice(MethodVisitor mv, int access, String name, String desc) {
            super(Opcodes.ASM9, mv, access, name, desc);
        }

        @Override
        protected void onMethodExit(int opcode) {
            // Called on both normal return and exception throw
            mv.visitMethodInsn(
                Opcodes.INVOKESTATIC,
                "OisDumper",
                "dumpAndReset",
                "()V",
                false
            );
        }
    }
}
