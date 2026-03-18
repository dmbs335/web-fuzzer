package iocd;

import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.jar.*;

/**
 * Scans JAR files using ASM to build a complete class database:
 * - Class hierarchy (superclass, interfaces)
 * - Field declarations (name, type descriptor, access)
 * - Method signatures and their call sites / field reads
 *
 * After scanning, resolves CHA (Class Hierarchy Analysis) subtype index:
 * interface → all Serializable implementations.
 */
public class ClassDatabase {

    // ── Data structures ──────────────────────────────────────────

    public static class FieldInfo {
        public final String name;
        public final String descriptor;  // e.g. "Ljava/util/Comparator;"
        public final int access;

        FieldInfo(String name, String descriptor, int access) {
            this.name = name;
            this.descriptor = descriptor;
            this.access = access;
        }

        public String typeName() {
            // Convert descriptor to FQCN: "Ljava/util/Comparator;" → "java.util.Comparator"
            if (descriptor.startsWith("L") && descriptor.endsWith(";")) {
                return descriptor.substring(1, descriptor.length() - 1).replace('/', '.');
            }
            if (descriptor.startsWith("[")) {
                return descriptor.replace('/', '.');
            }
            return descriptor; // primitives
        }

        public boolean isTransient() { return (access & Opcodes.ACC_TRANSIENT) != 0; }
        public boolean isStatic() { return (access & Opcodes.ACC_STATIC) != 0; }
    }

    public static class CallSite {
        public final String owner;   // internal name: "java/lang/Runtime"
        public final String name;    // method name: "exec"
        public final String desc;    // descriptor
        public final int opcode;     // INVOKEVIRTUAL, INVOKEINTERFACE, etc.

        CallSite(int opcode, String owner, String name, String desc) {
            this.opcode = opcode;
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }

        public String ownerDot() { return owner.replace('/', '.'); }
        public String key() { return owner + "." + name; }
    }

    public static class FieldRead {
        public final String owner;   // class that owns the field
        public final String name;    // field name
        public final String desc;    // field type descriptor

        FieldRead(String owner, String name, String desc) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
        }
    }

    public static class MethodInfo {
        public final String name;
        public final String descriptor;
        public final int access;
        public final List<CallSite> callSites = new ArrayList<>();
        public final List<FieldRead> fieldReads = new ArrayList<>();

        MethodInfo(String name, String descriptor, int access) {
            this.name = name;
            this.descriptor = descriptor;
            this.access = access;
        }
    }

    public static class ClassInfo {
        public final String name;           // FQCN dotted: "org.apache.commons.collections.map.LazyMap"
        public final String internalName;   // slash form: "org/apache/commons/collections/map/LazyMap"
        public final String superName;      // internal name of superclass
        public final String[] interfaces;   // internal names of directly declared interfaces
        public final int access;
        public final Map<String, FieldInfo> fields = new LinkedHashMap<>();
        public final Map<String, MethodInfo> methods = new LinkedHashMap<>(); // key: name+desc

        // Resolved after hierarchy resolution
        public final Set<String> allInterfaces = new LinkedHashSet<>(); // FQCN dotted, transitive
        public boolean serializable = false;

        ClassInfo(String internalName, String superName, String[] interfaces, int access) {
            this.internalName = internalName;
            this.name = internalName.replace('/', '.');
            this.superName = superName;
            this.interfaces = interfaces;
            this.access = access;
        }

        public boolean isAbstract() { return (access & Opcodes.ACC_ABSTRACT) != 0; }
        public boolean isInterface() { return (access & Opcodes.ACC_INTERFACE) != 0; }

        public MethodInfo getMethod(String name) {
            for (var entry : methods.entrySet()) {
                if (entry.getValue().name.equals(name)) return entry.getValue();
            }
            return null;
        }
    }

    // ── State ────────────────────────────────────────────────────

    private final Map<String, ClassInfo> classes = new LinkedHashMap<>();

    // CHA subtype index: interface/abstract FQCN → set of concrete Serializable impl FQCNs
    private final Map<String, Set<String>> subtypes = new HashMap<>();

    // ── Public API ───────────────────────────────────────────────

    public void scanJar(Path jarPath) throws IOException {
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (!entry.getName().endsWith(".class")) continue;
                // Skip module-info, package-info
                if (entry.getName().contains("module-info") || entry.getName().contains("package-info")) continue;

                try (InputStream is = jar.getInputStream(entry)) {
                    scanClass(is);
                } catch (Exception e) {
                    // Skip malformed classes
                }
            }
        }
    }

    public void scanClass(InputStream is) throws IOException {
        ClassReader cr = new ClassReader(is);
        ClassInfoCollector collector = new ClassInfoCollector();
        cr.accept(collector, ClassReader.SKIP_DEBUG | ClassReader.SKIP_FRAMES);
        if (collector.result != null) {
            classes.put(collector.result.name, collector.result);
        }
    }

    /**
     * Resolve transitive interfaces and build CHA subtype index.
     * Must be called after all JARs are scanned.
     */
    public void resolveHierarchy() {
        // Phase 1: resolve transitive interfaces for each class
        for (ClassInfo ci : classes.values()) {
            resolveAllInterfaces(ci, new HashSet<>());
        }

        // Phase 2: check Serializable
        for (ClassInfo ci : classes.values()) {
            ci.serializable = ci.allInterfaces.contains("java.io.Serializable")
                || isJdkSerializable(ci.name);
        }

        // Phase 3: build subtype index
        for (ClassInfo ci : classes.values()) {
            if (!ci.serializable || ci.isInterface() || ci.isAbstract()) continue;
            for (String iface : ci.allInterfaces) {
                subtypes.computeIfAbsent(iface, k -> new LinkedHashSet<>()).add(ci.name);
            }
            // Also index by superclass chain
            String sup = ci.superName;
            while (sup != null && !sup.equals("java/lang/Object")) {
                String supDot = sup.replace('/', '.');
                subtypes.computeIfAbsent(supDot, k -> new LinkedHashSet<>()).add(ci.name);
                ClassInfo supInfo = classes.get(supDot);
                sup = supInfo != null ? supInfo.superName : null;
            }
        }
    }

    private void resolveAllInterfaces(ClassInfo ci, Set<String> visited) {
        if (!visited.add(ci.name)) return;
        if (!ci.allInterfaces.isEmpty()) return; // already resolved

        // Direct interfaces
        if (ci.interfaces != null) {
            for (String iface : ci.interfaces) {
                String ifaceDot = iface.replace('/', '.');
                ci.allInterfaces.add(ifaceDot);
                ClassInfo ifaceInfo = classes.get(ifaceDot);
                if (ifaceInfo != null) {
                    resolveAllInterfaces(ifaceInfo, visited);
                    ci.allInterfaces.addAll(ifaceInfo.allInterfaces);
                } else {
                    // Try JDK reflection fallback
                    addJdkInterfaces(ifaceDot, ci.allInterfaces);
                }
            }
        }

        // Superclass
        if (ci.superName != null && !ci.superName.equals("java/lang/Object")) {
            String supDot = ci.superName.replace('/', '.');
            ClassInfo supInfo = classes.get(supDot);
            if (supInfo != null) {
                resolveAllInterfaces(supInfo, visited);
                ci.allInterfaces.addAll(supInfo.allInterfaces);
            } else {
                addJdkInterfaces(supDot, ci.allInterfaces);
            }
        }
    }

    private void addJdkInterfaces(String fqcn, Set<String> target) {
        try {
            Class<?> clz = Class.forName(fqcn);
            Deque<Class<?>> queue = new ArrayDeque<>();
            queue.add(clz);
            while (!queue.isEmpty()) {
                Class<?> c = queue.poll();
                for (Class<?> iface : c.getInterfaces()) {
                    if (target.add(iface.getName())) {
                        queue.add(iface);
                    }
                }
                if (c.getSuperclass() != null && c.getSuperclass() != Object.class) {
                    queue.add(c.getSuperclass());
                }
            }
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            // Not available
        }
    }

    private boolean isJdkSerializable(String fqcn) {
        try {
            return java.io.Serializable.class.isAssignableFrom(Class.forName(fqcn));
        } catch (ClassNotFoundException | NoClassDefFoundError e) {
            return false;
        }
    }

    // ── Query methods ────────────────────────────────────────────

    public ClassInfo get(String fqcn) { return classes.get(fqcn); }

    public Collection<ClassInfo> allClasses() { return classes.values(); }

    public Set<String> getImplementors(String interfaceFqcn) {
        return subtypes.getOrDefault(interfaceFqcn, Collections.emptySet());
    }

    public Set<String> getSerializableImplementors(String interfaceFqcn) {
        Set<String> impls = subtypes.getOrDefault(interfaceFqcn, Collections.emptySet());
        Set<String> result = new LinkedHashSet<>();
        for (String impl : impls) {
            ClassInfo ci = classes.get(impl);
            if (ci != null && ci.serializable && !ci.isAbstract() && !ci.isInterface()) {
                result.add(impl);
            }
        }
        return result;
    }

    public int size() { return classes.size(); }

    public int serializableCount() {
        int count = 0;
        for (ClassInfo ci : classes.values()) {
            if (ci.serializable && !ci.isInterface() && !ci.isAbstract()) count++;
        }
        return count;
    }

    /** Get all interfaces that have at least one Serializable implementor. */
    public Map<String, Set<String>> getTypeHierarchy() {
        Map<String, Set<String>> result = new LinkedHashMap<>();
        for (var entry : subtypes.entrySet()) {
            Set<String> serImpls = new LinkedHashSet<>();
            for (String impl : entry.getValue()) {
                ClassInfo ci = classes.get(impl);
                if (ci != null && ci.serializable && !ci.isAbstract() && !ci.isInterface()) {
                    serImpls.add(impl);
                }
            }
            if (serImpls.size() >= 2) { // Only useful if >1 impl
                result.put(entry.getKey(), serImpls);
            }
        }
        return result;
    }

    // ── ASM Visitor ──────────────────────────────────────────────

    private static class ClassInfoCollector extends ClassVisitor {
        ClassInfo result;

        ClassInfoCollector() { super(Opcodes.ASM9); }

        @Override
        public void visit(int version, int access, String name, String signature,
                         String superName, String[] interfaces) {
            result = new ClassInfo(name, superName, interfaces, access);
        }

        @Override
        public FieldVisitor visitField(int access, String name, String descriptor,
                                       String signature, Object value) {
            if (result != null) {
                result.fields.put(name, new FieldInfo(name, descriptor, access));
            }
            return null;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                          String signature, String[] exceptions) {
            if (result == null) return null;
            MethodInfo mi = new MethodInfo(name, descriptor, access);
            result.methods.put(name + descriptor, mi);
            return new MethodCallCollector(mi, result.internalName);
        }
    }

    private static class MethodCallCollector extends MethodVisitor {
        private final MethodInfo method;
        private final String ownerClass;

        MethodCallCollector(MethodInfo method, String ownerClass) {
            super(Opcodes.ASM9);
            this.method = method;
            this.ownerClass = ownerClass;
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            method.callSites.add(new CallSite(opcode, owner, name, descriptor));
        }

        @Override
        public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
            if (opcode == Opcodes.GETFIELD && owner.equals(ownerClass)) {
                method.fieldReads.add(new FieldRead(owner, name, descriptor));
            }
        }
    }
}
