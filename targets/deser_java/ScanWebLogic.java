import java.io.*;
import java.util.*;
import java.util.jar.*;
import java.lang.reflect.*;

/**
 * Scan WebLogic jars for Serializable classes useful as gadget chain components.
 * Outputs JSON for merging into TYPE_HIERARCHY.
 */
public class ScanWebLogic {
    public static void main(String[] args) throws Exception {
        String[] jars = {
            "targets/deser_java/weblogic_libs/weblogic.jar",
            "targets/deser_java/weblogic_libs/bea-spring.jar"
        };

        Map<String, List<String>> byCategory = new TreeMap<>();

        for (String jarPath : jars) {
            JarFile jar = new JarFile(jarPath);
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!name.endsWith(".class")) continue;

                String className = name.replace('/', '.').replace(".class", "");
                try {
                    Class<?> cls = Class.forName(className, false,
                        Thread.currentThread().getContextClassLoader());

                    if (!Serializable.class.isAssignableFrom(cls)) continue;
                    if (cls.isInterface() || cls.isEnum()) continue;
                    if (Modifier.isAbstract(cls.getModifiers())) continue;

                    boolean hasReadObject = false;
                    boolean hasReadResolve = false;

                    for (Method m : cls.getDeclaredMethods()) {
                        if (m.getName().equals("readObject")) hasReadObject = true;
                        if (m.getName().equals("readResolve")) hasReadResolve = true;
                    }

                    Set<String> ifaces = new HashSet<>();
                    for (Class<?> iface : getAllInterfaces(cls)) {
                        ifaces.add(iface.getName());
                    }

                    String category = null;

                    if (ifaces.contains("weblogic.jndi.internal.OpaqueReference")) {
                        category = "OPAQUE_REFERENCE";
                    } else if (hasReadResolve && (className.contains("Marshalled") ||
                             className.contains("Stub") || className.contains("Wrapper") ||
                             className.contains("Ref"))) {
                        category = "SECOND_ORDER";
                    } else if (ifaces.contains("java.lang.reflect.InvocationHandler")) {
                        category = "INVOCATION_HANDLER";
                    } else if (ifaces.contains("java.util.Comparator")) {
                        category = "COMPARATOR";
                    } else if (ifaces.contains("java.util.Map") && hasReadObject) {
                        category = "MAP_WITH_READ_OBJECT";
                    } else if (ifaces.contains("javax.naming.Referenceable") ||
                               ifaces.contains("javax.naming.spi.ObjectFactory")) {
                        category = "JNDI_FACTORY";
                    } else if (hasReadResolve) {
                        category = "READ_RESOLVE";
                    } else if (hasReadObject) {
                        boolean hasJndiFields = false;
                        for (Field f : cls.getDeclaredFields()) {
                            String fn = f.getName().toLowerCase();
                            if (fn.contains("jndi") || fn.contains("lookup") ||
                                fn.contains("remote") || fn.contains("provider_url")) {
                                hasJndiFields = true;
                                break;
                            }
                        }
                        if (hasJndiFields) category = "JNDI_FIELDS";
                    }

                    if (category != null) {
                        byCategory.computeIfAbsent(category, k -> new ArrayList<>()).add(className);
                    }
                } catch (Throwable t) {
                    // Skip
                }
            }
            jar.close();
        }

        for (Map.Entry<String, List<String>> e : byCategory.entrySet()) {
            System.out.println("=== " + e.getKey() + " (" + e.getValue().size() + ") ===");
            Collections.sort(e.getValue());
            for (String c : e.getValue()) {
                System.out.println("  " + c);
            }
            System.out.println();
        }
    }

    static Set<Class<?>> getAllInterfaces(Class<?> cls) {
        Set<Class<?>> result = new HashSet<>();
        while (cls != null && cls != Object.class) {
            for (Class<?> iface : cls.getInterfaces()) {
                result.add(iface);
                collectSuperInterfaces(iface, result);
            }
            cls = cls.getSuperclass();
        }
        return result;
    }

    static void collectSuperInterfaces(Class<?> iface, Set<Class<?>> result) {
        for (Class<?> parent : iface.getInterfaces()) {
            if (result.add(parent)) {
                collectSuperInterfaces(parent, result);
            }
        }
    }
}
