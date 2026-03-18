import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Attempt to revive "dead" chains with creative alternatives.
 *
 * WL6: BufferingConfig$Queue - transient fields, empty readObject
 *   -> Can we find OTHER WebLogic JNDI-triggering classes?
 *
 * WL7: SQLComparator - BeanMap not Serializable
 *   -> Can we find a Serializable Map that calls getters?
 *   -> DefaultedMap? TabularDataSupport? Custom proxy?
 *
 * WL8: NullObject - readResolve returns singleton
 *   -> Is there a way to hijack static field before readResolve?
 *   -> What about other objects in aop.target package?
 *
 * WL10: BooleanComparator - only compares Booleans
 *   -> What if we pair EmptyTargetSource with a DIFFERENT comparator?
 *
 * WL12: Runtime on denylist
 *   -> Can we use ProcessBuilder instead?
 *   -> Or ScriptEngine, or URLClassLoader?
 */
public class DeadChainRevival {
    public static void main(String[] args) throws Exception {
        System.out.println("=== Dead Chain Revival Attempts ===\n");

        // ============================================
        // WL7 REVIVAL: Find Serializable getter-invoking Map
        // ============================================
        System.out.println("=== WL7 REVIVAL: Serializable Map that calls getters ===\n");

        // Candidate 1: DefaultedMap (CC3)
        System.out.println("[1] org.apache.commons.collections.map.DefaultedMap");
        try {
            Class<?> c = Class.forName("org.apache.commons.collections.map.DefaultedMap");
            System.out.println("  Found. Ser:" + Serializable.class.isAssignableFrom(c) +
                " Map:" + Map.class.isAssignableFrom(c));
            System.out.println("  Package: org.apache.commons.collections.map -- NOT in denylist!");
            // DefaultedMap.get(key) returns transformer.transform(key) if key not found
            // The transformer is stored as 'value' field (Object type)
            // If we set a Transformer... but Transformer impls are in functors (blocked)
            // UNLESS: the 'value' field accepts any Object, and if it's a Closure/Function...
            for (Field f : c.getDeclaredFields()) {
                f.setAccessible(true);
                System.out.println("  field: " + f.getType().getName() + " " + f.getName());
            }
        } catch (ClassNotFoundException e) {
            System.out.println("  NOT FOUND");
        }

        // Candidate 2: TransformedMap (CC3) - transforms keys/values on put/get
        System.out.println("\n[2] org.apache.commons.collections.map.TransformedMap");
        try {
            Class<?> c = Class.forName("org.apache.commons.collections.map.TransformedMap");
            System.out.println("  Found. Ser:" + Serializable.class.isAssignableFrom(c));
            System.out.println("  Package: org.apache.commons.collections.map -- NOT in denylist!");
            for (Field f : c.getDeclaredFields()) {
                f.setAccessible(true);
                System.out.println("  field: " + f.getType().getName() + " " + f.getName());
            }
            // TransformedMap stores valueTransformer and keyTransformer
            // On get(), it does NOT transform -- only on put()
            // So this doesn't help for SQLComparator which calls get()
        } catch (ClassNotFoundException e) {
            System.out.println("  NOT FOUND");
        }

        // Candidate 3: LazyMap (CC3)
        System.out.println("\n[3] org.apache.commons.collections.map.LazyMap");
        try {
            Class<?> c = Class.forName("org.apache.commons.collections.map.LazyMap");
            System.out.println("  Found. Ser:" + Serializable.class.isAssignableFrom(c));
            System.out.println("  Package: org.apache.commons.collections.map -- NOT in denylist!");
            for (Field f : c.getDeclaredFields()) {
                f.setAccessible(true);
                System.out.println("  field: " + f.getType().getName() + " " + f.getName());
            }
            // LazyMap.get(key): if key not found, factory.transform(key) creates value
            // factory is a Transformer -- implementations are in functors (BLOCKED)
            // BUT: Transformer is an interface in root package
            // What if we use a non-functors Transformer implementation?
        } catch (ClassNotFoundException e) {
            System.out.println("  NOT FOUND");
        }

        // KEY QUESTION: Are there Transformer implementations NOT in functors?
        System.out.println("\n[4] Transformer implementations outside functors package:");
        String[] transformerCandidates = {
            "org.apache.commons.collections.functors.InvokerTransformer",
            "org.apache.commons.collections.functors.ChainedTransformer",
            "org.apache.commons.collections.functors.ConstantTransformer",
            // Non-functors?
            "org.apache.commons.collections.TransformerUtils",
            "org.apache.commons.collections.BeanMap",  // BeanMap in root?
            // WebLogic's own?
            "weblogic.utils.collections.LazyMap",
        };
        for (String name : transformerCandidates) {
            try {
                Class<?> c = Class.forName(name);
                boolean isTransformer = false;
                try {
                    Class<?> tIface = Class.forName("org.apache.commons.collections.Transformer");
                    isTransformer = tIface.isAssignableFrom(c);
                } catch (Exception ex) {}
                System.out.println("  " + name);
                System.out.println("    Ser:" + Serializable.class.isAssignableFrom(c) +
                    " Transformer:" + isTransformer +
                    " pkg:" + c.getPackage().getName());
            } catch (ClassNotFoundException e) {
                System.out.println("  " + name + " -- NOT FOUND");
            }
        }

        // ============================================
        // WL7 REVIVAL APPROACH B: Use BeanUtilsBean as a Transformer-like bridge
        // ============================================
        System.out.println("\n\n[5] BeanUtilsBean/PropertyUtilsBean as Transformer bridge:");
        try {
            // What if we create a custom Transformer impl via dynamic proxy?
            // Proxy(Transformer.class, handler) where handler calls PropertyUtils.getProperty()
            // AnnotationInvocationHandler IS Serializable
            // But it just returns memberValues.get(methodName), not useful

            // What about EventHandler?
            // EventHandler(target, "getDatabaseMetaData", null, null)
            // When ANY method is called on proxy, it calls target.getDatabaseMetaData()
            // EventHandler is NOT Serializable though...

            // CREATIVE IDEA: What about serializing the EventHandler fields manually?
            // EventHandler has: target, action, eventPropertyName, listenerMethodName
            // These are all Serializable (Object, String, String, String)
            // What if we use Unsafe/ReflectionFactory to write these to the stream?
            Class<?> ehClass = Class.forName("java.beans.EventHandler");
            System.out.println("  EventHandler fields:");
            for (Field f : ehClass.getDeclaredFields()) {
                f.setAccessible(true);
                System.out.println("    " + f.getType().getSimpleName() + " " + f.getName() +
                    " Ser:" + Serializable.class.isAssignableFrom(f.getType()));
            }
            // Check superclass fields
            Class<?> superClass = ehClass.getSuperclass();
            System.out.println("  Superclass: " + superClass.getName());
            for (Field f : superClass.getDeclaredFields()) {
                f.setAccessible(true);
                System.out.println("    " + f.getType().getSimpleName() + " " + f.getName());
            }
        } catch (Exception e) {
            System.out.println("  Error: " + e);
        }

        // ============================================
        // WL12 REVIVAL: Replace Runtime with non-blocked sink
        // ============================================
        System.out.println("\n\n=== WL12 REVIVAL: Non-blocked sinks ===\n");

        String[] sinkCandidates = {
            "java.lang.ProcessBuilder",
            "javax.script.ScriptEngineManager",
            "java.net.URLClassLoader",
            "javax.naming.InitialContext",
            "java.lang.Thread",
            "java.lang.Runtime",  // BLOCKED
        };
        System.out.println("Denylist classes (from bytecode):");
        System.out.println("  java.lang.Runtime -- BLOCKED");
        System.out.println("  java.rmi.server.UnicastRemoteObject -- BLOCKED");
        System.out.println("  java.rmi.server.RemoteObjectInvocationHandler -- BLOCKED");
        System.out.println("  java.rmi.server.RemoteObject -- BLOCKED\n");

        for (String name : sinkCandidates) {
            try {
                Class<?> c = Class.forName(name);
                System.out.println(name);
                System.out.println("  Ser:" + Serializable.class.isAssignableFrom(c));
                // Check if any of its methods are dangerous
                boolean blocked = name.equals("java.lang.Runtime");
                System.out.println("  Denylist: " + (blocked ? "BLOCKED" : "NOT BLOCKED"));
            } catch (ClassNotFoundException e) {
                System.out.println(name + " -- NOT FOUND");
            }
        }

        // ============================================
        // WL10 REVIVAL: EmptyTargetSource with different trigger
        // ============================================
        System.out.println("\n\n=== WL10 REVIVAL: EmptyTargetSource creative uses ===\n");

        // EmptyTargetSource has getTarget() which throws... not useful
        // But aop.target package has OTHER classes!
        System.out.println("Other classes in aop.target package:");
        String[] aopTargetClasses = {
            "com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.AbstractBeanFactoryBasedTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.SimpleBeanTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.LazyInitTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.SingletonTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.HotSwappableTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.AbstractPoolingTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.CommonsPoolTargetSource",
            "com.bea.core.repackaged.springframework.aop.target.ThreadLocalTargetSource",
        };
        for (String name : aopTargetClasses) {
            try {
                Class<?> c = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(c);
                // Check for interesting methods
                boolean hasGetTarget = false;
                boolean hasGetBeanFactory = false;
                for (Method m : c.getMethods()) {
                    if (m.getName().equals("getTarget")) hasGetTarget = true;
                    if (m.getName().contains("BeanFactory")) hasGetBeanFactory = true;
                }
                System.out.println("  " + c.getSimpleName() + " -- Ser:" + ser +
                    " getTarget:" + hasGetTarget + " BeanFactory:" + hasGetBeanFactory);
            } catch (ClassNotFoundException e) {
                // skip
            }
        }

        // ============================================
        // WILD CARD: JNDI via TemplatesImpl alternative
        // ============================================
        System.out.println("\n\n=== WILDCARD: Non-JNDI code execution sinks ===\n");

        // TemplatesImpl (xsltc.trax) is BLOCKED
        // What about javax.xml.transform?
        String[] xmlClasses = {
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",  // BLOCKED
            "javax.xml.transform.TransformerFactory",
            "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl",  // BLOCKED (same pkg)
            "com.sun.org.apache.bcel.internal.util.ClassLoader",
        };
        for (String name : xmlClasses) {
            try {
                Class<?> c = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(c);
                String pkg = c.getPackage() != null ? c.getPackage().getName() : "?";
                boolean blocked = pkg.equals("com.sun.org.apache.xalan.internal.xsltc.trax");
                System.out.println("  " + c.getSimpleName() + " -- Ser:" + ser +
                    " Blocked:" + blocked + " pkg:" + pkg);
            } catch (ClassNotFoundException e) {
                System.out.println("  " + name + " -- NOT FOUND");
            }
        }

        // ============================================
        // NUCLEAR OPTION: Scan WebLogic classpath for Serializable
        // classes with JNDI/connect/exec in getter methods
        // ============================================
        System.out.println("\n\n=== NUCLEAR: WebLogic classes with dangerous getters ===\n");
        // JdbcRowSetImpl.getDatabaseMetaData() -> connect() -> JNDI is the known one
        // Are there others?
        String[] jndiCandidates = {
            "com.sun.rowset.JdbcRowSetImpl",
            "javax.management.remote.rmi.RMIConnector",
            "com.sun.jndi.rmi.registry.BindingEnumeration",
            "com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl",
            "weblogic.jndi.WLContext",
            "weblogic.jms.common.DestinationImpl",
            "weblogic.jdbc.common.internal.ConnectionEnv",
            "weblogic.jdbc.jts.Connection",
        };
        for (String name : jndiCandidates) {
            try {
                Class<?> c = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(c);
                boolean map = Map.class.isAssignableFrom(c);
                System.out.println(c.getSimpleName() + " -- Ser:" + ser + " Map:" + map);
                // Look for connect/lookup methods
                for (Method m : c.getDeclaredMethods()) {
                    String mn = m.getName().toLowerCase();
                    if (mn.contains("connect") || mn.contains("lookup") || mn.contains("jndi")
                        || mn.contains("getdatabase") || mn.contains("geturl")) {
                        System.out.println("    " + m.getReturnType().getSimpleName() + " " + m.getName() +
                            "(" + m.getParameterCount() + " params)");
                    }
                }
            } catch (ClassNotFoundException e) {
                // skip
            } catch (NoClassDefFoundError e) {
                System.out.println(name + " -- ClassDefError: " + e.getMessage());
            }
        }
    }
}
