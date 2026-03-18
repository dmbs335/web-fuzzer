import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.*;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * JDBC connection-level attack target harness for differential fuzzing.
 *
 * Complements JndiTarget by directly exercising DriverManager.getConnection()
 * and connection pool lifecycle hooks, bypassing the JNDI layer entirely.
 *
 * Accepts JDBC IR JSON on stdin, constructs a connection (direct or via pool),
 * optionally executes SQL, and reports side effects as JSON on stdout.
 *
 * Instrumentation:
 *   - SecurityManager hooks for cmd_exec, file_write, file_read, network
 *   - JDBC connection + SQL execution tracking
 *   - Pool lifecycle hook tracking (initSQL, validationQuery, etc.)
 *   - Deserialization trigger detection
 *
 * Usage:
 *   echo '{"attack_type":"jdbc_exploit",...}' | java -cp ".:gson.jar:h2.jar:..." JdbcTarget
 *
 * Persistent mode (4-byte length prefix):
 *   java -cp ".:gson.jar:..." JdbcTarget --persistent
 */
public class JdbcTarget {

    private static final Gson GSON = new GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .serializeNulls()
        .create();
    private static boolean persistentMode = false;

    // ── Iteration tracking (prevents zombie thread state pollution) ──
    static final AtomicLong iterationCounter = new AtomicLong(0);
    static volatile long currentIteration = 0;
    static final InheritableThreadLocal<Long> threadIteration =
        new InheritableThreadLocal<>();

    // ── Tracking state ──────────────────────────────────────────
    static volatile boolean processSpawned = false;
    static volatile boolean fileWrite = false;
    static volatile boolean fileRead = false;
    static volatile boolean networkConnected = false;
    static volatile boolean classLoaded = false;
    static volatile boolean deserTriggered = false;
    static volatile String sinkReached = null;
    static final List<String> sinksHit = Collections.synchronizedList(new ArrayList<>());
    static volatile int unattributedSinks = 0;

    // ── Sink attribution tracking ──────────────────────────────
    // Maps class-name-like property values to their property names
    // e.g. "groovy.lang.GroovyShell" → "url_param:DATABASE_EVENT_LISTENER"
    static volatile Map<String, String> valueToProperty = Collections.emptyMap();
    static volatile String classLoadTrigger = null;
    static final Map<String, String> sinkAttribution =
        Collections.synchronizedMap(new LinkedHashMap<>());

    /** Check if calling thread belongs to current iteration. */
    static boolean isCurrentIteration() {
        Long iter = threadIteration.get();
        return iter != null && iter == currentIteration;
    }

    // ── Driver timeout cache (skip known-slow drivers/URLs) ──
    private static final Map<String, Integer> driverTimeoutCount = new HashMap<>();
    private static final int TIMEOUT_SKIP_THRESHOLD = 3;

    public static void main(String[] args) throws Exception {
        boolean enumerate = false;
        String enumerateOutput = null;
        boolean introspect = false;
        String introspectOutput = null;
        for (String arg : args) {
            if ("--persistent".equals(arg)) {
                persistentMode = true;
            } else if ("--enumerate".equals(arg)) {
                enumerate = true;
            } else if (arg.startsWith("--enumerate=")) {
                enumerate = true;
                enumerateOutput = arg.substring("--enumerate=".length());
            } else if ("--introspect".equals(arg)) {
                introspect = true;
            } else if (arg.startsWith("--introspect=")) {
                introspect = true;
                introspectOutput = arg.substring("--introspect=".length());
            }
        }

        if (enumerate) {
            enumerateClasspath(enumerateOutput);
            return;
        }
        if (introspect) {
            introspectDrivers(introspectOutput);
            return;
        }

        // Install tracking SecurityManager if none is set
        if (System.getSecurityManager() == null) {
            try {
                System.setSecurityManager(new TrackingSecurityManager());
            } catch (Exception e) {
                // JDK 17+ may not allow setting SecurityManager
            }
        }

        if (persistentMode) {
            runPersistent();
        } else {
            byte[] input = System.in.readAllBytes();
            String jsonStr = new String(input, StandardCharsets.UTF_8).trim();
            String result = processOne(jsonStr);
            System.out.println(result);
        }
    }

    // ── Classpath enumeration ─────────────────────────────────────
    /**
     * Scans all JARs on java.class.path and writes a JSON catalog of class names.
     * Output: {"classes": [...], "packages": {"org.h2": 342, ...}, "total": 10432}
     */
    private static void enumerateClasspath(String outputPath) throws Exception {
        Set<String> classes = new TreeSet<>();
        String cp = System.getProperty("java.class.path");
        for (String entry : cp.split(File.pathSeparator)) {
            if (!entry.endsWith(".jar")) continue;
            try (JarFile jar = new JarFile(entry)) {
                for (JarEntry e : Collections.list(jar.entries())) {
                    String name = e.getName();
                    if (name.endsWith(".class")
                            && !name.contains("$")
                            && !name.contains("module-info")
                            && !name.contains("package-info")
                            && !name.startsWith("META-INF/")) {
                        String fqcn = name.replace('/', '.').replace(".class", "");
                        classes.add(fqcn);
                    }
                }
            } catch (Exception ignored) {}
        }

        // Build package index
        Map<String, Integer> packages = new TreeMap<>();
        for (String cls : classes) {
            int lastDot = cls.lastIndexOf('.');
            if (lastDot > 0) {
                String pkg = cls.substring(0, lastDot);
                // Use top-2-level package for grouping
                String[] parts = pkg.split("\\.");
                String key = parts.length >= 2 ? parts[0] + "." + parts[1] : parts[0];
                packages.merge(key, 1, Integer::sum);
            }
        }

        // Build JSON manually (avoid Gson dependency for this utility mode)
        StringBuilder sb = new StringBuilder();
        sb.append("{\"classes\":[");
        boolean first = true;
        for (String cls : classes) {
            if (!first) sb.append(',');
            sb.append('"').append(cls).append('"');
            first = false;
        }
        sb.append("],\"packages\":{");
        first = true;
        for (Map.Entry<String, Integer> e : packages.entrySet()) {
            if (!first) sb.append(',');
            sb.append('"').append(e.getKey()).append("\":").append(e.getValue());
            first = false;
        }
        sb.append("},\"total\":").append(classes.size()).append('}');

        String json = sb.toString();
        if (outputPath != null && !outputPath.isEmpty()) {
            try (Writer w = new OutputStreamWriter(
                    new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
                w.write(json);
            }
            System.err.println("Wrote " + classes.size() + " classes to " + outputPath);
        } else {
            System.out.println(json);
        }
    }

    // ── Driver introspection ────────────────────────────────────
    /**
     * Auto-discovers driver properties via JDBC getPropertyInfo() API,
     * and classifies classpath classes by interface implementation.
     *
     * Output JSON:
     * {
     *   "driver_properties": {
     *     "org.h2.Driver": [
     *       {"name": "DATABASE_EVENT_LISTENER", "description": "...", "required": false,
     *        "choices": ["org.h2.security.auth.DefaultAuthenticator"]}
     *     ],
     *     ...
     *   },
     *   "interface_impls": {
     *     "org.h2.api.DatabaseEventListener": ["org.h2.security.auth.DefaultAuthenticator"],
     *     "javax.net.ssl.HostnameVerifier": ["org.postgresql.ssl.PGjdbcHostnameVerifier"],
     *     ...
     *   },
     *   "clinit_candidates": ["groovy.lang.GroovyShell", ...]
     * }
     */
    private static void introspectDrivers(String outputPath) throws Exception {
        // Known JDBC driver classes on this classpath
        String[] driverClasses = {
            "org.h2.Driver",
            "org.hsqldb.jdbc.JDBCDriver",
            "com.mysql.cj.jdbc.Driver",
            "org.postgresql.Driver",
            "org.apache.derby.jdbc.EmbeddedDriver",
        };

        // Known URLs for getPropertyInfo (driver needs valid URL prefix)
        Map<String, String> driverUrls = new LinkedHashMap<>();
        driverUrls.put("org.h2.Driver", "jdbc:h2:mem:test");
        driverUrls.put("org.hsqldb.jdbc.JDBCDriver", "jdbc:hsqldb:mem:test");
        driverUrls.put("com.mysql.cj.jdbc.Driver", "jdbc:mysql://localhost/test");
        driverUrls.put("org.postgresql.Driver", "jdbc:postgresql://localhost/test");
        driverUrls.put("org.apache.derby.jdbc.EmbeddedDriver", "jdbc:derby:memory:test;create=true");

        // Interfaces of interest for class-loading properties
        String[] targetInterfaces = {
            "org.h2.api.DatabaseEventListener",
            "org.h2.api.JavaObjectSerializer",
            "com.mysql.cj.protocol.SocketFactory",
            "com.mysql.cj.exceptions.ExceptionInterceptor",
            "com.mysql.cj.interceptors.QueryInterceptor",
            "com.mysql.cj.conf.ConnectionPropertiesTransform",
            "org.postgresql.plugin.AuthenticationPlugin",
            "org.postgresql.xml.PGXmlFactoryFactory",
            "javax.net.ssl.HostnameVerifier",
            "javax.security.auth.callback.CallbackHandler",
            "javax.net.SocketFactory",
        };

        // ── Part 1: Driver property introspection ──
        StringBuilder sb = new StringBuilder();
        sb.append("{\"driver_properties\":{");
        boolean firstDriver = true;
        for (String driverClass : driverClasses) {
            try {
                Class<?> cls = Class.forName(driverClass);
                Driver driver = (Driver) cls.getDeclaredConstructor().newInstance();
                String url = driverUrls.getOrDefault(driverClass, "");
                DriverPropertyInfo[] infos = driver.getPropertyInfo(url, new Properties());
                if (!firstDriver) sb.append(',');
                firstDriver = false;
                sb.append('"').append(driverClass).append("\":[");
                boolean firstProp = true;
                for (DriverPropertyInfo pi : infos) {
                    if (!firstProp) sb.append(',');
                    firstProp = false;
                    sb.append("{\"name\":\"").append(escapeJson(pi.name)).append('"');
                    sb.append(",\"description\":\"").append(escapeJson(
                        pi.description != null ? pi.description : "")).append('"');
                    sb.append(",\"required\":").append(pi.required);
                    if (pi.choices != null && pi.choices.length > 0) {
                        sb.append(",\"choices\":[");
                        for (int i = 0; i < pi.choices.length; i++) {
                            if (i > 0) sb.append(',');
                            sb.append('"').append(escapeJson(pi.choices[i])).append('"');
                        }
                        sb.append(']');
                    }
                    sb.append('}');
                }
                sb.append(']');
            } catch (Exception e) {
                // Driver not on classpath — skip
            }
        }
        sb.append("},");

        // ── Part 2: Interface implementation discovery ──
        // Collect all classes from classpath
        Set<String> allClasses = new TreeSet<>();
        String cp = System.getProperty("java.class.path");
        for (String entry : cp.split(File.pathSeparator)) {
            if (!entry.endsWith(".jar")) continue;
            try (JarFile jar = new JarFile(entry)) {
                for (JarEntry e : Collections.list(jar.entries())) {
                    String name = e.getName();
                    if (name.endsWith(".class")
                            && !name.contains("$")
                            && !name.contains("module-info")
                            && !name.contains("package-info")
                            && !name.startsWith("META-INF/")) {
                        allClasses.add(name.replace('/', '.').replace(".class", ""));
                    }
                }
            } catch (Exception ignored) {}
        }

        // Resolve interfaces and find implementations
        sb.append("\"interface_impls\":{");
        boolean firstIface = true;
        for (String ifaceName : targetInterfaces) {
            Class<?> iface;
            try {
                iface = Class.forName(ifaceName, false,
                    Thread.currentThread().getContextClassLoader());
            } catch (Exception e) {
                continue; // Interface not on classpath
            }
            List<String> impls = new ArrayList<>();
            for (String className : allClasses) {
                try {
                    Class<?> cls = Class.forName(className, false,
                        Thread.currentThread().getContextClassLoader());
                    if (iface.isAssignableFrom(cls) && !cls.isInterface()
                            && !Modifier.isAbstract(cls.getModifiers())) {
                        impls.add(className);
                    }
                } catch (Throwable ignored) {}
            }
            if (!impls.isEmpty()) {
                if (!firstIface) sb.append(',');
                firstIface = false;
                sb.append('"').append(ifaceName).append("\":[");
                for (int i = 0; i < impls.size(); i++) {
                    if (i > 0) sb.append(',');
                    sb.append('"').append(impls.get(i)).append('"');
                }
                sb.append(']');
            }
        }
        sb.append("},");

        // ── Part 3: clinit candidates — classes with static initializers ──
        // Heuristic: public classes in known-dangerous packages that have
        // static fields or that are known scripting/serialization entry points.
        sb.append("\"clinit_candidates\":[");
        List<String> clinitCandidates = new ArrayList<>();
        String[] dangerousPkgs = {
            "groovy.lang", "bsh", "org.yaml.snakeyaml",
            "org.springframework.context.support",
            "org.apache.xbean", "org.apache.commons.collections",
            "org.apache.commons.beanutils", "com.sun.rowset",
            "javax.el", "org.mvel2", "com.alibaba.druid",
        };
        for (String className : allClasses) {
            for (String pkg : dangerousPkgs) {
                if (className.startsWith(pkg + ".")) {
                    try {
                        Class<?> cls = Class.forName(className, false,
                            Thread.currentThread().getContextClassLoader());
                        if (Modifier.isPublic(cls.getModifiers())
                                && !cls.isInterface()
                                && !Modifier.isAbstract(cls.getModifiers())) {
                            clinitCandidates.add(className);
                        }
                    } catch (Throwable ignored) {}
                    break;
                }
            }
        }
        for (int i = 0; i < clinitCandidates.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(clinitCandidates.get(i)).append('"');
        }
        sb.append("]}");

        String json = sb.toString();
        if (outputPath != null && !outputPath.isEmpty()) {
            try (Writer w = new OutputStreamWriter(
                    new FileOutputStream(outputPath), StandardCharsets.UTF_8)) {
                w.write(json);
            }
            System.err.println("Introspection complete: wrote to " + outputPath);
        } else {
            System.out.println(json);
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    private static void runPersistent() throws Exception {
        DataInputStream din = new DataInputStream(
            new BufferedInputStream(System.in));
        DataOutputStream dout = new DataOutputStream(
            new BufferedOutputStream(System.out));

        while (true) {
            int len;
            try {
                len = din.readInt();
            } catch (EOFException e) {
                break;
            }
            if (len < 0 || len > 1_000_000) break;

            String result;
            if (len == 0) {
                result = GSON.toJson(new JdbcResult());
            } else {
                byte[] buf = new byte[len];
                din.readFully(buf);
                String jsonStr = new String(buf, StandardCharsets.UTF_8).trim();
                result = processOne(jsonStr);
            }
            byte[] resultBytes = result.getBytes(StandardCharsets.UTF_8);

            dout.writeInt(resultBytes.length);
            dout.write(resultBytes);
            dout.writeInt(0);  // exit code
            dout.flush();
        }
    }

    private static String processOne(String jsonStr) {
        // Advance iteration — zombie threads from prior iterations
        // will fail the isCurrentIteration() check.
        currentIteration = iterationCounter.incrementAndGet();
        threadIteration.set(currentIteration);

        // Reset tracking state
        processSpawned = false;
        fileWrite = false;
        fileRead = false;
        networkConnected = false;
        classLoaded = false;
        deserTriggered = false;
        sinkReached = null;
        sinksHit.clear();
        unattributedSinks = 0;
        classLoadTrigger = null;
        sinkAttribution.clear();
        valueToProperty = Collections.emptyMap();

        JdbcResult result = new JdbcResult();
        result.jdkVersion = System.getProperty("java.version");
        result.securityManager = System.getSecurityManager() != null;

        long start = System.currentTimeMillis();

        try {
            JsonObject ir = JsonParser.parseString(jsonStr).getAsJsonObject();

            String driver = getStr(ir, "driver");
            String driverClass = getStr(ir, "driver_class");
            String urlBase = getStr(ir, "jdbc_url_base");
            JsonObject urlParams = getObj(ir, "url_params");
            String pool = getStr(ir, "pool");
            JsonObject poolConfig = getObj(ir, "pool_config");
            JsonObject credentials = getObj(ir, "credentials");
            String sqlPayload = getNullableStr(ir, "sql_payload");
            JsonObject deserProps = getObj(ir, "deser_properties");

            result.driverClass = driverClass;
            result.driver = driver;
            result.poolType = pool.isEmpty() ? "none" : pool;
            result.jdbcUrl = urlBase;  // base URL (without exploit params)
            result.urlParamCount = urlParams != null ? urlParams.size() : 0;
            result.hasSqlPayload = sqlPayload != null && !sqlPayload.isEmpty();
            result.hasDeserProperties = deserProps != null && deserProps.size() > 0;

            // Step 1: Load JDBC driver
            long stepStart = System.currentTimeMillis();
            try {
                Class.forName(driverClass);
                result.driverLoaded = true;
            } catch (Throwable e) {
                result.driverLoaded = false;
                result.exceptionClass = e.getClass().getSimpleName();
                result.exception = "Driver load failed: " + e.getMessage();
                result.errorType = "class_not_found";
                result.failedStep = "driver_load";
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }
            result.driverLoadMs = System.currentTimeMillis() - stepStart;

            // Step 2: Check timeout cache
            String timeoutKey = driverClass + "|" + urlBase;
            Integer tCount = driverTimeoutCount.getOrDefault(timeoutKey, 0);
            if (tCount >= TIMEOUT_SKIP_THRESHOLD) {
                result.errorType = "connection_timeout_cached";
                result.exception = "Skipped: timed out " + tCount + " times";
                result.failedStep = "timeout_cache";
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }

            // Step 3: Build JDBC URL
            stepStart = System.currentTimeMillis();
            String jdbcUrl = buildJdbcUrl(driver, urlBase, urlParams);
            result.urlBuildMs = System.currentTimeMillis() - stepStart;
            result.builtUrl = jdbcUrl.length() > 512
                ? jdbcUrl.substring(0, 512) + "..." : jdbcUrl;

            // Step 4: Build connection properties
            Properties props = new Properties();
            if (credentials != null) {
                if (credentials.has("user"))
                    props.setProperty("user", credentials.get("user").getAsString());
                if (credentials.has("password"))
                    props.setProperty("password", credentials.get("password").getAsString());
            }
            // Add deserialization properties
            if (deserProps != null) {
                for (String key : deserProps.keySet()) {
                    props.setProperty(key, deserProps.get(key).getAsString());
                }
            }
            result.propCount = props.size();

            // Build value→property attribution map for class-name-like values
            Map<String, String> vtop = new HashMap<>();
            if (urlParams != null) {
                for (String key : urlParams.keySet()) {
                    String val = urlParams.get(key).getAsString();
                    if (looksLikeClassName(val)) {
                        vtop.put(val, "url_param:" + key);
                    }
                }
            }
            if (deserProps != null) {
                for (String key : deserProps.keySet()) {
                    String val = deserProps.get(key).getAsString();
                    if (looksLikeClassName(val)) {
                        vtop.put(val, "deser_prop:" + key);
                    }
                }
            }
            valueToProperty = vtop;
            // Store classNameProperties in result for Python-side processing
            if (!vtop.isEmpty()) {
                result.classNameProperties = new LinkedHashMap<>();
                for (Map.Entry<String, String> e : vtop.entrySet()) {
                    String prop = e.getValue();
                    // Reverse: property → class_name for easier Python lookup
                    String propName = prop.contains(":") ? prop.substring(prop.indexOf(':') + 1) : prop;
                    result.classNameProperties.put(propName, e.getKey());
                }
            }

            // Step 5: Connect (direct or pool)
            stepStart = System.currentTimeMillis();
            Connection conn = null;

            if ("none".equals(pool) || pool.isEmpty()) {
                conn = connectDirect(jdbcUrl, props, result, timeoutKey);
            } else {
                conn = connectViaPool(pool, jdbcUrl, props, poolConfig, result, timeoutKey);
            }
            result.connectionMs = System.currentTimeMillis() - stepStart;
            if (conn == null && result.failedStep == null) {
                result.failedStep = "connection";
            }

            // Step 6: Execute SQL payload if connection succeeded
            if (conn != null && sqlPayload != null && !sqlPayload.isEmpty()) {
                stepStart = System.currentTimeMillis();
                executeSql(conn, sqlPayload, result);
                result.sqlMs = System.currentTimeMillis() - stepStart;
                if (!result.sqlExecuted && result.failedStep == null) {
                    result.failedStep = "sql_exec";
                }
            }

            // Step 7: Clean up connection
            if (conn != null) {
                try { conn.close(); } catch (Exception ignore) {}
            }

        } catch (Throwable e) {
            result.exceptionClass = e.getClass().getName();
            result.exception = e.getMessage();
            result.errorType = classifyError(e);
        }

        // Collect tracking results
        result.processSpawned = processSpawned;
        result.fileWrite = fileWrite;
        result.fileRead = fileRead;
        result.networkConnected = networkConnected;
        result.classLoaded = classLoaded;
        result.deserTriggered = deserTriggered;
        result.sinkReached = sinkReached;
        result.sinksHit = new ArrayList<>(new LinkedHashSet<>(sinksHit));
        result.unattributedSinks = unattributedSinks;
        result.durationMs = System.currentTimeMillis() - start;
        result.classLoadTrigger = classLoadTrigger;
        if (!sinkAttribution.isEmpty()) {
            result.sinkAttribution = new LinkedHashMap<>(sinkAttribution);
        }

        return GSON.toJson(result);
    }

    // ── URL construction ─────────────────────────────────────────

    private static String buildJdbcUrl(String driver, String urlBase,
                                       JsonObject urlParams) {
        if (urlParams == null || urlParams.size() == 0) return urlBase;

        StringBuilder sb = new StringBuilder(urlBase);

        // Driver-specific URL parameter separator
        boolean useSemicolon = "h2".equals(driver) || "hsqldb".equals(driver)
            || "derby".equals(driver) || "sqlserver".equals(driver);

        boolean first = true;
        for (String key : urlParams.keySet()) {
            String value = urlParams.get(key).getAsString();
            if (useSemicolon) {
                sb.append(';').append(key).append('=').append(value);
            } else {
                sb.append(first && !urlBase.contains("?") ? '?' : '&');
                sb.append(key).append('=').append(value);
                first = false;
            }
        }

        return sb.toString();
    }

    // ── Direct connection ────────────────────────────────────────

    private static Connection connectDirect(String url, Properties props,
                                             JdbcResult result, String timeoutKey) {
        final Connection[] connHolder = {null};
        final Throwable[] errorHolder = {null};
        final long connIter = currentIteration;

        Thread connThread = new Thread(() -> {
            threadIteration.set(connIter);
            try {
                connHolder[0] = DriverManager.getConnection(url, props);
            } catch (Throwable e) {
                errorHolder[0] = e;
            }
        }, "jdbc-conn");
        connThread.setDaemon(true);
        connThread.start();
        try {
            connThread.join(2000);  // 2s timeout
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        if (connThread.isAlive()) {
            connThread.interrupt();
            driverTimeoutCount.merge(timeoutKey, 1, Integer::sum);
            result.errorType = "connection_timeout";
            result.exception = "Connection timed out";
            return null;
        }

        driverTimeoutCount.remove(timeoutKey);

        if (errorHolder[0] != null) {
            Throwable e = errorHolder[0];
            result.exceptionClass = e.getClass().getName();
            result.exception = e.getMessage();
            result.errorType = classifyError(e);
            return null;
        }

        if (connHolder[0] != null) {
            result.connected = true;
            try {
                DatabaseMetaData meta = connHolder[0].getMetaData();
                if (meta != null) {
                    result.driverName = meta.getDriverName();
                }
            } catch (Exception ignore) {}
        }

        return connHolder[0];
    }

    // ── Pool connection ──────────────────────────────────────────

    private static Connection connectViaPool(String pool, String url,
            Properties props, JsonObject poolConfig, JdbcResult result,
            String timeoutKey) {
        final Connection[] connHolder = {null};
        final Throwable[] errorHolder = {null};
        final long poolIter = currentIteration;

        Thread poolThread = new Thread(() -> {
            threadIteration.set(poolIter);
            try {
                String user = props.getProperty("user", "sa");
                String pass = props.getProperty("password", "");
                String driverClass = result.driverClass;

                switch (pool) {
                    case "dbcp2":
                        connHolder[0] = connectDbcp2(url, user, pass,
                            driverClass, poolConfig, result);
                        break;
                    case "hikari":
                        connHolder[0] = connectHikari(url, user, pass,
                            driverClass, poolConfig, result);
                        break;
                    case "c3p0":
                        connHolder[0] = connectC3p0(url, user, pass,
                            driverClass, poolConfig, result);
                        break;
                    case "druid":
                        connHolder[0] = connectDruid(url, user, pass,
                            driverClass, poolConfig, result);
                        break;
                    case "tomcat":
                        connHolder[0] = connectTomcatJdbc(url, user, pass,
                            driverClass, poolConfig, result);
                        break;
                    default:
                        result.errorType = "unknown_pool";
                        result.exception = "Unknown pool: " + pool;
                }
            } catch (Throwable e) {
                errorHolder[0] = e;
            }
        }, "jdbc-pool");
        poolThread.setDaemon(true);
        poolThread.start();
        try {
            poolThread.join(3000);  // 3s timeout for pools (init overhead)
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        if (poolThread.isAlive()) {
            poolThread.interrupt();
            driverTimeoutCount.merge(timeoutKey, 1, Integer::sum);
            result.errorType = "pool_timeout";
            result.exception = "Pool creation timed out";
            return null;
        }

        driverTimeoutCount.remove(timeoutKey);

        if (errorHolder[0] != null) {
            Throwable e = errorHolder[0];
            result.exceptionClass = e.getClass().getName();
            result.exception = e.getMessage();
            result.errorType = classifyError(e);
            return null;
        }

        return connHolder[0];
    }

    // ── DBCP2 ────────────────────────────────────────────────────

    private static Connection connectDbcp2(String url, String user, String pass,
            String driverClass, JsonObject poolConfig, JdbcResult result) throws Exception {
        Class<?> dsClass = Class.forName("org.apache.commons.dbcp2.BasicDataSource");
        Object ds = dsClass.getDeclaredConstructor().newInstance();
        result.poolCreated = true;

        invoke(ds, "setUrl", url);
        invoke(ds, "setUsername", user);
        invoke(ds, "setPassword", pass);
        invoke(ds, "setDriverClassName", driverClass);
        invoke(ds, "setMaxTotal", 1);
        invoke(ds, "setInitialSize", 0);

        // Lifecycle hooks
        if (poolConfig != null) {
            if (poolConfig.has("connectionInitSqls")) {
                String sql = poolConfig.get("connectionInitSqls").getAsString();
                List<String> sqls = Collections.singletonList(sql);
                Method m = dsClass.getMethod("setConnectionInitSqls", Collection.class);
                m.invoke(ds, sqls);
                result.lifecycleHookType = "connectionInitSqls";
            }
            if (poolConfig.has("validationQuery")) {
                invoke(ds, "setValidationQuery",
                    poolConfig.get("validationQuery").getAsString());
                invoke(ds, "setTestOnCreate", true);
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "validationQuery";
            }
        }

        Connection conn = ((javax.sql.DataSource) ds).getConnection();
        result.connected = true;
        if (result.lifecycleHookType != null) result.lifecycleHookExecuted = true;
        return conn;
    }

    // ── HikariCP ─────────────────────────────────────────────────

    private static Connection connectHikari(String url, String user, String pass,
            String driverClass, JsonObject poolConfig, JdbcResult result) throws Exception {
        Class<?> dsClass = Class.forName("com.zaxxer.hikari.HikariDataSource");
        Object ds = dsClass.getDeclaredConstructor().newInstance();
        result.poolCreated = true;

        invoke(ds, "setJdbcUrl", url);
        invoke(ds, "setUsername", user);
        invoke(ds, "setPassword", pass);
        invoke(ds, "setDriverClassName", driverClass);
        invoke(ds, "setMaximumPoolSize", 1);
        invoke(ds, "setMinimumIdle", 0);

        // Lifecycle hooks
        if (poolConfig != null) {
            if (poolConfig.has("connectionInitSql")) {
                invoke(ds, "setConnectionInitSql",
                    poolConfig.get("connectionInitSql").getAsString());
                result.lifecycleHookType = "connectionInitSql";
            }
            if (poolConfig.has("connectionTestQuery")) {
                invoke(ds, "setConnectionTestQuery",
                    poolConfig.get("connectionTestQuery").getAsString());
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "connectionTestQuery";
            }
        }

        Connection conn = ((javax.sql.DataSource) ds).getConnection();
        result.connected = true;
        if (result.lifecycleHookType != null) result.lifecycleHookExecuted = true;
        return conn;
    }

    // ── C3P0 ─────────────────────────────────────────────────────

    private static Connection connectC3p0(String url, String user, String pass,
            String driverClass, JsonObject poolConfig, JdbcResult result) throws Exception {
        Class<?> dsClass = Class.forName("com.mchange.v2.c3p0.ComboPooledDataSource");
        Object ds = dsClass.getDeclaredConstructor().newInstance();
        result.poolCreated = true;

        invoke(ds, "setJdbcUrl", url);
        invoke(ds, "setUser", user);
        invoke(ds, "setPassword", pass);
        invoke(ds, "setDriverClass", driverClass);
        invoke(ds, "setInitialPoolSize", 0);
        invoke(ds, "setMinPoolSize", 0);
        invoke(ds, "setMaxPoolSize", 1);

        // Lifecycle hooks
        if (poolConfig != null) {
            if (poolConfig.has("preferredTestQuery")) {
                invoke(ds, "setPreferredTestQuery",
                    poolConfig.get("preferredTestQuery").getAsString());
                invoke(ds, "setTestConnectionOnCheckout", true);
                result.lifecycleHookType = "preferredTestQuery";
            }
            if (poolConfig.has("connectionCustomizerClassName")) {
                invoke(ds, "setConnectionCustomizerClassName",
                    poolConfig.get("connectionCustomizerClassName").getAsString());
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "connectionCustomizerClassName";
            }
            if (poolConfig.has("userOverridesAsString")) {
                invoke(ds, "setUserOverridesAsString",
                    poolConfig.get("userOverridesAsString").getAsString());
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "userOverridesAsString";
                deserTriggered = true;
                sinksHit.add("deser");
            }
        }

        Connection conn = ((javax.sql.DataSource) ds).getConnection();
        result.connected = true;
        if (result.lifecycleHookType != null) result.lifecycleHookExecuted = true;
        return conn;
    }

    // ── Druid ────────────────────────────────────────────────────

    private static Connection connectDruid(String url, String user, String pass,
            String driverClass, JsonObject poolConfig, JdbcResult result) throws Exception {
        Class<?> dsClass = Class.forName("com.alibaba.druid.pool.DruidDataSource");
        Object ds = dsClass.getDeclaredConstructor().newInstance();
        result.poolCreated = true;

        invoke(ds, "setUrl", url);
        invoke(ds, "setUsername", user);
        invoke(ds, "setPassword", pass);
        invoke(ds, "setDriverClassName", driverClass);
        invoke(ds, "setMaxActive", 1);
        invoke(ds, "setInitialSize", 0);

        // Lifecycle hooks
        if (poolConfig != null) {
            if (poolConfig.has("initConnectionSqls")) {
                String sql = poolConfig.get("initConnectionSqls").getAsString();
                List<String> sqls = Collections.singletonList(sql);
                // Druid uses setConnectionInitSqls(Collection)
                Method m = dsClass.getMethod("setConnectionInitSqls", Collection.class);
                m.invoke(ds, sqls);
                result.lifecycleHookType = "initConnectionSqls";
            }
            if (poolConfig.has("validationQuery")) {
                invoke(ds, "setValidationQuery",
                    poolConfig.get("validationQuery").getAsString());
                invoke(ds, "setTestOnReturn", true);
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "validationQuery";
            }
            if (poolConfig.has("init") && "true".equals(
                    poolConfig.get("init").getAsString())) {
                // Call init() to eagerly initialize pool
                Method initMethod = dsClass.getMethod("init");
                initMethod.invoke(ds);
            }
        }

        Connection conn = ((javax.sql.DataSource) ds).getConnection();
        result.connected = true;
        if (result.lifecycleHookType != null) result.lifecycleHookExecuted = true;
        return conn;
    }

    // ── Tomcat JDBC Pool ─────────────────────────────────────────

    private static Connection connectTomcatJdbc(String url, String user, String pass,
            String driverClass, JsonObject poolConfig, JdbcResult result) throws Exception {
        Class<?> dsClass = Class.forName("org.apache.tomcat.jdbc.pool.DataSource");
        Object ds = dsClass.getDeclaredConstructor().newInstance();
        result.poolCreated = true;

        invoke(ds, "setUrl", url);
        invoke(ds, "setUsername", user);
        invoke(ds, "setPassword", pass);
        invoke(ds, "setDriverClassName", driverClass);
        invoke(ds, "setMaxActive", 1);
        invoke(ds, "setInitialSize", 0);

        // Lifecycle hooks
        if (poolConfig != null) {
            if (poolConfig.has("initSQL")) {
                invoke(ds, "setInitSQL",
                    poolConfig.get("initSQL").getAsString());
                result.lifecycleHookType = "initSQL";
            }
            if (poolConfig.has("validationQuery")) {
                invoke(ds, "setValidationQuery",
                    poolConfig.get("validationQuery").getAsString());
                invoke(ds, "setTestOnConnect", true);
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "validationQuery";
            }
            if (poolConfig.has("jdbcInterceptors")) {
                invoke(ds, "setJdbcInterceptors",
                    poolConfig.get("jdbcInterceptors").getAsString());
                if (result.lifecycleHookType == null)
                    result.lifecycleHookType = "jdbcInterceptors";
            }
        }

        Connection conn = ((javax.sql.DataSource) ds).getConnection();
        result.connected = true;
        if (result.lifecycleHookType != null) result.lifecycleHookExecuted = true;
        return conn;
    }

    // ── SQL execution ────────────────────────────────────────────

    private static void executeSql(Connection conn, String sqlPayload,
                                   JdbcResult result) {
        final Throwable[] errorHolder = {null};
        final boolean[] executed = {false};
        final long sqlIter = currentIteration;

        Thread sqlThread = new Thread(() -> {
            threadIteration.set(sqlIter);
            try {
                Statement stmt = conn.createStatement();
                try {
                    // Try executing as-is first (driver may handle multi-statement)
                    boolean hasResult = stmt.execute(sqlPayload);
                    executed[0] = true;
                    if (hasResult) {
                        ResultSet rs = stmt.getResultSet();
                        if (rs != null) {
                            try { rs.next(); } catch (Exception ignore) {}
                            rs.close();
                        }
                    }
                } catch (Throwable singleErr) {
                    // Fallback: split on ;\n or ; and execute each statement
                    String[] parts = sqlPayload.split(";\\s*\\n|;(?=\\s*[A-Z])");
                    if (parts.length > 1) {
                        for (String part : parts) {
                            String trimmed = part.trim();
                            if (trimmed.isEmpty()) continue;
                            try {
                                boolean hasResult = stmt.execute(trimmed);
                                executed[0] = true;
                                if (hasResult) {
                                    ResultSet rs = stmt.getResultSet();
                                    if (rs != null) {
                                        try { rs.next(); } catch (Exception ignore) {}
                                        rs.close();
                                    }
                                }
                            } catch (Throwable partErr) {
                                // Keep going — later stmts may succeed after setup
                                if (errorHolder[0] == null) errorHolder[0] = partErr;
                            }
                        }
                    } else {
                        throw singleErr;
                    }
                } finally {
                    stmt.close();
                }
            } catch (Throwable e) {
                if (errorHolder[0] == null) errorHolder[0] = e;
            }
        }, "jdbc-sql");
        sqlThread.setDaemon(true);
        sqlThread.start();
        try {
            sqlThread.join(1000);  // 1s timeout for SQL
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }

        if (sqlThread.isAlive()) {
            sqlThread.interrupt();
            result.errorType = "sql_timeout";
            return;
        }

        if (executed[0]) {
            result.sqlExecuted = true;
            sinksHit.add("sql_exec");
            if (sinkReached == null) sinkReached = "sql_exec";
        }

        if (errorHolder[0] != null) {
            Throwable e = errorHolder[0];
            // SQL error doesn't override connection success
            if (result.exception == null) {
                result.exceptionClass = e.getClass().getName();
                result.exception = e.getMessage();
                if (result.errorType == null)
                    result.errorType = classifyError(e);
            }
        }
    }

    // ── Reflection helpers ───────────────────────────────────────

    private static void invoke(Object obj, String methodName, String value) {
        try {
            Method m = obj.getClass().getMethod(methodName, String.class);
            m.invoke(obj, value);
        } catch (Exception ignore) {}
    }

    private static void invoke(Object obj, String methodName, int value) {
        try {
            Method m = obj.getClass().getMethod(methodName, int.class);
            m.invoke(obj, value);
        } catch (Exception ignore) {}
    }

    private static void invoke(Object obj, String methodName, boolean value) {
        try {
            Method m = obj.getClass().getMethod(methodName, boolean.class);
            m.invoke(obj, value);
        } catch (Exception ignore) {}
    }

    // ── Error classification ─────────────────────────────────────

    private static String classifyError(Throwable e) {
        String name = e.getClass().getSimpleName();
        String msg = e.getMessage() != null ? e.getMessage() : "";

        if (name.contains("ClassNotFoundException") || name.contains("NoClassDefFoundError"))
            return "class_not_found";
        if (name.contains("SecurityException")) return "security_exception";
        if (name.contains("SQLException")) return "sql_error";
        if (name.contains("NoSuchMethodException")) return "no_such_method";
        if (e instanceof InvocationTargetException && e.getCause() != null)
            return classifyError(e.getCause());
        if (msg.contains("driver")) return "driver_not_found";
        if (msg.contains("refused") || msg.contains("timeout")) return "connection_refused";
        if (msg.contains("denied")) return "security_exception";
        return "other";
    }

    /** Returns true if the value looks like a Java FQCN (e.g. "org.h2.Driver"). */
    private static boolean looksLikeClassName(String val) {
        if (val == null || val.isEmpty() || val.length() > 256) return false;
        // Must contain at least one dot and no spaces
        if (!val.contains(".") || val.contains(" ")) return false;
        // First segment should start with lowercase (package)
        char first = val.charAt(0);
        return first >= 'a' && first <= 'z';
    }

    private static String getStr(JsonObject obj, String key) {
        if (obj.has(key) && obj.get(key).isJsonPrimitive()) {
            return obj.get(key).getAsString();
        }
        return "";
    }

    private static String getNullableStr(JsonObject obj, String key) {
        if (!obj.has(key) || obj.get(key).isJsonNull()) return null;
        if (obj.get(key).isJsonPrimitive()) return obj.get(key).getAsString();
        return null;
    }

    private static JsonObject getObj(JsonObject obj, String key) {
        if (obj.has(key) && obj.get(key).isJsonObject()) {
            return obj.getAsJsonObject(key);
        }
        return null;
    }

    // ── Tracking SecurityManager ─────────────────────────────────

    static class TrackingSecurityManager extends SecurityManager {
        // Recursion guard — even ThreadLocal.get() triggers class loading,
        // so use a plain volatile (processOne is single-threaded).
        private static volatile boolean inPackageCheck = false;

        @Override
        public void checkExec(String cmd) {
            if (isCurrentIteration()) {
                processSpawned = true;
                if (sinkReached == null) sinkReached = "cmd_exec";
                sinksHit.add("cmd_exec");
            } else {
                unattributedSinks++;
            }
            throw new SecurityException("blocked: exec " + cmd);
        }

        @Override
        public void checkConnect(String host, int port) {
            if (isCurrentIteration()) {
                networkConnected = true;
                sinksHit.add("network");
            } else {
                unattributedSinks++;
            }
            throw new SecurityException("blocked: connect " + host + ":" + port);
        }

        @Override
        public void checkConnect(String host, int port, Object context) {
            if (isCurrentIteration()) {
                networkConnected = true;
                sinksHit.add("network");
            } else {
                unattributedSinks++;
            }
            throw new SecurityException("blocked: connect " + host + ":" + port);
        }

        @Override
        public void checkWrite(String file) {
            if (isCurrentIteration()) {
                fileWrite = true;
                sinksHit.add("file_write");
                if (sinkReached == null) sinkReached = "file_write";
            } else {
                unattributedSinks++;
            }
            throw new SecurityException("blocked: write " + file);
        }

        @Override
        public void checkRead(String file) {
            // Allow reads for classloading, but track non-classpath reads
            if (isCurrentIteration() && !file.endsWith(".class")
                    && !file.endsWith(".jar") && !file.contains("jre")
                    && !file.contains("jdk")) {
                fileRead = true;
                sinksHit.add("file_read");
            }
        }

        @Override
        public void checkPackageAccess(String pkg) {
            if (!isCurrentIteration()) return;
            if (inPackageCheck) return;  // recursion guard
            inPackageCheck = true;
            try {
                // Check if any class-name property value's package matches
                Map<String, String> vtop = valueToProperty;
                if (vtop != null && !vtop.isEmpty()) {
                    for (Map.Entry<String, String> e : vtop.entrySet()) {
                        String className = e.getKey();
                        // Class "a.b.ClassName" → package "a.b"
                        int lastDot = className.lastIndexOf('.');
                        if (lastDot > 0) {
                            String classPkg = className.substring(0, lastDot);
                            if (classPkg.equals(pkg) || pkg.startsWith(classPkg + ".")) {
                                classLoaded = true;
                                sinksHit.add("class_load");
                                if (classLoadTrigger == null) {
                                    classLoadTrigger = e.getValue();
                                }
                                sinkAttribution.putIfAbsent("class_load", e.getValue());
                                break;
                            }
                        }
                    }
                }
            } finally {
                inPackageCheck = false;
            }
        }

        @Override
        public void checkPermission(java.security.Permission perm) {
            if (!isCurrentIteration()) return;
            String name = perm.getName();
            if (name != null) {
                if (name.startsWith("exec") || name.equals("executeCommand")) {
                    processSpawned = true;
                    sinksHit.add("cmd_exec");
                    if (sinkReached == null) sinkReached = "cmd_exec";
                } else if (name.startsWith("connect") || name.startsWith("resolve")) {
                    networkConnected = true;
                    sinksHit.add("network");
                }
            }
        }

        @Override
        public void checkPermission(java.security.Permission perm, Object context) {
            checkPermission(perm);
        }
    }

    // ── Result DTO ───────────────────────────────────────────────

    static class JdbcResult {
        // --- Core outcome ---
        boolean connected = false;
        boolean driverLoaded = false;
        String driver = "";             // short name (h2, hsqldb, mysql, ...)
        String driverClass = "";
        String driverName = null;       // from DatabaseMetaData
        boolean poolCreated = false;
        String poolType = "none";
        boolean lifecycleHookExecuted = false;
        String lifecycleHookType = null;
        boolean sqlExecuted = false;
        String sqlResultType = null;

        // --- Sink tracking ---
        String sinkReached = null;      // highest-severity sink
        List<String> sinksHit = new ArrayList<>();
        int unattributedSinks = 0;
        boolean processSpawned = false;
        boolean fileRead = false;
        boolean fileWrite = false;
        boolean networkConnected = false;
        boolean classLoaded = false;
        boolean deserTriggered = false;

        // --- Sink attribution ---
        Map<String, String> classNameProperties = null;  // {prop_name: class_value}
        String classLoadTrigger = null;                  // "url_param:PROP" or "deser_prop:PROP"
        Map<String, String> sinkAttribution = null;      // {sink_type: "url_param:PROP"}

        // --- Error details ---
        String exceptionClass = null;
        String exception = null;
        String errorType = null;
        String failedStep = null;       // which step failed (driver_load, timeout_cache, connection, sql_exec)

        // --- Step-level timing (ms) ---
        long durationMs = 0;            // total wall time
        long driverLoadMs = 0;          // Step 1: Class.forName()
        long urlBuildMs = 0;            // Step 3: URL construction
        long connectionMs = 0;          // Step 5: getConnection() or pool create+connect
        long sqlMs = 0;                 // Step 6: Statement.execute()

        // --- Debug / input echo ---
        String jdbcUrl = "";            // base URL (for debugging)
        String builtUrl = null;         // full URL after param injection (truncated to 512 chars)
        int urlParamCount = 0;          // number of URL params injected
        int propCount = 0;              // number of connection properties
        boolean hasSqlPayload = false;  // whether sql_payload was non-null
        boolean hasDeserProperties = false; // whether deser_properties was non-empty

        // --- Environment ---
        String jdkVersion = "";
        boolean securityManager = false;
    }
}
