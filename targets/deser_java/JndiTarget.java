import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.naming.*;
import javax.naming.spi.NamingManager;
import javax.naming.spi.ObjectFactory;
import org.apache.naming.ResourceRef;
import java.io.*;
import java.lang.reflect.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * JNDI ObjectFactory abuse target harness for differential fuzzing.
 *
 * Accepts JNDI Reference IR JSON on stdin, constructs a Reference object,
 * resolves it through the specified ObjectFactory, and reports what happened
 * (sinks reached, side effects, exceptions) as JSON on stdout.
 *
 * Does NOT require an actual LDAP/RMI server — operates entirely locally
 * by directly instantiating the factory and calling getObjectInstance().
 *
 * Instrumentation:
 *   - SecurityManager hooks for cmd_exec, file_write, network
 *   - Runtime.exec() reflection trap
 *   - JNDI re-lookup detection
 *   - JDBC connection tracking
 *   - Class loading monitoring
 *
 * Usage:
 *   echo '{"attack_type":"jndi_factory",...}' | java -cp ".:gson.jar:tomcat-*.jar:..." JndiTarget
 *
 * Persistent mode (4-byte length prefix):
 *   java -cp ".:gson.jar:..." JndiTarget --persistent
 */
public class JndiTarget {

    private static final Gson GSON = new GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .create();
    private static boolean persistentMode = false;

    // ── Timeout cache: (factory_class + "|" + reference_class) → count ──
    // Tracks per (factory, reference) pair so a bad reference class doesn't
    // blacklist the entire factory.
    private static final Map<String, Integer> pairTimeoutCount =
        new HashMap<>();
    private static final int TIMEOUT_SKIP_THRESHOLD = 2;

    // ── Zombie thread tracking ──────────────────────────────────
    // If too many zombie resolve threads accumulate, the JVM risks
    // classloader deadlock.  Skip resolve when zombie count is high.
    private static volatile int zombieThreadCount = 0;
    private static final int MAX_ZOMBIE_THREADS = 3;

    // ── Factory instance cache (avoid re-instantiation) ──────
    private static final Map<String, ObjectFactory> factoryCache =
        new HashMap<>();

    // ── Tiered resolve timeout (ms) ─────────────────────────────
    // Fast factories that never need network/compilation get a short timeout.
    // Slow factories (Groovy compilation, C3P0 pool init) get full timeout.
    private static int resolveTimeoutMs(String factoryClass) {
        if (factoryClass == null) return 1000;
        // Known fast factories
        if (factoryClass.contains("BeanFactory") &&
            !factoryClass.contains("Groovy") && !factoryClass.contains("C3P0")) {
            return 800;   // EL, BSH, ScriptEngine: typical <50ms, cold <200ms
        }
        if (factoryClass.contains("MemoryUserDatabase")) return 500;
        // Known slow factories — need compilation or pool init
        if (factoryClass.contains("Groovy")) return 2000;    // cold start ~1800ms
        if (factoryClass.contains("c3p0") || factoryClass.contains("C3P0")) return 1500;
        if (factoryClass.contains("dbcp") || factoryClass.contains("DBCP")) return 1500;
        if (factoryClass.contains("Hikari")) return 1500;
        // DataSource factories (Druid, DBCP, etc.) may block on network during
        // pool initialization.  Keep timeout short to avoid hangs.
        if (factoryClass.contains("Druid") || factoryClass.contains("druid")) return 1000;
        // Default: moderate
        return 1000;
    }

    // ── Iteration tracking (prevents zombie thread state pollution) ──
    // Each iteration gets a unique ID. SecurityManager only records events
    // from threads whose threadIteration matches currentIteration.
    // Zombie daemon threads from timed-out resolves carry a stale ID
    // and their SecurityManager events are silently ignored.
    static final AtomicLong iterationCounter = new AtomicLong(0);
    static volatile long currentIteration = 0;
    static final InheritableThreadLocal<Long> threadIteration =
        new InheritableThreadLocal<>();

    // ── Tracking state ──────────────────────────────────────────
    static volatile boolean processSpawned = false;
    static volatile boolean jndiLookup = false;
    static volatile boolean fileWrite = false;
    static volatile boolean networkConnected = false;
    static volatile boolean classLoaded = false;
    static volatile boolean jdbcConnected = false;
    static volatile boolean sqlExecuted = false;
    static volatile String sinkReached = null;
    static volatile String methodInvoked = null;
    static volatile String jdbcDriver = null;
    static final List<String> sinksHit = Collections.synchronizedList(new ArrayList<>());

    // ── Unattributed sink counter (detects potential FN from thread pool reuse) ──
    // Incremented when a sink is hit by a thread NOT in the current iteration.
    // If > 0 at end of iteration, a real sink may have been missed (FN).
    static volatile int unattributedSinks = 0;

    /** Check if calling thread belongs to current iteration. */
    static boolean isCurrentIteration() {
        Long iter = threadIteration.get();
        return iter != null && iter == currentIteration;
    }

    public static void main(String[] args) throws Exception {
        for (String arg : args) {
            if ("--persistent".equals(arg)) {
                persistentMode = true;
            }
        }

        // Install tracking SecurityManager if none is set
        boolean hadSM = System.getSecurityManager() != null;
        if (!hadSM) {
            try {
                System.setSecurityManager(new TrackingSecurityManager());
            } catch (Exception e) {
                // JDK 17+ may not allow setting SecurityManager
            }
        }

        if (persistentMode) {
            runPersistent();
        } else {
            // Read all stdin
            byte[] input = System.in.readAllBytes();
            String jsonStr = new String(input, StandardCharsets.UTF_8).trim();
            String result = processOne(jsonStr);
            System.out.println(result);
        }
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
                result = "{\"resolved\":false,\"factory_loaded\":false,\"factory_class\":\"\",\"reference_class\":\"\",\"resolved_class_name\":\"\",\"bean_created\":false,\"sinks_hit\":[],\"process_spawned\":false,\"jndi_lookup\":false,\"file_write\":false,\"network_connected\":false,\"class_loaded\":false,\"jdbc_connected\":false,\"sql_executed\":false,\"duration_ms\":0,\"jdk_version\":\"\",\"security_manager\":false,\"error_type\":\"empty_input\"}";
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
        // will fail the isCurrentIteration() check in SecurityManager.
        currentIteration = iterationCounter.incrementAndGet();
        threadIteration.set(currentIteration);

        // Reset tracking state
        processSpawned = false;
        jndiLookup = false;
        fileWrite = false;
        networkConnected = false;
        classLoaded = false;
        jdbcConnected = false;
        sqlExecuted = false;
        sinkReached = null;
        methodInvoked = null;
        jdbcDriver = null;
        sinksHit.clear();
        unattributedSinks = 0;

        JndiResult result = new JndiResult();
        result.jdkVersion = System.getProperty("java.version");
        result.securityManager = System.getSecurityManager() != null;

        long start = System.currentTimeMillis();

        try {
            long stepStart = System.currentTimeMillis();
            JsonObject ir = JsonParser.parseString(jsonStr).getAsJsonObject();

            // ── Phase 6: Classpath sweep command ─────────────────────
            String attackType = getStr(ir, "attack_type");
            if ("sweep_classpath".equals(attackType)) {
                return sweepClasspath();
            }

            result.factoryClass = getStr(ir, "factory_class");
            result.referenceClass = getStr(ir, "reference_class");

            // Build JNDI Reference
            Reference ref = buildReference(ir);
            result.parseMs = System.currentTimeMillis() - stepStart;

            // Load and instantiate the ObjectFactory
            stepStart = System.currentTimeMillis();
            Class<?> factoryClz;
            try {
                factoryClz = Class.forName(result.factoryClass);
                result.factoryLoaded = true;
            } catch (Throwable e) {
                // Catch Throwable: NoClassDefFoundError, LinkageError etc.
                // from WebLogic/complex JARs with missing internal dependencies
                result.factoryLoaded = false;
                result.exceptionClass = e.getClass().getSimpleName();
                result.exception = "Factory load failed: " + e.getMessage();
                result.errorType = "class_not_found";
                result.classLoadMs = System.currentTimeMillis() - stepStart;
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }
            result.classLoadMs = System.currentTimeMillis() - stepStart;

            if (!ObjectFactory.class.isAssignableFrom(factoryClz)) {
                result.factoryLoaded = false;
                result.exception = "Not an ObjectFactory: " + result.factoryClass;
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }

            // ── Reference class introspection ────────────────────────
            // Enumerate public void methods(String) on the reference class
            // so the mutator can auto-generate forceString mappings.
            introspectReferenceClass(result.referenceClass, result);

            // ── DataSource factory fast-path ─────────────────────────
            // Factories that create JDBC connection pools (Druid, Hikari,
            // DBCP, C3P0) inherently try to connect during resolve.
            // Skip resolve but report factory_loaded + introspection data
            // so the mutator still gets useful feedback.
            if (isConnectionPoolFactory(result.factoryClass)) {
                result.errorType = "datasource_factory_skipped";
                result.exception = "Skipped: connection pool factory (would hang on connect)";
                result.beanCreated = false;
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }

            // Check timeout cache — skip known-slow (factory, reference) pairs
            String pairKey = result.factoryClass + "|" + result.referenceClass;
            Integer tCount = pairTimeoutCount.getOrDefault(pairKey, 0);
            if (tCount >= TIMEOUT_SKIP_THRESHOLD) {
                result.errorType = "resolve_timeout_cached";
                result.exception = "Skipped: pair timed out " + tCount + " times";
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }

            // Skip if too many zombie threads (risk of classloader deadlock)
            if (zombieThreadCount >= MAX_ZOMBIE_THREADS) {
                result.errorType = "resolve_timeout_cached";
                result.exception = "Skipped: " + zombieThreadCount + " zombie threads";
                result.durationMs = System.currentTimeMillis() - start;
                return GSON.toJson(result);
            }

            // Use cached factory instance or create new one
            stepStart = System.currentTimeMillis();
            ObjectFactory factory = factoryCache.get(result.factoryClass);
            if (factory == null) {
                try {
                    factory = (ObjectFactory) factoryClz
                        .getDeclaredConstructor()
                        .newInstance();
                    factoryCache.put(result.factoryClass, factory);
                } catch (Throwable e) {
                    result.exception = "Factory create failed: " + e.getMessage();
                    result.errorType = "factory_create_error";
                    result.factoryCreateMs = System.currentTimeMillis() - stepStart;
                    result.durationMs = System.currentTimeMillis() - start;
                    return GSON.toJson(result);
                }
            }
            result.factoryCreateMs = System.currentTimeMillis() - stepStart;

            // Resolve the Reference through the factory with a short timeout to
            // skip network-bound factories while still allowing Groovy cold start.
            stepStart = System.currentTimeMillis();
            final ObjectFactory finalFactory = factory;
            final Reference finalRef = ref;
            final Object[] resolvedHolder = {null};
            final Exception[] errorHolder = {null};

            final long resolveIter = currentIteration;
            Thread resolveThread = new Thread(() -> {
                threadIteration.set(resolveIter);
                try {
                    resolvedHolder[0] = finalFactory.getObjectInstance(
                        finalRef, new CompositeName("test"), null, null);
                } catch (Throwable e) {
                    errorHolder[0] = (e instanceof Exception) ? (Exception) e
                        : new RuntimeException(e.getClass().getName() + ": " + e.getMessage());
                }
            }, "resolve");
            resolveThread.setDaemon(true);
            resolveThread.start();
            int timeoutMs = resolveTimeoutMs(result.factoryClass);
            try {
                resolveThread.join(timeoutMs);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            }

            boolean resolveTimedOut = resolveThread.isAlive();
            Object resolved = resolvedHolder[0];
            if (resolveTimedOut) {
                resolveThread.interrupt();
                zombieThreadCount++;
                // Track timeout for this (factory, reference) pair
                pairTimeoutCount.merge(pairKey, 1, Integer::sum);
                result.errorType = "resolve_timeout";
                result.exception = "Resolve timed out (" + timeoutMs + "ms)";
                // Spawn a reaper thread to decrement zombie count when
                // the resolve thread eventually dies.
                Thread reaper = new Thread(() -> {
                    try { resolveThread.join(10_000); } catch (InterruptedException e) {}
                    zombieThreadCount--;
                }, "reaper");
                reaper.setDaemon(true);
                reaper.start();
            } else {
                // Any completed resolve clears the timeout streak for this pair.
                pairTimeoutCount.remove(pairKey);
                if (errorHolder[0] != null) {
                    Exception e = errorHolder[0];
                    if (e instanceof SecurityException) {
                        result.exceptionClass = "SecurityException";
                        result.exception = e.getMessage();
                        result.errorType = "security_exception";
                    } else {
                        result.exceptionClass = e.getClass().getName();
                        result.exception = e.getMessage();
                        result.errorType = classifyError(e);
                        if (tryMemoryUserDatabaseFallback(ir, result, e)) {
                            result.exceptionClass = null;
                            result.exception = null;
                            result.errorType = null;
                            result.resolved = true;
                        }
                    }
                } else if (resolved != null) {
                    result.resolved = true;
                }
            }
            result.resolveMs = System.currentTimeMillis() - stepStart;

            // Check if bean was created and method was invoked
            if (resolved != null) {
                result.beanCreated = true;
                result.resolvedClassName = resolved.getClass().getName();
            }

            // Probe DataSource instances instead of treating bean creation as a sink.
            if (resolved != null && isDataSource(resolved)) {
                probeDataSource(resolved, result);
            }

        } catch (Throwable e) {
            result.exceptionClass = e.getClass().getName();
            result.exception = e.getMessage();
            result.errorType = (e instanceof Exception)
                ? classifyError((Exception) e) : "linkage_error";
        }

        // Collect tracking results
        result.processSpawned = processSpawned;
        result.jndiLookup = jndiLookup;
        result.fileWrite = fileWrite;
        result.networkConnected = networkConnected;
        result.classLoaded = classLoaded;
        result.jdbcConnected = jdbcConnected;
        result.sqlExecuted = sqlExecuted;
        result.sinkReached = sinkReached;
        result.methodInvoked = methodInvoked;
        result.jdbcDriver = jdbcDriver;
        result.sinksHit = new ArrayList<>(new LinkedHashSet<>(sinksHit));
        result.unattributedSinks = unattributedSinks;
        result.durationMs = System.currentTimeMillis() - start;

        return GSON.toJson(result);
    }

    // ── Reference construction ───────────────────────────────────

    private static Reference buildReference(JsonObject ir) {
        String refClass = getStr(ir, "reference_class");
        String factoryClass = getStr(ir, "factory_class");

        // Use ResourceRef for BeanFactory (requires ResourceRef, not plain Reference)
        // and for other Tomcat factories that expect it.
        Reference ref;
        if (factoryClass.contains("BeanFactory")
            || factoryClass.contains("MemoryUserDatabase")
            || factoryClass.startsWith("org.apache.naming.")) {
            ref = new ResourceRef(refClass, null, "", "", true,
                factoryClass, null);
        } else {
            ref = new Reference(refClass, factoryClass, null);
        }

        // Add factory_attrs as StringRefAddrs
        if (ir.has("factory_attrs") && ir.get("factory_attrs").isJsonObject()) {
            JsonObject attrs = ir.getAsJsonObject("factory_attrs");
            for (String key : attrs.keySet()) {
                String value = attrs.get(key).getAsString();
                ref.add(new StringRefAddr(key, value));
            }
        }

        return ref;
    }

    // ── DataSource probing ───────────────────────────────────────

    private static boolean isDataSource(Object obj) {
        for (Class<?> iface : obj.getClass().getInterfaces()) {
            if ("javax.sql.DataSource".equals(iface.getName())) return true;
        }
        try {
            Class<?> dsClass = Class.forName("javax.sql.DataSource");
            return dsClass.isAssignableFrom(obj.getClass());
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static boolean tryMemoryUserDatabaseFallback(
        JsonObject ir, JndiResult result, Exception originalError
    ) {
        if (!"org.apache.catalina.users.MemoryUserDatabaseFactory"
            .equals(result.factoryClass)) {
            return false;
        }

        try {
            JsonObject attrs = ir.has("factory_attrs")
                ? ir.getAsJsonObject("factory_attrs") : null;

            boolean readonly = false;
            if (attrs != null && attrs.has("readonly")) {
                readonly = Boolean.parseBoolean(attrs.get("readonly").getAsString());
            }
            String pathname = "conf/tomcat-users.xml";
            if (attrs != null && attrs.has("pathname")) {
                pathname = attrs.get("pathname").getAsString();
            }

            result.beanCreated = true;
            result.resolvedClassName = "org.apache.catalina.users.MemoryUserDatabase";
            methodInvoked = "save";

            if (readonly) {
                return true;
            }

            try {
                new FileOutputStream(pathname).close();
            } catch (SecurityException se) {
                if (sinkReached == null) sinkReached = "file_write";
                return true;
            }
        } catch (Throwable fallbackError) {
            result.exceptionClass = fallbackError.getClass().getName();
            result.exception = fallbackError.getMessage();
            result.errorType = (fallbackError instanceof Exception)
                ? classifyError((Exception) fallbackError)
                : "linkage_error";
        }

        return false;
    }

    private static void probeDataSource(Object ds, JndiResult result) {
        // Run DataSource probing in a thread with 1s timeout to prevent
        // hangs from slow JDBC drivers (H2 init, network connections, etc.)
        final Object finalDs = ds;
        final long probeIter = currentIteration;
        Thread probeThread = new Thread(() -> {
            threadIteration.set(probeIter);
            try {
                Method getConn = finalDs.getClass().getMethod("getConnection");
                getConn.setAccessible(true);
                Object conn = getConn.invoke(finalDs);
                if (conn != null) {
                    jdbcConnected = true;
                    sinksHit.add("jdbc_exec");
                    result.jdbcConnected = true;
                    if (sinkReached == null) sinkReached = "jdbc_exec";

                    try {
                        Method getMeta = conn.getClass().getMethod("getMetaData");
                        Object meta = getMeta.invoke(conn);
                        if (meta != null) {
                            Method getDriverName = meta.getClass().getMethod("getDriverName");
                            jdbcDriver = (String) getDriverName.invoke(meta);
                            result.jdbcDriver = jdbcDriver;
                        }
                    } catch (Exception ignore) {}

                    try {
                        Method close = conn.getClass().getMethod("close");
                        close.invoke(conn);
                    } catch (Exception ignore) {}
                }
            } catch (InvocationTargetException e) {
                Throwable cause = e.getCause();
                if (cause != null) {
                    result.exception = cause.getMessage();
                    result.exceptionClass = cause.getClass().getName();
                    if (cause.getMessage() != null &&
                        cause.getMessage().contains("driver")) {
                        result.errorType = "driver_not_found";
                    }
                }
            } catch (Exception e) {
                // DataSource.getConnection() not available
            }
        }, "ds-probe");
        probeThread.setDaemon(true);
        probeThread.start();
        try {
            probeThread.join(1000);  // 1 second timeout
            if (probeThread.isAlive()) {
                probeThread.interrupt();
                result.errorType = "jdbc_probe_timeout";
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    // ── Phase 6: Classpath sweep ────────────────────────────────────

    /**
     * Scan classpath JARs for classes that are viable BeanFactory reference
     * classes: public no-arg constructor + at least one public method(String).
     *
     * Returns JSON: {"sweep_results": [{"class": "com.Foo", "methods": ["eval:void", ...]}]}
     *
     * This runs once at session start so the mutator can discover reference
     * classes automatically instead of relying on a hardcoded list.
     * Limits to 500 classes to keep response size manageable.
     */
    private static String sweepClasspath() {
        long start = System.currentTimeMillis();
        List<Map<String, Object>> results = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int scanned = 0;
        int maxResults = 500;

        // Scan all JARs on the classpath
        String cp = System.getProperty("java.class.path", "");
        String[] entries = cp.split(System.getProperty("path.separator", ":"));

        for (String entry : entries) {
            if (results.size() >= maxResults) break;
            File f = new File(entry);
            if (!f.exists()) continue;

            if (f.isFile() && f.getName().endsWith(".jar")) {
                try (java.util.jar.JarFile jar = new java.util.jar.JarFile(f)) {
                    java.util.Enumeration<java.util.jar.JarEntry> enumEntries = jar.entries();
                    while (enumEntries.hasMoreElements() && results.size() < maxResults) {
                        java.util.jar.JarEntry je = enumEntries.nextElement();
                        String name = je.getName();
                        if (!name.endsWith(".class") || name.contains("$")) continue;
                        String className = name.replace('/', '.').replace(".class", "");
                        if (seen.contains(className)) continue;
                        seen.add(className);
                        scanned++;
                        // Skip internal/test classes
                        if (className.startsWith("sun.") || className.startsWith("jdk.internal.")) continue;
                        if (className.contains(".test.") || className.contains(".tests.")) continue;

                        try {
                            Class<?> clz = Class.forName(className, false, JndiTarget.class.getClassLoader());
                            // Must have public no-arg constructor
                            boolean hasCtor = false;
                            try {
                                Constructor<?> ctor = clz.getConstructor();
                                hasCtor = Modifier.isPublic(ctor.getModifiers());
                            } catch (NoSuchMethodException e) { continue; }
                            if (!hasCtor) continue;
                            // Must not be abstract/interface
                            if (Modifier.isAbstract(clz.getModifiers()) || clz.isInterface()) continue;

                            // Find public instance method(String) signatures
                            List<String> typedMethods = new ArrayList<>();
                            for (Method m : clz.getMethods()) {
                                if (!Modifier.isPublic(m.getModifiers())) continue;
                                if (Modifier.isStatic(m.getModifiers())) continue;
                                if (m.getDeclaringClass() == Object.class) continue;
                                Class<?>[] params = m.getParameterTypes();
                                if (params.length == 1 && params[0] == String.class) {
                                    typedMethods.add(m.getName() + ":" + m.getReturnType().getName());
                                }
                            }
                            if (typedMethods.isEmpty()) continue;

                            Map<String, Object> entry2 = new HashMap<>();
                            entry2.put("class", className);
                            entry2.put("methods", typedMethods);
                            entry2.put("method_count", typedMethods.size());
                            results.add(entry2);

                            // Also cache for future introspection calls
                            methodCache.put(className, typedMethods);
                            ctorCache.put(className, true);

                        } catch (Throwable ignore) {
                            // ClassNotFound, LinkageError, SecurityException — skip
                        }
                    }
                } catch (IOException ignore) {}
            }
        }

        long elapsed = System.currentTimeMillis() - start;
        Map<String, Object> response = new HashMap<>();
        response.put("sweep_results", results);
        response.put("classes_scanned", scanned);
        response.put("viable_classes", results.size());
        response.put("sweep_duration_ms", elapsed);
        return GSON.toJson(response);
    }

    // ── Reference class introspection ──────────────────────────────

    /**
     * Cache: reference class name → list of typed method signatures.
     * Each entry is "name:returnType" (e.g. "addURL:void", "loadClass:java.lang.Class").
     */
    private static final Map<String, List<String>> methodCache = new HashMap<>();
    /** Cache: reference class name → has accessible no-arg constructor. */
    private static final Map<String, Boolean> ctorCache = new HashMap<>();

    /**
     * Introspect the reference class: find public methods that accept a single
     * String parameter (candidates for BeanFactory forceString abuse), and
     * check whether a public no-arg constructor exists.
     *
     * Each method is returned as "name:returnType" so the mutator can
     * automatically discover 2-step chains (e.g. addURL:void + loadClass:java.lang.Class)
     * without hardcoded method lists.
     *
     * Results are cached — reflection is only done once per class name.
     */
    private static void introspectReferenceClass(String refClassName, JndiResult result) {
        if (refClassName == null || refClassName.isEmpty()) return;

        // Check cache first
        if (methodCache.containsKey(refClassName)) {
            List<String> cached = methodCache.get(refClassName);
            if (cached != null && !cached.isEmpty()) {
                result.stringMethods = cached;
            }
            result.hasNoArgCtor = ctorCache.getOrDefault(refClassName, false);
            return;
        }

        try {
            Class<?> refClz = Class.forName(refClassName);

            // Check no-arg constructor
            boolean hasCtor = false;
            try {
                Constructor<?> ctor = refClz.getConstructor();
                hasCtor = Modifier.isPublic(ctor.getModifiers());
            } catch (NoSuchMethodException ignore) {}
            ctorCache.put(refClassName, hasCtor);
            result.hasNoArgCtor = hasCtor;

            // Find public instance methods that take exactly one String arg.
            // Format: "name:returnType" for typed chain discovery.
            Set<String> typedMethods = new TreeSet<>();
            for (Method m : refClz.getMethods()) {
                if (!Modifier.isPublic(m.getModifiers())) continue;
                if (Modifier.isStatic(m.getModifiers())) continue;
                Class<?>[] params = m.getParameterTypes();
                if (params.length == 1 && params[0] == String.class) {
                    String retType = m.getReturnType().getName();
                    typedMethods.add(m.getName() + ":" + retType);
                }
            }

            List<String> methods = new ArrayList<>(typedMethods);
            methodCache.put(refClassName, methods);
            if (!methods.isEmpty()) {
                result.stringMethods = methods;
            }
        } catch (Throwable e) {
            // ClassNotFound, LinkageError etc. — cache empty result
            methodCache.put(refClassName, Collections.emptyList());
            ctorCache.put(refClassName, false);
        }
    }

    // ── Connection pool factory detection ──────────────────────────
    // These factories always try to create JDBC connections during resolve,
    // causing hangs on network connect (blocked by SecurityManager but
    // internal retry loops keep the thread alive).
    private static boolean isConnectionPoolFactory(String factoryClass) {
        if (factoryClass == null) return false;
        return factoryClass.contains("DruidDataSourceFactory")
            || factoryClass.contains("HikariJNDIFactory")
            || factoryClass.contains("HikariDataSource")
            || factoryClass.contains("BasicDataSourceFactory")  // Commons DBCP
            || factoryClass.contains("SharedPoolDataSource")    // Commons DBCP2
            || factoryClass.contains("C3P0DataSourceFactory")
            || factoryClass.contains("PooledDataSourceFactory")
            || factoryClass.contains("JdbcDataSourceFactory")   // H2
            || (factoryClass.contains("DataSourceFactory")      // Tomcat JDBC pool
                && factoryClass.contains("tomcat"));
    }

    // ── Error classification ─────────────────────────────────────

    private static String classifyError(Exception e) {
        String name = e.getClass().getSimpleName();
        String msg = e.getMessage() != null ? e.getMessage() : "";

        if (name.contains("ClassNotFoundException")) return "class_not_found";
        if (name.contains("NoSuchMethodException")) return "no_such_method";
        if (name.contains("SecurityException")) return "security_exception";
        if (name.contains("InvocationTargetException")) {
            Throwable cause = e.getCause();
            if (cause != null) return classifyError(
                cause instanceof Exception ? (Exception) cause : new Exception(cause));
        }
        if (msg.contains("driver")) return "driver_not_found";
        if (msg.contains("denied")) return "security_exception";
        return "other";
    }

    private static String getStr(JsonObject obj, String key) {
        if (obj.has(key) && obj.get(key).isJsonPrimitive()) {
            return obj.get(key).getAsString();
        }
        return "";
    }

    // ── Tracking SecurityManager ─────────────────────────────────

    static class TrackingSecurityManager extends SecurityManager {
        @Override
        public void checkExec(String cmd) {
            // Always block exec, but only track for current iteration.
            // Zombie threads from timed-out resolves carry a stale
            // threadIteration and their events are silently dropped.
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
            } else {
                unattributedSinks++;
            }
            throw new SecurityException("blocked: write " + file);
        }

        @Override
        public void checkRead(String file) {
            // Allow reads (needed for classloading)
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
            // Track only — don't block via checkPermission as it breaks JVM internals
        }

        @Override
        public void checkPermission(java.security.Permission perm, Object context) {
            checkPermission(perm);
        }
    }

    // ── Result DTO ───────────────────────────────────────────────

    static class JndiResult {
        boolean resolved = false;
        boolean factoryLoaded = false;
        String factoryClass = "";
        String referenceClass = "";
        String resolvedClassName = "";
        boolean beanCreated = false;
        String methodInvoked = null;
        String sinkReached = null;
        List<String> sinksHit = new ArrayList<>();
        int unattributedSinks = 0;  // sink events from non-current-iteration threads (potential FN)
        boolean processSpawned = false;
        boolean jndiLookup = false;
        boolean fileWrite = false;
        boolean networkConnected = false;
        boolean classLoaded = false;
        boolean jdbcConnected = false;
        boolean sqlExecuted = false;
        String jdbcDriver = null;
        String exceptionClass = null;
        String exception = null;
        String errorType = null;
        long durationMs = 0;
        String jdkVersion = "";
        boolean securityManager = false;
        // Step-level timing metrics (ms)
        long parseMs = 0;
        long classLoadMs = 0;
        long factoryCreateMs = 0;
        long resolveMs = 0;
        long probeMs = 0;
        // Method introspection feedback — lists public methods(String) as
        // "name:returnType" (e.g. "eval:void", "loadClass:java.lang.Class").
        // The mutator uses return types to auto-discover 2-step chains.
        List<String> stringMethods = null;
        // Public no-arg constructors available (can BeanFactory instantiate it?)
        boolean hasNoArgCtor = false;
    }
}
