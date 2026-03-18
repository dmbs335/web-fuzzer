/**
 * GraphQL EXECUTION target -- Java graphql-java.
 *
 * Parses, validates, AND EXECUTES a GraphQL query against mock resolvers.
 * Same deterministic data as the Node.js target for differential comparison.
 *
 * Usage:
 *   java -cp "targets/graphql_java/*;targets/graphql_java" GraphqlJavaExec <file>
 *   java -cp "targets/graphql_java/*;targets/graphql_java" GraphqlJavaExec --persistent
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import graphql.*;
import graphql.language.*;
import graphql.schema.*;
import graphql.schema.idl.*;

public class GraphqlJavaExec {

    private static GraphQL GRAPHQL;

    // ── Mock Data ──────────────────────────────────────────────────
    static final Map<String, Map<String, Object>> USERS = new LinkedHashMap<>();
    static final Map<String, Map<String, Object>> PROFILES = new LinkedHashMap<>();
    static final Map<String, List<Map<String, Object>>> POSTS_BY_USER = new LinkedHashMap<>();
    static final Map<String, Map<String, Object>> POSTS = new LinkedHashMap<>();
    static final Map<String, Map<String, Object>> COMMENTS = new LinkedHashMap<>();

    static {
        // User#1: Alice - normal user
        Map<String, Object> u1 = new LinkedHashMap<>();
        u1.put("id", "1"); u1.put("name", "Alice"); u1.put("email", "alice@test.com");
        u1.put("role", "ADMIN"); u1.put("status", "ACTIVE"); u1.put("score", 95.5);
        u1.put("tags", Arrays.asList("admin", "staff"));
        u1.put("createdAt", "2024-01-01T00:00:00Z"); u1.put("updatedAt", "2024-06-01T00:00:00Z");
        u1.put("oldField", null);
        u1.put("_friendIds", Arrays.asList("2", "3"));
        u1.put("_postIds", Arrays.asList("101", "102"));
        USERS.put("1", u1);

        // User#2: Bob - score is null (Float nullable → OK)
        Map<String, Object> u2 = new LinkedHashMap<>();
        u2.put("id", "2"); u2.put("name", "Bob"); u2.put("email", "bob@test.com");
        u2.put("role", "USER"); u2.put("status", "ACTIVE"); u2.put("score", null);
        u2.put("tags", Collections.emptyList());
        u2.put("createdAt", "2024-02-01T00:00:00Z"); u2.put("updatedAt", null);
        u2.put("oldField", "legacy");
        u2.put("_friendIds", Arrays.asList("1"));
        u2.put("_postIds", Collections.emptyList());
        USERS.put("2", u2);

        // User#3: ★ name is null (String! → null propagation)
        Map<String, Object> u3 = new LinkedHashMap<>();
        u3.put("id", "3"); u3.put("name", null); u3.put("email", "charlie@test.com");
        u3.put("role", "GUEST"); u3.put("status", "SUSPENDED"); u3.put("score", 0.0);
        u3.put("tags", null);
        u3.put("createdAt", "2024-03-01T00:00:00Z"); u3.put("updatedAt", null);
        u3.put("oldField", null);
        u3.put("_friendIds", Collections.emptyList());
        u3.put("_postIds", Arrays.asList("201"));
        USERS.put("3", u3);

        // User#4: ★ email is null (String! → null propagation)
        Map<String, Object> u4 = new LinkedHashMap<>();
        u4.put("id", "4"); u4.put("name", "Diana"); u4.put("email", null);
        u4.put("role", "USER"); u4.put("status", "DELETED"); u4.put("score", 42.0);
        u4.put("tags", Arrays.asList("test"));
        u4.put("createdAt", null); u4.put("updatedAt", null);
        u4.put("oldField", null);
        u4.put("_friendIds", Arrays.asList("1", "2"));
        u4.put("_postIds", Collections.emptyList());
        USERS.put("4", u4);

        // Profiles
        Map<String, Object> p1 = new LinkedHashMap<>();
        p1.put("bio", "Engineer"); p1.put("avatar", "https://example.com/a.jpg");
        Map<String, Object> settings = new LinkedHashMap<>(); settings.put("theme", "dark");
        p1.put("settings", settings);
        PROFILES.put("1", p1);
        // "2" → null profile (handled in resolver)
        Map<String, Object> p4 = new LinkedHashMap<>();
        p4.put("bio", null); p4.put("avatar", null); p4.put("settings", null);
        PROFILES.put("4", p4);

        // Post#101: normal
        Map<String, Object> post101 = new LinkedHashMap<>();
        post101.put("id", "101"); post101.put("title", "Hello World"); post101.put("body", "First post");
        post101.put("status", "ACTIVE");
        Map<String, Object> meta101 = new LinkedHashMap<>(); meta101.put("views", 100);
        post101.put("metadata", meta101);
        post101.put("createdAt", "2024-01-15T00:00:00Z"); post101.put("updatedAt", null);
        post101.put("_authorId", "1"); post101.put("_commentIds", Arrays.asList("1001"));
        POSTS.put("101", post101);

        // Post#102: ★ title is null (String! → null propagation)
        Map<String, Object> post102 = new LinkedHashMap<>();
        post102.put("id", "102"); post102.put("title", null); post102.put("body", "Draft post");
        post102.put("status", "SUSPENDED"); post102.put("metadata", null);
        post102.put("createdAt", "2024-02-15T00:00:00Z"); post102.put("updatedAt", null);
        post102.put("_authorId", "1"); post102.put("_commentIds", Collections.emptyList());
        POSTS.put("102", post102);

        // Post#201: author is user#3 (who has null name → deep propagation)
        Map<String, Object> post201 = new LinkedHashMap<>();
        post201.put("id", "201"); post201.put("title", "Charlie's Post"); post201.put("body", null);
        post201.put("status", "DELETED");
        Map<String, Object> meta201 = new LinkedHashMap<>(); meta201.put("draft", true);
        post201.put("metadata", meta201);
        post201.put("createdAt", "2024-03-15T00:00:00Z"); post201.put("updatedAt", null);
        post201.put("_authorId", "3"); post201.put("_commentIds", Arrays.asList("2001"));
        POSTS.put("201", post201);

        // Comment#1001: normal
        Map<String, Object> c1001 = new LinkedHashMap<>();
        c1001.put("id", "1001"); c1001.put("text", "Great post!");
        c1001.put("_authorId", "2"); c1001.put("_postId", "101");
        COMMENTS.put("1001", c1001);

        // Comment#2001: ★ text is null (String! → null propagation)
        Map<String, Object> c2001 = new LinkedHashMap<>();
        c2001.put("id", "2001"); c2001.put("text", null);
        c2001.put("_authorId", "3"); c2001.put("_postId", "201");
        COMMENTS.put("2001", c2001);
    }

    // ── Schema + Wiring ───────────────────────────────────────────
    static {
        try {
            String schemaPath = System.getProperty("graphql.schema",
                "targets/graphql_schema.graphql");
            String sdl = new String(Files.readAllBytes(Paths.get(schemaPath)),
                StandardCharsets.UTF_8);

            SchemaParser schemaParser = new SchemaParser();
            TypeDefinitionRegistry registry = schemaParser.parse(sdl);

            RuntimeWiring wiring = RuntimeWiring.newRuntimeWiring()
                .scalar(graphql.scalars.ExtendedScalars.DateTime)
                .scalar(graphql.scalars.ExtendedScalars.Json)
                .type("Query", builder -> builder
                    .dataFetcher("user", env -> USERS.get(env.getArgument("id")))
                    .dataFetcher("users", env -> {
                        List<Map<String, Object>> result = new ArrayList<>(USERS.values());
                        Map<String, Object> filter = env.getArgument("filter");
                        if (filter != null) {
                            String role = (String) filter.get("role");
                            if (role != null) result.removeIf(u -> !role.equals(u.get("role")));
                            String status = (String) filter.get("status");
                            if (status != null) result.removeIf(u -> !status.equals(u.get("status")));
                            String nameContains = (String) filter.get("nameContains");
                            if (nameContains != null) result.removeIf(u -> {
                                String n = (String) u.get("name");
                                return n == null || !n.contains(nameContains);
                            });
                            Object scoreAboveObj = filter.get("scoreAbove");
                            if (scoreAboveObj != null) {
                                double scoreAbove = ((Number) scoreAboveObj).doubleValue();
                                result.removeIf(u -> u.get("score") == null || ((Number) u.get("score")).doubleValue() <= scoreAbove);
                            }
                            Object scoreBelowObj = filter.get("scoreBelow");
                            if (scoreBelowObj != null) {
                                double scoreBelow = ((Number) scoreBelowObj).doubleValue();
                                result.removeIf(u -> u.get("score") == null || ((Number) u.get("score")).doubleValue() >= scoreBelow);
                            }
                        }
                        Map<String, Object> page = env.getArgument("page");
                        int offset = 0;
                        int limit = 20;
                        if (page != null) {
                            Object offObj = page.get("offset");
                            if (offObj != null) offset = ((Number) offObj).intValue();
                            Object limObj = page.get("limit");
                            if (limObj != null) limit = ((Number) limObj).intValue();
                        }
                        int end = Math.min(offset + limit, result.size());
                        if (offset >= result.size() || limit <= 0) return Collections.emptyList();
                        return result.subList(offset, end);
                    })
                    .dataFetcher("post", env -> POSTS.get(env.getArgument("id")))
                    .dataFetcher("search", env -> {
                        String q = env.getArgument("query");
                        List<Object> results = new ArrayList<>();
                        for (Map<String, Object> u : USERS.values()) {
                            String name = (String) u.get("name");
                            if (name != null && name.toLowerCase().contains(q.toLowerCase()))
                                results.add(u);
                        }
                        for (Map<String, Object> p : POSTS.values()) {
                            String title = (String) p.get("title");
                            if (title != null && title.toLowerCase().contains(q.toLowerCase()))
                                results.add(p);
                        }
                        for (Map<String, Object> c : COMMENTS.values()) {
                            String text = (String) c.get("text");
                            if (text != null && text.toLowerCase().contains(q.toLowerCase()))
                                results.add(c);
                        }
                        return results;
                    })
                    .dataFetcher("node", env -> {
                        String id = env.getArgument("id");
                        if (USERS.containsKey(id)) return USERS.get(id);
                        if (POSTS.containsKey(id)) return POSTS.get(id);
                        if (COMMENTS.containsKey(id)) return COMMENTS.get(id);
                        return null;
                    })
                )
                .type("Mutation", builder -> builder
                    .dataFetcher("createUser", env -> {
                        Map<String, Object> input = env.getArgument("input");
                        Map<String, Object> user = new LinkedHashMap<>();
                        user.put("id", "999");
                        user.putAll(input);
                        user.put("status", "ACTIVE"); user.put("score", null);
                        Object tags = input.get("tags");
                        if (tags == null) user.put("tags", Collections.emptyList());
                        user.put("createdAt", "2024-12-01T00:00:00Z");
                        user.put("updatedAt", null); user.put("oldField", null);
                        user.put("_friendIds", Collections.emptyList());
                        user.put("_postIds", Collections.emptyList());
                        return user;
                    })
                    .dataFetcher("updateUser", env -> {
                        String id = env.getArgument("id");
                        Map<String, Object> u = USERS.get(id);
                        if (u == null) return null;
                        Map<String, Object> result = new LinkedHashMap<>(u);
                        String name = env.getArgument("name");
                        if (name != null) result.put("name", name);
                        String role = env.getArgument("role");
                        if (role != null) result.put("role", role);
                        return result;
                    })
                    .dataFetcher("deleteUser", env -> USERS.containsKey(env.getArgument("id")))
                    .dataFetcher("createPost", env -> {
                        Map<String, Object> post = new LinkedHashMap<>();
                        post.put("id", "999");
                        post.put("title", env.getArgument("title"));
                        post.put("body", env.getArgument("body"));
                        post.put("status", "ACTIVE"); post.put("metadata", null);
                        post.put("createdAt", "2024-12-01T00:00:00Z"); post.put("updatedAt", null);
                        post.put("_authorId", env.getArgument("authorId"));
                        post.put("_commentIds", Collections.emptyList());
                        return post;
                    })
                )
                .type("Subscription", builder -> builder
                    .dataFetcher("userCreated", env -> USERS.get("1"))
                    .dataFetcher("postAdded", env -> POSTS.get("101"))
                )
                .type("User", builder -> builder
                    .dataFetcher("profile", env -> {
                        Map<String, Object> user = env.getSource();
                        return PROFILES.get((String) user.get("id"));
                    })
                    .dataFetcher("friends", env -> {
                        Map<String, Object> user = env.getSource();
                        @SuppressWarnings("unchecked")
                        List<String> ids = (List<String>) user.get("_friendIds");
                        if (ids == null) return Collections.emptyList();
                        Integer limit = env.getArgument("limit");
                        if (limit == null) limit = 10;
                        return ids.stream().limit(limit).map(USERS::get).collect(Collectors.toList());
                    })
                    .dataFetcher("posts", env -> {
                        Map<String, Object> user = env.getSource();
                        @SuppressWarnings("unchecked")
                        List<String> ids = (List<String>) user.get("_postIds");
                        if (ids == null) return Collections.emptyList();
                        Integer offset = env.getArgument("offset");
                        Integer limit = env.getArgument("limit");
                        if (offset == null) offset = 0;
                        if (limit == null) limit = 10;
                        return ids.stream().skip(offset).limit(limit).map(POSTS::get).collect(Collectors.toList());
                    })
                )
                .type("Post", builder -> builder
                    .dataFetcher("author", env -> {
                        Map<String, Object> post = env.getSource();
                        return USERS.get((String) post.get("_authorId"));
                    })
                    .dataFetcher("comments", env -> {
                        Map<String, Object> post = env.getSource();
                        @SuppressWarnings("unchecked")
                        List<String> ids = (List<String>) post.get("_commentIds");
                        if (ids == null) return Collections.emptyList();
                        return ids.stream().map(COMMENTS::get).collect(Collectors.toList());
                    })
                )
                .type("Comment", builder -> builder
                    .dataFetcher("author", env -> {
                        Map<String, Object> c = env.getSource();
                        return USERS.get((String) c.get("_authorId"));
                    })
                    .dataFetcher("post", env -> {
                        Map<String, Object> c = env.getSource();
                        return POSTS.get((String) c.get("_postId"));
                    })
                )
                .type("Node", typeWiring -> typeWiring.typeResolver(env -> {
                    Map<String, Object> obj = env.getObject();
                    if (obj.containsKey("name") && obj.containsKey("email")) return env.getSchema().getObjectType("User");
                    if (obj.containsKey("title")) return env.getSchema().getObjectType("Post");
                    if (obj.containsKey("text")) return env.getSchema().getObjectType("Comment");
                    return null;
                }))
                .type("Timestamped", typeWiring -> typeWiring.typeResolver(env -> {
                    Map<String, Object> obj = env.getObject();
                    if (obj.containsKey("name") && obj.containsKey("email")) return env.getSchema().getObjectType("User");
                    if (obj.containsKey("title")) return env.getSchema().getObjectType("Post");
                    return null;
                }))
                .type("SearchResult", typeWiring -> typeWiring.typeResolver(env -> {
                    Map<String, Object> obj = env.getObject();
                    if (obj.containsKey("name") && obj.containsKey("email")) return env.getSchema().getObjectType("User");
                    if (obj.containsKey("title")) return env.getSchema().getObjectType("Post");
                    if (obj.containsKey("text")) return env.getSchema().getObjectType("Comment");
                    return null;
                }))
                .build();

            GraphQLSchema schema = new SchemaGenerator().makeExecutableSchema(registry, wiring);
            GRAPHQL = GraphQL.newGraphQL(schema).build();

        } catch (Exception e) {
            System.err.println("Failed to load schema: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }

    // ── Analysis ──────────────────────────────────────────────────

    static String analyzeQuery(String queryStr) {
        String raw = queryStr.trim();
        if (raw.isEmpty()) throw new IllegalArgumentException("Empty query");

        ExecutionResult execResult = GRAPHQL.execute(raw);

        Object data = execResult.getData();
        List<GraphQLError> errors = execResult.getErrors();

        // Check if it was a parse error
        boolean parseError = errors.stream().anyMatch(e ->
            e instanceof graphql.parser.InvalidSyntaxException ||
            e.getMessage().contains("Invalid syntax") ||
            e.getMessage().contains("More than 500 deep"));

        if (parseError) {
            StringBuilder sb = new StringBuilder();
            sb.append("{\"parsed\":false,\"valid\":false,\"executed\":false,");
            sb.append("\"parse_error\":\"").append(escapeJson(errors.get(0).getMessage().substring(0, Math.min(300, errors.get(0).getMessage().length())))).append("\",");
            sb.append("\"data\":null,\"data_hash\":null,\"data_shape\":null,");
            sb.append("\"null_paths\":[],\"error_paths\":[],\"error_messages_exec\":[],");
            sb.append("\"error_count_exec\":0,\"has_partial_data\":false,\"null_propagation_depth\":0}");
            return sb.toString();
        }

        // Check validation errors (non-execution errors that indicate invalid query)
        boolean hasValidationErrors = errors.stream().anyMatch(e ->
            e instanceof graphql.validation.ValidationError);

        if (hasValidationErrors && data == null) {
            List<String> valErrors = errors.stream()
                .filter(e -> e instanceof graphql.validation.ValidationError)
                .map(e -> e.getMessage().substring(0, Math.min(200, e.getMessage().length())))
                .collect(Collectors.toList());

            StringBuilder sb = new StringBuilder();
            sb.append("{\"parsed\":true,\"valid\":false,\"executed\":false,");
            sb.append("\"validation_errors\":").append(listToJsonArray(valErrors)).append(",");
            sb.append("\"validation_error_count\":").append(valErrors.size()).append(",");
            sb.append("\"data\":null,\"data_hash\":null,\"data_shape\":null,");
            sb.append("\"null_paths\":[],\"error_paths\":[],\"error_messages_exec\":[],");
            sb.append("\"error_count_exec\":0,\"has_partial_data\":false,\"null_propagation_depth\":0}");
            return sb.toString();
        }

        // Execution succeeded (possibly with errors)
        String dataJson = objectToJson(data);
        String dataHash = simpleHash(dataJson);
        String shape = dataShape(data, 0);

        List<String> nullPaths = new ArrayList<>();
        collectNullPaths(data, "", nullPaths);
        Collections.sort(nullPaths);

        List<String> errorPaths = new ArrayList<>();
        List<String> errorMsgs = new ArrayList<>();
        for (GraphQLError e : errors) {
            if (e.getPath() != null) {
                errorPaths.add(e.getPath().stream().map(String::valueOf).collect(Collectors.joining(".")));
            }
            errorMsgs.add(e.getMessage().substring(0, Math.min(200, e.getMessage().length())));
        }
        Collections.sort(errorPaths);
        Collections.sort(errorMsgs);

        int maxNullDepth = 0;
        for (String p : nullPaths) {
            int depth = p.split("\\.").length;
            if (depth > maxNullDepth) maxNullDepth = depth;
        }

        boolean hasPartialData = data != null && !errors.isEmpty();

        StringBuilder sb = new StringBuilder(2048);
        sb.append("{");
        sb.append("\"parsed\":true,\"valid\":true,\"executed\":true,");
        sb.append("\"data\":").append(dataJson).append(",");
        sb.append("\"data_hash\":\"").append(dataHash).append("\",");
        sb.append("\"data_shape\":\"").append(escapeJson(shape)).append("\",");
        sb.append("\"null_paths\":").append(listToJsonArray(nullPaths)).append(",");
        sb.append("\"null_path_hash\":\"").append(simpleHash(String.join("|", nullPaths))).append("\",");
        sb.append("\"error_paths\":").append(listToJsonArray(errorPaths)).append(",");
        sb.append("\"error_path_hash\":\"").append(simpleHash(String.join("|", errorPaths))).append("\",");
        sb.append("\"error_messages_exec\":").append(listToJsonArray(errorMsgs)).append(",");
        sb.append("\"error_count_exec\":").append(errors.size()).append(",");
        sb.append("\"has_partial_data\":").append(hasPartialData).append(",");
        sb.append("\"null_propagation_depth\":").append(maxNullDepth);
        sb.append("}");
        return sb.toString();
    }

    // ── Helpers ───────────────────────────────────────────────────

    static String simpleHash(String str) {
        int h = 0;
        for (int i = 0; i < str.length(); i++) {
            h = ((h << 5) - h + str.charAt(i));
        }
        return String.format("%08x", h & 0xFFFFFFFFL);
    }

    @SuppressWarnings("unchecked")
    static void collectNullPaths(Object obj, String prefix, List<String> paths) {
        if (obj == null) {
            paths.add(prefix.isEmpty() ? "root" : prefix);
            return;
        }
        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                String p = prefix.isEmpty() ? e.getKey() : prefix + "." + e.getKey();
                if (e.getValue() == null) paths.add(p);
                else if (e.getValue() instanceof Map || e.getValue() instanceof List)
                    collectNullPaths(e.getValue(), p, paths);
            }
        } else if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            for (int i = 0; i < list.size(); i++) {
                String p = prefix + "[" + i + "]";
                if (list.get(i) == null) paths.add(p);
                else if (list.get(i) instanceof Map || list.get(i) instanceof List)
                    collectNullPaths(list.get(i), p, paths);
            }
        }
    }

    @SuppressWarnings("unchecked")
    static String dataShape(Object obj, int depth) {
        if (depth > 6) return "...";
        if (obj == null) return "null";
        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            List<String> keys = new ArrayList<>(map.keySet());
            Collections.sort(keys);
            if (keys.size() > 20) keys = keys.subList(0, 20);
            return "{" + keys.stream()
                .map(k -> k + ":" + dataShape(map.get(k), depth + 1))
                .collect(Collectors.joining(",")) + "}";
        }
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            if (list.isEmpty()) return "[]";
            return "[" + dataShape(list.get(0), depth + 1) + "]";
        }
        if (obj instanceof String) return "string";
        if (obj instanceof Number) return "number";
        if (obj instanceof Boolean) return "boolean";
        return "unknown";
    }

    static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }

    static String listToJsonArray(List<String> list) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(list.get(i))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    static String objectToJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof Boolean) return obj.toString();
        if (obj instanceof Number) return obj.toString();
        if (obj instanceof String) return "\"" + escapeJson((String) obj) + "\"";
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < list.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append(objectToJson(list.get(i)));
            }
            sb.append("]");
            return sb.toString();
        }
        if (obj instanceof Map) {
            Map<String, Object> map = (Map<String, Object>) obj;
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> e : map.entrySet()) {
                // Skip internal mock fields (single underscore) but keep GraphQL introspection (__*)
                if (e.getKey().startsWith("_") && !e.getKey().startsWith("__")) continue;
                if (!first) sb.append(",");
                sb.append("\"").append(escapeJson(e.getKey())).append("\":");
                sb.append(objectToJson(e.getValue()));
                first = false;
            }
            sb.append("}");
            return sb.toString();
        }
        return "\"" + escapeJson(obj.toString()) + "\"";
    }

    // ── Persistent mode ──────────────────────────────────────────
    static void persistentMode() throws IOException {
        DataInputStream din = new DataInputStream(new BufferedInputStream(System.in));
        DataOutputStream dout = new DataOutputStream(new BufferedOutputStream(System.out));

        while (true) {
            int length;
            try { length = din.readInt(); } catch (EOFException e) { break; }

            byte[] inputBytes = new byte[length];
            din.readFully(inputBytes);
            String input = new String(inputBytes, StandardCharsets.UTF_8);

            String output;
            int exitCode;
            try {
                output = analyzeQuery(input);
                exitCode = 0;
            } catch (Exception e) {
                output = "";
                exitCode = 1;
            }

            byte[] outBytes = output.getBytes(StandardCharsets.UTF_8);
            dout.writeInt(outBytes.length);
            dout.write(outBytes);
            dout.writeInt(exitCode);
            dout.flush();
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--persistent")) {
            persistentMode();
            return;
        }
        if (args.length < 1) {
            System.err.println("Usage: java GraphqlJavaExec <file>");
            System.exit(2);
        }
        String data = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);
        try {
            System.out.println(analyzeQuery(data));
            System.exit(0);
        } catch (Exception e) {
            System.err.println("REJECT: " + e.getMessage());
            System.exit(1);
        }
    }
}
