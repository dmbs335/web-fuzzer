/**
 * GraphQL target -- Java graphql-java (independent implementation).
 *
 * Parses + validates a GraphQL query against the common schema.
 * Output: standardized JSON for differential comparison.
 *
 * Usage:
 *   java -cp "targets/graphql_java/*:targets/graphql_java" GraphqlJava <file>
 *   java -cp "targets/graphql_java/*:targets/graphql_java" GraphqlJava --persistent
 *
 * (Windows: use ';' instead of ':' in -cp)
 */

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import graphql.language.*;
import graphql.parser.Parser;
import graphql.parser.InvalidSyntaxException;
import graphql.schema.GraphQLSchema;
import graphql.schema.idl.RuntimeWiring;
import graphql.schema.idl.SchemaGenerator;
import graphql.schema.idl.SchemaParser;
import graphql.schema.idl.TypeDefinitionRegistry;
import graphql.validation.Validator;
import graphql.validation.ValidationError;
import graphql.GraphQLError;
import graphql.language.Document;
import graphql.language.OperationDefinition;
import graphql.language.FragmentDefinition;
import graphql.language.Field;
import graphql.language.InlineFragment;
import graphql.language.FragmentSpread;
import graphql.language.Directive;
import graphql.language.Argument;
import graphql.language.Value;
import graphql.language.IntValue;
import graphql.language.FloatValue;
import graphql.language.StringValue;
import graphql.language.BooleanValue;
import graphql.language.NullValue;
import graphql.language.EnumValue;
import graphql.language.ArrayValue;
import graphql.language.ObjectValue;
import graphql.language.ObjectField;
import graphql.language.VariableDefinition;
import graphql.language.Type;
import graphql.language.TypeName;
import graphql.language.NonNullType;
import graphql.language.ListType;
import graphql.language.SelectionSet;
import graphql.language.Selection;
// graphql-java 22.x: Validator.validateDocument takes Locale directly

public class GraphqlJava {

    private static GraphQLSchema SCHEMA;

    static {
        try {
            String schemaPath = System.getProperty("graphql.schema",
                "targets/graphql_schema.graphql");
            String sdl = new String(Files.readAllBytes(Paths.get(schemaPath)),
                StandardCharsets.UTF_8);
            SchemaParser schemaParser = new SchemaParser();
            TypeDefinitionRegistry registry = schemaParser.parse(sdl);

            // Minimal wiring (no resolvers needed for validation-only)
            RuntimeWiring wiring = RuntimeWiring.newRuntimeWiring()
                .scalar(graphql.scalars.ExtendedScalars.DateTime)
                .scalar(graphql.scalars.ExtendedScalars.Json)
                .type("Node", typeWiring -> typeWiring
                    .typeResolver(env -> null))
                .type("Timestamped", typeWiring -> typeWiring
                    .typeResolver(env -> null))
                .type("SearchResult", typeWiring -> typeWiring
                    .typeResolver(env -> null))
                .build();

            SCHEMA = new SchemaGenerator().makeExecutableSchema(registry, wiring);
        } catch (Exception e) {
            System.err.println("Failed to load schema: " + e.getMessage());
            e.printStackTrace(System.err);
            System.exit(2);
        }
    }

    static String analyzeQuery(String queryStr) {
        String raw = queryStr.trim();
        if (raw.isEmpty()) throw new IllegalArgumentException("Empty query");

        StringBuilder sb = new StringBuilder(1024);

        // Phase 1: Parse
        Document doc;
        try {
            doc = Parser.parse(raw);
        } catch (Exception parseErr) {
            String parseError = escapeJson(truncate(parseErr.getMessage(), 300));
            sb.append("{");
            sb.append("\"parsed\":false,");
            sb.append("\"valid\":false,");
            sb.append("\"parse_error\":\"").append(parseError).append("\",");
            sb.append("\"operation_type\":null,");
            sb.append("\"operation_name\":null,");
            sb.append("\"selection_count\":0,");
            sb.append("\"field_paths\":[],");
            sb.append("\"fragment_names\":[],");
            sb.append("\"fragment_type_conditions\":[],");
            sb.append("\"variable_defs\":{},");
            sb.append("\"directive_names\":[],");
            sb.append("\"directive_args\":{},");
            sb.append("\"max_depth\":0,");
            sb.append("\"errors\":[\"").append(parseError).append("\"],");
            sb.append("\"error_count\":1,");
            sb.append("\"type_conditions\":[],");
            sb.append("\"has_introspection\":false,");
            sb.append("\"has_subscription\":false,");
            sb.append("\"has_mutation\":false,");
            sb.append("\"alias_count\":0,");
            sb.append("\"inline_fragment_count\":0,");
            sb.append("\"spread_count\":0");
            sb.append("}");
            return sb.toString();
        }

        // Phase 2: Validate
        Validator validator = new Validator();
        List<ValidationError> validationErrors = validator.validateDocument(
            SCHEMA, doc, Locale.ENGLISH);
        boolean valid = validationErrors.isEmpty();

        // Extract operation info
        String operationType = null;
        String operationName = null;
        boolean hasSubscription = false;
        boolean hasMutation = false;
        Map<String, String> variableDefs = new LinkedHashMap<>();

        for (Definition<?> def : doc.getDefinitions()) {
            if (def instanceof OperationDefinition) {
                OperationDefinition op = (OperationDefinition) def;
                operationType = op.getOperation() != null
                    ? op.getOperation().name().toLowerCase() : null;
                operationName = op.getName();
                if ("subscription".equals(operationType)) hasSubscription = true;
                if ("mutation".equals(operationType)) hasMutation = true;
                if (op.getVariableDefinitions() != null) {
                    for (VariableDefinition v : op.getVariableDefinitions()) {
                        variableDefs.put(v.getName(), typeToString(v.getType()));
                    }
                }
            }
        }

        // Walk AST
        List<String> fieldPaths = new ArrayList<>();
        List<String> fragmentNames = new ArrayList<>();
        List<String> fragmentTypeConditions = new ArrayList<>();
        Set<String> directiveNames = new TreeSet<>();
        Map<String, Map<String, Object>> directiveArgs = new LinkedHashMap<>();
        List<String> typeConditions = new ArrayList<>();
        int[] maxDepth = {0};
        int[] selectionCount = {0};
        int[] aliasCount = {0};
        int[] inlineFragmentCount = {0};
        int[] spreadCount = {0};
        boolean[] hasIntrospection = {false};

        // Collect fragments
        for (Definition<?> def : doc.getDefinitions()) {
            if (def instanceof FragmentDefinition) {
                FragmentDefinition frag = (FragmentDefinition) def;
                fragmentNames.add(frag.getName());
                fragmentTypeConditions.add(frag.getTypeCondition().getName());
            }
        }

        // Walk selections
        for (Definition<?> def : doc.getDefinitions()) {
            if (def instanceof OperationDefinition) {
                OperationDefinition op = (OperationDefinition) def;
                collectDirectives(op.getDirectives(), directiveNames, directiveArgs);
                walkSelections(op.getSelectionSet(), new ArrayList<>(), fieldPaths,
                    directiveNames, directiveArgs, typeConditions,
                    maxDepth, selectionCount, aliasCount,
                    inlineFragmentCount, spreadCount, hasIntrospection);
            } else if (def instanceof FragmentDefinition) {
                FragmentDefinition frag = (FragmentDefinition) def;
                walkSelections(frag.getSelectionSet(), new ArrayList<>(), fieldPaths,
                    directiveNames, directiveArgs, typeConditions,
                    maxDepth, selectionCount, aliasCount,
                    inlineFragmentCount, spreadCount, hasIntrospection);
            }
        }

        // Build JSON
        Collections.sort(fieldPaths);
        Collections.sort(fragmentNames);
        Collections.sort(fragmentTypeConditions);
        Collections.sort(typeConditions);

        // Compute semantic hashes
        String fieldSetHash = simpleHash(String.join("|", fieldPaths));
        String directiveSetHash = simpleHash(String.join("|", new ArrayList<>(directiveNames)));
        String fragmentSetHash = simpleHash(
            String.join("|", fragmentNames) + ":" + String.join("|", fragmentTypeConditions));

        // Classify error categories
        List<String> errorCategories = classifyErrors(validationErrors);

        sb.append("{");
        sb.append("\"alias_count\":").append(aliasCount[0]).append(",");
        sb.append("\"directive_args\":").append(mapToJson(directiveArgs)).append(",");
        sb.append("\"directive_names\":").append(listToJsonArray(new ArrayList<>(directiveNames))).append(",");
        sb.append("\"directive_set_hash\":\"").append(directiveSetHash).append("\",");
        sb.append("\"error_categories\":").append(listToJsonArray(errorCategories)).append(",");
        sb.append("\"error_count\":").append(validationErrors.size()).append(",");
        sb.append("\"errors\":").append(errorsToJson(validationErrors)).append(",");
        sb.append("\"field_paths\":").append(listToJsonArray(fieldPaths)).append(",");
        sb.append("\"field_set_hash\":\"").append(fieldSetHash).append("\",");
        sb.append("\"fragment_names\":").append(listToJsonArray(fragmentNames)).append(",");
        sb.append("\"fragment_set_hash\":\"").append(fragmentSetHash).append("\",");
        sb.append("\"fragment_type_conditions\":").append(listToJsonArray(fragmentTypeConditions)).append(",");
        sb.append("\"has_introspection\":").append(hasIntrospection[0]).append(",");
        sb.append("\"has_mutation\":").append(hasMutation).append(",");
        sb.append("\"has_subscription\":").append(hasSubscription).append(",");
        sb.append("\"inline_fragment_count\":").append(inlineFragmentCount[0]).append(",");
        sb.append("\"max_depth\":").append(maxDepth[0]).append(",");
        sb.append("\"operation_name\":").append(operationName != null ? "\"" + escapeJson(operationName) + "\"" : "null").append(",");
        sb.append("\"operation_type\":").append(operationType != null ? "\"" + escapeJson(operationType) + "\"" : "null").append(",");
        sb.append("\"parse_error\":null,");
        sb.append("\"parsed\":true,");
        sb.append("\"selection_count\":").append(selectionCount[0]).append(",");
        sb.append("\"spread_count\":").append(spreadCount[0]).append(",");
        sb.append("\"type_conditions\":").append(listToJsonArray(typeConditions)).append(",");
        sb.append("\"valid\":").append(valid).append(",");
        sb.append("\"variable_defs\":").append(varDefsToJson(variableDefs));
        sb.append("}");
        return sb.toString();
    }

    static void walkSelections(
        SelectionSet selectionSet, List<String> pathPrefix,
        List<String> fieldPaths,
        Set<String> directiveNames, Map<String, Map<String, Object>> directiveArgs,
        List<String> typeConditions,
        int[] maxDepth, int[] selectionCount, int[] aliasCount,
        int[] inlineFragmentCount, int[] spreadCount, boolean[] hasIntrospection
    ) {
        if (selectionSet == null || selectionSet.getSelections() == null) return;

        for (Selection<?> sel : selectionSet.getSelections()) {
            if (sel instanceof Field) {
                Field field = (Field) sel;
                String fieldName = field.getName();
                List<String> currentPath = new ArrayList<>(pathPrefix);
                currentPath.add(fieldName);
                String pathStr = String.join(".", currentPath);
                fieldPaths.add(pathStr);
                selectionCount[0]++;
                if (currentPath.size() > maxDepth[0]) maxDepth[0] = currentPath.size();
                if (field.getAlias() != null) aliasCount[0]++;
                if (fieldName.startsWith("__")) hasIntrospection[0] = true;
                collectDirectives(field.getDirectives(), directiveNames, directiveArgs);
                if (field.getSelectionSet() != null) {
                    walkSelections(field.getSelectionSet(), currentPath, fieldPaths,
                        directiveNames, directiveArgs, typeConditions,
                        maxDepth, selectionCount, aliasCount,
                        inlineFragmentCount, spreadCount, hasIntrospection);
                }
            } else if (sel instanceof InlineFragment) {
                InlineFragment inlineFrag = (InlineFragment) sel;
                inlineFragmentCount[0]++;
                if (inlineFrag.getTypeCondition() != null) {
                    typeConditions.add(inlineFrag.getTypeCondition().getName());
                }
                collectDirectives(inlineFrag.getDirectives(), directiveNames, directiveArgs);
                walkSelections(inlineFrag.getSelectionSet(), pathPrefix, fieldPaths,
                    directiveNames, directiveArgs, typeConditions,
                    maxDepth, selectionCount, aliasCount,
                    inlineFragmentCount, spreadCount, hasIntrospection);
            } else if (sel instanceof FragmentSpread) {
                FragmentSpread spread = (FragmentSpread) sel;
                spreadCount[0]++;
                collectDirectives(spread.getDirectives(), directiveNames, directiveArgs);
            }
        }
    }

    static void collectDirectives(
        List<Directive> directives,
        Set<String> directiveNames,
        Map<String, Map<String, Object>> directiveArgs
    ) {
        if (directives == null) return;
        for (Directive d : directives) {
            String dName = d.getName();
            directiveNames.add(dName);
            if (d.getArguments() != null && !d.getArguments().isEmpty()) {
                Map<String, Object> args = new LinkedHashMap<>();
                for (Argument a : d.getArguments()) {
                    args.put(a.getName(), valueToJava(a.getValue()));
                }
                directiveArgs.put(dName, args);
            }
        }
    }

    static Object valueToJava(Value<?> value) {
        if (value instanceof IntValue) return ((IntValue) value).getValue().intValue();
        if (value instanceof FloatValue) return ((FloatValue) value).getValue().doubleValue();
        if (value instanceof StringValue) return ((StringValue) value).getValue();
        if (value instanceof BooleanValue) return ((BooleanValue) value).isValue();
        if (value instanceof NullValue) return null;
        if (value instanceof EnumValue) return ((EnumValue) value).getName();
        if (value instanceof ArrayValue) {
            return ((ArrayValue) value).getValues().stream()
                .map(GraphqlJava::valueToJava).collect(Collectors.toList());
        }
        if (value instanceof ObjectValue) {
            Map<String, Object> map = new LinkedHashMap<>();
            for (ObjectField f : ((ObjectValue) value).getObjectFields()) {
                map.put(f.getName(), valueToJava(f.getValue()));
            }
            return map;
        }
        return value.toString();
    }

    static String typeToString(Type<?> type) {
        if (type instanceof NonNullType) {
            return typeToString(((NonNullType) type).getType()) + "!";
        }
        if (type instanceof ListType) {
            return "[" + typeToString(((ListType) type).getType()) + "]";
        }
        if (type instanceof TypeName) {
            return ((TypeName) type).getName();
        }
        return type.toString();
    }

    // --- Semantic hash + error classification ---

    static String simpleHash(String str) {
        int h = 0;
        for (int i = 0; i < str.length(); i++) {
            h = ((h << 5) - h + str.charAt(i));
        }
        return String.format("%08x", h & 0xFFFFFFFFL);
    }

    static List<String> classifyErrors(List<ValidationError> errors) {
        Set<String> cats = new TreeSet<>();
        for (ValidationError err : errors) {
            String m = err.getMessage().toLowerCase();
            if (m.contains("enum") || m.contains("not exist in")) cats.add("enum_value");
            else if (m.contains("cannot query field")) cats.add("unknown_field");
            else if (m.contains("unknown argument")) cats.add("unknown_argument");
            else if (m.contains("required") || m.contains("non-null")) cats.add("required_field");
            else if (m.contains("variable")) cats.add("variable_type");
            else if (m.contains("fragment") && m.contains("cycle")) cats.add("fragment_cycle");
            else if (m.contains("fragment")) cats.add("fragment_error");
            else if (m.contains("directive")) cats.add("directive_error");
            else if (m.contains("type")) cats.add("type_error");
            else if (m.contains("subscription")) cats.add("subscription_error");
            else cats.add("other");
        }
        return new ArrayList<>(cats);
    }

    // --- JSON helpers (no external dependency) ---

    static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    static String truncate(String s, int maxLen) {
        if (s == null) return "";
        return s.length() > maxLen ? s.substring(0, maxLen) : s;
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

    static String errorsToJson(List<ValidationError> errors) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < errors.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append("\"").append(escapeJson(truncate(errors.get(i).getMessage(), 200))).append("\"");
        }
        sb.append("]");
        return sb.toString();
    }

    static String varDefsToJson(Map<String, String> vars) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : vars.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeJson(e.getKey())).append("\":\"")
              .append(escapeJson(e.getValue())).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    static String mapToJson(Map<String, Map<String, Object>> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Map<String, Object>> e : map.entrySet()) {
            if (!first) sb.append(",");
            sb.append("\"").append(escapeJson(e.getKey())).append("\":{");
            boolean innerFirst = true;
            for (Map.Entry<String, Object> ie : e.getValue().entrySet()) {
                if (!innerFirst) sb.append(",");
                sb.append("\"").append(escapeJson(ie.getKey())).append("\":");
                sb.append(objectToJson(ie.getValue()));
                innerFirst = false;
            }
            sb.append("}");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

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
            @SuppressWarnings("unchecked")
            Map<String, Object> map = (Map<String, Object>) obj;
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (Map.Entry<String, Object> e : map.entrySet()) {
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

    // --- Persistent mode: binary protocol ---
    static void persistentMode() throws IOException {
        DataInputStream din = new DataInputStream(
            new BufferedInputStream(System.in));
        DataOutputStream dout = new DataOutputStream(
            new BufferedOutputStream(System.out));

        while (true) {
            int length;
            try {
                length = din.readInt();
            } catch (EOFException e) {
                break;
            }

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
            System.err.println("Usage: java GraphqlJava <file>");
            System.err.println("       java GraphqlJava --persistent");
            System.exit(2);
        }

        String data;
        try {
            data = new String(Files.readAllBytes(Paths.get(args[0])),
                StandardCharsets.UTF_8);
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
            System.exit(2);
            return;
        }

        try {
            System.out.println(analyzeQuery(data));
            System.exit(0);
        } catch (Exception e) {
            System.err.println("REJECT: " + e.getMessage());
            System.exit(1);
        }
    }
}
