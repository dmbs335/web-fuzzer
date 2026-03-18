/**
 * GraphQL target -- Node graphql-js (reference implementation).
 *
 * Parses + validates a GraphQL query against the common schema.
 * Output: standardized JSON for differential comparison.
 * Exit 0 = processed, Exit 1 = parse failure.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const {
  parse,
  validate,
  buildSchema,
  TypeInfo,
  visit,
  visitWithTypeInfo,
  getNamedType,
  Kind,
} = require("graphql");

// Load shared schema
const SCHEMA_PATH = path.join(__dirname, "graphql_schema.graphql");
const SCHEMA_SDL = fs.readFileSync(SCHEMA_PATH, "utf8");

// Custom scalar stubs (DateTime, JSON) — schema needs resolvers for validation
const SCHEMA = buildSchema(SCHEMA_SDL);

function analyzeQuery(queryStr) {
  const raw = String(queryStr || "").trim();
  if (!raw) throw new Error("Empty query");

  // Phase 1: Parse
  let doc;
  try {
    doc = parse(raw);
  } catch (parseErr) {
    return JSON.stringify({
      parsed: false,
      valid: false,
      parse_error: String(parseErr.message || "").slice(0, 300),
      operation_type: null,
      operation_name: null,
      selection_count: 0,
      field_paths: [],
      fragment_names: [],
      fragment_type_conditions: [],
      variable_defs: {},
      directive_names: [],
      directive_args: {},
      max_depth: 0,
      errors: [String(parseErr.message || "").slice(0, 300)],
      error_count: 1,
      type_conditions: [],
      has_introspection: false,
      has_subscription: false,
      has_mutation: false,
      alias_count: 0,
      inline_fragment_count: 0,
      spread_count: 0,
    });
  }

  // Phase 2: Validate against schema
  const validationErrors = validate(SCHEMA, doc);
  const valid = validationErrors.length === 0;

  // Extract operation info
  let operationType = null;
  let operationName = null;
  let hasSubscription = false;
  let hasMutation = false;
  const variableDefs = {};

  for (const def of doc.definitions) {
    if (def.kind === Kind.OPERATION_DEFINITION) {
      operationType = def.operation || null;
      operationName = def.name ? def.name.value : null;
      if (def.operation === "subscription") hasSubscription = true;
      if (def.operation === "mutation") hasMutation = true;
      if (def.variableDefinitions) {
        for (const v of def.variableDefinitions) {
          const varName = v.variable.name.value;
          variableDefs[varName] = typeNodeToString(v.type);
        }
      }
    }
  }

  // Walk AST for field paths, directives, fragments, depth
  const fieldPaths = [];
  const fragmentNames = [];
  const fragmentTypeConditions = [];
  const directiveNames = new Set();
  const directiveArgs = {};
  const typeConditions = [];
  let maxDepth = 0;
  let selectionCount = 0;
  let aliasCount = 0;
  let inlineFragmentCount = 0;
  let spreadCount = 0;
  let hasIntrospection = false;

  // Collect fragment definitions
  for (const def of doc.definitions) {
    if (def.kind === Kind.FRAGMENT_DEFINITION) {
      fragmentNames.push(def.name.value);
      fragmentTypeConditions.push(def.typeCondition.name.value);
    }
  }

  // Walk with type info for field paths
  const typeInfo = new TypeInfo(SCHEMA);
  let depthStack = [];

  visit(doc, visitWithTypeInfo(typeInfo, {
    Field: {
      enter(node) {
        const fieldName = node.name.value;
        depthStack.push(fieldName);
        selectionCount++;

        const currentPath = depthStack.join(".");
        fieldPaths.push(currentPath);

        if (depthStack.length > maxDepth) maxDepth = depthStack.length;
        if (node.alias) aliasCount++;
        if (fieldName.startsWith("__")) hasIntrospection = true;

        // Collect directives
        if (node.directives) {
          for (const d of node.directives) {
            directiveNames.add(d.name.value);
            if (d.arguments && d.arguments.length > 0) {
              const args = {};
              for (const a of d.arguments) {
                args[a.name.value] = valueToJs(a.value);
              }
              directiveArgs[d.name.value] = args;
            }
          }
        }
      },
      leave() {
        depthStack.pop();
      },
    },
    InlineFragment: {
      enter(node) {
        inlineFragmentCount++;
        if (node.typeCondition) {
          typeConditions.push(node.typeCondition.name.value);
        }
        // Collect directives on inline fragments
        if (node.directives) {
          for (const d of node.directives) {
            directiveNames.add(d.name.value);
          }
        }
      },
    },
    FragmentSpread: {
      enter(node) {
        spreadCount++;
        if (node.directives) {
          for (const d of node.directives) {
            directiveNames.add(d.name.value);
          }
        }
      },
    },
    OperationDefinition: {
      enter(node) {
        if (node.directives) {
          for (const d of node.directives) {
            directiveNames.add(d.name.value);
          }
        }
      },
    },
  }));

  // Compute semantic hashes for coverage granularity
  const sortedPaths = fieldPaths.sort();
  const fieldSetHash = simpleHash(sortedPaths.join("|"));
  const directiveSetHash = simpleHash(Array.from(directiveNames).sort().join("|"));
  const fragmentSetHash = simpleHash(
    fragmentNames.sort().join("|") + ":" + fragmentTypeConditions.sort().join("|")
  );

  // Classify error categories for validation diff
  const errorCategories = classifyErrors(validationErrors.map(e => String(e.message)));

  const result = {
    parsed: true,
    valid: valid,
    parse_error: null,
    operation_type: operationType,
    operation_name: operationName,
    selection_count: selectionCount,
    field_paths: sortedPaths,
    fragment_names: fragmentNames.sort(),
    fragment_type_conditions: fragmentTypeConditions.sort(),
    variable_defs: variableDefs,
    directive_names: Array.from(directiveNames).sort(),
    directive_args: directiveArgs,
    max_depth: maxDepth,
    errors: validationErrors.map(e => String(e.message).slice(0, 200)),
    error_count: validationErrors.length,
    error_categories: errorCategories,
    type_conditions: typeConditions.sort(),
    has_introspection: hasIntrospection,
    has_subscription: hasSubscription,
    has_mutation: hasMutation,
    alias_count: aliasCount,
    inline_fragment_count: inlineFragmentCount,
    spread_count: spreadCount,
    field_set_hash: fieldSetHash,
    directive_set_hash: directiveSetHash,
    fragment_set_hash: fragmentSetHash,
  };
  return JSON.stringify(result);
}

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function classifyErrors(errorMessages) {
  const cats = new Set();
  for (const msg of errorMessages) {
    const m = msg.toLowerCase();
    if (m.includes("enum") || m.includes("not exist in")) cats.add("enum_value");
    else if (m.includes("cannot query field")) cats.add("unknown_field");
    else if (m.includes("unknown argument")) cats.add("unknown_argument");
    else if (m.includes("required") || m.includes("non-null")) cats.add("required_field");
    else if (m.includes("variable")) cats.add("variable_type");
    else if (m.includes("fragment") && m.includes("cycle")) cats.add("fragment_cycle");
    else if (m.includes("fragment")) cats.add("fragment_error");
    else if (m.includes("directive")) cats.add("directive_error");
    else if (m.includes("type")) cats.add("type_error");
    else if (m.includes("subscription")) cats.add("subscription_error");
    else cats.add("other");
  }
  return Array.from(cats).sort();
}

function typeNodeToString(typeNode) {
  if (typeNode.kind === Kind.NON_NULL_TYPE) {
    return typeNodeToString(typeNode.type) + "!";
  }
  if (typeNode.kind === Kind.LIST_TYPE) {
    return "[" + typeNodeToString(typeNode.type) + "]";
  }
  return typeNode.name.value;
}

function valueToJs(valueNode) {
  switch (valueNode.kind) {
    case Kind.INT: return parseInt(valueNode.value, 10);
    case Kind.FLOAT: return parseFloat(valueNode.value);
    case Kind.STRING: return valueNode.value;
    case Kind.BOOLEAN: return valueNode.value;
    case Kind.NULL: return null;
    case Kind.ENUM: return valueNode.value;
    case Kind.LIST: return valueNode.values.map(valueToJs);
    case Kind.OBJECT: {
      const obj = {};
      for (const f of valueNode.fields) {
        obj[f.name.value] = valueToJs(f.value);
      }
      return obj;
    }
    default: return String(valueNode.value || "");
  }
}

module.exports = { analyzeQuery };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node graphql_node_graphqljs.js <input_file>\n");
    process.exit(2);
  }
  try {
    const input = fs.readFileSync(inputPath, "utf8");
    process.stdout.write(analyzeQuery(input) + "\n");
    process.exit(0);
  } catch (err) {
    process.stderr.write("REJECT: " + err.message + "\n");
    process.exit(1);
  }
}
