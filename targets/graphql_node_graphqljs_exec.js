/**
 * GraphQL EXECUTION target -- Node graphql-js.
 *
 * Parses, validates, AND EXECUTES a GraphQL query against mock resolvers.
 * Deterministic data with intentional null/error injection points for
 * differential comparison of execution semantics across implementations.
 *
 * Exit 0 = processed, Exit 1 = rejected.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const {
  parse,
  validate,
  execute,
  buildSchema,
  GraphQLError,
  Kind,
} = require("graphql");

// ── Schema ────────────────────────────────────────────────────────────
const SCHEMA_PATH = path.join(__dirname, "graphql_schema.graphql");
const SCHEMA_SDL = fs.readFileSync(SCHEMA_PATH, "utf8");
const SCHEMA = buildSchema(SCHEMA_SDL);

// ── Mock Data ─────────────────────────────────────────────────────────
// Deterministic data set. Some fields intentionally violate non-null
// contracts to exercise null propagation across implementations.

const USERS = {
  "1": {
    id: "1", name: "Alice", email: "alice@test.com",
    role: "ADMIN", status: "ACTIVE", score: 95.5,
    tags: ["admin", "staff"],
    createdAt: "2024-01-01T00:00:00Z", updatedAt: "2024-06-01T00:00:00Z",
    oldField: null,  // deprecated, nullable → OK
    _friendIds: ["2", "3"],
    _postIds: ["101", "102"],
  },
  "2": {
    id: "2", name: "Bob", email: "bob@test.com",
    role: "USER", status: "ACTIVE", score: null,  // Float nullable → OK
    tags: [],
    createdAt: "2024-02-01T00:00:00Z", updatedAt: null,
    oldField: "legacy",
    _friendIds: ["1"],
    _postIds: [],
  },
  "3": {
    // ★ name is String! but resolver returns null → null propagation test
    id: "3", name: null, email: "charlie@test.com",
    role: "GUEST", status: "SUSPENDED", score: 0,
    tags: null,  // [String] nullable → OK
    createdAt: "2024-03-01T00:00:00Z", updatedAt: null,
    oldField: null,
    _friendIds: [],
    _postIds: ["201"],
  },
  "4": {
    // ★ email is String! but null → null propagation
    id: "4", name: "Diana", email: null,
    role: "USER", status: "DELETED", score: 42.0,
    tags: ["test"],
    createdAt: null,  // DateTime nullable → OK
    updatedAt: null,
    oldField: null,
    _friendIds: ["1", "2"],
    _postIds: [],
  },
};

const PROFILES = {
  "1": { bio: "Engineer", avatar: "https://example.com/a.jpg", settings: { theme: "dark" } },
  "2": null,  // Profile nullable → OK
  // "3" missing → returns undefined/null
  "4": { bio: null, avatar: null, settings: null },
};

const POSTS = {
  "101": {
    id: "101", title: "Hello World", body: "First post", status: "ACTIVE",
    metadata: { views: 100 },
    createdAt: "2024-01-15T00:00:00Z", updatedAt: null,
    _authorId: "1",
    _commentIds: ["1001"],
  },
  "102": {
    // ★ title is String! but null → null propagation in [Post!]!
    id: "102", title: null, body: "Draft post", status: "SUSPENDED",
    metadata: null,
    createdAt: "2024-02-15T00:00:00Z", updatedAt: null,
    _authorId: "1",
    _commentIds: [],
  },
  "201": {
    id: "201", title: "Charlie's Post", body: null, status: "DELETED",
    metadata: { draft: true },
    createdAt: "2024-03-15T00:00:00Z", updatedAt: null,
    // ★ author is User! referencing user#3 who has null name → deep propagation
    _authorId: "3",
    _commentIds: ["2001"],
  },
};

const COMMENTS = {
  "1001": {
    id: "1001", text: "Great post!",
    _authorId: "2", _postId: "101",
  },
  "2001": {
    // ★ text is String! but null → null propagation
    id: "2001", text: null,
    _authorId: "3", _postId: "201",
  },
};

// ── Resolvers ─────────────────────────────────────────────────────────
const ROOT = {
  user: ({ id }) => USERS[id] || null,
  users: ({ filter, page }) => {
    let result = Object.values(USERS);
    if (filter) {
      if (filter.role) result = result.filter(u => u.role === filter.role);
      if (filter.status) result = result.filter(u => u.status === filter.status);
      if (filter.nameContains) result = result.filter(u => u.name && u.name.includes(filter.nameContains));
      if (filter.scoreAbove != null) result = result.filter(u => u.score != null && u.score > filter.scoreAbove);
      if (filter.scoreBelow != null) result = result.filter(u => u.score != null && u.score < filter.scoreBelow);
    }
    const offset = Math.max(0, (page && page.offset) || 0);
    const limit = Math.max(0, (page && page.limit) || 20);
    return result.slice(offset, offset + limit);
  },
  post: ({ id }) => POSTS[id] || null,
  search: ({ query: q, types }) => {
    const results = [];
    for (const u of Object.values(USERS)) {
      if (u.name && u.name.toLowerCase().includes(q.toLowerCase())) {
        results.push({ ...u, __typename: "User" });
      }
    }
    for (const p of Object.values(POSTS)) {
      if (p.title && p.title.toLowerCase().includes(q.toLowerCase())) {
        results.push({ ...p, __typename: "Post" });
      }
    }
    for (const c of Object.values(COMMENTS)) {
      if (c.text && c.text.toLowerCase().includes(q.toLowerCase())) {
        results.push({ ...c, __typename: "Comment" });
      }
    }
    return results;
  },
  node: ({ id }) => {
    if (USERS[id]) return { ...USERS[id], __typename: "User" };
    if (POSTS[id]) return { ...POSTS[id], __typename: "Post" };
    if (COMMENTS[id]) return { ...COMMENTS[id], __typename: "Comment" };
    return null;
  },
  createUser: ({ input }) => ({
    id: "999", ...input, status: "ACTIVE", score: null, tags: input.tags || [],
    createdAt: "2024-12-01T00:00:00Z", updatedAt: null, oldField: null,
    _friendIds: [], _postIds: [],
  }),
  updateUser: ({ id, name, role }) => {
    const u = USERS[id];
    if (!u) return null;
    return { ...u, name: name || u.name, role: role || u.role };
  },
  deleteUser: ({ id }) => !!USERS[id],
  createPost: ({ authorId, title, body }) => ({
    id: "999", title, body: body || null, status: "ACTIVE",
    metadata: null, createdAt: "2024-12-01T00:00:00Z", updatedAt: null,
    _authorId: authorId, _commentIds: [],
  }),
  userCreated: () => USERS["1"],
  postAdded: () => POSTS["101"],
};

// ── Field resolvers for nested types ──────────────────────────────────
// buildSchema + rootValue only resolves top-level fields.
// For nested fields we need custom resolvers on the type.
// With buildSchema we can't set field resolvers directly, so we use
// property access (graphql-js resolves obj[fieldName] by default).

// Augment user objects with computed fields
function augmentUser(u) {
  if (!u || typeof u !== "object") return u;
  return {
    ...u,
    profile: () => PROFILES[u.id] !== undefined ? PROFILES[u.id] : null,
    friends: ({ limit }) => {
      const ids = u._friendIds || [];
      return ids.slice(0, limit || 10).map(id => augmentUser(USERS[id]));
    },
    posts: ({ limit, offset }) => {
      const ids = u._postIds || [];
      return ids.slice(offset || 0, (offset || 0) + (limit || 10))
        .map(id => augmentPost(POSTS[id]));
    },
  };
}

function augmentPost(p) {
  if (!p || typeof p !== "object") return p;
  return {
    ...p,
    author: () => augmentUser(USERS[p._authorId]),
    comments: () => (p._commentIds || []).map(id => augmentComment(COMMENTS[id])),
  };
}

function augmentComment(c) {
  if (!c || typeof c !== "object") return c;
  return {
    ...c,
    author: () => augmentUser(USERS[c._authorId]),
    post: () => augmentPost(POSTS[c._postId]),
  };
}

// Wrap root resolvers to augment return values
const AUGMENTED_ROOT = {
  ...ROOT,
  user: (args) => augmentUser(ROOT.user(args)),
  users: (args) => ROOT.users(args).map(augmentUser),
  post: (args) => augmentPost(ROOT.post(args)),
  search: (args) => ROOT.search(args).map(r => {
    if (r.__typename === "User") return augmentUser(r);
    if (r.__typename === "Post") return augmentPost(r);
    if (r.__typename === "Comment") return augmentComment(r);
    return r;
  }),
  node: (args) => {
    const n = ROOT.node(args);
    if (!n) return null;
    if (n.__typename === "User") return augmentUser(n);
    if (n.__typename === "Post") return augmentPost(n);
    if (n.__typename === "Comment") return augmentComment(n);
    return n;
  },
  createUser: (args) => augmentUser(ROOT.createUser(args)),
  updateUser: (args) => augmentUser(ROOT.updateUser(args)),
  createPost: (args) => augmentPost(ROOT.createPost(args)),
};

// ── Analysis helpers ──────────────────────────────────────────────────

function simpleHash(str) {
  let h = 0;
  for (let i = 0; i < str.length; i++) {
    h = ((h << 5) - h + str.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(16).padStart(8, "0");
}

function collectNullPaths(obj, prefix) {
  const paths = [];
  if (obj === null || obj === undefined) {
    paths.push(prefix || "root");
    return paths;
  }
  if (typeof obj !== "object") return paths;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const p = `${prefix}[${i}]`;
      if (obj[i] === null) paths.push(p);
      else paths.push(...collectNullPaths(obj[i], p));
    }
    return paths;
  }
  for (const [k, v] of Object.entries(obj)) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (v === null) paths.push(p);
    else if (typeof v === "object") paths.push(...collectNullPaths(v, p));
  }
  return paths;
}

function dataShape(obj, depth) {
  if (depth > 6) return "...";
  if (obj === null || obj === undefined) return "null";
  if (Array.isArray(obj)) {
    if (obj.length === 0) return "[]";
    return "[" + dataShape(obj[0], depth + 1) + "]";
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort().slice(0, 20);
    return "{" + keys.map(k => k + ":" + dataShape(obj[k], depth + 1)).join(",") + "}";
  }
  return typeof obj;
}

// ── Main analysis ─────────────────────────────────────────────────────

async function analyzeQuery(queryStr) {
  const raw = String(queryStr || "").trim();
  if (!raw) throw new Error("Empty query");

  // Phase 1: Parse
  let doc;
  try {
    doc = parse(raw);
  } catch (parseErr) {
    return JSON.stringify({
      parsed: false, valid: false, executed: false,
      parse_error: String(parseErr.message || "").slice(0, 300),
      data: null, data_hash: null, data_shape: null,
      null_paths: [], error_paths: [], error_messages_exec: [],
      error_count_exec: 0, has_partial_data: false,
      null_propagation_depth: 0,
    });
  }

  // Phase 2: Validate
  const validationErrors = validate(SCHEMA, doc);
  const valid = validationErrors.length === 0;

  if (!valid) {
    return JSON.stringify({
      parsed: true, valid: false, executed: false,
      validation_errors: validationErrors.map(e => String(e.message).slice(0, 200)),
      validation_error_count: validationErrors.length,
      data: null, data_hash: null, data_shape: null,
      null_paths: [], error_paths: [], error_messages_exec: [],
      error_count_exec: 0, has_partial_data: false,
      null_propagation_depth: 0,
    });
  }

  // Phase 3: Execute
  let execResult;
  try {
    execResult = await execute({
      schema: SCHEMA,
      document: doc,
      rootValue: AUGMENTED_ROOT,
    });
  } catch (execErr) {
    return JSON.stringify({
      parsed: true, valid: true, executed: false,
      exec_error: String(execErr.message).slice(0, 300),
      data: null, data_hash: null, data_shape: null,
      null_paths: [], error_paths: [], error_messages_exec: [],
      error_count_exec: 0, has_partial_data: false,
      null_propagation_depth: 0,
    });
  }

  const data = execResult.data || null;
  const errors = execResult.errors || [];

  // Collect null paths from data
  const nullPaths = data ? collectNullPaths(data, "") : ["root"];
  nullPaths.sort();

  // Collect error paths
  const errorPaths = errors
    .filter(e => e.path)
    .map(e => e.path.join("."))
    .sort();

  // Error messages for differential comparison
  const errorMsgs = errors.map(e => String(e.message).slice(0, 200)).sort();

  // Data shape for structural comparison
  const shape = dataShape(data, 0);

  // Data hash for exact comparison
  const dataStr = JSON.stringify(data, null, 0);
  const dHash = simpleHash(dataStr);

  // Null propagation depth: max depth of null in the data tree
  let maxNullDepth = 0;
  for (const p of nullPaths) {
    const depth = (p.match(/\./g) || []).length + 1;
    if (depth > maxNullDepth) maxNullDepth = depth;
  }

  const hasPartialData = data !== null && errors.length > 0;

  const result = {
    parsed: true,
    valid: true,
    executed: true,
    data: data,
    data_hash: dHash,
    data_shape: shape,
    null_paths: nullPaths,
    null_path_hash: simpleHash(nullPaths.join("|")),
    error_paths: errorPaths,
    error_path_hash: simpleHash(errorPaths.join("|")),
    error_messages_exec: errorMsgs,
    error_count_exec: errors.length,
    has_partial_data: hasPartialData,
    null_propagation_depth: maxNullDepth,
  };
  return JSON.stringify(result);
}

module.exports = { analyzeQuery };

if (require.main === module) {
  const inputPath = process.argv[2];
  if (!inputPath) {
    process.stderr.write("Usage: node graphql_node_graphqljs_exec.js <input_file>\n");
    process.exit(2);
  }
  try {
    const input = fs.readFileSync(inputPath, "utf8");
    analyzeQuery(input).then(result => {
      process.stdout.write(result + "\n");
      process.exit(0);
    }).catch(err => {
      process.stderr.write("REJECT: " + err.message + "\n");
      process.exit(1);
    });
  } catch (err) {
    process.stderr.write("REJECT: " + err.message + "\n");
    process.exit(1);
  }
}
