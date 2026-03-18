// Common escape validation for all sandbox targets.
// Instead of trusting _report() calls, we check if the reported value
// is actually a reference to an outer-scope object (process, require, etc.)

const ESCAPE_MARKERS = new Set([
    '[object process]', '[object Module]', '[object Object]',
]);

/**
 * Validate whether a reported value is a genuine sandbox escape.
 * - If val is the actual `process` object → genuine escape
 * - If val is `require` function → genuine escape
 * - If val looks like process.version (vX.Y.Z) → genuine escape
 * - If val is a simple string/number/boolean → NOT escape (FP from Proxy traps etc.)
 */
function validateEscape(val, outerProcess, outerRequire, outerGlobal) {
    if (val === undefined || val === null) return { escaped: false, reason: 'null' };

    // Direct reference check
    if (val === outerProcess) return { escaped: true, payload: 'process', reason: 'direct_ref' };
    if (val === outerRequire) return { escaped: true, payload: 'require', reason: 'direct_ref' };
    if (val === outerGlobal) return { escaped: true, payload: 'global', reason: 'direct_ref' };

    // Check if val has process-like properties (duck typing)
    try {
        if (val && typeof val === 'object' && typeof val.exit === 'function' && val.version) {
            return { escaped: true, payload: `process(${val.version})`, reason: 'duck_type' };
        }
        if (typeof val === 'function' && val.resolve) {
            return { escaped: true, payload: 'require', reason: 'duck_type' };
        }
    } catch (_) {}

    // Check if val is a string that looks like it came from outside
    const s = String(val);
    if (/^v\d+\.\d+\.\d+/.test(s)) return { escaped: true, payload: s, reason: 'version_string' };
    // Path leak but NOT in stack traces (which contain " at " lines)
    if ((s.includes('/Users/') || s.includes('/home/') || /^[A-Z]:\\/.test(s))
        && !s.includes(' at ') && !s.includes('Error:') && s.length < 200)
        return { escaped: true, payload: s.slice(0, 100), reason: 'path_leak' };
    if (s === 'function require' || s.startsWith('function require'))
        return { escaped: true, payload: 'require_toString', reason: 'func_string' };

    // Not a genuine escape
    return { escaped: false, payload: s.slice(0, 100), reason: 'benign_value' };
}

/**
 * Classify error message into a bucket for coverage signal.
 */
function classifyError(msg) {
    if (!msg) return 'none';
    if (msg.includes('not defined')) return 'not_defined';
    if (msg.includes('not a function')) return 'not_function';
    if (msg.includes('not a constructor')) return 'not_constructor';
    if (msg.includes('disallowed') || msg.includes('Disallowed')) return 'access_denied';
    if (msg.includes('Cannot read') || msg.includes('cannot read')) return 'null_access';
    if (msg.includes('Unexpected token') || msg.includes('Unexpected identifier')) return 'syntax';
    if (msg.includes('timed out') || msg.includes('timeout')) return 'timeout';
    if (msg.includes('not extensible') || msg.includes('read only')) return 'frozen';
    if (msg.includes('Maximum call stack')) return 'stack_overflow';
    if (msg.includes('could not be cloned')) return 'clone_error';
    return 'other';
}

/**
 * Create a tracked sandbox context that monitors API access patterns.
 * Returns {context, trace} where trace has boolean flags for coverage.
 */
function createTrackedContext(reportFn) {
    const trace = {
        constructorAccessed: false,
        protoAccessed: false,
        functionCreated: false,
        evalAttempted: false,
        proxyCreated: false,
        symbolAccessed: false,
        asyncUsed: false,
        reflectUsed: false,
    };

    const context = {
        _report: reportFn,
        // Trap common escape-related globals
        Function: new Proxy(Function, {
            apply(t, thisArg, args) { trace.functionCreated = true; return undefined; },
            construct(t, args) { trace.functionCreated = true; return {}; },
        }),
        eval: function(code) { trace.evalAttempted = true; return undefined; },
        Proxy: new Proxy(Proxy, {
            construct(t, args) { trace.proxyCreated = true; try { return new t(...args); } catch(e) { return {}; } },
        }),
        Reflect: new Proxy(Reflect || {}, {
            get(t, p) { trace.reflectUsed = true; return t[p]; },
        }),
        Symbol: new Proxy(Symbol, {
            get(t, p) { trace.symbolAccessed = true; return t[p]; },
        }),
        Promise: new Proxy(Promise, {
            get(t, p) { trace.asyncUsed = true; return t[p]; },
            construct(t, args) { trace.asyncUsed = true; return new t(...args); },
        }),
        // Standard safe builtins
        Object, Array, String, Number, Boolean, Math, JSON, Date, RegExp,
        parseInt, parseFloat, isNaN, isFinite,
        undefined, NaN, Infinity,
        Error, TypeError, RangeError, ReferenceError, SyntaxError, URIError,
        console: { log() {}, warn() {}, error() {} },
    };

    return { context, trace };
}

module.exports = { validateEscape, classifyError, createTrackedContext };
