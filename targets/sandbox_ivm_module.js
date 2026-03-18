// Sandbox target: isolated-vm (V8 Isolate, true realm isolation)
const ivm = require('isolated-vm');

module.exports.process = function (code) {
    const result = { escaped: false, payload: null, error: null, type: null, validation: null };
    let isolate;
    try {
        isolate = new ivm.Isolate({ memoryLimit: 32 });
        const context = isolate.createContextSync();
        const jail = context.global;

        // Inject _report — in ivm, callback runs in host context.
        // val is copied (not referenced) across isolate boundary.
        // Only mark as escape if val looks like a genuine outer-scope leak,
        // NOT error stacks or simple strings.
        jail.setSync('_report', new ivm.Callback((val) => {
            const s = String(val);
            // Genuine escape indicators:
            // 1. process.version string (vX.Y.Z at start)
            // 2. require function toString
            // 3. Absolute filesystem path (not in stack traces)
            const isVersion = /^v\d+\.\d+\.\d+$/.test(s.trim());
            const isRequire = s === 'function require' || s.startsWith('function require(');
            // Path leak but NOT in stack trace (stack traces contain "at " prefix)
            const isPathLeak = (s.includes('/Users/') || s.includes('/home/') || /^[A-Z]:\\/.test(s))
                && !s.includes(' at ') && !s.includes('Error:');
            if (isVersion || isRequire || isPathLeak) {
                result.escaped = true;
                result.payload = s.slice(0, 200);
                result.validation = 'ivm_callback';
            }
        }));

        const script = isolate.compileScriptSync(String(code));
        script.runSync(context, { timeout: 3000 });
    } catch (e) {
        result.error = (e.message || '').slice(0, 200);
        result.type = e.constructor ? e.constructor.name : 'Unknown';
    } finally {
        if (isolate) try { isolate.dispose(); } catch (_) {}
    }
    return { output: JSON.stringify(result), exitCode: result.escaped ? 0 : 1 };
};
