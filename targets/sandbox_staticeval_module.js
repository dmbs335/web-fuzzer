// Sandbox target: static-eval (AST-based static evaluation)
const evaluate = require('static-eval');
const { parse } = require('acorn');
const { validateEscape } = require('./sandbox_common');

const _outerProcess = process;
const _outerRequire = require;
const _outerGlobal = global;

module.exports.process = function (code) {
    const result = { escaped: false, payload: null, error: null, type: null,
                     validation: null, retType: null, reportCalled: false };
    try {
        // static-eval works on AST nodes, needs acorn to parse
        const ast = parse(String(code), { ecmaVersion: 2020, sourceType: 'script' });
        const expr = ast.body[0] && ast.body[0].expression;
        if (!expr) { result.error = 'no expression'; result.type = 'ParseError'; }
        else {
            const env = {
                _report: (val) => {
                    result.reportCalled = true;
                    const v = validateEscape(val, _outerProcess, _outerRequire, _outerGlobal);
                    if (v.escaped) { result.escaped = true; result.payload = v.payload; result.validation = v.reason; }
                },
            };
            const ret = evaluate(expr, env);
            if (ret !== undefined) { result.returnValue = String(ret).slice(0, 100); result.retType = typeof ret; }
        }
    } catch (e) {
        result.error = (e.message || '').slice(0, 200);
        result.type = e.constructor ? e.constructor.name : 'Unknown';
    }
    return { output: JSON.stringify(result), exitCode: result.escaped ? 0 : 1 };
};
