// Sandbox target: expression-eval (expression parser + evaluator)
const exprEval = require('expression-eval');
const { validateEscape, classifyError } = require('./sandbox_common');

const _outerProcess = process;
const _outerRequire = require;
const _outerGlobal = global;

module.exports.process = function (code) {
    const result = {
        escaped: false, payload: null, error: null, type: null,
        validation: null, retType: null, errorPattern: 'none',
        reportCalled: false, reportValType: null,
        constructorInCode: /\.constructor/.test(code),
        protoInCode: /__proto__|getPrototypeOf/.test(code),
        evalInCode: /\beval\b/.test(code),
        functionInCode: /\bFunction\b/.test(code),
        proxyInCode: /\bProxy\b/.test(code),
        symbolInCode: /\bSymbol\b/.test(code),
        asyncInCode: /\basync\b|\bPromise\b|\bawait\b/.test(code),
        tryCatchInCode: /\btry\b/.test(code),
    };
    try {
        const ast = exprEval.parse(String(code));
        const env = {
            _report: (val) => {
                result.reportCalled = true;
                result.reportValType = val === null ? 'null' : typeof val;
                const v = validateEscape(val, _outerProcess, _outerRequire, _outerGlobal);
                if (v.escaped) { result.escaped = true; result.payload = v.payload; result.validation = v.reason; }
            },
        };
        const ret = exprEval.eval(ast, env);
        if (ret !== undefined) { result.returnValue = String(ret).slice(0, 100); result.retType = typeof ret; }
    } catch (e) {
        result.error = (e.message || '').slice(0, 200);
        result.type = e.constructor ? e.constructor.name : 'Unknown';
        result.errorPattern = classifyError(result.error);
    }
    return { output: JSON.stringify(result), exitCode: result.escaped ? 0 : 1 };
};
