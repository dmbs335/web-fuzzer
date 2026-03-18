// Sandbox target: Node.js built-in vm module (NOT a real sandbox — known weak)
const vm = require('vm');
const { validateEscape } = require('./sandbox_common');

const _outerProcess = process;
const _outerRequire = require;
const _outerGlobal = global;

module.exports.process = function (code) {
    const result = { escaped: false, payload: null, error: null, type: null, validation: null };
    try {
        const sandbox = {
            _report: (val) => {
                const v = validateEscape(val, _outerProcess, _outerRequire, _outerGlobal);
                if (v.escaped) {
                    result.escaped = true;
                    result.payload = v.payload;
                    result.validation = v.reason;
                }
            },
        };
        vm.createContext(sandbox);
        const ret = vm.runInContext(String(code), sandbox, { timeout: 3000 });
        if (ret !== undefined) result.returnValue = String(ret).slice(0, 100);
    } catch (e) {
        result.error = (e.message || '').slice(0, 200);
        result.type = e.constructor ? e.constructor.name : 'Unknown';
    }
    return { output: JSON.stringify(result), exitCode: result.escaped ? 0 : 1 };
};
