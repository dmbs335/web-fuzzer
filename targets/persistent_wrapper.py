"""Persistent wrapper for Python fuzzing target modules.

Keeps Python process alive and reuses loaded modules.
Protocol: length-prefixed binary over stdin/stdout.

  Request:  [4-byte BE length][input bytes]
  Response: [4-byte BE length][output bytes][4-byte BE exit code]

Supported module interfaces:
  - process(input) -> {"output": str, "exit_code": int}
  - sanitize(input) -> str  (exit code always 0; raises -> exit code 1)

Usage: python persistent_wrapper.py ./module_path.py
"""
import importlib.util
import struct
import sys
import os


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python persistent_wrapper.py <module_path>\n")
        sys.exit(1)

    module_path = sys.argv[1]

    # Load module
    spec = importlib.util.spec_from_file_location("target_module", os.path.abspath(module_path))
    if spec is None or spec.loader is None:
        sys.stderr.write(f"Cannot load module: {module_path}\n")
        sys.exit(1)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    use_process = hasattr(mod, "process") and callable(mod.process)
    use_sanitize = hasattr(mod, "sanitize") and callable(mod.sanitize)
    if not use_process and not use_sanitize:
        sys.stderr.write(f"Module {module_path} must export process(input) or sanitize(input)\n")
        sys.exit(1)

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        # Read 4-byte length header
        header = stdin.read(4)
        if len(header) < 4:
            break  # EOF

        length = struct.unpack(">I", header)[0]

        # Read input data
        data = stdin.read(length)
        if len(data) < length:
            break  # EOF

        input_str = data.decode("utf-8", errors="replace")

        output = ""
        exit_code = 0
        try:
            if use_process:
                result = mod.process(input_str)
                output = result.get("output", "")
                exit_code = result.get("exit_code", 0)
            else:
                output = mod.sanitize(input_str)
        except Exception as e:
            output = ""
            exit_code = 1
            sys.stderr.write(f"Error: {e}\n")

        out_bytes = output.encode("utf-8")
        # Response: [4-byte len][output][4-byte exit code]
        resp = struct.pack(">I", len(out_bytes)) + out_bytes + struct.pack(">I", exit_code)
        stdout.write(resp)
        stdout.flush()


if __name__ == "__main__":
    main()
