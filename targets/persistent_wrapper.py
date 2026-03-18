"""Persistent wrapper for Python fuzzing target modules.

Keeps Python process alive and reuses loaded modules.
Protocol: length-prefixed binary over stdin/stdout.

  Request:  [4-byte BE length][input bytes]
  Response: [4-byte BE length][output bytes][4-byte BE exit code]

Extended protocol (--coverage flag):
  Response: [4B len][output][4B exit_code|0x01000000][4B cov_len][coverage bitmap]
  sys.settrace line-level coverage is hashed into a 16KB bitmap.

Supported module interfaces:
  - process(input) -> {"output": str, "exit_code": int}
  - sanitize(input) -> str  (exit code always 0; raises -> exit code 1)

Usage: python persistent_wrapper.py ./module_path.py [--coverage]
"""
import gc
import importlib.util
import struct
import sys
import os

# Periodic GC to prevent heap growth in long-running sessions.
_GC_EVERY = 500
_gc_counter = 0

# ── Coverage constants ──────────────────────────────────────────
COV_BITMAP_SIZE = 16384
COV_FLAG = 0x01000000  # Flag bit in exit code


def _fnv1a_hash(s: str) -> int:
    """Simple FNV-1a hash for coverage bitmap indexing."""
    h = 0x811C9DC5  # FNV-1a offset basis
    for c in s:
        h ^= ord(c)
        h = (h * 0x01000193) & 0xFFFFFFFF  # FNV prime, force uint32
    return h


class LineTracer:
    """sys.settrace-based line coverage collector.

    Hashes filename:lineno into a 16KB bitmap for fast novelty detection,
    AND collects actual (file, line) tuples for concolic branch mapping.
    """

    __slots__ = (
        "_bitmap", "_prev_bitmap", "_trace_dirs", "_active",
        "_cumulative_lines", "_iter_lines",
    )

    def __init__(self, trace_dirs: list[str] | str) -> None:
        self._bitmap = bytearray(COV_BITMAP_SIZE)
        self._prev_bitmap = bytearray(COV_BITMAP_SIZE)
        if isinstance(trace_dirs, str):
            trace_dirs = [trace_dirs]
        self._trace_dirs = trace_dirs
        self._active = False
        # Actual (file, line) tracking for concolic
        self._cumulative_lines: set = set()  # all lines ever hit
        self._iter_lines: set = set()  # lines hit this iteration

    def start(self) -> None:
        """Install the trace function."""
        self._prev_bitmap[:] = self._bitmap
        self._iter_lines = set()
        self._active = True
        sys.settrace(self._trace)

    def stop(self) -> tuple[bytes | None, list | None]:
        """Remove trace and return (delta_bitmap, new_lines_list).

        new_lines_list: [[basename, line], ...] for lines hit this iteration
        that were never hit before.  None if no new lines.
        """
        sys.settrace(None)
        self._active = False

        # Compute bitmap delta
        has_new_bitmap = False
        delta = bytearray(COV_BITMAP_SIZE)
        for i in range(COV_BITMAP_SIZE):
            if self._bitmap[i] and not self._prev_bitmap[i]:
                delta[i] = 1
                has_new_bitmap = True

        # Compute new source lines
        new_lines = self._iter_lines - self._cumulative_lines
        self._cumulative_lines.update(self._iter_lines)

        new_lines_list = None
        if new_lines:
            new_lines_list = [[f, l] for f, l in sorted(new_lines)]

        bitmap = bytes(delta) if has_new_bitmap else None
        return bitmap, new_lines_list

    def _trace(self, frame, event, arg):
        """Trace function installed via sys.settrace."""
        if event == "call":
            filename = frame.f_code.co_filename
            if sys.platform == "win32":
                filename = filename.lower()
            if any(d in filename for d in self._trace_dirs):
                return self._trace_lines
        return None

    def _trace_lines(self, frame, event, arg):
        """Line-level trace: bitmap hash + actual (file, line) collection."""
        if event == "line":
            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            # Bitmap (fast, for coverage novelty)
            key = f"{filename}:{lineno}"
            idx = _fnv1a_hash(key) % COV_BITMAP_SIZE
            self._bitmap[idx] = 1
            # Actual line tracking (for concolic branch mapping)
            # Use full path for unambiguous resolution, basename for backward compat
            self._iter_lines.add((filename, lineno))
        return self._trace_lines


def main():
    global _gc_counter

    # Parse args: module path + optional --coverage flag
    module_path = None
    coverage_enabled = False
    lines_only = False  # --coverage-lines-only: inject _covered_lines but no bitmap
    extra_trace_dirs = []  # --trace-dir <path>: additional dirs to trace
    args_iter = iter(sys.argv[1:])
    for arg in args_iter:
        if arg == "--coverage":
            coverage_enabled = True
        elif arg == "--coverage-lines-only":
            coverage_enabled = True
            lines_only = True
        elif arg == "--trace-dir":
            try:
                extra_trace_dirs.append(next(args_iter))
            except StopIteration:
                pass
        elif module_path is None:
            module_path = arg

    if not module_path:
        sys.stderr.write("Usage: python persistent_wrapper.py <module_path> [--coverage]\n")
        sys.exit(1)

    # Load module
    abs_module_path = os.path.abspath(module_path)
    spec = importlib.util.spec_from_file_location("target_module", abs_module_path)
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

    # Initialize coverage tracer
    tracer = None
    if coverage_enabled:
        # Track target module dir + specific library packages (not all site-packages)
        trace_dirs = [os.path.dirname(abs_module_path)]
        # Add known security library paths
        _lib_modules = ["signxml", "onelogin", "jwt", "jose", "jwcrypto", "authlib",
                        "oauthlib", "http"]
        for p in sys.path:
            if "site-packages" in p and os.path.isdir(p):
                for lib in _lib_modules:
                    lib_path = os.path.join(p, lib)
                    if os.path.isdir(lib_path):
                        trace_dirs.append(lib_path)
                break
        # Add stdlib path for modules like http.cookies
        import sysconfig
        stdlib_dir = sysconfig.get_path("stdlib")
        if stdlib_dir:
            for lib in _lib_modules:
                lib_path = os.path.join(stdlib_dir, lib)
                if os.path.isdir(lib_path):
                    trace_dirs.append(lib_path)
        # Add user-specified extra trace directories
        for d in extra_trace_dirs:
            abs_d = os.path.abspath(d)
            if os.path.isdir(abs_d):
                trace_dirs.append(abs_d)
        # Normalize case on Windows (co_filename may differ in case from os.path)
        if sys.platform == "win32":
            trace_dirs = [d.lower() for d in trace_dirs]
        tracer = LineTracer(trace_dirs)

    # Disable automatic GC; we trigger it manually on a schedule.
    gc.disable()

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

        # Start coverage tracing before target execution
        if tracer is not None:
            tracer.start()

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

        # Stop tracing and get delta bitmap + new source lines
        cov_bitmap = None
        new_lines = None
        if tracer is not None:
            cov_bitmap, new_lines = tracer.stop()
            if lines_only:
                cov_bitmap = None  # don't send bitmap, only _covered_lines in JSON

        out_bytes = output.encode("utf-8")

        # Inject new_lines into output JSON if available
        # This piggybacks on the existing output channel without protocol changes
        if new_lines is not None and out_bytes:
            import json as _json
            try:
                out_data = _json.loads(out_bytes)
                out_data["_covered_lines"] = new_lines
                out_bytes = _json.dumps(out_data).encode("utf-8")
            except Exception:
                pass

        if cov_bitmap is not None:
            # Extended protocol: [4B len][output][4B exit_code|COV_FLAG][4B cov_len][bitmap]
            resp = (
                struct.pack(">I", len(out_bytes))
                + out_bytes
                + struct.pack(">I", (exit_code | COV_FLAG) & 0xFFFFFFFF)
                + struct.pack(">I", len(cov_bitmap))
                + cov_bitmap
            )
        else:
            # Standard protocol: [4-byte len][output][4-byte exit code]
            resp = struct.pack(">I", len(out_bytes)) + out_bytes + struct.pack(">I", exit_code)

        stdout.write(resp)
        stdout.flush()

        # Periodic GC to cap memory growth
        _gc_counter += 1
        if _gc_counter >= _GC_EVERY:
            _gc_counter = 0
            gc.collect()


if __name__ == "__main__":
    main()
