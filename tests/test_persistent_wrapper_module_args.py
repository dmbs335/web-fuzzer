import json
import struct
import subprocess
import sys


def _read_response(stdout) -> tuple[str, int]:
    header = stdout.read(4)
    assert len(header) == 4
    out_len = struct.unpack(">I", header)[0]
    payload = stdout.read(out_len)
    exit_code = struct.unpack(">I", stdout.read(4))[0]
    return payload.decode("utf-8"), exit_code


def test_persistent_wrapper_passes_module_args(tmp_path):
    module_path = tmp_path / "echo_module.py"
    module_path.write_text(
        "\n".join(
            [
                "CONFIG = []",
                "",
                "def configure(args):",
                "    global CONFIG",
                "    CONFIG = list(args)",
                "",
                "def process(input):",
                "    import json",
                "    return {",
                "        'output': json.dumps({'args': CONFIG, 'input': input}),",
                "        'exit_code': 0,",
                "    }",
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.Popen(
        [
            sys.executable,
            "targets/persistent_wrapper.py",
            str(module_path),
            "--host",
            "127.0.0.1",
            "--port",
            "5432",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        payload = b"hello"
        proc.stdin.write(struct.pack(">I", len(payload)) + payload)
        proc.stdin.flush()
        output, exit_code = _read_response(proc.stdout)
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    data = json.loads(output)
    assert exit_code == 0
    assert data["input"] == "hello"
    assert data["args"] == ["--host", "127.0.0.1", "--port", "5432"]
