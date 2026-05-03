import json
import socket
import struct
import subprocess
import sys
import threading
import time


def test_pgwire_target_dry_run(tmp_path):
    artifact = tmp_path / "sample.pgwire"
    artifact.write_text(
        "\n".join(
            [
                "WFPG1",
                'M {"axis_delivery":"single","axis_framing":"valid","axis_query":"baseline","axis_startup":"plain","axis_state":"simple_query","delivery_mode":"single","frame_corruption":"none","pause_ms":0,"pgwire_mode":"stable","probe_mode":"none","request_id":"dryrun","split_offset":5,"startup_mode":"plain","transport_mode":"pgsql_v3","variant_family":"simple_query_baseline"}',
                'A {"op":"startup","parameters":{"application_name":"webfuzzer","database":"test","user":"fuzz"}}',
                'A {"op":"query","sql":"select 1"}',
                'A {"op":"terminate"}',
                "",
            ]
        ),
        encoding="utf-8",
    )

    proc = subprocess.run(
        [
            sys.executable,
            "targets/pgsql_wire_target.py",
            "--dry-run",
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["transport_mode"] == "pgsql_v3"
    assert data["action_count"] == 3
    assert data["expected_ready_count"] == 2
    assert data["frame_lengths"]
    assert data["parse_error"] == ""


def test_pgwire_target_reads_past_startup_ready(tmp_path):
    artifact = tmp_path / "sample.pgwire"
    artifact.write_text(
        "\n".join(
            [
                "WFPG1",
                'M {"axis_delivery":"single","axis_framing":"valid","axis_query":"baseline","axis_startup":"plain","axis_state":"simple_query","delivery_mode":"single","frame_corruption":"none","pause_ms":0,"pgwire_mode":"stable","probe_mode":"none","request_id":"readtwo","split_offset":5,"startup_mode":"plain","transport_mode":"pgsql_v3","variant_family":"simple_query_baseline"}',
                'A {"op":"startup","parameters":{"application_name":"webfuzzer","database":"test","user":"fuzz"}}',
                'A {"op":"query","sql":"select 1"}',
                'A {"op":"terminate"}',
                "",
            ]
        ),
        encoding="utf-8",
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    auth_ok = b"R" + struct.pack("!I", 8) + struct.pack("!I", 0)
    ready = b"Z" + struct.pack("!I", 5) + b"I"
    command_complete = (
        b"C" + struct.pack("!I", len(b"SELECT 1\x00") + 4) + b"SELECT 1\x00"
    )

    def _serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(8192)
            conn.sendall(auth_ok + ready + command_complete + ready)
            time.sleep(0.1)
        listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    proc = subprocess.run(
        [
            sys.executable,
            "targets/pgsql_wire_target.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["ready_for_query_seen"] is True
    assert data["execution_response_types"] == ["C", "Z"]
    assert data["command_complete_seen"] == 1
    assert data["query_effect_seen"] is True
    assert data["execution_completed"] is True
    assert data["progress_stage"] == "execution_complete"
    thread.join(timeout=1.0)


def test_pgwire_target_ssl_probe(tmp_path):
    artifact = tmp_path / "ssl.pgwire"
    artifact.write_text(
        "\n".join(
            [
                "WFPG1",
                'M {"axis_delivery":"single","axis_framing":"valid","axis_query":"none","axis_startup":"plain","axis_state":"handshake_probe","delivery_mode":"single","frame_corruption":"none","handshake_mode":"ssl","pause_ms":0,"pgwire_mode":"stable","probe_mode":"ssl_request","request_id":"sslprobe","split_offset":5,"startup_mode":"plain","transport_mode":"pgsql_v3","variant_family":"ssl_probe"}',
                'A {"op":"ssl_request"}',
                "",
            ]
        ),
        encoding="utf-8",
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(8192)
            conn.sendall(b"S")
            time.sleep(0.1)
        listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    proc = subprocess.run(
        [
            sys.executable,
            "targets/pgsql_wire_target.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["handshake_response_types"] == ["S"]
    assert data["variant_family"] == "ssl_probe"
    assert data["response_types"] == []
    thread.join(timeout=1.0)


def test_pgwire_target_gss_then_query(tmp_path):
    artifact = tmp_path / "gss_then_query.pgwire"
    artifact.write_text(
        "\n".join(
            [
                "WFPG1",
                'M {"axis_delivery":"single","axis_framing":"valid","axis_query":"baseline","axis_startup":"plain","axis_state":"probe_then_startup","delivery_mode":"single","frame_corruption":"none","handshake_mode":"gss","pause_ms":0,"pgwire_mode":"stable","probe_mode":"gssenc_request","request_id":"gssquery","split_offset":5,"startup_mode":"plain","transport_mode":"pgsql_v3","variant_family":"gss_then_query"}',
                'A {"op":"gssenc_request"}',
                'A {"op":"startup","parameters":{"application_name":"webfuzzer","database":"test","user":"fuzz"}}',
                'A {"op":"query","sql":"select 1"}',
                'A {"op":"terminate"}',
                "",
            ]
        ),
        encoding="utf-8",
    )

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    auth_ok = b"R" + struct.pack("!I", 8) + struct.pack("!I", 0)
    ready = b"Z" + struct.pack("!I", 5) + b"I"
    command_complete = (
        b"C" + struct.pack("!I", len(b"SELECT 1\x00") + 4) + b"SELECT 1\x00"
    )

    def _serve() -> None:
        conn, _ = listener.accept()
        with conn:
            conn.recv(8)
            conn.sendall(b"N")
            conn.recv(8192)
            conn.sendall(auth_ok + ready)
            conn.recv(8192)
            conn.sendall(command_complete + ready)
            time.sleep(0.1)
        listener.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()

    proc = subprocess.run(
        [
            sys.executable,
            "targets/pgsql_wire_target.py",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            str(artifact),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["handshake_response_types"] == ["N"]
    assert data["execution_response_types"] == ["C", "Z"]
    assert data["command_complete_seen"] == 1
    assert data["post_probe_startup_seen"] is True
    assert data["post_probe_execution_seen"] is True
    thread.join(timeout=1.0)
