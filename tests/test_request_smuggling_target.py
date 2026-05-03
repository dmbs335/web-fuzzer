import importlib.util
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded


_TARGET_PATH = Path(__file__).resolve().parents[1] / "targets" / "request_smuggling_target.py"
_SPEC = importlib.util.spec_from_file_location("request_smuggling_target", _TARGET_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
_extract_control = _MODULE._extract_control
execute_wire = _MODULE.execute_wire


def _server_once(responses: list[bytes]) -> tuple[int, threading.Thread]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _run():
        conn, _ = listener.accept()
        try:
            _ = conn.recv(65535)
            for item in responses:
                conn.sendall(item)
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return port, thread


def _early_response_server() -> tuple[int, threading.Thread]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _run():
        conn, _ = listener.accept()
        try:
            _ = conn.recv(128)
            conn.sendall(
                b"HTTP/1.1 400 Bad Request\r\n"
                b"Content-Length: 15\r\n"
                b"X-Frontend-Marker: yes\r\n\r\n"
                b"FRONTEND-MARKER"
            )
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return port, thread


def _h2_server_once() -> tuple[int, threading.Thread]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _run():
        conn, _ = listener.accept()
        conn.settimeout(1.0)
        config = H2Configuration(client_side=False, header_encoding="utf-8")
        h2_conn = H2Connection(config=config)
        h2_conn.initiate_connection()
        conn.sendall(h2_conn.data_to_send())
        body = bytearray()
        stream_id = None
        try:
            while True:
                data = conn.recv(65535)
                if not data:
                    break
                events = h2_conn.receive_data(data)
                for event in events:
                    if isinstance(event, RequestReceived):
                        stream_id = event.stream_id
                    elif isinstance(event, DataReceived):
                        body.extend(event.data)
                        h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        response_body = b"BACKEND-MARKER " + bytes(body[:64])
                        h2_conn.send_headers(
                            event.stream_id,
                            [
                                (":status", "200"),
                                ("content-length", str(len(response_body))),
                                ("x-backend-marker", "yes"),
                            ],
                        )
                        h2_conn.send_data(event.stream_id, response_body, end_stream=True)
                outgoing = h2_conn.data_to_send()
                if outgoing:
                    conn.sendall(outgoing)
                if stream_id is not None and body:
                    continue
        finally:
            conn.close()
            listener.close()

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return port, thread


class TestRequestSmugglingTarget:
    def test_extract_control_headers(self):
        wire = (
            b"POST / HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: abc123\r\n"
            b"X-WF-Family: cl_te\r\n"
            b"X-WF-Tags: CL.TE,content_length\r\n"
            b"X-WF-Transport: h1_raw\r\n"
            b"X-WF-Delivery: pause_probe_h1\r\n"
            b"X-WF-Probe: pause_prefix\r\n"
            b"X-WF-Pause-MS: 250\r\n"
            b"X-WF-Chunk-Shape: none\r\n"
            b"X-WF-Mode: research\r\n"
            b"X-WF-Axis-Framing: TE\r\n"
            b"X-WF-Axis-Leniency: obs_fold\r\n"
            b"X-WF-Axis-Chunk: chunk_extension\r\n"
            b"X-WF-Axis-Connection: keepalive\r\n"
            b"X-WF-Axis-Timing: pause_prefix\r\n"
            b"X-WF-Axis-Routing: x_original_url\r\n"
            b"X-WF-Stream-Shape: body_plus_canary\r\n"
            b"\r\n"
            b"body"
        )
        meta, stripped = _extract_control(wire)
        assert meta["request_id"] == "abc123"
        assert meta["variant_family"] == "cl_te"
        assert meta["taxonomy_tags"] == ["CL.TE", "content_length"]
        assert meta["delivery_mode"] == "pause_probe_h1"
        assert meta["probe_mode"] == "pause_prefix"
        assert meta["pause_ms"] == 250
        assert meta["request_smuggling_mode"] == "research"
        assert meta["axis_framing"] == "TE"
        assert meta["axis_routing"] == "x_original_url"
        assert b"X-WF-" not in stripped

    def test_extract_control_falls_back_to_family_axes(self):
        wire = (
            b"POST / HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: fallback01\r\n"
            b"X-WF-Family: trailer_merge\r\n"
            b"X-WF-Tags: TE.TE,trailer_merge\r\n"
            b"\r\n"
            b"body"
        )
        meta, _ = _extract_control(wire)
        assert meta["axis_framing"] == "TE"
        assert meta["axis_chunk"] == "trailer_override_path"
        assert meta["axis_routing"] == "x_original_url"
        assert meta["stream_shape"] == "trailers_plus_canary"

    def test_execute_wire_parses_two_responses_and_persists_artifact(self):
        body1 = b"front body"
        body2 = b"backend body /__canary__/abc123"
        responses = [
            (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: 10\r\n"
                b"X-Frontend-Marker: yes\r\n\r\n" + body1
            ),
            (
                b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Length: " + str(len(body2)).encode() + b"\r\n"
                b"X-Backend-Marker: yes\r\n\r\n" + body2
            ),
        ]
        port, thread = _server_once(responses)
        wire = (
            b"POST / HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: abc123\r\n"
            b"X-WF-Family: cl_te\r\n"
            b"X-WF-Tags: CL.TE,content_length,transfer_encoding\r\n"
            b"X-WF-Transport: h1_raw\r\n"
            b"X-WF-Delivery: oneshot_h1\r\n"
            b"X-WF-Probe: none\r\n"
            b"X-WF-Pause-MS: 0\r\n"
            b"X-WF-Chunk-Shape: none\r\n"
            b"Connection: keep-alive\r\n"
            b"Content-Length: 4\r\n\r\n"
            b"body"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = execute_wire(wire, host="127.0.0.1", port=port, timeout=1.0, artifact_dir=tmpdir)
        thread.join(timeout=1.0)
        assert result["first_response_status"] == 200
        assert result["second_response_status"] == 404
        assert result["frontend_marker_seen"] is True
        assert result["backend_marker_seen"] is True
        assert result["canary_seen_in_second"] is True
        assert result["response_count_observed"] == 2
        assert result["artifact_path_stable"].endswith("abc123.wire")

    def test_execute_wire_captures_observation_headers(self):
        body = b"BACKEND-MARKER cache IMPACT:cache_poison"
        responses = [
            (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"X-Backend-Marker: cache\r\n"
                b"X-Forwarded-Request-Line: POST /cache/store HTTP/1.1\r\n"
                b"X-Forwarded-Request-Hash: abcdef0123456789abcd\r\n"
                b"X-Effective-Headers: host=victim.local;x-original-url=/shadow-admin\r\n"
                b"X-Body-Boundary: bytes=7;chunked=false;trailers=1\r\n"
                b"X-Trailer-Forwarded: true\r\n"
                b"X-Routing-Decision-Source: trailer\r\n"
                b"X-Cache-Decision-Source: trailer\r\n"
                b"X-Impact-Marker: cache_poison\r\n"
                b"\r\n" + body
            ),
        ]
        port, thread = _server_once(responses)
        wire = (
            b"POST /cache/store HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: axis01\r\n"
            b"X-WF-Family: trailer_merge\r\n"
            b"X-WF-Tags: TE.TE,trailer_merge\r\n"
            b"X-WF-Transport: h1_raw\r\n"
            b"X-WF-Delivery: oneshot_h1\r\n"
            b"X-WF-Probe: none\r\n"
            b"X-WF-Pause-MS: 0\r\n"
            b"X-WF-Chunk-Shape: trailer_merge\r\n"
            b"X-WF-Mode: research\r\n"
            b"X-WF-Axis-Framing: TE\r\n"
            b"X-WF-Axis-Leniency: strict\r\n"
            b"X-WF-Axis-Chunk: trailer_override_path\r\n"
            b"X-WF-Axis-Connection: keepalive\r\n"
            b"X-WF-Axis-Timing: none\r\n"
            b"X-WF-Axis-Routing: x_original_url\r\n"
            b"X-WF-Stream-Shape: trailers_plus_canary\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n"
        )
        result = execute_wire(wire, host="127.0.0.1", port=port, timeout=1.0)
        thread.join(timeout=1.0)
        assert result["forwarded_request_hash"] == "abcdef0123456789abcd"
        assert result["effective_headers"].startswith("host=victim.local")
        assert result["trailer_forwarded"] is True
        assert result["routing_decision_source"] == "trailer"
        assert result["axis_projection"].startswith("framing=TE")

    def test_execute_wire_detects_impact_marker(self):
        impact_body = b"BACKEND-MARKER cache IMPACT:cache_poison"
        responses = [
            (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(impact_body)).encode() + b"\r\n"
                b"X-Backend-Marker: cache\r\n"
                b"X-Impact-Marker: cache_poison\r\n"
                b"X-Impact-Detail: key=/cache/store\r\n\r\n"
                + impact_body
            ),
        ]
        port, thread = _server_once(responses)
        wire = (
            b"POST /cache/store HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: impact01\r\n"
            b"X-WF-Family: cl_0\r\n"
            b"X-WF-Tags: CL.0,content_length_zero\r\n"
            b"X-WF-Transport: h1_raw\r\n"
            b"X-WF-Delivery: oneshot_h1\r\n"
            b"X-WF-Probe: none\r\n"
            b"X-WF-Pause-MS: 0\r\n"
            b"X-WF-Chunk-Shape: none\r\n"
            b"X-WF-Impact: /cache/store\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        result = execute_wire(wire, host="127.0.0.1", port=port, timeout=1.0)
        thread.join(timeout=1.0)
        assert result["impact_marker_seen"] is True
        assert result["impact_type"] == "cache_poison"
        assert result["impact_detail"] == "key=/cache/store"

    def test_pause_probe_detects_early_response(self):
        port, thread = _early_response_server()
        wire = (
            b"POST /early HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: pause01\r\n"
            b"X-WF-Family: early_response\r\n"
            b"X-WF-Tags: 0.CL,early_response_gadget,pause_probe\r\n"
            b"X-WF-Transport: h1_raw\r\n"
            b"X-WF-Delivery: pause_probe_h1\r\n"
            b"X-WF-Probe: early_response\r\n"
            b"X-WF-Pause-MS: 50\r\n"
            b"X-WF-Chunk-Shape: none\r\n"
            b"Content-Length: 8\r\n\r\n"
            b"12345678"
        )
        result = execute_wire(wire, host="127.0.0.1", port=port, timeout=1.0)
        thread.join(timeout=1.0)
        assert result["probe_mode"] == "early_response"
        assert result["probe_outcome"] in {"early_response_before_body", "closed_after_early_response"}
        assert result["first_response_status"] == 400

    def test_h2_raw_sender_returns_response_and_stable_artifact(self):
        port, thread = _h2_server_once()
        wire = (
            b"POST /h2/cl HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: h2abc\r\n"
            b"X-WF-Family: h2_cl\r\n"
            b"X-WF-Tags: H2.CL,downgrade,content_length\r\n"
            b"X-WF-Transport: h2_raw\r\n"
            b"X-WF-Delivery: h2_raw\r\n"
            b"X-WF-Probe: none\r\n"
            b"X-WF-Pause-MS: 0\r\n"
            b"X-WF-Chunk-Shape: none\r\n"
            b"Content-Length: 3\r\n\r\n"
            b"abc"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = execute_wire(wire, host="127.0.0.1", port=port, timeout=1.0, artifact_dir=tmpdir)
        thread.join(timeout=1.0)
        assert result["transport_mode"] == "h2_raw"
        assert result["delivery_mode"] == "h2_raw"
        assert result["first_response_status"] == 200
        assert result["response_count_observed"] == 1
        assert result["backend_marker_seen"] is True
        assert result["probe_outcome"] == "h2_complete"
        assert result["h2_event_trace"]
        assert result["h2_headers_seen"] >= 1
        assert result["artifact_path_stable"].endswith("h2abc.wire")

    def test_persistent_mode_returns_binary_protocol_response(self):
        body = b"BACKEND-MARKER"
        responses = [
            (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"X-Backend-Marker: yes\r\n\r\n" + body
            ),
        ]
        port, thread = _server_once(responses)
        wire = (
            b"POST / HTTP/1.1\r\n"
            b"Host: victim.local\r\n"
            b"X-WF-Request-ID: persist01\r\n"
            b"X-WF-Family: cl_te\r\n"
            b"X-WF-Tags: CL.TE,content_length\r\n"
            b"Content-Length: 4\r\n\r\n"
            b"body"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            env = dict(os.environ)
            env["WEBFUZZER_OUTPUT_DIR"] = tmpdir
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(_TARGET_PATH),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--persistent",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            try:
                assert proc.stdin is not None
                assert proc.stdout is not None
                proc.stdin.write(struct.pack(">I", len(wire)) + wire)
                proc.stdin.flush()
                header = proc.stdout.read(4)
                length = struct.unpack(">I", header)[0]
                payload = proc.stdout.read(length)
                exit_code = struct.unpack(">I", proc.stdout.read(4))[0]
            finally:
                proc.kill()
                proc.wait(timeout=5)
        thread.join(timeout=1.0)
        assert exit_code == 0
        result = json.loads(payload.decode("utf-8"))
        assert result["backend_marker_seen"] is True
        assert result["artifact_path_stable"].endswith("persist01.wire")
