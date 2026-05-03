"""Tests for FeatureDumpSink (per-input JSONL sink)."""

from __future__ import annotations

import json
import threading
from pathlib import Path

from webfuzzer.fuzzer.oracles.feature_dump import FeatureDumpSink


def _read_rows(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_lazy_file_open(tmp_path: Path):
    sink_path = tmp_path / "nested" / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    # File must not exist until first emit.
    assert not sink_path.exists()
    sink.close()
    assert not sink_path.exists()


def test_emit_single_row_schema(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    try:
        sink.emit_input(
            input_bytes=b"hello world",
            mutator_name="saml",
            applied_strategies=["xsw_envelope", "whitespace"],
            divergence=True,
            n_refs=3,
            n_diverged_refs=2,
            diff_fields=["status", "body"],
        )
    finally:
        sink.close()
    rows = _read_rows(sink_path)
    assert len(rows) == 1
    row = rows[0]
    assert row["seq"] == 0
    assert row["input_len"] == len(b"hello world")
    assert row["mutator"] == "saml"
    assert row["applied_strategies"] == ["xsw_envelope", "whitespace"]
    assert row["divergence"] is True
    assert row["n_refs"] == 3
    assert row["n_diverged_refs"] == 2
    assert row["diff_fields"] == ["body", "status"]  # sorted
    assert len(row["input_sha1"]) == 16
    assert "input_head" in row
    assert "input_tail" in row


def test_seq_monotonic(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    try:
        for i in range(5):
            sink.emit_input(
                input_bytes=bytes([i]),
                mutator_name="m",
                applied_strategies=None,
                divergence=False,
                n_refs=1,
                n_diverged_refs=0,
                diff_fields=None,
            )
    finally:
        sink.close()
    rows = _read_rows(sink_path)
    assert [r["seq"] for r in rows] == [0, 1, 2, 3, 4]


def test_short_input_head_equals_tail(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    try:
        sink.emit_input(
            input_bytes=b"abc",
            mutator_name=None,
            applied_strategies=None,
            divergence=False,
            n_refs=0,
            n_diverged_refs=0,
            diff_fields=None,
        )
    finally:
        sink.close()
    row = _read_rows(sink_path)[0]
    assert row["input_head"] == b"abc".hex()
    assert row["input_tail"] == row["input_head"]
    assert row["mutator"] == ""


def test_extra_does_not_overwrite_core(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    try:
        sink.emit_input(
            input_bytes=b"x",
            mutator_name="m",
            applied_strategies=None,
            divergence=True,
            n_refs=1,
            n_diverged_refs=1,
            diff_fields=None,
            extra={"divergence": False, "custom_field": 42},
        )
    finally:
        sink.close()
    row = _read_rows(sink_path)[0]
    assert row["divergence"] is True  # core not overwritten
    assert row["custom_field"] == 42  # extra added


def test_concurrent_emits_thread_safe(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    n_threads = 8
    per_thread = 25

    def worker(tid: int):
        for i in range(per_thread):
            sink.emit_input(
                input_bytes=bytes([tid, i]),
                mutator_name=f"t{tid}",
                applied_strategies=None,
                divergence=False,
                n_refs=1,
                n_diverged_refs=0,
                diff_fields=None,
            )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sink.close()

    rows = _read_rows(sink_path)
    assert len(rows) == n_threads * per_thread
    # seqs are unique and cover [0, n*per_thread)
    seqs = sorted(r["seq"] for r in rows)
    assert seqs == list(range(n_threads * per_thread))


def test_close_is_idempotent(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    sink.emit_input(
        input_bytes=b"z",
        mutator_name="m",
        applied_strategies=None,
        divergence=False,
        n_refs=0,
        n_diverged_refs=0,
        diff_fields=None,
    )
    sink.close()
    sink.close()  # no raise
    assert sink_path.exists()


def test_affected_refs_sorted_and_unique(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    try:
        sink.emit_input(
            input_bytes=b"x",
            mutator_name="m",
            applied_strategies=None,
            divergence=True,
            n_refs=4,
            n_diverged_refs=3,
            diff_fields=None,
            affected_refs=[3, 1, 1, 0],
        )
    finally:
        sink.close()
    row = _read_rows(sink_path)[0]
    assert row["affected_refs"] == [0, 1, 3]


def test_affected_refs_defaults_empty_when_omitted(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    sink = FeatureDumpSink(sink_path)
    try:
        sink.emit_input(
            input_bytes=b"x",
            mutator_name="m",
            applied_strategies=None,
            divergence=False,
            n_refs=2,
            n_diverged_refs=0,
            diff_fields=None,
        )
    finally:
        sink.close()
    row = _read_rows(sink_path)[0]
    assert row["affected_refs"] == []


def test_context_manager(tmp_path: Path):
    sink_path = tmp_path / "features.jsonl"
    with FeatureDumpSink(sink_path) as sink:
        sink.emit_input(
            input_bytes=b"q",
            mutator_name="m",
            applied_strategies=None,
            divergence=False,
            n_refs=0,
            n_diverged_refs=0,
            diff_fields=None,
        )
    assert _read_rows(sink_path)[0]["input_len"] == 1
