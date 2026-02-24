"""Native acceleration for webfuzzer hot paths.

Provides fast Rust implementations (PyO3) of performance-critical operations.
Falls back to optimized pure-Python when the Rust extension is not compiled.

Build the native module::

    cd webfuzzer/native && maturin develop --release

Check status::

    from webfuzzer.native import AVAILABLE, RUST_EXTENSION
    print(AVAILABLE)         # True (always — fast Python fallback exists)
    print(RUST_EXTENSION)    # True only if Rust extension compiled
"""

from __future__ import annotations

import hashlib
import math
import struct

AVAILABLE: bool = False
RUST_EXTENSION: bool = False

# ── Try Rust extension first ─────────────────────────────────────

try:
    from webfuzzer.native._speedups import (  # type: ignore[import-not-found]
        bitmap_has_new_bits,
        bitmap_update,
        bitmap_count,
        feature_hash_index,
        feature_set_bitmap,
        entropic_compute,
        havoc_mutate,
        parallel_pipe_execute,
    )
    AVAILABLE = True
    RUST_EXTENSION = True
except ImportError:
    pass


# ── Optimised pure-Python fallbacks ──────────────────────────────

if not AVAILABLE:

    # AFL bucket table: 0→0, N→bucket(N)
    _BUCKET = bytearray(256)
    _BUCKET[0] = 0
    for _i in range(1, 256):
        for _b in (1, 2, 3, 4, 8, 16, 32, 128):
            if _i < _b:
                _BUCKET[_i] = _b
                break
        else:
            _BUCKET[_i] = 128

    def bitmap_has_new_bits(  # type: ignore[misc]
        self_bm: bytes | bytearray,
        other_bm: bytes | bytearray,
    ) -> bool:
        """Two-phase scan: 64-bit word for new edges, then per-byte buckets."""
        bkt = _BUCKET

        # Phase 1: 64-bit word scan for new edges (C-backed struct ops)
        for (sw,), (ow,) in zip(
            struct.iter_unpack("<Q", self_bm),
            struct.iter_unpack("<Q", other_bm),
        ):
            if ow == 0:
                continue
            if ow & ~sw:
                return True

        # Phase 2: per-byte bucket check for overlapping edges
        for s, o in zip(self_bm, other_bm):
            if o and s and bkt[o] != bkt[s]:
                return True
        return False

    def bitmap_update(  # type: ignore[misc]
        self_bm: bytearray,
        other_bm: bytes | bytearray,
    ) -> tuple[set[int], int]:
        """Merge other into self. Skip all-zero 8-byte chunks."""
        new_edges: set[int] = set()
        bkt = _BUCKET

        for chunk_idx, (ow,) in enumerate(
            struct.iter_unpack("<Q", other_bm),
        ):
            if ow == 0:
                continue
            base = chunk_idx * 8
            for j in range(8):
                idx = base + j
                ob = other_bm[idx]
                if ob:
                    sb = self_bm[idx]
                    if bkt[sb] != bkt[ob]:
                        new_edges.add(idx)
                    if ob > sb:
                        self_bm[idx] = ob

        edge_count = len(self_bm) - self_bm.count(0)
        return new_edges, edge_count

    def bitmap_count(buf: bytes | bytearray) -> int:  # type: ignore[misc]
        return len(buf) - buf.count(0)

    def feature_hash_index(key: str, map_size: int) -> int:  # type: ignore[misc]
        h = hashlib.sha256(key.encode()).digest()
        return (h[0] | (h[1] << 8)) % map_size

    def feature_set_bitmap(  # type: ignore[misc]
        bitmap: bytearray,
        namespace: str,
        value: str,
        map_size: int,
    ) -> None:
        h = hashlib.sha256(f"{namespace}:{value}".encode()).digest()
        idx = (h[0] | (h[1] << 8)) % map_size
        if bitmap[idx] < 255:
            bitmap[idx] += 1

    def entropic_compute(  # type: ignore[misc]
        feature_sets: list,
        edge_freq: dict[int, int],
        total_seeds: int,
        theta: int,
        base_energy: float,
    ) -> list[float]:
        inv_total = 1.0 / total_seeds
        _log2 = math.log2
        _get = edge_freq.get
        result: list[float] = []
        for fset in feature_sets:
            if not fset:
                result.append(base_energy)
                continue
            entropy = 0.0
            for f in fset:
                freq = _get(f, 1)
                if freq >= theta:
                    continue
                p = freq * inv_total
                if p > 0.0:
                    entropy -= _log2(p)
            energy = entropy * base_energy
            result.append(energy if energy >= 0.01 else 0.01)
        return result

    def havoc_mutate(  # type: ignore[misc]
        data: bytes, num_ops: int, seed: int,
    ) -> bytearray:
        """Pure-Python havoc fallback with xorshift128+ PRNG."""
        buf = bytearray(data)
        if not buf:
            return buf
        max_len = max(min(len(buf) * 2, 1 << 20), 256)
        mask64 = (1 << 64) - 1
        s0 = seed | 1
        s1 = ((seed >> 32) ^ 0xDEADBEEFCAFE) | 1

        def _next() -> int:
            nonlocal s0, s1
            _s1, _s0 = s0, s1
            s0 = _s0
            _s1 = ((_s1 ^ ((_s1 << 23) & mask64)) ^ (_s1 >> 17) ^ _s0 ^ (_s0 >> 26)) & mask64
            s1 = _s1
            return (s0 + s1) & mask64

        def _ri(lo: int, hi: int) -> int:
            return lo if lo >= hi else lo + int(_next() % (hi - lo + 1))

        _I8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
        _I16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
        _I32 = [0, 1, 32768, 65535, 65536, 100663045, 2147483647, 2147483648, 4294967295]

        for _ in range(num_ops):
            ln = len(buf)
            if ln <= 0:
                break
            op = _ri(0, 13)
            if op == 0:
                p = _ri(0, ln - 1); buf[p] ^= 1 << _ri(0, 7)
            elif op == 1:
                p = _ri(0, ln - 1); buf[p] ^= 0xFF
            elif op == 2:
                p = _ri(0, ln - 1); buf[p] = _ri(0, 255)
            elif op == 3:
                p = _ri(0, ln - 1); d = _ri(1, 35)
                buf[p] = ((buf[p] + d) if _next() & 1 else (buf[p] - d)) & 0xFF
            elif op == 4 and ln >= 2:
                p = _ri(0, ln - 2)
                v = struct.unpack_from("<H", buf, p)[0]; d = _ri(1, 35)
                v = ((v + d) if _next() & 1 else (v - d)) & 0xFFFF
                struct.pack_into("<H", buf, p, v)
            elif op == 5 and ln >= 4:
                p = _ri(0, ln - 4)
                v = struct.unpack_from("<I", buf, p)[0]; d = _ri(1, 35)
                v = ((v + d) if _next() & 1 else (v - d)) & 0xFFFFFFFF
                struct.pack_into("<I", buf, p, v)
            elif op == 6:
                p = _ri(0, ln - 1); buf[p] = _I8[_ri(0, 8)] & 0xFF
            elif op == 7 and ln >= 2:
                p = _ri(0, ln - 2); v = _I16[_ri(0, 10)] & 0xFFFF
                if _next() & 1:
                    struct.pack_into("<H", buf, p, v)
                else:
                    struct.pack_into(">H", buf, p, v)
            elif op == 8 and ln >= 4:
                p = _ri(0, ln - 4); v = _I32[_ri(0, 8)] & 0xFFFFFFFF
                if _next() & 1:
                    struct.pack_into("<I", buf, p, v)
                else:
                    struct.pack_into(">I", buf, p, v)
            elif op == 9 and ln > 4:
                bl = _ri(1, min(ln // 4, 32)); p = _ri(0, ln - bl)
                del buf[p:p + bl]
            elif op == 10:
                bl = _ri(1, 32)
                if ln + bl <= max_len:
                    p = _ri(0, ln)
                    buf[p:p] = bytes(_ri(0, 255) for _ in range(bl))
            elif op == 11:
                bl = _ri(1, min(16, ln)); p = _ri(0, ln - bl)
                for j in range(bl):
                    buf[p + j] = _ri(0, 255)
            elif op in (12, 13) and ln > 4:
                bl = _ri(1, min(ln // 4, 32)); src = _ri(0, ln - bl)
                dst = _ri(0, ln)
                if ln + bl <= max_len:
                    buf[dst:dst] = bytes(buf[src:src + bl])
        return buf

    def parallel_pipe_execute(  # type: ignore[misc]
        handles: list[tuple[int, int]],
        input_data: bytes,
        timeout_ms: int,
    ) -> list[tuple[bytes, int, float, str | None]]:
        """Fallback stub — engine uses ThreadPoolExecutor when Rust unavailable."""
        raise NotImplementedError(
            "parallel_pipe_execute requires the Rust extension. "
            "Build with: cd webfuzzer/native && maturin develop --release"
        )

    AVAILABLE = True
