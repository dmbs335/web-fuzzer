"""AFL-style byte-level havoc mutator.

Applies a stack of random mutation operations per round, following
AFL's havoc stage design. Operations include bit/byte flips,
arithmetic, interesting values, and block operations.

When the native C extension is available, non-splice operations
(ops 0-12) are executed as a batch in C for ~10-30x throughput.
"""

from __future__ import annotations

import random
import struct
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# Native acceleration (optional)
try:
    from webfuzzer.native import AVAILABLE as _NATIVE
    if _NATIVE:
        from webfuzzer.native import havoc_mutate as _n_havoc
    else:
        _NATIVE = False
except ImportError:
    _NATIVE = False

# AFL interesting values
INTERESTING_8 = [0, 1, 16, 32, 64, 100, 127, 128, 255]
INTERESTING_16 = [0, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535]
INTERESTING_32 = [
    0, 1, 32768, 65535, 65536, 100663045, 2147483647, 2147483648, 4294967295,
]


class HavocMutator:
    """AFL-style byte-level havoc mutation.

    Each mutation round applies 2^(1 + rng(6)) stacked operations.
    """

    name = "havoc"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)
        if not data:
            data = bytearray(self.rng.randbytes(16))

        # Number of stacked mutations: 2^(1 + rng(6)) = 2..128
        num_ops = 1 << (1 + self.rng.randint(0, 6))

        if _NATIVE:
            # Native path: batch-apply ops 0-12 in C, then optionally splice
            rng_seed = self.rng.getrandbits(64)
            data = _n_havoc(bytes(data), num_ops, rng_seed)
            # One additional splice from corpus (~1/14 probability)
            if corpus and self.rng.randint(0, 13) == 0:
                other = self.rng.choice(corpus)
                if other.input.data:
                    split_self = self.rng.randint(0, len(data))
                    split_other = self.rng.randint(0, len(other.input.data))
                    data = bytearray(data[:split_self]) + bytearray(other.input.data[split_other:])
        else:
            for _ in range(num_ops):
                op = self.rng.randint(0, 13)
                data = self._apply_op(op, data, corpus)

        return Input(data=bytes(data), metadata={**inp.metadata, "mutator": self.name})

    def _apply_op(self, op: int, data: bytearray, corpus: list[Seed]) -> bytearray:
        if not data:
            return data
        length = len(data)

        if op == 0:  # bit flip
            pos = self.rng.randint(0, length - 1)
            bit = self.rng.randint(0, 7)
            data[pos] ^= 1 << bit

        elif op == 1:  # byte flip
            pos = self.rng.randint(0, length - 1)
            data[pos] ^= 0xFF

        elif op == 2:  # byte set random
            pos = self.rng.randint(0, length - 1)
            data[pos] = self.rng.randint(0, 255)

        elif op == 3:  # arithmetic 8-bit
            pos = self.rng.randint(0, length - 1)
            delta = self.rng.randint(1, 35)
            if self.rng.random() < 0.5:
                data[pos] = (data[pos] + delta) & 0xFF
            else:
                data[pos] = (data[pos] - delta) & 0xFF

        elif op == 4:  # arithmetic 16-bit
            if length >= 2:
                pos = self.rng.randint(0, length - 2)
                val = struct.unpack_from("<H", data, pos)[0]
                delta = self.rng.randint(1, 35)
                if self.rng.random() < 0.5:
                    val = (val + delta) & 0xFFFF
                else:
                    val = (val - delta) & 0xFFFF
                struct.pack_into("<H", data, pos, val)

        elif op == 5:  # arithmetic 32-bit
            if length >= 4:
                pos = self.rng.randint(0, length - 4)
                val = struct.unpack_from("<I", data, pos)[0]
                delta = self.rng.randint(1, 35)
                if self.rng.random() < 0.5:
                    val = (val + delta) & 0xFFFFFFFF
                else:
                    val = (val - delta) & 0xFFFFFFFF
                struct.pack_into("<I", data, pos, val)

        elif op == 6:  # interesting 8-bit
            pos = self.rng.randint(0, length - 1)
            data[pos] = self.rng.choice(INTERESTING_8) & 0xFF

        elif op == 7:  # interesting 16-bit
            if length >= 2:
                pos = self.rng.randint(0, length - 2)
                val = self.rng.choice(INTERESTING_16)
                if self.rng.random() < 0.5:
                    struct.pack_into("<H", data, pos, val & 0xFFFF)
                else:
                    struct.pack_into(">H", data, pos, val & 0xFFFF)

        elif op == 8:  # interesting 32-bit
            if length >= 4:
                pos = self.rng.randint(0, length - 4)
                val = self.rng.choice(INTERESTING_32)
                if self.rng.random() < 0.5:
                    struct.pack_into("<I", data, pos, val & 0xFFFFFFFF)
                else:
                    struct.pack_into(">I", data, pos, val & 0xFFFFFFFF)

        elif op == 9:  # delete block
            if length > 4:
                block_len = self.rng.randint(1, min(length // 4, 32))
                pos = self.rng.randint(0, length - block_len)
                del data[pos:pos + block_len]

        elif op == 10:  # insert block (random bytes)
            block_len = self.rng.randint(1, 32)
            pos = self.rng.randint(0, length)
            data[pos:pos] = self.rng.randbytes(block_len)

        elif op == 11:  # overwrite block (random bytes)
            block_len = self.rng.randint(1, min(16, length))
            pos = self.rng.randint(0, length - block_len)
            data[pos:pos + block_len] = self.rng.randbytes(block_len)

        elif op == 12:  # clone block (copy from same input)
            if length > 4:
                block_len = self.rng.randint(1, min(length // 4, 32))
                src = self.rng.randint(0, length - block_len)
                dst = self.rng.randint(0, length)
                block = bytes(data[src:src + block_len])
                data[dst:dst] = block

        elif op == 13:  # splice from corpus
            if corpus:
                other = self.rng.choice(corpus)
                if other.input.data:
                    other_data = other.input.data
                    split_self = self.rng.randint(0, length)
                    split_other = self.rng.randint(0, len(other_data))
                    data = bytearray(data[:split_self]) + bytearray(other_data[split_other:])

        return data
