"""Token-level mutator (USENIX Security'21).

Operates at an intermediate granularity between byte and grammar level.
Tokenizes input using regex patterns, then mutates individual tokens.

Strategies:
  a) token_replace  — replace a token with another of the same type
  b) token_delete   — delete a random token
  c) token_duplicate — duplicate a token
  d) token_swap     — swap two adjacent tokens
  e) token_insert   — insert a dictionary token
"""

from __future__ import annotations

import random
import re
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# Default tokenization pattern — splits on whitespace and punctuation boundaries
DEFAULT_TOKEN_PATTERN = re.compile(
    r"""(\s+|[{}()\[\]<>;:,=&?#@!'"\\/.]+|[^\s{}()\[\]<>;:,=&?#@!'"\\/.]+)"""
)


class TokenMutator:
    """Token-level mutation — intermediate granularity."""

    name = "token"

    def __init__(
        self,
        seed: int | None = None,
        token_pattern: re.Pattern[str] | None = None,
        dictionary: list[str] | None = None,
    ) -> None:
        self.rng = random.Random(seed)
        self.pattern = token_pattern or DEFAULT_TOKEN_PATTERN
        self.dictionary = dictionary or []

        self._strategies = [
            self._token_replace,
            self._token_delete,
            self._token_duplicate,
            self._token_swap,
            self._token_insert,
        ]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        try:
            text = inp.data.decode("utf-8", errors="replace")
        except Exception:
            text = inp.data.decode("latin-1")

        tokens = self.pattern.findall(text)
        if not tokens:
            return inp

        # Apply 1-3 token mutations
        num_ops = self.rng.randint(1, 3)
        for _ in range(num_ops):
            strategy = self.rng.choice(self._strategies)
            tokens = strategy(tokens, corpus)

        result = "".join(tokens)
        return Input(
            data=result.encode("utf-8"),
            metadata={**inp.metadata, "mutator": self.name},
        )

    def _token_replace(self, tokens: list[str], corpus: list[Seed]) -> list[str]:
        """Replace a random token with one from the corpus or a random string."""
        if not tokens:
            return tokens
        idx = self.rng.randint(0, len(tokens) - 1)
        original = tokens[idx]

        # Try to find a token of similar type from corpus
        replacement = self._find_replacement(original, corpus)
        tokens[idx] = replacement
        return tokens

    def _token_delete(self, tokens: list[str], corpus: list[Seed]) -> list[str]:
        if len(tokens) <= 1:
            return tokens
        idx = self.rng.randint(0, len(tokens) - 1)
        tokens.pop(idx)
        return tokens

    def _token_duplicate(self, tokens: list[str], corpus: list[Seed]) -> list[str]:
        if not tokens:
            return tokens
        idx = self.rng.randint(0, len(tokens) - 1)
        tokens.insert(idx + 1, tokens[idx])
        return tokens

    def _token_swap(self, tokens: list[str], corpus: list[Seed]) -> list[str]:
        if len(tokens) < 2:
            return tokens
        idx = self.rng.randint(0, len(tokens) - 2)
        tokens[idx], tokens[idx + 1] = tokens[idx + 1], tokens[idx]
        return tokens

    def _token_insert(self, tokens: list[str], corpus: list[Seed]) -> list[str]:
        idx = self.rng.randint(0, len(tokens))
        if self.dictionary:
            token = self.rng.choice(self.dictionary)
        else:
            # Generate a random token-like string
            chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            length = self.rng.randint(1, 8)
            token = "".join(self.rng.choices(chars, k=length))
        tokens.insert(idx, token)
        return tokens

    def _find_replacement(self, original: str, corpus: list[Seed]) -> str:
        """Find a replacement token of similar characteristics."""
        # Try dictionary first
        if self.dictionary and self.rng.random() < 0.3:
            return self.rng.choice(self.dictionary)

        # Try corpus tokens
        if corpus and self.rng.random() < 0.5:
            other = self.rng.choice(corpus)
            try:
                other_text = other.input.data.decode("utf-8", errors="replace")
            except Exception:
                other_text = other.input.data.decode("latin-1")
            other_tokens = self.pattern.findall(other_text)
            if other_tokens:
                return self.rng.choice(other_tokens)

        # Generate random replacement of similar length
        length = max(1, len(original) + self.rng.randint(-2, 2))
        if original.isdigit():
            return str(self.rng.randint(0, 10 ** length - 1))
        if original.isalpha():
            chars = "abcdefghijklmnopqrstuvwxyz"
            return "".join(self.rng.choices(chars, k=length))
        return original[::-1] if len(original) > 1 else original
