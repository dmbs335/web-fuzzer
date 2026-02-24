"""Tokenizer-based JSON parser — port of zserge/jsmn.

Faithfully ports Serge Zaitsev's jsmn (Jasmine), a minimalist JSON
tokenizer written in ~400 lines of C.  jsmn doesn't build a parse tree;
it produces a flat array of tokens that point into the original string.

Key behaviors (matching the original):
  - Token types: OBJECT, ARRAY, STRING, PRIMITIVE (no separate bool/null/number)
  - Primitives are validated loosely: first char must be [0-9tfn-], rest is permissive
  - String escape validation is strict: only recognizes standard JSON escapes
  - Does NOT check for duplicate keys
  - Does NOT validate number format deeply (no leading-zero check, accepts "1." etc.)
  - Accepts bare `t`, `f`, `n` as valid primitive starts (doesn't check full word)
  - Zero-copy design: tokens store start/end positions, not values

After tokenization, we reconstruct a Python object from the token stream
and serialize to canonical JSON for comparison.

Source: https://github.com/zserge/jsmn
        Serge Zaitsev, MIT License.

References:
  - Seriot, "Parsing JSON is a Minefield" (2016)
  - Nezha (IEEE S&P'17): differential testing of parser implementations
"""

import json
import sys
from dataclasses import dataclass, field
from enum import IntEnum


# ── Token types (matching jsmn's jsmntype_t) ─────────────────────

class TokenType(IntEnum):
    UNDEFINED = 0
    OBJECT = 1
    ARRAY = 2
    STRING = 4
    PRIMITIVE = 8


class JsmnError(Exception):
    pass


class JsmnInvalid(JsmnError):
    """JSMN_ERROR_INVAL — invalid character in JSON."""
    pass


class JsmnPartial(JsmnError):
    """JSMN_ERROR_PART — incomplete JSON."""
    pass


# ── Token structure ──────────────────────────────────────────────

@dataclass
class Token:
    type: TokenType = TokenType.UNDEFINED
    start: int = -1
    end: int = -1
    size: int = 0       # number of child tokens
    parent: int = -1


# ── Parser ───────────────────────────────────────────────────────

class JsmnParser:
    """Port of jsmn_parser from jsmn.h."""

    def __init__(self, max_tokens: int = 4096):
        self.pos: int = 0
        self.toknext: int = 0
        self.toksuper: int = -1
        self.tokens: list[Token] = []
        self.max_tokens = max_tokens

    def _alloc_token(self) -> Token:
        """jsmn_alloc_token — allocate a new token from the pool."""
        if self.toknext >= self.max_tokens:
            raise JsmnError("Token limit exceeded")
        tok = Token()
        self.tokens.append(tok)
        idx = self.toknext
        self.toknext += 1
        return tok

    def _fill_token(self, tok: Token, type_: TokenType, start: int, end: int):
        """jsmn_fill_token — set token boundaries."""
        tok.type = type_
        tok.start = start
        tok.end = end
        tok.size = 0

    def _parse_primitive(self, js: str) -> int:
        """jsmn_parse_primitive — parse a primitive value.

        jsmn is very permissive here: it only checks that the first character
        is valid and then scans until a delimiter is found.
        """
        start = self.pos

        # jsmn original: validate first char
        # Primitives start with: - 0-9 t f n
        ch = js[self.pos] if self.pos < len(js) else ''
        if ch not in '-0123456789tfn':
            raise JsmnInvalid(f"Invalid primitive start: '{ch}' at {self.pos}")

        while self.pos < len(js):
            ch = js[self.pos]
            # jsmn original: break on delimiters
            if ch in '\t\r\n :,]}':
                break
            # jsmn original: only ASCII printable range
            if ch < '\x20' or ch >= '\x7f':
                raise JsmnInvalid(f"Invalid char in primitive at {self.pos}")
            self.pos += 1

        # jsmn with JSMN_STRICT would do more checking here; base jsmn does not

        token = self._alloc_token()
        self._fill_token(token, TokenType.PRIMITIVE, start, self.pos)
        token.parent = self.toksuper
        self.pos -= 1  # will be incremented in main loop
        return 0

    def _parse_string(self, js: str) -> int:
        """jsmn_parse_string — parse a JSON string with escape handling."""
        start = self.pos
        self.pos += 1  # skip opening quote

        while self.pos < len(js):
            ch = js[self.pos]

            if ch == '"':
                token = self._alloc_token()
                self._fill_token(token, TokenType.STRING, start + 1, self.pos)
                token.parent = self.toksuper
                return 0

            if ch == '\\' and self.pos + 1 < len(js):
                self.pos += 1
                esc = js[self.pos]
                # jsmn original: validates escape sequences
                if esc in '"\\/ bfnrt':
                    pass
                elif esc == 'u':
                    # validate 4 hex digits
                    for i in range(1, 5):
                        if self.pos + i >= len(js):
                            raise JsmnInvalid("Incomplete unicode escape")
                        h = js[self.pos + i]
                        if h not in '0123456789abcdefABCDEF':
                            raise JsmnInvalid(f"Bad unicode hex: '{h}'")
                    self.pos += 4
                else:
                    raise JsmnInvalid(f"Bad escape: \\{esc}")

            self.pos += 1

        raise JsmnPartial("Unterminated string")

    def parse(self, js: str) -> int:
        """jsmn_parse — main parsing function.

        Returns the number of tokens parsed.
        """
        self.pos = 0
        self.toknext = 0
        self.toksuper = -1
        self.tokens = []

        count = 0  # non-empty tokens

        while self.pos < len(js):
            ch = js[self.pos]

            if ch == '{' or ch == '[':
                count += 1
                token = self._alloc_token()
                if self.toksuper != -1:
                    parent = self.tokens[self.toksuper]
                    # jsmn: parent must be object or array
                    if parent.type == TokenType.OBJECT:
                        # In jsmn strict mode, key must come first
                        pass
                    parent.size += 1
                    token.parent = self.toksuper

                token.type = TokenType.OBJECT if ch == '{' else TokenType.ARRAY
                token.start = self.pos
                self.toksuper = self.toknext - 1

            elif ch == '}' or ch == ']':
                expected = TokenType.OBJECT if ch == '}' else TokenType.ARRAY

                # Find matching open token
                i = self.toknext - 1
                while i >= 0:
                    token = self.tokens[i]
                    if token.start != -1 and token.end == -1:
                        if token.type != expected:
                            raise JsmnInvalid(f"Mismatched bracket at {self.pos}")
                        self.toksuper = token.parent
                        token.end = self.pos + 1
                        break
                    i -= 1

                if i < 0:
                    raise JsmnInvalid(f"Unexpected '{ch}' at {self.pos}")

            elif ch == '"':
                self._parse_string(js)
                count += 1
                if self.toksuper != -1:
                    self.tokens[self.toksuper].size += 1

            elif ch == '\t' or ch == '\r' or ch == '\n' or ch == ' ':
                pass  # skip whitespace

            elif ch == ':':
                self.toksuper = self.toknext - 1

            elif ch == ',':
                # After comma, toksuper goes back to parent container
                i = self.toknext - 1
                while i >= 0:
                    if self.tokens[i].type in (TokenType.ARRAY, TokenType.OBJECT):
                        if self.tokens[i].end == -1:
                            self.toksuper = i
                            break
                    i -= 1

            else:
                # Must be a primitive
                self._parse_primitive(js)
                count += 1
                if self.toksuper != -1:
                    self.tokens[self.toksuper].size += 1

            self.pos += 1

        # Verify all containers are closed
        for i in range(self.toknext):
            if self.tokens[i].start != -1 and self.tokens[i].end == -1:
                raise JsmnPartial("Unclosed container")

        return count


# ── Token stream → Python object reconstruction ─────────────────

def _decode_string(js: str, tok: Token) -> str:
    """Decode a jsmn string token, processing escape sequences."""
    raw = js[tok.start:tok.end]
    result = []
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '\\' and i + 1 < len(raw):
            esc = raw[i + 1]
            if esc == '"':
                result.append('"')
            elif esc == '\\':
                result.append('\\')
            elif esc == '/':
                result.append('/')
            elif esc == 'b':
                result.append('\b')
            elif esc == 'f':
                result.append('\f')
            elif esc == 'n':
                result.append('\n')
            elif esc == 'r':
                result.append('\r')
            elif esc == 't':
                result.append('\t')
            elif esc == 'u' and i + 5 < len(raw):
                hex_str = raw[i + 2:i + 6]
                try:
                    result.append(chr(int(hex_str, 16)))
                except ValueError:
                    result.append(esc)
                i += 4  # extra skip for \uXXXX
            else:
                result.append(esc)
            i += 2
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def _decode_primitive(js: str, tok: Token):
    """Decode a jsmn primitive token to Python value."""
    raw = js[tok.start:tok.end]
    if raw == 'true':
        return True
    elif raw == 'false':
        return False
    elif raw == 'null':
        return None
    else:
        # Number — try int first, then float
        try:
            return int(raw)
        except ValueError:
            try:
                return float(raw)
            except ValueError:
                raise JsmnInvalid(f"Invalid primitive: {raw!r}")


def _reconstruct(js: str, tokens: list[Token], idx: int) -> tuple:
    """Reconstruct Python object from token stream.

    Returns (value, next_index).
    """
    tok = tokens[idx]

    if tok.type == TokenType.PRIMITIVE:
        return _decode_primitive(js, tok), idx + 1

    elif tok.type == TokenType.STRING:
        return _decode_string(js, tok), idx + 1

    elif tok.type == TokenType.ARRAY:
        arr = []
        child_idx = idx + 1
        for _ in range(tok.size):
            if child_idx >= len(tokens):
                break
            val, child_idx = _reconstruct(js, tokens, child_idx)
            arr.append(val)
        return arr, child_idx

    elif tok.type == TokenType.OBJECT:
        obj = {}
        child_idx = idx + 1
        for _ in range(tok.size):
            if child_idx + 1 >= len(tokens):
                break
            # Key
            key_tok = tokens[child_idx]
            if key_tok.type != TokenType.STRING:
                raise JsmnInvalid("Object key must be string")
            key = _decode_string(js, key_tok)
            child_idx += 1
            # Value
            val, child_idx = _reconstruct(js, tokens, child_idx)
            obj[key] = val  # jsmn: no duplicate key check, last wins
        return obj, child_idx

    else:
        raise JsmnInvalid(f"Unexpected token type: {tok.type}")


# ── Public API ───────────────────────────────────────────────────

def jsmn_parse(data: str) -> str:
    """Parse JSON using jsmn tokenizer, then reconstruct and serialize."""
    parser = JsmnParser(max_tokens=8192)
    count = parser.parse(data)

    if count == 0 or not parser.tokens:
        raise JsmnInvalid("Empty input")

    obj, _ = _reconstruct(data, parser.tokens, 0)
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: json_jsmn.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = jsmn_parse(data)
        print(result)
        sys.exit(0)
    except (JsmnError, ValueError, TypeError, OverflowError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
