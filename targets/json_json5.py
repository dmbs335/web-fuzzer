"""JSON5 parser — hand-written recursive descent per json5.org spec.

Implements the JSON5 Data Interchange Format (https://spec.json5.org/).
JSON5 is a superset of JSON based on ECMAScript 5.1 syntax.

Extensions over standard JSON:
  - Single-line (//) and multi-line (/* */) comments
  - Trailing commas in objects and arrays
  - Unquoted object keys (ECMAScript IdentifierName)
  - Single-quoted strings
  - Multi-line strings (escaped newlines)
  - Hex integer literals (0x...)
  - Leading and trailing decimal points (.5, 5.)
  - Positive sign (+) on numbers
  - Infinity, -Infinity, +Infinity, NaN as number literals
  - Additional whitespace characters (U+00A0, etc.)
  - Additional escape sequences (\\0, \\v, \\', line continuations)

Source: https://json5.org/ — JSON5 specification
        https://github.com/json5/json5 — reference implementation

References:
  - Seriot, "Parsing JSON is a Minefield" (2016)
  - Nezha (IEEE S&P'17): differential testing of parser implementations
"""

import json
import math
import re
import sys
import unicodedata


class JSON5Error(Exception):
    def __init__(self, message: str, line: int = 0, col: int = 0):
        self.line = line
        self.col = col
        super().__init__(f"{message} at line {line}, col {col}")


class JSON5Parser:
    """Hand-written recursive descent JSON5 parser."""

    # ECMAScript 5.1 whitespace characters
    WHITESPACE = set(' \t\n\r\x0b\x0c\xa0\u2028\u2029\ufeff')

    # ECMAScript 5.1 line terminators
    LINE_TERMINATORS = set('\n\r\u2028\u2029')

    ESCAPEE = {
        "'": "'",
        '"': '"',
        '\\': '\\',
        '/': '/',
        'b': '\b',
        'f': '\f',
        'n': '\n',
        'r': '\r',
        't': '\t',
        'v': '\x0b',
        '0': '\0',
    }

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.line = 1
        self.col = 0

    def error(self, msg: str):
        raise JSON5Error(msg, self.line, self.col)

    def _peek(self) -> str:
        if self.pos < len(self.text):
            return self.text[self.pos]
        return ''

    def _peek2(self) -> str:
        """Peek at current and next character."""
        if self.pos + 1 < len(self.text):
            return self.text[self.pos:self.pos + 2]
        return self._peek()

    def _advance(self) -> str:
        """Advance one character and return it."""
        if self.pos >= len(self.text):
            return ''
        ch = self.text[self.pos]
        self.pos += 1
        if ch == '\n' or (ch == '\r' and self._peek() != '\n'):
            self.line += 1
            self.col = 0
        elif ch == '\r':
            pass  # \r\n handled when \n is consumed
        else:
            self.col += 1
        return ch

    def _expect(self, expected: str):
        ch = self._advance()
        if ch != expected:
            self.error(f"Expected '{expected}', got '{ch}'")

    def _skip_whitespace_and_comments(self):
        """Skip whitespace and JSON5 comments."""
        while self.pos < len(self.text):
            ch = self._peek()

            # Whitespace
            if ch in self.WHITESPACE:
                self._advance()
                continue

            # Single-line comment
            if self._peek2() == '//':
                self._advance()
                self._advance()
                while self.pos < len(self.text) and self._peek() not in self.LINE_TERMINATORS:
                    self._advance()
                continue

            # Multi-line comment
            if self._peek2() == '/*':
                self._advance()
                self._advance()
                while self.pos < len(self.text):
                    if self._peek2() == '*/':
                        self._advance()
                        self._advance()
                        break
                    self._advance()
                else:
                    self.error("Unterminated multi-line comment")
                continue

            break

    def _is_identifier_start(self, ch: str) -> bool:
        """Check if character can start an ECMAScript IdentifierName."""
        if not ch:
            return False
        if ch == '_' or ch == '$':
            return True
        if ch == '\\':
            return True  # unicode escape
        cat = unicodedata.category(ch)
        return cat in ('Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Nl')

    def _is_identifier_part(self, ch: str) -> bool:
        """Check if character can continue an ECMAScript IdentifierName."""
        if self._is_identifier_start(ch):
            return True
        if not ch:
            return False
        cat = unicodedata.category(ch)
        return cat in ('Mn', 'Mc', 'Nd', 'Pc') or ch == '\u200c' or ch == '\u200d'

    def _parse_identifier(self) -> str:
        """Parse an unquoted ECMAScript IdentifierName."""
        result = ''
        ch = self._peek()

        if ch == '\\':
            # Unicode escape in identifier
            self._advance()
            self._expect('u')
            code = self._parse_hex_digits(4)
            ch = chr(code)
            if not self._is_identifier_start(ch):
                self.error(f"Invalid identifier start: U+{code:04X}")
            result += ch
        elif self._is_identifier_start(ch):
            result += ch
            self._advance()
        else:
            self.error(f"Invalid identifier start: '{ch}'")

        while self.pos < len(self.text):
            ch = self._peek()
            if ch == '\\':
                self._advance()
                self._expect('u')
                code = self._parse_hex_digits(4)
                ch = chr(code)
                if not self._is_identifier_part(ch):
                    self.error(f"Invalid identifier part: U+{code:04X}")
                result += ch
            elif self._is_identifier_part(ch):
                result += ch
                self._advance()
            else:
                break

        return result

    def _parse_hex_digits(self, count: int) -> int:
        """Parse exactly `count` hex digits and return the integer value."""
        hex_str = ''
        for _ in range(count):
            ch = self._advance()
            if ch not in '0123456789abcdefABCDEF':
                self.error(f"Invalid hex digit: '{ch}'")
            hex_str += ch
        return int(hex_str, 16)

    def _parse_string(self, quote: str) -> str:
        """Parse a JSON5 string (single or double quoted)."""
        self._advance()  # skip opening quote
        result = []

        while self.pos < len(self.text):
            ch = self._peek()

            if ch == quote:
                self._advance()
                return ''.join(result)

            if ch in self.LINE_TERMINATORS:
                self.error("Unterminated string (newline)")

            if ch == '\\':
                self._advance()
                esc = self._peek()

                # Line continuation (escaped newline)
                if esc in self.LINE_TERMINATORS:
                    self._advance()
                    # \r\n is one line terminator
                    if esc == '\r' and self._peek() == '\n':
                        self._advance()
                    continue

                self._advance()

                if esc in self.ESCAPEE:
                    result.append(self.ESCAPEE[esc])
                elif esc == 'u':
                    code = self._parse_hex_digits(4)
                    result.append(chr(code))
                elif esc == 'x':
                    code = self._parse_hex_digits(2)
                    result.append(chr(code))
                elif esc >= '1' and esc <= '9':
                    # JSON5 does NOT allow octal escapes (unlike ES5 sloppy)
                    self.error(f"Octal escape not allowed: \\{esc}")
                else:
                    # Unknown escape: literal character (JSON5 spec)
                    result.append(esc)
            else:
                result.append(ch)
                self._advance()

        self.error("Unterminated string")

    def _parse_number(self) -> float | int:
        """Parse a JSON5 number literal."""
        start = self.pos
        sign = 1

        ch = self._peek()

        # Sign
        if ch == '+' or ch == '-':
            if ch == '-':
                sign = -1
            self._advance()
            ch = self._peek()

        # Infinity
        if ch == 'I':
            for expected in 'Infinity':
                self._expect(expected)
            return sign * math.inf

        # NaN
        if ch == 'N':
            self._expect('N')
            self._expect('a')
            self._expect('N')
            return math.nan

        # Hex
        if ch == '0' and self.pos + 1 < len(self.text) and self.text[self.pos + 1] in 'xX':
            self._advance()  # '0'
            self._advance()  # 'x'
            hex_str = ''
            while self.pos < len(self.text) and self._peek() in '0123456789abcdefABCDEF':
                hex_str += self._advance()
            if not hex_str:
                self.error("Invalid hex number")
            return sign * int(hex_str, 16)

        # Decimal
        num_str = ''
        has_dot = False
        has_exp = False
        has_digit = False

        # Integer part
        while self.pos < len(self.text) and self._peek() >= '0' and self._peek() <= '9':
            num_str += self._advance()
            has_digit = True

        # Fractional part
        if self._peek() == '.':
            has_dot = True
            num_str += self._advance()
            while self.pos < len(self.text) and self._peek() >= '0' and self._peek() <= '9':
                num_str += self._advance()
                has_digit = True

        if not has_digit:
            self.error("Invalid number")

        # Exponent
        if self._peek() in ('e', 'E'):
            has_exp = True
            num_str += self._advance()
            if self._peek() in ('+', '-'):
                num_str += self._advance()
            exp_digits = False
            while self.pos < len(self.text) and self._peek() >= '0' and self._peek() <= '9':
                num_str += self._advance()
                exp_digits = True
            if not exp_digits:
                self.error("Invalid exponent")

        if has_dot or has_exp:
            return sign * float(num_str)
        else:
            return sign * int(num_str)

    def _parse_array(self) -> list:
        """Parse a JSON5 array."""
        self._advance()  # skip '['
        arr = []

        self._skip_whitespace_and_comments()

        if self._peek() == ']':
            self._advance()
            return arr

        while True:
            val = self._parse_value()
            arr.append(val)

            self._skip_whitespace_and_comments()

            if self._peek() == ',':
                self._advance()
                self._skip_whitespace_and_comments()
                # Trailing comma
                if self._peek() == ']':
                    self._advance()
                    return arr
                continue

            if self._peek() == ']':
                self._advance()
                return arr

            self.error(f"Expected ',' or ']', got '{self._peek()}'")

    def _parse_object(self) -> dict:
        """Parse a JSON5 object."""
        self._advance()  # skip '{'
        obj = {}

        self._skip_whitespace_and_comments()

        if self._peek() == '}':
            self._advance()
            return obj

        while True:
            self._skip_whitespace_and_comments()

            # Key: quoted string or unquoted identifier
            ch = self._peek()
            if ch == '"' or ch == "'":
                key = self._parse_string(ch)
            elif self._is_identifier_start(ch):
                key = self._parse_identifier()
            else:
                self.error(f"Expected property name, got '{ch}'")

            self._skip_whitespace_and_comments()
            self._expect(':')

            obj[key] = self._parse_value()  # duplicate keys: last wins

            self._skip_whitespace_and_comments()

            if self._peek() == ',':
                self._advance()
                self._skip_whitespace_and_comments()
                # Trailing comma
                if self._peek() == '}':
                    self._advance()
                    return obj
                continue

            if self._peek() == '}':
                self._advance()
                return obj

            self.error(f"Expected ',' or '}}', got '{self._peek()}'")

    def _parse_value(self):
        """Parse a JSON5 value."""
        self._skip_whitespace_and_comments()

        ch = self._peek()

        if ch == '':
            self.error("Unexpected end of input")
        elif ch == '{':
            return self._parse_object()
        elif ch == '[':
            return self._parse_array()
        elif ch == '"' or ch == "'":
            return self._parse_string(ch)
        elif ch == 'n':
            # null
            for expected in 'null':
                self._expect(expected)
            return None
        elif ch == 't':
            for expected in 'true':
                self._expect(expected)
            return True
        elif ch == 'f':
            for expected in 'false':
                self._expect(expected)
            return False
        elif ch == 'I':
            return self._parse_number()
        elif ch == 'N':
            return self._parse_number()
        elif ch in '-+' or ch == '.' or (ch >= '0' and ch <= '9'):
            return self._parse_number()
        else:
            self.error(f"Unexpected character: '{ch}'")

    def parse(self):
        """Parse the complete JSON5 text."""
        result = self._parse_value()
        self._skip_whitespace_and_comments()
        if self.pos < len(self.text):
            self.error(f"Trailing data: '{self._peek()}'")
        return result


def json5_parse(data: str) -> str:
    """Parse JSON5 and serialize to canonical JSON."""
    parser = JSON5Parser(data)
    obj = parser.parse()

    # Handle non-JSON-serializable values
    def default_handler(o):
        if isinstance(o, float):
            if math.isnan(o):
                return "NaN"
            if math.isinf(o):
                return "Infinity" if o > 0 else "-Infinity"
        raise TypeError(f"Not serializable: {o!r}")

    return json.dumps(obj, sort_keys=True, ensure_ascii=True, default=default_handler)


def main():
    if len(sys.argv) < 2:
        print("Usage: json_json5.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = json5_parse(data)
        print(result)
        sys.exit(0)
    except (JSON5Error, ValueError, TypeError, OverflowError, RecursionError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
