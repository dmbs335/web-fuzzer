"""Recursive descent JSON parser — port of Crockford's json_parse.js.

Faithfully ports Douglas Crockford's reference JSON parser from json.org.
This is a character-by-character recursive descent parser, NOT a wrapper
around Python's json module.

Key behaviors (matching the original):
  - Rejects duplicate object keys
  - Rejects non-finite numbers (Infinity, NaN from overflow)
  - Rejects trailing data after root value
  - Only recognizes standard escape sequences (\", \\, /, b, f, n, r, t, u)
  - Whitespace: only chars <= ' ' (space, tab, newline, CR)
  - Does NOT reject leading zeros in numbers (quirk of original)

Source: https://github.com/douglascrockford/JSON-js
        Douglas Crockford, json_parse.js, Public Domain.

References:
  - Seriot, "Parsing JSON is a Minefield" (2016)
  - Nezha (IEEE S&P'17): differential testing of parser implementations
"""

import json
import math
import sys


class JSONSyntaxError(Exception):
    def __init__(self, message: str, at: int = 0, text: str = ""):
        self.at = at
        self.source_text = text
        super().__init__(f"{message} (at position {at})")


class CrockfordParser:
    """Direct port of Crockford's json_parse.js recursive descent parser."""

    ESCAPEE = {
        '"': '"',
        '\\': '\\',
        '/': '/',
        'b': '\b',
        'f': '\f',
        'n': '\n',
        'r': '\r',
        't': '\t',
    }

    def __init__(self, text: str):
        self.text = text
        self.at = 0        # index of current character
        self.ch = ' '      # current character (initialized to space like original)

    def error(self, m: str):
        raise JSONSyntaxError(m, self.at, self.text)

    def next(self, c: str | None = None) -> str:
        """Advance to next character. If c is given, verify current char matches."""
        if c is not None and c != self.ch:
            self.error(f"Expected '{c}' instead of '{self.ch}'")

        if self.at < len(self.text):
            self.ch = self.text[self.at]
        else:
            self.ch = ''  # EOF
        self.at += 1
        return self.ch

    def number(self):
        """Parse a JSON number."""
        string = ''

        if self.ch == '-':
            string = '-'
            self.next('-')

        while self.ch >= '0' and self.ch <= '9':
            string += self.ch
            self.next()

        if self.ch == '.':
            string += '.'
            while self.next() and self.ch >= '0' and self.ch <= '9':
                string += self.ch

        if self.ch == 'e' or self.ch == 'E':
            string += self.ch
            self.next()
            if self.ch == '-' or self.ch == '+':
                string += self.ch
                self.next()
            while self.ch >= '0' and self.ch <= '9':
                string += self.ch
                self.next()

        if not string or string == '-' or string == '.':
            self.error("Bad number")

        try:
            value = float(string) if ('.' in string or 'e' in string or 'E' in string) else int(string)
        except ValueError:
            self.error("Bad number")

        # Crockford's original: if (!isFinite(value)) error("Bad number")
        if isinstance(value, float) and not math.isfinite(value):
            self.error("Bad number")

        return value

    def string(self) -> str:
        """Parse a JSON string."""
        value = ''

        if self.ch == '"':
            while True:
                self.next()
                if self.ch == '':
                    break
                if self.ch == '"':
                    self.next()
                    return value
                if self.ch == '\\':
                    self.next()
                    if self.ch == 'u':
                        uffff = 0
                        for _ in range(4):
                            self.next()
                            h = self.ch
                            if h in '0123456789abcdefABCDEF':
                                uffff = uffff * 16 + int(h, 16)
                            else:
                                self.error("Bad unicode escape")
                        value += chr(uffff)
                    elif self.ch in self.ESCAPEE:
                        value += self.ESCAPEE[self.ch]
                    else:
                        # Crockford's original breaks out and falls to error
                        self.error(f"Bad escape: \\{self.ch}")
                else:
                    value += self.ch

        self.error("Bad string")

    def white(self):
        """Skip whitespace (chars <= ' ')."""
        while self.ch and self.ch <= ' ':
            self.next()

    def word(self):
        """Parse true, false, or null."""
        if self.ch == 't':
            self.next('t')
            self.next('r')
            self.next('u')
            self.next('e')
            return True
        elif self.ch == 'f':
            self.next('f')
            self.next('a')
            self.next('l')
            self.next('s')
            self.next('e')
            return False
        elif self.ch == 'n':
            self.next('n')
            self.next('u')
            self.next('l')
            self.next('l')
            return None
        self.error(f"Unexpected '{self.ch}'")

    def array(self) -> list:
        """Parse a JSON array."""
        arr = []

        if self.ch == '[':
            self.next('[')
            self.white()
            if self.ch == ']':
                self.next(']')
                return arr
            while self.ch:
                arr.append(self.value())
                self.white()
                if self.ch == ']':
                    self.next(']')
                    return arr
                self.next(',')
                self.white()

        self.error("Bad array")

    def object(self) -> dict:
        """Parse a JSON object."""
        obj = {}

        if self.ch == '{':
            self.next('{')
            self.white()
            if self.ch == '}':
                self.next('}')
                return obj
            while self.ch:
                key = self.string()
                self.white()
                self.next(':')
                # Crockford's original: duplicate key check
                if key in obj:
                    self.error(f"Duplicate key '{key}'")
                obj[key] = self.value()
                self.white()
                if self.ch == '}':
                    self.next('}')
                    return obj
                self.next(',')
                self.white()

        self.error("Bad object")

    def value(self):
        """Parse a JSON value."""
        self.white()
        if self.ch == '{':
            return self.object()
        elif self.ch == '[':
            return self.array()
        elif self.ch == '"':
            return self.string()
        elif self.ch == '-':
            return self.number()
        elif self.ch >= '0' and self.ch <= '9':
            return self.number()
        else:
            return self.word()

    def parse(self):
        """Parse the complete JSON text."""
        result = self.value()
        self.white()
        # Crockford's original: if (ch) error("Syntax error")
        if self.ch:
            self.error("Syntax error: trailing data")
        return result


def crockford_parse(data: str) -> str:
    """Parse JSON using Crockford's recursive descent parser."""
    parser = CrockfordParser(data)
    obj = parser.parse()
    return json.dumps(obj, sort_keys=True, ensure_ascii=True)


def main():
    if len(sys.argv) < 2:
        print("Usage: json_crockford.py <file>", file=sys.stderr)
        sys.exit(2)

    try:
        with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
    except OSError as e:
        print(f"IO error: {e}", file=sys.stderr)
        sys.exit(2)

    try:
        result = crockford_parse(data)
        print(result)
        sys.exit(0)
    except (JSONSyntaxError, ValueError, TypeError, OverflowError) as e:
        print(f"REJECT: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
