"""Property-learning concolic coordinator.

Replaces the hardcoded expert-system ConcolicCoordinator with a
learning-based system that discovers which structural XML properties
predict behavioral divergence across library pairs.

Same API as ConcolicCoordinator: ``on_differential_result() -> list[Input]``.
"""

from __future__ import annotations

import json
import logging
import random
import re
from typing import Any

from ..protocols import ExecutionResult, Input
from .correlation_tracker import CorrelationTracker
from .property_extractor import PROPERTY_NAMES, PropertyExtractor
from .property_vector import DivergenceVector, Observation

logger = logging.getLogger(__name__)

MAX_SOLUTIONS = 5
_WARMUP_ITERS = 500
_MI_THRESHOLD = 0.02  # minimum MI to consider a property "important"
_WEIGHT_UPDATE_INTERVAL = 1000  # push strategy weights every N iterations


class PropertyGuidedCoordinator:
    """Learning-based concolic coordinator.

    Loop:
        1. Extract input properties (PropertyExtractor)
        2. Compute divergence vectors (domain-agnostic JSON diff)
        3. Record observation (CorrelationTracker)
        4. Use learned correlations to generate targeted inputs

    Budget control: same as v1 — ``concolic_execs / total_iters < budget_pct``.
    Cold start: first ``_WARMUP_ITERS`` iterations are observation-only.
    """

    def __init__(
        self,
        budget_pct: float = 0.10,
        seed: int | None = None,
    ) -> None:
        self._extractor = PropertyExtractor()
        self._tracker = CorrelationTracker()
        self._rng = random.Random(seed)
        self._budget_pct = budget_pct

        # Counters
        self._concolic_execs = 0
        self._total_iters = 0

        # Cached strategy weights (updated periodically)
        self._cached_strategy_weights: dict[str, float] = {}
        self._iters_since_weight_update = 0

    def on_differential_result(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
        found_finding: bool,
    ) -> list[Input]:
        """Called after each differential execution.

        Returns 0-5 targeted inputs, or [] during warmup/over-budget/no-divergence.
        """
        self._total_iters += 1

        # 1. Extract input properties
        props = self._extractor.extract(inp.data)

        # 2. Compute divergence vectors
        divergences = self._compute_divergences(primary_result, ref_results)

        # 3. Record observation
        strategies = []
        if hasattr(inp, "metadata"):
            s = inp.metadata.get("strategies") or inp.metadata.get("strategy")
            if isinstance(s, list):
                strategies = s
            elif isinstance(s, str):
                strategies = [s]

        obs = Observation(
            properties=props,
            divergences=divergences,
            strategy_names=strategies,
            found_finding=found_finding,
            timestamp=self._total_iters,
        )
        self._tracker.record(obs)

        # 4. Periodic strategy weight update
        self._iters_since_weight_update += 1
        if self._iters_since_weight_update >= _WEIGHT_UPDATE_INTERVAL:
            self._cached_strategy_weights = self._tracker.strategy_effectiveness()
            self._iters_since_weight_update = 0

        # 5. Cold start — observe only
        if self._total_iters < _WARMUP_ITERS:
            return []

        # 6. Budget check
        if self._is_over_budget():
            return []

        # 7. Only generate if divergence detected
        if not any(d.field_diffs for d in divergences):
            return []

        # 8. Generate targeted inputs using learned correlations
        targeted = self._generate_targeted(inp, props, divergences)
        self._concolic_execs += len(targeted)

        if targeted:
            logger.debug(
                "PropertyGuided: %d targeted inputs (budget: %.1f%%, obs: %d)",
                len(targeted),
                self._budget_ratio() * 100,
                len(self._tracker._observations),
            )

        return targeted

    def get_strategy_weights(self) -> dict[str, float]:
        """Return empirical strategy -> divergence_rate for mutator weight adjustment."""
        return self._cached_strategy_weights

    def get_stats(self) -> dict[str, Any]:
        """Return stats for status line and report.json."""
        tracker_stats = self._tracker.get_stats()
        return {
            "concolic_execs": self._concolic_execs,
            "total_iters": self._total_iters,
            "budget_pct": round(self._budget_ratio() * 100, 1),
            "warmup_complete": self._total_iters >= _WARMUP_ITERS,
            **tracker_stats,
        }

    def get_status_line(self) -> str:
        """Short status string for the engine's periodic status output."""
        ratio = self._budget_ratio() * 100
        top = self._tracker.top_correlations(1)
        top_str = ""
        if top:
            p, f, mi = top[0]
            top_str = f" top:{p}->{f}({mi:.3f})"
        return f"plearn:{self._concolic_execs}({ratio:.0f}%) obs:{len(self._tracker._observations)}{top_str}"

    # ── Divergence computation (domain-agnostic) ──────────────

    def _compute_divergences(
        self,
        primary: ExecutionResult,
        refs: list[ExecutionResult],
    ) -> list[DivergenceVector]:
        """Compare ALL JSON keys between primary and each ref.

        No keyword matching — just ``p_data[k] != r_data[k]`` for every key.
        Field names are discovered at runtime.
        """
        p_data = self._parse_output(primary)
        if not p_data:
            return []

        result: list[DivergenceVector] = []
        for i, ref in enumerate(refs):
            r_data = self._parse_output(ref)
            if not r_data:
                continue

            all_keys = set(p_data.keys()) | set(r_data.keys())
            # Exclude noisy fields that change on every execution
            all_keys -= _EXCLUDED_FIELDS

            differing = frozenset(
                k for k in all_keys if p_data.get(k) != r_data.get(k)
            )

            if differing:
                result.append(
                    DivergenceVector(
                        pair=(0, i + 1),
                        field_diffs=differing,
                        sig_diverges="signature_valid" in differing,
                        subject_diverges="subject" in differing,
                    )
                )

        return result

    @staticmethod
    def _parse_output(result: ExecutionResult) -> dict[str, Any] | None:
        """Parse target JSON output."""
        if not result.stdout:
            return None
        try:
            return json.loads(result.stdout)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    # ── Targeted input generation ─────────────────────────────

    def _generate_targeted(
        self,
        inp: Input,
        props: "Any",
        divergences: list[DivergenceVector],
    ) -> list[Input]:
        """Use learned correlations to generate property-perturbing inputs."""
        important = self._tracker.property_importance()
        targeted: list[Input] = []

        for prop_idx, mi_score in important:
            if mi_score < _MI_THRESHOLD:
                break
            if len(targeted) >= MAX_SOLUTIONS:
                break

            mutations = _perturb_property(inp.data, prop_idx, self._rng)
            for m in mutations[:1]:  # max 1 per property
                if m != inp.data:
                    targeted.append(
                        Input(
                            data=m,
                            metadata={
                                "mutator": "concolic",
                                "concolic_domain": "property_guided",
                                "target_property": PROPERTY_NAMES[prop_idx],
                                "mi_score": round(mi_score, 4),
                            },
                        )
                    )

        return targeted[:MAX_SOLUTIONS]

    # ── Budget control ────────────────────────────────────────

    def _is_over_budget(self) -> bool:
        if self._total_iters < 100:
            return False
        return self._budget_ratio() > self._budget_pct

    def _budget_ratio(self) -> float:
        if self._total_iters == 0:
            return 0.0
        return self._concolic_execs / self._total_iters


# ── Excluded output fields (too noisy to track) ──────────────────

_EXCLUDED_FIELDS = frozenset({
    "duration_ms",
    "digest_input_hash",
    "signed_info_hash",
    "canonical_assertion_hex",
    "signature_error",  # free-text error messages vary trivially
})


# ── Property perturbation registry ───────────────────────────────
#
# Structural operators, NOT attack templates.
# "Add a namespace" is not "void c14n attack" — it's a generic
# structural change.  The learning system discovers which structural
# changes correlate with divergence.


def _perturb_ns_decl_count(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or remove a namespace declaration."""
    results: list[bytes] = []
    prefixes = ["x", "ns1", "foo", "a", "evil"]
    uris = [
        "1",
        "urn:test",
        "",
        ".",
        "http://example.com/ns",
        "relative/path",
        "#frag",
        "//proto",
        "%00",
        "data:,",
    ]
    # Add a namespace
    m = re.search(rb"<(\w+(?::\w+)?)\s", data[:4096])
    if m:
        pos = m.end() - 1
        p = rng.choice(prefixes)
        u = rng.choice(uris)
        ns_decl = f' xmlns:{p}="{u}"'.encode()
        results.append(data[:pos] + ns_decl + data[pos:])

    # Remove a namespace declaration
    ns_matches = list(re.finditer(rb'\s*xmlns(?::\w+)?="[^"]*"', data[:8192]))
    if ns_matches:
        m = rng.choice(ns_matches)
        results.append(data[: m.start()] + data[m.end() :])

    return results


def _perturb_assertion_count(data: bytes, rng: random.Random) -> list[bytes]:
    """Duplicate or wrap an Assertion-like element."""
    results: list[bytes] = []
    # Find an Assertion opening tag
    m = re.search(rb"(<(?:\w+:)?Assertion\b[^>]*>)", data)
    if m:
        # Insert a minimal clone before it
        clone = (
            b'<saml:Assertion Version="2.0" ID="_clone_'
            + str(rng.randint(1000, 9999)).encode()
            + b'"><saml:Subject><saml:NameID>CLONED</saml:NameID>'
            + b"</saml:Subject></saml:Assertion>"
        )
        results.append(data[: m.start()] + clone + data[m.start() :])
    return results


def _perturb_comment_count(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject XML comments at various positions."""
    results: list[bytes] = []
    comment = b"<!--INJECTED-->"
    # Before a closing tag
    closes = list(re.finditer(rb"</", data[:8192]))
    if closes:
        pos = rng.choice(closes).start()
        results.append(data[:pos] + comment + data[pos:])
    # Inside a text node (before NameID-like content)
    nameid = re.search(rb"(<(?:\w+:)?NameID[^>]*>)", data)
    if nameid:
        pos = nameid.end()
        results.append(data[:pos] + comment + data[pos:])
    return results


def _perturb_empty_ns(data: bytes, rng: random.Random) -> list[bytes]:
    """Add xmlns:prefix="" undeclaration."""
    m = re.search(rb"<(\w+(?::\w+)?)\s", data[:4096])
    if not m:
        return []
    pos = m.end() - 1
    p = rng.choice(["x", "ns1", "void"])
    return [data[:pos] + f' xmlns:{p}=""'.encode() + data[pos:]]


def _perturb_relative_ns(data: bytes, rng: random.Random) -> list[bytes]:
    """Add a relative namespace URI."""
    m = re.search(rb"<(\w+(?::\w+)?)\s", data[:4096])
    if not m:
        return []
    pos = m.end() - 1
    p = rng.choice(["x", "void", "rel"])
    u = rng.choice(["1", ".", "a/b", "#", "//", "?q", "%00", "data:,"])
    return [data[:pos] + f' xmlns:{p}="{u}"'.encode() + data[pos:]]


def _perturb_duplicate_id(data: bytes, rng: random.Random) -> list[bytes]:
    """Clone an element to create duplicate ID values."""
    id_m = re.search(rb'\bID="([^"]*)"', data)
    if not id_m:
        return []
    id_val = id_m.group(1)
    # Insert element with same ID before the original
    clone = (
        b'<DuplicateElement ID="'
        + id_val
        + b'"><Content>DUPLICATE</Content></DuplicateElement>'
    )
    return [data[: id_m.start() - 1] + clone + data[id_m.start() - 1 :]]


def _perturb_transform_count(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or remove a Transform element."""
    results: list[bytes] = []
    # Add a transform
    transforms_end = re.search(rb"</(?:\w+:)?Transforms\s*>", data)
    if transforms_end:
        algos = [
            b"http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
            b"http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
            b"http://www.w3.org/2002/06/xmldsig-filter2",
        ]
        algo = rng.choice(algos)
        inject = b'<ds:Transform Algorithm="' + algo + b'"/>'
        pos = transforms_end.start()
        results.append(data[:pos] + inject + data[pos:])

    # Remove a transform
    transform_m = list(
        re.finditer(rb"<(?:\w+:)?Transform\b[^>]*/?>", data)
    )
    if transform_m:
        m = rng.choice(transform_m)
        results.append(data[: m.start()] + data[m.end() :])

    return results


def _perturb_xpath_transform(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject an XPath transform."""
    transforms_end = re.search(rb"</(?:\w+:)?Transforms\s*>", data)
    if not transforms_end:
        return []
    xpath_exprs = [
        b"//saml:Conditions",
        b"//saml:Subject",
        b"ancestor-or-self::saml:Assertion",
        b"//ds:Signature",
    ]
    expr = rng.choice(xpath_exprs)
    inject = (
        b'<ds:Transform Algorithm="http://www.w3.org/2002/06/xmldsig-filter2">'
        b'<dsig-xpath:XPath xmlns:dsig-xpath="http://www.w3.org/2002/06/xmldsig-filter2" '
        b'Filter="subtract">' + expr + b"</dsig-xpath:XPath>"
        b"</ds:Transform>"
    )
    pos = transforms_end.start()
    return [data[:pos] + inject + data[pos:]]


def _perturb_depth(data: bytes, rng: random.Random) -> list[bytes]:
    """Wrap content in additional nesting."""
    m = re.search(rb"(<(?:\w+:)?Assertion\b[^>]*>)", data)
    if not m:
        return []
    pos = m.end()
    wrapper_open = b"<Wrapper>" * rng.randint(1, 3)
    wrapper_close = b"</Wrapper>" * wrapper_open.count(b"<Wrapper>")
    # Find the matching close tag
    close = re.search(rb"</(?:\w+:)?Assertion\s*>", data[pos:])
    if not close:
        return []
    close_pos = pos + close.start()
    return [
        data[:pos] + wrapper_open + data[pos:close_pos] + wrapper_close + data[close_pos:]
    ]


def _perturb_cdata(data: bytes, rng: random.Random) -> list[bytes]:
    """Wrap text content in CDATA sections."""
    # Find a NameID text node
    m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)([^<]+)(</)", data)
    if not m:
        return []
    text = m.group(2)
    wrapped = b"<![CDATA[" + text + b"]]>"
    return [data[: m.start(2)] + wrapped + data[m.end(2) :]]


def _perturb_pi(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject processing instructions."""
    m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)", data)
    if not m:
        return []
    pi = b"<?pi data?>"
    return [data[: m.end()] + pi + data[m.end() :]]


def _perturb_bom(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or remove UTF-8 BOM."""
    bom = b"\xef\xbb\xbf"
    if data[:3] == bom:
        return [data[3:]]  # remove
    return [bom + data]  # add


def _perturb_encoding_decl(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or change encoding declaration."""
    encodings = [b"UTF-8", b"utf-8", b"UTF-16", b"ISO-8859-1", b"us-ascii"]
    enc = rng.choice(encodings)
    m = re.search(rb"<\?xml[^?]*\?>", data[:200])
    if m:
        decl = m.group()
        if b"encoding=" in decl:
            new_decl = re.sub(rb'encoding="[^"]*"', b'encoding="' + enc + b'"', decl)
        else:
            new_decl = decl.replace(b"?>", b' encoding="' + enc + b'"?>')
        return [data[: m.start()] + new_decl + data[m.end() :]]
    return [b'<?xml version="1.0" encoding="' + enc + b'"?>' + data]


def _perturb_id_attrs(data: bytes, rng: random.Random) -> list[bytes]:
    """Change ID attribute name casing or type."""
    results: list[bytes] = []
    # Swap ID → Id or Id → ID
    if b'ID="' in data:
        results.append(data.replace(b'ID="', b'Id="', 1))
    if b' Id="' in data:
        results.append(data.replace(b' Id="', b' ID="', 1))
    # Add xml:id alongside existing ID
    m = re.search(rb'(ID="([^"]*)")', data)
    if m:
        extra = b' xml:id="' + m.group(2) + b'"'
        results.append(data[: m.end()] + extra + data[m.end() :])
    return results


def _perturb_tag_count(data: bytes, rng: random.Random) -> list[bytes]:
    """Add extra elements at various positions."""
    results: list[bytes] = []
    extras = [
        b"<Extra/>",
        b"<saml:AttributeValue>INJECTED</saml:AttributeValue>",
        b"<Extension><Data>X</Data></Extension>",
    ]
    closes = list(re.finditer(rb"</(?:\w+:)?\w+\s*>", data[:8192]))
    if closes:
        pos = rng.choice(closes).start()
        elem = rng.choice(extras)
        results.append(data[:pos] + elem + data[pos:])
    return results


# ── NEW perturbation functions (10-gap coverage) ─────────────────


def _perturb_entity_ref(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject custom entity references."""
    m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)([^<]*)(</)", data)
    if not m:
        return []
    entities = [b"&custom;", b"&#x41;", b"&#65;", b"&amp;amp;"]
    ent = rng.choice(entities)
    return [data[: m.start(2)] + ent + m.group(2) + data[m.end(2) :]]


def _perturb_dtd_entities(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject DTD with entity declarations."""
    dtds = [
        b'<!DOCTYPE Response [<!ENTITY xxe "INJECTED">]>',
        b'<!DOCTYPE Response [<!ENTITY % pe SYSTEM "file:///dev/null">]>',
        b'<!DOCTYPE Response [<!ENTITY boom "BOOM"><!ENTITY boom2 "&boom;&boom;">]>',
    ]
    dtd = rng.choice(dtds)
    # Insert after XML declaration if present
    xml_decl = re.search(rb"<\?xml[^?]*\?>", data[:200])
    pos = xml_decl.end() if xml_decl else 0
    return [data[:pos] + dtd + data[pos:]]


def _perturb_xml_version(data: bytes, rng: random.Random) -> list[bytes]:
    """Change XML version to 1.1 or add version declaration."""
    m = re.search(rb'version=["\']([^"\']*)["\']', data[:200])
    if m:
        return [data[: m.start(1)] + b"1.1" + data[m.end(1) :]]
    xml_decl = re.search(rb"<\?xml\s", data[:100])
    if xml_decl:
        return [data[: xml_decl.end()] + b'version="1.1" ' + data[xml_decl.end() :]]
    return [b'<?xml version="1.1"?>' + data]


def _perturb_conditions(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or modify Conditions element."""
    results: list[bytes] = []
    cond_m = re.search(rb"<(?:\w+:)?Conditions\b[^>]*>", data)
    if cond_m:
        # Remove NotBefore/NotOnOrAfter
        modified = re.sub(rb'\s*NotBefore="[^"]*"', b"", data, count=1)
        if modified != data:
            results.append(modified)
        modified2 = re.sub(rb'\s*NotOnOrAfter="[^"]*"', b"", data, count=1)
        if modified2 != data:
            results.append(modified2)
    else:
        # Add Conditions before Subject
        subj = re.search(rb"<(?:\w+:)?Subject[\s>]", data)
        if subj:
            cond = (
                b'<saml:Conditions NotBefore="2000-01-01T00:00:00Z" '
                b'NotOnOrAfter="2099-01-01T00:00:00Z"/>'
            )
            results.append(data[: subj.start()] + cond + data[subj.start() :])
    return results


def _perturb_audience(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or modify AudienceRestriction."""
    results: list[bytes] = []
    aud_m = re.search(rb"<(?:\w+:)?AudienceRestriction[\s>]", data)
    if aud_m:
        # Add extra Audience
        aud_close = re.search(rb"</(?:\w+:)?AudienceRestriction\s*>", data[aud_m.start():])
        if aud_close:
            pos = aud_m.start() + aud_close.start()
            extra = b"<saml:Audience>https://EVIL.sp.example.com</saml:Audience>"
            results.append(data[:pos] + extra + data[pos:])
    else:
        # Add AudienceRestriction inside Conditions
        cond_m = re.search(rb"(<(?:\w+:)?Conditions\b[^>]*>)", data)
        if cond_m:
            block = (
                b"<saml:AudienceRestriction>"
                b"<saml:Audience>https://sp.example.com</saml:Audience>"
                b"</saml:AudienceRestriction>"
            )
            results.append(data[: cond_m.end()] + block + data[cond_m.end() :])
    return results


def _perturb_nameid_format(data: bytes, rng: random.Random) -> list[bytes]:
    """Change or add NameID Format attribute."""
    formats = [
        b"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        b"urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        b"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
        b"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
    ]
    fmt = rng.choice(formats)
    m = re.search(rb'(<(?:\w+:)?NameID)\b([^>]*>)', data)
    if not m:
        return []
    tag_start = m.group(1)
    tag_rest = m.group(2)
    if b"Format=" in tag_rest:
        new_rest = re.sub(rb'Format="[^"]*"', b'Format="' + fmt + b'"', tag_rest, count=1)
        return [data[: m.start()] + tag_start + new_rest + data[m.end() :]]
    return [data[: m.start()] + tag_start + b' Format="' + fmt + b'"' + tag_rest + data[m.end() :]]


def _perturb_issuer(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or modify Issuer elements."""
    results: list[bytes] = []
    issuers = list(re.finditer(rb"(<(?:\w+:)?Issuer[^>]*>)([^<]*)(</(?:\w+:)?Issuer\s*>)", data))
    if issuers:
        # Change issuer value
        m = rng.choice(issuers)
        evil = b"https://evil.idp.example.com"
        results.append(data[: m.start(2)] + evil + data[m.end(2) :])
    # Add response-level issuer if only assertion-level exists
    resp_m = re.search(rb"(<(?:\w+:)?Response\b[^>]*>)", data)
    if resp_m:
        pos = resp_m.end()
        extra = b"<saml:Issuer>https://extra-issuer.example.com</saml:Issuer>"
        results.append(data[:pos] + extra + data[pos:])
    return results


def _perturb_keyinfo(data: bytes, rng: random.Random) -> list[bytes]:
    """Add or modify KeyInfo element."""
    results: list[bytes] = []
    sig_m = re.search(rb"</(?:\w+:)?SignedInfo\s*>", data)
    if sig_m:
        keyinfo = (
            b"<ds:KeyInfo><ds:KeyValue><ds:RSAKeyValue>"
            b"<ds:Modulus>AAAA</ds:Modulus><ds:Exponent>AQAB</ds:Exponent>"
            b"</ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>"
        )
        results.append(data[: sig_m.end()] + keyinfo + data[sig_m.end() :])
    return results


def _perturb_duplicate_attrs(data: bytes, rng: random.Random) -> list[bytes]:
    """Add duplicate attribute to a tag."""
    m = re.search(rb'(<(?:\w+:)?Assertion\b)([^>]*)(>)', data)
    if not m:
        return []
    # Add duplicate Version attribute
    return [
        data[: m.start(3)] + b' Version="1.0"' + data[m.start(3) :]
    ]


def _perturb_comment_inside_assertion(data: bytes, rng: random.Random) -> list[bytes]:
    """Inject comments inside assertion at security-relevant positions."""
    results: list[bytes] = []
    comments = [
        b"<!--HIDDEN-->",
        b"<!-- admin -->",
        b"<!--\x00-->",
        b"<!----!>",
    ]
    comment = rng.choice(comments)
    # Before NameID content
    m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)", data)
    if m:
        results.append(data[: m.end()] + comment + data[m.end() :])
    # Between Conditions and Subject
    subj = re.search(rb"<(?:\w+:)?Subject[\s>]", data)
    if subj:
        results.append(data[: subj.start()] + comment + data[subj.start() :])
    return results


# ── Perturbation registry ────────────────────────────────────────
#
# Maps property index → list of perturbation functions.
# Each function: (data: bytes, rng: Random) -> list[bytes]

_PROPERTY_PERTURBATIONS: dict[int, list] = {
    # Size (indices 0-3)
    0: [_perturb_tag_count],           # total_bytes (add/remove elements)
    1: [_perturb_tag_count],           # tag_count
    2: [_perturb_duplicate_attrs],     # attr_count (add attributes)
    3: [_perturb_cdata, _perturb_comment_count],  # text_ratio (change text/tag ratio)
    # Namespace (4-8)
    4: [_perturb_ns_decl_count],
    5: [_perturb_ns_decl_count],
    6: [_perturb_empty_ns],
    7: [_perturb_relative_ns],
    8: [_perturb_ns_decl_count],       # default_ns_present (add default ns)
    # Structure (9-14)
    9: [_perturb_depth],
    10: [_perturb_assertion_count],
    11: [_perturb_assertion_count],     # signature_count (more assertions → more sigs)
    12: [_perturb_duplicate_id],        # reference_count (duplicate refs via ID)
    13: [_perturb_comment_count],
    14: [_perturb_pi],
    # Signature (15-19)
    15: [_perturb_transform_count],
    16: [_perturb_transform_count],     # has_enveloped (toggle via transform)
    17: [_perturb_xpath_transform],
    18: [_perturb_xpath_transform],     # has_xslt_transform (similar transform injection)
    19: [_perturb_ns_decl_count],       # prefix_list_present (namespace change triggers)
    # Content (20-24)
    20: [_perturb_cdata],
    21: [_perturb_dtd_entities],        # doctype_present
    22: [_perturb_bom],
    23: [_perturb_encoding_decl],
    24: [_perturb_bom, _perturb_encoding_decl],  # non_ascii_ratio (BOM/encoding change)
    # ID (25-27)
    25: [_perturb_id_attrs],
    26: [_perturb_duplicate_id],
    27: [_perturb_id_attrs],
    # Entropy (28-29)
    28: [_perturb_entity_ref, _perturb_cdata],   # byte_entropy
    29: [_perturb_tag_count],           # tag_name_diversity
    # 10-gap coverage (30-47)
    30: [_perturb_entity_ref],
    31: [_perturb_dtd_entities],
    32: [_perturb_xml_version],
    33: [_perturb_encoding_decl],
    34: [_perturb_conditions],
    35: [_perturb_conditions],
    36: [_perturb_conditions],
    37: [_perturb_audience],
    38: [_perturb_audience],
    39: [_perturb_nameid_format],
    40: [_perturb_nameid_format],
    41: [_perturb_issuer],
    42: [_perturb_issuer],
    43: [_perturb_assertion_count],
    44: [_perturb_keyinfo],
    45: [_perturb_keyinfo],
    46: [_perturb_duplicate_attrs],
    47: [_perturb_comment_inside_assertion],
}


def _perturb_property(
    data: bytes, prop_idx: int, rng: random.Random
) -> list[bytes]:
    """Generate byte-level mutations that shift a specific property.

    Returns list of mutated byte strings (may be empty).
    """
    perturbations = _PROPERTY_PERTURBATIONS.get(prop_idx, [])
    results: list[bytes] = []
    for fn in perturbations:
        try:
            mutated = fn(data, rng)
            results.extend(m for m in mutated if m and m != data)
        except Exception:
            pass
    return results
