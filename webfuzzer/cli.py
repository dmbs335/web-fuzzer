"""CLI interface for the web fuzzer framework.

Usage:
    python -m webfuzzer generate --grammar html --count 5
    python -m webfuzzer generate --grammar csp --count 10 --seed 42
    python -m webfuzzer list
    python -m webfuzzer validate --grammar html
    python -m webfuzzer fuzz --grammar json --target-cmd "./parser {input}" --count 1000
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
from pathlib import Path

from .core.generator import Generator, GenerationError
from .core.registry import GrammarRegistry, RegistryError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webfuzzer",
        description="Grammar-based web fuzzing framework",
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    # --- generate ---
    gen = sub.add_parser("generate", help="Generate output from a grammar")
    gen.add_argument(
        "-g", "--grammar", required=True, help="Grammar name to use"
    )
    gen.add_argument(
        "-r", "--rule", default=None, help="Starting rule (default: grammar root)"
    )
    gen.add_argument(
        "-n", "--count", type=int, default=1, help="Number of outputs to generate"
    )
    gen.add_argument(
        "-s", "--seed", type=int, default=None, help="Random seed for reproducibility"
    )
    gen.add_argument(
        "-d", "--max-depth", type=int, default=None, help="Max recursion depth"
    )
    gen.add_argument(
        "--grammar-dir",
        type=Path,
        default=None,
        help="Additional directory to load grammars from",
    )
    gen.add_argument(
        "--no-builtins",
        action="store_true",
        help="Don't load built-in grammar files",
    )
    gen.add_argument(
        "-o", "--output", type=Path, default=None, help="Output file (default: stdout)"
    )
    gen.add_argument(
        "--separator",
        default="\n---\n",
        help="Separator between generated outputs (default: ---)",
    )

    # --- list ---
    sub.add_parser("list", help="List loaded grammars and their rules")

    # --- validate ---
    val = sub.add_parser("validate", help="Validate grammar files")
    val.add_argument(
        "-g", "--grammar", default=None, help="Specific grammar to validate (or all)"
    )
    val.add_argument(
        "--grammar-dir",
        type=Path,
        default=None,
        help="Additional directory to load grammars from",
    )

    # --- fuzz ---
    fuz = sub.add_parser("fuzz", help="Fuzz a target using grammar-based generation")
    fuz.add_argument(
        "-g", "--grammar", required=True, help="Grammar name for input generation"
    )
    fuz.add_argument(
        "-r", "--rule", default=None, help="Starting rule (default: grammar root)"
    )
    fuz.add_argument(
        "--target-cmd", required=True,
        help="Command to execute. Use {input} as placeholder for input file path",
    )
    fuz.add_argument(
        "-n", "--count", type=int, default=0,
        help="Max iterations (0 = unlimited, default: 0)",
    )
    fuz.add_argument(
        "-t", "--timeout", type=float, default=0,
        help="Max time in seconds (0 = unlimited)",
    )
    fuz.add_argument(
        "-s", "--seed", type=int, default=None, help="Random seed"
    )
    fuz.add_argument(
        "--mutators", default="grammar,havoc",
        help="Comma-separated mutator list (grammar,havoc,token,splice,dictionary,mxss,structural,saml,cookie,jwt,oauth,domclobber)",
    )
    fuz.add_argument(
        "--scheduler", default="entropic",
        help="Seed scheduler (random,entropic,ecofuzz,rare-branch,map-elites)",
    )
    fuz.add_argument(
        "--oracle", default="crash,sanitizer",
        help="Comma-separated oracle list (crash,response,sanitizer,xss,mxss,ssrf,saml,saml_sigtrue,saml_validator,cookie,jwt,oauth,graphql,graphql_exec,sanitizer_diff,deser,jndi,jdbc,domclobber,domclobber_diff)",
    )
    fuz.add_argument(
        "--initial-seeds", type=int, default=100,
        help="Number of initial seeds to generate (default: 100)",
    )
    fuz.add_argument(
        "-o", "--output-dir", type=Path, default=None,
        help="Directory for findings and corpus",
    )
    fuz.add_argument(
        "--grammar-dir", type=Path, default=None,
        help="Additional directory to load grammars from",
    )
    fuz.add_argument(
        "--no-builtins", action="store_true",
        help="Don't load built-in grammar files",
    )
    fuz.add_argument(
        "--diff-cmd", action="append", default=[],
        help="Reference target for differential fuzzing (repeatable)",
    )
    fuz.add_argument(
        "--dict-file", type=Path, default=None,
        help="Dictionary file for dictionary mutator (one token per line)",
    )
    fuz.add_argument(
        "--seeds-dir", type=Path, default=None,
        help="Directory of seed files to load into initial corpus",
    )
    fuz.add_argument(
        "--max-corpus-size", type=int, default=5000,
        help="Maximum corpus size (default: 5000, dynamically scales up to 2x when discovering new coverage)",
    )
    fuz.add_argument(
        "--max-assertions", type=int, default=0,
        help="Limit max assertion count per SAML payload (0=no limit, 1=single assertion mode for FP reduction)",
    )
    fuz.add_argument(
        "--import-findings", type=Path, nargs="+", default=None,
        help="Import finding inputs from previous session directories as seeds "
             "(e.g. --import-findings /path/to/session/53 /path/to/session/58)",
    )
    fuz.add_argument(
        "--persistent", action="store_true",
        help="Use persistent target mode (keep subprocess alive, ~50x faster)",
    )
    fuz.add_argument(
        "--resume", action="store_true",
        help="Resume from last checkpoint (requires --output-dir with existing checkpoint)",
    )
    fuz.add_argument(
        "--checkpoint-interval", type=float, default=60.0,
        help="Checkpoint save interval in seconds (default: 60)",
    )

    fuz.add_argument(
        "--campaign", default=None,
        help="Campaign preset (cve_detect, patch_bypass, novel). "
             "Pre-configures oracle/mutators/seeds for the campaign goal.",
    )

    # ── Exploration strategy flags ─────────────────────────────
    fuz.add_argument(
        "--mcts", action="store_true",
        help="Use MCTS-guided grammar derivation (UCB1 production selection)",
    )
    fuz.add_argument(
        "--mcts-exploration", type=float, default=1.41,
        help="MCTS exploration weight (UCB1 c parameter, default: 1.41)",
    )
    fuz.add_argument(
        "--mutator-scheduler", default="random",
        help="Mutator scheduler (random,mopt,darwin,linucb)",
    )
    fuz.add_argument(
        "--mutator-weights",
        default=None,
        help="Comma-separated weights for mutators (e.g. '1,1,3' for grammar,havoc,saml → 20%%/20%%/60%%)",
    )
    fuz.add_argument(
        "--linucb-alpha", type=float, default=1.0,
        help="LinUCB exploration parameter (default: 1.0)",
    )
    fuz.add_argument(
        "--danger-boost", action="store_true", default=True,
        help="Enable danger-weighted seed scheduling (default: on)",
    )
    fuz.add_argument(
        "--no-danger-boost", dest="danger_boost", action="store_false",
        help="Disable danger-weighted seed scheduling",
    )
    fuz.add_argument(
        "--adaptive-coverage", action="store_true",
        help="Enable CEGAR-inspired adaptive coverage abstraction",
    )
    fuz.add_argument(
        "--adaptive-level", type=int, default=1, choices=range(5),
        help="Initial refinement level 0-4 (default: 1=coarse)",
    )
    fuz.add_argument(
        "--adaptive-upper-pct", type=float, default=5.0,
        help="Coarsen when corpus%% exceeds this threshold (default: 5.0)",
    )
    fuz.add_argument(
        "--adaptive-check-interval", type=int, default=5000,
        help="Check abstraction every N iterations (default: 5000)",
    )
    fuz.add_argument(
        "--target-coverage", action="store_true",
        help="Enable per-target code coverage collection (augments diff coverage with structural code paths)",
    )
    fuz.add_argument(
        "--verify-browser", action="store_true",
        help="Publish interesting inputs to a file queue for async browser verification",
    )
    fuz.add_argument(
        "--guidance", default=None, choices=["jwt", "saml"],
        help="Enable static-analysis guidance for mutation bias and finding attribution",
    )
    fuz.add_argument(
        "--guidance-profiles", type=Path, default=None,
        help="Directory with cached guidance profile JSONs (skip live analysis)",
    )
    fuz.add_argument(
        "--concolic", action="store_true", default=False,
        help="Enable concolic constraint extraction and solving (SAML only)",
    )
    fuz.add_argument(
        "--concolic-budget", type=float, default=0.10,
        help="Max fraction of iterations for concolic phase (default: 0.10)",
    )
    fuz.add_argument(
        "--concolic-mode", choices=["expert", "learned", "hybrid", "whitebox"],
        default="hybrid",
        help="Concolic mode: 'hybrid' (default), 'whitebox' (coverage-guided, no expert), 'expert' (v1), 'learned' (v2)",
    )

    # ── verify-browser subcommand ──────────────────────────────
    vb = sub.add_parser(
        "verify-browser",
        help="Browser verification: consume queue, re-parse in Chromium",
    )
    vb.add_argument(
        "-o", "--output-dir", type=Path, required=True,
        help="Session output directory (same as the fuzzer session)",
    )
    vb.add_argument(
        "--sanitizer", default="dompurify",
        choices=["dompurify", "jsxss", "sanitize-html"],
        help="Which sanitizer's browser module to use (default: dompurify)",
    )

    return parser


# ── Persistent target helpers ────────────────────────────────────

# Maps subprocess target scripts to their persistent module equivalents
# Value format: (wrapper_cmd, module_path)
_PERSISTENT_MODULE_MAP = {
    "targets/sanitizer_dompurify.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_module.js"),
    "targets/sanitizer_sanitize_html.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_module.js"),
    "targets/sanitizer_jsxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_jsxss_module.js"),
    "targets/sanitizer_dompurify_mxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_module.js"),
    "targets/sanitizer_dompurify_mxss_browser.js": ("node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js", "targets/sanitizer_dompurify_mxss_browser_module.js"),
    # DOMPurify config variant targets
    "targets/sanitizer_dompurify_mxss_templates.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_templates_module.js"),
    "targets/sanitizer_dompurify_mxss_xhtml.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_xhtml_module.js"),
    "targets/sanitizer_dompurify_mxss_wholedoc.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_wholedoc_module.js"),
    "targets/sanitizer_dompurify_mxss_custom.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_mxss_custom_module.js"),
    "targets/sanitizer_jsxss_mxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_jsxss_mxss_module.js"),
    "targets/sanitizer_sanitize_html_mxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_mxss_module.js"),
    # Browser-in-the-loop mXSS targets (Playwright + Chromium)
    "targets/sanitizer_jsxss_mxss_browser.js": ("node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js", "targets/sanitizer_jsxss_mxss_browser_module.js"),
    "targets/sanitizer_sanitize_html_mxss_browser.js": ("node --expose-gc --max-old-space-size=1024 targets/persistent_wrapper_async.js", "targets/sanitizer_sanitize_html_mxss_browser_module.js"),
    # Sanitizer differential targets
    "targets/sanitizer_dompurify_diff.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_dompurify_diff_module.js"),
    "targets/sanitizer_sanitize_html_diff.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_sanitize_html_diff_module.js"),
    "targets/sanitizer_jsxss_diff.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/sanitizer_jsxss_diff_module.js"),
    "targets/url_node_whatwg.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/url_node_whatwg_module.js"),
    "targets/url_node_legacy.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/url_node_legacy_module.js"),
    "targets/url_python_urllib.py": ("python targets/persistent_wrapper.py", "targets/url_python_urllib_module.py"),
    "targets/url_python_rfc3986.py": ("python targets/persistent_wrapper.py", "targets/url_python_rfc3986_module.py"),
    # New URL parser targets
    "targets/url_curl.py": ("python targets/persistent_wrapper.py", "targets/url_curl_module.py"),
    "targets/url_php_parse_url.php": ("python targets/persistent_wrapper.py", "targets/url_php_parse_url_module.py"),
    "targets/url_wget.py": ("python targets/persistent_wrapper.py", "targets/url_wget_module.py"),
    # SAML targets
    "targets/saml_xmlcrypto.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/saml_xmlcrypto_module.js"),
    "targets/saml_samlify.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/saml_samlify_module.js"),
    "targets/saml_nodesaml.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/saml_nodesaml_module.js"),
    "targets/saml_signxml.py": ("python targets/persistent_wrapper.py", "targets/saml_signxml_module.py"),
    "targets/saml_python3saml.py": ("python targets/persistent_wrapper.py", "targets/saml_python3saml_module.py"),
    "targets/saml_rubysaml.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/saml_rubysaml_module.rb"),
    "targets/saml_phpsaml.php": ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php", "targets/saml_phpsaml_module.php"),
    # JWT targets
    "targets/jwt_python_strict.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_strict_module.py"),
    "targets/jwt_node_permissive.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_permissive_module.js"),
    "targets/jwt_node_pac4j_like.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_pac4j_like_module.js"),
    "targets/jwt_python_jwcrypto.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jwcrypto_module.py"),
    "targets/jwt_node_jsonwebtoken.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jsonwebtoken_module.js"),
    "targets/jwt_node_jose4.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jose4_module.js"),
    "targets/jwt_python_pyjwt.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_pyjwt_module.py"),
    "targets/jwt_python_jose.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jose_module.py"),
    "targets/jwt_node_fastjwt.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_fastjwt_module.js"),
    # JWT RSA targets (§1-2, §2-3, §7-1 keyless attacks)
    "targets/jwt_node_jsonwebtoken_rsa.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jsonwebtoken_rsa_module.js"),
    "targets/jwt_python_pyjwt_rsa.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_pyjwt_rsa_module.py"),
    "targets/jwt_python_jwcrypto_rsa.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jwcrypto_rsa_module.py"),
    # JWT EC targets (§1-3 algorithm downgrade, §3-2 ECDSA curve confusion)
    "targets/jwt_python_pyjwt_ec.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_pyjwt_ec_module.py"),
    "targets/jwt_python_jwcrypto_ec.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_jwcrypto_ec_module.py"),
    # JWT Authlib target
    "targets/jwt_python_authlib.py": ("python targets/persistent_wrapper.py", "targets/jwt_python_authlib_module.py"),
    "targets/jwt_node_jsonwebtoken_ec.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jsonwebtoken_ec_module.js"),
    "targets/jwt_node_jose4_ec.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/jwt_node_jose4_ec_module.js"),
    # Multi-language sanitizer differential targets
    "targets/sanitizer_bleach_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_bleach_diff_module.py"),
    "targets/sanitizer_nh3_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_nh3_diff_module.py"),
    "targets/sanitizer_lxml_diff.py": ("python targets/persistent_wrapper.py", "targets/sanitizer_lxml_diff_module.py"),
    "targets/sanitizer_sanitize_diff.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/sanitizer_sanitize_diff_module.rb"),
    "targets/sanitizer_loofah_diff.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/sanitizer_loofah_diff_module.rb"),
    "targets/sanitizer_htmlpurifier_diff.php": ("C:/Users/dmbs3/AppData/Local/Microsoft/WinGet/Packages/PHP.PHP.8.3_Microsoft.Winget.Source_8wekyb3d8bbwe/php.exe targets/persistent_wrapper.php", "targets/sanitizer_htmlpurifier_diff_module.php"),
    # Cookie targets
    "targets/cookie_python_stdlib.py": ("python targets/persistent_wrapper.py", "targets/cookie_python_stdlib_module.py"),
    "targets/cookie_node_setcookieparser.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/cookie_node_setcookieparser_module.js"),
    "targets/cookie_node_toughcookie.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/cookie_node_toughcookie_module.js"),
    "targets/cookie_node_cookie.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/cookie_node_cookie_module.js"),
    "targets/cookie_ruby_webrick.rb": ("C:/Ruby32-x64/bin/ruby targets/persistent_wrapper.rb", "targets/cookie_ruby_webrick_module.rb"),
    # OAuth targets
    "targets/oauth_redirect_oidcprovider.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_redirect_oidcprovider_module.js"),
    "targets/oauth_redirect_nodeoauth2.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_redirect_nodeoauth2_module.js"),
    "targets/oauth_redirect_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_redirect_authlib_module.py"),
    "targets/oauth_scope_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_scope_oauthlib_module.py"),
    # OAuth real-library scope targets
    "targets/oauth_scope_authlib_real.py": ("python targets/persistent_wrapper.py", "targets/oauth_scope_authlib_real_module.py"),
    "targets/oauth_scope_oauthlib_real.py": ("python targets/persistent_wrapper.py", "targets/oauth_scope_oauthlib_real_module.py"),
    # OAuth PKCE targets
    "targets/oauth_pkce_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_pkce_authlib_module.py"),
    "targets/oauth_pkce_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_pkce_oauthlib_module.py"),
    "targets/oauth_pkce_node.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_pkce_node_module.js"),
    # OAuth token request targets
    "targets/oauth_tokenreq_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenreq_authlib_module.py"),
    "targets/oauth_tokenreq_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenreq_oauthlib_module.py"),
    "targets/oauth_tokenreq_node.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_tokenreq_node_module.js"),
    # OAuth token response targets
    "targets/oauth_tokenresp_authlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenresp_authlib_module.py"),
    "targets/oauth_tokenresp_oauthlib.py": ("python targets/persistent_wrapper.py", "targets/oauth_tokenresp_oauthlib_module.py"),
    "targets/oauth_tokenresp_node.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/oauth_tokenresp_node_module.js"),
    # DPoP targets (RFC 9449)
    "targets/dpop_node_jose.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/dpop_node_jose_module.js"),
    "targets/dpop_python_authlib.py": ("python targets/persistent_wrapper.py", "targets/dpop_python_authlib_module.py"),
    "targets/dpop_python_strict.py": ("python targets/persistent_wrapper.py", "targets/dpop_python_strict_module.py"),
    # Markdown targets
    "targets/markdown_node_marked.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_marked_module.js"),
    "targets/markdown_node_markdownit.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_markdownit_module.js"),
    "targets/markdown_node_showdown.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_showdown_module.js"),
    "targets/markdown_python_markdown.py": ("python targets/persistent_wrapper.py", "targets/markdown_python_markdown_module.py"),
    "targets/markdown_python_mistune.py": ("python targets/persistent_wrapper.py", "targets/markdown_python_mistune_module.py"),
    "targets/markdown_python_commonmark.py": ("python targets/persistent_wrapper.py", "targets/markdown_python_commonmark_module.py"),
    "targets/markdown_node_markdownit_safe.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_markdownit_safe_module.js"),
    "targets/markdown_node_marked_gfm.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/markdown_node_marked_gfm_module.js"),
    # GraphQL targets (parse+validate)
    "targets/graphql_node_graphqljs.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/graphql_node_graphqljs_module.js"),
    "targets/graphql_python_graphqlcore.py": ("python targets/persistent_wrapper.py", "targets/graphql_python_graphqlcore_module.py"),
    # GraphQL execution targets (parse+validate+execute with mock resolvers)
    "targets/graphql_node_graphqljs_exec.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper_async.js", "targets/graphql_node_graphqljs_exec_module.js"),
    # DOM Clobbering targets
    "targets/domclobber_dompurify.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/domclobber_dompurify_module.js"),
    "targets/domclobber_jsxss.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/domclobber_jsxss_module.js"),
    "targets/domclobber_sanitize_html.js": ("node --expose-gc --max-old-space-size=512 targets/persistent_wrapper.js", "targets/domclobber_sanitize_html_module.js"),
    # Class pollution targets
    "targets/class_pollution_merge_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_merge_target_module.py"),
    "targets/class_pollution_instrumented_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_instrumented_target_module.py"),
    "targets/class_pollution_deepdiff_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_deepdiff_target_module.py"),
    "targets/class_pollution_pydantic_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_pydantic_target_module.py"),
    "targets/class_pollution_reallib_target.py": ("python targets/persistent_wrapper.py", "targets/class_pollution_reallib_target_module.py"),
    # Apache confusion targets (per-port config via env var)
    "targets/apache_confusion_target.py": ("python targets/persistent_wrapper.py", "targets/apache_confusion_target_module.py"),
    # JS sandbox escape targets
    "node targets/sandbox_vm2_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_vm2_module.js"),
    "node targets/sandbox_ivm_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_ivm_module.js"),
    "node targets/sandbox_ses_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_ses_module.js"),
    "node targets/sandbox_safeeval_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_safeeval_module.js"),
    "node targets/sandbox_vm_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_vm_module.js"),
    "node targets/sandbox_expreval_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_expreval_module.js"),
    "node targets/sandbox_notevil_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_notevil_module.js"),
    "node targets/sandbox_staticeval_module.js": ("node --expose-gc targets/persistent_wrapper.js", "targets/sandbox_staticeval_module.js"),
}

# Targets with native persistent mode (binary protocol, no wrapper needed).
# Command format for PersistentTarget: the command itself runs the binary protocol loop.
_NATIVE_PERSISTENT_MAP = {
    "java -cp targets/url_java_uri UrlJavaUri": "java -cp targets/url_java_uri UrlJavaUri --persistent",
    "java -cp targets/url_java_url UrlJavaUrl": "java -cp targets/url_java_url UrlJavaUrl --persistent",
    "targets/url_go_neturl/url_go_neturl.exe": "targets/url_go_neturl/url_go_neturl.exe --persistent",
    "targets/url_go_neturl/url_go_neturl": "targets/url_go_neturl/url_go_neturl --persistent",
    "targets/url_go_net_url/url_go_net_url.exe": "targets/url_go_net_url/url_go_net_url.exe --persistent",
    "targets/url_go_net_url/url_go_net_url": "targets/url_go_net_url/url_go_net_url --persistent",
    "targets/url_rust_url/target/release/url_rust_url.exe": "targets/url_rust_url/target/release/url_rust_url.exe --persistent",
    "targets/url_rust_url/target/release/url_rust_url": "targets/url_rust_url/target/release/url_rust_url --persistent",
    # Python wrapper maps to Go binary persistent mode
    "python targets/url_go_neturl.py": "targets/url_go_neturl/url_go_neturl.exe --persistent",
    # SAML Go target (crewjam/saml)
    "targets/saml_crewjam/saml_crewjam.exe": "targets/saml_crewjam/saml_crewjam.exe --persistent",
    "targets/saml_crewjam/saml_crewjam": "targets/saml_crewjam/saml_crewjam --persistent",
    # SAML Java target (JDK javax.xml.crypto / Xerces)
    "java -cp targets/saml_java_xmldsig SamlJavaXmldsig": "java -cp targets/saml_java_xmldsig SamlJavaXmldsig --persistent",
    # SAML Rust target (quick-xml parser)
    "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser.exe": "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser.exe --persistent",
    "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser": "targets/saml_rust_xmlparser/target/release/saml_rust_xmlparser --persistent",
    # OAuth Go target (fosite)
    "targets/oauth_fosite/oauth_fosite.exe": "targets/oauth_fosite/oauth_fosite.exe --persistent",
    "targets/oauth_fosite/oauth_fosite": "targets/oauth_fosite/oauth_fosite --persistent",
    # GraphQL Java target (graphql-java — parse+validate)
    "java -cp targets/graphql_java GraphqlJava": "java -cp targets/graphql_java/*;targets/graphql_java GraphqlJava --persistent",
    # GraphQL Java execution target (graphql-java — parse+validate+execute)
    "java -cp targets/graphql_java GraphqlJavaExec": "java -cp targets/graphql_java/*;targets/graphql_java GraphqlJavaExec --persistent",
    # JWT Java targets (nimbus-jose-jwt, auth0 java-jwt, jjwt)
    "java -cp targets/jwt_java/*;targets/jwt_java JwtNimbus": "java -cp targets/jwt_java/*;targets/jwt_java JwtNimbus --persistent",
    "java -cp targets/jwt_java/*;targets/jwt_java JwtAuth0": "java -cp targets/jwt_java/*;targets/jwt_java JwtAuth0 --persistent",
    "java -cp targets/jwt_java/*;targets/jwt_java JwtJjwt": "java -cp targets/jwt_java/*;targets/jwt_java JwtJjwt --persistent",
    "java -cp targets/jwt_java/*;targets/jwt_java JwtJose4j": "java -cp targets/jwt_java/*;targets/jwt_java JwtJose4j --persistent",
    # JWT Go targets (go-jose, golang-jwt)
    "targets/jwt_go/jwt_go.exe go_jose": "targets/jwt_go/jwt_go.exe go_jose --persistent",
    "targets/jwt_go/jwt_go.exe golang_jwt": "targets/jwt_go/jwt_go.exe golang_jwt --persistent",
    # Multi-language sanitizer (native binary protocol, no args = persistent)
    "targets/sanitizer_bluemonday.exe": "targets/sanitizer_bluemonday.exe",
    "targets/sanitizer_ammonia.exe": "targets/sanitizer_ammonia.exe",
    "targets/rust-sanitizer/target/release/sanitizer_ammonia.exe": "targets/rust-sanitizer/target/release/sanitizer_ammonia.exe",
    # Java deserialization gadget targets (CC3/CC4/mixed × open/filtered)
    # --add-opens required for Java 17+ module system (reflection on internal fields)
    # java.xml → TemplatesImpl (class_load sink), java.sql.rowset → JdbcRowSetImpl (jndi sink)
    # Classpath uses explicit jars (no wildcards) for Windows compatibility
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath cc3":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath cc3",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath cc4":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath cc4",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath cc4 --filter jep290":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath cc4 --filter jep290",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath mixed":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath mixed",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath mixed --filter denylist":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath mixed --filter denylist",
    # Docker-based WebLogic 14.1.1.0: DeserB64Wrapper inside real WL container
    # Base64 text protocol avoids Windows binary pipe issues, ~70 exec/s
    # Container ID e3a1ac3f2d14 — update if recreated
    "docker DeserTarget --classpath weblogic":
        "python targets/docker_deser_b64_bridge.py e3a1ac3f2d14 --classpath weblogic",
    "docker DeserTarget --classpath weblogic --filter weblogic":
        "python targets/docker_deser_b64_bridge.py e3a1ac3f2d14 --classpath weblogic --filter weblogic",
    # WebLogic classpath: mixed libs + weblogic.jar + BEA Spring (novel gadget hunting)
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath weblogic":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/weblogic_libs/weblogic.jar;targets/deser_java/weblogic_libs/bea-spring.jar;targets/deser_java/weblogic_libs/javax.transaction_1.0.0.0_1-1.jar;targets/deser_java/weblogic_libs/javax.jms_1.1.1.jar;targets/deser_java/weblogic_libs/com.bea.core.transaction_2.7.1.0.jar;targets/deser_java/weblogic_libs/coherence.jar;targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath weblogic",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath weblogic --filter denylist":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/weblogic_libs/weblogic.jar;targets/deser_java/weblogic_libs/bea-spring.jar;targets/deser_java/weblogic_libs/javax.transaction_1.0.0.0_1-1.jar;targets/deser_java/weblogic_libs/javax.jms_1.1.1.jar;targets/deser_java/weblogic_libs/com.bea.core.transaction_2.7.1.0.jar;targets/deser_java/weblogic_libs/coherence.jar;targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath weblogic --filter denylist",
    # WebLogic 14.1.1.0 ClassFilter: exact replica of actual WL blacklist (package + class level)
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath weblogic --filter weblogic":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/weblogic_libs/weblogic.jar;targets/deser_java/weblogic_libs/bea-spring.jar;targets/deser_java/weblogic_libs/javax.transaction_1.0.0.0_1-1.jar;targets/deser_java/weblogic_libs/javax.jms_1.1.1.jar;targets/deser_java/weblogic_libs/com.bea.core.transaction_2.7.1.0.jar;targets/deser_java/weblogic_libs/coherence.jar;targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --classpath weblogic --filter weblogic",
    # WildFly shaded gadget discovery: JSTL shaded Xalan + CC3 + CB + Hibernate
    # Shaded classes live in application namespace → no --add-opens needed for them
    # --add-opens still needed for JDK internals used by CC3/CB reflection
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath wildfly":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/wildfly_libs/jakarta.servlet.jsp.jstl-3.0.1-jbossorg-1.jar;targets/deser_java/wildfly_libs/commons-beanutils-1.11.0.jar;targets/deser_java/wildfly_libs/commons-collections-3.2.2.jar;targets/deser_java/wildfly_libs/commons-logging-jboss-logging-1.0.0.Final.jar;targets/deser_java/wildfly_libs/jboss-logging-3.6.1.Final.jar;targets/deser_java/wildfly_libs/hibernate-core-6.6.40.Final.jar;targets/deser_java/wildfly_libs/asm-9.7.1.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java DeserTarget --persistent --classpath wildfly",
    "java -javaagent:targets/deser_java/deser_agent.jar -cp targets/deser_java DeserTarget --classpath wildfly --filter wildfly":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/wildfly_libs/jakarta.servlet.jsp.jstl-3.0.1-jbossorg-1.jar;targets/deser_java/wildfly_libs/commons-beanutils-1.11.0.jar;targets/deser_java/wildfly_libs/commons-collections-3.2.2.jar;targets/deser_java/wildfly_libs/commons-logging-jboss-logging-1.0.0.Final.jar;targets/deser_java/wildfly_libs/jboss-logging-3.6.1.Final.jar;targets/deser_java/wildfly_libs/hibernate-core-6.6.40.Final.jar;targets/deser_java/wildfly_libs/asm-9.7.1.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java DeserTarget --persistent --classpath wildfly --filter wildfly",
    # Binary mode: raw .ser bytes → deserialize only (skip IR compilation)
    # -javaagent for JDD-style sink tracking (cmd_exec/jndi/reflection/class_load)
    # WildFly binary mode: shaded Xalan + CC3 + CB + Hibernate on classpath
    "java DeserTarget --binary --classpath wildfly":
        "java -javaagent:targets/deser_java/deser_agent.jar -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -cp targets/deser_java/wildfly_libs/jakarta.servlet.jsp.jstl-3.0.1-jbossorg-1.jar;targets/deser_java/wildfly_libs/commons-beanutils-1.11.0.jar;targets/deser_java/wildfly_libs/commons-collections-3.2.2.jar;targets/deser_java/wildfly_libs/commons-logging-jboss-logging-1.0.0.Final.jar;targets/deser_java/wildfly_libs/jboss-logging-3.6.1.Final.jar;targets/deser_java/wildfly_libs/hibernate-core-6.6.40.Final.jar;targets/deser_java/wildfly_libs/asm-9.7.1.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java DeserTarget --persistent --binary --classpath wildfly",
    "java DeserTarget --binary --classpath mixed":
        "java -javaagent:targets/deser_java/deser_agent.jar --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -Dorg.apache.commons.collections.enableUnsafeSerialization=true -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --binary --classpath mixed",
    "java DeserTarget --binary --classpath mixed --filter jep290":
        "java -javaagent:targets/deser_java/deser_agent.jar --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -Dorg.apache.commons.collections.enableUnsafeSerialization=true -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --binary --classpath mixed --filter jep290",
    "java DeserTarget --binary --classpath mixed --filter denylist":
        "java -javaagent:targets/deser_java/deser_agent.jar --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.base/java.util=ALL-UNNAMED --add-opens java.base/java.lang.reflect=ALL-UNNAMED --add-opens java.base/java.util.concurrent=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED --add-opens java.sql.rowset/javax.sql.rowset=ALL-UNNAMED -Dorg.apache.commons.collections.enableUnsafeSerialization=true -cp targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java/asm-9.7.jar;targets/deser_java/asm-commons-9.7.jar;targets/deser_java DeserTarget --persistent --binary --classpath mixed --filter denylist",
    # ── JNDI ObjectFactory targets (post-8u191 exploitation via local factories) ──
    # Requires Tomcat jars on classpath for BeanFactory, DataSource factories, etc.
    # --add-opens for javax.naming internal access
    # Tomcat 9.0.98 (forceString patched — BeanFactory restricted)
    "java -cp targets/deser_java JndiTarget --classpath tomcat":
        "java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp targets/deser_java/jndi_libs/tomcat-catalina.jar;targets/deser_java/jndi_libs/tomcat-naming.jar;targets/deser_java/jndi_libs/el-api.jar;targets/deser_java/jndi_libs/tomcat-el.jar;targets/deser_java/jndi_libs/tomcat-dbcp.jar;targets/deser_java/jndi_libs/tomcat-api.jar;targets/deser_java/jndi_libs/tomcat-juli.jar;targets/deser_java/jndi_libs/tomcat-util.jar;targets/deser_java/jndi_libs/annotations-api.jar;targets/deser_java/jndi_libs/h2.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # Tomcat 9.0.62 (forceString WORKS — pre-patch, BeanFactory → RCE)
    "java -cp targets/deser_java JndiTarget --classpath tomcat962":
        "java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp targets/deser_java/jndi_libs/tomcat962-catalina.jar;targets/deser_java/jndi_libs/tomcat962-el-api.jar;targets/deser_java/jndi_libs/tomcat962-el.jar;targets/deser_java/jndi_libs/tomcat962-dbcp.jar;targets/deser_java/jndi_libs/tomcat962-api.jar;targets/deser_java/jndi_libs/tomcat962-juli.jar;targets/deser_java/jndi_libs/tomcat962-util.jar;targets/deser_java/jndi_libs/h2.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # Mixed classpath (Tomcat 9.0.62 + extra sinks: Groovy, BeanShell, SnakeYAML)
    "java -cp targets/deser_java JndiTarget --classpath mixed":
        "java --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp targets/deser_java/jndi_libs/tomcat962-catalina.jar;targets/deser_java/jndi_libs/tomcat962-el-api.jar;targets/deser_java/jndi_libs/tomcat962-el.jar;targets/deser_java/jndi_libs/tomcat962-dbcp.jar;targets/deser_java/jndi_libs/tomcat962-api.jar;targets/deser_java/jndi_libs/tomcat962-juli.jar;targets/deser_java/jndi_libs/tomcat962-util.jar;targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/groovy.jar;targets/deser_java/jndi_libs/bsh.jar;targets/deser_java/jndi_libs/snakeyaml.jar;targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # Full classpath (Tomcat 9.0.62 + WebLogic 14.1.1.0 modules + all gadget JARs)
    # Uses wildcard for WL14 modules (441 JARs, 197MB) — Java resolves at startup
    # NOTE: Tomcat EL JARs listed BEFORE WL wildcard to prevent javax.javaee-api.jar shadow
    "java -cp targets/deser_java JndiTarget --classpath full":
        "java -Dorg.apache.commons.collections.enableUnsafeSerialization=true --add-opens java.base/java.lang=ALL-UNNAMED --add-opens java.naming/javax.naming=ALL-UNNAMED --add-opens java.naming/javax.naming.spi=ALL-UNNAMED -cp "
        "targets/deser_java/jndi_libs/tomcat962-catalina.jar;targets/deser_java/jndi_libs/tomcat962-el-api.jar;targets/deser_java/jndi_libs/tomcat962-el.jar;targets/deser_java/jndi_libs/tomcat962-dbcp.jar;targets/deser_java/jndi_libs/tomcat962-api.jar;targets/deser_java/jndi_libs/tomcat962-juli.jar;targets/deser_java/jndi_libs/tomcat962-util.jar;"
        "targets/deser_java/weblogic_libs/wl14/*;"
        "targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/hsqldb.jar;targets/deser_java/jndi_libs/groovy.jar;targets/deser_java/jndi_libs/bsh.jar;targets/deser_java/jndi_libs/snakeyaml.jar;"
        "targets/deser_java/jndi_libs/commons-dbcp2.jar;targets/deser_java/jndi_libs/commons-pool2.jar;targets/deser_java/jndi_libs/hikaricp.jar;targets/deser_java/jndi_libs/druid.jar;"
        "targets/deser_java/jndi_libs/c3p0-0.9.5.5.jar;targets/deser_java/jndi_libs/mchange-commons-java-0.2.20.jar;targets/deser_java/jndi_libs/postgresql-42.7.1.jar;targets/deser_java/jndi_libs/mysql-connector-j-8.2.0.jar;"
        "targets/deser_java/jndi_libs/tomcat-jdbc-9.0.62.jar;targets/deser_java/jndi_libs/derby-10.15.2.0.jar;targets/deser_java/jndi_libs/mvel2-2.5.2.Final.jar;"
        "targets/deser_java/jndi_libs/slf4j-api-2.0.9.jar;targets/deser_java/jndi_libs/slf4j-simple-2.0.9.jar;"
        "targets/deser_java/commons-collections-3.2.2.jar;targets/deser_java/commons-collections4-4.4.jar;"
        "targets/deser_java/spring-beans-5.3.31.jar;targets/deser_java/commons-beanutils-1.9.4.jar;targets/deser_java/commons-logging-1.3.4.jar;"
        "targets/deser_java/gson-2.11.0.jar;targets/deser_java JndiTarget --persistent",
    # ── JDBC connection-level targets (direct DriverManager + pool lifecycle) ──
    # Uses same jndi_libs/ JARs: JDBC drivers + connection pools + Spring (for PG socketFactory RCE)
    "java -cp targets/deser_java JdbcTarget --classpath full":
        "java -Xmx256m -Xms64m --add-opens java.base/java.lang=ALL-UNNAMED "
        "-cp "
        "targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/hsqldb.jar;"
        "targets/deser_java/jndi_libs/postgresql-42.7.1.jar;targets/deser_java/jndi_libs/mysql-connector-j-8.2.0.jar;"
        "targets/deser_java/jndi_libs/hikaricp.jar;targets/deser_java/jndi_libs/commons-dbcp2.jar;targets/deser_java/jndi_libs/commons-pool2.jar;"
        "targets/deser_java/jndi_libs/c3p0-0.9.5.5.jar;targets/deser_java/jndi_libs/mchange-commons-java-0.2.20.jar;"
        "targets/deser_java/jndi_libs/druid.jar;targets/deser_java/jndi_libs/tomcat-jdbc-9.0.62.jar;"
        "targets/deser_java/jndi_libs/derby-10.15.2.0.jar;"
        "targets/deser_java/jndi_libs/groovy.jar;targets/deser_java/jndi_libs/bsh.jar;targets/deser_java/jndi_libs/snakeyaml.jar;"
        "targets/deser_java/jndi_libs/spring-context-5.3.31.jar;targets/deser_java/jndi_libs/spring-core-5.3.31.jar;"
        "targets/deser_java/jndi_libs/spring-beans-5.3.31.jar;targets/deser_java/jndi_libs/spring-expression-5.3.31.jar;"
        "targets/deser_java/jndi_libs/spring-jcl-5.3.31.jar;"
        "targets/deser_java/jndi_libs/slf4j-api-2.0.9.jar;targets/deser_java/jndi_libs/slf4j-simple-2.0.9.jar;"
        # pyn3rd additions: SQLite, MySQL 5.1 FabricDriver, ModeShape JCR
        "targets/deser_java/jndi_libs/sqlite-jdbc-3.45.1.0.jar;"
        "targets/deser_java/jndi_libs/mysql-connector-java-5.1.49.jar;"
        "targets/deser_java/jndi_libs/modeshape-jdbc-local-5.4.1.Final.jar;"
        # Additional drivers: MariaDB, SQL Server, Oracle
        "targets/deser_java/jndi_libs/mariadb-java-client-3.3.2.jar;"
        "targets/deser_java/jndi_libs/mssql-jdbc-12.4.2.jar;"
        "targets/deser_java/jndi_libs/ojdbc11-23.3.0.jar;"
        "targets/deser_java/gson-2.11.0.jar;targets/deser_java JdbcTarget --persistent",
    # JDBC with embedded drivers only (H2, HSQLDB, Derby — no network needed)
    "java -cp targets/deser_java JdbcTarget --classpath embedded":
        "java -Xmx256m -Xms64m --add-opens java.base/java.lang=ALL-UNNAMED "
        "-cp "
        "targets/deser_java/jndi_libs/h2.jar;targets/deser_java/jndi_libs/hsqldb.jar;"
        "targets/deser_java/jndi_libs/derby-10.15.2.0.jar;"
        "targets/deser_java/jndi_libs/hikaricp.jar;targets/deser_java/jndi_libs/commons-dbcp2.jar;targets/deser_java/jndi_libs/commons-pool2.jar;"
        "targets/deser_java/jndi_libs/c3p0-0.9.5.5.jar;targets/deser_java/jndi_libs/mchange-commons-java-0.2.20.jar;"
        "targets/deser_java/jndi_libs/druid.jar;targets/deser_java/jndi_libs/tomcat-jdbc-9.0.62.jar;"
        "targets/deser_java/jndi_libs/slf4j-api-2.0.9.jar;targets/deser_java/jndi_libs/slf4j-simple-2.0.9.jar;"
        "targets/deser_java/gson-2.11.0.jar;targets/deser_java JdbcTarget --persistent",
}


def _to_persistent_cmd(cmd: str, target_coverage: bool = False, lines_only: bool = False) -> str | None:
    """Convert a subprocess target command to a persistent wrapper command.

    Returns None if no persistent mapping exists (caller should fall back
    to ProcessTarget).

    Args:
        target_coverage: If True, append --coverage to Node.js wrapper commands
            to enable V8 function-level coverage collection.

    Example:
        "node targets/sanitizer_dompurify.js {input}"
        -> "node targets/persistent_wrapper.js targets/sanitizer_dompurify_module.js"
        "python targets/url_python_urllib.py {input}"
        -> "python targets/persistent_wrapper.py targets/url_python_urllib_module.py"
        "java -cp targets/url_java_uri UrlJavaUri {input}"
        -> "java -cp targets/url_java_uri UrlJavaUri --persistent"
    """
    # Check native persistent mode first (e.g., Java targets with --persistent flag)
    base_cmd = cmd.replace(" {input}", "").strip()
    # If the command already uses persistent_wrapper or --persistent, use as-is
    if "persistent_wrapper" in base_cmd:
        if base_cmd.startswith("python "):
            base_cmd = f"{sys.executable} {base_cmd[7:]}"
        return base_cmd
    if "--persistent" in base_cmd and base_cmd not in _NATIVE_PERSISTENT_MAP:
        return base_cmd
    if base_cmd in _NATIVE_PERSISTENT_MAP:
        result = _NATIVE_PERSISTENT_MAP[base_cmd]
        # Windows cmd.exe needs backslashes for relative executable paths,
        # but Java handles forward slashes fine and backslashes break -cp globs.
        if sys.platform == "win32" and not result.startswith("java "):
            result = result.replace("/", "\\")
        return result

    for script, (wrapper, module) in _PERSISTENT_MODULE_MAP.items():
        if script in cmd:
            result = f"{wrapper} {module}"
            # Append coverage flag for V8 (Node.js) / settrace (Python)
            if (target_coverage or lines_only) and (
                "persistent_wrapper.js" in wrapper
                or "persistent_wrapper.py" in wrapper
            ):
                result += " --coverage-lines-only" if lines_only else " --coverage"
            # Replace bare "python " with sys.executable to ensure the venv
            # Python is used (subprocess.Popen doesn't activate the venv).
            if result.startswith("python "):
                result = f"{sys.executable} {result[7:]}"
            return result
    # No mapping found — caller should fall back to ProcessTarget
    print(f"Warning: no persistent module mapping for: {cmd}", file=sys.stderr)
    return None


def _persistent_timeout_for_cmd(
    cmd: str,
    grammar: str,
    oracle_names: set[str],
    *,
    is_reference: bool = False,
) -> float:
    """Choose a persistent target timeout tuned to the target family."""
    # Docker bridge: each request = docker exec + JVM startup (~1-2s)
    if cmd.startswith("docker "):
        return 15.0

    is_java = "java " in cmd or "java.exe " in cmd
    if not is_java:
        return 2.0

    low_cmd = cmd.lower()
    is_jndi = (
        grammar == "jndi"
        or "jnditarget" in low_cmd
        or "jndi" in oracle_names
    )
    if is_jndi:
        return 3.0  # JndiTarget resolve timeout is tiered (500-2000ms)
    is_jdbc = (
        grammar == "jdbc"
        or "jdbctarget" in low_cmd
        or "jdbc" in oracle_names
    )
    if is_jdbc:
        return 5.0
    return 5.0 if is_reference else 3.0


def make_registry(
    grammar_dir: Path | None = None, no_builtins: bool = False
) -> GrammarRegistry:
    """Create and populate a grammar registry."""
    registry = GrammarRegistry()

    if not no_builtins:
        registry.load_builtins()

    if grammar_dir:
        registry.load_directory(grammar_dir)

    return registry


def cmd_generate(args: argparse.Namespace) -> int:
    """Handle the 'generate' command."""
    registry = make_registry(args.grammar_dir, args.no_builtins)

    if args.grammar not in registry:
        print(f"Error: Grammar {args.grammar!r} not found.", file=sys.stderr)
        print(f"Available: {', '.join(registry.grammar_names)}", file=sys.stderr)
        return 1

    generator = Generator(
        registry, seed=args.seed, max_depth_override=args.max_depth
    )

    outputs: list[str] = []
    for i in range(args.count):
        try:
            result = generator.generate(args.grammar, args.rule)
            outputs.append(result)
        except GenerationError as e:
            print(f"Error generating #{i + 1}: {e}", file=sys.stderr)
            return 1

    text = args.separator.join(outputs)

    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Wrote {args.count} output(s) to {args.output}", file=sys.stderr)
    else:
        print(text)

    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """Handle the 'list' command."""
    registry = make_registry()

    if not registry.grammar_names:
        print("No grammars loaded.")
        return 0

    for name in registry.grammar_names:
        grammar = registry.get(name)
        if grammar is None:
            continue
        rule_count = len(grammar.rules)
        root = grammar.root or "(none)"
        print(f"  {name}")
        print(f"    Root: <{root}>")
        print(f"    Rules: {rule_count}")
        print(f"    Max depth: {grammar.max_depth}")
        if grammar.imports:
            print(f"    Imports: {', '.join(grammar.imports)}")
        print()

    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Handle the 'validate' command."""
    registry = make_registry(args.grammar_dir)

    errors = registry.validate_all()

    if errors:
        print(f"Found {len(errors)} error(s):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("All grammars valid.")
    return 0


def _build_mutators(names: str, registry: GrammarRegistry,
                     grammar_name: str, rule: str | None,
                     seed: int | None,
                     dict_file: Path | None = None,
                     ucb_table=None,
                     max_assertions: int = 0,
                     campaign_mode: str = "novel") -> list:
    """Instantiate mutators from comma-separated names."""
    from .fuzzer.mutators.grammar_mutator import GrammarMutator
    from .fuzzer.mutators.havoc_mutator import HavocMutator
    from .fuzzer.mutators.token_mutator import TokenMutator
    from .fuzzer.mutators.splice_mutator import SpliceMutator
    from .fuzzer.mutators.dictionary_mutator import DictionaryMutator
    from .fuzzer.mutators.mxss_mutator import MxssMutator
    from .fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator
    from .fuzzer.mutators.xml_havoc_mutator import XmlHavocMutator
    from .fuzzer.mutators.saml_mutator import SamlMutator
    from .fuzzer.mutators.cookie_mutator import CookieMutator
    from .fuzzer.mutators.jwt_mutator import JwtMutator
    from .fuzzer.mutators.oauth_mutator import OAuthMutator
    from .fuzzer.mutators.markdown_mutator import MarkdownMutator
    from .fuzzer.mutators.graphql_mutator import GraphqlMutator
    from .fuzzer.mutators.deser_mutator import DeserMutator
    from .fuzzer.mutators.deser_binary_mutator import DeserBinaryMutator
    from .fuzzer.mutators.jndi_mutator import JndiMutator
    from .fuzzer.mutators.jdbc_mutator import JdbcMutator
    from .fuzzer.mutators.class_pollution_mutator import ClassPollutionMutator
    from .fuzzer.mutators.domclobber_mutator import DomClobberMutator
    from .fuzzer.mutators.apache_confusion_mutator import ApacheConfusionMutator
    from .fuzzer.mutators.sandbox_mutator import SandboxMutator

    MUTATOR_MAP = {
        "grammar": lambda: GrammarMutator(registry, grammar_name, rule, seed=seed, ucb_table=ucb_table),
        "havoc": lambda: HavocMutator(seed=seed),
        "token": lambda: TokenMutator(seed=seed),
        "splice": lambda: SpliceMutator(seed=seed),
        "dictionary": lambda: DictionaryMutator(seed=seed, dict_file=dict_file),
        "mxss": lambda: MxssMutator(seed=seed),
        "structural": lambda: StructuralHavocMutator(seed=seed),
        "xml_havoc": lambda: XmlHavocMutator(seed=seed),
        "saml": lambda: SamlMutator(seed=seed, max_assertions=max_assertions),
        "cookie": lambda: CookieMutator(seed=seed),
        "jwt": lambda: JwtMutator(seed=seed),
        "oauth": lambda: OAuthMutator(seed=seed),
        "markdown": lambda: MarkdownMutator(seed=seed),
        "graphql": lambda: GraphqlMutator(seed=seed),
        "deser": lambda: DeserBinaryMutator(seed=seed),  # structure-aware binary mutator (default)
        "deser_ir": lambda: DeserMutator(seed=seed),    # [DEPRECATED] IR-based, silent FN risk
        "deser_bin": lambda: DeserBinaryMutator(seed=seed),  # alias for deser
        "jndi": lambda: JndiMutator(seed=seed),
        "jdbc": lambda: JdbcMutator(seed=seed),
        "class_pollution": lambda: ClassPollutionMutator(seed=seed),
        "domclobber": lambda: DomClobberMutator(seed=seed),
        "apache_confusion": lambda: ApacheConfusionMutator(seed=seed, campaign_mode=campaign_mode),
        "sandbox": lambda: SandboxMutator(seed=seed),
    }

    mutators = []
    for name in names.split(","):
        name = name.strip()
        if name in MUTATOR_MAP:
            mutators.append(MUTATOR_MAP[name]())
        else:
            print(f"Warning: Unknown mutator {name!r}, skipping.", file=sys.stderr)

    if not mutators:
        mutators.append(HavocMutator(seed=seed))

    return mutators


def _build_scheduler(name: str, seed: int | None):
    """Instantiate a seed scheduler by name."""
    from .fuzzer.schedulers.random_scheduler import RandomSeedScheduler
    from .fuzzer.schedulers.entropic import EntropicScheduler
    from .fuzzer.schedulers.ecofuzz import EcoFuzzScheduler
    from .fuzzer.schedulers.rare_branch import RareBranchScheduler

    SCHEDULER_MAP = {
        "random": lambda: RandomSeedScheduler(seed=seed),
        "entropic": lambda: EntropicScheduler(seed=seed),
        "ecofuzz": lambda: EcoFuzzScheduler(seed=seed),
        "rare-branch": lambda: RareBranchScheduler(seed=seed),
    }

    # MAP-Elites: compose with Entropic as primary.
    if name == "map-elites":
        from .fuzzer.schedulers.map_elites import MapElitesScheduler
        from .fuzzer.schedulers.composite import CompositeScheduler
        return CompositeScheduler(
            primary=EntropicScheduler(seed=seed),
            secondary=MapElitesScheduler(seed=seed),
            p_secondary=0.3,
            seed=seed,
        )

    factory = SCHEDULER_MAP.get(name)
    if factory is None:
        print(f"Warning: Unknown scheduler {name!r}, using entropic.", file=sys.stderr)
        return EntropicScheduler(seed=seed)
    return factory()


def _build_mutator_scheduler(name: str, seed: int | None, **kwargs):
    """Instantiate a mutator scheduler by name."""
    if name == "random":
        weights_str = kwargs.get("weights")
        if weights_str:
            from .fuzzer.engine import _DefaultMutatorScheduler
            weights = [float(w) for w in weights_str.split(",")]
            return _DefaultMutatorScheduler(random.Random(seed), weights=weights)
        return None  # engine uses _DefaultMutatorScheduler

    from .fuzzer.schedulers.mutation_scheduler import MOPTScheduler, DARWINScheduler
    from .fuzzer.schedulers.linucb_scheduler import LinUCBScheduler

    MUTATOR_SCHEDULER_MAP = {
        "mopt": lambda: MOPTScheduler(seed=seed),
        "darwin": lambda: DARWINScheduler(seed=seed),
        "linucb": lambda: LinUCBScheduler(
            alpha=kwargs.get("alpha", 1.0), seed=seed,
        ),
    }

    factory = MUTATOR_SCHEDULER_MAP.get(name)
    if factory is None:
        print(f"Warning: Unknown mutator scheduler {name!r}, using random.", file=sys.stderr)
        return None
    return factory()


def _make_confused_deputy():
    from .fuzzer.oracles.confused_deputy_strategy import ConfusedDeputyStrategy
    return ConfusedDeputyStrategy()


def _make_cve_scanner():
    from .fuzzer.oracles.cve_detector_strategy import CVEScannerStrategy
    return CVEScannerStrategy()


def _build_oracles(names: str) -> list:
    """Instantiate oracles from comma-separated names."""
    from .fuzzer.oracles.crash_oracle import CrashOracle
    from .fuzzer.oracles.response_oracle import ResponseOracle
    from .fuzzer.oracles.sanitizer_oracle import SanitizerOracle
    from .fuzzer.oracles.xss_oracle import XssOracle
    from .fuzzer.oracles.mxss_oracle import MxssOracle
    from .fuzzer.oracles.ssrf_oracle import SsrfOracle
    from .fuzzer.oracles.saml_oracle import SamlOracle, SamlSigTrueOracle, SamlValidatorOracle
    from .fuzzer.oracles.cookie_oracle import CookieOracle
    from .fuzzer.oracles.jwt_oracle import JwtOracle
    from .fuzzer.oracles.oauth_oracle import OAuthOracle
    from .fuzzer.oracles.graphql_oracle import GraphqlOracle
    from .fuzzer.oracles.deser_oracle import DeserOracle
    from .fuzzer.oracles.jndi_oracle import JndiOracle
    from .fuzzer.oracles.jdbc_oracle import JdbcOracle
    from .fuzzer.oracles.class_pollution_oracle import ClassPollutionOracle
    from .fuzzer.oracles.domclobber_oracle import DomClobberOracle

    # Sandbox oracle is a placeholder — real strategy injected via DiffOracle
    ORACLE_MAP = {
        "crash": lambda: CrashOracle(),
        "response": lambda: ResponseOracle(),
        "sanitizer": lambda: SanitizerOracle(),
        "xss": lambda: XssOracle(),
        "mxss": lambda: MxssOracle(),
        "ssrf": lambda: SsrfOracle(),
        "saml": lambda: SamlOracle(),
        "saml_sigtrue": lambda: SamlSigTrueOracle(),
        "saml_validator": lambda: SamlValidatorOracle(),
        "cookie": lambda: CookieOracle(),
        "jwt": lambda: JwtOracle(),
        "oauth": lambda: OAuthOracle(),
        "graphql": lambda: GraphqlOracle(),
        "graphql_exec": lambda: GraphqlOracle(),  # reuse single-target oracle; exec strategies via DiffOracle
        "sanitizer_diff": lambda: None,  # placeholder — strategies injected via DiffOracle
        "markdown": lambda: None,  # placeholder — strategies injected via DiffOracle
        "deser": lambda: DeserOracle(),
        "jndi": lambda: JndiOracle(),
        "jdbc": lambda: JdbcOracle(),
        "class_pollution": lambda: ClassPollutionOracle(),
        "domclobber": lambda: DomClobberOracle(),
        "domclobber_diff": lambda: None,  # placeholder — strategies injected via DiffOracle
        "apache_confusion": lambda: None,  # placeholder — strategies injected via DiffOracle
        "sandbox": lambda: None,  # placeholder — SandboxEscapeDiffStrategy via DiffOracle
        "confused_deputy": lambda: _make_confused_deputy(),
        "cve_scanner": lambda: _make_cve_scanner(),
    }

    oracles = []
    for name in names.split(","):
        name = name.strip()
        if name in ORACLE_MAP:
            o = ORACLE_MAP[name]()
            if o is not None:
                oracles.append(o)
        else:
            print(f"Warning: Unknown oracle {name!r}, skipping.", file=sys.stderr)

    if not oracles:
        oracles.append(CrashOracle())

    return oracles


_CAMPAIGN_PRESETS = {
    "cve_detect": {
        "oracle": "cve_scanner",
        "mutators": "apache_confusion,grammar,havoc",
        "seeds_dir": "targets/apache_confusion_seeds_cve",
        "grammar": "apache_confusion",
        "campaign_mode": "cve_detect",
    },
    "patch_bypass": {
        "oracle": "cve_scanner",
        "mutators": "apache_confusion,havoc",
        "seeds_dir": "targets/apache_confusion_seeds_cve/patch_bypass",
        "grammar": "apache_confusion",
        "campaign_mode": "patch_bypass",
    },
    "novel": {
        "oracle": "apache_confusion",
        "mutators": "apache_confusion,grammar,havoc",
        "seeds_dir": "targets/apache_confusion_seeds",
        "grammar": "apache_confusion",
        "campaign_mode": "novel",
    },
}


def cmd_fuzz(args: argparse.Namespace) -> int:
    """Handle the 'fuzz' command."""
    from .fuzzer.engine import FuzzEngine
    from .fuzzer.grammar_source import GrammarInputSource
    from .fuzzer.targets.process_target import ProcessTarget
    from .fuzzer.coverage.response_coverage import ResponseCoverageCollector
    from .fuzzer.coverage.diff_coverage import DiffCoverageCollector
    from .fuzzer.oracles.diff_oracle import DiffOracle

    # Apply campaign preset (overrides defaults, explicit flags still win)
    campaign = getattr(args, "campaign", None)
    _campaign_mode = "novel"
    if campaign and campaign in _CAMPAIGN_PRESETS:
        preset = _CAMPAIGN_PRESETS[campaign]
        _campaign_mode = preset.get("campaign_mode", "novel")
        # Only apply preset values if user didn't explicitly set them
        if args.oracle == "crash,sanitizer":  # default value → apply preset
            args.oracle = preset["oracle"]
        if args.mutators == "grammar,havoc":  # default value → apply preset
            args.mutators = preset["mutators"]
        if args.seeds_dir is None:
            args.seeds_dir = Path(preset["seeds_dir"])
        if args.grammar == "html":  # default grammar → apply preset
            args.grammar = preset.get("grammar", args.grammar)

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    # Build grammar registry
    registry = make_registry(
        getattr(args, "grammar_dir", None),
        getattr(args, "no_builtins", False),
    )

    if args.grammar not in registry:
        print(f"Error: Grammar {args.grammar!r} not found.", file=sys.stderr)
        print(f"Available: {', '.join(registry.grammar_names)}", file=sys.stderr)
        return 1

    # Target — supports mixed mode: PersistentTarget for mapped targets,
    # ProcessTarget fallback for unmapped ones.
    # Auto-enable persistent mode if any target has a persistent mapping.
    requested_oracle_names = {n.strip() for n in args.oracle.split(",") if n.strip()}

    use_persistent = getattr(args, "persistent", False)
    # Whitebox concolic: use --coverage-lines-only (no bitmap, just _covered_lines in JSON)
    # This avoids the 22x overhead of bitmap I/O while still feeding RealConcolicEngine.
    _whitebox_lines_only = (
        getattr(args, "concolic", False)
        and getattr(args, "concolic_mode", "") == "whitebox"
    )
    use_target_cov = getattr(args, "target_coverage", False)
    if not use_persistent:
        all_cmds = [args.target_cmd] + getattr(args, "diff_cmd", [])
        if any(_to_persistent_cmd(c) is not None for c in all_cmds):
            use_persistent = True
            print("Auto-enabled persistent mode (mapping found)", file=sys.stderr)
    # Java targets need longer timeout (JVM cold start, JDBC init, etc.)
    _persistent_timeout = _persistent_timeout_for_cmd(
        args.target_cmd,
        args.grammar,
        requested_oracle_names,
    )

    if use_persistent:
        from .fuzzer.targets.persistent_target import PersistentTarget
        pcmd = _to_persistent_cmd(args.target_cmd, target_coverage=use_target_cov, lines_only=_whitebox_lines_only)
        if pcmd is not None:
            target = PersistentTarget(pcmd, timeout_seconds=_persistent_timeout)
        else:
            target = ProcessTarget(args.target_cmd)
    else:
        target = ProcessTarget(args.target_cmd)
    target.original_cmd = args.target_cmd  # for library name extraction

    # Reference targets for differential fuzzing
    diff_cmds: list[str] = getattr(args, "diff_cmd", [])
    if use_persistent:
        from .fuzzer.targets.persistent_target import PersistentTarget
        reference_targets = []
        for cmd in diff_cmds:
            _ref_timeout = _persistent_timeout_for_cmd(
                cmd,
                args.grammar,
                requested_oracle_names,
                is_reference=True,
            )
            pcmd = _to_persistent_cmd(cmd, target_coverage=use_target_cov, lines_only=_whitebox_lines_only)
            if pcmd is not None:
                t = PersistentTarget(pcmd, timeout_seconds=_ref_timeout)
            else:
                t = ProcessTarget(cmd)
            t.original_cmd = cmd  # for library name extraction
            reference_targets.append(t)
    else:
        reference_targets = []
        for cmd in diff_cmds:
            t = ProcessTarget(cmd)
            t.original_cmd = cmd
            reference_targets.append(t)
    is_diff_mode = len(reference_targets) > 0

    # Warn about synthetic/test targets in differential comparison.
    # These are NOT real libraries and will generate false positives.
    _SYNTHETIC_PATTERNS = ("_strict.", "_permissive.", "_pac4j_like.", "_manual.")
    all_cmds = [args.target_cmd] + diff_cmds
    synthetic_found = [
        cmd for cmd in all_cmds
        if any(pat in cmd for pat in _SYNTHETIC_PATTERNS)
    ]
    if synthetic_found and is_diff_mode:
        print(
            f"\n  ⚠ WARNING: {len(synthetic_found)} synthetic target(s) detected "
            f"in differential comparison.\n"
            f"  Findings involving these targets are likely FALSE POSITIVES:\n"
            + "".join(f"    → {cmd}\n" for cmd in synthetic_found)
            + "  Consider removing them from --diff-cmd for production runs.\n",
            file=sys.stderr,
        )

    # MCTS UCB table (shared between input source and grammar mutator)
    ucb_table = None
    if getattr(args, "mcts", False):
        from .fuzzer.mcts import UCBTable
        ucb_table = UCBTable(
            exploration_weight=getattr(args, "mcts_exploration", 1.41),
            seed=args.seed,
        )

    # Input source
    input_source = GrammarInputSource(
        registry, args.grammar, args.rule, seed=args.seed,
        ucb_table=ucb_table,
    )

    # Mutators
    mutators = _build_mutators(
        args.mutators, registry, args.grammar, args.rule, args.seed,
        dict_file=getattr(args, "dict_file", None),
        ucb_table=ucb_table,
        max_assertions=getattr(args, "max_assertions", 0),
        campaign_mode=_campaign_mode,
    )

    # Scheduler
    scheduler = _build_scheduler(args.scheduler, args.seed)

    # Mutator scheduler
    mutator_scheduler = _build_mutator_scheduler(
        getattr(args, "mutator_scheduler", "random"),
        args.seed,
        alpha=getattr(args, "linucb_alpha", 1.0),
        weights=getattr(args, "mutator_weights", None),
    )

    # Oracles — auto-add DiffOracle in differential mode
    _DIFF_ONLY_ORACLES = {"sanitizer_diff", "markdown", "domclobber_diff", "sandbox"}
    diff_only_requested = requested_oracle_names & _DIFF_ONLY_ORACLES
    if diff_only_requested and not is_diff_mode:
        names = ", ".join(sorted(diff_only_requested))
        print(
            f"Error: --oracle {names} requires differential mode (--diff-cmd). "
            f"These oracles are placeholders that only work via DiffOracle with reference targets.",
            file=sys.stderr,
        )
        return 1

    oracles = _build_oracles(args.oracle)
    if is_diff_mode:
        # Use domain-specific strategies when specialized oracles are active
        has_xss = any(getattr(o, "name", "") == "xss" for o in oracles)
        has_ssrf = any(getattr(o, "name", "") == "ssrf" for o in oracles)
        has_saml = any(getattr(o, "name", "") == "saml" for o in oracles)
        has_saml_sigtrue = any(getattr(o, "name", "") == "saml_sigtrue" for o in oracles)
        has_saml_validator = any(getattr(o, "name", "") == "saml_validator" for o in oracles)
        has_cookie = any(getattr(o, "name", "") == "cookie" for o in oracles)
        has_jwt = any(getattr(o, "name", "") == "jwt" for o in oracles)
        has_oauth = any(getattr(o, "name", "") == "oauth" for o in oracles)
        has_graphql = any(getattr(o, "name", "") == "graphql" for o in oracles)
        has_deser = any(getattr(o, "name", "") == "deser" for o in oracles)
        has_jndi = any(getattr(o, "name", "") == "jndi" for o in oracles)
        has_jdbc = any(getattr(o, "name", "") == "jdbc" for o in oracles)
        has_class_pollution = any(getattr(o, "name", "") == "class_pollution" for o in oracles)
        has_domclobber = any(getattr(o, "name", "") == "domclobber" for o in oracles)
        has_apache_confusion = "apache_confusion" in [n.strip() for n in args.oracle.split(",")]
        oracle_names = [n.strip() for n in args.oracle.split(",")]
        has_graphql_exec = "graphql_exec" in oracle_names
        has_markdown = "markdown" in oracle_names
        has_sanitizer_diff = "sanitizer_diff" in oracle_names
        has_domclobber_diff = "domclobber_diff" in oracle_names
        has_sandbox = "sandbox" in oracle_names
        if has_sandbox:
            from .fuzzer.oracles.sandbox_diff_strategy import SandboxEscapeDiffStrategy
            strategies = [SandboxEscapeDiffStrategy()]
        elif has_apache_confusion:
            from .fuzzer.oracles.apache_confusion_diff_strategy import get_apache_confusion_strategies
            strategies = get_apache_confusion_strategies()
        elif has_markdown:
            from .fuzzer.oracles.markdown_diff_strategy import get_markdown_strategies
            strategies = get_markdown_strategies()
        elif has_sanitizer_diff:
            from .fuzzer.oracles.sanitizer_diff_strategy import get_sanitizer_strategies
            strategies = get_sanitizer_strategies()
        elif has_saml_validator:
            from .fuzzer.oracles.saml_validator_diff_strategy import get_saml_validator_strategies
            strategies = get_saml_validator_strategies()
        elif has_saml_sigtrue:
            from .fuzzer.oracles.saml_diff_strategy import get_saml_sigtrue_strategies
            strategies = get_saml_sigtrue_strategies(
                target_count=1 + len(reference_targets),
            )
        elif has_saml:
            from .fuzzer.oracles.saml_diff_strategy import get_saml_strategies
            strategies = get_saml_strategies(
                target_count=1 + len(reference_targets),
            )
        elif has_cookie:
            from .fuzzer.oracles.cookie_diff_strategy import get_cookie_strategies
            strategies = get_cookie_strategies()
        elif has_jwt:
            from .fuzzer.oracles.jwt_diff_strategy import get_jwt_strategies
            strategies = get_jwt_strategies()
        elif has_oauth:
            from .fuzzer.oracles.oauth_diff_strategy import get_oauth_strategies
            strategies = get_oauth_strategies()
        elif has_graphql_exec:
            from .fuzzer.oracles.graphql_exec_diff_strategy import get_graphql_exec_strategies
            strategies = get_graphql_exec_strategies()
        elif has_graphql:
            from .fuzzer.oracles.graphql_diff_strategy import get_graphql_strategies
            strategies = get_graphql_strategies()
        elif has_jdbc:
            from .fuzzer.oracles.jdbc_diff_strategy import get_jdbc_strategies
            strategies = get_jdbc_strategies()
        elif has_jndi:
            from .fuzzer.oracles.jndi_diff_strategy import get_jndi_strategies
            strategies = get_jndi_strategies()
        elif has_deser:
            from .fuzzer.oracles.deser_diff_strategy import get_deser_strategies
            strategies = get_deser_strategies()
        elif has_domclobber_diff:
            from .fuzzer.oracles.domclobber_diff_strategy import get_domclobber_strategies
            strategies = get_domclobber_strategies()
        elif has_domclobber:
            from .fuzzer.oracles.domclobber_diff_strategy import get_domclobber_strategies
            strategies = get_domclobber_strategies()
        elif has_class_pollution:
            from .fuzzer.oracles.class_pollution_diff_strategy import get_class_pollution_strategies
            strategies = get_class_pollution_strategies()
        elif has_ssrf:
            from .fuzzer.oracles.ssrf_oracle import get_ssrf_strategies
            strategies = get_ssrf_strategies()
        elif has_xss:
            from .fuzzer.oracles.diff_oracle import get_xss_strategies
            strategies = get_xss_strategies()
        else:
            strategies = None  # use defaults
        oracles.append(DiffOracle(
            reference_targets=reference_targets,
            strategies=strategies,
        ))

    # Coverage — use DiffCoverageCollector in differential mode
    if is_diff_mode:
        if getattr(args, "adaptive_coverage", False):
            from .fuzzer.coverage.adaptive_coverage import (
                AdaptiveDiffCoverage, AdaptiveConfig, RefinementLevel,
            )
            # Sanitizer domain: start at L2 with faster refinement
            # (boolean comparison_keys saturate L1 quickly)
            if has_sanitizer_diff:
                adaptive_config = AdaptiveConfig(
                    initial_level=RefinementLevel.L2_COMPONENT,
                    stagnation_window=5000,
                    check_interval=getattr(args, "adaptive_check_interval", 5000),
                    upper_corpus_pct=getattr(args, "adaptive_upper_pct", 5.0),
                )
            else:
                adaptive_config = AdaptiveConfig(
                    initial_level=RefinementLevel(getattr(args, "adaptive_level", 1)),
                    check_interval=getattr(args, "adaptive_check_interval", 5000),
                    upper_corpus_pct=getattr(args, "adaptive_upper_pct", 5.0),
                )
            coverage = AdaptiveDiffCoverage(
                reference_targets=reference_targets,
                config=adaptive_config,
            )
        else:
            coverage = DiffCoverageCollector(reference_targets=reference_targets)
    else:
        coverage = ResponseCoverageCollector()

    # Danger-weighted seed scheduling
    from .fuzzer.schedulers.danger_booster import DangerBooster
    danger_booster = DangerBooster() if getattr(args, "danger_boost", True) else None

    # Static-analysis guidance (optional)
    guidance_hooks = None
    if getattr(args, "guidance", None):
        from .guidance.integration import build_guidance_engine, GuidanceFuzzHooks
        guidance_engine = build_guidance_engine(
            protocol=args.guidance,
            profile_dir=getattr(args, "guidance_profiles", None),
        )
        if guidance_engine:
            guidance_hooks = GuidanceFuzzHooks(guidance_engine)
            print(f"  Guidance: {args.guidance} — "
                  f"{guidance_engine.metrics.gaps_identified} gaps, "
                  f"{guidance_engine.metrics.targeted_seeds_generated} seeds",
                  file=sys.stderr)
        else:
            print(f"  Guidance: {args.guidance} — no libraries found, disabled",
                  file=sys.stderr)

    # Concolic constraint extraction + solving (optional, domain-agnostic)
    concolic_coordinator = None
    if getattr(args, "concolic", False):
        concolic_mode = getattr(args, "concolic_mode", "hybrid")
        budget = getattr(args, "concolic_budget", 0.10)

        # Auto-detect domain plugin from oracle/grammar
        domain_plugin = None
        from .fuzzer.concolic.plugins.registry import get_plugin
        oracle_name = getattr(args, "oracle", None)
        grammar_name = getattr(args, "grammar", None)
        domain_plugin = get_plugin(oracle=oracle_name, grammar=grammar_name)
        plugin_name = type(domain_plugin).__name__ if domain_plugin else "default(SAML)"

        if concolic_mode == "expert":
            from .fuzzer.concolic.coordinator import ConcolicCoordinator
            from .fuzzer.concolic.constraint_extractor import ConstraintExtractor
            from .fuzzer.concolic.solver import ConstraintSolver
            concolic_coordinator = ConcolicCoordinator(
                extractor=ConstraintExtractor(),
                solver=ConstraintSolver(seed=args.seed),
                budget_pct=budget,
            )
        elif concolic_mode == "learned":
            from .fuzzer.concolic.property_guided import PropertyGuidedCoordinator
            concolic_coordinator = PropertyGuidedCoordinator(
                budget_pct=budget,
                seed=args.seed,
            )
        elif concolic_mode == "whitebox":
            from .fuzzer.concolic.hybrid_coordinator import HybridCoordinator
            concolic_coordinator = HybridCoordinator(
                budget_pct=budget,
                seed=args.seed,
                use_expert=False,
                use_coverage=True,
                domain_plugin=domain_plugin,
            )
        else:  # hybrid (default)
            from .fuzzer.concolic.hybrid_coordinator import HybridCoordinator
            concolic_coordinator = HybridCoordinator(
                budget_pct=budget,
                seed=args.seed,
                domain_plugin=domain_plugin,
            )
        print(f"  Concolic: enabled (mode={concolic_mode}, plugin={plugin_name}, budget={budget:.0%})",
              file=sys.stderr)

    # Build and run engine
    engine = FuzzEngine(
        target=target,
        input_source=input_source,
        mutators=mutators,
        oracles=oracles,
        coverage=coverage,
        seed_scheduler=scheduler,
        mutator_scheduler=mutator_scheduler,
        max_iterations=args.count,
        max_time_seconds=args.timeout,
        initial_seed_count=args.initial_seeds,
        seed=args.seed,
        output_dir=args.output_dir,
        reference_targets=reference_targets,
        seeds_dir=getattr(args, "seeds_dir", None),
        import_findings=getattr(args, "import_findings", None),
        resume=getattr(args, "resume", False),
        checkpoint_interval=getattr(args, "checkpoint_interval", 60.0),
        danger_booster=danger_booster,
        verify_browser=getattr(args, "verify_browser", False),
        max_corpus_size=getattr(args, "max_corpus_size", 5000),
        target_coverage=getattr(args, "target_coverage", False),
        guidance_hooks=guidance_hooks,
        concolic=concolic_coordinator,
    )

    print(f"Starting fuzzer: grammar={args.grammar}, target={args.target_cmd}",
          file=sys.stderr)
    if is_diff_mode:
        print(f"  Mode: DIFFERENTIAL ({len(reference_targets)} reference target(s))",
              file=sys.stderr)
        for i, cmd in enumerate(diff_cmds):
            print(f"    ref[{i}]: {cmd}", file=sys.stderr)
    print(f"  Mutators: {', '.join(m.name for m in mutators)}", file=sys.stderr)
    print(f"  Scheduler: {args.scheduler}", file=sys.stderr)
    print(f"  Mutator scheduler: {getattr(args, 'mutator_scheduler', 'random')}", file=sys.stderr)
    print(f"  Oracles: {', '.join(o.name for o in oracles)}", file=sys.stderr)
    if danger_booster:
        print(f"  Danger boost: enabled", file=sys.stderr)
    if getattr(args, "mcts", False):
        expl = getattr(args, "mcts_exploration", 1.41)
        print(f"  MCTS: enabled (c={expl})", file=sys.stderr)
    if getattr(args, "target_coverage", False):
        print(f"  Target coverage: enabled (V8/settrace)", file=sys.stderr)
    if getattr(args, "adaptive_coverage", False):
        lvl = getattr(args, "adaptive_level", 1)
        print(f"  Adaptive coverage: L{lvl} (CEGAR)", file=sys.stderr)
    print(f"  Initial seeds: {args.initial_seeds}", file=sys.stderr)
    if guidance_hooks and guidance_hooks.active:
        print(f"  Guidance: {args.guidance} (static analysis → mutation bias)", file=sys.stderr)
    if getattr(args, "seeds_dir", None):
        print(f"  Seeds dir: {args.seeds_dir}", file=sys.stderr)
    if getattr(args, "import_findings", None):
        print(f"  Import findings: {len(args.import_findings)} session dir(s)", file=sys.stderr)
    if getattr(args, "resume", False):
        print(f"  Resume: enabled (checkpoint interval: {getattr(args, 'checkpoint_interval', 60)}s)", file=sys.stderr)
    if args.count:
        print(f"  Max iterations: {args.count}", file=sys.stderr)
    if args.timeout:
        print(f"  Max time: {args.timeout}s", file=sys.stderr)
    print(file=sys.stderr)

    stats = engine.run()

    # Print deser compile/deserialize rates if available
    if hasattr(engine, '_deser_total') and engine._deser_total > 0:
        t = engine._deser_total
        c = engine._deser_compiled
        d = engine._deser_deserialized
        print(
            f"\n  Deser pipeline: {c}/{t} compiled ({c*100//t}%), "
            f"{d}/{t} deserialized ({d*100//t}%)",
            file=sys.stderr,
        )

    # Print guidance summary if active
    if guidance_hooks and guidance_hooks.active:
        report_section = guidance_hooks.get_report_section()
        if report_section:
            print(f"\n  Guidance summary:", file=sys.stderr)
            print(f"    Gaps: {report_section.get('total_gaps', 0)} "
                  f"(active: {report_section.get('active_gaps', 0)})",
                  file=sys.stderr)
            metrics = report_section.get("metrics", {})
            rt = metrics.get("runtime", {})
            print(f"    Findings attributed: {rt.get('findings_attributed', 0)}"
                  f"/{rt.get('findings_total', 0)}",
                  file=sys.stderr)
            if rt.get("focus_rotations", 0):
                print(f"    Focus rotations: {rt['focus_rotations']}", file=sys.stderr)

    # Print final report
    print(stats.report(), file=sys.stderr)
    return 0


def cmd_verify_browser(args: argparse.Namespace) -> int:
    """Run the async browser verifier."""
    from .fuzzer.browser_verifier import BrowserVerifier
    from .fuzzer.verification_queue import create_verification_queue

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    output_dir: Path = args.output_dir
    if not output_dir.exists():
        print(f"Output directory does not exist: {output_dir}", file=sys.stderr)
        return 1

    queue = create_verification_queue(output_dir)
    verifier = BrowserVerifier(
        queue=queue,
        output_dir=output_dir,
        sanitizer=args.sanitizer,
    )

    print(f"Starting browser verifier: sanitizer={args.sanitizer}, output={output_dir}",
          file=sys.stderr)
    print(f"  Queue dir: {output_dir / 'verify_queue'}", file=sys.stderr)
    print(f"  Watching for interesting inputs from JSDOM fuzzer...", file=sys.stderr)
    print(file=sys.stderr)

    verifier.run()
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "generate": cmd_generate,
        "list": cmd_list,
        "validate": cmd_validate,
        "fuzz": cmd_fuzz,
        "verify-browser": cmd_verify_browser,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
