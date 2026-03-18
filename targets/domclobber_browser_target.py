"""Playwright-based batch evaluator for DOM Clobbering primitive discovery.

Evaluates HTML snippets across Chromium/Firefox/WebKit to find cross-browser
differences in Named Property Visibility behavior.

Two operation modes:
1. Standalone: systematic enumeration or fuzz-mode batch evaluation
2. Engine-integrated: Target protocol adapter with asyncio bridge
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Probe JS — embedded for reliability (mirrors domclobber_browser_probe.js)
# ---------------------------------------------------------------------------

_PROBE_JS_PATH = Path(__file__).parent / "domclobber_browser_probe.js"

_PROBE_JS: str | None = None


def _load_probe_js() -> str:
    """Load probe JS from companion file, cache in module global."""
    global _PROBE_JS
    if _PROBE_JS is not None:
        return _PROBE_JS
    if _PROBE_JS_PATH.exists():
        _PROBE_JS = _PROBE_JS_PATH.read_text(encoding="utf-8")
        logger.info("Loaded probe JS from %s (%d bytes)", _PROBE_JS_PATH, len(_PROBE_JS))
    else:
        raise FileNotFoundError(
            f"Probe JS not found at {_PROBE_JS_PATH}. "
            "Ensure domclobber_browser_probe.js is next to this file."
        )
    return _PROBE_JS


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SnippetSpec:
    """One HTML snippet to evaluate for DOM clobbering behavior."""
    html: str
    target_props: list[str]   # property names to probe (e.g. ['x', 'y'])
    snippet_id: int = 0


@dataclass
class Divergence:
    """A single cross-browser divergence on one property aspect."""
    property: str
    aspect: str               # doc_type, doc_constructor, chain.href, etc.
    chromium: Any = None
    firefox: Any = None
    webkit: Any = None


@dataclass
class SnippetResult:
    """Evaluation result for one snippet."""
    snippet_id: int
    divergences: list[Divergence] = field(default_factory=list)
    browsers: dict[str, dict] = field(default_factory=dict)  # full probe per browser
    error: str | None = None


# ---------------------------------------------------------------------------
# Batch Evaluator
# ---------------------------------------------------------------------------

class DomClobberBatchEvaluator:
    """Manages 3 browser instances and evaluates HTML snippet batches."""

    BATCH_SIZE = 500
    BROWSER_NAMES = ("chromium", "firefox", "webkit")
    PAGE_RECYCLE_EVERY = 50    # new page every N batches
    BROWSER_RECYCLE_EVERY = 500  # full browser restart every N batches
    EVAL_TIMEOUT = 15          # seconds per batch evaluation

    def __init__(self) -> None:
        self._pw = None          # Playwright instance
        self._browsers: dict[str, Any] = {}   # name -> Browser
        self._pages: dict[str, Any] = {}      # name -> Page
        self._batch_count: dict[str, int] = {n: 0 for n in self.BROWSER_NAMES}
        self._probe_js: str = ""

    # ── lifecycle ──────────────────────────────────────────────────

    async def setup(self) -> None:
        """Launch 3 browsers via Playwright."""
        from playwright.async_api import async_playwright  # lazy import

        self._probe_js = _load_probe_js()
        self._pw = await async_playwright().start()

        for name in self.BROWSER_NAMES:
            await self._launch_browser(name)
            await self._new_page(name)
            logger.info("Browser %s ready", name)

    async def teardown(self) -> None:
        """Close all browsers and stop Playwright."""
        for name in list(self._browsers):
            try:
                browser = self._browsers.pop(name, None)
                if browser:
                    await browser.close()
            except Exception as exc:
                logger.warning("Error closing %s: %s", name, exc)
            self._pages.pop(name, None)

        if self._pw:
            await self._pw.stop()
            self._pw = None
        logger.info("All browsers shut down")

    async def _launch_browser(self, name: str) -> None:
        """Launch a single browser by name."""
        launcher = getattr(self._pw, name)
        self._browsers[name] = await launcher.launch(headless=True)
        self._batch_count[name] = 0
        logger.debug("Launched %s (pid=%s)", name, getattr(self._browsers[name], "process", "?"))

    async def _new_page(self, name: str) -> None:
        """Create a fresh page for a browser."""
        old = self._pages.pop(name, None)
        if old:
            try:
                await old.close()
            except Exception:
                pass
        browser = self._browsers[name]
        self._pages[name] = await browser.new_page()

    async def _recover_browser(self, name: str) -> None:
        """Restart a crashed browser."""
        logger.warning("Recovering browser %s", name)
        old_browser = self._browsers.pop(name, None)
        self._pages.pop(name, None)
        if old_browser:
            try:
                await old_browser.close()
            except Exception:
                pass
        await self._launch_browser(name)
        await self._new_page(name)
        logger.info("Browser %s recovered", name)

    async def _maybe_recycle(self, name: str) -> None:
        """Recycle page or browser based on batch count."""
        count = self._batch_count[name]
        if count > 0 and count % self.BROWSER_RECYCLE_EVERY == 0:
            logger.info("Recycling browser %s after %d batches", name, count)
            await self._recover_browser(name)
        elif count > 0 and count % self.PAGE_RECYCLE_EVERY == 0:
            logger.debug("Recycling page for %s after %d batches", name, count)
            await self._new_page(name)

    # ── batch evaluation ──────────────────────────────────────────

    async def evaluate_batch(
        self, snippets: list[SnippetSpec]
    ) -> list[SnippetResult]:
        """Evaluate a batch of snippets across all 3 browsers."""
        if not snippets:
            return []

        batch_html = self._build_batch_html(snippets)
        all_results: dict[str, list[dict]] = {}

        # Evaluate in all 3 browsers concurrently
        tasks = {
            name: self._evaluate_in_browser(name, batch_html)
            for name in self.BROWSER_NAMES
        }
        gathered = await asyncio.gather(
            *tasks.values(), return_exceptions=True,
        )
        for name, result in zip(tasks.keys(), gathered):
            if isinstance(result, Exception):
                logger.error("Browser %s failed: %s", name, result)
                all_results[name] = [
                    {"id": i, "error": str(result), "probes": {}}
                    for i in range(len(snippets))
                ]
                # Attempt recovery
                try:
                    await self._recover_browser(name)
                except Exception as exc2:
                    logger.error("Recovery of %s failed: %s", name, exc2)
            else:
                all_results[name] = result

        return self._compare_results(snippets, all_results)

    def _build_batch_html(self, snippets: list[SnippetSpec]) -> str:
        """Build HTML page with N srcdoc iframes."""
        parts = [
            "<!DOCTYPE html><html><head><meta charset='utf-8'></head><body>\n",
        ]
        for i, spec in enumerate(snippets):
            escaped_html = html.escape(spec.html, quote=True)
            props_json = html.escape(json.dumps(spec.target_props), quote=True)
            parts.append(
                f'<iframe id="f{i}" srcdoc="{escaped_html}" '
                f'data-props="{props_json}" '
                f'sandbox="allow-same-origin" '
                f'style="display:none"></iframe>\n'
            )
        parts.append("</body></html>")
        return "".join(parts)

    async def _evaluate_in_browser(
        self, browser_name: str, batch_html: str
    ) -> list[dict]:
        """Send batch page to one browser, run probe, return results."""
        await self._maybe_recycle(browser_name)

        page = self._pages.get(browser_name)
        if page is None:
            await self._new_page(browser_name)
            page = self._pages[browser_name]

        try:
            await page.set_content(batch_html, wait_until="load", timeout=self.EVAL_TIMEOUT * 1000)

            # Wait briefly for iframes to finish parsing
            await page.wait_for_timeout(100)

            results = await page.evaluate(self._probe_js)
            self._batch_count[browser_name] += 1
            return results

        except Exception as exc:
            logger.error("Evaluation failed in %s: %s", browser_name, exc)
            # Try recovery and re-raise so gather catches it
            raise

    def _compare_results(
        self,
        snippets: list[SnippetSpec],
        all_results: dict[str, list[dict]],
    ) -> list[SnippetResult]:
        """Compare probe results across 3 browsers, detect divergences."""
        out: list[SnippetResult] = []
        n = len(snippets)

        for i in range(n):
            per_browser: dict[str, dict] = {}
            errors: list[str] = []

            for bname in self.BROWSER_NAMES:
                browser_list = all_results.get(bname, [])
                if i < len(browser_list):
                    per_browser[bname] = browser_list[i]
                    if browser_list[i].get("error"):
                        errors.append(f"{bname}:{browser_list[i]['error']}")
                else:
                    per_browser[bname] = {"id": i, "error": "missing", "probes": {}}
                    errors.append(f"{bname}:missing")

            divergences = self._detect_divergences(per_browser)
            out.append(SnippetResult(
                snippet_id=snippets[i].snippet_id,
                divergences=divergences,
                browsers=per_browser,
                error="; ".join(errors) if errors else None,
            ))

        return out

    def _detect_divergences(
        self, per_browser: dict[str, dict]
    ) -> list[Divergence]:
        """Find all divergent aspects across browsers for one snippet."""
        divergences: list[Divergence] = []

        # Collect all probed property names
        all_props: set[str] = set()
        for bdata in per_browser.values():
            all_props.update(bdata.get("probes", {}).keys())

        for prop in sorted(all_props):
            probes = {
                bname: bdata.get("probes", {}).get(prop, {})
                for bname, bdata in per_browser.items()
            }

            # Top-level scalar aspects
            TOP_ASPECTS = [
                "doc_type", "doc_constructor", "doc_toString",
                "doc_is_collection", "doc_collection_length",
                "win_type", "win_constructor", "win_toString",
                "win_is_collection",
            ]
            for aspect in TOP_ASPECTS:
                vals = {bname: p.get(aspect) for bname, p in probes.items()}
                unique = set(str(v) for v in vals.values())
                if len(unique) > 1:
                    divergences.append(Divergence(
                        property=prop,
                        aspect=aspect,
                        chromium=vals.get("chromium"),
                        firefox=vals.get("firefox"),
                        webkit=vals.get("webkit"),
                    ))

            # Proto chain (compare as joined string)
            chains = {
                bname: ",".join(p.get("doc_proto_chain", []))
                for bname, p in probes.items()
            }
            if len(set(chains.values())) > 1:
                divergences.append(Divergence(
                    property=prop,
                    aspect="doc_proto_chain",
                    chromium=chains.get("chromium"),
                    firefox=chains.get("firefox"),
                    webkit=chains.get("webkit"),
                ))

            # Chain sub-properties
            all_chain_keys: set[str] = set()
            for p in probes.values():
                all_chain_keys.update(p.get("chain", {}).keys())

            for ck in sorted(all_chain_keys):
                for sub in ("type", "constructor", "value"):
                    vals = {}
                    for bname, p in probes.items():
                        chain_entry = p.get("chain", {}).get(ck, {})
                        vals[bname] = chain_entry.get(sub)
                    unique = set(str(v) for v in vals.values())
                    if len(unique) > 1:
                        divergences.append(Divergence(
                            property=prop,
                            aspect=f"chain.{ck}.{sub}",
                            chromium=vals.get("chromium"),
                            firefox=vals.get("firefox"),
                            webkit=vals.get("webkit"),
                        ))

        return divergences


# ---------------------------------------------------------------------------
# Systematic Enumerator
# ---------------------------------------------------------------------------

class SystematicEnumerator:
    """Generates all tag x attr x nesting combinations for systematic testing."""

    CLOBBER_TAGS = [
        "a", "area", "form", "img", "input", "object", "embed",
        "iframe", "button", "fieldset", "output", "select", "textarea",
        "div", "span", "section", "article", "header", "footer",
        "nav", "main", "aside", "details", "summary", "dialog",
        "table", "tr", "td", "th", "caption", "colgroup",
        "ol", "ul", "li", "dl", "dt", "dd",
        "p", "h1", "h2", "h3", "blockquote", "pre",
        "b", "i", "u", "em", "strong", "mark", "small", "del", "ins",
    ]

    CLOBBER_ATTRS = ["id", "name"]

    NESTING_PATTERNS: list[tuple[str, str]] = [
        # (pattern_template, description)
        ('<{tag} {attr}="x">', "single"),
        ('<{tag} {attr}="x"></{tag}><{tag} {attr}="x">', "duplicate_id"),
        ('<form id="x"><{tag} name="y"></form>', "form_child"),
        ('<form id="x"><{tag} name="y"></{tag}><{tag} name="z"></form>', "form_multi_child"),
        ('<{tag} {attr}="x"></{tag}><a {attr}="x" name="y" href="http://test.com/">', "collection_anchor"),
        ('<svg><foreignObject><{tag} {attr}="x"></foreignObject></svg>', "svg_ns"),
        ('<math><mtext><{tag} {attr}="x"></mtext></math>', "math_ns"),
        ('<fieldset><{tag} {attr}="x"></fieldset>', "fieldset_child"),
        ('<form id="x"><object name="y"><param name="z" value="test"></object></form>', "form_object_param"),
        ('<{tag} {attr}="x" href="http://test.com/">', "with_href"),
        ('<{tag} {attr}="x" src="http://test.com/">', "with_src"),
        ('<{tag} {attr}="x" action="http://test.com/">', "with_action"),
        ('<{tag} {attr}="x" data="http://test.com/">', "with_data"),
    ]

    def generate_all(self) -> Iterator[SnippetSpec]:
        """Yield all tag x attr x nesting combinations."""
        snippet_id = 0
        for tag in self.CLOBBER_TAGS:
            for attr in self.CLOBBER_ATTRS:
                for pattern_tpl, _desc in self.NESTING_PATTERNS:
                    html_str = pattern_tpl.format(tag=tag, attr=attr)
                    # Determine which props to probe
                    props = ["x"]
                    if 'name="y"' in html_str:
                        props.append("y")
                    if 'name="z"' in html_str:
                        props.append("z")
                    yield SnippetSpec(
                        html=html_str,
                        target_props=props,
                        snippet_id=snippet_id,
                    )
                    snippet_id += 1

    def total_count(self) -> int:
        """Return total number of combinations without generating them."""
        return len(self.CLOBBER_TAGS) * len(self.CLOBBER_ATTRS) * len(self.NESTING_PATTERNS)


# ---------------------------------------------------------------------------
# Engine-integrated Target adapter
# ---------------------------------------------------------------------------

_ATTR_RE = re.compile(r'(?:id|name)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)


class DomClobberBrowserTarget:
    """Sync Target adapter wrapping async DomClobberBatchEvaluator.

    Conforms to the Target protocol for use with the fuzzing engine.
    Accumulates inputs into batches and flushes when full.
    """

    BATCH_SIZE = 50  # smaller batch for engine integration (latency trade-off)

    def __init__(self) -> None:
        self._evaluator = DomClobberBatchEvaluator()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._pending: list[tuple[SnippetSpec, asyncio.Future]] = []
        self._alive = False
        self._exec_count = 0

    def setup(self) -> None:
        """Launch event loop thread and start browsers."""
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="domclobber-asyncio",
        )
        self._thread.start()

        future = asyncio.run_coroutine_threadsafe(
            self._evaluator.setup(), self._loop,
        )
        future.result(timeout=60)
        self._alive = True
        logger.info("DomClobberBrowserTarget ready")

    def execute(self, inp: "Input") -> "ExecutionResult":  # noqa: F821
        """Evaluate a single input (batching handled internally)."""
        from webfuzzer.fuzzer.protocols import ExecutionResult

        html_str = inp.data.decode("utf-8", errors="replace")

        # Extract property names to probe from the HTML
        props = list(set(_ATTR_RE.findall(html_str)))
        if not props:
            props = ["x"]

        spec = SnippetSpec(html=html_str, target_props=props, snippet_id=self._exec_count)
        self._exec_count += 1

        t0 = time.monotonic()
        results = self._run_batch([spec])
        elapsed = (time.monotonic() - t0) * 1000

        if results and results[0].divergences:
            result_data = {
                "snippet_id": results[0].snippet_id,
                "divergences": [
                    {
                        "property": d.property,
                        "aspect": d.aspect,
                        "chromium": d.chromium,
                        "firefox": d.firefox,
                        "webkit": d.webkit,
                    }
                    for d in results[0].divergences
                ],
                "browsers": results[0].browsers,
            }
            stdout = json.dumps(result_data, default=str).encode()
            exit_code = 1  # divergence found
        elif results and results[0].error:
            stdout = json.dumps({"error": results[0].error}).encode()
            exit_code = 2
        else:
            stdout = b'{"divergences":[]}'
            exit_code = 0

        return ExecutionResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=b"",
            duration_ms=elapsed,
        )

    def _run_batch(self, specs: list[SnippetSpec]) -> list[SnippetResult]:
        """Run a batch synchronously via the event loop thread."""
        if not self._loop or not self._alive:
            return []
        future = asyncio.run_coroutine_threadsafe(
            self._evaluator.evaluate_batch(specs), self._loop,
        )
        try:
            return future.result(timeout=self._evaluator.EVAL_TIMEOUT + 10)
        except Exception as exc:
            logger.error("Batch execution failed: %s", exc)
            return [
                SnippetResult(snippet_id=s.snippet_id, error=str(exc))
                for s in specs
            ]

    def teardown(self) -> None:
        """Shut down browsers and event loop."""
        if self._loop and self._alive:
            future = asyncio.run_coroutine_threadsafe(
                self._evaluator.teardown(), self._loop,
            )
            try:
                future.result(timeout=30)
            except Exception as exc:
                logger.warning("Teardown error: %s", exc)

        self._alive = False

        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)
        self._loop = None
        self._thread = None
        logger.info("DomClobberBrowserTarget shut down")

    def is_alive(self) -> bool:
        return self._alive

    def reset(self) -> None:
        """No-op for browser target — browsers are recycled internally."""
        pass


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

def _save_divergence(
    output_dir: str,
    result: SnippetResult,
    snippets: list[SnippetSpec],
) -> None:
    """Save divergence to JSON file."""
    # Find the matching snippet
    matching_spec = None
    for s in snippets:
        if s.snippet_id == result.snippet_id:
            matching_spec = s
            break

    record = {
        "snippet_id": result.snippet_id,
        "html": matching_spec.html if matching_spec else "",
        "target_props": matching_spec.target_props if matching_spec else [],
        "divergences": [
            {
                "property": d.property,
                "aspect": d.aspect,
                "chromium": d.chromium,
                "firefox": d.firefox,
                "webkit": d.webkit,
            }
            for d in result.divergences
        ],
        "browsers": result.browsers,
    }

    path = os.path.join(output_dir, f"divergence_{result.snippet_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, default=str)


async def run_systematic_scan(
    output_dir: str,
    batch_size: int = 500,
    max_snippets: int | None = None,
) -> None:
    """Run systematic enumeration, save all divergences."""
    os.makedirs(output_dir, exist_ok=True)

    evaluator = DomClobberBatchEvaluator()
    await evaluator.setup()

    enumerator = SystematicEnumerator()
    batch: list[SnippetSpec] = []
    total_divergences = 0
    total_snippets = 0
    batch_num = 0
    t0 = time.monotonic()

    try:
        for spec in enumerator.generate_all():
            batch.append(spec)

            if len(batch) >= batch_size:
                batch_num += 1
                results = await evaluator.evaluate_batch(batch)
                for r in results:
                    if r.divergences:
                        total_divergences += len(r.divergences)
                        _save_divergence(output_dir, r, batch)
                total_snippets += len(batch)
                elapsed = time.monotonic() - t0
                logger.info(
                    "Batch %d: %d snippets, %d divergences so far (%.1fs elapsed, %.0f snippets/s)",
                    batch_num, total_snippets, total_divergences,
                    elapsed, total_snippets / max(elapsed, 0.001),
                )
                batch = []

            if max_snippets and spec.snippet_id >= max_snippets - 1:
                break

        # Final batch
        if batch:
            batch_num += 1
            results = await evaluator.evaluate_batch(batch)
            for r in results:
                if r.divergences:
                    total_divergences += len(r.divergences)
                    _save_divergence(output_dir, r, batch)
            total_snippets += len(batch)

    finally:
        await evaluator.teardown()

    elapsed = time.monotonic() - t0

    # Write summary
    summary = {
        "total_snippets": total_snippets,
        "total_divergences": total_divergences,
        "elapsed_seconds": round(elapsed, 2),
        "snippets_per_second": round(total_snippets / max(elapsed, 0.001), 1),
        "enumeration_total": enumerator.total_count(),
    }
    summary_path = os.path.join(output_dir, "summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(
        f"Scan complete: {total_snippets} snippets evaluated, "
        f"{total_divergences} divergences found in {elapsed:.1f}s"
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    # Ensure UTF-8 on Windows
    if sys.platform == "win32":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="DOM Clobbering Browser Primitive Scanner",
    )
    parser.add_argument("-o", "--output", required=True, help="Output directory")
    parser.add_argument("--batch-size", type=int, default=500)
    parser.add_argument("--max-snippets", type=int, default=None)
    parser.add_argument(
        "--mode", choices=["systematic", "fuzz"], default="systematic",
        help="Scan mode (systematic=full enumeration, fuzz=engine-driven)",
    )
    args = parser.parse_args()

    if args.mode == "systematic":
        asyncio.run(
            run_systematic_scan(args.output, args.batch_size, args.max_snippets),
        )
    else:
        print("Fuzz mode: use DomClobberBrowserTarget with the fuzzing engine.")
        sys.exit(1)
