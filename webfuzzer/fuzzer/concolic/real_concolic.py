"""Real concolic engine: source-line coverage → AST condition → semantic negation → targeted mutation.

This replaces the keyword-based ConcolicEngine with a source-guided targeted
mutation path:
1. Read _covered_lines from execution output (actual file:line tuples)
2. Cross-reference with AST-extracted branch conditions
3. Find uncovered branches adjacent to covered code
4. Negate the branch condition semantically
5. Apply the negation as a concrete XML mutation

Requires --target-coverage flag (Python targets only for now). This is not a
complete symbolic executor; parser-level synthetic branches and domain-specific
mutation directives are part of the design.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
from dataclasses import dataclass, field
from typing import Any

from ..protocols import ExecutionResult, Input
from .ast_analyzer import AstBranchExtractor, ExtractedBranch
from .condition_negator import ConditionNegator, MutationDirective, _VAR_TO_XML

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class BranchState:
    """Tracking state for one source-level branch."""
    branch: ExtractedBranch
    directives: list[MutationDirective]
    covered: bool = False  # has this line been hit?
    neighbor_covered: bool = False  # are nearby lines covered?
    attempted: bool = False
    success_count: int = 0


class RealConcolicEngine:
    """Source-guided concolic execution engine.

    Lifecycle:
        1. At startup: analyze target library source with AST extractor
        2. Each iteration: receive _covered_lines from execution output
        3. Update branch coverage state
        4. Find uncovered branches with covered neighbors
        5. Generate targeted mutations from semantic negation
    """

    MAX_TARGETED = 3
    NEIGHBOR_WINDOW = 5  # lines within ±5 are "neighbors"

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._negator = ConditionNegator()
        self._ast_extractor = AstBranchExtractor()

        # Branch database
        self._branches: list[BranchState] = []
        self._branches_by_file: dict[str, list[BranchState]] = {}

        # Coverage state
        self._covered_lines: dict[str, set[int]] = {}  # file → {line numbers}
        self._total_covered = 0

        # Round-robin
        self._round_robin = 0

        # Stats
        self._total_generated = 0
        self._total_new_coverage = 0
        self._total_branches_covered = 0

        # Auto-analyze known libraries
        self._analyzed_libraries: set[str] = set()
        self._auto_analyze()

    def _auto_analyze(self) -> None:
        """Analyze known Python + JS SAML/JWT libraries at startup."""
        # Python libraries (via ast module)
        py_libs = [
            ("signxml", "signxml"),
            ("python3-saml", "onelogin.saml2"),
            ("pyjwt", "jwt"),
        ]
        for name, module in py_libs:
            try:
                branches = self._ast_extractor.analyze_module(module)
                self._register_branches(name, branches)
                self._analyzed_libraries.add(name)
            except Exception:
                pass

        # JS/TS libraries (via tree-sitter)
        try:
            from .ts_analyzer import TreeSitterBranchExtractor
            ts = TreeSitterBranchExtractor()
            js_libs = [
                ("xml-crypto", "targets/node_modules/xml-crypto", [".js"]),
                ("samlify", "targets/node_modules/samlify", [".js"]),
                ("node-saml", "targets/node_modules/@node-saml/node-saml", [".js", ".ts"]),
            ]
            for name, path, exts in js_libs:
                try:
                    branches = ts.analyze_directory(path, library_name=name, extensions=exts)
                    self._register_branches(name, branches)
                    self._analyzed_libraries.add(name)
                except Exception:
                    pass
        except ImportError:
            pass  # tree-sitter not installed

        # Add synthetic parser-level branches FIRST (highest priority)
        # These target XML parser divergence that library code delegates to lxml/libxml2
        self._add_parser_branches()
        # Move parser branches to front of list so round-robin hits them early
        parser = [b for b in self._branches if b.branch.library == "parser_synthetic"]
        others = [b for b in self._branches if b.branch.library != "parser_synthetic"]
        self._branches = parser + others

        logger.info(
            "RealConcolicEngine: analyzed %d libraries, %d branches (%d synthetic) with %d directives",
            len(self._analyzed_libraries),
            len(self._branches),
            self._synthetic_count,
            sum(len(b.directives) for b in self._branches),
        )

    _synthetic_count: int = 0

    def _add_parser_branches(self) -> None:
        """Add synthetic branches for parser-level divergence.

        XML parsers (lxml, libxml2, DOMParser) handle these internally
        so they don't appear in library AST. But they cause real
        differential behavior across libraries.
        """
        parser_directives = [
            # Encoding divergence
            [MutationDirective("add", "BOM", b"\xef\xbb\xbf", "parser: add UTF-8 BOM")],
            [MutationDirective("set_value", "encoding", "UTF-16", "parser: change encoding to UTF-16")],
            [MutationDirective("set_value", "encoding", "ISO-8859-1", "parser: change encoding to ISO-8859-1")],
            [MutationDirective("set_value", "xml_version", "1.1", "parser: set XML version 1.1")],
            # Entity/DTD divergence
            [MutationDirective("add", "DTD", None, "parser: add DTD with entity")],
            [MutationDirective("add", "entity_ref", None, "parser: add entity reference in NameID")],
            [MutationDirective("add", "external_entity", None, "parser: add external entity")],
            # Namespace divergence
            [MutationDirective("add", "empty_ns", None, "parser: add empty namespace xmlns:x=''")],
            [MutationDirective("add", "relative_ns", None, "parser: add relative namespace xmlns:x='1'")],
            [MutationDirective("add", "default_ns_override", None, "parser: override default namespace")],
            # Comment/PI divergence (c14n)
            [MutationDirective("add", "comment_in_signed", None, "parser: comment inside signed element")],
            [MutationDirective("add", "pi_in_signed", None, "parser: PI inside signed element")],
            [MutationDirective("add", "cdata_in_nameid", None, "parser: CDATA section in NameID")],
            # Whitespace/normalization
            [MutationDirective("add", "xml_space", None, "parser: add xml:space='preserve'")],
            [MutationDirective("add", "unicode_in_value", None, "parser: non-ASCII in attribute value")],
            # Error recovery
            [MutationDirective("add", "duplicate_attr", None, "parser: duplicate attribute on element")],
            [MutationDirective("add", "unmatched_ns", None, "parser: use undefined namespace prefix")],
        ]

        for directives in parser_directives:
            branch = ExtractedBranch(
                library="parser_synthetic",
                file="xml_parser",
                file_path="",
                line_start=0,
                line_end=0,
                condition_source=directives[0].context,
                condition_ast="synthetic",
                input_properties=frozenset({"parser"}),
                category="parsing",
                negatable=True,
            )
            bs = BranchState(branch=branch, directives=directives)
            self._branches.append(bs)
            self._branches_by_file.setdefault("xml_parser", []).append(bs)
            self._synthetic_count += 1

    def _register_branches(self, library: str, branches: list[ExtractedBranch]) -> None:
        """Register branches and pre-compute negation directives."""
        for branch in branches:
            if not branch.negatable:
                continue

            directives = self._negator.negate(branch.condition_source)
            if not directives:
                continue

            # Filter: only keep directives targeting known XML elements
            valid = [d for d in directives if _is_xml_target(d.target)]
            if not valid:
                continue

            bs = BranchState(branch=branch, directives=valid)
            self._branches.append(bs)
            self._branches_by_file.setdefault(branch.file, []).append(bs)

    def update_coverage(
        self,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> None:
        """Update branch coverage from execution results.

        Reads _covered_lines from JSON output (injected by persistent_wrapper.py).
        """
        all_results = [primary_result] + (ref_results or [])
        for result in all_results:
            lines = self._extract_covered_lines(result)
            if not lines:
                continue

            for filename, lineno in lines:
                file_lines = self._covered_lines.setdefault(filename, set())
                if lineno not in file_lines:
                    file_lines.add(lineno)
                    self._total_covered += 1

        # Update branch states
        self._update_branch_states()

    def generate_targeted(
        self,
        inp: Input,
        primary_result: ExecutionResult,
        ref_results: list[ExecutionResult],
    ) -> list[Input]:
        """Generate inputs targeting uncovered branches near covered code."""
        self.update_coverage(primary_result, ref_results)

        candidates = self._find_candidates()
        if not candidates:
            return []

        targeted: list[Input] = []
        for bs in candidates[:self.MAX_TARGETED]:
            bs.attempted = True
            mutation = self._apply_directive(inp.data, bs)
            if mutation and mutation != inp.data:
                targeted.append(
                    Input(
                        data=mutation,
                        metadata={
                            "mutator": "concolic",
                            "concolic_source": "real_concolic",
                            "target_branch": f"{bs.branch.library}/{bs.branch.file}:{bs.branch.line_start}",
                            "condition": bs.branch.condition_source[:100],
                            "directive": bs.directives[0].context if bs.directives else "",
                            "action": bs.directives[0].action if bs.directives else "",
                        },
                    )
                )

        self._total_generated += len(targeted)
        return targeted

    def on_result(self, had_new_coverage: bool) -> None:
        """Feedback: did the last targeted mutation produce new coverage?"""
        if had_new_coverage:
            self._total_new_coverage += 1

    def get_stats(self) -> dict[str, Any]:
        total = len(self._branches)
        covered = sum(1 for b in self._branches if b.covered)
        with_neighbors = sum(1 for b in self._branches if b.neighbor_covered and not b.covered)
        attempted = sum(1 for b in self._branches if b.attempted)
        return {
            "total_branches": total,
            "covered_branches": covered,
            "targetable": with_neighbors,  # uncovered but neighbor is covered
            "attempted": attempted,
            "total_generated": self._total_generated,
            "total_new_coverage": self._total_new_coverage,
            "covered_source_lines": self._total_covered,
            "analyzed_libraries": sorted(self._analyzed_libraries),
        }

    def get_status_line(self) -> str:
        stats = self.get_stats()
        return (
            f"RC:{stats['total_generated']}("
            f"{stats['covered_branches']}/{stats['total_branches']}cov "
            f"{stats['targetable']}tgt "
            f"{stats['total_new_coverage']}hit)"
        )

    # ── Internal ────────────────────────────────────────────────

    @staticmethod
    def _extract_covered_lines(result: ExecutionResult) -> list[tuple[str, int]]:
        """Extract _covered_lines from JSON output."""
        if not result.stdout:
            return []
        try:
            data = json.loads(result.stdout)
            lines = data.get("_covered_lines")
            if lines and isinstance(lines, list):
                return [(f, l) for f, l in lines if isinstance(f, str) and isinstance(l, int)]
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        return []

    def _update_branch_states(self) -> None:
        """Mark branches as covered / neighbor-covered based on line data."""
        for filename, branches in self._branches_by_file.items():
            covered_lines = self._covered_lines.get(filename, set())
            if not covered_lines:
                continue

            for bs in branches:
                # Direct coverage
                for line in range(bs.branch.line_start, bs.branch.line_end + 1):
                    if line in covered_lines:
                        bs.covered = True
                        break

                # Neighbor coverage (within NEIGHBOR_WINDOW lines)
                if not bs.covered:
                    for offset in range(-self.NEIGHBOR_WINDOW, self.NEIGHBOR_WINDOW + 1):
                        if (bs.branch.line_start + offset) in covered_lines:
                            bs.neighbor_covered = True
                            break

    def _find_candidates(self) -> list[BranchState]:
        """Find uncovered branches with covered neighbors, round-robin.

        Priority order:
        1. Parser-level synthetic branches (under-explored, highest value)
        2. Uncovered branches with covered neighbors
        3. Other untried branches
        """
        parser_candidates: list[BranchState] = []
        neighbor_candidates: list[BranchState] = []
        other_candidates: list[BranchState] = []
        n = len(self._branches)
        if n == 0:
            return []

        for offset in range(n):
            idx = (self._round_robin + offset) % n
            bs = self._branches[idx]
            if bs.covered:
                continue
            if bs.attempted:
                continue

            if bs.branch.library == "parser_synthetic":
                parser_candidates.append(bs)
            elif bs.neighbor_covered:
                neighbor_candidates.append(bs)
            elif bs.directives:
                other_candidates.append(bs)

            if len(parser_candidates) + len(neighbor_candidates) + len(other_candidates) >= self.MAX_TARGETED * 3:
                break

        # Interleave: at least 1 parser candidate per batch
        candidates: list[BranchState] = []
        if parser_candidates:
            candidates.append(parser_candidates.pop(0))
        candidates.extend(neighbor_candidates)
        candidates.extend(parser_candidates)
        candidates.extend(other_candidates)

        # Reset if all attempted
        if not candidates:
            for bs in self._branches:
                bs.attempted = False
            # Retry
            for offset in range(min(n, self.MAX_TARGETED)):
                idx = (self._round_robin + offset) % n
                bs = self._branches[idx]
                if not bs.covered and bs.directives:
                    candidates.append(bs)

        self._round_robin = (self._round_robin + self.MAX_TARGETED) % max(n, 1)
        return candidates

    def _apply_directive(self, data: bytes, bs: BranchState) -> bytes | None:
        """Apply a MutationDirective to input bytes."""
        if not bs.directives:
            return None

        directive = self._rng.choice(bs.directives)
        target = directive.target
        action = directive.action

        # Synthetic parser-level mutations (special handling)
        synthetic_result = self._apply_parser_mutation(data, target)
        if synthetic_result is not None:
            return synthetic_result

        if action == "remove":
            return self._remove_element(data, target)
        elif action == "add":
            return self._add_element(data, target)
        elif action == "set_count":
            return self._set_element_count(data, target, directive.value or 1)
        elif action == "set_value":
            return self._set_value(data, target, str(directive.value or ""))
        elif action == "toggle":
            removed = self._remove_element(data, target)
            if removed != data:
                return removed
            return self._add_element(data, target)
        return None

    def _apply_parser_mutation(self, data: bytes, target: str) -> bytes | None:
        """Apply parser-level synthetic mutations. Returns None if not a parser target."""
        if target == "BOM":
            if data[:3] != b"\xef\xbb\xbf":
                return b"\xef\xbb\xbf" + data
            return data[3:]

        if target == "encoding":
            m = re.search(rb'encoding=["\']([^"\']*)["\']', data[:200])
            if m:
                return data[:m.start(1)] + b"UTF-16" + data[m.end(1):]
            xml_decl = re.search(rb"<\?xml\s[^?]*\?>", data[:200])
            if xml_decl:
                return data[:xml_decl.end()-2] + b' encoding="UTF-16"' + data[xml_decl.end()-2:]
            return b'<?xml version="1.0" encoding="UTF-16"?>' + data

        if target == "xml_version":
            m = re.search(rb'version=["\']([^"\']*)["\']', data[:200])
            if m:
                return data[:m.start(1)] + b"1.1" + data[m.end(1):]
            return b'<?xml version="1.1"?>' + data

        if target == "DTD":
            if b"<!DOCTYPE" in data:
                return None
            xml_decl = re.search(rb"<\?xml[^?]*\?>", data[:200])
            pos = xml_decl.end() if xml_decl else 0
            dtds = [
                b'<!DOCTYPE Response [<!ENTITY xxe "INJECTED">]>',
                b'<!DOCTYPE Response [<!ENTITY % pe SYSTEM "file:///dev/null">]>',
                b'<!DOCTYPE Response [<!ENTITY boom "BOOM"><!ENTITY boom2 "&boom;&boom;">]>',
            ]
            return data[:pos] + self._rng.choice(dtds) + data[pos:]

        if target == "entity_ref":
            m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)([^<]*)(</)", data)
            if m:
                entities = [b"&custom;", b"&#x41;", b"&#65;", b"&amp;amp;"]
                return data[:m.end(1)] + self._rng.choice(entities) + data[m.end(1):]
            return None

        if target == "external_entity":
            xml_decl = re.search(rb"<\?xml[^?]*\?>", data[:200])
            pos = xml_decl.end() if xml_decl else 0
            return data[:pos] + b'<!DOCTYPE Response [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' + data[pos:]

        if target == "empty_ns":
            m = re.search(rb"<(\w+(?::\w+)?)\s", data[:4096])
            if m:
                return data[:m.end()-1] + b' xmlns:evil=""' + data[m.end()-1:]
            return None

        if target == "relative_ns":
            m = re.search(rb"<(\w+(?::\w+)?)\s", data[:4096])
            if m:
                uri = self._rng.choice([b"1", b".", b"a/b", b"#", b"//", b"data:,"])
                return data[:m.end()-1] + b' xmlns:void="' + uri + b'"' + data[m.end()-1:]
            return None

        if target == "default_ns_override":
            m = re.search(rb"<(\w+(?::\w+)?)\s", data[:4096])
            if m:
                return data[:m.end()-1] + b' xmlns="urn:evil:override"' + data[m.end()-1:]
            return None

        if target == "comment_in_signed":
            m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)", data)
            if m:
                return data[:m.end()] + b"<!--INJECTED-->" + data[m.end():]
            return None

        if target == "pi_in_signed":
            m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)", data)
            if m:
                return data[:m.end()] + b"<?pi data?>" + data[m.end():]
            return None

        if target == "cdata_in_nameid":
            m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)([^<]+)(</)", data)
            if m:
                return data[:m.start(2)] + b"<![CDATA[" + m.group(2) + b"]]>" + data[m.end(2):]
            return None

        if target == "xml_space":
            m = re.search(rb"(<(?:\w+:)?Assertion\b)", data)
            if m:
                return data[:m.end()] + b' xml:space="preserve"' + data[m.end():]
            return None

        if target == "unicode_in_value":
            m = re.search(rb"(<(?:\w+:)?NameID[^>]*>)([^<]+)(</)", data)
            if m:
                text = m.group(2)
                # Insert zero-width space
                return data[:m.start(2)] + text[:3] + b"\xc2\xa0" + text[3:] + data[m.end(2):]
            return None

        if target == "duplicate_attr":
            m = re.search(rb"(<(?:\w+:)?Assertion\b)([^>]*)(>)", data)
            if m:
                return data[:m.start(3)] + b' Version="1.0"' + data[m.start(3):]
            return None

        if target == "unmatched_ns":
            m = re.search(rb"(<(?:\w+:)?NameID)", data)
            if m:
                return data[:m.start()] + b"<undefined:NameID" + data[m.end():]
            return None

        return None  # not a parser target

    def _remove_element(self, data: bytes, target: str) -> bytes:
        """Remove an XML element matching target."""
        tag = self._xml_tag(target).encode()
        # Try self-closing: <tag ... />
        m = re.search(rb"<" + tag + rb"\b[^>]*/>", data)
        if m:
            return data[:m.start()] + data[m.end():]
        # Try open+close (non-greedy): <tag ...>...</tag>
        m = re.search(rb"<" + tag + rb"\b[^>]*>.*?</" + tag + rb"\s*>", data, re.DOTALL)
        if m:
            return data[:m.start()] + data[m.end():]
        # Try removing attribute if target looks like one (e.g., NotBefore, Format)
        attr_pattern = rb'\s*' + re.escape(target.split(":")[-1]).encode() + rb'="[^"]*"'
        m = re.search(attr_pattern, data)
        if m:
            return data[:m.start()] + data[m.end():]
        return data

    def _add_element(self, data: bytes, target: str) -> bytes:
        """Add an XML element. Uses smart insertion based on target type."""
        # Attribute target (e.g., "ds:DigestMethod@Algorithm")
        if "@" in target:
            parts = target.split("@")
            attr_name = parts[1]
            parent_tag = self._xml_tag(parts[0]).encode()
            m = re.search(rb"(<" + parent_tag + rb")\b", data)
            if m:
                return data[:m.end()] + f' {attr_name}="injected"'.encode() + data[m.end():]
            return data

        # Known insertion templates for specific elements
        templates = {
            "ds:X509Data": b"<ds:X509Data><ds:X509Certificate>MIIC</ds:X509Certificate></ds:X509Data>",
            "ds:X509Certificate": b"<ds:X509Certificate>MIIC</ds:X509Certificate>",
            "ds:KeyValue": b"<ds:KeyValue><ds:RSAKeyValue><ds:Modulus>AAAA</ds:Modulus><ds:Exponent>AQAB</ds:Exponent></ds:RSAKeyValue></ds:KeyValue>",
            "ds:KeyInfo": b"<ds:KeyInfo/>",
            "ds:Transform": b'<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>',
            "ds:Transforms": b"<ds:Transforms/>",
            "ds:Reference": b'<ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>',
            "ec:InclusiveNamespaces": b'<ec:InclusiveNamespaces xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" PrefixList="ds saml"/>',
            "saml:Conditions": b'<saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/>',
            "saml:AudienceRestriction": b"<saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>",
            "saml:Audience": b"<saml:Audience>https://sp.example.com</saml:Audience>",
            "saml:Issuer": b"<saml:Issuer>https://idp.example.com</saml:Issuer>",
            "saml:NameID": b'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user@example.com</saml:NameID>',
            "saml:Subject": b"<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>",
        }

        tag = target.split(":")[-1] if ":" in target else target
        full_target = target
        elem = templates.get(full_target)
        if elem is None:
            # Generic element
            if ":" in target:
                elem = f"<{target}/>".encode()
            else:
                elem = f"<saml:{target}/>".encode()

        # Smart insertion: find appropriate parent
        # ds:* elements → inside ds:SignedInfo or ds:Signature
        if target.startswith("ds:"):
            parent_close = re.search(rb"</(?:\w+:)?SignedInfo\s*>", data)
            if parent_close:
                return data[:parent_close.start()] + elem + data[parent_close.start():]
        # saml:* elements → inside saml:Assertion
        if target.startswith("saml:"):
            assertion_m = re.search(rb"(<(?:\w+:)?Assertion\b[^>]*>)", data)
            if assertion_m:
                return data[:assertion_m.end()] + elem + data[assertion_m.end():]
        # ec:* → inside ds:Transform
        if target.startswith("ec:"):
            transform_close = re.search(rb"</(?:\w+:)?Transform\s*>", data)
            if transform_close:
                return data[:transform_close.start()] + elem + data[transform_close.start():]

        # Fallback: before first closing tag
        close = re.search(rb"</", data)
        if close:
            return data[:close.start()] + elem + data[close.start():]
        return data

    def _set_element_count(self, data: bytes, target: str, count: int) -> bytes:
        """Set the number of elements matching target to exactly count."""
        tag = self._xml_tag(target)
        pattern = rb"<" + tag.encode() + rb"\b[^>]*(?:/>|>.*?</" + tag.encode() + rb"\s*>)"
        matches = list(re.finditer(pattern, data, re.DOTALL))
        current = len(matches)

        if current == count:
            return data  # already at target count

        if current > count:
            # Remove excess (from the end)
            result = data
            for m in reversed(matches[count:]):
                result = result[:m.start()] + result[m.end():]
            return result

        if current < count and matches:
            # Duplicate first match
            template = matches[0].group()
            # Change ID to avoid duplicates
            copies = []
            for i in range(count - current):
                copy = re.sub(
                    rb'(ID|Id)="([^"]*)"',
                    f'ID="_clone_{i}"'.encode(),
                    template,
                    count=1,
                )
                copies.append(copy)
            insert_pos = matches[-1].end()
            return data[:insert_pos] + b"".join(copies) + data[insert_pos:]

        return data

    def _set_value(self, data: bytes, target: str, value: str) -> bytes:
        """Set an element's text content or attribute value."""
        tag = self._xml_tag(target)

        # If it's an attribute target
        if "@" in target:
            parts = target.split("@")
            parent_tag = self._xml_tag(parts[0])
            attr_name = parts[1]
            pattern = rb"(<" + parent_tag.encode() + rb"\b[^>]*)" + attr_name.encode() + rb'="[^"]*"'
            m = re.search(pattern, data)
            if m:
                new_attr = f'{attr_name}="{value}"'.encode()
                return data[:m.start()] + m.group(1) + new_attr + data[m.end():]
            return data

        # Element text content
        pattern = rb"(<" + tag.encode() + rb"\b[^>]*>)[^<]*(</)"
        m = re.search(pattern, data)
        if m:
            return data[:m.end(1)] + value.encode() + data[m.start(2):]
        return data

    @staticmethod
    def _xml_tag(target: str) -> str:
        """Convert target name to XML tag pattern (handle prefixes)."""
        if "@" in target:
            target = target.split("@")[0]
        # Already has prefix (ds:Reference, saml:Assertion)
        if ":" in target:
            return target
        # Convert to wildcard prefix pattern
        return f"(?:\\w+:)?{re.escape(target)}"


# ── Known XML targets ────────────────────────────────────────────
# Only allow targets that map to actual XML elements/attributes.
# Reject generic Python variable names like "arguments", "c", "name", "rhs".

_KNOWN_XML_TARGETS = frozenset(
    list(_VAR_TO_XML.values()) + [
        # Common XML element/attribute names
        "ds:Signature", "ds:SignedInfo", "ds:Reference", "ds:Transform",
        "ds:Transforms", "ds:DigestMethod", "ds:SignatureMethod",
        "ds:CanonicalizationMethod", "ds:KeyInfo", "ds:KeyValue",
        "ds:X509Data", "ds:X509Certificate",
        "saml:Assertion", "saml:Subject", "saml:NameID", "saml:Issuer",
        "saml:Conditions", "saml:Audience", "saml:AudienceRestriction",
        "saml:AttributeStatement", "saml:Attribute",
        "samlp:Response", "samlp:Status", "samlp:StatusCode",
        "ec:InclusiveNamespaces",
        "Algorithm", "ID", "Id", "URI", "Version",
        "NotBefore", "NotOnOrAfter", "Format",
        # JWT-relevant
        "alg", "typ", "kid", "jku", "jwk", "x5u", "crit",
        "sub", "iss", "aud", "exp", "nbf", "iat",
        "payload", "header", "key",
    ]
)


def _is_xml_target(target: str) -> bool:
    """Check if a target name corresponds to a known XML element/attribute."""
    if target in _KNOWN_XML_TARGETS:
        return True
    # Allow prefixed names (ds:X, saml:X, etc.)
    if ":" in target:
        return True
    # Allow attribute targets (X@Y)
    if "@" in target:
        base = target.split("@")[0]
        return base in _KNOWN_XML_TARGETS or ":" in base
    return False
