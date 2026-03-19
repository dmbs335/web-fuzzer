"""Mutator factory helpers."""

from __future__ import annotations

import sys
from pathlib import Path

from ...core.registry import GrammarRegistry


def build_mutators(
    names: str,
    registry: GrammarRegistry,
    grammar_name: str,
    rule: str | None,
    seed: int | None,
    dict_file: Path | None = None,
    ucb_table=None,
    max_assertions: int = 0,
    campaign_mode: str = "novel",
) -> list:
    """Instantiate mutators from comma-separated names."""
    from ...fuzzer.mutators.apache_confusion_mutator import ApacheConfusionMutator
    from ...fuzzer.mutators.class_pollution_mutator import ClassPollutionMutator
    from ...fuzzer.mutators.cookie_mutator import CookieMutator
    from ...fuzzer.mutators.deser_binary_mutator import DeserBinaryMutator
    from ...fuzzer.mutators.deser_mutator import DeserMutator
    from ...fuzzer.mutators.dictionary_mutator import DictionaryMutator
    from ...fuzzer.mutators.domclobber_mutator import DomClobberMutator
    from ...fuzzer.mutators.graphql_mutator import GraphqlMutator
    from ...fuzzer.mutators.grammar_mutator import GrammarMutator
    from ...fuzzer.mutators.havoc_mutator import HavocMutator
    from ...fuzzer.mutators.jdbc_mutator import JdbcMutator
    from ...fuzzer.mutators.jndi_mutator import JndiMutator
    from ...fuzzer.mutators.jwt_mutator import JwtMutator
    from ...fuzzer.mutators.markdown_mutator import MarkdownMutator
    from ...fuzzer.mutators.mxss_mutator import MxssMutator
    from ...fuzzer.mutators.oauth_mutator import OAuthMutator
    from ...fuzzer.mutators.saml_mutator import SamlMutator
    from ...fuzzer.mutators.sandbox_mutator import SandboxMutator
    from ...fuzzer.mutators.splice_mutator import SpliceMutator
    from ...fuzzer.mutators.structural_havoc_mutator import StructuralHavocMutator
    from ...fuzzer.mutators.token_mutator import TokenMutator
    from ...fuzzer.mutators.xml_havoc_mutator import XmlHavocMutator

    mutator_map = {
        "grammar": lambda: GrammarMutator(
            registry, grammar_name, rule, seed=seed, ucb_table=ucb_table,
        ),
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
        "deser": lambda: DeserBinaryMutator(seed=seed),
        "deser_ir": lambda: DeserMutator(seed=seed),
        "deser_bin": lambda: DeserBinaryMutator(seed=seed),
        "jndi": lambda: JndiMutator(seed=seed),
        "jdbc": lambda: JdbcMutator(seed=seed),
        "class_pollution": lambda: ClassPollutionMutator(seed=seed),
        "domclobber": lambda: DomClobberMutator(seed=seed),
        "apache_confusion": lambda: ApacheConfusionMutator(
            seed=seed, campaign_mode=campaign_mode,
        ),
        "sandbox": lambda: SandboxMutator(seed=seed),
    }

    mutators = []
    for name in names.split(","):
        name = name.strip()
        factory = mutator_map.get(name)
        if factory is None:
            print(f"Warning: Unknown mutator {name!r}, skipping.", file=sys.stderr)
            continue
        mutators.append(factory())

    if not mutators:
        mutators.append(HavocMutator(seed=seed))

    return mutators
