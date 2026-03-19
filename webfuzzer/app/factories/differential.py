"""Differential-mode assembly helpers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DifferentialSetup:
    """Result of wiring differential-specific runtime pieces."""

    oracles: list
    has_sanitizer_diff: bool = False


def configure_differential_oracles(
    oracles: list,
    oracle_csv: str,
    reference_targets: list,
) -> DifferentialSetup:
    """Attach the differential oracle with the right domain strategies."""
    from ...fuzzer.oracles.diff_oracle import DiffOracle

    oracle_names = [name.strip() for name in oracle_csv.split(",") if name.strip()]
    has_xss = any(getattr(o, "name", "") == "xss" for o in oracles)
    has_ssrf = any(getattr(o, "name", "") == "ssrf" for o in oracles)
    has_saml = any(getattr(o, "name", "") == "saml" for o in oracles)
    has_saml_sigtrue = any(
        getattr(o, "name", "") == "saml_sigtrue" for o in oracles
    )
    has_saml_validator = any(
        getattr(o, "name", "") == "saml_validator" for o in oracles
    )
    has_cookie = any(getattr(o, "name", "") == "cookie" for o in oracles)
    has_jwt = any(getattr(o, "name", "") == "jwt" for o in oracles)
    has_oauth = any(getattr(o, "name", "") == "oauth" for o in oracles)
    has_graphql = any(getattr(o, "name", "") == "graphql" for o in oracles)
    has_deser = any(getattr(o, "name", "") == "deser" for o in oracles)
    has_jndi = any(getattr(o, "name", "") == "jndi" for o in oracles)
    has_jdbc = any(getattr(o, "name", "") == "jdbc" for o in oracles)
    has_class_pollution = any(
        getattr(o, "name", "") == "class_pollution" for o in oracles
    )
    has_domclobber = any(
        getattr(o, "name", "") == "domclobber" for o in oracles
    )
    has_apache_confusion = "apache_confusion" in oracle_names
    has_graphql_exec = "graphql_exec" in oracle_names
    has_markdown = "markdown" in oracle_names
    has_sanitizer_diff = "sanitizer_diff" in oracle_names
    has_domclobber_diff = "domclobber_diff" in oracle_names
    has_sandbox = "sandbox" in oracle_names

    if has_sandbox:
        from ...fuzzer.oracles.sandbox_diff_strategy import (
            SandboxEscapeDiffStrategy,
        )

        strategies = [SandboxEscapeDiffStrategy()]
    elif has_apache_confusion:
        from ...fuzzer.oracles.apache_confusion_diff_strategy import (
            get_apache_confusion_strategies,
        )

        strategies = get_apache_confusion_strategies()
    elif has_markdown:
        from ...fuzzer.oracles.markdown_diff_strategy import get_markdown_strategies

        strategies = get_markdown_strategies()
    elif has_sanitizer_diff:
        from ...fuzzer.oracles.sanitizer_diff_strategy import (
            get_sanitizer_strategies,
        )

        strategies = get_sanitizer_strategies()
    elif has_saml_validator:
        from ...fuzzer.oracles.saml_validator_diff_strategy import (
            get_saml_validator_strategies,
        )

        strategies = get_saml_validator_strategies()
    elif has_saml_sigtrue:
        from ...fuzzer.oracles.saml_diff_strategy import get_saml_sigtrue_strategies

        strategies = get_saml_sigtrue_strategies(
            target_count=1 + len(reference_targets),
        )
    elif has_saml:
        from ...fuzzer.oracles.saml_diff_strategy import get_saml_strategies

        strategies = get_saml_strategies(target_count=1 + len(reference_targets))
    elif has_cookie:
        from ...fuzzer.oracles.cookie_diff_strategy import get_cookie_strategies

        strategies = get_cookie_strategies()
    elif has_jwt:
        from ...fuzzer.oracles.jwt_diff_strategy import get_jwt_strategies

        strategies = get_jwt_strategies()
    elif has_oauth:
        from ...fuzzer.oracles.oauth_diff_strategy import get_oauth_strategies

        strategies = get_oauth_strategies()
    elif has_graphql_exec:
        from ...fuzzer.oracles.graphql_exec_diff_strategy import (
            get_graphql_exec_strategies,
        )

        strategies = get_graphql_exec_strategies()
    elif has_graphql:
        from ...fuzzer.oracles.graphql_diff_strategy import get_graphql_strategies

        strategies = get_graphql_strategies()
    elif has_jdbc:
        from ...fuzzer.oracles.jdbc_diff_strategy import get_jdbc_strategies

        strategies = get_jdbc_strategies()
    elif has_jndi:
        from ...fuzzer.oracles.jndi_diff_strategy import get_jndi_strategies

        strategies = get_jndi_strategies()
    elif has_deser:
        from ...fuzzer.oracles.deser_diff_strategy import get_deser_strategies

        strategies = get_deser_strategies()
    elif has_domclobber_diff or has_domclobber:
        from ...fuzzer.oracles.domclobber_diff_strategy import (
            get_domclobber_strategies,
        )

        strategies = get_domclobber_strategies()
    elif has_class_pollution:
        from ...fuzzer.oracles.class_pollution_diff_strategy import (
            get_class_pollution_strategies,
        )

        strategies = get_class_pollution_strategies()
    elif has_ssrf:
        from ...fuzzer.oracles.ssrf_oracle import get_ssrf_strategies

        strategies = get_ssrf_strategies()
    elif has_xss:
        from ...fuzzer.oracles.diff_oracle import get_xss_strategies

        strategies = get_xss_strategies()
    else:
        strategies = None

    diff_oracles = list(oracles)
    diff_oracles.append(
        DiffOracle(reference_targets=reference_targets, strategies=strategies),
    )
    return DifferentialSetup(
        oracles=diff_oracles,
        has_sanitizer_diff=has_sanitizer_diff,
    )
