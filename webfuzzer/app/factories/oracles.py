"""Oracle factory helpers."""

from __future__ import annotations

import sys


def _make_confused_deputy():
    from ...fuzzer.oracles.confused_deputy_strategy import ConfusedDeputyStrategy

    return ConfusedDeputyStrategy()


def _make_cve_scanner():
    from ...fuzzer.oracles.cve_detector_strategy import CVEScannerStrategy

    return CVEScannerStrategy()


def build_oracles(names: str) -> list:
    """Instantiate oracles from comma-separated names."""
    from ...fuzzer.oracles.class_pollution_oracle import ClassPollutionOracle
    from ...fuzzer.oracles.cookie_oracle import CookieOracle
    from ...fuzzer.oracles.crash_oracle import CrashOracle
    from ...fuzzer.oracles.deser_oracle import DeserOracle
    from ...fuzzer.oracles.domclobber_oracle import DomClobberOracle
    from ...fuzzer.oracles.graphql_oracle import GraphqlOracle
    from ...fuzzer.oracles.jdbc_oracle import JdbcOracle
    from ...fuzzer.oracles.jndi_oracle import JndiOracle
    from ...fuzzer.oracles.jwt_oracle import JwtOracle
    from ...fuzzer.oracles.mxss_oracle import MxssOracle
    from ...fuzzer.oracles.oauth_oracle import OAuthOracle
    from ...fuzzer.oracles.response_oracle import ResponseOracle
    from ...fuzzer.oracles.saml_oracle import (
        SamlOracle,
        SamlSigTrueOracle,
        SamlValidatorOracle,
    )
    from ...fuzzer.oracles.sanitizer_oracle import SanitizerOracle
    from ...fuzzer.oracles.ssrf_oracle import SsrfOracle
    from ...fuzzer.oracles.xss_oracle import XssOracle

    oracle_map = {
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
        "graphql_exec": lambda: GraphqlOracle(),
        "sanitizer_diff": lambda: None,
        "markdown": lambda: None,
        "deser": lambda: DeserOracle(),
        "jndi": lambda: JndiOracle(),
        "jdbc": lambda: JdbcOracle(),
        "class_pollution": lambda: ClassPollutionOracle(),
        "domclobber": lambda: DomClobberOracle(),
        "domclobber_diff": lambda: None,
        "apache_confusion": lambda: None,
        "sandbox": lambda: None,
        "confused_deputy": lambda: _make_confused_deputy(),
        "cve_scanner": lambda: _make_cve_scanner(),
    }

    oracles = []
    for name in names.split(","):
        name = name.strip()
        factory = oracle_map.get(name)
        if factory is None:
            print(f"Warning: Unknown oracle {name!r}, skipping.", file=sys.stderr)
            continue
        oracle = factory()
        if oracle is not None:
            oracles.append(oracle)

    if not oracles:
        oracles.append(CrashOracle())

    return oracles
