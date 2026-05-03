"""PostgreSQL driver fuzzing oracle strategies.

Analyzes evil-server → driver interaction reports for anomalies:
  - Driver accepted malformed responses without error
  - Driver crashed on specific response mutations
  - Driver parsed rows from corrupted messages
  - State machine confusion (connected despite missing auth)
"""

from __future__ import annotations

from ..protocols import ExecutionResult, Finding, Input, Severity


def _parse_report(result: ExecutionResult) -> dict | None:
    data = result.parsed_json()
    if not isinstance(data, dict):
        return None
    if "client" not in data and "driver" not in data:
        return None
    return data


class PgdriverCrashStrategy:
    """Detects driver crashes or uncaught exceptions from malformed responses."""

    name = "pgdriver_crash"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_report(primary)
        if pp is None:
            return None

        client = pp.get("client", {})
        if not client.get("crash"):
            return None

        return Finding(
            title=f"Driver crash: {client.get('driver', '?')}",
            severity=Severity.CRITICAL,
            input=inp,
            result=primary,
            oracle_name="pgdriver",
            metadata={
                "strategy": "pgdriver_crash",
                "category": "driver_crash",
                "driver": client.get("driver"),
                "error": client.get("error", "")[:200],
                "mutation_family": inp.metadata.get("mutation_family"),
                "mutation_count": pp.get("mutations_applied", 0),
            },
        )


class PgdriverMalformedAcceptStrategy:
    """Detects when a driver silently accepts malformed server responses."""

    name = "pgdriver_malformed_accept"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_report(primary)
        if pp is None:
            return None

        anomalies = pp.get("anomalies", [])
        if not anomalies:
            return None

        # Filter for high-value anomalies
        high_value = [a for a in anomalies if a in (
            "accepted_malformed_response",
            "parsed_rows_from_malformed",
            "accepted_wrong_type",
            "extra_rows_from_malformed",
        )]
        if not high_value:
            return None

        client = pp.get("client", {})
        severity = Severity.MEDIUM
        if "parsed_rows_from_malformed" in high_value:
            severity = Severity.HIGH
        if "extra_rows_from_malformed" in high_value:
            severity = Severity.HIGH

        return Finding(
            title=f"Driver accepted malformed response: {client.get('driver', '?')}",
            severity=severity,
            input=inp,
            result=primary,
            oracle_name="pgdriver",
            metadata={
                "strategy": "pgdriver_malformed_accept",
                "category": "malformed_accept",
                "driver": client.get("driver"),
                "anomalies": high_value,
                "mutation_family": inp.metadata.get("mutation_family"),
                "rows_received": client.get("rows_received", 0),
                "query_result": client.get("query_result"),
            },
        )


class PgdriverOverflowStrategy:
    """Specifically targets integer overflow vulnerabilities (CVE-2024-27304 pattern).

    Looks for cases where near-MAX_INT32 length values cause the driver
    to behave unexpectedly (not just error out).
    """

    name = "pgdriver_overflow"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_report(primary)
        if pp is None:
            return None

        family = inp.metadata.get("mutation_family", "")
        if family not in ("overflow_length", "negative_length"):
            return None

        client = pp.get("client", {})

        # Crash with overflow is critical
        if client.get("crash"):
            return Finding(
                title=f"Overflow crash: {client.get('driver', '?')}",
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_overflow",
                    "category": "overflow_crash",
                    "driver": client.get("driver"),
                    "error": client.get("error", "")[:200],
                    "mutation_family": family,
                },
            )

        # Connected and got data despite overflow length is suspicious
        if client.get("connected") and client.get("rows_received", 0) > 0:
            return Finding(
                title=f"Overflow: driver parsed data: {client.get('driver', '?')}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_overflow",
                    "category": "overflow_data_parsed",
                    "driver": client.get("driver"),
                    "rows_received": client.get("rows_received", 0),
                    "mutation_family": family,
                },
            )

        return None


class PgdriverStateMachineStrategy:
    """Detects state machine confusion in driver protocol handling."""

    name = "pgdriver_state_machine"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_report(primary)
        if pp is None:
            return None

        family = inp.metadata.get("mutation_family", "")
        if family not in ("drop_readyforquery", "drop_auth_ok", "extra_readyforquery"):
            return None

        client = pp.get("client", {})

        # Connected despite missing auth
        if family == "drop_auth_ok" and client.get("connected"):
            return Finding(
                title=f"Connected without AuthOk: {client.get('driver', '?')}",
                severity=Severity.HIGH,
                input=inp,
                result=primary,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_state_machine",
                    "category": "connected_without_auth",
                    "driver": client.get("driver"),
                },
            )

        # Got query result despite missing ReadyForQuery
        if family == "drop_readyforquery" and client.get("query_result") == "success":
            return Finding(
                title=f"Query succeeded without ReadyForQuery: {client.get('driver', '?')}",
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_state_machine",
                    "category": "query_without_ready",
                    "driver": client.get("driver"),
                },
            )

        return None


class PgdriverDifferentialStrategy:
    """Cross-driver differential: same malformed input, different behavior."""

    name = "pgdriver_differential"

    def compare(
        self,
        inp: Input,
        primary: ExecutionResult,
        reference: ExecutionResult,
        ref_index: int,
    ) -> Finding | None:
        pp = _parse_report(primary)
        rp = _parse_report(reference)
        if pp is None or rp is None:
            return None

        p_client = pp.get("client", {})
        r_client = rp.get("client", {})

        # Different drivers, same transcript
        p_driver = p_client.get("driver", "?")
        r_driver = r_client.get("driver", "?")
        if p_driver == r_driver:
            return None

        # One crashed, other didn't
        if p_client.get("crash") != r_client.get("crash"):
            return Finding(
                title=f"Differential crash: {p_driver} vs {r_driver}",
                severity=Severity.CRITICAL,
                input=inp,
                result=primary,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_differential",
                    "category": "differential_crash",
                    "driver_primary": p_driver,
                    "driver_reference": r_driver,
                    "primary_crashed": p_client.get("crash", False),
                    "ref_crashed": r_client.get("crash", False),
                    "mutation_family": inp.metadata.get("mutation_family"),
                    "ref_index": ref_index,
                },
            )

        # One accepted data, other errored
        p_ok = p_client.get("query_result") == "success"
        r_ok = r_client.get("query_result") == "success"
        if p_ok != r_ok and inp.metadata.get("mutation_family") != "baseline":
            return Finding(
                title=f"Differential behavior: {p_driver} vs {r_driver}",
                severity=Severity.MEDIUM,
                input=inp,
                result=primary,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_differential",
                    "category": "differential_behavior",
                    "driver_primary": p_driver,
                    "driver_reference": r_driver,
                    "primary_result": p_client.get("query_result"),
                    "ref_result": r_client.get("query_result"),
                    "mutation_family": inp.metadata.get("mutation_family"),
                    "ref_index": ref_index,
                },
            )

        return None


def get_pgdriver_strategies() -> list:
    return [
        PgdriverCrashStrategy(),
        PgdriverMalformedAcceptStrategy(),
        PgdriverOverflowStrategy(),
        PgdriverStateMachineStrategy(),
        PgdriverDifferentialStrategy(),
    ]
