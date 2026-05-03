"""PostgreSQL driver fuzzing oracle.

Single-target oracle that analyzes evil-server → driver interaction
reports for anomalies without requiring a reference target.
"""

from __future__ import annotations

import json

from ..protocols import ExecutionResult, Finding, Input, Severity


class PgdriverOracle:
    """Detects driver misbehavior from malformed server responses.

    Works as a single-target oracle (check() interface) — no reference needed.
    """

    name = "pgdriver"

    def check(self, inp: Input, result: ExecutionResult) -> Finding | None:
        data = result.parsed_json()
        if not isinstance(data, dict):
            return None

        client = data.get("client", {})
        anomalies = data.get("anomalies", [])
        family = inp.metadata.get("mutation_family", "") or data.get("mutation_family", "")

        # 1. Driver crash — highest priority
        if client.get("crash"):
            return Finding(
                title=f"Driver crash: {client.get('driver', '?')}",
                severity=Severity.CRITICAL,
                input=inp,
                result=result,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_crash",
                    "category": "driver_crash",
                    "driver": client.get("driver"),
                    "error": str(client.get("error", ""))[:200],
                    "mutation_family": family,
                },
            )

        # 2. Overflow-specific: driver parsed data despite overflow length
        if family in ("overflow_length", "negative_length"):
            if client.get("connected") and client.get("rows_received", 0) > 0:
                return Finding(
                    title=f"Overflow: driver parsed data: {client.get('driver', '?')}",
                    severity=Severity.HIGH,
                    input=inp,
                    result=result,
                    oracle_name="pgdriver",
                    metadata={
                        "strategy": "pgdriver_overflow",
                        "category": "overflow_data_parsed",
                        "driver": client.get("driver"),
                        "rows_received": client.get("rows_received", 0),
                        "mutation_family": family,
                    },
                )

        # 3. Driver accepted malformed response and parsed rows
        if "parsed_rows_from_malformed" in anomalies or "extra_rows_from_malformed" in anomalies:
            return Finding(
                title=f"Malformed data accepted: {client.get('driver', '?')}",
                severity=Severity.HIGH,
                input=inp,
                result=result,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_malformed_accept",
                    "category": "malformed_accept",
                    "driver": client.get("driver"),
                    "anomalies": anomalies,
                    "mutation_family": family,
                    "rows_received": client.get("rows_received", 0),
                },
            )

        # 4. State machine: connected without auth
        if "connected_without_auth" in anomalies or (family == "drop_auth_ok" and client.get("connected")):
            sev = Severity.HIGH
            if "query_success_without_auth" in anomalies:
                sev = Severity.CRITICAL
            return Finding(
                title=f"Connected without AuthOk: {client.get('driver', '?')}",
                severity=sev,
                input=inp,
                result=result,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_state_machine",
                    "category": "connected_without_auth",
                    "driver": client.get("driver"),
                    "query_succeeded": "query_success_without_auth" in anomalies,
                    "anomalies": anomalies,
                },
            )

        # 5. Accepted wrong message type
        if "accepted_wrong_type" in anomalies:
            return Finding(
                title=f"Wrong type accepted: {client.get('driver', '?')}",
                severity=Severity.MEDIUM,
                input=inp,
                result=result,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_type_confusion",
                    "category": "wrong_type_accepted",
                    "driver": client.get("driver"),
                    "anomalies": anomalies,
                    "mutation_family": family,
                },
            )

        # 6. Silently accepted malformed response (no rows but no error either)
        if "accepted_malformed_response" in anomalies:
            return Finding(
                title=f"Malformed response accepted: {client.get('driver', '?')}",
                severity=Severity.LOW,
                input=inp,
                result=result,
                oracle_name="pgdriver",
                metadata={
                    "strategy": "pgdriver_malformed_accept",
                    "category": "malformed_silent_accept",
                    "driver": client.get("driver"),
                    "anomalies": anomalies,
                    "mutation_family": family,
                },
            )

        return None
