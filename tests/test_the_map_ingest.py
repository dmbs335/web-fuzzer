from webfuzzer.the_map_learning import parse_topic_markdown


SAMPLE_MARKDOWN = """# OAuth 2.0 / OpenID Connect Mutation & Variation Taxonomy

## Classification Structure

This taxonomy organizes the entire OAuth/OIDC attack surface along three orthogonal axes.
**Axis 1 — Mutation Target (Primary):** The structural component of the OAuth protocol being mutated or exploited.
**Axis 2 — Discrepancy Type (Cross-cutting):** The nature of the mismatch or bypass that each mutation creates.
**Axis 3 — Attack Scenario (Mapping):** The real-world outcome.

### Axis 2 Summary

| Code | Discrepancy Type | Description |
|------|------------------|-------------|
| **D1** | Validation Bypass | redirect_uri validation is insufficient |
| **D2** | Identity Confusion | identity is misattributed |

## §1. Redirect URI Manipulation

The `redirect_uri` parameter is the primary target.

### §1-1. Validation Bypass Techniques

| Subtype | Mechanism | Key Condition | Discrepancy |
|---------|-----------|---------------|-------------|
| **No validation** | Server accepts any redirect_uri | No allowlist | D1 |
| **Regex bypass** | Exploiting flawed regex patterns | Custom regex validation | D1 |

## §11. Attack Scenario Mapping (Axis 3)

| Scenario | Description |
|----------|-------------|
| Account Takeover | Code lands on attacker callback |

## §12. CVE / Bounty Mapping (2023–2025)

| ID | Summary |
|----|---------|
| CVE-2025-0001 | Example issue |

## §13. Detection Tools

| Tool | Notes |
|------|-------|
| Burp Suite | Manual testing |

## §14. Summary: Core Principles

Incremental fixes fail when redirect validation remains parser-dependent.

## References

- RFC 6749
- OAuth 2.1 draft
"""


def test_parse_topic_markdown_extracts_sections_and_techniques():
    payload = parse_topic_markdown(
        SAMPLE_MARKDOWN,
        "C:/Users/dmbs3/Downloads/the-map/the-map/02-auth/oauth.md",
    )

    assert payload["schema_version"] == "1.0.0"
    topic = payload["topic"]
    assert topic["slug"] == "oauth"
    assert topic["category_slug"] == "02-auth"
    assert topic["overview"]["axis_summaries"]["axis1"] is not None
    assert len(topic["overview"]["discrepancy_types"]) == 2

    section = topic["axis1_sections"][0]
    assert section["section_ref"] == "1"
    assert section["title"] == "Redirect URI Manipulation"
    assert len(section["subsections"]) == 1

    subsection = section["subsections"][0]
    assert subsection["subsection_ref"] == "1-1"
    assert subsection["techniques"][0]["name"] == "No validation"
    assert subsection["techniques"][0]["fields"]["Discrepancy"] == "D1"

    assert topic["appendices"]["scenario_mapping"][0]["Scenario"] == "Account Takeover"
    assert topic["appendices"]["case_studies"][0]["ID"] == "CVE-2025-0001"
    assert topic["appendices"]["tools"][0]["Tool"] == "Burp Suite"
    assert "Incremental fixes fail" in topic["appendices"]["principles"][0]
    assert topic["appendices"]["references"][0] == "- RFC 6749"
