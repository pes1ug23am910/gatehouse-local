from __future__ import annotations

from gatehouse.policy.sensitive import inspect_sensitive_content


def test_reports_sensitive_class_without_returning_value() -> None:
    secret = "sample_token_value_1234567890_ABCDEFG"

    result = inspect_sensitive_content({"api_key": secret})

    assert result.denied
    assert "sensitive_field_name" in result.findings
    assert secret not in repr(result)


def test_normal_public_query_is_allowed() -> None:
    result = inspect_sensitive_content(
        {
            "query": "graduate software roles Bengaluru",
            "data_classification": ["public_web_query"],
        }
    )

    assert not result.denied
    assert result.complete


def test_private_key_material_is_denied() -> None:
    marker = "-----BEGIN " + "PRIVATE KEY-----"
    result = inspect_sensitive_content(f"{marker}\nnot-a-real-key")

    assert result.denied
    assert result.findings == ("private_key_material",)


def test_inspection_limits_fail_closed() -> None:
    result = inspect_sensitive_content(["x"] * 20, maximum_nodes=3)

    assert result.denied
    assert not result.complete
    assert "inspection_limit_exceeded" in result.findings
