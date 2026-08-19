from __future__ import annotations

import pytest

from gatehouse.sessions import build_child_environment


def test_child_environment_strips_provider_secrets_case_insensitively() -> None:
    result = build_child_environment(
        {
            "Path": "C:\\Windows",
            "firecrawl_api_key": "fc-secret",
            "SOURCE_CONTROL_TOKEN": "source-control-secret",
            "SERVICE_PASSWORD": "password-secret",
            "GATEHOUSE_ACCESS_TOKEN": "must-not-propagate",
            "GATEHOUSE_SESSION_BOOTSTRAP": "stale",
        },
        {
            "GATEHOUSE_SESSION_BOOTSTRAP": "fresh-bootstrap",
            "GATEHOUSE_SESSION_ID": "ses_new",
        },
    )

    assert result["Path"] == "C:\\Windows"
    assert result["GATEHOUSE_SESSION_BOOTSTRAP"] == "fresh-bootstrap"
    assert result["GATEHOUSE_SESSION_ID"] == "ses_new"
    assert all(
        name.upper()
        not in {
            "FIRECRAWL_API_KEY",
            "SOURCE_CONTROL_TOKEN",
            "SERVICE_PASSWORD",
        }
        for name in result
    )
    assert "GATEHOUSE_ACCESS_TOKEN" not in result


def test_child_environment_rejects_reintroducing_a_secret() -> None:
    with pytest.raises(ValueError, match="forbidden child environment"):
        build_child_environment({}, {"Future_Service_Api_Key": "secret"})
