from gatehouse.credentials.validation import is_admissible_firecrawl_secret


def test_firecrawl_secret_namespace_accepts_provider_and_reserved_synthetic_values() -> None:
    accepted = (
        b"fc-" + b"0123456789abcdefghijklmnop",
        b"FAKE-NO-NETWORK-CREDENTIAL-000001",
        b"synthetic-no-network-credential-000001",
        b'synthetic-escaped-"boundary"-credential',
    )

    assert all(is_admissible_firecrawl_secret(value, maximum_bytes=16_384) for value in accepted)


def test_firecrawl_secret_namespace_rejects_durable_state_and_unbounded_values() -> None:
    rejected = (
        b"RUNNING",
        b"none",
        b"application/json",
        b"201",
        b"fc-too-short",
        b"fc-" + b"0123456789abcdefghij!",
        b"arbitrary-long-secret-without-an-owned-namespace",
        b"FAKE-short",
        b"synthetic-short",
        b"fc-" + b"a" * 40,
    )

    for value in rejected[:-1]:
        assert not is_admissible_firecrawl_secret(value, maximum_bytes=32)
    assert not is_admissible_firecrawl_secret(rejected[-1], maximum_bytes=32)
