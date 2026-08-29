"""Canonical public-web targets and SSRF-resistant address checks."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_PERCENT_ESCAPE = re.compile(r"%([0-9a-fA-F]{2})")
_BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
_UNRESERVED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
_MAXIMUM_DNS_ANSWERS = 64


class TargetValidationError(ValueError):
    """A target is not safe for an outbound public-web request."""

    def __init__(self, reason: str) -> None:
        super().__init__("target is not an allowed public HTTPS URL")
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CanonicalTarget:
    """Validated URL representation used by policy and fingerprinting."""

    url: str
    host: str
    port: int
    path: str
    query: str

    @property
    def summary(self) -> str:
        """Return a query-free audit label that cannot disclose query content."""

        return f"{self.host}{self.path}"


def _reject_unsafe_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if not address.is_global:
        raise TargetValidationError("non_public_address")


def validate_resolved_addresses(addresses: Iterable[str]) -> tuple[str, ...]:
    """Require every DNS answer to be globally routable.

    The provider transport uses one returned literal address as the TCP
    destination while retaining the configured hostname for HTTP Host, TLS SNI,
    and certificate verification. User-target URLs delegated to an external
    provider remain subject to that provider's independent resolution policy.
    """

    normalized: set[str] = set()
    for answer_count, raw in enumerate(addresses, start=1):
        if answer_count > _MAXIMUM_DNS_ANSWERS:
            raise TargetValidationError("too_many_dns_answers")
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise TargetValidationError("invalid_dns_answer") from exc
        _reject_unsafe_ip(address)
        normalized.add(address.compressed)
    if not normalized:
        raise TargetValidationError("host_did_not_resolve")
    return tuple(sorted(normalized))


def _normalize_host(raw_host: str) -> str:
    host = raw_host.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("invalid_hostname") from exc
    if not host or len(host) > 253:
        raise TargetValidationError("invalid_hostname")
    if host == "localhost" or host.endswith(_BLOCKED_HOST_SUFFIXES):
        raise TargetValidationError("local_hostname")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if "." not in host:
            raise TargetValidationError("single_label_hostname") from None
        labels = host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
            for label in labels
        ):
            raise TargetValidationError("invalid_hostname") from None
    else:
        _reject_unsafe_ip(address)
        host = address.compressed
    return host


def _decode_unreserved(match: re.Match[str]) -> str:
    character = chr(int(match.group(1), 16))
    return character if character in _UNRESERVED else match.group(0).upper()


def _normalize_path(raw_path: str) -> str:
    if "\\" in raw_path:
        raise TargetValidationError("backslash_in_path")
    path = _PERCENT_ESCAPE.sub(_decode_unreserved, raw_path or "/")
    if re.search(r"%(?![0-9A-Fa-f]{2})", path):
        raise TargetValidationError("invalid_percent_escape")
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in {"", "."}:
            continue
        if segment == "..":
            raise TargetValidationError("path_traversal")
        segments.append(segment)
    normalized = "/" + "/".join(segments)
    if raw_path.endswith("/") and normalized != "/":
        normalized += "/"
    return quote(normalized, safe="/%:@!$&'()*+,;=-._~")


def canonicalize_public_url(value: str) -> CanonicalTarget:
    """Validate and canonicalize one outbound HTTPS URL without DNS I/O."""

    if not isinstance(value, str) or not 9 <= len(value) <= 2_048:
        raise TargetValidationError("invalid_length")
    if _CONTROL_OR_SPACE.search(value) or "\\" in value:
        raise TargetValidationError("control_or_space")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise TargetValidationError("invalid_url") from exc
    if parsed.scheme.lower() != "https":
        raise TargetValidationError("https_required")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("embedded_credentials")
    if parsed.fragment:
        raise TargetValidationError("fragment_forbidden")
    if not parsed.hostname:
        raise TargetValidationError("missing_hostname")
    host = _normalize_host(parsed.hostname)
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise TargetValidationError("invalid_port") from exc
    if port != 443:
        raise TargetValidationError("non_standard_port")
    path = _normalize_path(parsed.path)
    try:
        query_items = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=False,
            max_num_fields=100,
        )
    except ValueError as exc:
        raise TargetValidationError("invalid_query") from exc
    if any(len(key) > 500 or len(item) > 2_000 for key, item in query_items):
        raise TargetValidationError("query_component_too_long")
    query = urlencode(sorted(query_items), doseq=True)
    netloc = f"[{host}]" if ":" in host else host
    url = urlunsplit(("https", netloc, path, query, ""))
    return CanonicalTarget(url=url, host=host, port=port, path=path, query=query)
