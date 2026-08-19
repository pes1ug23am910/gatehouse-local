"""Server-side feed-set resolution and strict target authorization."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType
from urllib.parse import quote, unquote_to_bytes, urlsplit, urlunsplit

from gatehouse.config import FeedSetConfig

from .models import AuthorizedTarget, TargetRequest

_DANGEROUS_ESCAPE = re.compile(r"%(?:25|2e|2f|5c)", re.IGNORECASE)
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_MAX_TARGET_URL_BYTES = 8_192


class FeedSetResolutionError(LookupError):
    """Raised when a caller names an unconfigured feed set."""


class TargetNotAllowedError(PermissionError):
    """Raised when a URL/operation pair is outside a feed-set allowlist."""


class FeedSetRegistry:
    """Immutable server-side mapping from feed-set ID to validated config."""

    def __init__(self, configs: Mapping[str, FeedSetConfig] | Iterable[FeedSetConfig]) -> None:
        if isinstance(configs, Mapping):
            resolved = dict(configs)
            for key, config in resolved.items():
                if key != config.feed_set.id:
                    raise ValueError("feed-set registry key does not match the configured ID")
        else:
            resolved = {}
            for config in configs:
                feed_set_id = str(config.feed_set.id)
                if feed_set_id in resolved:
                    raise ValueError("feed-set IDs must be unique")
                resolved[feed_set_id] = config
        if not resolved:
            raise ValueError("at least one feed set must be configured")
        self._configs: Mapping[str, FeedSetConfig] = MappingProxyType(resolved)

    def resolve(self, feed_set_id: str) -> FeedSetConfig:
        try:
            return self._configs[feed_set_id]
        except KeyError as error:
            raise FeedSetResolutionError("feed set is not configured") from error


def _canonical_host(host: str) -> str:
    try:
        normalized = host.rstrip(".").encode("idna").decode("ascii").casefold()
    except UnicodeError as error:
        raise TargetNotAllowedError("target hostname is invalid") from error
    if not normalized:
        raise TargetNotAllowedError("target hostname is missing")
    return normalized


def _canonical_path(raw_path: str) -> str:
    path = raw_path or "/"
    if not path.startswith("/") or _CONTROL_CHARACTER.search(path):
        raise TargetNotAllowedError("target path is invalid")
    if "\\" in path or _DANGEROUS_ESCAPE.search(path):
        raise TargetNotAllowedError("dangerous encoded path characters are not allowed")
    try:
        decoded = unquote_to_bytes(path).decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise TargetNotAllowedError("target path is not valid UTF-8") from error
    if _CONTROL_CHARACTER.search(decoded) or "\\" in decoded:
        raise TargetNotAllowedError("target path contains prohibited characters")
    if any(segment in {".", ".."} for segment in decoded.split("/")):
        raise TargetNotAllowedError("dot path segments are not allowed")
    return decoded


def authorize_target(
    config: FeedSetConfig,
    request: TargetRequest,
) -> AuthorizedTarget:
    """Authorize one HTTPS URL against exact operation, host, and path rules."""

    if not request.operation or _CONTROL_CHARACTER.search(request.operation):
        raise TargetNotAllowedError("operation is invalid")
    if not request.url or len(request.url.encode("utf-8")) > _MAX_TARGET_URL_BYTES:
        raise TargetNotAllowedError("target URL is empty or exceeds the size limit")
    try:
        parsed = urlsplit(request.url)
        port = parsed.port
    except ValueError as error:
        raise TargetNotAllowedError("target URL is malformed") from error
    if parsed.scheme.casefold() != "https":
        raise TargetNotAllowedError("only HTTPS targets are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise TargetNotAllowedError("target URL user information is not allowed")
    if parsed.fragment:
        raise TargetNotAllowedError("target URL fragments are not allowed")
    if port not in {None, 443}:
        raise TargetNotAllowedError("target URL uses a non-HTTPS port")
    host = _canonical_host(parsed.hostname or "")
    path = _canonical_path(parsed.path)

    for rule in config.allowed_targets:
        exact_host = host == rule.host
        permitted_subdomain = config.crawl.allow_subdomains and host.endswith(f".{rule.host}")
        if not (exact_host or permitted_subdomain):
            continue
        if request.operation not in rule.operations:
            continue
        if re.fullmatch(rule.path_regex, path) is None:
            continue
        normalized_path = quote(path, safe="/:@-._~!$&'()*+,;=")
        normalized_query = "" if config.crawl.ignore_query_parameters else parsed.query
        normalized_url = urlunsplit(("https", host, normalized_path, normalized_query, ""))
        return AuthorizedTarget(
            operation=request.operation,
            normalized_url=normalized_url,
            matched_host=rule.host,
            matched_path_regex=rule.path_regex,
        )
    raise TargetNotAllowedError("target is outside the feed-set allowlist")
