"""Safe, bounded YAML loading for strict configuration models."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver
from yaml.tokens import AliasToken, AnchorToken

from .models import ClientProfileConfig, FeedSetConfig, MainConfig, WorkspacePolicyConfig

DEFAULT_MAX_CONFIG_BYTES = 1_048_576
_ENVIRONMENT_PATTERN = re.compile(r"%([A-Za-z_][A-Za-z0-9_]*)%")
_ALLOWED_ENVIRONMENT_NAMES = frozenset({"APPDATA", "LOCALAPPDATA"})


class ConfigLoadStage(StrEnum):
    READ = "read"
    DECODE = "decode"
    YAML = "yaml"
    ENVIRONMENT = "environment"
    VALIDATION = "validation"


class ConfigLoadError(ValueError):
    """Sanitized configuration failure that does not echo document values."""

    def __init__(self, path: Path, stage: ConfigLoadStage, summary: str) -> None:
        self.path = path
        self.stage = stage
        self.summary = summary
        super().__init__(f"configuration {stage.value} failed for {path.name}: {summary}")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as error:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be scalar and hashable",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "duplicate mapping key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _validation_summary(error: ValidationError) -> str:
    failures: list[str] = []
    for item in error.errors(include_url=False, include_context=False, include_input=False):
        location = ".".join(str(part) for part in item["loc"]) or "document"
        failures.append(f"{location}: {item['type']}")
    return "; ".join(failures[:10])


def _expand_environment_value(value: Any, environment: Mapping[str, str]) -> Any:
    if isinstance(value, str):

        def replace(match: re.Match[str]) -> str:
            name = match.group(1).upper()
            if name not in _ALLOWED_ENVIRONMENT_NAMES:
                raise ValueError(f"environment variable {name!r} is not allowed")
            replacement = environment.get(name)
            if replacement is None or not replacement:
                raise ValueError(f"environment variable {name!r} is not defined")
            if "\x00" in replacement or "\n" in replacement or "\r" in replacement:
                raise ValueError(f"environment variable {name!r} contains invalid characters")
            return replacement

        return _ENVIRONMENT_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_expand_environment_value(item, environment) for item in value]
    if isinstance(value, dict):
        return {key: _expand_environment_value(item, environment) for key, item in value.items()}
    return value


def load_yaml_model[ConfigModelT: BaseModel](
    path: str | Path,
    model_type: type[ConfigModelT],
    *,
    expand_environment: bool = False,
    environment: Mapping[str, str] | None = None,
    maximum_bytes: int = DEFAULT_MAX_CONFIG_BYTES,
) -> ConfigModelT:
    """Read, safely parse, and strictly validate one YAML configuration file."""

    resolved_path = Path(path)
    if isinstance(maximum_bytes, bool) or maximum_bytes <= 0:
        raise ValueError("maximum_bytes must be a positive integer")

    try:
        raw = resolved_path.read_bytes()
    except OSError as error:
        raise ConfigLoadError(resolved_path, ConfigLoadStage.READ, "file is unavailable") from error
    if len(raw) > maximum_bytes:
        raise ConfigLoadError(
            resolved_path,
            ConfigLoadStage.READ,
            "file exceeds the configured size limit",
        )

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ConfigLoadError(
            resolved_path, ConfigLoadStage.DECODE, "file is not valid UTF-8"
        ) from error

    try:
        if any(
            isinstance(token, (AliasToken, AnchorToken))
            for token in yaml.scan(text, Loader=yaml.SafeLoader)
        ):
            raise ConfigLoadError(
                resolved_path,
                ConfigLoadStage.YAML,
                "anchors and aliases are not permitted",
            )
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        suffix = f" near line {mark.line + 1}" if mark is not None else ""
        raise ConfigLoadError(
            resolved_path, ConfigLoadStage.YAML, f"invalid YAML{suffix}"
        ) from error

    try:
        # The custom loader subclasses SafeLoader and only changes duplicate-key handling.
        document = yaml.load(text, Loader=_UniqueKeySafeLoader)  # noqa: S506
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        suffix = f" near line {mark.line + 1}" if mark is not None else ""
        raise ConfigLoadError(
            resolved_path, ConfigLoadStage.YAML, f"invalid YAML{suffix}"
        ) from error
    if not isinstance(document, dict):
        raise ConfigLoadError(
            resolved_path,
            ConfigLoadStage.YAML,
            "document root must be a mapping",
        )

    if expand_environment:
        source = environment if environment is not None else os.environ
        normalized_environment = {str(key).upper(): str(value) for key, value in source.items()}
        try:
            document = _expand_environment_value(document, normalized_environment)
        except ValueError as error:
            raise ConfigLoadError(resolved_path, ConfigLoadStage.ENVIRONMENT, str(error)) from error

    try:
        return model_type.model_validate(document)
    except ValidationError as error:
        raise ConfigLoadError(
            resolved_path,
            ConfigLoadStage.VALIDATION,
            _validation_summary(error),
        ) from error


def load_main_config(
    path: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> MainConfig:
    return load_yaml_model(
        path,
        MainConfig,
        expand_environment=True,
        environment=environment,
    )


def load_client_profile(path: str | Path) -> ClientProfileConfig:
    return load_yaml_model(path, ClientProfileConfig)


def load_feed_set(path: str | Path) -> FeedSetConfig:
    return load_yaml_model(path, FeedSetConfig)


def load_workspace_policy(path: str | Path) -> WorkspacePolicyConfig:
    return load_yaml_model(path, WorkspacePolicyConfig)
