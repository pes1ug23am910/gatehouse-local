"""Bounded, read-only Windows configuration capture without pathname rereads."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping
from contextlib import ExitStack
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from pathlib import Path, PureWindowsPath
from types import MappingProxyType
from typing import Any, Literal, Protocol

MAXIMUM_CONFIG_FILES = 64
MAXIMUM_DIRECTORY_ENTRIES = 128
MAXIMUM_FILE_BYTES = 1_048_576
MAXIMUM_AGGREGATE_BYTES = 4_194_304
MAXIMUM_MANIFEST_BYTES = 4_194_304
MAXIMUM_ANCESTRY_COMPONENTS = 64
MAXIMUM_PATH_TEXT = 65_536
_MAXIMUM_WINDOWS_PATH = 32_767
_MAXIMUM_SECURITY_BYTES = 65_536
_MAXIMUM_ACES = 128
_MAXIMUM_ENVIRONMENT_TEXT = 65_536
_DIRECTORIES = ("clients", "policies", "feeds")
_ENVIRONMENT_NAMES = frozenset({"APPDATA", "LOCALAPPDATA"})
_SID_PATTERN = re.compile(r"S-1-[0-9]+(?:-[0-9]+){0,15}\Z")
_OWNER_RIGHTS_SID = "S-1-3-4"
_TRUSTED_OS_SIDS = frozenset(
    {
        "S-1-5-18",
        "S-1-5-32-544",
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
    }
)
_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"|?*~')
_RESERVED_COMPONENT_STEMS = frozenset(
    {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{index}" for index in range(1, 10)),
        *(f"LPT{index}" for index in range(1, 10)),
        *(f"COM{index}" for index in "¹²³"),
        *(f"LPT{index}" for index in "¹²³"),
    }
)
_FILE_ALL_ACCESS = 0x001F01FF
# Ancestors are retained by identity without delete sharing. Creating a sibling
# name cannot replace an already opened component; the private root and every
# configuration object still require their exact owner-only descriptors.
_ANCESTOR_MUTATION_ACCESS = 0x000D0150 | 0x50000000
_INHERIT_ONLY_ACE = 0x08
_KNOWN_ACE_FLAGS = 0x1F
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_SHARE_READ = 0x00000001
_GENERIC_READ = 0x80000000
_OPEN_EXISTING = 3
_ERROR_NO_MORE_FILES = 18
_ERROR_INSUFFICIENT_BUFFER = 122
_FILE_FULL_DIRECTORY_INFO = 14
_FILE_FULL_DIRECTORY_RESTART_INFO = 15
_ENUMERATION_BUFFER_BYTES = 65_536
_READ_CHUNK_BYTES = 65_536


class ConfigSecurityError(ValueError):
    """A path-free failure of the configuration trust contract."""


@dataclass(frozen=True, slots=True)
class FileIdentity:
    volume_serial: int
    file_id: int


@dataclass(frozen=True, slots=True)
class AccessRule:
    sid: str
    mask: int
    flags: int = 0
    kind: int = 0


@dataclass(frozen=True, slots=True)
class ObjectSecurity:
    identity: FileIdentity
    final_path: str
    is_directory: bool
    owner_sid: str
    dacl: tuple[AccessRule, ...] | None
    dacl_protected: bool
    reparse: bool = False
    link_count: int = 1
    size: int = 0
    creation_time: int = 0
    last_write: int = 0
    filesystem: str = "NTFS"
    drive_type: int = 3


class ConfigurationFilesystem(Protocol):
    execution_sid: str

    def open_existing(self, path: str) -> object: ...

    def describe(self, handle: object) -> ObjectSecurity: ...

    def read(self, handle: object, maximum_bytes: int) -> bytes: ...

    def entries(self, handle: object) -> Iterable[str]: ...

    def close(self, handle: object) -> None: ...


@dataclass(frozen=True, slots=True)
class ConfigurationDocument:
    relative_path: str
    content: bytes = field(repr=False)
    identity: FileIdentity
    sha256: str


@dataclass(frozen=True, slots=True)
class ScriptedConfigurationDocument:
    relative_path: str
    content: bytes = field(repr=False)
    identity: FileIdentity
    sha256: str
    origin: Path
    role: Literal["firecrawl_scripted_responses"] = "firecrawl_scripted_responses"


type ScriptedDocumentSelector = Callable[[bytes, Path, Mapping[str, str]], str | None]


@dataclass(frozen=True, slots=True)
class ConfigurationSnapshot:
    main_path: Path
    main_relative_path: str
    documents: tuple[ConfigurationDocument, ...]
    manifest_digest: str
    bound_environment: tuple[tuple[str, str], ...] = field(repr=False)
    scripted_document: ScriptedConfigurationDocument | None = None
    manifest_bytes: bytes = field(default=b"", repr=False)

    def document(self, relative_path: str) -> ConfigurationDocument:
        for document in self.documents:
            if document.relative_path == relative_path:
                return document
        raise ConfigSecurityError("configuration snapshot document is unavailable")

    def matches_main_path(self, path: str | Path) -> bool:
        try:
            return str(_absolute_lexical_path(path)) == str(self.main_path)
        except ConfigSecurityError:
            return False


def _valid_component(component: str) -> bool:
    return bool(
        component
        and component not in {".", ".."}
        and not component.endswith((" ", "."))
        and not any(
            ord(character) < 32 or 0xD800 <= ord(character) <= 0xDFFF for character in component
        )
        and not any(character in _FORBIDDEN_COMPONENT_CHARACTERS for character in component)
        and "\\" not in component
        and "/" not in component
        and component.split(".", 1)[0].rstrip(" .").upper() not in _RESERVED_COMPONENT_STEMS
    )


def _absolute_lexical_path(path: str | Path) -> PureWindowsPath:
    raw = str(path)
    if not raw or len(raw) > _MAXIMUM_WINDOWS_PATH or raw.startswith(("\\\\", "//")):
        raise ConfigSecurityError("configuration path is not a supported local path")
    candidate = PureWindowsPath(raw)
    if not candidate.is_absolute() or len(candidate.drive) != 2 or candidate.drive[1] != ":":
        raise ConfigSecurityError("configuration requires an absolute local Windows path")
    raw_components = raw.replace("/", "\\").split("\\")[1:]
    if any(component in {".", ".."} for component in raw_components):
        raise ConfigSecurityError("configuration path contains an unsupported alias")
    if not all(_valid_component(component) for component in candidate.parts[1:]):
        raise ConfigSecurityError("configuration path contains an unsupported alias")
    return PureWindowsPath(candidate.drive.upper() + "\\", *candidate.parts[1:])


def scripted_sibling_path(main_path: str | Path, raw: str) -> Path:
    """Validate one exact sibling spelling without resolving or reading it."""

    main = _absolute_lexical_path(main_path)
    if type(raw) is not str or not raw or len(raw) > _MAXIMUM_WINDOWS_PATH:
        raise ConfigSecurityError("scripted configuration origin is invalid")
    if _valid_component(raw):
        candidate = main.parent / raw
    else:
        components = raw.replace("/", "\\").split("\\")
        if (
            len(components) < 2
            or components[0] != main.drive
            or any(not _valid_component(component) for component in components[1:])
        ):
            raise ConfigSecurityError("scripted configuration origin is not an exact sibling")
        candidate = _absolute_lexical_path(raw)
        if str(candidate.parent) != str(main.parent):
            raise ConfigSecurityError("scripted configuration origin is not an exact sibling")
    if candidate.name.casefold() == main.name.casefold():
        raise ConfigSecurityError("scripted configuration cannot reuse the main document")
    if len(str(candidate)) > _MAXIMUM_WINDOWS_PATH:
        raise ConfigSecurityError("scripted configuration origin exceeds its path bound")
    return Path(str(candidate))


def require_snapshot_manifest_binding(snapshot: ConfigurationSnapshot) -> None:
    """Check retained document fields against the captured canonical manifest."""

    try:
        raw = snapshot.manifest_bytes
        if type(raw) is not bytes or not 0 < len(raw) <= MAXIMUM_MANIFEST_BYTES:
            raise ConfigSecurityError("configuration manifest binding is unavailable")
        if hashlib.sha256(raw).hexdigest() != snapshot.manifest_digest:
            raise ConfigSecurityError("configuration manifest binding does not match its digest")
        bindings = snapshot.bound_environment
        if (
            type(bindings) is not tuple
            or len(bindings) > len(_ENVIRONMENT_NAMES)
            or any(
                type(item) is not tuple
                or len(item) != 2
                or any(type(value) is not str for value in item)
                for item in bindings
            )
            or sum(len(name) + len(value) for name, value in bindings) > _MAXIMUM_ENVIRONMENT_TEXT
            or _bound_environment(dict(bindings)) != bindings
        ):
            raise ConfigSecurityError("configuration expansion binding is inconsistent")
        manifest = json.loads(raw.decode("utf-8"))
        attachment = snapshot.scripted_document
        keys = {"version", "main_path", "environment", "objects", "memberships", "documents"}
        if attachment is not None:
            keys.add("scripted_document")
        if (
            not isinstance(manifest, dict)
            or set(manifest) != keys
            or type(manifest["version"]) is not int
            or manifest["version"] != 1
            or json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
            != raw
            or manifest["main_path"] != str(snapshot.main_path)
            or manifest["environment"] != [list(item) for item in snapshot.bound_environment]
            or snapshot.main_relative_path != snapshot.main_path.name
        ):
            raise ConfigSecurityError("configuration manifest binding is inconsistent")
        objects = manifest["objects"]
        if not isinstance(objects, list) or not objects:
            raise ConfigSecurityError("configuration object bindings are unavailable")
        object_rows: dict[str, dict[str, object]] = {}
        for row in objects:
            if not isinstance(row, dict) or type(row.get("final_path")) is not str:
                raise ConfigSecurityError("configuration object binding is invalid")
            path = row["final_path"]
            if path in object_rows:
                raise ConfigSecurityError("configuration object binding is ambiguous")
            object_rows[path] = row
        documents = snapshot.documents
        if (
            type(documents) is not tuple
            or not documents
            or len(documents) + int(attachment is not None) > MAXIMUM_CONFIG_FILES
        ):
            raise ConfigSecurityError("configuration document binding exceeds its bound")
        aggregate = 0
        document_rows: list[list[str]] = []
        names: set[str] = set()

        def verify_document(
            content: bytes,
            identity: FileIdentity,
            digest: str,
            origin: str,
        ) -> None:
            nonlocal aggregate
            if type(content) is not bytes or len(content) > MAXIMUM_FILE_BYTES:
                raise ConfigSecurityError("configuration document binding exceeds its byte bound")
            aggregate += len(content)
            row = object_rows.get(origin)
            if (
                aggregate > MAXIMUM_AGGREGATE_BYTES
                or hashlib.sha256(content).hexdigest() != digest
                or type(identity) is not FileIdentity
                or type(identity.volume_serial) is not int
                or type(identity.file_id) is not int
                or row is None
                or row.get("identity") != asdict(identity)
                or row.get("is_directory") is not False
                or row.get("size") != len(content)
            ):
                raise ConfigSecurityError("configuration document binding is inconsistent")

        for document in documents:
            if type(document) is not ConfigurationDocument or document.relative_path in names:
                raise ConfigSecurityError("configuration document binding is ambiguous")
            names.add(document.relative_path)
            origin = str(PureWindowsPath(str(snapshot.main_path.parent)) / document.relative_path)
            verify_document(document.content, document.identity, document.sha256, origin)
            document_rows.append([document.relative_path, document.sha256])
        if snapshot.main_relative_path not in names or manifest["documents"] != document_rows:
            raise ConfigSecurityError("configuration main document binding is inconsistent")
        if attachment is not None:
            if type(attachment) is not ScriptedConfigurationDocument:
                raise ConfigSecurityError("scripted configuration attachment is invalid")
            origin = str(scripted_sibling_path(snapshot.main_path, attachment.relative_path))
            if attachment.role != "firecrawl_scripted_responses" or str(origin) != str(
                attachment.origin
            ):
                raise ConfigSecurityError("scripted configuration origin is inconsistent")
            verify_document(attachment.content, attachment.identity, attachment.sha256, str(origin))
            if manifest["scripted_document"] != {
                "role": attachment.role,
                "origin": str(attachment.origin),
                "relative_path": attachment.relative_path,
                "identity": asdict(attachment.identity),
                "sha256": attachment.sha256,
            }:
                raise ConfigSecurityError("scripted configuration binding is inconsistent")
    except ConfigSecurityError:
        raise
    except (AttributeError, TypeError, ValueError, OverflowError, RecursionError):
        raise ConfigSecurityError("configuration manifest binding is invalid") from None


def _bound_environment(environment: Mapping[str, str] | None) -> tuple[tuple[str, str], ...]:
    values: dict[str, str] = {}
    if environment is None:
        source = {name: os.environ.get(name) for name in _ENVIRONMENT_NAMES}
    else:
        source = {
            name: environment[name] for name in environment if name.upper() in _ENVIRONMENT_NAMES
        }
    for name, value in source.items():
        if value is None:
            continue
        normalized = name.upper()
        if not isinstance(value, str) or any(character in value for character in "\x00\n\r"):
            raise ConfigSecurityError("configuration expansion context is invalid")
        if normalized in values and values[normalized] != value:
            raise ConfigSecurityError("configuration expansion context is ambiguous")
        values[normalized] = value
    if sum(len(name) + len(value) for name, value in values.items()) > _MAXIMUM_ENVIRONMENT_TEXT:
        raise ConfigSecurityError("configuration expansion context exceeds its bound")
    return tuple(sorted(values.items()))


def _valid_sid(value: str) -> bool:
    return (
        isinstance(value, str) and len(value) <= 184 and _SID_PATTERN.fullmatch(value) is not None
    )


def _check_security(
    observed: ObjectSecurity,
    *,
    expected_path: str,
    directory: bool,
    private: bool,
    execution_sid: str,
) -> None:
    if (
        observed.drive_type != 3
        or observed.filesystem != "NTFS"
        or observed.reparse
        or observed.is_directory is not directory
        or (not directory and observed.link_count != 1)
        or observed.identity.file_id <= 0
        or observed.identity.volume_serial < 0
        or observed.final_path != expected_path
        or not _valid_sid(observed.owner_sid)
        or observed.size < 0
    ):
        raise ConfigSecurityError("configuration object identity or filesystem is untrusted")
    acl = observed.dacl
    if acl is None or len(acl) > _MAXIMUM_ACES:
        raise ConfigSecurityError("configuration object permissions are untrusted")
    trusted = _TRUSTED_OS_SIDS | {execution_sid}
    if observed.owner_sid not in trusted:
        raise ConfigSecurityError("configuration ancestor ownership is untrusted")
    for ace in acl:
        if (
            ace.kind not in {0, 1}
            or not _valid_sid(ace.sid)
            or ace.mask < 0
            or ace.mask > 0xFFFFFFFF
            or ace.flags & ~_KNOWN_ACE_FLAGS
        ):
            raise ConfigSecurityError("configuration access rule is unsupported")
        if (
            not private
            and ace.kind == 0
            and not ace.flags & _INHERIT_ONLY_ACE
            and ace.sid not in trusted
            and not (ace.sid == _OWNER_RIGHTS_SID and observed.owner_sid in trusted)
            and ace.mask & _ANCESTOR_MUTATION_ACCESS
        ):
            raise ConfigSecurityError("configuration ancestry permits untrusted modification")
    if private and (
        observed.owner_sid != execution_sid
        or not observed.dacl_protected
        or acl
        != (AccessRule(sid=execution_sid, mask=_FILE_ALL_ACCESS, flags=3 if directory else 0),)
    ):
        raise ConfigSecurityError("configuration requires protected owner-only permissions")


def _bounded_members(backend: ConfigurationFilesystem, handle: object) -> tuple[str, ...]:
    names: list[str] = []
    aliases: set[str] = set()
    for name in backend.entries(handle):
        if len(names) >= MAXIMUM_DIRECTORY_ENTRIES:
            raise ConfigSecurityError("configuration directory exceeds its entry bound")
        if not isinstance(name, str) or not _valid_component(name) or name.casefold() in aliases:
            raise ConfigSecurityError("configuration directory contains an unsupported alias")
        aliases.add(name.casefold())
        names.append(name)
    return tuple(sorted(names))


def capture_configuration(
    main_path: str | Path,
    *,
    backend: ConfigurationFilesystem | None = None,
    environment: Mapping[str, str] | None = None,
    scripted_document_selector: ScriptedDocumentSelector | None = None,
) -> ConfigurationSnapshot:
    """Capture exact trusted configuration bytes; never create or repair anything."""

    main = _absolute_lexical_path(main_path)
    root = main.parent
    ancestry = tuple(reversed((root, *root.parents)))
    if len(ancestry) > MAXIMUM_ANCESTRY_COMPONENTS:
        raise ConfigSecurityError("configuration ancestry exceeds its bound")
    bound_environment = _bound_environment(environment)
    path_text = sum(len(str(path)) for path in ancestry)
    if path_text > MAXIMUM_PATH_TEXT:
        raise ConfigSecurityError("configuration paths exceed their aggregate bound")
    documents: list[ConfigurationDocument] = []
    objects: list[tuple[object, ObjectSecurity]] = []
    directories: list[tuple[object, tuple[str, ...]]] = []
    aggregate_bytes = 0
    scripted_document: ScriptedConfigurationDocument | None = None
    try:
        selected = backend if backend is not None else NativeConfigurationFilesystem()
        if not _valid_sid(selected.execution_sid):
            raise ConfigSecurityError("configuration execution identity is unavailable")
        with ExitStack() as stack:

            def open_checked(path: PureWindowsPath, *, directory: bool, private: bool) -> object:
                handle = selected.open_existing(str(path))
                stack.callback(selected.close, handle)
                observed = selected.describe(handle)
                _check_security(
                    observed,
                    expected_path=str(path),
                    directory=directory,
                    private=private,
                    execution_sid=selected.execution_sid,
                )
                if (
                    objects
                    and observed.identity.volume_serial != objects[0][1].identity.volume_serial
                ):
                    raise ConfigSecurityError("configuration ancestry crosses a volume boundary")
                objects.append((handle, observed))
                return handle

            root_handle: object | None = None
            for path in ancestry:
                root_handle = open_checked(path, directory=True, private=path == root)
            if root_handle is None:
                raise ConfigSecurityError("configuration root is unavailable")
            root_members = _bounded_members(selected, root_handle)
            directories.append((root_handle, root_members))
            if main.name not in root_members:
                raise ConfigSecurityError("configuration main file is unavailable or aliased")
            candidates = [(main.name, main)]
            for name in root_members:
                if name.casefold() in _DIRECTORIES and name not in _DIRECTORIES:
                    raise ConfigSecurityError("configuration directory name is aliased")
            for name in _DIRECTORIES:
                if name not in root_members:
                    continue
                directory = root / name
                path_text += len(str(directory))
                if path_text > MAXIMUM_PATH_TEXT:
                    raise ConfigSecurityError("configuration paths exceed their aggregate bound")
                handle = open_checked(directory, directory=True, private=True)
                members = _bounded_members(selected, handle)
                directories.append((handle, members))
                for member in members:
                    if PureWindowsPath(member).suffix.casefold() == ".yaml":
                        if len(candidates) >= MAXIMUM_CONFIG_FILES:
                            raise ConfigSecurityError("configuration exceeds its document bound")
                        candidates.append((f"{name}/{member}", directory / member))
            for relative_path, path in sorted(candidates):
                path_text += len(str(path))
                if path_text > MAXIMUM_PATH_TEXT:
                    raise ConfigSecurityError("configuration paths exceed their aggregate bound")
                handle = open_checked(path, directory=False, private=True)
                before = objects[-1][1]
                if (
                    before.size > MAXIMUM_FILE_BYTES
                    or before.size > MAXIMUM_AGGREGATE_BYTES - aggregate_bytes
                ):
                    raise ConfigSecurityError("configuration exceeds its byte bound")
                content = selected.read(handle, MAXIMUM_FILE_BYTES)
                if (
                    not isinstance(content, bytes)
                    or len(content) != before.size
                    or len(content) > MAXIMUM_FILE_BYTES
                ):
                    raise ConfigSecurityError("configuration changed during its bounded read")
                aggregate_bytes += len(content)
                if aggregate_bytes > MAXIMUM_AGGREGATE_BYTES:
                    raise ConfigSecurityError("configuration exceeds its byte bound")
                if selected.describe(handle) != before:
                    raise ConfigSecurityError("configuration object changed during capture")
                documents.append(
                    ConfigurationDocument(
                        relative_path, content, before.identity, hashlib.sha256(content).hexdigest()
                    )
                )
            if scripted_document_selector is not None:
                main_document = next(
                    document for document in documents if document.relative_path == main.name
                )
                selection = scripted_document_selector(
                    main_document.content,
                    Path(str(main)),
                    MappingProxyType(dict(bound_environment)),
                )
                if selection is not None:
                    origin = scripted_sibling_path(Path(str(main)), selection)
                    scripted_path = PureWindowsPath(str(origin))
                    if scripted_path.name not in root_members:
                        raise ConfigSecurityError(
                            "scripted configuration is unavailable or aliased"
                        )
                    if len(documents) >= MAXIMUM_CONFIG_FILES:
                        raise ConfigSecurityError("configuration exceeds its document bound")
                    path_text += len(str(scripted_path))
                    if path_text > MAXIMUM_PATH_TEXT:
                        raise ConfigSecurityError(
                            "configuration paths exceed their aggregate bound"
                        )
                    handle = open_checked(scripted_path, directory=False, private=True)
                    before = objects[-1][1]
                    if (
                        before.size > MAXIMUM_FILE_BYTES
                        or before.size > MAXIMUM_AGGREGATE_BYTES - aggregate_bytes
                    ):
                        raise ConfigSecurityError("configuration exceeds its byte bound")
                    content = selected.read(handle, MAXIMUM_FILE_BYTES)
                    if (
                        type(content) is not bytes
                        or len(content) != before.size
                        or len(content) > MAXIMUM_FILE_BYTES
                    ):
                        raise ConfigSecurityError("configuration changed during its bounded read")
                    aggregate_bytes += len(content)
                    if aggregate_bytes > MAXIMUM_AGGREGATE_BYTES:
                        raise ConfigSecurityError("configuration exceeds its byte bound")
                    if selected.describe(handle) != before:
                        raise ConfigSecurityError("configuration object changed during capture")
                    scripted_document = ScriptedConfigurationDocument(
                        scripted_path.name,
                        content,
                        before.identity,
                        hashlib.sha256(content).hexdigest(),
                        origin,
                    )
            for handle, members in directories:
                if _bounded_members(selected, handle) != members:
                    raise ConfigSecurityError("configuration membership changed during capture")
            for handle, before in objects:
                if selected.describe(handle) != before:
                    raise ConfigSecurityError("configuration object changed during capture")
            object_bindings = []
            for index, (_handle, observed) in enumerate(objects):
                binding = asdict(observed)
                if index < len(ancestry) - 1:
                    # Sibling activity changes ancestor timestamps and size without
                    # changing the captured configuration or its trusted origin.
                    # Full metadata equality above still protects each capture.
                    binding.pop("last_write")
                    binding.pop("size")
                object_bindings.append(binding)
            manifest = {
                "version": 1,
                "main_path": str(main),
                "environment": bound_environment,
                "objects": object_bindings,
                "memberships": [members for _handle, members in directories],
                "documents": [(document.relative_path, document.sha256) for document in documents],
            }
            if scripted_document is not None:
                manifest["scripted_document"] = {
                    "role": scripted_document.role,
                    "origin": str(scripted_document.origin),
                    "relative_path": scripted_document.relative_path,
                    "identity": asdict(scripted_document.identity),
                    "sha256": scripted_document.sha256,
                }
            manifest_bytes = json.dumps(
                manifest,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            if len(manifest_bytes) > MAXIMUM_MANIFEST_BYTES:
                raise ConfigSecurityError("configuration manifest exceeds its byte bound")
            digest = hashlib.sha256(manifest_bytes).hexdigest()
        return ConfigurationSnapshot(
            Path(str(main)),
            main.name,
            tuple(documents),
            digest,
            bound_environment,
            scripted_document,
            manifest_bytes,
        )
    except ConfigSecurityError:
        raise
    except (OSError, AttributeError, TypeError, ValueError, OverflowError):
        raise ConfigSecurityError("configuration trust verification failed") from None


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", ctypes.c_uint32),
        ("created", _FileTime),
        ("accessed", _FileTime),
        ("written", _FileTime),
        ("volume", ctypes.c_uint32),
        ("size_high", ctypes.c_uint32),
        ("size_low", ctypes.c_uint32),
        ("links", ctypes.c_uint32),
        ("index_high", ctypes.c_uint32),
        ("index_low", ctypes.c_uint32),
    ]


class _DirectoryInformation(ctypes.Structure):
    _fields_ = [
        ("next_offset", ctypes.c_uint32),
        ("file_index", ctypes.c_uint32),
        ("created", ctypes.c_int64),
        ("accessed", ctypes.c_int64),
        ("written", ctypes.c_int64),
        ("changed", ctypes.c_int64),
        ("end_of_file", ctypes.c_int64),
        ("allocation_size", ctypes.c_int64),
        ("attributes", ctypes.c_uint32),
        ("name_length", ctypes.c_uint32),
        ("ea_size", ctypes.c_uint32),
    ]


class _AclHeader(ctypes.Structure):
    _fields_ = [
        ("revision", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte),
        ("size", ctypes.c_uint16),
        ("ace_count", ctypes.c_uint16),
        ("reserved_two", ctypes.c_uint16),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [("kind", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("size", ctypes.c_uint16)]


class _RelativeSecurityDescriptor(ctypes.Structure):
    _fields_ = [
        ("revision", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte),
        ("control", ctypes.c_uint16),
        ("owner", ctypes.c_uint32),
        ("group", ctypes.c_uint32),
        ("sacl", ctypes.c_uint32),
        ("dacl", ctypes.c_uint32),
    ]


@dataclass(frozen=True, slots=True)
class _NativeHandle:
    value: int
    path: str


class _Win32Bindings:
    def __init__(self) -> None:
        if os.name != "nt":
            raise ConfigSecurityError("trusted configuration requires Windows fixed NTFS")
        self.kernel32: Any = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
        self.advapi: Any = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        self.ntdll: Any = ctypes.WinDLL("Ntdll.dll", use_last_error=True)
        pointer = ctypes.c_void_p
        signatures: tuple[tuple[Any, str, list[Any], Any], ...] = (
            (
                self.kernel32,
                "CreateFileW",
                [
                    wintypes.LPCWSTR,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    pointer,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.HANDLE,
                ],
                wintypes.HANDLE,
            ),
            (self.kernel32, "CloseHandle", [wintypes.HANDLE], wintypes.BOOL),
            (
                self.kernel32,
                "GetFileInformationByHandle",
                [wintypes.HANDLE, ctypes.POINTER(_FileInformation)],
                wintypes.BOOL,
            ),
            (
                self.kernel32,
                "GetFileInformationByHandleEx",
                [wintypes.HANDLE, ctypes.c_int, pointer, wintypes.DWORD],
                wintypes.BOOL,
            ),
            (
                self.kernel32,
                "GetFinalPathNameByHandleW",
                [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD],
                wintypes.DWORD,
            ),
            (
                self.kernel32,
                "GetVolumeInformationByHandleW",
                [
                    wintypes.HANDLE,
                    wintypes.LPWSTR,
                    wintypes.DWORD,
                    ctypes.POINTER(wintypes.DWORD),
                    ctypes.POINTER(wintypes.DWORD),
                    ctypes.POINTER(wintypes.DWORD),
                    wintypes.LPWSTR,
                    wintypes.DWORD,
                ],
                wintypes.BOOL,
            ),
            (self.kernel32, "GetDriveTypeW", [wintypes.LPCWSTR], wintypes.UINT),
            (
                self.kernel32,
                "ReadFile",
                [wintypes.HANDLE, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), pointer],
                wintypes.BOOL,
            ),
            (self.kernel32, "GetCurrentProcess", [], wintypes.HANDLE),
            (self.kernel32, "LocalFree", [pointer], pointer),
            (
                self.advapi,
                "OpenProcessToken",
                [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)],
                wintypes.BOOL,
            ),
            (
                self.advapi,
                "GetTokenInformation",
                [
                    wintypes.HANDLE,
                    ctypes.c_int,
                    pointer,
                    wintypes.DWORD,
                    ctypes.POINTER(wintypes.DWORD),
                ],
                wintypes.BOOL,
            ),
            (
                self.ntdll,
                "NtQuerySecurityObject",
                [
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    pointer,
                    wintypes.DWORD,
                    ctypes.POINTER(wintypes.DWORD),
                ],
                ctypes.c_int32,
            ),
            (
                self.advapi,
                "GetAce",
                [pointer, wintypes.DWORD, ctypes.POINTER(pointer)],
                wintypes.BOOL,
            ),
        )
        for library, name, arguments, result in signatures:
            function = getattr(library, name)
            function.argtypes = arguments
            function.restype = result

    @staticmethod
    def error_code() -> int:
        return int(ctypes.get_last_error())


def _sid_at(address: int, *, base: int, length: int) -> str:
    if address < base or address > base + length - 8:
        raise ConfigSecurityError("configuration security identifier is malformed")
    header = ctypes.string_at(address, 8)
    count = header[1]
    size = 8 + count * 4
    if header[0] != 1 or count > 15 or address > base + length - size:
        raise ConfigSecurityError("configuration security identifier is malformed")
    raw = ctypes.string_at(address, size)
    authority = int.from_bytes(raw[2:8], "big")
    subauthorities = [
        str(int.from_bytes(raw[index : index + 4], "little")) for index in range(8, size, 4)
    ]
    return "-".join(("S", "1", str(authority), *subauthorities))


class NativeConfigurationFilesystem:
    """Read-only handle adapter; injectable bindings keep native tests deterministic."""

    def __init__(self, *, api: Any = None) -> None:
        self._api = api if api is not None else _Win32Bindings()
        self.execution_sid = self._current_user_sid()

    def _current_user_sid(self) -> str:
        token = wintypes.HANDLE()
        if not self._api.advapi.OpenProcessToken(
            self._api.kernel32.GetCurrentProcess(), 8, ctypes.byref(token)
        ):
            raise ConfigSecurityError("configuration execution identity is unavailable")
        try:
            required = wintypes.DWORD()
            first = self._api.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
            if (
                first
                or self._api.error_code() != _ERROR_INSUFFICIENT_BUFFER
                or not ctypes.sizeof(ctypes.c_void_p) + 8
                <= required.value
                <= _MAXIMUM_SECURITY_BYTES
            ):
                raise ConfigSecurityError("configuration execution identity is unavailable")
            buffer = ctypes.create_string_buffer(required.value)
            if not self._api.advapi.GetTokenInformation(
                token, 1, buffer, len(buffer), ctypes.byref(required)
            ) or not ctypes.sizeof(ctypes.c_void_p) + 8 <= required.value <= len(buffer):
                raise ConfigSecurityError("configuration execution identity is unavailable")
            address = int(ctypes.c_void_p.from_buffer(buffer).value or 0)
            return _sid_at(address, base=ctypes.addressof(buffer), length=required.value)
        finally:
            if not self._api.kernel32.CloseHandle(token):
                raise ConfigSecurityError(
                    "configuration identity handle could not be closed"
                ) from None

    @staticmethod
    def _handle(handle: object) -> _NativeHandle:
        if not isinstance(handle, _NativeHandle):
            raise ConfigSecurityError("configuration handle is invalid")
        return handle

    def open_existing(self, path: str) -> object:
        value = self._api.kernel32.CreateFileW(
            path,
            _GENERIC_READ,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        if value in {None, 0, -1, ctypes.c_void_p(-1).value}:
            raise ConfigSecurityError("configuration object could not be opened safely")
        return _NativeHandle(int(value), path)

    def close(self, handle: object) -> None:
        if not self._api.kernel32.CloseHandle(self._handle(handle).value):
            raise ConfigSecurityError("configuration handle could not be closed")

    def _security(self, handle: int) -> tuple[str, bool, tuple[AccessRule, ...] | None]:
        # NtQuerySecurityObject returns the stored self-relative descriptor into
        # caller-owned memory. Win32 GetSecurityInfo can report a different
        # protection flag for an unchanged child after its parent's ACL changes.
        buffer = ctypes.create_string_buffer(_MAXIMUM_SECURITY_BYTES)
        required = wintypes.DWORD()
        result: object = None
        try:
            result = self._api.ntdll.NtQuerySecurityObject(
                handle,
                5,
                buffer,
                len(buffer),
                ctypes.byref(required),
            )
        except Exception:
            result = None
        if type(result) is not int or result != 0:
            raise ConfigSecurityError("configuration object permissions are unavailable")
        length = required.value
        if not ctypes.sizeof(_RelativeSecurityDescriptor) <= length <= len(buffer):
            raise ConfigSecurityError("configuration security descriptor exceeds its bound")
        base = ctypes.addressof(buffer)
        descriptor = _RelativeSecurityDescriptor.from_buffer(buffer)
        if descriptor.revision != 1 or not descriptor.control & 0x8000:
            raise ConfigSecurityError("configuration security descriptor is malformed")
        if not 20 <= descriptor.owner <= length - 8 or descriptor.owner % 4:
            raise ConfigSecurityError("configuration security identifier is malformed")
        owner_sid = _sid_at(base + descriptor.owner, base=base, length=length)
        protected = bool(descriptor.control & 0x1000)
        if not descriptor.dacl or not descriptor.control & 4:
            return owner_sid, protected, None
        if not 20 <= descriptor.dacl <= length - ctypes.sizeof(_AclHeader) or descriptor.dacl % 4:
            raise ConfigSecurityError("configuration access list is malformed")
        acl_address = base + descriptor.dacl
        dacl = ctypes.c_void_p(acl_address)
        acl = _AclHeader.from_address(acl_address)
        if (
            acl.revision not in {2, 4}
            or acl.ace_count > _MAXIMUM_ACES
            or acl.size < ctypes.sizeof(_AclHeader)
            or acl_address > base + length - acl.size
        ):
            raise ConfigSecurityError("configuration access list exceeds its bound")
        rules: list[AccessRule] = []
        for index in range(acl.ace_count):
            pointer = ctypes.c_void_p()
            if not self._api.advapi.GetAce(dacl, index, ctypes.byref(pointer)):
                raise ConfigSecurityError("configuration access rule is unavailable")
            address = int(pointer.value or 0)
            if (
                address < acl_address + ctypes.sizeof(_AclHeader)
                or address > acl_address + acl.size - 16
            ):
                raise ConfigSecurityError("configuration access rule is malformed")
            header = _AceHeader.from_address(address)
            if (
                header.kind not in {0, 1}
                or header.size < 16
                or address > acl_address + acl.size - header.size
            ):
                raise ConfigSecurityError("configuration access rule is unsupported")
            mask = ctypes.c_uint32.from_address(address + 4).value
            sid = _sid_at(address + 8, base=address, length=header.size)
            rules.append(AccessRule(sid=sid, mask=mask, flags=header.flags, kind=header.kind))
        return owner_sid, protected, tuple(rules)

    def describe(self, handle: object) -> ObjectSecurity:
        native = self._handle(handle)
        information = _FileInformation()
        if not self._api.kernel32.GetFileInformationByHandle(
            native.value, ctypes.byref(information)
        ):
            raise ConfigSecurityError("configuration object identity is unavailable")
        final_buffer = ctypes.create_unicode_buffer(_MAXIMUM_WINDOWS_PATH + 1)
        size = self._api.kernel32.GetFinalPathNameByHandleW(
            native.value, final_buffer, len(final_buffer), 0
        )
        if not 0 < size < len(final_buffer):
            raise ConfigSecurityError("configuration final path is unavailable")
        final_name = final_buffer.value
        if final_name.startswith("\\\\?\\"):
            final_name = final_name[4:]
        final_path = _absolute_lexical_path(final_name)
        filesystem = ctypes.create_unicode_buffer(64)
        serial = wintypes.DWORD()
        maximum_component = wintypes.DWORD()
        flags = wintypes.DWORD()
        if (
            not self._api.kernel32.GetVolumeInformationByHandleW(
                native.value,
                None,
                0,
                ctypes.byref(serial),
                ctypes.byref(maximum_component),
                ctypes.byref(flags),
                filesystem,
                len(filesystem),
            )
            or serial.value != information.volume
        ):
            raise ConfigSecurityError("configuration volume identity is unavailable")
        drive_type = int(self._api.kernel32.GetDriveTypeW(final_path.anchor))
        owner, protected, dacl = self._security(native.value)
        return ObjectSecurity(
            identity=FileIdentity(
                information.volume, (information.index_high << 32) | information.index_low
            ),
            final_path=str(final_path),
            is_directory=bool(information.attributes & _FILE_ATTRIBUTE_DIRECTORY),
            owner_sid=owner,
            dacl=dacl,
            dacl_protected=protected,
            reparse=bool(information.attributes & _FILE_ATTRIBUTE_REPARSE_POINT),
            link_count=information.links,
            size=(information.size_high << 32) | information.size_low,
            creation_time=(information.created.high << 32) | information.created.low,
            last_write=(information.written.high << 32) | information.written.low,
            filesystem=filesystem.value,
            drive_type=drive_type,
        )

    def read(self, handle: object, maximum_bytes: int) -> bytes:
        native = self._handle(handle)
        if type(maximum_bytes) is not int or not 0 < maximum_bytes <= MAXIMUM_FILE_BYTES:
            raise ConfigSecurityError("configuration read bound is invalid")
        output = bytearray()
        while len(output) <= maximum_bytes:
            size = min(_READ_CHUNK_BYTES, maximum_bytes + 1 - len(output))
            if not size:
                break
            buffer = ctypes.create_string_buffer(size)
            read = wintypes.DWORD()
            if (
                not self._api.kernel32.ReadFile(
                    native.value, buffer, size, ctypes.byref(read), None
                )
                or read.value > size
            ):
                raise ConfigSecurityError("configuration bounded read failed")
            if not read.value:
                return bytes(output)
            output.extend(buffer.raw[: read.value])
        raise ConfigSecurityError("configuration file exceeds its byte bound")

    def entries(self, handle: object) -> Iterable[str]:
        native = self._handle(handle)
        observed = 0
        name_offset = _DirectoryInformation.ea_size.offset + ctypes.sizeof(ctypes.c_uint32)
        for batch in range(MAXIMUM_DIRECTORY_ENTRIES + 3):
            buffer = ctypes.create_string_buffer(_ENUMERATION_BUFFER_BYTES)
            information_class = (
                _FILE_FULL_DIRECTORY_RESTART_INFO if batch == 0 else _FILE_FULL_DIRECTORY_INFO
            )
            if not self._api.kernel32.GetFileInformationByHandleEx(
                native.value, information_class, buffer, len(buffer)
            ):
                if self._api.error_code() == _ERROR_NO_MORE_FILES:
                    return
                raise ConfigSecurityError("configuration directory enumeration failed")
            offset = 0
            while True:
                if offset > len(buffer) - name_offset:
                    raise ConfigSecurityError("configuration directory record is malformed")
                header = _DirectoryInformation.from_buffer_copy(
                    buffer.raw[offset : offset + ctypes.sizeof(_DirectoryInformation)]
                )
                name_length = int(header.name_length)
                end = offset + name_offset + name_length
                if not name_length or name_length % 2 or name_length > 510 or end > len(buffer):
                    raise ConfigSecurityError("configuration directory name is malformed")
                try:
                    name = buffer.raw[offset + name_offset : end].decode("utf-16-le")
                except UnicodeDecodeError:
                    raise ConfigSecurityError("configuration directory name is malformed") from None
                observed += 1
                if observed > MAXIMUM_DIRECTORY_ENTRIES + 2:
                    raise ConfigSecurityError("configuration directory exceeds its entry bound")
                if name not in {".", ".."}:
                    yield name
                next_offset = int(header.next_offset)
                if not next_offset:
                    break
                if (
                    next_offset % 8
                    or next_offset < name_offset + name_length
                    or offset + next_offset >= len(buffer)
                ):
                    raise ConfigSecurityError("configuration directory record is malformed")
                offset += next_offset
        raise ConfigSecurityError("configuration directory exceeds its enumeration bound")
