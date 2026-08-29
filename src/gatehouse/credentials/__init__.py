"""Credential custody interfaces and built-in KeyStore backends."""

from .base import (
    CredentialAlreadyExistsError,
    CredentialGenerationMismatchError,
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyStore,
    KeyStoreError,
    SecretLease,
    SecretLeaseExpiredError,
    UnsupportedKeyStorePlatformError,
)
from .composite import CompositeKeyStore
from .dpapi import DpapiCurrentUserKeyStore
from .installation import derive_installation_key, load_or_create_installation_key
from .lease import ZeroingSecretLease
from .memory import InMemoryKeyStore
from .overlap import ActiveSecretInspectionUnavailable, ActiveSecretOverlapInspector
from .redaction import SecretDetectedError, SecretFinding, SecretScanner

__all__ = [
    "ActiveSecretInspectionUnavailable",
    "ActiveSecretOverlapInspector",
    "CredentialAlreadyExistsError",
    "CredentialGenerationMismatchError",
    "CredentialMetadata",
    "CredentialNotFoundError",
    "CredentialUnavailableError",
    "CompositeKeyStore",
    "DpapiCurrentUserKeyStore",
    "InMemoryKeyStore",
    "KeyStore",
    "KeyStoreError",
    "SecretDetectedError",
    "SecretFinding",
    "SecretLease",
    "SecretLeaseExpiredError",
    "SecretScanner",
    "UnsupportedKeyStorePlatformError",
    "ZeroingSecretLease",
    "derive_installation_key",
    "load_or_create_installation_key",
]
