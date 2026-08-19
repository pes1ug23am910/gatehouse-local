"""Credential custody interfaces and built-in KeyStore backends."""

from .base import (
    CredentialMetadata,
    CredentialNotFoundError,
    CredentialUnavailableError,
    KeyStore,
    KeyStoreError,
    SecretLease,
    SecretLeaseExpiredError,
    UnsupportedKeyStorePlatformError,
)
from .dpapi import DpapiCurrentUserKeyStore
from .installation import derive_installation_key, load_or_create_installation_key
from .lease import ZeroingSecretLease
from .memory import InMemoryKeyStore
from .redaction import SecretDetectedError, SecretFinding, SecretScanner

__all__ = [
    "CredentialMetadata",
    "CredentialNotFoundError",
    "CredentialUnavailableError",
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
