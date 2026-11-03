class SecureKitError(Exception):
    """Base class for securekit errors."""


class InvalidToken(SecureKitError):
    """A token failed to parse or authenticate. Deliberately uninformative."""


class UnknownKeyError(InvalidToken):
    """The token names a key id that is not in the keyring."""


class SecretNotFoundError(SecureKitError):
    """No active secret with that name (or version)."""


class TamperedVaultError(SecureKitError):
    """The vault file fails its integrity checks: it was edited, truncated or mixed up outside the application."""


class VaultLockedError(SecureKitError):
    """Another process holds the vault lock and did not release it in time."""


class VaultExistsError(SecureKitError):
    """A vault already exists at that path."""


class WrongPassphraseError(SecureKitError):
    """The passphrase (or recovery key) does not unlock this user vault."""


class TamperedRowError(SecureKitError):
    """A sealed row no longer matches its seal: a sealed column was changed outside the application."""
