'use strict';

class SecureKitError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

/** A token failed to parse or authenticate. Deliberately uninformative. */
class InvalidToken extends SecureKitError {}

/** The token names a key id that is not in the keyring. */
class UnknownKeyError extends InvalidToken {}

/** No active secret with that name (or version). */
class SecretNotFoundError extends SecureKitError {}

/** The vault file fails its integrity checks: edited, truncated or mixed up outside the application. */
class TamperedVaultError extends SecureKitError {}

/** Another process holds the vault lock and did not release it in time. */
class VaultLockedError extends SecureKitError {}

/** A vault already exists at that path. */
class VaultExistsError extends SecureKitError {}

/** The passphrase (or recovery key) does not unlock this user vault. */
class WrongPassphraseError extends SecureKitError {}

module.exports = {
  SecureKitError,
  InvalidToken,
  UnknownKeyError,
  SecretNotFoundError,
  TamperedVaultError,
  VaultLockedError,
  VaultExistsError,
  WrongPassphraseError,
};
