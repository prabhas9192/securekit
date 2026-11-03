'use strict';
// securekit: a thin, opinionated layer over node:crypto. No primitives are implemented here.
// See ../../SPEC.md for the wire formats shared with the Python package.

const { context, normalizeText } = require('./encoding');
const errors = require('./errors');
const { BlindIndexer } = require('./blind');
const { FieldCipher } = require('./fields');
const { Keyring, generateKey } = require('./keys');
const { hashPassword, needsRehash, verifyPassword } = require('./passwords');
const { RecordSealer } = require('./seal');
const { Signer } = require('./signing');
const { constantTimeEquals, randomToken } = require('./tokens');
const { UserVault } = require('./uservault');
const { Vault } = require('./vault');

module.exports = {
  ...errors,
  BlindIndexer,
  FieldCipher,
  Keyring,
  RecordSealer,
  Signer,
  UserVault,
  Vault,
  constantTimeEquals,
  context,
  generateKey,
  hashPassword,
  needsRehash,
  normalizeText,
  randomToken,
  verifyPassword,
};
