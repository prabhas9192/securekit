#!/usr/bin/env node
'use strict';
// Command line: securekit <command>. Secret values are read from stdin, never from arguments.
//   securekit genkey | genkeyring [kid]
//   securekit vault [--file F] [--keyring F] [--actor A] [--audit-reads] init|put|get|list|versions|destroy|delete|rotate-keys|audit|verify ...

const fs = require('node:fs');
const { Keyring, SecureKitError, Vault, generateKey } = require('../src');

const BOOLEAN_FLAGS = new Set(['audit-reads', 'keep-newline', 'json', 'deep', 'help']);
const VALUE_FLAGS = new Set(['file', 'keyring', 'actor', 'retain', 'version']);
const USAGE = [
  'usage: securekit genkey | genkeyring [kid]',
  '       securekit vault [--file F] [--keyring F] [--actor A] [--audit-reads] init|put|get|list|versions|destroy|delete|rotate-keys|audit|verify ...',
].join('\n');

function parse(argv) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '-h' || arg === '--help') {
      flags.help = true;
    } else if (arg === '-f') {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith('-')) throw new RangeError('option -f requires a value');
      flags.file = next;
      i += 1;
    } else if (arg.startsWith('--')) {
      const eq = arg.indexOf('=');
      const key = eq === -1 ? arg.slice(2) : arg.slice(2, eq);
      if (BOOLEAN_FLAGS.has(key)) {
        if (eq !== -1) throw new RangeError(`option --${key} does not take a value`);
        flags[key] = true;
      } else if (VALUE_FLAGS.has(key)) {
        const val = eq === -1 ? argv[i + 1] : arg.slice(eq + 1);
        if (val === undefined || val === '' || (eq === -1 && val.startsWith('-'))) {
          throw new RangeError(`option --${key} requires a value`);
        }
        flags[key] = val;
        if (eq === -1) i += 1;
      } else {
        throw new RangeError(`unknown option: --${key}`);
      }
    } else if (arg.startsWith('-') && arg.length > 1) {
      throw new RangeError(`unknown option: ${arg}`);
    } else {
      positional.push(arg);
    }
  }
  return { positional, flags };
}

function readValue(flags) {
  if (process.stdin.isTTY) throw new RangeError('pipe the secret value on stdin, e.g.  printf %s "$VALUE" | securekit vault put NAME');
  const value = fs.readFileSync(0);
  if (flags['keep-newline']) return value;
  if (value.subarray(-2).toString() === '\r\n') return value.subarray(0, -2);
  return value[value.length - 1] === 0x0a ? value.subarray(0, -1) : value;
}

function vaultCommand(positional, flags) {
  const [sub, name, extra] = positional;
  const file = flags.file || process.env.SECUREKIT_VAULT;
  if (!file) throw new RangeError('give the vault file with --file or the SECUREKIT_VAULT environment variable');
  const keyring = flags.keyring ? Keyring.fromJSON(fs.readFileSync(flags.keyring, 'utf8')) : Keyring.fromEnv();
  const actor = flags.actor || process.env.USER || 'cli';

  if (sub === 'init') {
    Vault.create(file, keyring, { actor });
    console.log(`created ${file}`);
    return;
  }
  const vault = Vault.open(file, keyring, { actor, auditReads: Boolean(flags['audit-reads']) });
  const number = (text) => {
    const n = Number(text);
    if (!Number.isInteger(n)) throw new RangeError('expected a whole number');
    return n;
  };
  switch (sub) {
    case 'put':
      console.log(`stored ${name} version ${vault.put(name, readValue(flags), flags.retain !== undefined ? { retain: number(flags.retain) } : {})}`);
      break;
    case 'get': {
      const value = vault.get(name, flags.version !== undefined ? { version: number(flags.version) } : {});
      process.stdout.write(process.stdout.isTTY ? Buffer.concat([value, Buffer.from('\n')]) : value);
      break;
    }
    case 'list':
      console.log(vault.names().join('\n'));
      break;
    case 'versions':
      for (const v of vault.versions(name)) console.log(`v${v.version}\t${v.state}\tcreated=${v.created}\tby=${v.by}`);
      break;
    case 'destroy':
      vault.destroy(name, number(extra));
      console.log(`destroyed ${name} version ${extra}`);
      break;
    case 'delete':
      vault.delete(name);
      console.log(`deleted ${name}`);
      break;
    case 'rotate-keys':
      console.log(`re-encrypted ${vault.rotateKeys()} secret version(s) under key ${keyring.primaryKid}`);
      break;
    case 'audit':
      if (flags.json) {
        console.log(JSON.stringify(vault.audit().map(({ seal, ...entry }) => entry), null, 2));
      } else {
        for (const e of vault.audit()) console.log([e.seq, e.ts, e.actor, e.action, e.name ?? '-', e.version ?? '-'].join('\t'));
      }
      break;
    case 'verify':
      vault.verify({ deep: Boolean(flags.deep) });
      console.log(`ok: manifest, audit chain${flags.deep ? ' and every secret decrypt' : ''} verified`);
      break;
    default:
      throw new RangeError('usage: securekit vault init|put|get|list|versions|destroy|delete|rotate-keys|audit|verify');
  }
}

function main(argv) {
  try {
    const [command, ...rest] = argv;
    if (command === '-h' || command === '--help') {
      console.log(USAGE);
      return 0;
    }
    const { positional, flags } = parse(rest);
    if (flags.help) {
      console.log(USAGE);
      return 0;
    }
    if (command === 'genkey') console.log(generateKey());
    else if (command === 'genkeyring') {
      const kid = positional[0] || 'k1';
      console.log(JSON.stringify({ primary: kid, keys: { [kid]: generateKey() } }, null, 2));
    } else if (command === 'vault') vaultCommand(positional, flags);
    else {
      console.error(USAGE);
      return 2;
    }
    return 0;
  } catch (error) {
    console.error(`securekit: ${error.message}`);
    return error instanceof SecureKitError ? 1 : 2;
  }
}

process.exitCode = main(process.argv.slice(2));
