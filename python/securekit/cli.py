"""Command line: python -m securekit <command>. Secret values are read from stdin or a hidden prompt, never from arguments."""

import argparse
import getpass
import json
import os
import sys

from .errors import SecureKitError
from .keys import Keyring, generate_key
from .vault import Vault


def _keyring(args) -> Keyring:
    if args.keyring:
        with open(args.keyring, "r", encoding="utf-8") as handle:
            return Keyring.from_json(handle.read())
    return Keyring.from_env()


def _vault_path(args) -> str:
    path = args.file or os.environ.get("SECUREKIT_VAULT")
    if not path:
        raise ValueError("give the vault file with --file or the SECUREKIT_VAULT environment variable")
    return path


def _actor(args) -> str:
    return args.actor or os.environ.get("USER") or "cli"


def _read_value(args) -> bytes:
    if sys.stdin.isatty():
        return getpass.getpass("secret value (hidden): ").encode("utf-8")
    value = sys.stdin.buffer.read()
    if not args.keep_newline:
        value = value[:-2] if value.endswith(b"\r\n") else value[:-1] if value.endswith(b"\n") else value
    return value


def _vault_command(args) -> int:
    path, ring, actor = _vault_path(args), _keyring(args), _actor(args)
    if args.vault_command == "init":
        Vault.create(path, ring, actor=actor)
        print(f"created {path}")
        return 0
    vault = Vault.open(path, ring, actor=actor, audit_reads=args.audit_reads)
    if args.vault_command == "put":
        print(f"stored {args.name} version {vault.put(args.name, _read_value(args), retain=args.retain)}")
    elif args.vault_command == "get":
        value = vault.get(args.name, version=args.version)
        sys.stdout.buffer.write(value + (b"\n" if sys.stdout.isatty() else b""))
        sys.stdout.buffer.flush()
    elif args.vault_command == "list":
        print("\n".join(vault.names()))
    elif args.vault_command == "versions":
        for item in vault.versions(args.name):
            print(f"v{item['version']}\t{item['state']}\tcreated={item['created']}\tby={item['by']}")
    elif args.vault_command == "destroy":
        vault.destroy(args.name, args.version)
        print(f"destroyed {args.name} version {args.version}")
    elif args.vault_command == "delete":
        vault.delete(args.name)
        print(f"deleted {args.name}")
    elif args.vault_command == "rotate-keys":
        print(f"re-encrypted {vault.rotate_keys()} secret version(s) under key {ring.primary_kid}")
    elif args.vault_command == "audit":
        entries = vault.audit()
        if args.json:
            print(json.dumps([{k: v for k, v in e.items() if k != 'seal'} for e in entries], indent=2))
        else:
            for e in entries:
                print(f"{e['seq']}\t{e['ts']}\t{e['actor']}\t{e['action']}\t{e['name'] or '-'}\t{e['version'] or '-'}")
    elif args.vault_command == "verify":
        vault.verify(deep=args.deep)
        print("ok: manifest, audit chain" + (" and every secret decrypt" if args.deep else "") + " verified")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="securekit")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("genkey", help="print a new root key")
    genring = commands.add_parser("genkeyring", help="print a new keyring as JSON")
    genring.add_argument("kid", nargs="?", default="k1")

    vault = commands.add_parser("vault", help="app secrets vault")
    vault.add_argument("--file", "-f", help="vault file (or SECUREKIT_VAULT)")
    vault.add_argument("--keyring", help="keyring JSON file (default: SECUREKIT_KEYRING)")
    vault.add_argument("--actor", help="name recorded in the audit log (default: $USER)")
    vault.add_argument("--audit-reads", action="store_true", help="also audit reads (rewrites the file on every read)")
    sub = vault.add_subparsers(dest="vault_command", required=True)
    sub.add_parser("init")
    put = sub.add_parser("put")
    put.add_argument("name")
    put.add_argument("--retain", type=int, default=10)
    put.add_argument("--keep-newline", action="store_true")
    get = sub.add_parser("get")
    get.add_argument("name")
    get.add_argument("--version", type=int)
    sub.add_parser("list")
    sub.add_parser("versions").add_argument("name")
    destroy = sub.add_parser("destroy")
    destroy.add_argument("name")
    destroy.add_argument("version", type=int)
    sub.add_parser("delete").add_argument("name")
    sub.add_parser("rotate-keys")
    audit = sub.add_parser("audit")
    audit.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify")
    verify.add_argument("--deep", action="store_true", help="also decrypt every active secret")

    scan = commands.add_parser("scan", help="scan a codebase for places that need encryption")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "never"], default="high")
    scan.add_argument("--include-tests", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "genkey":
            print(generate_key())
        elif args.command == "genkeyring":
            print(json.dumps({"primary": args.kid, "keys": {args.kid: generate_key()}}, indent=2))
        elif args.command == "vault":
            return _vault_command(args)
        elif args.command == "scan":
            from .scan import run_cli

            return run_cli(args)
        return 0
    except SecureKitError as error:
        print(f"securekit: {error}", file=sys.stderr)
        return 1
    except (ValueError, OSError) as error:
        print(f"securekit: {error}", file=sys.stderr)
        return 2
