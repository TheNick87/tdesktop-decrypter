import os
import sys
import json
import argparse

from datetime import datetime
from typing import Dict, Any, List, Optional

from .cache import CacheException
from .crypto import CryptoException
from .file_io import LegacyTdataException
from .stored_files import (
    KIND_MEDIA,
    KINDS,
    AccountFiles,
    StoredFile,
    StoredFileException,
    extract,
    parse_stored_file_id,
)
from .decrypter import (
    ParsedTdata,
    TdataReader,
    ParsedAccount,
    SettingsBlock,
    NoKeyFileException,
)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def display_accounts(accounts: Dict[int, ParsedAccount]):
    for account in accounts.values():
        print(f"Account {account.index}:")

        print("MTP data:")
        print(f"User ID: {account.mtp_data.user_id}")
        print(f"Main DC ID: {account.mtp_data.current_dc_id}")

        for dc_id, key in account.mtp_data.keys.items():
            print(f"Key DC {dc_id}: {key.hex()}")


def display_setting_value(setting: Any) -> str:
    if isinstance(setting, bytes):
        return setting.hex()

    if isinstance(setting, dict):
        return {k: display_setting_value(v) for k, v in setting.items()}

    if isinstance(setting, list):
        return [display_setting_value(v) for v in setting]

    assert any(isinstance(setting, c) for c in (int, float, str))
    return setting


def display_settings(settings: Optional[Dict[SettingsBlock, Any]]):
    if settings is None:
        print("No settings found.")
        return

    for setting_block, value in settings.items():
        print(f"{setting_block}: {display_setting_value(value)}")


def display_stdout(parsed_tdata: ParsedTdata, show_settings: bool):
    display_accounts(parsed_tdata.accounts)

    if show_settings:
        display_settings(parsed_tdata.settings)


def display_json(parsed_tdata: ParsedTdata):
    accounts = [
        {
            "index": account.index,
            "user_id": account.mtp_data.user_id,
            "main_dc_id": account.mtp_data.current_dc_id,
            "dc_auth_keys": {
                dc_id: key.hex().lower() for dc_id, key in account.mtp_data.keys.items()
            },
        }
        for account in parsed_tdata.accounts.values()
    ]

    if parsed_tdata.settings is None:
        settings = None
    else:
        settings = {
            str(k): display_setting_value(v) for k, v in parsed_tdata.settings.items()
        }

    obj = {
        "accounts": accounts,
        "settings": settings,
    }

    # Settings
    print(json.dumps(obj, indent=4))

def format_size(size: Optional[int]) -> str:
    if size is None:
        return "?"

    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024

    return f"{size:.1f} GB"


def format_time(timestamp: Optional[int]) -> str:
    if not timestamp:
        return ""

    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")


def stored_file_details(stored: StoredFile) -> str:
    details = []
    if stored.kind == KIND_MEDIA:
        size = format_size(stored.size)
        if stored.known_size:
            size += f" of {format_size(stored.known_size)}"
        details.append(f"{size} in {stored.chunks} chunks")
    else:
        details.append(format_size(stored.size))

    for detail in (
        format_time(stored.time),
        stored.label,
        stored.tag,
        stored.extension,
        "partial" if stored.partial else None,
        stored.original_name,
    ):
        if detail:
            details.append(detail)

    return ", ".join(details)


def stored_file_json(stored: StoredFile) -> Dict[str, Any]:
    return {
        "id": stored.id,
        "kind": stored.kind,
        "size": stored.size,
        "time": stored.time,
        "label": stored.label,
        "tag": stored.tag,
        "extension": stored.extension,
        "partial": stored.partial,
        "original_name": stored.original_name,
        "known_size": stored.known_size,
        "chunks": stored.chunks,
    }


def open_accounts(args) -> List[AccountFiles]:
    reader = TdataReader(args.tdata)
    parsed_tdata = reader.read(args.passcode)

    accounts = []
    for index, parsed_account in parsed_tdata.accounts.items():
        account = AccountFiles(reader.io, index, reader.dataname, parsed_tdata.local_key)
        account.user_id = parsed_account.mtp_data.user_id
        accounts.append(account)

    return accounts


def command_info(args):
    parsed_tdata = TdataReader(args.tdata).read(args.passcode)

    if args.json:
        display_json(parsed_tdata)
    else:
        display_stdout(parsed_tdata, args.show_settings)


def command_list(args):
    kinds = [args.kind] if args.kind else KINDS
    accounts = [
        account
        for account in open_accounts(args)
        if args.account is None or account.index == args.account
    ]

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "index": account.index,
                        "user_id": account.user_id,
                        "files": [stored_file_json(f) for f in account.list(kinds)],
                    }
                    for account in accounts
                ],
                indent=4,
            )
        )
        return

    for account in accounts:
        files = account.list(kinds)
        print(f"Account {account.index} (user {account.user_id}):")
        for stored in files:
            print(f"  {stored.id}  {stored_file_details(stored)}")


def command_extract(args):
    index, kind, key = parse_stored_file_id(args.stored_file_id)

    accounts = {account.index: account for account in open_accounts(args)}
    if index not in accounts:
        raise StoredFileException(f"no account {index} in this tdata")

    result = extract(accounts[index], kind, key, args.out_dir, args.force, args.chunks)

    if args.json:
        obj = stored_file_json(result.stored)
        obj["path"] = result.path
        if result.reassembly is not None:
            obj["size"] = result.reassembly.end
            obj["size_known"] = result.reassembly.size is not None
            obj["covered"] = result.reassembly.covered()
            obj["gaps"] = result.reassembly.gaps()
            obj["chunk_paths"] = result.chunk_paths
        print(json.dumps(obj, indent=4))
        return

    print(f"Extracted {result.stored.id} to {result.path}")

    reassembly = result.reassembly
    if reassembly is not None:
        if reassembly.size is None:
            size = f"size unknown, >= {format_size(reassembly.end)}"
        else:
            size = format_size(reassembly.size)

        covered = reassembly.covered()
        percent = 100 * covered / reassembly.end if reassembly.end else 0
        gaps = reassembly.gaps()
        print(
            f"Covered {format_size(covered)} of {size} ({percent:.1f}%), "
            f"{len(gaps)} gap{'s' if len(gaps) != 1 else ''} filled with zeros"
        )
        for offset, length in gaps:
            print(f"  gap at {offset}: {format_size(length)}")

        for chunk_path in result.chunk_paths:
            print(f"Chunk: {chunk_path}")


COMMANDS = ("info", "list", "extract")


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("tdata", type=str, help="Path to tdata/ directory")
    common.add_argument(
        "--passcode", "-p", type=str, default=None, required=False, help="Passcode"
    )
    common.add_argument("--json", "-j", action="store_true", help="Output JSON")

    parser = argparse.ArgumentParser(prog="tdesktop-decrypter")
    commands = parser.add_subparsers(dest="command", required=True)

    info = commands.add_parser(
        "info", parents=[common], help="Show accounts' MTP auth data (default)"
    )
    info.add_argument(
        "--show_settings",
        action="store_true",
        help="Show decrypted settings",
    )
    info.set_defaults(handler=command_info)

    list_ = commands.add_parser(
        "list", parents=[common], help="List every account's stored files"
    )
    list_.add_argument("--account", type=int, default=None, help="Only this account index")
    list_.add_argument("--kind", choices=KINDS, default=None, help="Only this kind")
    list_.set_defaults(handler=command_list)

    extract_ = commands.add_parser(
        "extract", parents=[common], help="Decrypt one stored file into a folder"
    )
    extract_.add_argument(
        "stored_file_id", help="Stored-file ID as printed by list, e.g. 1/cache/<key>"
    )
    extract_.add_argument("out_dir", help="Folder to write the file into")
    extract_.add_argument("--force", action="store_true", help="Overwrite existing files")
    extract_.add_argument(
        "--chunks",
        action="store_true",
        help="For media documents, also dump each decrypted chunk",
    )
    extract_.set_defaults(handler=command_extract)

    return parser


def main(argv: Optional[List[str]] = None):
    if argv is None:
        argv = sys.argv[1:]

    # Without a command, behave as before: show accounts' MTP auth data.
    if argv and argv[0] not in COMMANDS and argv[0] not in ("-h", "--help"):
        argv = ["info"] + argv

    args = build_parser().parse_args(argv)

    try:
        args.handler(args)
    except BrokenPipeError:
        # The reader went away (e.g. `| head`): stop quietly.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
    except NoKeyFileException:
        eprint("No key file was found. Is the tdata path correct?")
        sys.exit(1)
    except (
        StoredFileException,
        CacheException,
        CryptoException,
        LegacyTdataException,
    ) as exc:
        eprint(f"Error: {exc}")
        sys.exit(1)
