# Telegram Desktop tdata decrypter
Inspired by [telegram-desktop-decrypt](https://github.com/atilaromero/telegram-desktop-decrypt)

## Features
- Accounts MTP auth data decryption (User ID, DC ID, DC keys)
- Settings decryption
- Listing and extracting every account's stored files: account-folder files, cache entries, streamed media documents and other media-cache entries

## Installation
Install with pipx (recommended):
```bash
pipx install git+https://github.com/ntqbit/tdesktop-decrypter.git
```

Install with pip:
```bash
pip install git+https://github.com/ntqbit/tdesktop-decrypter.git
```

## Usage
Run as executable:
```bash
tdesktop-decrypter arguments
```
Or run as python module (only with pip installation):
```bash
python -m tdesktop_decrypter arguments
```

### Commands
- `info` (default when no command is given) - show accounts' MTP auth data
- `list` - list every account's stored files
- `extract` - decrypt one stored file into a folder

### Arguments
- `tdata` - path to tdata folder containing `settings` (or `settings`) and `key_*` files
- `--passcode`, `-p` - an optional passcode for data decryption
- `--json`, `-j` - JSON output
- `info --show_settings` - show decrypted settings
- `list --account N` / `list --kind account|cache|media|media-entry` - filter the listing
- `extract <stored-file-id> <out_dir>` - the ID is printed by `list`, e.g. `1/cache/<32 hex>` or `1/media/<document id>`
- `extract --force` - overwrite existing files
- `extract --chunks` - for media documents, also dump each decrypted chunk

Telegram Desktop locks the cache while it runs: quit it before `list` or `extract`.

Media documents are rebuilt from the streamed parts that were cached; parts never played are missing and are filled with zeros. `extract` reports the coverage.

### Example
```bash
$ tdesktop-decrypter /path/to/tdata -p passcode

Account 0:
MTP data:
User ID: 12345
Main DC ID: 1
Key DC 1: aabbccdd...


$ tdesktop-decrypter /path/to/tdata -p passcode -j

{
    "accounts": [
        {
            "index": 0,
            "user_id": 12345,
            "main_dc_id": 1,
            "dc_auth_keys": {
                "1": "aabbccdd..."
            }
        }
    ],
    "settings": null
}
```

## Todo (not yet implemented)
- Parse the contents of account-folder files (drafts, stickers, ...); `extract` writes their raw decrypted bytes
- Decode `dbiApplicationSettings` setting block

## Tests
```bash
python -m unittest discover -s tests -t .
```

## Useful links
- https://github.com/atilaromero/telegram-desktop-decrypt

- https://github.com/MihaZupan/TelegramStorageParser
