# DPAPI Blob Decryptor

Small, single-file utility to decrypt Windows DPAPI blobs using a provided masterkey. It wraps impacket's DPAPI_BLOB to perform the decryption and prints the plaintext in multiple encodings for convenience.

## Features
- Accepts DPAPI blob as base64 or hex, via CLI argument or file
- Accepts masterkey as hex, via CLI argument or file
- Outputs decrypted data as UTF-8 (if decodable), hex, and base64
- Clear logging and error messages

## Install (recommended: pipx)
Using pipx provides an isolated environment and exposes a global `dpapi-blob` command.

1) Install pipx (if not installed):
- Windows (PowerShell):
  - `python -m pip install --user pipx`
  - `python -m pipx ensurepath` (restart terminal afterward)
- Linux/macOS:
  - `python3 -m pip install --user pipx`
  - `python3 -m pipx ensurepath` (restart shell afterward)

2) Install this tool from GitHub:
```
pipx install git+https://github.com/luckystars0612/dpapi-blob.git
```

3) Upgrade later:
```
pipx upgrade dpapi-blob
```

4) Uninstall:
```
pipx uninstall dpapi-blob
```

Alternative: install from a local checkout of this repository:
```
# from the repository root where pyproject.toml is located
pipx install .
```

## Usage

Show help:
```
dpapi-blob -h
```

Basic usage with inline values:
```
# Blob can be base64 or hex; masterkey must be hex
dpapi-blob \
  --blob "<BLOB_BASE64_OR_HEX>" \
  --masterkey "<MASTERKEY_HEX>"
```

Using files as inputs:
```
dpapi-blob \
  --blob-file path/to/blob.txt \
  --masterkey-file path/to/masterkey.txt
```

Mixing sources is supported (e.g., `--blob` with `--masterkey-file`).

### Input formats
- Blob: base64 (preferred) or hex-encoded string
- Masterkey: hex-encoded string

The tool will try base64 decode first for the blob; if that fails, it falls back to hex. The masterkey is decoded as hex only.

### Output
On success, the tool logs the decrypted data in several encodings:
- UTF-8 (if decodable)
- Hex
- Base64

Example output:
```
YYYY-MM-DD HH:MM:SS,mmm - INFO - Decrypted data:
YYYY-MM-DD HH:MM:SS,mmm - INFO - UTF-8  : example-plaintext
YYYY-MM-DD HH:MM:SS,mmm - INFO - Hex    : 6578616d706c652d706c61696e74657874
YYYY-MM-DD HH:MM:SS,mmm - INFO - Base64 : ZXhhbXBsZS1wbGFpbnRleHQ=
```

### Exit codes
- 0: Decryption succeeded
- 1: Error (invalid input, file not found, decode failure, or decryption failure)

## Alternative installation (pip/virtualenv)
If you prefer not to use pipx:
```
python -m venv .venv
. .venv/Scripts/activate  # PowerShell: .venv\Scripts\Activate.ps1; CMD: .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install .
```
Then run `dpapi-blob ...`, or invoke directly without installing: `python decrypt.py ...`.

## Practical notes
- Getting the masterkey: You can extract masterkeys with Impacket's `dpapi.py` or other tooling. When `dpapi.py` prints a value like `MasterKey: 0x<hex>`, pass only the hex characters to this tool (strip the leading `0x`). This script assumes you already have the correct masterkey bytes (hex). Obtaining DPAPI masterkeys typically involves Windows-specific procedures and is out of scope for this tool. Common sources include live system context, domain backup keys, or other forensic tools.
- Keep your masterkeys secure. Avoid pasting secrets into shared terminals or shell history.

## Logging
The script uses standard logging with an INFO level default:
```
%(asctime)s - %(levelname)s - %(message)s
```

## Project structure
- `decrypt.py` — main CLI utility
- `pyproject.toml` — packaging metadata and entry point
- `README.md` — this documentation

## License
No license file is provided in this repository.

## Acknowledgments
- [impacket](https://github.com/fortra/impacket) for DPAPI blob parsing/decryption primitives
