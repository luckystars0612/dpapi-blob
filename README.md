# DPAPI Blob Decryptor

Small, single-file utility to decrypt Windows DPAPI blobs using a provided masterkey. It wraps impacket's DPAPI_BLOB to perform the decryption and prints the plaintext in multiple encodings for convenience.

## Features
- Accepts DPAPI blob as base64 or hex, via CLI argument or file
- Accepts masterkey as hex, via CLI argument or file
- Outputs decrypted data as UTF-8 (if decodable), hex, and base64
- Clear logging and error messages

## Requirements
- Python 3.8+
- impacket (provides `impacket.dpapi.DPAPI_BLOB`)

Install dependencies (recommended in a virtual environment):

```bash
python -m venv .venv
. .venv/Scripts/activate  # PowerShell: .venv\Scripts\Activate.ps1; CMD: .venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install impacket
```

On Linux/macOS shells, activate with `source .venv/bin/activate`.

## Usage

Show help:

```bash
python decrypt.py -h
```

Basic usage with inline values:

```bash
# Blob can be base64 or hex; masterkey must be hex
python decrypt.py \
  --blob "<BLOB_BASE64_OR_HEX>" \
  --masterkey "<MASTERKEY_HEX>"
```

Using files as inputs:

```bash
# Files should contain raw text of the respective encodings
python decrypt.py \
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

## Practical notes
- Getting the masterkey: This script assumes you already have the correct masterkey bytes (hex). Obtaining DPAPI masterkeys typically involves Windows-specific procedures and is out of scope for this tool. Common sources include live system context, domain backup keys, or other forensic tools.
- Keep your masterkeys secure. Avoid pasting secrets into shared terminals or shell history.

## Examples

Blob as base64 string, masterkey as hex string:

```bash
python decrypt.py -b "AQAA..." -m "4f3a...c9"
```

Blob in file, masterkey inline:

```bash
python decrypt.py -bf blob.txt -m "4f3a...c9"
```

Both from files:

```bash
python decrypt.py -bf blob.txt -mf masterkey.txt
```

## Logging
The script uses standard logging with an INFO level default:
```
%(asctime)s - %(levelname)s - %(message)s
```

## Project structure
- `decrypt.py` — main CLI utility
- `README.md` — this documentation

## License
No license file is provided in this repository.

## Acknowledgments
- [impacket](https://github.com/fortra/impacket) for DPAPI blob parsing/decryption primitives
