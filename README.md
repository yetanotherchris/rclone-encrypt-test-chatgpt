# cli-chatgpt-go
A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

(Remove this details below for hardcore mode)
Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 for the filenames.
- scrypt for keymaterial.

## Installation

**Homebrew (macOS/Linux)**
```bash
brew tap yetanotherchris/cli-chatgpt https://github.com/yetanotherchris/cli-chatgpt
brew install cli
```

**Scoop (Windows)**
```powershell
scoop bucket add cli-chatgpt https://github.com/yetanotherchris/cli-chatgpt
scoop install cli
```

## Examples

### Encrypting a file

The CLI prompts for a password and an optional salt (press Enter to use the built-in salt).

```bash
cli encrypt -i TEST_FILE.txt
```

Want to control the destination path? Use `-o` and the CLI will still print the encoded filename so you can track it.

### Decrypting by filename encoding

Filenames are encrypted with AES/EME and encoded using base32 by default. Use `--filename-encoding` to match the encoding if you stored the file name differently.

```bash
cli decrypt -i kr9tu4e1da4u3nifdd99g9tf5o -o TEST_FILE.txt
cli decrypt -i Iyxcijgc9bp3o5Y0npW6xqUvwWNcc3MA4SadB0sR6cY --filename-encoding base64 -o TEST_FILE.txt
```

### Passing a password from the CLI

For automation you can use `--password`, but the CLI prints a warning because the value may be visible in shell history or process lists. Prefer the `RCLONE_ENCRYPT_PASSWORD` environment variable or type the password when prompted.

```bash
cli encrypt -i TEST_FILE.txt --password 'Testpassword1'
```

## Environment variables

- `RCLONE_ENCRYPT_PASSWORD` — skip the interactive prompt by exporting the password.
- `RCLONE_ENCRYPT_SALT` — provide a custom salt without retyping it on every run. Leave it unset to use the built-in salt (same as rclone).

## Details

- **Data encryption**: NaCl SecretBox (XSalsa20 + Poly1305) with a 24-byte nonce and the `RCLONE\x00\x00` magic header that rclone uses.
- **Filename encryption**: AES-EME with PKCS7 padding; the CLI supports base32, base64, and base32768 encodings to stay compatible with different remotes.
- **Key derivation**: scrypt with `N=16384`, `r=8`, `p=1`, producing 80 bytes of key material (32 for data, 32 for names, 16 for tweak) just like rclone.
- **Defaults**: If no salt is supplied, the tool reuses rclone's built-in salt, so decrypting rclone files works out of the box.

## Building from Source

Requires Go 1.25+. Clone this repository and build the binary directly.

```bash
git clone https://github.com/yetanotherchris/cli-chatgpt
cd cli-chatgpt
go build -o cli .
```

## Testing

```bash
go test ./...
```

## Releases

Pushing a `vX.Y.Z` tag triggers the [Build and Release workflow](.github/workflows/build-release.yml), which cross-compiles binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64). The release job uploads the artifacts, creates a GitHub Release, and uses [`updatescoop.ps1`](updatescoop.ps1) plus [`updatebrew.ps1`](updatebrew.ps1) to refresh the Scoop manifest (`cli.json`) and Homebrew formula (`Formula/cli.rb`).
