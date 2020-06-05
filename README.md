# crtool
Helper tooling for certificate management

Benefits:
- Static binary builds
- Does not require any host tools/packages

## Installation

### Linux

Install one of the packages (`.deb` or `.rpm` from the [releases page](https://github.com/sgnn7/crtool/releases))

Or install manually:
- Replace `${VERSION}` with the appropriate release version (e.g. `0.0.3`)
- Download the `crtool`:
```sh-session
wget -O crtool https://github.com/sgnn7/crtool/releases/download/v${VERSION}/crtool_linux && \
  chmod +x ./crtool
```

### macOS

- Replace `${VERSION}` with the appropriate release version (e.g. `0.0.3`)
- Download the `crtool`:
```sh-session
wget -O crtool https://github.com/sgnn7/crtool/releases/download/v${VERSION}/crtool_darwin && \
  chmod +x ./crtool
```

### Windows

- Replace `${VERSION}` with the appropriate release version (e.g. `0.0.3`)
- Download the `crtool`:
```sh-session
wget -O crtool.exe https://github.com/sgnn7/crtool/releases/download/v${VERSION}/crtool.exe
```

## Usage

- [`crtool verify`](#crtool-verify)
- [`crtool dump`](#crtool-dump)

### `crtool verify`

Verify certifcates of target server

```sh-session
crtool verify -t <target> [-p port]
```

_Note: This command supports verification of file-provided PEM certs too if you
specify the `file://` schema:_
```sh-session
crtool verify -t file://path/to/file.crt
```

Currently this verifies per connection:
- Hostname
- System's CA certificate chain
- Issuer's CN
- Issuer's Signature

Currently this verifies per-cert fields:
- NotBefore
- NotAfter

#### Examples

Verify an expired cert
```sh-session
crtool verify -t expired.badssl.com
```

Verify a valid cert
```sh-session
crtool verify -t expired.badssl.com
```

Verify certificate(s) in a file
```sh-session
crtool verify -t file://server.crt
```

### `crtool dump`

Dump certifcates of target server to output. Works with self-signed certificates!

```sh-session
crtool dump -t <target> [-p port] [-o file] [-e < pem | der >]
```

_Note: This command supports using file-provided PEM-encoded certs if you specify the
`file://` schema which is useful in transcoding._
```sh-session
crtool dump -t file://server.pem -o server.der -e der
```

#### Examples

Dump certifates from an https server to stdout in PEM encoding:
```sh-session
crtool dump -t google.com
```

Dump certifates from an https server into a file:
```sh-session
crtool dump -t google.com -o certs.txt
```

Dump leaf certifate from an https server into a file in DER encoding:
```sh-session
crtool dump -t google.com -o cert.der -e der
```

Dump certifates from an https server on a custom port into a file:
```sh-session
crtool dump -t google.com -p 8443 -o certs.txt
```

Dump certificates from an https server and pass it to another program
```sh-session
crtool dump -t google.com | cat
```
