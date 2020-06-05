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

Currently this verifies per connection:
- Hostname
- System's CA certificate chain

Currently this verifies per-cert fields:
- NotBefore
- NotAfter

Example:
```sh-session
crtool verify -t expired.badssl.com
```

### `crtool dump`

Dump certifcates of target server to output. Works with self-signed certificates!

```sh-session
crtool dump -t <target> [-p port] [-o file] [-e < pem | der >]
```

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
