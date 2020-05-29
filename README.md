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

### `crtool -t <target> [-p port] [-o file] [-e < pem | der >] dump`

Dump certifcates of target server to output. Works with self-signed certificates!

Dump certifates from an https server to stdout in PEM encoding:
```sh-session
crtool -t google.com dump
```

Dump certifates from an https server into a file:
```sh-session
crtool -t google.com -o certs.txt dump
```

Dump leaf certifate from an https server into a file in DER encoding:
```sh-session
crtool -t google.com -o cert.der -e der dump
```

Dump certifates from an https server on a custom port into a file:
```sh-session
crtool -t google.com -p 8443 -o certs.txt dump
```

Dump certificates from an https server and pass it to another program
```sh-session
crtool -t google.com -p 8443 dump | cat
```
