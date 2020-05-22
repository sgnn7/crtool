# crtool
Helper tooling for certificate management

Benefits:
- Static binary builds
- Does not require any host tools/packages

## Installation

### Linux

Install one of the packages (`.deb` or `.rpm` from the [releases page](https://github.com/sgnn7/crtool/releases))

Or install manually:
- Replace `${VERSION}` with the appropriate release version (e.g. `0.0.2`)
- Download the `crtool`:
```sh-session
wget -O crtool https://github.com/sgnn7/crtool/releases/download/v${VERSION}/crtool_linux && \
  chmod +x ./crtool
```

### macOS

- Replace `${VERSION}` with the appropriate release version (e.g. `0.0.2`)
- Download the `crtool`:
```sh-session
wget -O crtool https://github.com/sgnn7/crtool/releases/download/v${VERSION}/crtool_darwin && \
  chmod +x ./crtool
```

### Windows

- Replace `${VERSION}` with the appropriate release version (e.g. `0.0.2`)
- Download the `crtool`:
```sh-session
wget -O crtool.exe https://github.com/sgnn7/crtool/releases/download/v${VERSION}/crtool.exe
```

## Usage

### `crtool -t <target [-p port] [-o file] dump`

Dump certifcates of target server to output. Works with self-signed certificates!

Dump certifates from an https server to stdout:
```sh-session
crtool -t google.com dump
```

Dump certifates from an https server into a file:
```sh-session
crtool -t google.com -o certs.txt dump
```

Dump certifates from an https server on a custom port into a file:
```sh-session
crtool -t google.com -p 8443 -o certs.txt dump
```

Dump certifates from an https server and pass it to another program
```sh-session
crtool -t google.com -p 8443 dump | cat
```
