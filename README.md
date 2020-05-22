# crtool
Helper tooling for certificate management

Benefits:
- Static binary builds
- Does not require any host tools/packages

## Usage

### `crtool -t <target [-p port] dump`

Dump certifcates of target server to output. Works with self-signed certificates!

Dump certifates from an https server to stdout:
```sh-session
crtool -t google.com dump
```

Dump certifates from an https server into a file:
```sh-session
crtool -t google.com dump > certs.txt
```

Dump certifates from an https server on a custom port into a file:
```sh-session
crtool -t google.com -p 8443 dump > certs.txt
```
