# disconcert

TLS certificate/DNS consistency checker. Scans IPs or CIDR ranges, retrieves
TLS certificate common names, and verifies that DNS for each CN resolves back
to the original IP.

## Installation

### Nix

```
nix run github:illustris/disconcert -- 1.1.1.1
```

Or install into your profile:

```
nix profile install github:illustris/disconcert
```

### From source

```
cd src && go build -o disconcert .
```

## Usage

```
disconcert [flags] <ip-or-cidr> [...]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d` | system resolver | Custom DNS server (e.g. `8.8.8.8`) |
| `-p` | `443` | TLS port to connect to |
| `-t` | `5s` | Connection and DNS timeout |
| `-w` | `32` | Number of concurrent workers |

### Examples

Scan a single IP:

```
disconcert 1.1.1.1
```

Scan a CIDR range with a custom DNS server:

```
disconcert -d 8.8.8.8 198.51.100.0/28
```

Scan multiple targets on a non-standard port:

```
disconcert -p 8443 10.0.0.1 10.0.0.2 192.168.1.0/24
```

## Output format

```
IP              CN                      DNS Result          Status
10.0.0.1        example.com             10.0.0.1            OK
10.0.0.2        old.example.com         -                   FLAGGED: NXDOMAIN
10.0.0.3        moved.example.com       10.0.0.99           FLAGGED: IP mismatch
10.0.0.4        -                       -                   ERROR: connection refused
```

### Statuses

- **OK** - DNS for the certificate CN resolves back to the scanned IP
- **FLAGGED: NXDOMAIN** - the CN does not exist in DNS
- **FLAGGED: IP mismatch** - DNS resolves but not to the scanned IP
- **ERROR** - TLS connection failed or no usable certificate

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All results OK |
| 1 | One or more results flagged or errored |
| 2 | Usage error (bad arguments) |

## How it works

1. Parses each argument as a single IP or CIDR range
2. Expands CIDR ranges to individual host IPs (excluding network/broadcast)
3. Connects to each IP over TLS with certificate verification disabled
4. Extracts the Common Name (CN) from the leaf certificate, falling back to
   the first SAN DNS name if CN is empty
5. Performs a DNS lookup on the CN
6. Compares the resolved addresses against the original IP
7. Reports mismatches as flagged results
