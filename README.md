# SecureDMARC

High-performance DMARC policy evaluation milter for Postfix, implementing RFC 7489.

## Overview

SecureDMARC evaluates DMARC policies by reading upstream SPF and DKIM Authentication-Results headers, fetching the sender domain's `_dmarc.` TXT record, and checking identifier alignment (strict and relaxed). It adds its own Authentication-Results header with the DMARC verdict (pass/fail/none) and publishes evaluation events via ZMQ for aggregate reporting.

**Must run AFTER SecureSPF and SecureDKIM** in the Postfix milter chain so their A-R headers are available.

## Features

- **Full RFC 7489 compliance** — policy lookup, alignment checks, subdomain policies
- **Strict and relaxed alignment** for both SPF and DKIM identifiers
- **Thread-per-core architecture** with kqueue I/O multiplexing
- **DNS resolution** with per-worker TTL caching and proactive health monitoring
- **Multi-listener** support (TCP and Unix domain sockets)
- **ZMQ event publishing** for aggregate reporting pipeline
- **SIGHUP reload** without dropping connections

## Quick Start

```sh
# Build
zig build

# Create user and directories
pw useradd _dmarc -d /nonexistent -s /usr/sbin/nologin
mkdir -p /var/run/securedmarc /usr/local/etc/securedmarc
chown _dmarc:_dmarc /var/run/securedmarc

# Write config
cat > /usr/local/etc/securedmarc/securedmarc.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = _dmarc
PidFile         = /var/run/securedmarc/securedmarc.pid
DnsNameserver   = 127.0.0.1

[listener:inbound]
Socket          = inet:8894@0.0.0.0
EOF

# Install and start
cp zig-out/bin/securedmarc /usr/local/sbin/
securedmarc -c /usr/local/etc/securedmarc/securedmarc.conf
```

## Configuration Reference

### [global]

| Option | Default | Description |
|--------|---------|-------------|
| `AuthservID` | `localhost` | A-R header identifier (must match SPF/DKIM) |
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `PidFile` | `/var/run/securedmarc/securedmarc.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `dmarc.evaluation` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | — | `inet:port@host` or `unix:/path` |

## Postfix Integration

```ini
smtpd_milters = inet:127.0.0.1:8890,
                inet:127.0.0.1:8891,
                inet:127.0.0.1:8894
milter_connect_macros = j {daemon_name} v {client_addr}
milter_default_action = accept
```

> **Important**: The `AuthservID` must match across all milters in the chain so SecureDMARC can find upstream SPF/DKIM results.

### Milter Chain Ordering

Order: **SPF (8890) → DKIM (8891) → DMARC (8894) → ARC (8895)**

## Signals

- **SIGHUP** — Reload configuration
- **SIGTERM** — Graceful shutdown (30s drain timeout)

## Part of the SecureMilter Suite

- [securemilter-lib](https://pacyworld.dev/securemessage/securemilter-lib) — Shared infrastructure library
- [SecureSPF](https://pacyworld.dev/securemessage/securespf) — SPF verification
- [SecureDKIM](https://pacyworld.dev/securemessage/securedkim) — DKIM signing and verification
- **SecureDMARC** — DMARC policy evaluation (this project)
- [SecureARC](https://pacyworld.dev/securemessage/securearc) — ARC chain validation and sealing

## Requirements

- Zig 0.15.x
- FreeBSD (kqueue/kevent)
- Postfix with milter support (`milter_protocol = 6`)

## License

BSD-2-Clause. Copyright (c) 2026 Daniel Morante.
