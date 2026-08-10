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

# Create directories (mailnull is the shared FreeBSD milter account other
# milters already run as -- no dedicated user needed)
mkdir -p /var/run/securedmarc /usr/local/etc/securedmarc

# Write config
cat > /usr/local/etc/securedmarc/securedmarc.conf << 'EOF'
[global]
AuthservID      = mail.example.com
User            = mailnull
PidFile         = /var/run/securedmarc/securedmarc.pid
DnsNameserver   = 127.0.0.1

[listener:inbound]
Socket          = inet:8894@127.0.0.1
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
| `StripAuthResults` | `no` | Remove pre-existing Authentication-Results headers claiming our `AuthservID`; enable only where no other SecureMilter daemon precedes this one |
| `PublicSuffixList` | *(unset)* | Path to a Public Suffix List file, used only to veto a DNS tree-walk result. Deprecated, expected to be removed once `psd=` is widely deployed |
| `WorkerThreads` | `0` (auto) | Worker thread count (0 = CPU count) |
| `MaxConnections` | `256` | Max simultaneous connections per worker |
| `PidFile` | `/var/run/securedmarc/securedmarc.pid` | PID file path |
| `Foreground` | `no` | Run in foreground (no daemonize) |
| `User` | *(none)* | Drop privileges to this user |
| `UMask` | *(inherited)* | File-creation mask (octal) for the PID file and any unix-domain listener |
| `Syslog` | `yes` | Enable syslog output |
| `SyslogFacility` | `mail` | Syslog facility |
| `LogLevel` | `info` | Log level: err, warn, info, debug |
| `DnsNameserver` | `127.0.0.1` | Comma-separated nameserver IPs |
| `DnsTimeout` | `5` | DNS timeout in seconds |
| `DnsRetries` | `2` | DNS retry count |
| `DnsCacheSize` | `1000` | Per-worker DNS cache max entries |
| `DnsNegativeTTL` | `60` | Negative cache TTL in seconds |
| `MaxHeaders` | `500` | Largest number of headers accumulated per message; 0 disables the limit |
| `MaxHeaderBytes` | `1M` | Largest total header size per message; 0 disables the limit |
| `MaxEvaluationMs` | `20000` | Wall-clock ceiling for evaluating one message; 0 disables it |
| `ApplyPct` | `no` | Honor a published deprecated `pct=` tag (RFC 9989 transition aid) |
| `ZmqEndpoint` | *(disabled)* | ZMQ PUB endpoint |
| `ZmqTopic` | `dmarc.evaluation` | ZMQ topic prefix |

### [listener:name]

| Option | Default | Description |
|--------|---------|-------------|
| `Socket` | — | `inet:port@ip` or `unix:/path`. The IP must be numeric (no DNS). An unparseable value is a fatal startup error, never ignored. |

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

## CLI Tools

### securedmarc-check

Evaluate DMARC for a set of already-authenticated SPF/DKIM identifiers, calling the same policy, tree-walk, alignment, and disposition code path the daemon uses. Takes identifiers directly on the command line rather than a message file:

```sh
securedmarc-check --from example.com --mailfrom example.com --spf pass \
    --dkim example.com --dkim-result pass
```

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
