# SecureDMARC

High-performance DMARC policy evaluation milter (RFC 7489) written in Zig.

## Overview

SecureDMARC evaluates DMARC policies by reading upstream SPF and DKIM
Authentication-Results headers, fetching the sender domain's `_dmarc.` TXT
record, and checking identifier alignment. It adds its own A-R header with the
DMARC verdict (pass/fail/none) and publishes evaluation events via ZMQ for
future aggregate reporting.

**Must run AFTER SecureSPF and SecureDKIM** in the Postfix milter chain.

## Build

```sh
zig build
```

## Test

```sh
zig build test
```

## Configuration

```ini
[global]
AuthservID      = mail.example.com
WorkerThreads   = 0
Foreground      = yes
PidFile         = /var/run/securedmarc/securedmarc.pid
DnsNameserver   = 127.0.0.1
DnsTimeout      = 5
DnsRetries      = 2

[listener:inbound]
Socket          = inet:8894@0.0.0.0
```

## Milter Chain Order

```
smtpd_milters = inet:127.0.0.1:8890, inet:127.0.0.1:8891, inet:127.0.0.1:8894
#               securespf              securedkim-verify     securedmarc
```

## License

BSD-2-Clause — see LICENSE.
