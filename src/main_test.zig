//! Configuration tests for `main.zig` — listener addresses.
//!
//! Separated following the `dmarc_test.zig` precedent already used by this
//! daemon, so `main.zig` reflects the daemon rather than its test fixtures.
//! Pulled into the test build by `main.zig`.
//!
//! Only tests touching ALREADY-PUBLIC symbols live here — `parseDmarcConfig` and
//! `DmarcConfig` were both `pub` before this file existed, so nothing was exported
//! merely to move a test. `getFromDomain`, `addArHeaderSimple` and
//! `addArHeaderFull` are private and their tests stay in `main.zig` deliberately.

const std = @import("std");

const securemilter = @import("securemilter");
const config_mod = securemilter.config;

const main = @import("main.zig");
const parseDmarcConfig = main.parseDmarcConfig;

// The implicit listener binds loopback, never 0.0.0.0.
//
// Until 2026-07-29 it bound 0.0.0.0 and nothing tested it. This daemon decides
// disposition, so a reachable port lets an attacker supply a message whose
// Authentication-Results it will believe -- M-1/X-1 without forging a header -- and
// under p=reject it decides what gets bounced. The milter protocol authenticates
// nobody, so reachability IS authorization.
test "the implicit listener binds loopback, not every interface" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const dmarc_cfg = try parseDmarcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(dmarc_cfg.listen_addresses);
    defer std.testing.allocator.free(dmarc_cfg.dns_nameservers);

    try std.testing.expectEqual(@as(usize, 1), dmarc_cfg.listen_addresses.len);
    switch (dmarc_cfg.listen_addresses[0]) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("127.0.0.1", tcp.host);
            try std.testing.expectEqual(@as(u16, 8894), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}

// A safe default, not a policy override: an operator whose Postfix runs in another
// jail must still be able to ask for a routable socket.
//
// This asserts the host explicitly. It previously checked only that the config
// parsed and that one listener came back, which would still have passed if an
// over-zealous "harden the listener" change had rewritten the operator's 0.0.0.0
// to loopback -- the exact regression the test exists to catch. `cfg` is kept alive
// across the assertion because a host from a `Socket =` line borrows from it.
test "parse config minimal, and an explicit 0.0.0.0 socket is still honoured" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:inbound]
        \\Socket = inet:8894@0.0.0.0
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const dmarc_cfg = try parseDmarcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(dmarc_cfg.listen_addresses);
    defer std.testing.allocator.free(dmarc_cfg.dns_nameservers);

    try std.testing.expectEqualStrings("mail.test.com", dmarc_cfg.authserv_id);
    try std.testing.expectEqual(@as(usize, 1), dmarc_cfg.listen_addresses.len);
    switch (dmarc_cfg.listen_addresses[0]) {
        .tcp => |tcp| {
            try std.testing.expectEqualStrings("0.0.0.0", tcp.host);
            try std.testing.expectEqual(@as(u16, 8894), tcp.port);
        },
        else => return error.TestUnexpectedResult,
    }
}
