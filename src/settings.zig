//! SecureDMARC configuration: the shape of the parsed config and the parser.
//!
//! Split out of `main.zig` at stage 4.2, matching `securearc` and the split
//! `securedkim` took at 4.1. Everything an operator can set in the INI file
//! lands here; `main.zig` copies the parts the workers read into its globals
//! before the pool spawns, and `flow.zig` sees them only through a `MsgCtx`.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;

/// SecureDMARC runtime configuration parsed from INI config.
pub const DmarcConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    /// Per-worker cap on simultaneous connections, enforced in the accept path.
    ///
    /// No default on this field on purpose. It reached the worker as a hard-coded
    /// `DEFAULT_MAX_CONNECTIONS` while `MaxConnections` was already read by
    /// `securespf`, so the same key was honoured by one daemon and silently ignored
    /// by this one (audit L-2). A field that quietly supplies a constant when the
    /// caller forgets to set it is how that happens, so every construction site
    /// states it.
    max_connections: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    dns_nameservers: []const []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    dns_cache_size: u32,
    dns_negative_ttl: u32,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
    strip_auth_results: bool,
    /// Honour a published `pct=` (audit M-4). Off by default; RFC 9989 §A.6
    /// removed the tag.
    apply_pct: bool,
    public_suffix_list: ?[]const u8,
    limits: connection_mod.Limits,
};
/// Parse the SecureDMARC config from a loaded Config.
pub fn parseDmarcConfig(allocator: Allocator, cfg: *const config_mod.Config) !DmarcConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);

    // Read beside `WorkerThreads` because the two are multiplied: `calculateFdNeed`
    // sizes the RLIMIT_NOFILE raise as workers x (max_connections + listeners + 3),
    // so raising either one alone is not the whole change.
    const max_connections = global.getInt("MaxConnections", u32, worker_mod.DEFAULT_MAX_CONNECTIONS);

    const pid_file = global.getOrDefault("PidFile", "/var/run/securedmarc/securedmarc.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;

            // X-14: a malformed or missing Socket is refused, not skipped.
            const addr = try listener_mod.parseListenerSocket(section_name, section.get("Socket"));
            try addrs.append(allocator, addr);
        }
    }

    // Loopback, NOT 0.0.0.0. The milter protocol has no authentication, so anything
    // reaching this socket is trusted absolutely -- and this daemon is the one that
    // decides disposition. A reachable port lets an attacker feed a message whose
    // Authentication-Results it will believe, which is finding M-1/X-1 delivered
    // without needing to forge a header at all, and under p=reject it decides what
    // gets bounced. Postfix is the only intended client and it is local.
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "127.0.0.1", .port = 8894 } });
    }

    // Owned slice, borrowed contents; unlike the ArrayList above it does not
    // unwind itself, so it needs its own `errdefer` for every `try` below.
    const dns_nameservers = try global.getCsvList(allocator, "DnsNameserver", "127.0.0.1");
    errdefer allocator.free(dns_nameservers);
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000;
    const dns_retries = global.getInt("DnsRetries", u8, 2);
    const dns_cache_size = global.getInt("DnsCacheSize", u32, 1000);
    const dns_negative_ttl = global.getInt("DnsNegativeTTL", u32, 60);

    // ZMQ event publishing
    const zmq_endpoint = global.get("ZmqEndpoint");
    const zmq_topic = global.getOrDefault("ZmqTopic", "dmarc.evaluation");

    // Trust boundary. Off by default: DMARC reads the spf= and dkim= results
    // that SecureSPF and SecureDKIM added earlier in the same milter chain, and
    // those carry our authserv-id too. Only enable where no other SecureMilter
    // daemon precedes this one.
    const strip_auth_results = global.getBool("StripAuthResults", false);

    // `pct=` was removed by RFC 9989 §A.6 in favour of `t=`, so the default is to
    // ignore it. An operator running through the transition can switch it back on
    // for domains that have not moved yet (audit M-4).
    const apply_pct = global.getBool("ApplyPct", false);

    // Optional Public Suffix List, used only to veto a tree-walk result.
    const public_suffix_list = global.get("PublicSuffixList");

    // Caps on attacker-controlled message content (audit X-4). DMARC reads the
    // From header and the spf=/dkim= results, so an uninspected header block is
    // exactly what it must not evaluate against.
    const limits = connection_mod.Limits.fromSection(global);

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .max_connections = max_connections,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .dns_nameservers = dns_nameservers,
        .dns_timeout_ms = dns_timeout,
        .dns_retries = dns_retries,
        .dns_cache_size = dns_cache_size,
        .dns_negative_ttl = dns_negative_ttl,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
        .strip_auth_results = strip_auth_results,
        .apply_pct = apply_pct,
        .public_suffix_list = public_suffix_list,
        .limits = limits,
    };
}

// X-14. A malformed Socket must be refused rather than skipped -- and in
// particular must NOT fall through to the loopback default below, which would
// leave the daemon listening somewhere the operator never named while its
// startup log reported success.
test "a malformed listener Socket is refused, not replaced by the default" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:typo]
        \\Socket = inet6:8894@::1
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseDmarcConfig(std.testing.allocator, &cfg));
}

test "a hostname in Socket is refused at config time" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:main]
        \\Socket = inet:8894@localhost
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidListenerSocket, parseDmarcConfig(std.testing.allocator, &cfg));
}

test "a listener section with no Socket is refused" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:empty]
        \\MaxConnections = 10
    );
    defer cfg.deinit();

    try std.testing.expectError(error.MissingListenerSocket, parseDmarcConfig(std.testing.allocator, &cfg));
}

// L-2: `MaxConnections` was read by `securespf` and ignored here, so an operator
// who set it on this daemon got 256 and no diagnostic. The value has two
// consumers -- the accept-path cap and the RLIMIT_NOFILE calculation -- and
// wiring only one of them would raise the fd budget without raising the limit
// that budget was sized for, or the reverse.
test "L-2: MaxConnections is honoured, and defaults when absent" {
    {
        var cfg = try config_mod.parse(std.testing.allocator,
            \\[global]
            \\AuthservID = mail.test.com
            \\MaxConnections = 32
        );
        defer cfg.deinit();

        const parsed = try parseDmarcConfig(std.testing.allocator, &cfg);
        defer std.testing.allocator.free(parsed.listen_addresses);
        defer std.testing.allocator.free(parsed.dns_nameservers);

        try std.testing.expectEqual(@as(u32, 32), parsed.max_connections);
    }

    {
        var cfg = try config_mod.parse(std.testing.allocator,
            \\[global]
            \\AuthservID = mail.test.com
        );
        defer cfg.deinit();

        const parsed = try parseDmarcConfig(std.testing.allocator, &cfg);
        defer std.testing.allocator.free(parsed.listen_addresses);
        defer std.testing.allocator.free(parsed.dns_nameservers);

        try std.testing.expectEqual(worker_mod.DEFAULT_MAX_CONNECTIONS, parsed.max_connections);
    }
}

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
test "M-4: ApplyPct is off unless the config says otherwise" {
    // The function-level guard in dmarc_test.zig proves `ignore` is inert; this
    // proves `ignore` is what an operator who says nothing actually gets. They
    // are different failures: shipping the wrong default would silently stop
    // enforcing every domain still publishing pct=0, and no test of
    // `effectivePolicySampled` would notice.
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const dmarc_cfg = try parseDmarcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(dmarc_cfg.listen_addresses);
    defer std.testing.allocator.free(dmarc_cfg.dns_nameservers);

    try std.testing.expect(!dmarc_cfg.apply_pct);
}

test "M-4: ApplyPct can be turned on" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
        \\ApplyPct = yes
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const dmarc_cfg = try parseDmarcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(dmarc_cfg.listen_addresses);
    defer std.testing.allocator.free(dmarc_cfg.dns_nameservers);

    try std.testing.expect(dmarc_cfg.apply_pct);
}

// A safe default, not a policy override: an operator whose Postfix runs in another
// jail must still be able to ask for a routable socket.
//
// This asserts the host explicitly. It previously checked only that the config
// parsed and that one listener came back, which would still have passed if an
// over-zealous "harden the listener" change had rewritten the operator's 0.0.0.0
// to loopback -- the exact regression the test exists to catch. A test whose name
// promises more than its assertions deliver is worse than an absent one, because
// it reads as covered. `cfg` is kept alive across the assertion because a host from
// a `Socket =` line borrows from it.
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
