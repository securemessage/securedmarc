//! SecureDMARC configuration parsing and runtime configuration.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const log = securemilter.log;
const deadline_mod = securemilter.deadline;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;

/// What a listener does with a `dmarc=fail` verdict
/// (design-dmarc-enforcement.md): nothing, tag for the LDA, or reject at
/// SMTP time. Ordered — each level includes the ones below it.
pub const Enforcement = enum {
    none,
    quarantine,
    reject,

    /// Parse `Enforcement`; rejects unrecognised values (a silent default
    /// would pick an unintended policy on the disposition path — the same
    /// rule securearc's On-DNSError follows).
    pub fn parse(raw: []const u8) error{InvalidEnforcement}!Enforcement {
        if (mem.eql(u8, raw, "none")) return .none;
        if (mem.eql(u8, raw, "quarantine")) return .quarantine;
        if (mem.eql(u8, raw, "reject")) return .reject;
        return error.InvalidEnforcement;
    }
};

/// SecureDMARC runtime configuration parsed from INI config.
pub const DmarcConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    /// Per-listener enforcement, aligned by index with `listen_addresses`.
    enforcement: []Enforcement,
    worker_threads: u32,
    /// Per-worker connection cap enforced by the accept path.
    max_connections: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    /// File-creation mask for the PID file and any unix-domain listener.
    umask: ?std.posix.mode_t,
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
    /// Message-evaluation deadline in milliseconds; zero disables it.
    max_evaluation_ms: i64,
    /// Header added when quarantine enforcement tags a message for the LDA.
    quarantine_header: []const u8,
    /// SMTP reply text for reject enforcement; must contain %s exactly once
    /// (OpenDMARC RejectString rule), replaced by the Author Domain.
    reject_text: []const u8,
    /// authserv-ids whose sealed ARC chains may downgrade reject to
    /// quarantine. Loaded once at startup (restart to refresh), like the PSL.
    trusted_sealers_file: ?[]const u8,
};
/// Parse the SecureDMARC config from a loaded Config.
/// Known configuration keys; anything else refuses startup. A key no table
/// knows is a typo, and a known global key inside a listener section is
/// silently inert — both reached production as real operator mistakes.
const known_global_keys: []const []const u8 = &(config_mod.base_global_keys ++ [_][]const u8{
    "AuthservID",       "WorkerThreads", "MaxConnections",   "PidFile",
    "User",             "UMask",         "Foreground",       "DnsNameserver",
    "DnsTimeout",       "DnsRetries",    "DnsCacheSize",     "DnsNegativeTTL",
    "ZmqEndpoint",      "ZmqTopic",      "StripAuthResults", "ApplyPct",
    "PublicSuffixList", "RejectText",    "QuarantineHeader", "TrustedSealersFile",
});
const known_listener_keys = [_][]const u8{ "Socket", "Enforcement" };

pub fn parseDmarcConfig(allocator: Allocator, cfg: *const config_mod.Config) !DmarcConfig {
    if (config_mod.validateKeys(cfg, known_global_keys, &known_listener_keys)) |offense| {
        // stderr as well as the log: this fires before the logger is
        // initialized, and an operator message that only reaches an unopened
        // syslog socket is silent by another name.
        switch (offense.kind) {
            .unknown => {
                log.err("config: [{s}] unrecognized key \"{s}\" (typo?); refusing to start", .{ offense.section, offense.key });
                std.debug.print("config: [{s}] unrecognized key \"{s}\" (typo?); refusing to start\n", .{ offense.section, offense.key });
            },
            .misplaced => {
                log.err("config: [{s}] key \"{s}\" is a global key with no effect here; move it to [global]. Refusing to start", .{ offense.section, offense.key });
                std.debug.print("config: [{s}] key \"{s}\" is a global key with no effect here; move it to [global]. Refusing to start\n", .{ offense.section, offense.key });
            },
        }
        return error.InvalidConfiguration;
    }
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
    const umask = try global.getMode("UMask");

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);
    var enforcement: std.ArrayListUnmanaged(Enforcement) = .{};
    errdefer enforcement.deinit(allocator);

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;

            // X-14: a malformed or missing Socket is refused, not skipped.
            const addr = try listener_mod.parseListenerSocket(section_name, section.get("Socket"));
            try addrs.append(allocator, addr);

            // Default none: an operator who says nothing gets stamping, never
            // a disposition. An unrecognised value refuses startup rather than
            // silently picking a policy on the reject path.
            const enf = if (section.get("Enforcement")) |raw|
                Enforcement.parse(raw) catch {
                    log.err("config: [{s}] Enforcement \"{s}\" is not none|quarantine|reject; refusing to start", .{ section_name, raw });
                    std.debug.print("config: [{s}] Enforcement \"{s}\" is not none|quarantine|reject; refusing to start\n", .{ section_name, raw });
                    return error.InvalidEnforcement;
                }
            else
                .none;
            try enforcement.append(allocator, enf);
        }
    }

    // Default to loopback because the milter protocol does not authenticate clients.
    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "127.0.0.1", .port = 8894 } });
        try enforcement.append(allocator, .none);
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

    // Leave prior local SPF and DKIM results available unless this is the first
    // SecureMilter daemon in the chain.
    const strip_auth_results = global.getBool("StripAuthResults", false);

    // `pct=` was removed by RFC 9989 §A.6 in favour of `t=`, so the default is to
    // ignore it. An operator running through the transition can switch it back on
    // for domains that have not moved yet (audit M-4).
    const apply_pct = global.getBool("ApplyPct", false);

    // X-21: shared spelling and default with securespf's limit of the same name.
    const max_evaluation_ms = global.getInt(deadline_mod.OPTION_NAME, i64, deadline_mod.DEFAULT_MS);

    // Optional Public Suffix List, used only to veto a tree-walk result.
    const public_suffix_list = global.get("PublicSuffixList");

    const reject_text = global.getOrDefault("RejectText", "rejected by DMARC policy for %s");
    if (mem.indexOf(u8, reject_text, "%s") == null) {
        log.err("config: RejectText must contain %s exactly once (the Author Domain); refusing to start", .{});
        std.debug.print("config: RejectText must contain %%s (the Author Domain); refusing to start\n", .{});
        return error.InvalidRejectText;
    }

    const quarantine_header = global.getOrDefault("QuarantineHeader", "X-SecureDMARC-Disposition");
    if (!validHeaderName(quarantine_header)) {
        log.err("config: QuarantineHeader \"{s}\" is not a valid header field name; refusing to start", .{quarantine_header});
        std.debug.print("config: QuarantineHeader \"{s}\" is not a valid header field name; refusing to start\n", .{quarantine_header});
        return error.InvalidQuarantineHeader;
    }

    const trusted_sealers_file = global.get("TrustedSealersFile");

    // Caps on attacker-controlled message content (audit X-4). DMARC reads the
    // From header and the spf=/dkim= results, so an uninspected header block is
    // exactly what it must not evaluate against.
    const limits = connection_mod.Limits.fromSection(global);

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .enforcement = try enforcement.toOwnedSlice(allocator),
        .worker_threads = workers,
        .max_connections = max_connections,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .umask = umask,
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
        .max_evaluation_ms = max_evaluation_ms,
        .quarantine_header = quarantine_header,
        .reject_text = reject_text,
        .trusted_sealers_file = trusted_sealers_file,
    };
}

/// A header field name is a printable-ASCII token with no colon (RFC 5322
/// §2.2). An invalid one would produce a stamp no downstream parser can read.
fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |ch| {
        if (ch <= 32 or ch >= 127 or ch == ':') return false;
    }
    return true;
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
        \\
    );
    defer cfg.deinit();

    try std.testing.expectError(error.MissingListenerSocket, parseDmarcConfig(std.testing.allocator, &cfg));
}

// L-2: `MaxConnections` must be honoured here the same way every daemon
// honours it, or an operator gets no diagnostic for a value that appears to do
// nothing. The value has two consumers -- the accept-path cap and the
// RLIMIT_NOFILE calculation -- and wiring only one of them would raise the fd
// budget without raising the limit that budget was sized for, or the reverse.
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
        defer std.testing.allocator.free(parsed.enforcement);
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
        defer std.testing.allocator.free(parsed.enforcement);
        defer std.testing.allocator.free(parsed.dns_nameservers);

        try std.testing.expectEqual(worker_mod.DEFAULT_MAX_CONNECTIONS, parsed.max_connections);
    }
}

// The implicit listener binds loopback, never 0.0.0.0: this daemon decides
// disposition, so a reachable port would let an attacker supply a message whose
// Authentication-Results it will believe -- M-1/X-1 without forging a header --
// and under p=reject it decides what gets bounced. The milter protocol
// authenticates nobody, so reachability IS authorization.
test "the implicit listener binds loopback, not every interface" {
    const ini_text =
        \\[global]
        \\AuthservID = mail.test.com
    ;

    var cfg = try config_mod.parse(std.testing.allocator, ini_text);
    defer cfg.deinit();

    const dmarc_cfg = try parseDmarcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(dmarc_cfg.listen_addresses);
    defer std.testing.allocator.free(dmarc_cfg.enforcement);
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
    // The function-level guard in dmarc.zig proves `ignore` is inert; this
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
    defer std.testing.allocator.free(dmarc_cfg.enforcement);
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
    defer std.testing.allocator.free(dmarc_cfg.enforcement);
    defer std.testing.allocator.free(dmarc_cfg.dns_nameservers);

    try std.testing.expect(dmarc_cfg.apply_pct);
}

test "Enforcement defaults to none per listener and parses per section" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:inbound]
        \\Socket = inet:8894@127.0.0.1
        \\Enforcement = quarantine
        \\
        \\[listener:internal]
        \\Socket = inet:8895@127.0.0.1
    );
    defer cfg.deinit();

    const dmarc_cfg = try parseDmarcConfig(std.testing.allocator, &cfg);
    defer std.testing.allocator.free(dmarc_cfg.listen_addresses);
    defer std.testing.allocator.free(dmarc_cfg.enforcement);
    defer std.testing.allocator.free(dmarc_cfg.dns_nameservers);

    // Aligned by index with listen_addresses; the unconfigured listener gets
    // stamping, never a disposition.
    try std.testing.expectEqual(@as(usize, 2), dmarc_cfg.enforcement.len);
    try std.testing.expectEqual(Enforcement.quarantine, dmarc_cfg.enforcement[0]);
    try std.testing.expectEqual(Enforcement.none, dmarc_cfg.enforcement[1]);
}

test "an unrecognised Enforcement value refuses startup" {
    // The disposition path is where a silent default is worst: `none` would
    // stamp mail the operator wanted rejected, `reject` would bounce mail the
    // operator wanted stamped. Refuse instead.
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\
        \\[listener:inbound]
        \\Socket = inet:8894@127.0.0.1
        \\Enforcement = block
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidEnforcement, parseDmarcConfig(std.testing.allocator, &cfg));
}

test "RejectText without the %s placeholder refuses startup" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\RejectText = rejected
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidRejectText, parseDmarcConfig(std.testing.allocator, &cfg));
}

test "QuarantineHeader must be a valid header field name" {
    var cfg = try config_mod.parse(std.testing.allocator,
        \\[global]
        \\AuthservID = mail.test.com
        \\QuarantineHeader = Bad Header
    );
    defer cfg.deinit();

    try std.testing.expectError(error.InvalidQuarantineHeader, parseDmarcConfig(std.testing.allocator, &cfg));
}

// A safe default, not a policy override: an operator whose Postfix runs in another
// jail must still be able to ask for a routable socket.
//
// The host is asserted explicitly rather than merely checking that the config
// parsed and one listener came back, so an over-zealous "harden the listener"
// change that rewrote the operator's 0.0.0.0 to loopback would fail this test.
// `cfg` is kept alive across the assertion because a host from a `Socket =`
// line borrows from it.
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
    defer std.testing.allocator.free(dmarc_cfg.enforcement);
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
