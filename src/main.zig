const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const listener_mod = securemilter.listener;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const auth_results = securemilter.auth_results;
const commands = securemilter.milter.commands;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;
const dns_mod = securemilter.dns;
const zmq = securemilter.zmq;

pub const dmarc = @import("dmarc.zig");
pub const alignment = @import("alignment.zig");

/// SecureDMARC runtime configuration parsed from INI config.
pub const DmarcConfig = struct {
    authserv_id: []const u8,
    listen_addresses: []const listener_mod.ListenAddress,
    worker_threads: u32,
    pid_file: []const u8,
    foreground: bool,
    user: ?[]const u8,
    dns_nameserver: []const u8,
    dns_timeout_ms: u32,
    dns_retries: u8,
    zmq_endpoint: ?[]const u8,
    zmq_topic: []const u8,
};

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "dmarc.evaluation";

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
}

/// Parse the SecureDMARC config from a loaded Config.
pub fn parseDmarcConfig(allocator: Allocator, cfg: *const config_mod.Config) !DmarcConfig {
    const global = cfg.getSection("global") orelse return error.MissingGlobalSection;

    const authserv_id = global.get("AuthservID") orelse "localhost";
    const workers = global.getInt("WorkerThreads", u32, 0);
    const pid_file = global.getOrDefault("PidFile", "/var/run/securedmarc/securedmarc.pid");
    const foreground_val = global.getBool("Foreground", false);
    const user = global.get("User");

    var addrs: std.ArrayListUnmanaged(listener_mod.ListenAddress) = .{};
    errdefer addrs.deinit(allocator);

    for (cfg.section_order.items) |section_name| {
        if (mem.startsWith(u8, section_name, "listener:")) {
            const section = cfg.getSection(section_name) orelse continue;
            const socket_str = section.get("Socket") orelse continue;
            const addr = listener_mod.ListenAddress.parse(socket_str) catch continue;
            try addrs.append(allocator, addr);
        }
    }

    if (addrs.items.len == 0) {
        try addrs.append(allocator, .{ .tcp = .{ .host = "0.0.0.0", .port = 8894 } });
    }

    const dns_ns = global.getOrDefault("DnsNameserver", "127.0.0.1");
    const dns_timeout = global.getInt("DnsTimeout", u32, 5) * 1000;
    const dns_retries = global.getInt("DnsRetries", u8, 2);

    // ZMQ event publishing
    const zmq_endpoint = global.get("ZmqEndpoint");
    const zmq_topic = global.getOrDefault("ZmqTopic", "dmarc.evaluation");

    return .{
        .authserv_id = authserv_id,
        .listen_addresses = try addrs.toOwnedSlice(allocator),
        .worker_threads = workers,
        .pid_file = pid_file,
        .foreground = foreground_val,
        .user = user,
        .dns_nameserver = dns_ns,
        .dns_timeout_ms = dns_timeout,
        .dns_retries = dns_retries,
        .zmq_endpoint = zmq_endpoint,
        .zmq_topic = zmq_topic,
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var args = std.process.args();
    _ = args.next();
    const config_path = args.next() orelse "/usr/local/etc/securedmarc/securedmarc.conf";

    var cfg = config_mod.parseFile(allocator, config_path) catch |err| {
        std.log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const dmarc_cfg = parseDmarcConfig(allocator, &cfg) catch |err| {
        std.log.err("config parse error: {}", .{err});
        return err;
    };

    // Set module-level globals
    g_authserv_id = dmarc_cfg.authserv_id;
    g_dns_config = .{
        .nameserver = dmarc_cfg.dns_nameserver,
        .timeout_ms = dmarc_cfg.dns_timeout_ms,
        .retries = dmarc_cfg.dns_retries,
    };
    g_zmq_endpoint = dmarc_cfg.zmq_endpoint;
    g_zmq_topic = dmarc_cfg.zmq_topic;

    // Daemonize
    if (!dmarc_cfg.foreground) {
        daemon_mod.daemonize() catch |err| {
            std.log.err("daemonize failed: {}", .{err});
            return err;
        };
    }

    daemon_mod.writePidFile(dmarc_cfg.pid_file) catch |err| {
        std.log.err("pid file write failed: {}", .{err});
    };
    defer daemon_mod.removePidFile(dmarc_cfg.pid_file);

    // Drop privileges after PID file is written, before workers spawn
    if (dmarc_cfg.user) |user| {
        daemon_mod.dropPrivileges(user) catch |err| {
            std.log.err("privilege drop to '{s}' failed: {}", .{ user, err });
            return err;
        };
    }

    std.log.info("SecureDMARC starting, AuthservID={s}, listeners={d}", .{
        dmarc_cfg.authserv_id,
        dmarc_cfg.listen_addresses.len,
    });

    const required_actions = negotiate.ActionFlags{ .add_headers = true };

    const callbacks = worker_mod.Callbacks{
        .on_connect = onConnect,
        .on_helo = onHelo,
        .on_mail_from = onMailFrom,
        .on_header = onHeader,
        .on_eoh = onEoh,
        .on_body = onBody,
        .on_eom = onEom,
        .required_actions = required_actions,
    };

    var threads = try worker_mod.spawnPool(
        allocator,
        dmarc_cfg.worker_threads,
        dmarc_cfg.listen_addresses,
        callbacks,
    );
    defer threads.deinit(allocator);

    for (threads.items) |t| t.join();
}

// =============================================================================
// Milter Callbacks
// =============================================================================

fn onConnect(conn: *connection_mod.Connection, _: commands.ConnectInfo) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHelo(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onMailFrom(conn: *connection_mod.Connection, _: []const u8) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onHeader(conn: *connection_mod.Connection, _: []const u8, _: []const u8) u8 {
    // Headers are accumulated automatically by Connection.addHeader() in the worker
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onEoh(conn: *connection_mod.Connection) u8 {
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onBody(conn: *connection_mod.Connection, _: []const u8) u8 {
    // DMARC doesn't need body content — but we don't request SMFIP_NOBODY
    // since the protocol requires us to accept what Postfix sends.
    _ = conn;
    return @intFromEnum(responses.Code.@"continue");
}

fn onEom(conn: *connection_mod.Connection) u8 {
    return doDmarcEvaluation(conn);
}

/// Perform DMARC evaluation at end-of-message.
///
/// 1. Extract From: header domain
/// 2. Read upstream A-R headers to find SPF and DKIM results
/// 3. DNS lookup _dmarc.<from_domain> TXT
/// 4. Parse DMARC record, check alignment, determine result
/// 5. Add our own A-R header with DMARC result
fn doDmarcEvaluation(conn: *connection_mod.Connection) u8 {
    // Step 1: Extract From: domain
    const from_domain = getFromDomain(conn) orelse {
        addArHeaderSimple(conn, "none", "no From header");
        return @intFromEnum(responses.Code.@"continue");
    };

    // Step 2: Parse upstream Authentication-Results headers
    var spf_result: ?[]const u8 = null;
    var dkim_result: ?[]const u8 = null;
    var dkim_domain: ?[]const u8 = null;

    // The envelope-from domain is what SPF authenticated
    const envelope_domain = getEnvelopeDomain(conn);

    for (conn.headers.items) |hdr| {
        if (!eqlIgnoreCase(hdr.name, "Authentication-Results")) continue;
        // Only trust A-R headers from our own authserv-id
        if (!auth_results.matchesAuthservId(hdr.value, g_authserv_id)) continue;

        var parsed = auth_results.parseResults(conn.allocator, hdr.value) catch continue;
        defer parsed.deinit(conn.allocator);

        if (spf_result == null) {
            if (parsed.getResult("spf")) |r| {
                spf_result = dupeOrNull(conn.allocator, r);
            }
        }
        if (dkim_result == null) {
            if (parsed.getResult("dkim")) |r| {
                dkim_result = dupeOrNull(conn.allocator, r);
            }
        }
    }
    defer {
        if (spf_result) |s| conn.allocator.free(s);
        if (dkim_result) |s| conn.allocator.free(s);
        if (dkim_domain) |s| conn.allocator.free(s);
    }

    // Try to extract DKIM d= domain from header properties
    // (simplified: look for header.d= in A-R header text)
    dkim_domain = extractDkimDomain(conn);

    // Step 3: DNS lookup _dmarc.<from_domain>
    const dmarc_domain = std.fmt.allocPrint(conn.allocator, "_dmarc.{s}", .{from_domain}) catch {
        addArHeaderSimple(conn, "temperror", "internal error");
        return @intFromEnum(responses.Code.@"continue");
    };
    defer conn.allocator.free(dmarc_domain);

    var resolver = dns_mod.Resolver.init(conn.allocator, g_dns_config);
    defer resolver.deinit();

    var dns_result = resolver.resolve(dmarc_domain, .TXT) catch {
        addArHeaderSimple(conn, "temperror", "DNS lookup failed");
        return @intFromEnum(responses.Code.@"continue");
    };
    defer dns_result.deinit();

    // Step 4: Find and parse DMARC record among TXT results
    var record: ?dmarc.DmarcRecord = null;
    var txt_iter = dns_result.txtRecords();
    while (txt_iter.next()) |txt| {
        if (dmarc.parseRecord(txt)) |r| {
            record = r;
            break;
        }
    }

    const rec = record orelse {
        addArHeaderSimple(conn, "none", "no DMARC record found");
        return @intFromEnum(responses.Code.@"continue");
    };

    // Step 5: Evaluate alignment
    const is_subdomain = isSubdomainOfOrg(from_domain);
    const result = dmarc.evaluate(
        &rec,
        from_domain,
        spf_result,
        envelope_domain,
        dkim_result,
        dkim_domain,
        is_subdomain,
    );

    // Step 6: Add Authentication-Results header
    const disposition = dmarc.getDisposition(&rec, is_subdomain);
    addArHeaderFull(conn, result.toString(), from_domain, disposition);

    // Publish ZMQ event with full evaluation details
    publishEvent(
        conn.allocator,
        from_domain,
        result.toString(),
        disposition,
        spf_result orelse "none",
        dkim_result orelse "none",
        dkim_domain orelse "",
        envelope_domain orelse "",
    );

    return @intFromEnum(responses.Code.@"continue");
}

// =============================================================================
// Helper functions
// =============================================================================

fn getFromDomain(conn: *connection_mod.Connection) ?[]const u8 {
    for (conn.headers.items) |hdr| {
        if (eqlIgnoreCase(hdr.name, "From")) {
            // Extract email address from From: header value
            // Handle "Display Name <addr@domain>" and bare "addr@domain"
            const val = mem.trim(u8, hdr.value, &std.ascii.whitespace);
            if (mem.lastIndexOfScalar(u8, val, '>')) |gt| {
                if (mem.lastIndexOfScalar(u8, val[0..gt], '<')) |lt| {
                    return alignment.getDomainFromEmail(val[lt + 1 .. gt]);
                }
            }
            return alignment.getDomainFromEmail(val);
        }
    }
    return null;
}

fn getEnvelopeDomain(conn: *connection_mod.Connection) ?[]const u8 {
    const raw = conn.mail_from_raw orelse return null;
    const addr = alignment.stripAngleBrackets(raw);
    return alignment.getDomainFromEmail(addr);
}

fn extractDkimDomain(conn: *connection_mod.Connection) ?[]const u8 {
    // Look through A-R headers for "header.d=<domain>" property
    for (conn.headers.items) |hdr| {
        if (!eqlIgnoreCase(hdr.name, "Authentication-Results")) continue;
        if (!auth_results.matchesAuthservId(hdr.value, g_authserv_id)) continue;
        // Simple extraction: find "header.d=" in the header value
        if (mem.indexOf(u8, hdr.value, "header.d=")) |pos| {
            const start = pos + "header.d=".len;
            const rest = hdr.value[start..];
            const end = mem.indexOfAny(u8, rest, &.{ ' ', '\t', ';', '\r', '\n' }) orelse rest.len;
            if (end > 0) {
                return conn.allocator.dupe(u8, rest[0..end]) catch null;
            }
        }
    }
    return null;
}

fn isSubdomainOfOrg(domain: []const u8) bool {
    const org = alignment.getOrganizationalDomain(domain);
    return !eqlIgnoreCase(domain, org);
}

fn publishEvent(
    allocator: Allocator,
    from_domain: []const u8,
    result_str: []const u8,
    disposition: []const u8,
    spf_result_str: []const u8,
    dkim_result_str: []const u8,
    dkim_domain_str: []const u8,
    envelope_from: []const u8,
) void {
    const json = std.fmt.allocPrint(allocator,
        \\{{"from_domain":"{s}","result":"{s}","disposition":"{s}","spf_result":"{s}","dkim_result":"{s}","dkim_domain":"{s}","envelope_from":"{s}"}}
    , .{ from_domain, result_str, disposition, spf_result_str, dkim_result_str, dkim_domain_str, envelope_from }) catch return;
    defer allocator.free(json);

    getPublisher().publish(json);
}

fn addArHeaderSimple(conn: *connection_mod.Connection, result_str: []const u8, reason: []const u8) void {
    const ar_value = auth_results.build(conn.allocator, g_authserv_id, &.{
        .{
            .method = "dmarc",
            .result = result_str,
            .reason = reason,
            .properties = &.{},
        },
    }) catch return;
    defer conn.allocator.free(ar_value);

    const hdr_payload = responses.addHeader(
        conn.allocator,
        "Authentication-Results",
        ar_value,
    ) catch return;
    defer conn.allocator.free(hdr_payload);

    codec.writePacket(conn.fd, hdr_payload) catch {};
}

fn addArHeaderFull(
    conn: *connection_mod.Connection,
    result_str: []const u8,
    from_domain: []const u8,
    disposition: []const u8,
) void {
    const reason = std.fmt.allocPrint(conn.allocator, "p={s}", .{disposition}) catch return;
    defer conn.allocator.free(reason);

    const ar_value = auth_results.build(conn.allocator, g_authserv_id, &.{
        .{
            .method = "dmarc",
            .result = result_str,
            .reason = reason,
            .properties = &.{.{
                .ptype = "header",
                .property = "from",
                .value = from_domain,
            }},
        },
    }) catch return;
    defer conn.allocator.free(ar_value);

    const hdr_payload = responses.addHeader(
        conn.allocator,
        "Authentication-Results",
        ar_value,
    ) catch return;
    defer conn.allocator.free(hdr_payload);

    codec.writePacket(conn.fd, hdr_payload) catch {};
}

fn dupeOrNull(allocator: Allocator, s: []const u8) ?[]const u8 {
    return allocator.dupe(u8, s) catch null;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLower(ca) != toLower(cb)) return false;
    }
    return true;
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// =============================================================================
// Tests
// =============================================================================

test {
    _ = dmarc;
    _ = alignment;
}

test "parse config minimal" {
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

    try std.testing.expectEqualStrings("mail.test.com", dmarc_cfg.authserv_id);
    try std.testing.expectEqual(@as(usize, 1), dmarc_cfg.listen_addresses.len);
}

test "get from domain" {
    // This test validates the From: header parsing logic conceptually.
    // Full integration with Connection struct requires the milter framework.
    const from_value = "User Name <user@example.com>";
    // Simulate the parsing logic
    if (mem.lastIndexOfScalar(u8, from_value, '>')) |gt| {
        if (mem.lastIndexOfScalar(u8, from_value[0..gt], '<')) |lt| {
            const addr = from_value[lt + 1 .. gt];
            const domain = alignment.getDomainFromEmail(addr);
            try std.testing.expectEqualStrings("example.com", domain.?);
            return;
        }
    }
    return error.TestFailed;
}
