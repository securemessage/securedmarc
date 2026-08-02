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
const bootstrap_mod = securemilter.bootstrap;
const auth_results = securemilter.auth_results;
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const codec = securemilter.milter.codec;
const responses = securemilter.milter.responses;
const negotiate = securemilter.milter.negotiate;
const dns_mod = securemilter.dns;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

pub const dmarc = @import("dmarc.zig");
pub const alignment = @import("alignment.zig");
pub const treewalk = @import("treewalk.zig");
pub const psl = @import("psl.zig");
pub const upstream = @import("upstream.zig");

/// How many DKIM results from `Authentication-Results` are evaluated.
///
/// Every relaxed-mode identifier that passed can cost one DNS tree walk, and
/// the number of `dkim=` results in the header is chosen by whoever sent the
/// message. The cap is the same reasoning as the other content limits (audit
/// X-4): bound work that an attacker gets to size. Ten is far above what real
/// mail carries — a message with more aligned candidates than this is not one
/// whose eleventh signature decides the verdict.
const MAX_DKIM_IDENTIFIERS = 10;

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

const reload_mod = securemilter.reload;

// Module-level config set before worker spawn, read-only during runtime.
var g_authserv_id: []const u8 = "localhost";
var g_dns_config: dns_mod.ResolverConfig = .{};
var g_zmq_endpoint: ?[]const u8 = null;
var g_zmq_topic: []const u8 = "dmarc.evaluation";
var g_strip_policy: header_scrub.StripPolicy = .{ .own_methods = &.{"dmarc"} };

/// Whether a published `pct=` is honoured (audit M-4). Off by default: RFC 9989
/// §A.6 removed the tag, so ignoring it is what the current spec says. On is for
/// operators who would rather keep honouring it while senders finish moving to
/// `t=`, which is a transition still in progress.
var g_sampling: dmarc.SamplingPolicy = .ignore;
var g_health_monitor: ?*dns_mod.HealthMonitor = null;

/// `daemon.Options.spawn_threads`: start the DNS health monitor.
///
/// Context-free because that is what `daemon.Options` takes, and deliberately so — the
/// hook runs at the one point in the bootstrap where creating a thread is safe, after
/// the fork and after the managed signals are blocked. `g_allocator` and `g_dns_config`
/// are both set from the parsed configuration before then.
fn spawnHealthMonitor() void {
    g_health_monitor = dns_mod.startMonitor(g_allocator, g_dns_config.nameservers);
}
var g_config_gen: reload_mod.ConfigGeneration = reload_mod.ConfigGeneration.init();
var g_allocator: Allocator = undefined;
var g_psl: ?psl.PublicSuffixList = null;

// Thread-local ZMQ publisher (one socket per worker thread — ZMQ thread-safety)
threadlocal var tl_publisher: ?zmq.Publisher = null;

// Thread-local DNS resolver. The tree walk issues up to eight lookups per
// identity, and most of those names repeat across messages, so the resolver —
// and with it its TTL cache — has to outlive a single message. One per worker
// thread keeps it lock-free, matching the publisher and logger.
threadlocal var tl_resolver: ?dns_mod.Resolver = null;

fn getPublisher() *zmq.Publisher {
    if (tl_publisher == null) {
        tl_publisher = zmq.Publisher.init(g_zmq_endpoint, g_zmq_topic);
    }
    return &tl_publisher.?;
}

fn getResolver() *dns_mod.Resolver {
    if (tl_resolver == null) {
        tl_resolver = dns_mod.Resolver.initWithMonitor(g_allocator, g_dns_config, g_health_monitor);
    }
    return &tl_resolver.?;
}

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

fn usageError() error{InvalidArgument} {
    log.err("usage: securedmarc -c <config-file>", .{});
    return error.InvalidArgument;
}

/// Every failure below is reported by `bootstrap.fatal`, which explains why: after
/// `daemonize` stderr is /dev/null and syslog is the only channel left (X-16).
pub fn main() !void {
    runDaemon() catch |e| return bootstrap_mod.fatal(e);
}

fn runDaemon() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    g_allocator = allocator;

    // Parse command-line: securedmarc -c /path/to/config
    var args = std.process.args();
    _ = args.next();
    const flag = args.next() orelse return usageError();
    if (!std.mem.eql(u8, flag, "-c")) return usageError();
    const config_path = args.next() orelse return usageError();

    var cfg = config_mod.parseFile(allocator, config_path) catch |err| {
        log.err("failed to load config {s}: {}", .{ config_path, err });
        return err;
    };
    defer cfg.deinit();

    const dmarc_cfg = parseDmarcConfig(allocator, &cfg) catch |err| {
        log.err("config parse error: {}", .{err});
        return err;
    };

    // Initialize logging from config
    const log_cfg = if (cfg.global()) |g| log.LogConfig.fromSection(g, "securedmarc") else log.LogConfig.init(true, .mail, .info, "securedmarc");
    log.initGlobal(&log_cfg);
    log.initThread();

    // Set module-level globals
    g_authserv_id = dmarc_cfg.authserv_id;
    g_sampling = if (dmarc_cfg.apply_pct) .honor else .ignore;
    g_dns_config = .{
        .nameservers = dmarc_cfg.dns_nameservers,
        .timeout_ms = dmarc_cfg.dns_timeout_ms,
        .retries = dmarc_cfg.dns_retries,
        .cache_size = dmarc_cfg.dns_cache_size,
        .negative_ttl = dmarc_cfg.dns_negative_ttl,
    };

    g_zmq_endpoint = dmarc_cfg.zmq_endpoint;
    g_zmq_topic = dmarc_cfg.zmq_topic;
    g_strip_policy = .{ .own_methods = &.{"dmarc"}, .strip_all = dmarc_cfg.strip_auth_results };

    // The tree walk decides the organizational boundary; the list, if present,
    // may only reject a boundary that is demonstrably a public suffix.
    if (dmarc_cfg.public_suffix_list) |path| {
        var list = psl.PublicSuffixList.init(allocator);
        if (list.loadFile(path)) {
            log.info("loaded {d} public suffix rules from {s}", .{ list.count(), path });
            g_psl = list;
        } else |err| {
            list.deinit();
            // ASCII only: syslog renders an em dash as escaped bytes, and this is
            // the line an operator reads when alignment starts degrading (A-12).
            log.err("failed to load PublicSuffixList {s}: {}; continuing on the DNS tree walk alone", .{ path, err });
        }
    } else {
        // Say so explicitly: which of the two modes is in effect should be
        // readable from the log, not inferred from the absence of a line.
        log.info("no PublicSuffixList configured; organizational domains come from the DNS tree walk alone", .{});
    }

    // Daemonize, block signals, start the monitor thread, claim the PID file, raise the
    // fd budget, drop privileges — in that order, for reasons recorded once in
    // `daemon.bootstrap` and enforced by its ordering tests.
    var boot = try bootstrap_mod.run(.{
        .foreground = dmarc_cfg.foreground,
        .pid_file = dmarc_cfg.pid_file,
        .user = dmarc_cfg.user,
        .worker_threads = dmarc_cfg.worker_threads,
        .max_connections = dmarc_cfg.max_connections,
        .num_listeners = @intCast(dmarc_cfg.listen_addresses.len),
        .spawn_threads = spawnHealthMonitor,
    });
    defer boot.deinit();

    log.info("SecureDMARC starting, AuthservID={s}, listeners={d}", .{
        dmarc_cfg.authserv_id,
        dmarc_cfg.listen_addresses.len,
    });

    const required_actions = negotiate.ActionFlags{ .add_headers = true, .change_headers = true };

    const callbacks = worker_mod.Callbacks{
        .on_eom = onEom,
        .on_reload = onWorkerReload,
        .required_actions = required_actions,
        .limits = dmarc_cfg.limits,
    };

    const shutdown_pipe = try posix.pipe();
    defer posix.close(shutdown_pipe[0]);

    var threads = try securemilter.pool.spawnPoolWithReload(
        allocator,
        dmarc_cfg.worker_threads,
        dmarc_cfg.listen_addresses,
        callbacks,
        shutdown_pipe[0],
        &g_config_gen,
        dmarc_cfg.max_connections,
    );
    defer threads.deinit(allocator);

    // Bound and serving: release the parent blocked in `daemonize` (X-16).
    boot.notifyReady();

    daemon_mod.ManagedSignals.signalLoop(shutdown_pipe[1], reloadConfig);
    for (threads.items) |t| t.join();
    if (g_health_monitor) |monitor| monitor.deinit();
}

// =============================================================================
// Milter Callbacks
// =============================================================================

// This daemon acts only at end-of-message, so `on_eom` is the only phase
// registered below. An unregistered callback yields `Code.continue`, which is
// exactly what the six stubs that used to sit here returned.
//
// Two of them carried reasoning worth keeping, since neither is recoverable from
// the remaining code:
//
//   - Headers need no callback. The worker calls `Connection.addHeader` itself
//     before dispatching, so accumulation does not depend on this daemon
//     registering anything; a stub here only looked as though it did.
//
//   - `skip_flags` deliberately does NOT set `no_body`, even though DMARC never
//     reads the body. Declining the body is a negotiation this daemon could win
//     and chooses not to: we accept whatever Postfix sends. Contrast
//     `securespf`, which does set it.

fn onEom(conn: *connection_mod.Connection) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged dmarc= claims before evaluating. The spf= and dkim= results
    // this evaluation consumes were scrubbed of forgeries by SecureSPF and
    // SecureDKIM earlier in the chain; what survives here was produced by them.
    _ = header_scrub.stripAuthResults(conn, g_authserv_id, g_strip_policy);

    const result = doDmarcEvaluation(conn);
    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const queue_id = conn.macros.queue_id orelse "-";
    // Via the accessor, not the macro: {client_addr} is absent from Postfix's
    // default milter_connect_macros, so reading it directly logs "unknown" for
    // every connection on a stock MTA. The accessor falls back to the address
    // SMFIC_CONNECT carried. Here the placeholder is display-only.
    const client_addr = conn.clientAddr() orelse "unknown";
    const from_domain = getFromDomain(conn) orelse "unknown";
    const peer = conn.getPeerDisplay();
    // `domain` here is taken from the message's own `From:` field, which is
    // entirely sender-chosen and may be folded across lines -- so its unfolded
    // value can begin with whitespace or contain a bare LF. Unescaped, that
    // either forged a second syslog line or made `elapsed=` look like this
    // field's value. This is the field the x5a probe reported (audit X-5).
    log.info("id={f} peer={f}[{f}] client={f} domain={f} elapsed={d}ms", .{
        escape.logField(queue_id),
        escape.logField(peer.name),
        escape.logField(peer.ip),
        escape.logField(client_addr),
        escape.logField(from_domain),
        elapsed_ms,
    });
    return result;
}

/// Perform DMARC evaluation at end-of-message.
///
/// 1. Extract From: header domain
/// 2. Read upstream A-R headers to find SPF and DKIM results
/// 3. DNS lookup _dmarc.<from_domain> TXT
/// 4. Parse DMARC record, check alignment, determine result
/// 5. Add our own A-R header with DMARC result
fn doDmarcEvaluation(conn: *connection_mod.Connection) u8 {
    // Step 0: A message with more than one From field has no single author
    // domain to evaluate. RFC 5322 forbids it and RFC 7489 §6.6.1 declines to
    // guess; picking one instance means the domain we authenticate can differ
    // from the one the reader is shown. Fail rather than choose.
    const from_count = countFromHeaders(conn);
    if (from_count > 1) {
        addArHeaderSimple(conn, "fail", "multiple From header fields") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    }

    // Step 1: Extract From: domain
    const from_domain = getFromDomain(conn) orelse {
        addArHeaderSimple(conn, "none", "no From header") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    };

    // Step 2: Parse upstream Authentication-Results headers
    // The envelope-from domain is what SPF authenticated
    const envelope_domain = getEnvelopeDomain(conn);

    // Each DKIM signature contributes its own (result, d=) pair, and they stay
    // paired — see `upstream.zig`, which is where audit M-6 lives.
    var up = upstream.collect(conn.allocator, conn.headers.items, g_authserv_id, MAX_DKIM_IDENTIFIERS);
    defer up.deinit(conn.allocator);

    const spf_result = up.spf_result;
    const dkim_idents = up.dkim;

    if (up.truncated) {
        log.warn(
            "more than {d} DKIM results in Authentication-Results; evaluating the first {d}",
            .{ MAX_DKIM_IDENTIFIERS, MAX_DKIM_IDENTIFIERS },
        );
    }

    // Step 3: Policy discovery and Organizational Domain, both by DNS tree
    // walk (RFC 9989 §4.10). The walk starts at the Author Domain: if it
    // publishes a record that is the policy, and the walk continues upward
    // only to establish where the organizational boundary lies.
    const resolver = getResolver();

    var author_walk = treewalk.walk(conn.allocator, resolver, from_domain) catch {
        addArHeaderSimple(conn, "temperror", "internal error") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    };
    defer author_walk.deinit();

    // §4.10.1: the Author Domain's own record wins; otherwise the record
    // belonging to its Organizational or Public Suffix Domain applies.
    const selected = author_walk.recordAtStart() orelse author_walk.policyRecord() orelse {
        if (author_walk.transient_error) {
            addArHeaderSimple(conn, "temperror", "DNS lookup failed") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
        } else {
            addArHeaderSimple(conn, "none", "no DMARC record found") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
        }
        return @intFromEnum(responses.Code.@"continue");
    };

    // §4.10.1: a record whose p= is missing or invalid, or which carries an
    // invalid sp= or np=, is not simply ignored. A valid rua= makes it act as
    // p=none; without one, DMARC does not apply to this message at all.
    //
    // The second branch is why this is a decision and not a default: reporting
    // `none` here is the RFC's answer, whereas falling through to a parent's
    // record -- what returning null from parseRecord used to cause -- could
    // apply an organizational `p=reject` to a domain the RFC says to leave
    // alone, and reject mail on the strength of a malformed record.
    var rec = selected;
    switch (rec.applicability()) {
        .apply => {},
        .as_none => {
            rec.policy = .none;
            rec.subdomain_policy = null;
            log.info("dmarc: {s}: record has no usable policy but a valid rua=, applying p=none per RFC 9989 4.10.1", .{from_domain});
        },
        .no_processing => {
            log.info("dmarc: {s}: record has no usable policy and no valid rua=, no DMARC processing per RFC 9989 4.10.1", .{from_domain});
            addArHeaderSimple(conn, "none", "record has no usable policy") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
            return @intFromEnum(responses.Code.@"continue");
        },
    }

    const from_org = treewalk.organizationalDomain(&author_walk, pslPtr());
    const is_subdomain = !std.ascii.eqlIgnoreCase(from_domain, from_org);

    // Step 4: Resolve each authenticated identifier's own Organizational
    // Domain. Only needed for relaxed mode and only for identifiers that
    // actually passed — strict mode is a string comparison (§4.10.2).
    var spf_ident = alignment.Identifier{ .domain = envelope_domain, .result = spf_result };

    var spf_walk = treewalk.orgWalk(conn.allocator, resolver, rec.aspf, from_domain, from_org, &spf_ident, pslPtr());
    defer if (spf_walk) |*w| w.deinit();

    // One walk per DKIM identifier, each kept alive because the identifier's
    // `org_domain` points into it. `orgWalk` returns null for the cases that
    // need no DNS at all (strict mode, a result that did not pass, a domain
    // equal to the Author Domain), so the common single-signature message still
    // costs exactly one walk. MAX_DKIM_IDENTIFIERS is what stops a message
    // carrying a hundred signatures from buying a hundred tree walks (X-4).
    var dkim_walks: [MAX_DKIM_IDENTIFIERS]?treewalk.Walk = @splat(null);
    defer for (&dkim_walks) |*w| {
        if (w.*) |*walk| walk.deinit();
    };
    for (dkim_idents, 0..) |*ident, i| {
        dkim_walks[i] = treewalk.orgWalk(conn.allocator, resolver, rec.adkim, from_domain, from_org, ident, pslPtr());
    }

    // Step 5: Evaluate alignment
    //
    // The detailed form keeps the two alignment booleans the verdict was built
    // from, which the reporting event has to state and cannot safely re-derive
    // (audit M-7a).
    const evaluation = dmarc.evaluateDetailed(&rec, from_domain, from_org, spf_ident, dkim_idents);
    const result = evaluation.result;

    // Report the signature the verdict actually rests on: the aligned one when
    // there is one, otherwise the first, so a `dkim=pass` in the event is never
    // paired with a `d=` from some other signature — the M-6 defect itself.
    const reported_dkim = dmarc.alignedDkim(&rec, from_domain, from_org, dkim_idents) orelse
        if (dkim_idents.len > 0) dkim_idents[0] else alignment.Identifier{};

    // Step 6: Add Authentication-Results header
    // Sampling keys off the Message-ID so a retried message keeps the verdict it
    // was given; see `dmarc.inSample`. Absent, the message counts as selected.
    const disposition = dmarc.effectivePolicySampled(
        &rec,
        is_subdomain,
        g_sampling,
        getMessageId(conn),
    ).toString();
    addArHeaderFull(conn, result.toString(), from_domain, disposition) catch |err|
        return auth_stamp.deferCode(err, "dmarc");

    // Publish ZMQ event with full evaluation details
    publishEvent(conn.allocator, .{
        // Via the accessor so this is populated on a stock MTA, where the
        // {client_addr} macro is not sent. An empty value here is not cosmetic:
        // client_ip is mandatory on every RFC 7489 SS7.2 <record><row>, so an
        // event without it cannot become a valid aggregate report row.
        .client_ip = conn.clientAddr() orelse "",
        .from_domain = from_domain,
        .header_from = getFromAddress(conn) orelse "",
        .envelope_from = envelope_domain orelse "",
        .policy = dmarc.publishedPolicy(&rec, is_subdomain).toString(),
        .disposition = disposition,
        .dmarc_result = result.toString(),
        .spf_result = spf_result orelse "none",
        .spf_aligned = evaluation.spf_aligned,
        .dkim_result = reported_dkim.result orelse "none",
        .dkim_domain = reported_dkim.domain orelse "",
        .dkim_aligned = evaluation.dkim_aligned,
    });

    return @intFromEnum(responses.Code.@"continue");
}

// =============================================================================
// Helper functions
// =============================================================================

fn pslPtr() ?*const psl.PublicSuffixList {
    if (g_psl) |*list| return list;
    return null;
}

fn countFromHeaders(conn: *connection_mod.Connection) usize {
    var count: usize = 0;
    for (conn.headers.items) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "From")) count += 1;
    }
    return count;
}

/// The Message-ID this message carries, if it carries exactly one.
///
/// Null when absent *or* duplicated. A second Message-ID would let a sender pick
/// which one we sample on, and RFC 5322 §3.6 allows at most one, so a message
/// with two has no single identity to key a stable decision to (audit M-4).
fn getMessageId(conn: *connection_mod.Connection) ?[]const u8 {
    var found: ?[]const u8 = null;
    for (conn.headers.items) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "Message-ID")) continue;
        if (found != null) return null;
        found = mem.trim(u8, hdr.value, &std.ascii.whitespace);
    }
    return found;
}

/// The address in the `From` header, without any display name.
///
/// Split out from `getFromDomain` so the reporting event can state the full
/// address RFC 7489 §7.2 asks for without a second, possibly divergent, parse of
/// the same header (audit M-7a).
fn getFromAddress(conn: *connection_mod.Connection) ?[]const u8 {
    for (conn.headers.items) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "From")) {
            // Extract email address from From: header value
            // Handle "Display Name <addr@domain>" and bare "addr@domain"
            const val = mem.trim(u8, hdr.value, &std.ascii.whitespace);
            if (mem.lastIndexOfScalar(u8, val, '>')) |gt| {
                if (mem.lastIndexOfScalar(u8, val[0..gt], '<')) |lt| {
                    return val[lt + 1 .. gt];
                }
            }
            return val;
        }
    }
    return null;
}

fn getFromDomain(conn: *connection_mod.Connection) ?[]const u8 {
    return alignment.getDomainFromEmail(getFromAddress(conn) orelse return null);
}

fn getEnvelopeDomain(conn: *connection_mod.Connection) ?[]const u8 {
    const raw = conn.mail_from_raw orelse return null;
    const addr = alignment.stripAngleBrackets(raw);
    return alignment.getDomainFromEmail(addr);
}

/// One DMARC evaluation, as the future `securedmarc-reporter` needs to see it.
///
/// The field set is the one the suite plan specifies, which in turn is what
/// RFC 7489 §7.2 requires of an aggregate report row. Five of these used to be
/// absent (audit M-7a). `client_ip` was the one that mattered: it is mandatory on
/// every `<record><row>` and it is the only field here that a subscriber cannot
/// reconstruct after the fact, because the connecting address is known to the
/// milter and to nothing downstream of it.
const Event = struct {
    client_ip: []const u8,
    from_domain: []const u8,
    header_from: []const u8,
    envelope_from: []const u8,
    /// What the Domain Owner published, before `t=y` or `pct=` reduced it.
    policy: []const u8,
    /// What we actually applied, after those reductions.
    disposition: []const u8,
    dmarc_result: []const u8,
    spf_result: []const u8,
    spf_aligned: bool,
    dkim_result: []const u8,
    dkim_domain: []const u8,
    dkim_aligned: bool,
};

fn publishEvent(allocator: Allocator, ev: Event) void {
    const json = formatEvent(allocator, ev) catch return;
    defer allocator.free(json);

    getPublisher().publish(json);
}

/// Serialize one event.
///
/// Separate from `publishEvent` so the payload can be asserted on without a ZMQ
/// socket: the field set is a contract with a consumer that does not exist yet,
/// which is exactly the kind of thing that silently rots if nothing checks it.
fn formatEvent(allocator: Allocator, ev: Event) ![]u8 {
    // `from_domain`, `header_from`, `dkim_domain` and `envelope_from` all
    // originate in the message or its envelope, so each is sender-chosen; the
    // results, the policy and the disposition are ours, and `client_ip` comes
    // from the MTA rather than the message. A `"` in any sender-chosen value used
    // to end its JSON string early and leave the rest of the payload to be
    // reinterpreted by the consumer (audit X-5), so every value that did not
    // originate here is escaped — `client_ip` included, since a value being
    // trustworthy today is not a reason for the payload to depend on it.
    return std.fmt.allocPrint(allocator,
        \\{{"client_ip":"{f}","from_domain":"{f}","header_from":"{f}","envelope_from":"{f}","policy":"{s}","disposition":"{s}","dmarc_result":"{s}","spf_result":"{s}","spf_aligned":{s},"dkim_result":"{s}","dkim_domain":"{f}","dkim_aligned":{s}}}
    , .{
        escape.jsonString(ev.client_ip),
        escape.jsonString(ev.from_domain),
        escape.jsonString(ev.header_from),
        escape.jsonString(ev.envelope_from),
        ev.policy,
        ev.disposition,
        ev.dmarc_result,
        ev.spf_result,
        if (ev.spf_aligned) "true" else "false",
        ev.dkim_result,
        escape.jsonString(ev.dkim_domain),
        if (ev.dkim_aligned) "true" else "false",
    });
}

/// Record the DMARC result on the message.
///
/// Both stamping functions here returned `void` and swallowed every failure, so
/// a message could be delivered carrying no `dmarc=` field while the daemon
/// reported success (audit X-9). This daemon is the end of the chain: its field
/// is what a downstream mailbox provider or a local delivery rule reads to decide
/// disposition. Losing it silently means the message is treated as if DMARC was
/// never evaluated, which for a `p=reject` domain is the difference between a
/// rejection and a delivery.
fn addArHeaderSimple(conn: *connection_mod.Connection, result_str: []const u8, reason: []const u8) !void {
    try auth_stamp.stamp(conn.allocator, conn.fd, g_authserv_id, &.{
        .{
            .method = "dmarc",
            .result = result_str,
            .reason = reason,
            .properties = &.{},
        },
    });
}

fn addArHeaderFull(
    conn: *connection_mod.Connection,
    result_str: []const u8,
    from_domain: []const u8,
    disposition: []const u8,
) !void {
    const reason = try std.fmt.allocPrint(conn.allocator, "p={s}", .{disposition});
    defer conn.allocator.free(reason);

    try auth_stamp.stamp(conn.allocator, conn.fd, g_authserv_id, &.{
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
    });
}

fn dupeOrNull(allocator: Allocator, s: []const u8) ?[]const u8 {
    return allocator.dupe(u8, s) catch null;
}

// =============================================================================
// Reload
// =============================================================================

/// Main-thread reload callback. SecureDMARC holds no reloadable file state:
/// DMARC records are read from DNS per message, and the optional public suffix
/// list is loaded once at startup. Swapping that list under running workers
/// would free memory they are reading, so refreshing it requires a restart
/// until the RCU config container exists (audit X-2).
fn reloadConfig() void {
    _ = g_config_gen.increment();
    // Wake the workers so they notice the new generation and drop their cached
    // resolver promptly, rather than on their next message.
    g_config_gen.wake();
    log.info("SIGHUP: config generation advanced to {d}", .{g_config_gen.load()});
}

fn onWorkerReload() void {
    // Drop the cached resolver so a reload picks up new nameservers and starts
    // from a clean cache rather than serving answers from the old config.
    if (tl_resolver) |*r| {
        r.deinit();
        tl_resolver = null;
    }
    log.debug("worker: config reload acknowledged", .{});
}

// =============================================================================
// Tests
// =============================================================================

// Every module has to be named here or its tests are silently skipped: the
// test root is main.zig, and Zig only analyses what is referenced. A file added
// without a line here still compiles, still looks tested, and never runs —
// verified by making a test in `upstream.zig` assert false and watching
// `zig build test` pass.
test {
    _ = dmarc;
    _ = @import("dmarc_test.zig");
    _ = alignment;
    _ = treewalk;
    _ = psl;
    _ = upstream;
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

test "M-7a: the event carries every field an aggregate report row needs" {
    // The consumer does not exist yet, so nothing else would notice a field going
    // missing until the reporter was written and found the data unrecoverable.
    // `client_ip` is the one that cannot be backfilled: it is mandatory on every
    // RFC 7489 §7.2 `<record><row>` and only the milter ever sees it.
    const json = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .from_domain = "example.com",
        .header_from = "sender@example.com",
        .envelope_from = "bounce@example.com",
        .policy = "reject",
        .disposition = "quarantine",
        .dmarc_result = "fail",
        .spf_result = "pass",
        .spf_aligned = false,
        .dkim_result = "pass",
        .dkim_domain = "example.com",
        .dkim_aligned = true,
    });
    defer std.testing.allocator.free(json);

    for ([_][]const u8{
        "\"client_ip\":\"203.0.113.42\"",
        "\"header_from\":\"sender@example.com\"",
        "\"envelope_from\":\"bounce@example.com\"",
        "\"policy\":\"reject\"",
        "\"disposition\":\"quarantine\"",
        "\"dmarc_result\":\"fail\"",
        "\"spf_aligned\":false",
        "\"dkim_aligned\":true",
    }) |needle| {
        if (mem.indexOf(u8, json, needle) == null) {
            std.debug.print("event payload missing {s}\ngot: {s}\n", .{ needle, json });
            return error.TestFailed;
        }
    }
}

test "M-7a: the published policy and the applied disposition are reported separately" {
    // A domain mid-rollout publishes `p=reject` and gets `quarantine` applied.
    // Reporting only one of the two would make it indistinguishable, in the
    // aggregate report, from a domain that asked for `quarantine` outright -- so
    // the Domain Owner could not tell their own rollout was in effect.
    var record = dmarc.DmarcRecord{ .policy = .reject, .testing = .testing };

    const published = dmarc.publishedPolicy(&record, false);
    const applied = dmarc.effectivePolicySampled(&record, false, .ignore, null);

    try std.testing.expectEqualStrings("reject", published.toString());
    try std.testing.expectEqualStrings("quarantine", applied.toString());

    const json = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .from_domain = "example.com",
        .header_from = "sender@example.com",
        .envelope_from = "sender@example.com",
        .policy = published.toString(),
        .disposition = applied.toString(),
        .dmarc_result = "fail",
        .spf_result = "fail",
        .spf_aligned = false,
        .dkim_result = "fail",
        .dkim_domain = "",
        .dkim_aligned = false,
    });
    defer std.testing.allocator.free(json);

    try std.testing.expect(mem.indexOf(u8, json, "\"policy\":\"reject\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"disposition\":\"quarantine\"") != null);
}

test "M-7a: a quote in a sender-chosen field cannot break the payload" {
    // header_from is taken from the message, so it is chosen by whoever sent it.
    // Unescaped, the `"` would close the string and hand the rest of the object to
    // the sender to redefine -- X-5, in a new field.
    const json = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .from_domain = "example.com",
        .header_from = "a\",\"policy\":\"none\",\"x\":\"b@example.com",
        .envelope_from = "sender@example.com",
        .policy = "reject",
        .disposition = "reject",
        .dmarc_result = "fail",
        .spf_result = "fail",
        .spf_aligned = false,
        .dkim_result = "fail",
        .dkim_domain = "",
        .dkim_aligned = false,
    });
    defer std.testing.allocator.free(json);

    // The injected `"policy":"none"` must not appear as a structural member.
    try std.testing.expect(mem.indexOf(u8, json, "\"policy\":\"none\"") == null);
    try std.testing.expect(mem.indexOf(u8, json, "\"policy\":\"reject\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "reject",
        parsed.value.object.get("policy").?.string,
    );
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

// X-9: both wrappers must stay fallible.
//
// Both returned `void` and swallowed every failure, so a message could be
// delivered with no `dmarc=` field while this daemon reported success. This
// daemon is the end of the chain, so that field is the only record of the
// verdict: losing it silently means the message is treated as though DMARC was
// never evaluated, which for a `p=reject` domain is the difference between a
// rejection and a delivery.
test "the DMARC stamping wrappers cannot swallow failures" {
    comptime {
        for (.{ addArHeaderSimple, addArHeaderFull }) |f| {
            const ret = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
            if (@typeInfo(ret) != .error_union) @compileError(
                "the DMARC stamping wrappers must return an error union. Swallowing a " ++
                    "failure delivers the message with no dmarc= field while reporting " ++
                    "success, and this daemon is the end of the chain: nothing downstream " ++
                    "can reconstruct the verdict (audit X-9).",
            );
            if (@typeInfo(ret).error_union.payload != void) @compileError(
                "the DMARC stamping wrappers should return !void.",
            );
        }
    }
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
