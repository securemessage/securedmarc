const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const config_mod = securemilter.config;
const connection_mod = securemilter.connection;
const worker_mod = securemilter.worker;
const daemon_mod = securemilter.daemon;
const bootstrap_mod = securemilter.bootstrap;
const negotiate = securemilter.milter.negotiate;
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;
const zmq = securemilter.zmq;
const log = securemilter.log;
const header_scrub = securemilter.header_scrub;

pub const dmarc = @import("dmarc.zig");
pub const alignment = @import("alignment.zig");
pub const treewalk = @import("treewalk.zig");
pub const psl = @import("psl.zig");
pub const upstream = @import("upstream.zig");
pub const settings = @import("settings.zig");
pub const flow = @import("flow.zig");

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

/// Wall-clock bound on one message's evaluation (X-21). Set once at startup;
/// 0 disables.
var g_max_evaluation_ms: i64 = deadline_mod.DEFAULT_MS;

/// Start health monitor. Context-free to match `daemon.Options.spawn_threads`;
/// safe after daemonize and signal blocking.
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

/// The loaded public suffix list, or null when none was configured.
///
/// Read-only for the life of the process -- `reloadConfig` below declines to
/// swap it under running workers on purpose -- so handing out a pointer to it
/// is safe for as long as any message holds one.
fn pslPtr() ?*const psl.PublicSuffixList {
    if (g_psl) |*list| return list;
    return null;
}

/// Gather what the flow reads from this file's state, once per message.
///
/// Every global here is written during `runDaemon` before the worker pool
/// spawns and is read-only afterwards, so this collects already-settled state
/// rather than racing a writer. Doing it at one call site is what keeps
/// `flow.zig` from reaching back into this module.
///
/// `resolver` and `publisher` are passed as the accessors themselves, not as
/// pointers to constructed objects -- see the note on `flow.MsgCtx`, which is
/// where the reasoning lives.
fn msgCtx() flow.MsgCtx {
    return .{
        .authserv_id = g_authserv_id,
        .strip_policy = g_strip_policy,
        .sampling = g_sampling,
        .psl = pslPtr(),
        .resolver = getResolver,
        .publisher = getPublisher,
        .max_evaluation_ms = g_max_evaluation_ms,
    };
}

/// `worker.Callbacks.on_eom` is a bare function pointer and cannot carry a
/// context, so the context is built here and handed to the flow.
fn onEom(conn: *connection_mod.Connection) u8 {
    return flow.doEom(conn, msgCtx());
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

    const dmarc_cfg = settings.parseDmarcConfig(allocator, &cfg) catch |err| {
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
    g_max_evaluation_ms = dmarc_cfg.max_evaluation_ms;
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
        .umask = dmarc_cfg.umask,
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

    var threads = try securemilter.pool.spawnPool(allocator, .{
        .num_workers = dmarc_cfg.worker_threads,
        .addresses = dmarc_cfg.listen_addresses,
        .callbacks = callbacks,
        .shutdown_pipe_rd = shutdown_pipe[0],
        .config_gen = &g_config_gen,
        .max_connections = dmarc_cfg.max_connections,
    });
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
    _ = alignment;
    _ = treewalk;
    _ = psl;
    _ = upstream;
    _ = settings;
    _ = flow;
}
