//! Public Suffix List load and lookup benchmark.
//!
//! Run with `zig build bench`, optionally passing a path to a list:
//!
//!     zig build bench
//!     zig build bench -- /path/to/public_suffix_list.dat
//!
//! Built ReleaseSafe regardless of -Doptimize, because the point is to measure
//! what the daemon ships. Skips with a note rather than failing when the list
//! is not installed, so it stays runnable on a machine without the package.
//!
//! Context for reading the output: isPublicSuffix is consulted at most once
//! per organizational-domain decision, and only on the tree walk's rule-3
//! path — an explicit psd= tag or a walk that found nothing returns before
//! touching the list. There are at most three such decisions per message
//! (author domain, SPF identifier, DKIM identifier), so per-message cost is
//! at most three times the figure below, against a tree walk of up to eight
//! DNS queries per identity.

const std = @import("std");
const psl = @import("psl");

const DEFAULT_PATH = "/usr/local/share/public_suffix_list/public_suffix_list.dat";

/// Names that are public suffixes: the path that returns true and vetoes a
/// tree walk result.
const HITS = [_][]const u8{
    "com",
    "co.uk",
    "org.uk",
    "ac.jp",
    "com.au",
    "github.io",
    "s3.amazonaws.com",
};

/// Names a real message carries: author and identifier domains. The tree walk
/// picked a registrable name and the list is asked to confirm it is not a
/// registry, so this is the common case.
const MISSES = [_][]const u8{
    "example.com",
    "bambania.com",
    "victim.co.uk",
    "a.victim.co.uk",
    "attacker.co.uk",
    "mail.google.com",
};

/// The monotonic clock is quantised on some hosts — on FreeBSD/amd64 here it
/// moves in 10 ms steps, so a single load times as either 0 or 10 ms. Grow the
/// iteration count until the timed region is long enough for that quantum to
/// be noise rather than the measurement.
const MIN_RUN_NS: u64 = 500 * std.time.ns_per_ms;
const MAX_ITERS: usize = 1 << 32;

const Measurement = struct {
    ns_per_op: f64,
    ops: usize,
    elapsed_ns: u64,
    sink: usize,
};

fn measure(list: *const psl.PublicSuffixList, names: []const []const u8) !Measurement {
    var iters: usize = 1024;
    while (true) {
        var sink: usize = 0;
        var t = try std.time.Timer.start();
        var i: usize = 0;
        while (i < iters) : (i += 1) {
            for (names) |n| {
                if (list.isPublicSuffix(n)) sink +%= 1;
            }
        }
        const ns = t.read();
        const ops = iters * names.len;

        if (ns >= MIN_RUN_NS) {
            return .{
                .ns_per_op = @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(ops)),
                .ops = ops,
                .elapsed_ns = ns,
                .sink = sink,
            };
        }
        // A clock stuck at zero would spin forever otherwise.
        if (iters >= MAX_ITERS) return error.ClockTooCoarse;
        iters *= 4;
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .enable_memory_limit = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const path = if (args.len > 1) args[1] else DEFAULT_PATH;

    std.fs.cwd().access(path, .{}) catch |err| {
        std.debug.print(
            \\public suffix list not found at {s} ({s})
            \\
            \\Install it with:  pkg install public_suffix_list
            \\Or pass a path:   zig build bench -- /path/to/public_suffix_list.dat
            \\
        , .{ path, @errorName(err) });
        return;
    };

    const before = gpa.total_requested_bytes;
    var list = psl.PublicSuffixList.init(allocator);
    defer list.deinit();
    try list.loadFile(path);
    const held = gpa.total_requested_bytes - before;

    // Repeat the load for the same reason the lookups are repeated.
    var load_reps: usize = 1;
    var load_ns: u64 = 0;
    while (true) {
        var t = try std.time.Timer.start();
        var r: usize = 0;
        while (r < load_reps) : (r += 1) {
            var scratch = psl.PublicSuffixList.init(allocator);
            defer scratch.deinit();
            try scratch.loadFile(path);
            std.mem.doNotOptimizeAway(scratch.count());
        }
        load_ns = t.read();
        if (load_ns >= MIN_RUN_NS or load_reps >= 4096) break;
        load_reps *= 4;
    }

    std.debug.print("list           : {s}\n", .{path});
    std.debug.print("\n--- load (once, at startup) ---\n", .{});
    std.debug.print("rules          : {d}\n", .{list.count()});
    std.debug.print("load           : {d:.2} ms   (mean of {d})\n", .{
        @as(f64, @floatFromInt(load_ns)) / @as(f64, @floatFromInt(load_reps)) / 1e6,
        load_reps,
    });
    std.debug.print("memory         : {d} bytes requested ({d:.1} KiB)\n", .{
        held,
        @as(f64, @floatFromInt(held)) / 1024.0,
    });

    // A hit set that silently stopped matching would turn the veto benchmark
    // into a second miss benchmark without saying so.
    for (HITS) |h| {
        if (!list.isPublicSuffix(h)) {
            std.debug.print("\nWARNING: expected public suffix {s} is not in this list\n", .{h});
        }
    }

    const miss = try measure(&list, &MISSES);
    const hit = try measure(&list, &HITS);

    // Worst case the API permits: the longest name it will lowercase and hash
    // before deciding.
    var long_buf: [253]u8 = undefined;
    @memset(&long_buf, 'a');
    var k: usize = 3;
    while (k < long_buf.len) : (k += 4) long_buf[k] = '.';
    const long = try measure(&list, &.{&long_buf});

    std.debug.print("\n--- lookup (at most 3 per message) ---\n", .{});
    std.debug.print("miss, typical  : {d:6.1} ns/op   ({d} ops in {d} ms)\n", .{
        miss.ns_per_op, miss.ops, miss.elapsed_ns / std.time.ns_per_ms,
    });
    std.debug.print("hit, veto      : {d:6.1} ns/op   ({d} ops in {d} ms)\n", .{
        hit.ns_per_op, hit.ops, hit.elapsed_ns / std.time.ns_per_ms,
    });
    std.debug.print("253-char name  : {d:6.1} ns/op   ({d} ops in {d} ms)\n", .{
        long.ns_per_op, long.ops, long.elapsed_ns / std.time.ns_per_ms,
    });
    std.debug.print("\nworst case per message: {d:.0} ns\n", .{miss.ns_per_op * 3});

    std.mem.doNotOptimizeAway(miss.sink + hit.sink + long.sink);
}
