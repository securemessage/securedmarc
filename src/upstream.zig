const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_results = securemilter.auth_results;
const header_scrub = securemilter.header_scrub;

const alignment = @import("alignment.zig");

/// Reading the authentication results produced earlier in this milter chain.
///
/// DMARC does not authenticate anything itself: it reads the SPF and DKIM
/// results that upstream milters recorded in `Authentication-Results` and asks
/// whether either aligns with the Author Domain. That makes this the point
/// where a forged or misread header becomes a DMARC verdict, so it is worth
/// keeping separate from the milter plumbing and testing directly.
///
/// The rule that matters (audit M-6): **a result and the properties describing
/// it are one unit.** Collecting `dkim=` verdicts with one scan and `header.d=`
/// domains with another lets a `pass` earned by one signature be paired with a
/// domain named by a different one — or by no signature at all, if the text sat
/// inside a comment. Everything here is built per result, from that result's
/// own property span.
pub const Upstream = struct {
    /// The first `spf=` result found, if any.
    spf_result: ?[]const u8 = null,
    /// One identifier per `dkim=` result, each carrying its own `header.d`.
    dkim: []alignment.Identifier = &.{},
    /// True when more DKIM results were present than `max_dkim` allowed.
    truncated: bool = false,

    pub fn deinit(self: *Upstream, allocator: Allocator) void {
        if (self.spf_result) |s| allocator.free(s);
        for (self.dkim) |d| {
            if (d.domain) |s| allocator.free(s);
            if (d.result) |s| allocator.free(s);
        }
        allocator.free(self.dkim);
        self.* = .{};
    }
};

/// Collect the upstream results from every A-R header claiming `authserv_id`.
///
/// `max_dkim` bounds the identifiers returned. The count of `dkim=` results in
/// a header is chosen by whoever sent the message, and each relaxed-mode
/// identifier that passed can cost a DNS tree walk later, so this is the same
/// reasoning as the other content caps (audit X-4).
///
/// Allocation failure yields a shorter list rather than an error: a DMARC
/// verdict computed from fewer identifiers is conservative — it can only fail
/// to find an alignment, never invent one.
pub fn collect(
    allocator: Allocator,
    headers: []const connection_mod.Header,
    authserv_id: []const u8,
    max_dkim: usize,
) Upstream {
    var out = Upstream{};

    var dkim: std.ArrayListUnmanaged(alignment.Identifier) = .{};
    defer dkim.deinit(allocator);

    for (headers) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, header_scrub.HEADER_NAME)) continue;
        // Only results this ADMD recorded are trustworthy. Anything else is a
        // claim by the sender about its own authentication.
        if (!auth_results.matchesAuthservId(hdr.value, authserv_id)) continue;

        var parsed = auth_results.parseResults(allocator, hdr.value) catch continue;
        defer parsed.deinit(allocator);

        for (parsed.results.items) |r| {
            if (out.spf_result == null and std.ascii.eqlIgnoreCase(r.method, "spf")) {
                out.spf_result = allocator.dupe(u8, r.result) catch null;
                continue;
            }
            if (!std.ascii.eqlIgnoreCase(r.method, "dkim")) continue;
            if (dkim.items.len >= max_dkim) {
                out.truncated = true;
                break;
            }
            // A signature with no d= cannot align, but it is still recorded so
            // the count an operator sees matches the header.
            const d = r.property("header.d");
            dkim.append(allocator, .{
                .domain = if (d) |v| (allocator.dupe(u8, v) catch null) else null,
                .result = allocator.dupe(u8, r.result) catch null,
            }) catch break;
        }
    }

    out.dkim = dkim.toOwnedSlice(allocator) catch &.{};
    return out;
}

// =============================================================================
// Tests
// =============================================================================

const testing = std.testing;

fn arHeader(value: []const u8) connection_mod.Header {
    return .{ .name = "Authentication-Results", .value = value };
}

test "a single signature yields its own domain" {
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; spf=pass smtp.mailfrom=a.test; dkim=pass header.d=a.test")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqualStrings("pass", up.spf_result.?);
    try testing.expectEqual(@as(usize, 1), up.dkim.len);
    try testing.expectEqualStrings("a.test", up.dkim[0].domain.?);
    try testing.expectEqualStrings("pass", up.dkim[0].result.?);
}

test "M-6: each signature keeps the domain it earned" {
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; dkim=fail header.d=noise.test; dkim=pass header.d=real.test")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), up.dkim.len);
    try testing.expectEqualStrings("fail", up.dkim[0].result.?);
    try testing.expectEqualStrings("noise.test", up.dkim[0].domain.?);
    try testing.expectEqualStrings("pass", up.dkim[1].result.?);
    try testing.expectEqualStrings("real.test", up.dkim[1].domain.?);
}

test "M-6: a domain in a comment on another method is not borrowed" {
    // The bypass: the only `header.d=` text in the header belongs to no dkim
    // result at all. The passing signature must come back with no domain, which
    // cannot align, rather than with victim.test.
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; spf=fail (header.d=victim.test ) ; dkim=pass")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), up.dkim.len);
    try testing.expectEqualStrings("pass", up.dkim[0].result.?);
    try testing.expect(up.dkim[0].domain == null);
}

test "M-6: results are gathered across several A-R headers" {
    var up = collect(
        testing.allocator,
        &.{
            arHeader("mx.test; dkim=pass header.d=one.test"),
            arHeader("mx.test; dkim=pass header.d=two.test"),
        },
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), up.dkim.len);
    try testing.expectEqualStrings("one.test", up.dkim[0].domain.?);
    try testing.expectEqualStrings("two.test", up.dkim[1].domain.?);
}

test "headers from another authserv-id are ignored" {
    var up = collect(
        testing.allocator,
        &.{arHeader("evil.test; dkim=pass header.d=victim.test")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 0), up.dkim.len);
    try testing.expect(up.spf_result == null);
}

test "the identifier count is capped and the truncation is reported" {
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; dkim=pass header.d=a; dkim=pass header.d=b; dkim=pass header.d=c")},
        "mx.test",
        2,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), up.dkim.len);
    try testing.expect(up.truncated);
}
