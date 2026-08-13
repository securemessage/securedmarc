const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_results = securemilter.auth_results;
const header_scrub = securemilter.header_scrub;

const alignment = @import("alignment.zig");

/// Collect trusted upstream SPF and DKIM authentication results.
///
/// Each DKIM result remains paired with properties from its own result span.
pub const Upstream = struct {
    /// The first `spf=` result found, if any.
    spf_result: ?[]const u8 = null,
    /// The first `arc=` result found, if any — our own securearc's verdict,
    /// consumed by the trusted-sealer override (design-dmarc-enforcement §5a).
    arc_result: ?[]const u8 = null,
    /// One identifier per `dkim=` result, each carrying its own `header.d`.
    dkim: []alignment.Identifier = &.{},
    /// True when more DKIM results were present than `max_dkim` allowed.
    truncated: bool = false,

    pub fn deinit(self: *Upstream, allocator: Allocator) void {
        if (self.spf_result) |s| allocator.free(s);
        if (self.arc_result) |s| allocator.free(s);
        for (self.dkim) |d| {
            if (d.domain) |s| allocator.free(s);
            if (d.result) |s| allocator.free(s);
        }
        allocator.free(self.dkim);
        self.* = .{};
    }
};

/// Collect results from A-R headers claiming `authserv_id`.
///
/// `max_dkim` bounds later identifier tree walks; allocation failure conservatively
/// produces a shorter candidate list.
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
            if (out.arc_result == null and std.ascii.eqlIgnoreCase(r.method, "arc")) {
                out.arc_result = allocator.dupe(u8, r.result) catch null;
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

            // securedkim marks a result whose key was published `t=y` (D-11).
            // Read from this result's own property span, like everything else
            // here: a marker attached to one signature must not silence another,
            // which is the same pairing rule M-6 was about. Compared against the
            // shared constant so the two daemons cannot drift apart.
            const marker = r.property(
                auth_results.testing_key_marker.ptype ++ "." ++ auth_results.testing_key_marker.property,
            );
            const is_testing = if (marker) |v|
                std.ascii.eqlIgnoreCase(v, auth_results.testing_key_marker.value)
            else
                false;

            dkim.append(allocator, .{
                .domain = if (d) |v| (allocator.dupe(u8, v) catch null) else null,
                .result = allocator.dupe(u8, r.result) catch null,
                .testing = is_testing,
            }) catch break;
        }
    }

    out.dkim = dkim.toOwnedSlice(allocator) catch &.{};
    return out;
}

/// Trusted-sealer evidence for the disposition override
/// (design-dmarc-enforcement.md §5a).
///
/// Returns the listed authserv-id whose ARC-Authentication-Results shows pass
/// evidence for `from_domain`, or null. Pass evidence is deliberately narrow:
/// a `dmarc=pass` the sealer computed itself, or an exact-domain `dkim=pass` /
/// `spf=pass` — no organizational walk on this path, so only an exact match
/// needs none. Anything looser would let a sealer's pass for an unrelated
/// domain stand in for the author domain.
///
/// This reads CONTENT, not crypto: chain validity is a separate question our
/// own securearc already answered (`arc=` in `Upstream`), and an honest
/// sealer's AAR recording a failure must not trigger anything here.
pub fn trustedSealerEvidence(
    allocator: Allocator,
    headers: []const connection_mod.Header,
    sealers: []const []const u8,
    from_domain: []const u8,
) ?[]const u8 {
    if (from_domain.len == 0) return null;
    for (headers) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "ARC-Authentication-Results")) continue;
        // AAR form: "i=N; authserv-id; results". The instance tag is skipped,
        // not parsed — a missing one means this is not an AAR at all.
        const rest = skipInstanceTag(hdr.value) orelse continue;
        const id = auth_results.authservId(rest);
        if (!isListed(sealers, id)) continue;
        var parsed = auth_results.parseResults(allocator, rest) catch continue;
        defer parsed.deinit(allocator);
        if (aarShowsPass(parsed.results.items, from_domain)) {
            return allocator.dupe(u8, id) catch null;
        }
    }
    return null;
}

fn skipInstanceTag(value: []const u8) ?[]const u8 {
    const trimmed = mem.trimLeft(u8, value, &std.ascii.whitespace);
    if (trimmed.len < 2 or !std.ascii.eqlIgnoreCase(trimmed[0..2], "i=")) return null;
    const semi = mem.indexOfScalar(u8, trimmed, ';') orelse return null;
    return trimmed[semi + 1 ..];
}

fn isListed(sealers: []const []const u8, id: []const u8) bool {
    for (sealers) |s| {
        if (std.ascii.eqlIgnoreCase(s, id)) return true;
    }
    return false;
}

fn aarShowsPass(results: []const auth_results.ParsedHeader.ParsedResult, from_domain: []const u8) bool {
    for (results) |r| {
        if (!r.passed()) continue;
        if (std.ascii.eqlIgnoreCase(r.method, "dmarc")) return true;
        if (std.ascii.eqlIgnoreCase(r.method, "dkim")) {
            if (r.property("header.d")) |d| {
                if (std.ascii.eqlIgnoreCase(d, from_domain)) return true;
            }
        }
        if (std.ascii.eqlIgnoreCase(r.method, "spf")) {
            if (r.property("smtp.mailfrom")) |mf| {
                const dom = alignment.getDomainFromEmail(mf) orelse mf;
                if (std.ascii.eqlIgnoreCase(dom, from_domain)) return true;
            }
        }
    }
    return false;
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

test "D-11: a testing-key marker is read, and keeps the result it decorates" {
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; dkim=pass header.d=a.test policy.dkim-rules=testing-key")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), up.dkim.len);
    // The result is still reported as what the verifier found.
    try testing.expectEqualStrings("pass", up.dkim[0].result.?);
    try testing.expectEqualStrings("a.test", up.dkim[0].domain.?);
    // But it is not something to decide on.
    try testing.expect(up.dkim[0].testing);
    try testing.expect(!up.dkim[0].passed());
}

test "D-11: an unmarked result is not marked testing" {
    // The guard. If the marker were detected on everything, no DKIM pass would
    // ever reach DMARC and every domain relying on DKIM alignment would start
    // failing -- with nothing in the A-R to show why.
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; dkim=pass header.d=a.test")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), up.dkim.len);
    try testing.expect(!up.dkim[0].testing);
    try testing.expect(up.dkim[0].passed());
}

test "D-11: the marker binds to its own signature, not the next one" {
    // Same pairing rule as M-6, applied to the new property. A testing key
    // signing first must not silence a real signature that follows it -- that
    // would be a way to suppress a domain's genuine DKIM pass by prepending a
    // signature from a throwaway domain published `t=y`.
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; dkim=pass header.d=test.test policy.dkim-rules=testing-key; " ++
            "dkim=pass header.d=real.test")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 2), up.dkim.len);
    try testing.expect(up.dkim[0].testing);
    try testing.expect(!up.dkim[0].passed());
    try testing.expect(!up.dkim[1].testing);
    try testing.expect(up.dkim[1].passed());
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

test "our own arc= verdict is collected alongside spf=" {
    var up = collect(
        testing.allocator,
        &.{arHeader("mx.test; spf=pass smtp.mailfrom=a.test; arc=pass")},
        "mx.test",
        10,
    );
    defer up.deinit(testing.allocator);

    try testing.expectEqualStrings("pass", up.arc_result.?);
}

fn aarHeader(value: []const u8) connection_mod.Header {
    return .{ .name = "ARC-Authentication-Results", .value = value };
}

test "a trusted sealer's dmarc=pass is evidence" {
    const sealers = [_][]const u8{"forwarder.test"};
    const found = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("i=1; forwarder.test; dmarc=pass header.from=victim.test"),
    }, &sealers, "victim.test");
    defer if (found) |f| testing.allocator.free(f);
    try testing.expectEqualStrings("forwarder.test", found.?);
}

test "an unlisted sealer's dmarc=pass is not evidence" {
    const sealers = [_][]const u8{"forwarder.test"};
    const found = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("i=1; stranger.test; dmarc=pass header.from=victim.test"),
    }, &sealers, "victim.test");
    try testing.expect(found == null);
}

test "a trusted sealer's recorded FAILURE is not evidence" {
    // The override exists because an intact chain carries the assessment at
    // acceptance; a chain that honestly sealed a failure carries nothing to
    // override with.
    const sealers = [_][]const u8{"forwarder.test"};
    const found = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("i=1; forwarder.test; dmarc=fail header.from=victim.test"),
    }, &sealers, "victim.test");
    try testing.expect(found == null);
}

test "exact-domain dkim=pass is evidence; a parent domain is not" {
    const sealers = [_][]const u8{"forwarder.test"};
    // No organizational walk on this path: exact match only, so a sealer's
    // pass for the parent cannot stand in for the author domain.
    const exact = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("i=1; forwarder.test; dkim=pass header.d=victim.test"),
    }, &sealers, "victim.test");
    defer if (exact) |f| testing.allocator.free(f);
    try testing.expect(exact != null);

    const parent = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("i=1; forwarder.test; dkim=pass header.d=victim.test"),
    }, &sealers, "sub.victim.test");
    try testing.expect(parent == null);
}

test "spf=pass evidence matches on the mailfrom domain, not a comment" {
    const sealers = [_][]const u8{"forwarder.test"};
    const found = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("i=1; forwarder.test; spf=pass smtp.mailfrom=bounce@victim.test"),
    }, &sealers, "victim.test");
    defer if (found) |f| testing.allocator.free(f);
    try testing.expect(found != null);
}

test "a missing i= tag means the header is not treated as an AAR" {
    const sealers = [_][]const u8{"forwarder.test"};
    const found = trustedSealerEvidence(testing.allocator, &.{
        aarHeader("forwarder.test; dmarc=pass header.from=victim.test"),
    }, &sealers, "victim.test");
    try testing.expect(found == null);
}
