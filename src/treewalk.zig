const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;
const log = securemilter.log;

const dmarc = @import("dmarc.zig");
const psl_mod = @import("psl.zig");

/// RFC 9989 §4.10 DNS Tree Walk.
///
/// DMARC needs the boundary between the labels a registry controls and the
/// labels a registrant controls. RFC 7489 outsourced that question to the
/// Public Suffix List; RFC 9989 answers it from the DNS itself by walking up
/// the hierarchy looking for DMARC policy records, with the psd= tag letting
/// a zone state which side of the boundary it is on.
///
/// The walk is bounded: at most MAX_QUERIES lookups, and domains with eight or
/// more labels are shortened to seven before walking, so a sender cannot force
/// unbounded DNS work with a deeply nested Author Domain.
/// RFC 9989 §4.10: eight queries maximum.
pub const MAX_QUERIES: usize = 8;

/// Label count at which the walk stops removing labels one at a time.
const LABEL_SHORTCUT: usize = 8;

/// One name at which a valid DMARC policy record was found.
pub const Found = struct {
    domain: []const u8,
    record: dmarc.DmarcRecord,
    labels: usize,
};

pub const Walk = struct {
    allocator: Allocator,
    /// Names carrying a valid record, in query order (longest name first).
    found: std.ArrayListUnmanaged(Found) = .{},
    /// Names visited, owned by the walk. `found` entries point into these.
    names: std.ArrayListUnmanaged([]const u8) = .{},
    /// The domain the walk started from.
    start: []const u8 = "",
    /// True if any lookup failed in a way that is not "no such record".
    transient_error: bool = false,

    pub fn deinit(self: *Walk) void {
        for (self.names.items) |n| self.allocator.free(n);
        self.names.deinit(self.allocator);
        self.found.deinit(self.allocator);
    }

    /// The record published at the starting domain itself, if any.
    pub fn recordAtStart(self: *const Walk) ?dmarc.DmarcRecord {
        for (self.found.items) |f| {
            if (eqlIgnoreCase(f.domain, self.start)) return f.record;
        }
        return null;
    }

    /// The record to apply when the starting domain publishes none: the one
    /// belonging to the Organizational or Public Suffix Domain.
    pub fn policyRecord(self: *const Walk) ?dmarc.DmarcRecord {
        if (self.found.items.len == 0) return null;
        return self.found.items[self.found.items.len - 1].record;
    }
};

/// Walk up from `domain`, collecting every name that publishes a valid DMARC
/// policy record. Caller owns the returned Walk.
pub fn walk(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    domain: []const u8,
) !Walk {
    var result = Walk{ .allocator = allocator };
    errdefer result.deinit();

    const start = try allocator.dupe(u8, domain);
    try result.names.append(allocator, start);
    result.start = start;

    var target: []const u8 = start;
    var queries: usize = 0;

    while (queries < MAX_QUERIES) : (queries += 1) {
        switch (lookup(allocator, resolver, target)) {
            .found => |record| {
                try result.found.append(allocator, .{
                    .domain = target,
                    .record = record,
                    .labels = countLabels(target),
                });
                // §4.10 steps 2 and 6: an explicit boundary declaration ends
                // the walk — there is nothing further up worth asking.
                if (record.psd != .unknown) break;
            },
            .absent => {},
            .transient => result.transient_error = true,
        }

        const next = nextTarget(target) orelse break;
        const owned = try allocator.dupe(u8, next);
        try result.names.append(allocator, owned);
        target = owned;
    }

    return result;
}

/// Determine the Organizational Domain from a completed walk
/// (RFC 9989 §4.10.2), optionally vetoed by a Public Suffix List.
///
/// The list is advisory: the tree walk decides, and the list may only reject a
/// boundary that is demonstrably a public suffix. It exists because rule 3
/// below trusts that a public suffix which publishes DMARC also publishes
/// psd=y; a registry that forgets the tag would otherwise be selected as an
/// Organizational Domain, which is precisely the collapse the PSL prevented.
pub fn organizationalDomain(w: *const Walk, psl: ?*const psl_mod.PublicSuffixList) []const u8 {
    // Rule 1: an explicit psd=n names the Organizational Domain outright.
    // Examined longest name first, as the RFC specifies.
    for (w.found.items) |f| {
        if (f.record.psd == .no) return f.domain;
    }

    // Rule 2: a psd=y above the starting point puts the boundary one label
    // below the declaring domain.
    for (w.found.items) |f| {
        if (f.record.psd != .yes) continue;
        if (eqlIgnoreCase(f.domain, w.start)) continue;
        return oneLabelBelow(w.start, f.domain) orelse f.domain;
    }

    // Rule 3: otherwise the shortest name that published a record.
    var best: ?Found = null;
    for (w.found.items) |f| {
        if (best == null or f.labels < best.?.labels) best = f;
    }

    if (best) |b| {
        if (psl) |list| {
            if (list.isPublicSuffix(b.domain)) {
                // The chosen boundary is a registry. Honour the list and step
                // one label back down toward the starting domain.
                log.warn("tree walk selected public suffix {s} as organizational domain; overriding", .{b.domain});
                return oneLabelBelow(w.start, b.domain) orelse w.start;
            }
        }
        return b.domain;
    }

    // Rule 4: nothing published anywhere, so the domain speaks only for itself.
    return w.start;
}

const LookupResult = union(enum) {
    found: dmarc.DmarcRecord,
    absent: void,
    transient: void,
};

fn lookup(allocator: Allocator, resolver: *dns_mod.Resolver, domain: []const u8) LookupResult {
    const qname = std.fmt.allocPrint(allocator, "_dmarc.{s}", .{domain}) catch return .transient;
    defer allocator.free(qname);

    var res = resolver.resolve(qname, .TXT) catch |err| {
        // An authoritative "no such name" is not a failure here, it is the
        // answer: almost every step of a tree walk asks about a `_dmarc` name
        // that does not exist. Reporting it as transient latched
        // `transient_error` on the walk, and since the flag is only consulted
        // when nothing was found anywhere, the visible effect was
        // `dmarc=temperror` for every domain that publishes no DMARC record —
        // which is most of them.
        //
        // The resolver could not express the difference until NegativeKind
        // existed; `transient_error` has always been documented as meaning
        // "failed in a way that is not 'no such record'".
        if (dns_mod.isTransientError(err)) return .transient;
        return .absent;
    };
    defer res.deinit();

    // §4.10 steps 2 and 6: more than one valid record at a name is
    // unresolvable ambiguity, so all of them are discarded.
    var record: ?dmarc.DmarcRecord = null;
    var count: usize = 0;
    var iter = res.txtRecords();
    while (iter.next()) |txt| {
        if (dmarc.parseRecord(txt)) |r| {
            record = r;
            count += 1;
        }
    }
    if (count != 1) return .absent;
    return .{ .found = record.? };
}

/// The next name to query, per §4.10 steps 3, 4 and 7.
fn nextTarget(target: []const u8) ?[]const u8 {
    const labels = countLabels(target);
    if (labels <= 1) return null;

    if (labels >= LABEL_SHORTCUT) {
        // Collapse straight to seven labels rather than querying each one.
        return dropLabels(target, labels - 7);
    }
    return dropLabels(target, 1);
}

fn dropLabels(domain: []const u8, count: usize) ?[]const u8 {
    var rest = domain;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        const dot = mem.indexOfScalar(u8, rest, '.') orelse return null;
        rest = rest[dot + 1 ..];
        if (rest.len == 0) return null;
    }
    return rest;
}

/// The subdomain of `ancestor` that lies on the path from `start`, i.e. one
/// label longer than `ancestor`. Null when `ancestor` is not a proper suffix.
fn oneLabelBelow(start: []const u8, ancestor: []const u8) ?[]const u8 {
    const start_labels = countLabels(start);
    const ancestor_labels = countLabels(ancestor);
    if (start_labels <= ancestor_labels) return null;
    return dropLabels(start, start_labels - ancestor_labels - 1);
}

pub fn countLabels(domain: []const u8) usize {
    if (domain.len == 0) return 0;
    var count: usize = 1;
    for (domain) |c| {
        if (c == '.') count += 1;
    }
    return count;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

// =============================================================================
// Tests
// =============================================================================

fn testWalk(allocator: Allocator, start: []const u8, entries: []const struct { []const u8, dmarc.DmarcRecord }) !Walk {
    var w = Walk{ .allocator = allocator };
    const owned_start = try allocator.dupe(u8, start);
    try w.names.append(allocator, owned_start);
    w.start = owned_start;
    for (entries) |e| {
        const name = try allocator.dupe(u8, e[0]);
        try w.names.append(allocator, name);
        try w.found.append(allocator, .{ .domain = name, .record = e[1], .labels = countLabels(name) });
    }
    return w;
}

test "count labels" {
    try std.testing.expectEqual(@as(usize, 4), countLabels("a.mail.example.com"));
    try std.testing.expectEqual(@as(usize, 1), countLabels("com"));
    try std.testing.expectEqual(@as(usize, 0), countLabels(""));
}

test "next target removes one label below the shortcut" {
    try std.testing.expectEqualStrings("mail.example.com", nextTarget("a.mail.example.com").?);
    try std.testing.expectEqualStrings("com", nextTarget("example.com").?);
    try std.testing.expect(nextTarget("com") == null);
}

test "next target collapses deep names to seven labels" {
    // RFC 9989 §4.10: the walk must not cost more than eight queries, so a
    // thirteen-label Author Domain jumps straight to seven labels. This is the
    // example given in the RFC; its second query is _dmarc.g.h.i.j.mail.example.com.
    const deep = "a.b.c.d.e.f.g.h.i.j.mail.example.com";
    try std.testing.expectEqual(@as(usize, 13), countLabels(deep));
    try std.testing.expectEqualStrings("g.h.i.j.mail.example.com", nextTarget(deep).?);
    try std.testing.expectEqual(@as(usize, 7), countLabels(nextTarget(deep).?));
}

test "a deep name costs no more than the query budget" {
    // Walking from the shortened name down to the TLD must fit in the eight
    // queries the RFC allows, counting the query at the starting name.
    var target: []const u8 = "a.b.c.d.e.f.g.h.i.j.mail.example.com";
    var queries: usize = 1;
    while (nextTarget(target)) |next| : (queries += 1) {
        target = next;
    }
    try std.testing.expectEqual(@as(usize, 8), queries);
    try std.testing.expectEqualStrings("com", target);
}

test "one label below" {
    try std.testing.expectEqualStrings("mail.example.com", oneLabelBelow("a.mail.example.com", "example.com").?);
    try std.testing.expectEqualStrings("example.com", oneLabelBelow("a.mail.example.com", "com").?);
    try std.testing.expect(oneLabelBelow("example.com", "example.com") == null);
}

test "organizational domain: shortest name that published a record" {
    const allocator = std.testing.allocator;
    // The M-2 exploit: victim publishes at two levels, attacker at one, and
    // neither co.uk nor uk publishes anything.
    var victim = try testWalk(allocator, "a.victim.co.uk", &.{
        .{ "a.victim.co.uk", .{ .policy = .reject } },
        .{ "victim.co.uk", .{ .policy = .reject } },
    });
    defer victim.deinit();
    try std.testing.expectEqualStrings("victim.co.uk", organizationalDomain(&victim, null));

    var attacker = try testWalk(allocator, "attacker.co.uk", &.{
        .{ "attacker.co.uk", .{ .policy = .reject } },
    });
    defer attacker.deinit();
    try std.testing.expectEqualStrings("attacker.co.uk", organizationalDomain(&attacker, null));
}

test "organizational domain: psd=n wins outright" {
    const allocator = std.testing.allocator;
    var w = try testWalk(allocator, "a.mail.example.com", &.{
        .{ "mail.example.com", .{ .policy = .none, .psd = .no } },
        .{ "example.com", .{ .policy = .reject } },
    });
    defer w.deinit();
    try std.testing.expectEqualStrings("mail.example.com", organizationalDomain(&w, null));
}

test "organizational domain: psd=y puts the boundary one label below" {
    const allocator = std.testing.allocator;
    var w = try testWalk(allocator, "a.mail.example.com", &.{
        .{ "example.com", .{ .policy = .none, .psd = .yes } },
    });
    defer w.deinit();
    try std.testing.expectEqualStrings("mail.example.com", organizationalDomain(&w, null));

    // RFC 9989 §4.10.2 example: only _dmarc.com publishes, with psd=y.
    var tld = try testWalk(allocator, "a.mail.example.com", &.{
        .{ "com", .{ .policy = .none, .psd = .yes } },
    });
    defer tld.deinit();
    try std.testing.expectEqualStrings("example.com", organizationalDomain(&tld, null));
}

test "organizational domain: nothing published anywhere" {
    const allocator = std.testing.allocator;
    var w = try testWalk(allocator, "attacker.co.uk", &.{});
    defer w.deinit();
    try std.testing.expectEqualStrings("attacker.co.uk", organizationalDomain(&w, null));
}

test "organizational domain: psl vetoes a registry that forgot psd=y" {
    const allocator = std.testing.allocator;
    var list = psl_mod.PublicSuffixList.init(allocator);
    defer list.deinit();
    try list.loadText("co.uk\nuk\n");

    // co.uk publishes DMARC but omits psd=y, so rule 3 would hand the whole
    // registry to every registrant under it.
    var w = try testWalk(allocator, "a.victim.co.uk", &.{
        .{ "a.victim.co.uk", .{ .policy = .reject } },
        .{ "co.uk", .{ .policy = .none } },
    });
    defer w.deinit();

    try std.testing.expectEqualStrings("co.uk", organizationalDomain(&w, null));
    try std.testing.expectEqualStrings("victim.co.uk", organizationalDomain(&w, &list));
}
