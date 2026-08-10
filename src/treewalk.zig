const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;
const log = securemilter.log;

const dmarc = @import("dmarc.zig");
const psl_mod = @import("psl.zig");
const alignment = @import("alignment.zig");

/// RFC 9989 §4.10 DNS tree walk.
///
/// It discovers DMARC policy records and the organizational-domain boundary.
/// The walk is limited to `MAX_QUERIES` DNS lookups.
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
            if (std.ascii.eqlIgnoreCase(f.domain, self.start)) return f.record;
        }
        return null;
    }

    /// The record to apply when the starting domain publishes none: the one
    /// belonging to the Organizational or Public Suffix Domain.
    pub fn policyRecord(self: *const Walk) ?dmarc.DmarcRecord {
        if (self.found.items.len == 0) return null;
        return self.found.items[self.found.items.len - 1].record;
    }

    /// Domain that supplied `policyRecord`, if any.
    pub fn policyDomain(self: *const Walk) ?[]const u8 {
        if (self.found.items.len == 0) return null;
        return self.found.items[self.found.items.len - 1].domain;
    }
};

/// Establish an identifier's organizational domain for relaxed alignment.
///
/// Returns the owning walk when one was needed because `ident.org_domain` borrows
/// from it. Strict mode, failed identifiers, and exact-domain matches need none.
pub fn orgWalk(
    allocator: Allocator,
    resolver: *dns_mod.Resolver,
    mode: alignment.AlignmentMode,
    from_domain: []const u8,
    from_org: []const u8,
    ident: *alignment.Identifier,
    psl: ?*const psl_mod.PublicSuffixList,
) ?Walk {
    if (mode != .relaxed) return null;
    if (!ident.passed()) return null;
    const domain = ident.domain orelse return null;

    if (std.ascii.eqlIgnoreCase(domain, from_domain)) {
        ident.org_domain = from_org;
        return null;
    }

    var w = walk(allocator, resolver, domain) catch return null;
    ident.org_domain = organizationalDomain(&w, psl);
    return w;
}

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

/// Determine the organizational domain from a completed RFC 9989 walk.
///
/// An optional Public Suffix List can veto, but not select, a boundary.
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
        if (std.ascii.eqlIgnoreCase(f.domain, w.start)) continue;
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
        // that does not exist. Reporting it as transient would latch
        // `transient_error` on the walk, and since the flag is only consulted
        // when nothing was found anywhere, that would report `dmarc=temperror`
        // for every domain that publishes no DMARC record -- which is most of
        // them. `transient_error` means "failed in a way that is not 'no such
        // record'".
        if (dns_mod.isTransientError(err)) return .transient;
        return .absent;
    };
    defer res.deinit();

    var selector = RecordSelector{};
    var iter = res.txtRecords();
    while (iter.next()) |txt| selector.offer(txt);
    return .{ .found = selector.selected() orelse return .absent };
}

/// RFC 9989 §4.10 steps 2 and 6: exactly one DMARC Policy Record may exist at a
/// name. More than one is unresolvable ambiguity and *all* of them are
/// discarded, rather than one being picked.
///
/// A named type rather than two locals because "a record" here means precisely
/// "text with a current `v=DMARC1`" — including a record whose `p=` is missing
/// or invalid, which §4.10.1 handles separately and which therefore still
/// counts towards the ambiguity test. A name publishing `v=DMARC1; rua=...`
/// alongside `v=DMARC1; p=reject` must count as two records and be discarded
/// as ambiguous, not resolved by picking the one with a usable `p=`.
const RecordSelector = struct {
    record: ?dmarc.DmarcRecord = null,
    count: usize = 0,

    fn offer(self: *RecordSelector, txt: []const u8) void {
        const parsed = dmarc.parseRecord(txt) orelse return;
        self.record = parsed;
        self.count += 1;
    }

    fn selected(self: *const RecordSelector) ?dmarc.DmarcRecord {
        if (self.count != 1) return null;
        return self.record;
    }
};

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

test "4.10 step 2: exactly one record at a name, or none" {
    const one = blk: {
        var s = RecordSelector{};
        s.offer("v=DMARC1; p=reject");
        break :blk s;
    };
    try std.testing.expectEqual(dmarc.Policy.reject, one.selected().?.policy);

    // Nothing that is a DMARC record at all.
    const none = blk: {
        var s = RecordSelector{};
        s.offer("v=spf1 -all");
        s.offer("some unrelated TXT record");
        break :blk s;
    };
    try std.testing.expect(none.selected() == null);

    // Two records: ambiguous, so *neither* is used.
    const two = blk: {
        var s = RecordSelector{};
        s.offer("v=DMARC1; p=reject");
        s.offer("v=DMARC1; p=none");
        break :blk s;
    };
    try std.testing.expect(two.selected() == null);

    // A record with no usable p= still counts, so this name is ambiguous
    // rather than resolving to the p=reject. Non-DMARC TXT records alongside
    // it are still ignored.
    const ambiguous_via_unusable = blk: {
        var s = RecordSelector{};
        s.offer("v=DMARC1; rua=mailto:d@example.com");
        s.offer("v=DMARC1; p=reject");
        s.offer("v=spf1 -all");
        break :blk s;
    };
    try std.testing.expect(ambiguous_via_unusable.selected() == null);

    // And on its own it is the one record at that name.
    const unusable_alone = blk: {
        var s = RecordSelector{};
        s.offer("v=DMARC1; rua=mailto:d@example.com");
        break :blk s;
    };
    const rec = unusable_alone.selected() orelse return error.ExpectedRecord;
    try std.testing.expectEqual(dmarc.Applicability.as_none, rec.applicability());
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
