const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Optional Public Suffix List veto for RFC 9989 DNS tree walks.
///
/// The tree walk selects the organizational domain; a configured list may only
/// reject a selected public suffix. It accepts publicsuffix.org rules, comments,
/// wildcards, and exceptions.
pub const PublicSuffixList = struct {
    allocator: Allocator,
    /// Literal rules, e.g. "co.uk".
    rules: std.StringHashMapUnmanaged(void) = .{},
    /// Wildcard rules with the leading "*." removed, e.g. "ck" for "*.ck".
    wildcards: std.StringHashMapUnmanaged(void) = .{},
    /// Exception rules with the leading "!" removed, e.g. "www.ck".
    exceptions: std.StringHashMapUnmanaged(void) = .{},

    pub fn init(allocator: Allocator) PublicSuffixList {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PublicSuffixList) void {
        freeKeys(self.allocator, &self.rules);
        freeKeys(self.allocator, &self.wildcards);
        freeKeys(self.allocator, &self.exceptions);
    }

    pub fn count(self: *const PublicSuffixList) usize {
        return self.rules.count() + self.wildcards.count() + self.exceptions.count();
    }

    /// Load rules from the on-disk list. Existing rules are kept, so a reload
    /// should use a fresh instance.
    pub fn loadFile(self: *PublicSuffixList, path: []const u8) !void {
        const content = try std.fs.cwd().readFileAlloc(self.allocator, path, MAX_FILE_BYTES);
        defer self.allocator.free(content);
        try self.loadText(content);
    }

    pub fn loadText(self: *PublicSuffixList, content: []const u8) !void {
        var lines = mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw| {
            const line = mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            if (mem.startsWith(u8, line, "//")) continue;

            if (line[0] == '!') {
                try self.insert(&self.exceptions, line[1..]);
            } else if (mem.startsWith(u8, line, "*.")) {
                try self.insert(&self.wildcards, line[2..]);
            } else {
                try self.insert(&self.rules, line);
            }
        }
    }

    /// True if `domain` is itself a public suffix, i.e. a name under which
    /// registrations happen rather than a registered name.
    pub fn isPublicSuffix(self: *const PublicSuffixList, domain: []const u8) bool {
        const trimmed = mem.trim(u8, domain, ".");
        if (trimmed.len == 0 or trimmed.len > MAX_DOMAIN_LEN) return false;

        // Rules are stored lowercased; DNS names are case-insensitive and
        // arrive in whatever case the sender chose.
        var buf: [MAX_DOMAIN_LEN]u8 = undefined;
        for (trimmed, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        const name = buf[0..trimmed.len];

        // An exception rule names something that *is* registrable, so it is
        // not a public suffix even though its parent wildcard says otherwise.
        if (self.exceptions.contains(name)) return false;
        if (self.rules.contains(name)) return true;

        // "*.ck" makes any single label under "ck" a public suffix.
        if (parentOf(name)) |parent| {
            if (self.wildcards.contains(parent)) return true;
        }
        return false;
    }

    fn insert(self: *PublicSuffixList, map: *std.StringHashMapUnmanaged(void), rule: []const u8) !void {
        if (rule.len == 0 or rule.len > MAX_DOMAIN_LEN) return;

        // Normalise before the duplicate check, not after. Testing the raw
        // rule against a map keyed by lowercase misses a mixed-case repeat,
        // and `put` on an already-present key keeps the original key — the
        // freshly allocated one would then be unreachable and never freed.
        var buf: [MAX_DOMAIN_LEN]u8 = undefined;
        for (rule, 0..) |c, i| buf[i] = std.ascii.toLower(c);
        const key = buf[0..rule.len];

        if (map.contains(key)) return;
        const owned = try self.allocator.dupe(u8, key);
        errdefer self.allocator.free(owned);
        try map.put(self.allocator, owned, {});
    }
};

const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;

/// RFC 1035 §2.3.4: a domain name is at most 255 octets on the wire, which is
/// 253 characters in presentation form.
const MAX_DOMAIN_LEN: usize = 253;

fn parentOf(domain: []const u8) ?[]const u8 {
    const dot = mem.indexOfScalar(u8, domain, '.') orelse return null;
    const parent = domain[dot + 1 ..];
    return if (parent.len == 0) null else parent;
}

fn freeKeys(allocator: Allocator, map: *std.StringHashMapUnmanaged(void)) void {
    var it = map.keyIterator();
    while (it.next()) |k| allocator.free(k.*);
    map.deinit(allocator);
}

// =============================================================================
// Tests
// =============================================================================

test "literal rules" {
    var list = PublicSuffixList.init(std.testing.allocator);
    defer list.deinit();
    try list.loadText(
        \\// comment line
        \\com
        \\co.uk
        \\uk
        \\
    );

    try std.testing.expect(list.isPublicSuffix("com"));
    try std.testing.expect(list.isPublicSuffix("co.uk"));
    try std.testing.expect(list.isPublicSuffix("uk"));
    // Registered names are not public suffixes.
    try std.testing.expect(!list.isPublicSuffix("victim.co.uk"));
    try std.testing.expect(!list.isPublicSuffix("example.com"));
    try std.testing.expect(!list.isPublicSuffix(""));
}

test "wildcard and exception rules" {
    var list = PublicSuffixList.init(std.testing.allocator);
    defer list.deinit();
    try list.loadText("ck\n*.ck\n!www.ck\n");

    try std.testing.expect(list.isPublicSuffix("ck"));
    try std.testing.expect(list.isPublicSuffix("anything.ck"));
    // The exception marks www.ck as registrable.
    try std.testing.expect(!list.isPublicSuffix("www.ck"));
    // The wildcard covers one label only.
    try std.testing.expect(!list.isPublicSuffix("deep.anything.ck"));
}

test "matching is case-insensitive and tolerates trailing dots" {
    var list = PublicSuffixList.init(std.testing.allocator);
    defer list.deinit();
    try list.loadText("CO.UK\n");

    try std.testing.expect(list.isPublicSuffix("co.uk"));
    try std.testing.expect(list.isPublicSuffix("co.uk."));
    try std.testing.expect(list.isPublicSuffix("Co.Uk"));
    try std.testing.expect(list.isPublicSuffix("CO.UK"));
    try std.testing.expect(!list.isPublicSuffix("Victim.Co.Uk"));
}

test "duplicate rules are stored once" {
    var list = PublicSuffixList.init(std.testing.allocator);
    defer list.deinit();
    try list.loadText("com\ncom\ncom\n");
    try std.testing.expectEqual(@as(usize, 1), list.count());
}

test "duplicate rules differing only in case are stored once" {
    // Both orderings: the second insert must be recognised as a repeat rather
    // than allocating a key that `put` would then discard. std.testing's
    // allocator fails the test if that key leaks.
    var lower_first = PublicSuffixList.init(std.testing.allocator);
    defer lower_first.deinit();
    try lower_first.loadText("co.uk\nCO.UK\nCo.Uk\n");
    try std.testing.expectEqual(@as(usize, 1), lower_first.count());
    try std.testing.expect(lower_first.isPublicSuffix("co.uk"));

    var upper_first = PublicSuffixList.init(std.testing.allocator);
    defer upper_first.deinit();
    try upper_first.loadText("CO.UK\nco.uk\n");
    try std.testing.expectEqual(@as(usize, 1), upper_first.count());
    try std.testing.expect(upper_first.isPublicSuffix("CO.UK"));
}

test "rules longer than a domain name are ignored" {
    var list = PublicSuffixList.init(std.testing.allocator);
    defer list.deinit();
    const too_long = "a" ** (MAX_DOMAIN_LEN + 1);
    try list.loadText(too_long ++ "\ncom\n");
    try std.testing.expectEqual(@as(usize, 1), list.count());
    try std.testing.expect(list.isPublicSuffix("com"));
}
