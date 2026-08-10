const std = @import("std");
const mem = std.mem;

/// Alignment mode per RFC 7489 §3.1.
pub const AlignmentMode = enum {
    /// Relaxed: authenticated domain may be a parent or child of From domain.
    relaxed,
    /// Strict: authenticated domain must exactly match From domain.
    strict,
};

/// An authenticated identifier and the Organizational Domain established for
/// it by the DNS tree walk (RFC 9989 §4.10.2).
pub const Identifier = struct {
    /// Authenticated domain: the SPF MAIL FROM domain, or a DKIM d= value.
    domain: ?[]const u8 = null,
    /// Organizational Domain of `domain`. Only consulted for relaxed mode.
    org_domain: ?[]const u8 = null,
    /// The method result as reported by the milter that produced it.
    result: ?[]const u8 = null,
    /// Whether a DKIM `t=y` key produced this result; always false for SPF.
    testing: bool = false,

    /// Whether this identifier can authenticate a policy decision.
    ///
    /// Results from testing keys remain visible but never satisfy this predicate.
    pub fn passed(self: Identifier) bool {
        if (self.testing) return false;
        const r = self.result orelse return false;
        return std.ascii.eqlIgnoreCase(r, "pass");
    }
};

/// Whether an authenticated identifier aligns with the RFC5322.From domain.
///
/// Strict mode compares domains; relaxed mode compares caller-supplied
/// organizational domains from the DNS tree walk.
pub fn isAligned(
    from_domain: []const u8,
    from_org: []const u8,
    auth: Identifier,
    mode: AlignmentMode,
) bool {
    const auth_domain = auth.domain orelse return false;
    if (from_domain.len == 0 or auth_domain.len == 0) return false;

    return switch (mode) {
        .strict => std.ascii.eqlIgnoreCase(from_domain, auth_domain),
        .relaxed => blk: {
            const auth_org = auth.org_domain orelse auth_domain;
            if (from_org.len == 0 or auth_org.len == 0) break :blk false;
            break :blk std.ascii.eqlIgnoreCase(from_org, auth_org);
        },
    };
}

/// Extract the domain part from an email address (everything after @).
/// Returns null if no @ is present.
pub fn getDomainFromEmail(addr: []const u8) ?[]const u8 {
    if (mem.lastIndexOfScalar(u8, addr, '@')) |at| {
        const domain = addr[at + 1 ..];
        if (domain.len > 0) return domain;
    }
    return null;
}

/// Strip angle brackets from a milter address (e.g., "<user@example.com>" → "user@example.com").
pub fn stripAngleBrackets(addr: []const u8) []const u8 {
    var s = addr;
    if (s.len > 0 and s[0] == '<') s = s[1..];
    if (s.len > 0 and s[s.len - 1] == '>') s = s[0 .. s.len - 1];
    return s;
}

// =============================================================================
// Tests
// =============================================================================

fn ident(domain: []const u8, org: []const u8) Identifier {
    return .{ .domain = domain, .org_domain = org, .result = "pass" };
}

test "strict alignment exact match" {
    try std.testing.expect(isAligned("example.com", "example.com", ident("example.com", "example.com"), .strict));
    try std.testing.expect(isAligned("Example.COM", "example.com", ident("example.com", "example.com"), .strict));
    try std.testing.expect(!isAligned("mail.example.com", "example.com", ident("example.com", "example.com"), .strict));
    try std.testing.expect(!isAligned("example.com", "example.com", ident("mail.example.com", "example.com"), .strict));
}

test "relaxed alignment compares organizational domains" {
    try std.testing.expect(isAligned("mail.example.com", "example.com", ident("example.com", "example.com"), .relaxed));
    try std.testing.expect(isAligned("example.com", "example.com", ident("mx.example.com", "example.com"), .relaxed));
    try std.testing.expect(!isAligned("example.com", "example.com", ident("example.org", "example.org"), .relaxed));
}

test "relaxed alignment does not collapse public suffixes" {
    // The M-2 bypass: under the old last-two-labels rule both sides reduced to
    // "co.uk". With tree-walk organizational domains they stay distinct.
    try std.testing.expect(!isAligned(
        "a.victim.co.uk",
        "victim.co.uk",
        ident("attacker.co.uk", "attacker.co.uk"),
        .relaxed,
    ));
}

test "an identifier without an org domain falls back to itself" {
    const no_org = Identifier{ .domain = "example.com", .result = "pass" };
    try std.testing.expect(isAligned("mail.example.com", "example.com", no_org, .relaxed));
    try std.testing.expect(!isAligned("mail.example.com", "mail.example.com", no_org, .relaxed));
}

test "a missing identifier never aligns" {
    try std.testing.expect(!isAligned("example.com", "example.com", .{}, .relaxed));
    try std.testing.expect(!isAligned("example.com", "example.com", .{}, .strict));
}

test "identifier passed" {
    try std.testing.expect((Identifier{ .result = "pass" }).passed());
    try std.testing.expect((Identifier{ .result = "PASS" }).passed());
    try std.testing.expect(!(Identifier{ .result = "fail" }).passed());
    try std.testing.expect(!(Identifier{}).passed());
}

test "get domain from email" {
    try std.testing.expectEqualStrings("example.com", getDomainFromEmail("user@example.com").?);
    try std.testing.expectEqualStrings("EXAMPLE.COM", getDomainFromEmail("User@EXAMPLE.COM").?);
    try std.testing.expect(getDomainFromEmail("noatsign") == null);
    try std.testing.expect(getDomainFromEmail("user@") == null);
}

test "strip angle brackets" {
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("<user@example.com>"));
    try std.testing.expectEqualStrings("user@example.com", stripAngleBrackets("user@example.com"));
    try std.testing.expectEqualStrings("", stripAngleBrackets("<>"));
}
