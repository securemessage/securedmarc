const std = @import("std");
const mem = std.mem;

/// Alignment mode per RFC 7489 §3.1.
pub const AlignmentMode = enum {
    /// Relaxed: authenticated domain may be a parent or child of From domain.
    relaxed,
    /// Strict: authenticated domain must exactly match From domain.
    strict,
};

/// Check if an authenticated identifier (SPF domain or DKIM d= domain)
/// aligns with the RFC5322.From header domain.
///
/// RFC 7489 §3.1:
/// - Strict: exact case-insensitive match
/// - Relaxed: organizational domain of both must match
pub fn isAligned(from_domain: []const u8, auth_domain: []const u8, mode: AlignmentMode) bool {
    if (from_domain.len == 0 or auth_domain.len == 0) return false;

    return switch (mode) {
        .strict => eqlIgnoreCase(from_domain, auth_domain),
        .relaxed => {
            const from_org = getOrganizationalDomain(from_domain);
            const auth_org = getOrganizationalDomain(auth_domain);
            return eqlIgnoreCase(from_org, auth_org);
        },
    };
}

/// Extract the organizational domain from a fully-qualified domain.
///
/// Simple heuristic: the organizational domain is the registered domain
/// (effective TLD + 1 label). Without a full Public Suffix List, we use
/// a simple two-label extraction (last two labels separated by dot).
///
/// For domains like "co.uk", "com.au", etc., this heuristic may be wrong.
/// A full PSL implementation is deferred to a future enhancement.
///
/// Examples:
///   "mail.example.com" → "example.com"
///   "sub.host.example.com" → "example.com"
///   "example.com" → "example.com"
///   "localhost" → "localhost"
pub fn getOrganizationalDomain(domain: []const u8) []const u8 {
    // Find the rightmost dot
    const last_dot = mem.lastIndexOfScalar(u8, domain, '.') orelse return domain;
    if (last_dot == 0) return domain;

    // Find the second-to-last dot
    const prefix = domain[0..last_dot];
    const second_dot = mem.lastIndexOfScalar(u8, prefix, '.') orelse return domain;

    // Return everything after the second-to-last dot
    return domain[second_dot + 1 ..];
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

test "strict alignment exact match" {
    try std.testing.expect(isAligned("example.com", "example.com", .strict));
    try std.testing.expect(isAligned("Example.COM", "example.com", .strict));
    try std.testing.expect(!isAligned("mail.example.com", "example.com", .strict));
    try std.testing.expect(!isAligned("example.com", "mail.example.com", .strict));
}

test "relaxed alignment organizational domain" {
    try std.testing.expect(isAligned("example.com", "example.com", .relaxed));
    try std.testing.expect(isAligned("mail.example.com", "example.com", .relaxed));
    try std.testing.expect(isAligned("example.com", "mail.example.com", .relaxed));
    try std.testing.expect(isAligned("sub.host.example.com", "mx.example.com", .relaxed));
    try std.testing.expect(!isAligned("example.com", "example.org", .relaxed));
    try std.testing.expect(!isAligned("notexample.com", "example.com", .relaxed));
}

test "organizational domain extraction" {
    try std.testing.expectEqualStrings("example.com", getOrganizationalDomain("mail.example.com"));
    try std.testing.expectEqualStrings("example.com", getOrganizationalDomain("sub.host.example.com"));
    try std.testing.expectEqualStrings("example.com", getOrganizationalDomain("example.com"));
    try std.testing.expectEqualStrings("localhost", getOrganizationalDomain("localhost"));
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
