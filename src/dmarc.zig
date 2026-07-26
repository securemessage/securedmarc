const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const alignment = @import("alignment.zig");

/// DMARC policy disposition per RFC 7489 §6.3.
pub const Policy = enum {
    none,
    quarantine,
    reject,

    pub fn fromString(s: []const u8) ?Policy {
        if (eqlIgnoreCase(s, "none")) return .none;
        if (eqlIgnoreCase(s, "quarantine")) return .quarantine;
        if (eqlIgnoreCase(s, "reject")) return .reject;
        return null;
    }

    pub fn toString(self: Policy) []const u8 {
        return switch (self) {
            .none => "none",
            .quarantine => "quarantine",
            .reject => "reject",
        };
    }
};

/// DMARC evaluation result.
pub const Result = enum {
    pass,
    fail,
    temperror,
    permerror,
    none,

    pub fn toString(self: Result) []const u8 {
        return switch (self) {
            .pass => "pass",
            .fail => "fail",
            .temperror => "temperror",
            .permerror => "permerror",
            .none => "none",
        };
    }
};

/// Parsed DMARC record (RFC 7489 §6.3).
pub const DmarcRecord = struct {
    /// Domain policy (p=). Required.
    policy: Policy = .none,
    /// Subdomain policy (sp=). Defaults to domain policy.
    subdomain_policy: ?Policy = null,
    /// DKIM alignment mode (adkim=). Default: relaxed.
    adkim: alignment.AlignmentMode = .relaxed,
    /// SPF alignment mode (aspf=). Default: relaxed.
    aspf: alignment.AlignmentMode = .relaxed,
    /// Percentage of messages to apply policy (pct=). Default: 100.
    pct: u8 = 100,
    /// Aggregate report URI (rua=). Informational only for milter.
    rua: ?[]const u8 = null,
    /// Forensic report URI (ruf=). Informational only for milter.
    ruf: ?[]const u8 = null,
    /// Failure reporting options (fo=). Default: "0".
    fo: []const u8 = "0",

    /// Get the effective subdomain policy.
    pub fn getSubdomainPolicy(self: *const DmarcRecord) Policy {
        return self.subdomain_policy orelse self.policy;
    }
};

/// Parse a DMARC TXT record value.
///
/// RFC 7489 §6.3: record starts with "v=DMARC1" (case-insensitive),
/// followed by semicolon-separated tag=value pairs.
///
/// Returns null if the record is not a valid DMARC record.
pub fn parseRecord(txt: []const u8) ?DmarcRecord {
    const trimmed = mem.trim(u8, txt, &std.ascii.whitespace);
    if (trimmed.len < 8) return null;

    // Must start with v=DMARC1
    if (!startsWithIgnoreCase(trimmed, "v=DMARC1")) return null;
    // After v=DMARC1, must be end of string, semicolon, or whitespace
    if (trimmed.len > 8) {
        const next = trimmed[8];
        if (next != ';' and next != ' ' and next != '\t') return null;
    }

    var record = DmarcRecord{};
    var found_policy = false;

    // Parse tag=value pairs after v=DMARC1
    var rest = if (trimmed.len > 8) trimmed[8..] else "";
    rest = mem.trimLeft(u8, rest, &(.{ ';', ' ', '\t' }));

    var iter = mem.splitScalar(u8, rest, ';');
    while (iter.next()) |pair_raw| {
        const pair = mem.trim(u8, pair_raw, &std.ascii.whitespace);
        if (pair.len == 0) continue;

        const eq = mem.indexOfScalar(u8, pair, '=') orelse continue;
        const tag = mem.trim(u8, pair[0..eq], &std.ascii.whitespace);
        const val = mem.trim(u8, pair[eq + 1 ..], &std.ascii.whitespace);

        if (eqlIgnoreCase(tag, "p")) {
            record.policy = Policy.fromString(val) orelse continue;
            found_policy = true;
        } else if (eqlIgnoreCase(tag, "sp")) {
            record.subdomain_policy = Policy.fromString(val);
        } else if (eqlIgnoreCase(tag, "adkim")) {
            record.adkim = parseAlignmentTag(val);
        } else if (eqlIgnoreCase(tag, "aspf")) {
            record.aspf = parseAlignmentTag(val);
        } else if (eqlIgnoreCase(tag, "pct")) {
            record.pct = std.fmt.parseInt(u8, val, 10) catch 100;
        } else if (eqlIgnoreCase(tag, "rua")) {
            record.rua = val;
        } else if (eqlIgnoreCase(tag, "ruf")) {
            record.ruf = val;
        } else if (eqlIgnoreCase(tag, "fo")) {
            record.fo = val;
        }
    }

    // p= tag is REQUIRED (RFC 7489 §6.3)
    if (!found_policy) return null;

    return record;
}

/// Evaluate DMARC policy given SPF and DKIM results.
///
/// RFC 7489 §4.2: A message passes DMARC if at least one of:
/// - SPF passes AND the SPF-authenticated domain aligns with From domain
/// - DKIM passes AND a DKIM-authenticated domain aligns with From domain
pub fn evaluate(
    record: *const DmarcRecord,
    from_domain: []const u8,
    spf_result: ?[]const u8,
    spf_domain: ?[]const u8,
    dkim_result: ?[]const u8,
    dkim_domain: ?[]const u8,
    is_subdomain: bool,
) Result {
    var spf_aligned = false;
    var dkim_aligned = false;

    // Check SPF alignment
    if (spf_result) |sr| {
        if (eqlIgnoreCase(sr, "pass")) {
            if (spf_domain) |sd| {
                spf_aligned = alignment.isAligned(from_domain, sd, record.aspf);
            }
        }
    }

    // Check DKIM alignment
    if (dkim_result) |dr| {
        if (eqlIgnoreCase(dr, "pass")) {
            if (dkim_domain) |dd| {
                dkim_aligned = alignment.isAligned(from_domain, dd, record.adkim);
            }
        }
    }

    // Pass if either mechanism is aligned
    if (spf_aligned or dkim_aligned) return .pass;

    // Determine effective policy
    const effective_policy = if (is_subdomain)
        record.getSubdomainPolicy()
    else
        record.policy;

    // Even though the message failed alignment, the DMARC *result* is "fail"
    // regardless of the policy disposition. The policy determines what ACTION
    // the MTA takes, not the result value in the A-R header.
    _ = effective_policy;
    return .fail;
}

/// Get the disposition action string for an A-R header reason comment.
pub fn getDisposition(record: *const DmarcRecord, is_subdomain: bool) []const u8 {
    const effective = if (is_subdomain)
        record.getSubdomainPolicy()
    else
        record.policy;
    return effective.toString();
}

fn parseAlignmentTag(val: []const u8) alignment.AlignmentMode {
    if (val.len == 1) {
        if (val[0] == 's' or val[0] == 'S') return .strict;
    }
    return .relaxed;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (toLower(ca) != toLower(cb)) return false;
    }
    return true;
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn toLower(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

// =============================================================================
// Tests
// =============================================================================

test "parse minimal DMARC record" {
    const r = parseRecord("v=DMARC1; p=none") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.none, r.policy);
    try std.testing.expectEqual(alignment.AlignmentMode.relaxed, r.adkim);
    try std.testing.expectEqual(alignment.AlignmentMode.relaxed, r.aspf);
    try std.testing.expectEqual(@as(u8, 100), r.pct);
}

test "parse full DMARC record" {
    const r = parseRecord("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; rua=mailto:dmarc@example.com") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, r.policy);
    try std.testing.expectEqual(Policy.quarantine, r.subdomain_policy.?);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.adkim);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.aspf);
    try std.testing.expectEqual(@as(u8, 50), r.pct);
    try std.testing.expectEqualStrings("mailto:dmarc@example.com", r.rua.?);
}

test "parse case insensitive" {
    const r = parseRecord("V=DMARC1; P=Reject; ADKIM=S") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, r.policy);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.adkim);
}

test "reject invalid records" {
    try std.testing.expect(parseRecord("v=spf1 include:example.com -all") == null);
    try std.testing.expect(parseRecord("v=DMARC1") == null); // no p= tag
    try std.testing.expect(parseRecord("") == null);
    try std.testing.expect(parseRecord("v=DMARC2; p=none") == null);
}

test "evaluate pass with SPF aligned" {
    const record = DmarcRecord{ .policy = .reject, .aspf = .relaxed, .adkim = .relaxed };
    const result = evaluate(&record, "example.com", "pass", "mail.example.com", null, null, false);
    try std.testing.expectEqual(Result.pass, result);
}

test "evaluate pass with DKIM aligned" {
    const record = DmarcRecord{ .policy = .reject, .aspf = .relaxed, .adkim = .relaxed };
    const result = evaluate(&record, "example.com", "fail", "other.com", "pass", "example.com", false);
    try std.testing.expectEqual(Result.pass, result);
}

test "evaluate fail neither aligned" {
    const record = DmarcRecord{ .policy = .reject, .aspf = .strict, .adkim = .strict };
    const result = evaluate(&record, "example.com", "pass", "other.com", "pass", "different.com", false);
    try std.testing.expectEqual(Result.fail, result);
}

test "evaluate fail SPF pass but not aligned strict" {
    const record = DmarcRecord{ .policy = .quarantine, .aspf = .strict };
    const result = evaluate(&record, "example.com", "pass", "mail.example.com", null, null, false);
    try std.testing.expectEqual(Result.fail, result);
}

test "subdomain policy" {
    const record = DmarcRecord{ .policy = .reject, .subdomain_policy = .none };
    try std.testing.expectEqual(Policy.none, record.getSubdomainPolicy());

    const record2 = DmarcRecord{ .policy = .reject };
    try std.testing.expectEqual(Policy.reject, record2.getSubdomainPolicy());
}
