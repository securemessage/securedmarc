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

/// Value of the psd= tag, defined in RFC 9989 §4.7 and consumed by the tree
/// walk in §4.10 (it stops the walk) and §4.10.2 (it selects the
/// Organizational Domain).
pub const Psd = enum {
    /// psd=y — this domain is a Public Suffix Domain; the Organizational
    /// Domain is one label below it.
    yes,
    /// psd=n — this domain is itself the Organizational Domain.
    no,
    /// psd=u or absent — boundary undeclared, decided by the tree walk.
    unknown,

    pub fn fromString(s: []const u8) Psd {
        if (eqlIgnoreCase(s, "y")) return .yes;
        if (eqlIgnoreCase(s, "n")) return .no;
        return .unknown;
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
    /// Public-suffix declaration (psd=), RFC 9989 §4.10.
    /// The domain states whether it is a Public Suffix Domain. Absent means
    /// "unknown", which leaves the boundary for the DNS tree walk to work out.
    psd: Psd = .unknown,

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
        } else if (eqlIgnoreCase(tag, "psd")) {
            record.psd = Psd.fromString(val);
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
///
/// `from_org_domain` is the Author Domain's Organizational Domain as
/// established by the DNS tree walk; each identifier carries its own.
pub fn evaluate(
    record: *const DmarcRecord,
    from_domain: []const u8,
    from_org_domain: []const u8,
    spf: alignment.Identifier,
    dkim: alignment.Identifier,
) Result {
    const spf_aligned = spf.passed() and
        alignment.isAligned(from_domain, from_org_domain, spf, record.aspf);

    const dkim_aligned = dkim.passed() and
        alignment.isAligned(from_domain, from_org_domain, dkim, record.adkim);

    // Pass if either mechanism is aligned. The DMARC *result* is "fail"
    // otherwise, regardless of policy: the policy determines the action the
    // MTA takes, not the result value in the A-R header.
    return if (spf_aligned or dkim_aligned) .pass else .fail;
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

test "parse psd tag" {
    const y = parseRecord("v=DMARC1; p=reject; psd=y") orelse return error.ParseFailed;
    try std.testing.expectEqual(Psd.yes, y.psd);

    const n = parseRecord("v=DMARC1; p=none; psd=n") orelse return error.ParseFailed;
    try std.testing.expectEqual(Psd.no, n.psd);

    // psd=u and an absent tag both leave the boundary undeclared.
    const u = parseRecord("v=DMARC1; p=none; psd=u") orelse return error.ParseFailed;
    try std.testing.expectEqual(Psd.unknown, u.psd);
    const absent = parseRecord("v=DMARC1; p=none") orelse return error.ParseFailed;
    try std.testing.expectEqual(Psd.unknown, absent.psd);
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
    const spf = alignment.Identifier{
        .domain = "mail.example.com",
        .org_domain = "example.com",
        .result = "pass",
    };
    try std.testing.expectEqual(Result.pass, evaluate(&record, "example.com", "example.com", spf, .{}));
}

test "evaluate pass with DKIM aligned" {
    const record = DmarcRecord{ .policy = .reject, .aspf = .relaxed, .adkim = .relaxed };
    const spf = alignment.Identifier{
        .domain = "other.com",
        .org_domain = "other.com",
        .result = "fail",
    };
    const dkim = alignment.Identifier{
        .domain = "example.com",
        .org_domain = "example.com",
        .result = "pass",
    };
    try std.testing.expectEqual(Result.pass, evaluate(&record, "example.com", "example.com", spf, dkim));
}

test "evaluate fail neither aligned" {
    const record = DmarcRecord{ .policy = .reject, .aspf = .strict, .adkim = .strict };
    const spf = alignment.Identifier{ .domain = "other.com", .result = "pass" };
    const dkim = alignment.Identifier{ .domain = "different.com", .result = "pass" };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", spf, dkim));
}

test "evaluate fail SPF pass but not aligned strict" {
    const record = DmarcRecord{ .policy = .quarantine, .aspf = .strict };
    const spf = alignment.Identifier{
        .domain = "mail.example.com",
        .org_domain = "example.com",
        .result = "pass",
    };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", spf, .{}));
}

test "evaluate fail when public suffixes no longer collapse" {
    // M-2: the SPF identity really did pass, but the two registrants under
    // co.uk have distinct organizational domains, so relaxed alignment fails.
    const record = DmarcRecord{ .policy = .reject, .aspf = .relaxed, .adkim = .relaxed };
    const spf = alignment.Identifier{
        .domain = "attacker.co.uk",
        .org_domain = "attacker.co.uk",
        .result = "pass",
    };
    try std.testing.expectEqual(
        Result.fail,
        evaluate(&record, "a.victim.co.uk", "victim.co.uk", spf, .{}),
    );
}

test "evaluate fail when no identifier authenticated" {
    const record = DmarcRecord{ .policy = .reject };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", .{}, .{}));
}

test "subdomain policy" {
    const record = DmarcRecord{ .policy = .reject, .subdomain_policy = .none };
    try std.testing.expectEqual(Policy.none, record.getSubdomainPolicy());

    const record2 = DmarcRecord{ .policy = .reject };
    try std.testing.expectEqual(Policy.reject, record2.getSubdomainPolicy());
}
