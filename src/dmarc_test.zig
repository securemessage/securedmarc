//! Tests for `dmarc.zig` -- DMARC Policy Record parsing, RFC 9989 4.10.1
//! applicability, 4.7 test mode, and alignment evaluation.
//!
//! Separate file per the `securearc` precedent (`settings_test.zig`,
//! `sealbuild_test.zig`). The immediate reason is that the line-limit gate
//! excludes `_test.zig` files -- a table-driven conformance test grows with the
//! cases it covers, and splitting one to satisfy a goal aimed at production
//! readability would be cargo-culting the rule against its purpose. Every
//! symbol exercised here is already part of `dmarc.zig`'s public API, so
//! nothing was made visible just to test it.

const std = @import("std");

const alignment = @import("alignment.zig");
const dmarc = @import("dmarc.zig");

const Applicability = dmarc.Applicability;
const DmarcRecord = dmarc.DmarcRecord;
const Policy = dmarc.Policy;
const Psd = dmarc.Psd;
const Result = dmarc.Result;
const TestMode = dmarc.TestMode;

const effectivePolicy = dmarc.effectivePolicy;
const evaluate = dmarc.evaluate;
const getDisposition = dmarc.getDisposition;
const hasValidReportingUri = dmarc.hasValidReportingUri;
const parseRecord = dmarc.parseRecord;

test "parse minimal DMARC record" {
    const r = parseRecord("v=DMARC1; p=none") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.none, r.policy);
    try std.testing.expectEqual(alignment.AlignmentMode.relaxed, r.adkim);
    try std.testing.expectEqual(alignment.AlignmentMode.relaxed, r.aspf);
    try std.testing.expectEqual(TestMode.apply, r.testing);
    try std.testing.expectEqual(Applicability.apply, r.applicability());
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

test "parse full DMARC record, and pct is ignored as historic" {
    // pct= is left in the record deliberately. RFC 9989 Appendix A.6 removes
    // the tag, and §4.8 says unknown tags MUST be ignored, so a record still
    // publishing it must parse exactly as if it were absent rather than be
    // rejected -- plenty of deployed records still carry it.
    const r = parseRecord("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; rua=mailto:dmarc@example.com") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, r.policy);
    try std.testing.expectEqual(Policy.quarantine, r.subdomain_policy.?);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.adkim);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.aspf);
    try std.testing.expectEqualStrings("mailto:dmarc@example.com", r.rua.?);
    try std.testing.expectEqual(Applicability.apply, r.applicability());
}

test "tag names are case insensitive but the v= value is not" {
    // §4.8: dmarc-version = "v" equals %s"DMARC1". The %s makes only the value
    // case sensitive, so an upper-case tag name is still a valid record.
    const r = parseRecord("V=DMARC1; P=Reject; ADKIM=S") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, r.policy);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.adkim);

    // These used to parse as valid records, which meant a record the RFC says
    // to ignore entirely was read as policy.
    try std.testing.expect(parseRecord("v=dmarc1; p=reject") == null);
    try std.testing.expect(parseRecord("v=DMARc1; p=reject") == null);
    try std.testing.expect(parseRecord("v=Dmarc1; p=reject") == null);
}

test "reject things that are not DMARC records at all" {
    try std.testing.expect(parseRecord("v=spf1 include:example.com -all") == null);
    try std.testing.expect(parseRecord("") == null);
    try std.testing.expect(parseRecord("v=DMARC2; p=none") == null);
    // v= must be first (§4.7).
    try std.testing.expect(parseRecord("p=reject; v=DMARC1") == null);
}

test "a record with no p= is still a record, per 4.10.1" {
    // This previously asserted `== null`, encoding the pre-RFC-9989 reading
    // that a missing p= means "no record here". §4.10.1 gives such a record
    // defined behaviour, and treating it as absent let the tree walk apply a
    // *parent's* policy -- potentially p=reject -- to a domain the RFC says to
    // treat as p=none or to exempt from DMARC entirely.
    const bare = parseRecord("v=DMARC1") orelse return error.ParseFailed;
    try std.testing.expect(!bare.policy_valid);
    try std.testing.expectEqual(Applicability.no_processing, bare.applicability());

    const with_rua = parseRecord("v=DMARC1; rua=mailto:d@example.com") orelse return error.ParseFailed;
    try std.testing.expect(!with_rua.policy_valid);
    try std.testing.expectEqual(Applicability.as_none, with_rua.applicability());
}

test "4.10.1 applicability matrix" {
    const Case = struct { txt: []const u8, want: Applicability };
    const cases = [_]Case{
        // Usable policy: apply it.
        .{ .txt = "v=DMARC1; p=none", .want = .apply },
        .{ .txt = "v=DMARC1; p=reject; sp=none", .want = .apply },
        .{ .txt = "v=DMARC1; p=reject; np=quarantine", .want = .apply },
        // Invalid p=, with and without a usable rua=.
        .{ .txt = "v=DMARC1; p=bogus", .want = .no_processing },
        .{ .txt = "v=DMARC1; p=bogus; rua=mailto:d@example.com", .want = .as_none },
        // An invalid sp= or np= is the same trigger as a missing p=, even when
        // p= itself is perfectly good. This is the part of §4.10.1 that is easy
        // to miss: a valid p=reject does not save the record.
        .{ .txt = "v=DMARC1; p=reject; sp=bogus", .want = .no_processing },
        .{ .txt = "v=DMARC1; p=reject; sp=bogus; rua=mailto:d@example.com", .want = .as_none },
        .{ .txt = "v=DMARC1; p=reject; np=bogus", .want = .no_processing },
        // A rua= that is present but syntactically unusable does not rescue it.
        .{ .txt = "v=DMARC1; p=bogus; rua=not-a-uri", .want = .no_processing },
        .{ .txt = "v=DMARC1; p=bogus; rua=", .want = .no_processing },
    };
    for (cases) |c| {
        const r = parseRecord(c.txt) orelse {
            std.debug.print("failed to parse: {s}\n", .{c.txt});
            return error.ParseFailed;
        };
        std.testing.expectEqual(c.want, r.applicability()) catch |err| {
            std.debug.print("record: {s}\n", .{c.txt});
            return err;
        };
    }
}

test "rua reporting URI syntax" {
    try std.testing.expect(hasValidReportingUri("mailto:d@example.com"));
    try std.testing.expect(hasValidReportingUri("https://example.com/dmarc"));
    // The obsolete size limit is stripped, not treated as part of the URI.
    try std.testing.expect(hasValidReportingUri("mailto:d@example.com!10m"));
    // One valid entry anywhere in the list is enough.
    try std.testing.expect(hasValidReportingUri("garbage, mailto:d@example.com"));
    try std.testing.expect(hasValidReportingUri(" mailto:a@b.c , junk"));
    // A scheme this daemon cannot send to is still syntactically valid: §4.10.1
    // asks about syntax, not about whether we would use it.
    try std.testing.expect(hasValidReportingUri("ftp://example.com/x"));

    try std.testing.expect(!hasValidReportingUri(""));
    try std.testing.expect(!hasValidReportingUri("not-a-uri"));
    try std.testing.expect(!hasValidReportingUri(":no-scheme"));
    try std.testing.expect(!hasValidReportingUri("mailto:")); // empty remainder
    try std.testing.expect(!hasValidReportingUri("1http://example.com")); // scheme must start ALPHA
    try std.testing.expect(!hasValidReportingUri("ma_ilto:d@example.com")); // bad scheme char
}

test "t= test mode downgrades one level, and never below none" {
    // §4.7: t=y asks for the policy one level below the declared one. Mapping
    // it to "none" outright would be a bigger downgrade than requested and
    // would let a domain testing p=reject through unquarantined.
    const reject = parseRecord("v=DMARC1; p=reject; t=y") orelse return error.ParseFailed;
    try std.testing.expectEqual(TestMode.testing, reject.testing);
    try std.testing.expectEqual(Policy.quarantine, effectivePolicy(&reject, false));

    const quarantine = parseRecord("v=DMARC1; p=quarantine; t=y") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.none, effectivePolicy(&quarantine, false));

    // "it has no effect on any policy that is none"
    const none = parseRecord("v=DMARC1; p=none; t=y") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.none, effectivePolicy(&none, false));

    // t=n and an absent t= both apply the policy as declared.
    const explicit_n = parseRecord("v=DMARC1; p=reject; t=n") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, effectivePolicy(&explicit_n, false));
    const absent = parseRecord("v=DMARC1; p=reject") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, effectivePolicy(&absent, false));

    // §4.8: a bad value falls back to the default rather than rejecting.
    const bad = parseRecord("v=DMARC1; p=reject; t=maybe") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, effectivePolicy(&bad, false));

    // The downgrade applies to the subdomain policy too.
    const sub = parseRecord("v=DMARC1; p=none; sp=reject; t=y") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.quarantine, effectivePolicy(&sub, true));
    try std.testing.expectEqual(Policy.none, effectivePolicy(&sub, false));
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
