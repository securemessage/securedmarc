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

const SamplingPolicy = dmarc.SamplingPolicy;

const alignedDkim = dmarc.alignedDkim;
const effectivePolicy = dmarc.effectivePolicy;
const effectivePolicySampled = dmarc.effectivePolicySampled;
const inSample = dmarc.inSample;
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

test "parse full DMARC record, including the historic pct tag" {
    // pct= is parsed even though RFC 9989 Appendix A.6 removed it (audit M-4).
    // Parsing and acting are separate: the value is read here so an operator who
    // opts in can honour it, and ignored at decision time otherwise. A record
    // still carrying pct= must in either case parse rather than be rejected --
    // plenty of deployed records still have it.
    const r = parseRecord("v=DMARC1; p=reject; sp=quarantine; adkim=s; aspf=s; pct=50; rua=mailto:dmarc@example.com") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.reject, r.policy);
    try std.testing.expectEqual(Policy.quarantine, r.subdomain_policy.?);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.adkim);
    try std.testing.expectEqual(alignment.AlignmentMode.strict, r.aspf);
    try std.testing.expectEqual(@as(u8, 50), r.pct);
    try std.testing.expectEqualStrings("mailto:dmarc@example.com", r.rua.?);
    try std.testing.expectEqual(Applicability.apply, r.applicability());
}

test "M-4: pct defaults to 100 and rejects out-of-range or unparseable values" {
    // RFC 7489 §6.3: "integer between 0 and 100, inclusive; OPTIONAL; default is
    // 100". Every rejected form must land on the default, and the default is the
    // safe direction -- full enforcement, not silent sampling.
    const absent = parseRecord("v=DMARC1; p=reject") orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u8, 100), absent.pct);

    const over = parseRecord("v=DMARC1; p=reject; pct=101") orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u8, 100), over.pct);

    const huge = parseRecord("v=DMARC1; p=reject; pct=99999") orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u8, 100), huge.pct);

    const junk = parseRecord("v=DMARC1; p=reject; pct=half") orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u8, 100), junk.pct);

    const zero = parseRecord("v=DMARC1; p=reject; pct=0") orelse return error.ParseFailed;
    try std.testing.expectEqual(@as(u8, 0), zero.pct);
}

test "M-4: pct is inert unless the operator opts in" {
    // The guard, and the one that matters most: shipped default is `ignore`,
    // because RFC 9989 removed the tag. If this ever flipped, every domain still
    // publishing pct=0 -- of which there are many, it was the standard way to ask
    // for monitoring -- would silently stop being enforced.
    const r = parseRecord("v=DMARC1; p=reject; pct=0") orelse return error.ParseFailed;

    try std.testing.expectEqual(
        Policy.reject,
        effectivePolicySampled(&r, false, .ignore, "<a@example.com>"),
    );
    // And with it on, the same record steps down.
    try std.testing.expectEqual(
        Policy.quarantine,
        effectivePolicySampled(&r, false, .honor, "<a@example.com>"),
    );
}

test "M-4: an unselected message steps down one level, per RFC 7489 6.6.4" {
    // §6.6.4: "If the email is not subject to the 'reject' policy (due to the
    // 'pct' tag), the Mail Receiver SHOULD treat the email as though the
    // 'quarantine' policy applies." Not `none` -- that would be a bigger
    // downgrade than the domain asked for, the same trap t=y has.
    const reject = parseRecord("v=DMARC1; p=reject; pct=0") orelse return error.ParseFailed;
    try std.testing.expectEqual(
        Policy.quarantine,
        effectivePolicySampled(&reject, false, .honor, "<a@example.com>"),
    );

    const quarantine = parseRecord("v=DMARC1; p=quarantine; pct=0") orelse return error.ParseFailed;
    try std.testing.expectEqual(
        Policy.none,
        effectivePolicySampled(&quarantine, false, .honor, "<a@example.com>"),
    );

    // pct=100 selects everything, so the declared policy stands.
    const full = parseRecord("v=DMARC1; p=reject; pct=100") orelse return error.ParseFailed;
    try std.testing.expectEqual(
        Policy.reject,
        effectivePolicySampled(&full, false, .honor, "<a@example.com>"),
    );
}

test "M-4: sampling is stable for a given Message-ID" {
    // The whole reason for hashing rather than drawing at random. A message
    // deferred with a 4xx and retried must come back to the same verdict; if it
    // did not, a sender could re-roll the sample by retrying until it slipped
    // through, which would make pct= unenforceable rather than partial.
    const id = "<retry-me@example.com>";
    const first = inSample(50, id);
    for (0..64) |_| {
        try std.testing.expectEqual(first, inSample(50, id));
    }
}

test "M-4: sampling approximates the requested percentage across a stream" {
    // §6.6.4 asks for "a close approximation to the requested percentage" and "a
    // representative sample". A stable hash could satisfy the determinism test
    // above while selecting nothing at all, or everything -- this is the half
    // that catches that.
    var selected: usize = 0;
    var buf: [64]u8 = undefined;
    const total = 1000;
    for (0..total) |i| {
        const id = std.fmt.bufPrint(&buf, "<msg-{d}@example.com>", .{i}) catch unreachable;
        if (inSample(25, id)) selected += 1;
    }
    // Generous bounds: this pins "roughly a quarter", not the exact hash.
    try std.testing.expect(selected > total * 15 / 100);
    try std.testing.expect(selected < total * 35 / 100);
}

test "M-4: pct composes with t=y and can only step further down" {
    // Both tags are reductions and a domain publishing both means both. t=y takes
    // reject to quarantine; an unselected sample takes it one further, to none.
    // What must never happen is the composition stepping back UP.
    const r = parseRecord("v=DMARC1; p=reject; t=y; pct=0") orelse return error.ParseFailed;
    try std.testing.expectEqual(Policy.quarantine, effectivePolicy(&r, false));
    try std.testing.expectEqual(
        Policy.none,
        effectivePolicySampled(&r, false, .honor, "<a@example.com>"),
    );
}

test "M-4: a message with no Message-ID is selected, not exempted" {
    // Treating an absent Message-ID as "not selected" would make dropping one
    // header a way out of a domain's enforcement, and a missing Message-ID is
    // exactly what bulk forged mail tends to lack.
    try std.testing.expect(inSample(1, null));

    const r = parseRecord("v=DMARC1; p=reject; pct=1") orelse return error.ParseFailed;
    try std.testing.expectEqual(
        Policy.reject,
        effectivePolicySampled(&r, false, .honor, null),
    );
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
    try std.testing.expectEqual(Result.pass, evaluate(&record, "example.com", "example.com", spf, &.{}));
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
    try std.testing.expectEqual(Result.pass, evaluate(&record, "example.com", "example.com", spf, &.{dkim}));
}

test "D-11: a testing-key DKIM pass does not carry DMARC, however well aligned" {
    // Identical to "evaluate pass with DKIM aligned" in every respect except the
    // testing flag, so the flag is demonstrably the only thing deciding it.
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
        .testing = true,
    };

    // RFC 6376 §3.6.1: a testing key must not be treated differently from
    // unsigned email. Unsigned mail with a failing SPF fails DMARC, so this must
    // too -- otherwise publishing `t=y` buys a domain a better outcome than
    // publishing nothing, which is exactly backwards.
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", spf, &.{dkim}));

    // And it must not be nominated as the signature the verdict rests on.
    try std.testing.expect(alignedDkim(&record, "example.com", "example.com", &.{dkim}) == null);
}

test "D-11: a real signature still carries DMARC alongside a testing one" {
    // The guard, and the ordering trap: the testing signature comes FIRST, so an
    // implementation that let the first identifier decide -- or that stopped
    // scanning at the first `pass` without checking the flag -- would fail this.
    const record = DmarcRecord{ .policy = .reject, .aspf = .relaxed, .adkim = .relaxed };
    const spf = alignment.Identifier{ .domain = "other.com", .org_domain = "other.com", .result = "fail" };
    const testing_sig = alignment.Identifier{
        .domain = "example.com",
        .org_domain = "example.com",
        .result = "pass",
        .testing = true,
    };
    const real_sig = alignment.Identifier{
        .domain = "example.com",
        .org_domain = "example.com",
        .result = "pass",
    };

    try std.testing.expectEqual(
        Result.pass,
        evaluate(&record, "example.com", "example.com", spf, &.{ testing_sig, real_sig }),
    );

    // The reported signature must be the real one, not the testing one that
    // happened to be scanned first (the M-6 reporting rule).
    const chosen = alignedDkim(&record, "example.com", "example.com", &.{ testing_sig, real_sig });
    try std.testing.expect(chosen != null);
    try std.testing.expect(!chosen.?.testing);
}

test "evaluate fail neither aligned" {
    const record = DmarcRecord{ .policy = .reject, .aspf = .strict, .adkim = .strict };
    const spf = alignment.Identifier{ .domain = "other.com", .result = "pass" };
    const dkim = alignment.Identifier{ .domain = "different.com", .result = "pass" };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", spf, &.{dkim}));
}

test "evaluate fail SPF pass but not aligned strict" {
    const record = DmarcRecord{ .policy = .quarantine, .aspf = .strict };
    const spf = alignment.Identifier{
        .domain = "mail.example.com",
        .org_domain = "example.com",
        .result = "pass",
    };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", spf, &.{}));
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
        evaluate(&record, "a.victim.co.uk", "victim.co.uk", spf, &.{}),
    );
}

test "evaluate fail when no identifier authenticated" {
    const record = DmarcRecord{ .policy = .reject };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "example.com", "example.com", .{}, &.{}));
}

test "M-6: an aligned signature behind a failing one still passes" {
    // Signature order is chosen by the sender. Taking only the first dkim
    // result made a legitimate aligned signature invisible.
    const record = DmarcRecord{ .policy = .reject, .aspf = .strict, .adkim = .strict };
    const spf = alignment.Identifier{ .domain = "other.com", .result = "fail" };
    const dkim = [_]alignment.Identifier{
        .{ .domain = "noise.test", .result = "fail" },
        .{ .domain = "example.com", .result = "pass" },
    };
    try std.testing.expectEqual(Result.pass, evaluate(&record, "example.com", "example.com", spf, &dkim));
}

test "M-6: one signature's pass cannot carry another's domain" {
    // The bypass shape: a pass earned by attacker.test must not license
    // alignment for victim.test just because both appear in the header.
    const record = DmarcRecord{ .policy = .reject, .aspf = .strict, .adkim = .strict };
    const dkim = [_]alignment.Identifier{
        .{ .domain = "attacker.test", .result = "pass" },
        .{ .domain = "victim.test", .result = "fail" },
    };
    try std.testing.expectEqual(Result.fail, evaluate(&record, "victim.test", "victim.test", .{}, &dkim));
    try std.testing.expect(dmarc.alignedDkim(&record, "victim.test", "victim.test", &dkim) == null);
}

test "M-6: alignedDkim names the signature the verdict rests on" {
    const record = DmarcRecord{ .policy = .reject, .adkim = .strict };
    const dkim = [_]alignment.Identifier{
        .{ .domain = "other.test", .result = "pass" },
        .{ .domain = "example.com", .result = "pass" },
    };
    const winner = dmarc.alignedDkim(&record, "example.com", "example.com", &dkim).?;
    try std.testing.expectEqualStrings("example.com", winner.domain.?);
}

test "subdomain policy" {
    const record = DmarcRecord{ .policy = .reject, .subdomain_policy = .none };
    try std.testing.expectEqual(Policy.none, record.getSubdomainPolicy());

    const record2 = DmarcRecord{ .policy = .reject };
    try std.testing.expectEqual(Policy.reject, record2.getSubdomainPolicy());
}
