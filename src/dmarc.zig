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
        if (std.ascii.eqlIgnoreCase(s, "none")) return .none;
        if (std.ascii.eqlIgnoreCase(s, "quarantine")) return .quarantine;
        if (std.ascii.eqlIgnoreCase(s, "reject")) return .reject;
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

/// Value of the t= tag, RFC 9989 §4.7. Whether the Domain Owner wants the
/// policy in p=/sp=/np= actually applied, or is still testing it.
pub const TestMode = enum {
    /// t=n or absent — apply the declared policy.
    apply,
    /// t=y — the Domain Owner is testing, and expects one level below the
    /// declared policy to be applied to failing messages.
    testing,

    pub fn fromString(s: []const u8) TestMode {
        // §4.8: a syntax error in the remainder of the record is discarded in
        // favour of the default, so anything that is not "y" reads as t=n.
        if (std.ascii.eqlIgnoreCase(s, "y")) return .testing;
        return .apply;
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
        if (std.ascii.eqlIgnoreCase(s, "y")) return .yes;
        if (std.ascii.eqlIgnoreCase(s, "n")) return .no;
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
    /// Test mode (t=), RFC 9989 §4.7. Default: apply the policy as declared.
    testing: TestMode = .apply,
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

    /// Policy for non-existent subdomains (np=), RFC 9989 §4.7.
    ///
    /// Parsed so §4.10.1 can tell a *valid* np= from an invalid one, which is
    /// one of the three triggers for the applicability rule. **Not yet applied:**
    /// choosing np= over sp= requires a DNS existence check on the Author
    /// Domain that the daemon does not currently make, so a domain publishing
    /// `sp=none; np=reject` still gets sp= treatment. Tracked as post-V1.
    np: ?Policy = null,

    /// A valid `p=` tag was present. §4.10.1 turns on this and the two flags
    /// below, so they are recorded at parse time rather than re-derived.
    policy_valid: bool = false,

    /// An `sp=` or `np=` tag was present but its value was not a policy.
    /// §4.10.1 treats that exactly like a missing `p=`.
    subdomain_tag_invalid: bool = false,

    /// `rua=` was present and held at least one syntactically valid URI.
    rua_valid: bool = false,

    /// Get the effective subdomain policy.
    pub fn getSubdomainPolicy(self: *const DmarcRecord) Policy {
        return self.subdomain_policy orelse self.policy;
    }

    /// RFC 9989 §4.10.1, applied to the record policy discovery selected.
    pub fn applicability(self: *const DmarcRecord) Applicability {
        if (self.policy_valid and !self.subdomain_tag_invalid) return .apply;
        // "If a rua tag is present and contains at least one syntactically
        // valid reporting URI, the Mail Receiver MUST act as if a record
        // containing p=none was retrieved and continue processing."
        if (self.rua_valid) return .as_none;
        // "Otherwise, the Mail Receiver applies no DMARC processing to this
        // message." Note this is *not* the same as continuing the tree walk:
        // a retrieved-but-unusable record ends DMARC for the message rather
        // than deferring to a parent's policy.
        return .no_processing;
    }
};

/// What RFC 9989 §4.10.1 says to do with the record policy discovery selected.
pub const Applicability = enum {
    /// The record carries a usable policy; apply it.
    apply,
    /// Unusable policy but a valid `rua=`: act as if `p=none` was published.
    as_none,
    /// Unusable policy and no valid `rua=`: apply no DMARC processing at all.
    no_processing,
};

/// Does `rua=` hold at least one syntactically valid reporting URI?
///
/// §4.8: `dmarc-urilist` is a comma-separated list of `dmarc-uri`, which is a
/// URI per RFC 3986, optionally carrying the obsolete `!size` suffix that
/// §4.8 says to ignore. A URI needs a scheme -- ALPHA followed by ALPHA /
/// DIGIT / "+" / "-" / "." -- then ":" and a non-empty remainder.
///
/// Scheme *support* is deliberately not considered. §4.6 says a receiver must
/// ignore URIs whose schemes it does not support, but that governs whether a
/// report is sent; §4.10.1 asks only whether a URI is syntactically valid. A
/// record listing `https://` alone still counts here even though this daemon
/// sends no reports at all, because the question is what policy to apply.
pub fn hasValidReportingUri(rua: []const u8) bool {
    var iter = mem.splitScalar(u8, rua, ',');
    while (iter.next()) |raw| {
        var uri = mem.trim(u8, raw, &std.ascii.whitespace);
        // Strip the obsolete size limit: dmarc-uri "!" 1*DIGIT [k/m/g/t].
        if (mem.indexOfScalar(u8, uri, '!')) |bang| uri = uri[0..bang];
        const colon = mem.indexOfScalar(u8, uri, ':') orelse continue;
        if (colon == 0) continue;
        if (colon + 1 >= uri.len) continue;
        if (!std.ascii.isAlphabetic(uri[0])) continue;
        var scheme_ok = true;
        for (uri[1..colon]) |c| {
            if (std.ascii.isAlphanumeric(c) or c == '+' or c == '-' or c == '.') continue;
            scheme_ok = false;
            break;
        }
        if (scheme_ok) return true;
    }
    return false;
}

/// Parse a DMARC TXT record value.
///
/// Returns null only when the text is **not a DMARC Policy Record at all** --
/// that is, when `v=` is absent, not first, or not exactly `DMARC1` (§4.7,
/// §4.8). A record whose `v=` is good but whose `p=` is missing or invalid
/// still parses, because §4.10.1 gives those records defined behaviour that
/// depends on `rua=` and cannot be expressed by returning null.
///
/// This distinction matters to the tree walk: null means "nothing here, keep
/// walking", whereas a record with an unusable policy may end DMARC processing
/// for the message outright. Returning null for a missing `p=` conflated the
/// two and silently applied a *parent's* policy to a domain the RFC says to
/// treat as `p=none`.
pub fn parseRecord(txt: []const u8) ?DmarcRecord {
    const trimmed = mem.trim(u8, txt, &std.ascii.whitespace);
    if (trimmed.len < 8) return null;

    // §4.8: dmarc-version = "v" equals %s"DMARC1". The %s prefix (RFC 7405)
    // makes the *value* case sensitive while the tag name, like every other
    // tag name, is not. §4.7 states the same thing in prose and adds that a
    // record whose v= is absent, not first, or not exactly "DMARC1" MUST be
    // ignored entirely.
    //
    // So "V=DMARC1" is a valid record and "v=dmarc1" is not one at all. Both
    // used to parse, which meant a malformed record was read as policy.
    if (trimmed.len < 2) return null;
    if (std.ascii.toLower(trimmed[0]) != 'v') return null;
    if (trimmed[1] != '=') return null;
    if (!mem.startsWith(u8, trimmed[2..], "DMARC1")) return null;
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

        if (std.ascii.eqlIgnoreCase(tag, "p")) {
            record.policy = Policy.fromString(val) orelse continue;
            found_policy = true;
        } else if (std.ascii.eqlIgnoreCase(tag, "sp")) {
            // An *absent* sp= defaults to p=; an sp= with an unparseable value
            // is a §4.10.1 trigger. Leaving subdomain_policy null for both
            // would silently downgrade the second case to the first.
            record.subdomain_policy = Policy.fromString(val) orelse {
                record.subdomain_tag_invalid = true;
                continue;
            };
        } else if (std.ascii.eqlIgnoreCase(tag, "np")) {
            record.np = Policy.fromString(val) orelse {
                record.subdomain_tag_invalid = true;
                continue;
            };
        } else if (std.ascii.eqlIgnoreCase(tag, "adkim")) {
            record.adkim = parseAlignmentTag(val);
        } else if (std.ascii.eqlIgnoreCase(tag, "aspf")) {
            record.aspf = parseAlignmentTag(val);
        } else if (std.ascii.eqlIgnoreCase(tag, "t")) {
            record.testing = TestMode.fromString(val);
        } else if (std.ascii.eqlIgnoreCase(tag, "rua")) {
            record.rua = val;
            record.rua_valid = hasValidReportingUri(val);
        } else if (std.ascii.eqlIgnoreCase(tag, "ruf")) {
            record.ruf = val;
        } else if (std.ascii.eqlIgnoreCase(tag, "fo")) {
            record.fo = val;
        } else if (std.ascii.eqlIgnoreCase(tag, "psd")) {
            record.psd = Psd.fromString(val);
        }
    }

    // p= is REQUIRED, but a record missing it is not thereby "not a DMARC
    // record": §4.10.1 defines what to do with it. The caller decides via
    // applicability(); see the doc comment above.
    record.policy_valid = found_policy;

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
    return effectivePolicy(record, is_subdomain).toString();
}

/// The policy this hop should actually act on, after RFC 9989 §4.7 test mode.
///
/// `t=y` is **not** "treat as none". §4.7 asks for the policy one level below
/// the declared one -- `reject` becomes `quarantine`, `quarantine` becomes
/// `none` -- and says the tag "has no effect on any policy that is none". A
/// naive mapping of `t=y` to `none` would let a domain testing `p=reject`
/// through unquarantined, which is a larger downgrade than it asked for.
///
/// Test mode deliberately does not affect the DMARC *result*, only the
/// disposition: §4.7 states it does not affect report generation, and the
/// `dmarc=` value in `Authentication-Results` is what a downstream consumer
/// and any future reporter read.
pub fn effectivePolicy(record: *const DmarcRecord, is_subdomain: bool) Policy {
    const declared = if (is_subdomain)
        record.getSubdomainPolicy()
    else
        record.policy;

    return switch (record.testing) {
        .apply => declared,
        .testing => switch (declared) {
            .reject => .quarantine,
            .quarantine => .none,
            .none => .none,
        },
    };
}

fn parseAlignmentTag(val: []const u8) alignment.AlignmentMode {
    if (val.len == 1) {
        if (val[0] == 's' or val[0] == 'S') return .strict;
    }
    return .relaxed;
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

