//! `securedmarc-check` — evaluate DMARC for one set of identifiers and print the
//! result, so an external conformance suite can drive the shipped evaluator.
//!
//! Exists for the same reason `securespf-check` and `securearc-check` do: RFC
//! conformance is a V1 release gate, and a gate is only meaningful if the thing
//! under test is the code that ships. The suite this serves is built from
//! RFC 9989's own worked examples in Appendix B, which state expected
//! Organizational Domains, alignment outcomes and — in §4.10 and B.4.2 — the
//! exact sequence of DNS queries a tree walk must make.
//!
//! It takes identifiers rather than a message on purpose. DMARC's inputs are the
//! RFC5322.From domain plus the SPF and DKIM results that earlier milters in the
//! chain already established, and `securedmarc` reads those from
//! `Authentication-Results` headers. Reconstructing them from a message would
//! mean reimplementing SPF and DKIM inside the checker, which is precisely the
//! parallel implementation the gate is meant to rule out. Appendix B specifies
//! the identifiers directly, so that is the interface.
//!
//! The evaluation below is the same sequence `main.zig`'s `onEom` performs, in
//! the same order, calling the same functions: `treewalk.walk`,
//! `Walk.recordAtStart`/`policyRecord`, `DmarcRecord.applicability`,
//! `treewalk.organizationalDomain`, `treewalk.orgWalk`, `dmarc.evaluate` and
//! `dmarc.getDisposition`. `onEom` itself is not reused only because it needs a
//! live milter `Connection`.

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const process = std.process;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const dns_mod = securemilter.dns;

const dmarc = @import("dmarc.zig");
const treewalk = @import("treewalk.zig");
const alignment = @import("alignment.zig");
const psl_mod = @import("psl.zig");

fn writeOut(data: []const u8) void {
    _ = posix.write(posix.STDOUT_FILENO, data) catch {};
}

fn writeErr(data: []const u8) void {
    _ = posix.write(posix.STDERR_FILENO, data) catch {};
}

fn fatal(msg: []const u8) noreturn {
    writeErr("securedmarc-check: ");
    writeErr(msg);
    writeErr("\n");
    process.exit(2);
}

const Usage =
    \\Usage: securedmarc-check [options]
    \\
    \\Evaluate DMARC for a set of authenticated identifiers and print the
    \\outcome as key=value lines on stdout.
    \\
    \\Options:
    \\  --from <domain>         Author Domain (RFC5322.From). Required.
    \\  --mailfrom <domain>     RFC5321.MailFrom domain (the SPF identifier)
    \\  --spf <result>          SPF result: pass, fail, none, ... (default: none)
    \\  --dkim <domain>         DKIM-Authenticated Identifier (the d= value)
    \\  --dkim-result <result>  DKIM result: pass, fail, none, ... (default: none)
    \\  --psl <file>            Public Suffix List used only to veto a tree-walk result
    \\  -n <nameserver>         DNS nameserver (default: 127.0.0.1)
    \\  -p <port>               DNS nameserver port (default: 53)
    \\  -h                      Show this help
    \\
    \\Output keys:
    \\  result           DMARC result: pass, fail, none, temperror, permerror
    \\  disposition      Policy to apply: none, quarantine, reject
    \\  policy_domain    Name whose DMARC record supplied the policy
    \\  from_org         Organizational Domain of the Author Domain
    \\  spf_org          Organizational Domain of the SPF identifier, if walked
    \\  spf_aligned      yes or no
    \\  dkim_org         Organizational Domain of the DKIM identifier, if walked
    \\  dkim_aligned     yes or no
    \\
    \\Exit status is 0 whenever a verdict was reached, including "fail" — the
    \\verdict goes to stdout. A non-zero status means the tool could not run.
    \\
;

const Args = struct {
    from: ?[]const u8 = null,
    mailfrom: ?[]const u8 = null,
    spf: []const u8 = "none",
    dkim: ?[]const u8 = null,
    dkim_result: []const u8 = "none",
    psl_path: ?[]const u8 = null,
    nameserver: []const u8 = "127.0.0.1",
    port: u16 = 53,
};

fn parseArgs(allocator: Allocator) !Args {
    var result = Args{};
    var it = try process.argsWithAllocator(allocator);
    defer it.deinit();
    _ = it.next();

    while (it.next()) |arg| {
        if (mem.eql(u8, arg, "-h") or mem.eql(u8, arg, "--help")) {
            writeOut(Usage);
            process.exit(0);
        } else if (mem.eql(u8, arg, "--from")) {
            result.from = try allocator.dupe(u8, it.next() orelse fatal("--from needs a value"));
        } else if (mem.eql(u8, arg, "--mailfrom")) {
            result.mailfrom = try allocator.dupe(u8, it.next() orelse fatal("--mailfrom needs a value"));
        } else if (mem.eql(u8, arg, "--spf")) {
            result.spf = try allocator.dupe(u8, it.next() orelse fatal("--spf needs a value"));
        } else if (mem.eql(u8, arg, "--dkim")) {
            result.dkim = try allocator.dupe(u8, it.next() orelse fatal("--dkim needs a value"));
        } else if (mem.eql(u8, arg, "--dkim-result")) {
            result.dkim_result = try allocator.dupe(u8, it.next() orelse fatal("--dkim-result needs a value"));
        } else if (mem.eql(u8, arg, "--psl")) {
            result.psl_path = try allocator.dupe(u8, it.next() orelse fatal("--psl needs a value"));
        } else if (mem.eql(u8, arg, "-n")) {
            result.nameserver = try allocator.dupe(u8, it.next() orelse fatal("-n needs a value"));
        } else if (mem.eql(u8, arg, "-p")) {
            const raw = it.next() orelse fatal("-p needs a value");
            result.port = std.fmt.parseInt(u16, raw, 10) catch fatal("invalid port");
        } else {
            fatal("unknown argument");
        }
    }

    if (result.from == null) fatal("--from is required (see -h)");
    return result;
}

/// Print one `key=value` line. Absent values print as an empty value rather than
/// being omitted, so a consumer can tell "walked, got nothing" from "never
/// asked" only by the key's presence, and every run yields the same key set.
fn emit(key: []const u8, value: []const u8) void {
    writeOut(key);
    writeOut("=");
    writeOut(value);
    writeOut("\n");
}

fn emitAll(
    result: []const u8,
    disposition: []const u8,
    policy_domain: []const u8,
    from_org: []const u8,
    spf_org: []const u8,
    spf_aligned: bool,
    dkim_org: []const u8,
    dkim_aligned: bool,
) void {
    emit("result", result);
    emit("disposition", disposition);
    emit("policy_domain", policy_domain);
    emit("from_org", from_org);
    emit("spf_org", spf_org);
    emit("spf_aligned", if (spf_aligned) "yes" else "no");
    emit("dkim_org", dkim_org);
    emit("dkim_aligned", if (dkim_aligned) "yes" else "no");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try parseArgs(allocator);
    const from_domain = args.from.?;

    var resolver = dns_mod.Resolver.init(allocator, .{
        .nameservers = &.{args.nameserver},
        .port = args.port,
    });
    defer resolver.deinit();

    var psl: ?psl_mod.PublicSuffixList = null;
    defer if (psl) |*p| p.deinit();
    if (args.psl_path) |path| {
        var list = psl_mod.PublicSuffixList.init(allocator);
        list.loadFile(path) catch fatal("could not load the public suffix list");
        psl = list;
    }
    const psl_ptr: ?*const psl_mod.PublicSuffixList = if (psl) |*p| p else null;

    // Step 3, as in onEom: policy discovery and the Organizational Domain both
    // come from one tree walk starting at the Author Domain (RFC 9989 §4.10).
    var author_walk = treewalk.walk(allocator, &resolver, from_domain) catch {
        emitAll("temperror", "none", "", "", "", false, "", false);
        return;
    };
    defer author_walk.deinit();

    // §4.10.1: the Author Domain's own record wins; otherwise the record
    // belonging to its Organizational or Public Suffix Domain applies.
    const at_start = author_walk.recordAtStart();
    const selected = at_start orelse author_walk.policyRecord() orelse {
        if (author_walk.transient_error) {
            emitAll("temperror", "none", "", "", "", false, "", false);
        } else {
            emitAll("none", "none", "", "", "", false, "", false);
        }
        return;
    };
    const policy_domain = if (at_start != null)
        from_domain
    else
        author_walk.policyDomain() orelse "";

    // §4.10.1: a record with no usable p=, or an invalid sp=/np=, acts as
    // p=none when it carries a valid rua= and otherwise disables DMARC for the
    // message entirely.
    var rec = selected;
    switch (rec.applicability()) {
        .apply => {},
        .as_none => {
            rec.policy = .none;
            rec.subdomain_policy = null;
        },
        .no_processing => {
            emitAll("none", "none", policy_domain, "", "", false, "", false);
            return;
        },
    }

    const from_org = treewalk.organizationalDomain(&author_walk, psl_ptr);
    const is_subdomain = !std.ascii.eqlIgnoreCase(from_domain, from_org);

    // Step 4: each identifier's own Organizational Domain, via the same shared
    // helper the milter uses.
    var spf_ident = alignment.Identifier{ .domain = args.mailfrom, .result = args.spf };
    var dkim_ident = alignment.Identifier{ .domain = args.dkim, .result = args.dkim_result };

    var spf_walk = treewalk.orgWalk(allocator, &resolver, rec.aspf, from_domain, from_org, &spf_ident, psl_ptr);
    defer if (spf_walk) |*w| w.deinit();
    var dkim_walk = treewalk.orgWalk(allocator, &resolver, rec.adkim, from_domain, from_org, &dkim_ident, psl_ptr);
    defer if (dkim_walk) |*w| w.deinit();

    // Step 5 and 6.
    const result = dmarc.evaluate(&rec, from_domain, from_org, spf_ident, dkim_ident);
    const disposition = dmarc.getDisposition(&rec, is_subdomain);

    emitAll(
        result.toString(),
        disposition,
        policy_domain,
        from_org,
        spf_ident.org_domain orelse "",
        alignment.isAligned(from_domain, from_org, spf_ident, rec.aspf),
        dkim_ident.org_domain orelse "",
        alignment.isAligned(from_domain, from_org, dkim_ident, rec.adkim),
    );
}
