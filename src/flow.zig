//! Per-message SecureDMARC evaluation, stamping, and event publishing.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

const securemilter = @import("securemilter");
const connection_mod = securemilter.connection;
const auth_stamp = securemilter.auth_stamp;
const escape = securemilter.escape;
const responses = securemilter.milter.responses;
const header_scrub = securemilter.header_scrub;
const dns_mod = securemilter.dns;
const deadline_mod = securemilter.deadline;
const zmq = securemilter.zmq;
const log = securemilter.log;

const dmarc = @import("dmarc.zig");
const alignment = @import("alignment.zig");
const treewalk = @import("treewalk.zig");
const psl = @import("psl.zig");
const upstream = @import("upstream.zig");
const settings = @import("settings.zig");


/// Per-message configuration used by the flow.
pub const MsgCtx = struct {
    authserv_id: []const u8,
    strip_policy: header_scrub.StripPolicy,
    sampling: dmarc.SamplingPolicy,
    /// Loaded once at startup and read-only for the life of the process -- see
    /// `reloadConfig`, which explicitly refuses to swap it under running
    /// workers -- so carrying the pointer is safe. Null when none is configured.
    psl: ?*const psl.PublicSuffixList,

    /// Lazy per-thread resolver and publisher accessors.
    resolver: *const fn () *dns_mod.Resolver,
    publisher: *const fn () *zmq.Publisher,
    /// Wall-clock bound on one message's evaluation, in ms; 0 disables (X-21).
    /// No default: it must come from configuration -- a silently supplied
    /// constant is the L-2 mechanism. The DMARC walk and each DKIM
    /// identifier's org-domain walk are the DNS steps it bounds.
    max_evaluation_ms: i64,

    /// Per-listener disposition enforcement (design-dmarc-enforcement.md),
    /// indexed by `conn.listener_index`. Empty slice means never enforce.
    enforcement: []const settings.Enforcement,
    /// SMTP reply text template for reject enforcement (%s = Author Domain).
    reject_text: []const u8,
    /// Header name used when quarantine enforcement tags for the LDA.
    quarantine_header: []const u8,
    /// authserv-ids whose sealed ARC chains downgrade reject to quarantine.
    trusted_sealers: []const []const u8,
};

/// What the gate does with a judged failure.
pub const GateAction = enum { none, tag, reject };

/// The enforcement gate, pure: verdict x effective policy x listener setting
/// x trusted-sealer override.
///
/// Only a judged `fail` acts: RFC 9989 §5.3.6 forbids applying the published
/// policy to a message that could not be evaluated, and every non-fail path
/// (temperror/permerror/none) is exactly that. The override downgrades one
/// level -- reject to tag -- never to silent acceptance: a chain we trust
/// says the mail authenticated at a hop we trust, not that we must deliver it
/// to the inbox.
pub fn decideGate(
    result: dmarc.Result,
    policy: dmarc.Policy,
    enforcement: settings.Enforcement,
    override: bool,
) GateAction {
    if (result != .fail) return .none;
    return switch (policy) {
        .none => .none,
        .quarantine => switch (enforcement) {
            .none => .none,
            .quarantine, .reject => .tag,
        },
        .reject => switch (enforcement) {
            .none => .none,
            .quarantine => .tag,
            .reject => if (override) .tag else .reject,
        },
    };
}

/// Maximum DKIM results evaluated from Authentication-Results.
const MAX_DKIM_IDENTIFIERS = 10;

/// End-of-message: scrub forged claims, evaluate, and log the verdict.
pub fn doEom(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    const start_ns = std.time.nanoTimestamp();

    // Drop forged dmarc= claims before evaluating. The spf= and dkim= results
    // this evaluation consumes were scrubbed of forgeries by SecureSPF and
    // SecureDKIM earlier in the chain; what survives here was produced by them.
    _ = header_scrub.stripAuthResults(conn, ctx.authserv_id, ctx.strip_policy);

    const result = doDmarcEvaluation(conn, ctx);
    const elapsed_ms = @divFloor(std.time.nanoTimestamp() - start_ns, 1_000_000);
    const queue_id = conn.macros.queue_id orelse "-";
    // Via the accessor, not the macro: {client_addr} is absent from Postfix's
    // default milter_connect_macros, so reading it directly logs "unknown" for
    // every connection on a stock MTA. The accessor falls back to the address
    // SMFIC_CONNECT carried. Here the placeholder is display-only.
    const client_addr = conn.clientAddr() orelse "unknown";
    const from_domain = getFromDomain(conn) orelse "unknown";
    const peer = conn.getPeerDisplay();
    // `domain` here is taken from the message's own `From:` field, which is
    // entirely sender-chosen and may be folded across lines -- so its unfolded
    // value can begin with whitespace or contain a bare LF. Unescaped, that
    // either forged a second syslog line or made `elapsed=` look like this
    // field's value. This is the field the x5a probe reported (audit X-5).
    log.info("id={f} peer={f}[{f}] client={f} domain={f} elapsed={d}ms", .{
        escape.logField(queue_id),
        escape.logField(peer.name),
        escape.logField(peer.ip),
        escape.logField(client_addr),
        escape.logField(from_domain),
        elapsed_ms,
    });
    return result;
}

/// Perform DMARC evaluation at end-of-message.
///
/// 1. Extract From: header domain
/// 2. Read upstream A-R headers to find SPF and DKIM results
/// 3. DNS lookup _dmarc.<from_domain> TXT
/// 4. Parse DMARC record, check alignment, determine result
/// 5. Add our own A-R header with DMARC result
fn doDmarcEvaluation(conn: *connection_mod.Connection, ctx: MsgCtx) u8 {
    // Step 0: A message with more than one From field has no single author
    // domain to evaluate. RFC 5322 forbids it and RFC 7489 §6.6.1 declines to
    // guess; picking one instance means the domain we authenticate can differ
    // from the one the reader is shown. Fail rather than choose.
    const from_count = countFromHeaders(conn);
    if (from_count > 1) {
        addArHeaderSimple(conn, ctx, "fail", "multiple From header fields") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    }

    // Step 1: Extract From: domain
    const from_domain = getFromDomain(conn) orelse {
        addArHeaderSimple(conn, ctx, "none", "no From header") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    };

    // Step 2: Parse upstream Authentication-Results headers
    // The envelope-from domain is what SPF authenticated
    const envelope_domain = getEnvelopeDomain(conn);

    // Each DKIM signature contributes its own (result, d=) pair, and they stay
    // paired — see `upstream.zig`, which is where audit M-6 lives.
    var up = upstream.collect(conn.allocator, conn.headers.items, ctx.authserv_id, MAX_DKIM_IDENTIFIERS);
    defer up.deinit(conn.allocator);

    const spf_result = up.spf_result;
    const dkim_idents = up.dkim;

    if (up.truncated) {
        log.warn(
            "more than {d} DKIM results in Authentication-Results; evaluating the first {d}",
            .{ MAX_DKIM_IDENTIFIERS, MAX_DKIM_IDENTIFIERS },
        );
    }

    // Step 3: Policy discovery and Organizational Domain, both by DNS tree
    // walk (RFC 9989 §4.10). The walk starts at the Author Domain: if it
    // publishes a record that is the policy, and the walk continues upward
    // only to establish where the organizational boundary lies.
    //
    // X-21: the deadline starts here, before the first DNS-dependent step, and
    // is checked again before each DKIM identifier's org walk below. Expiry is
    // temperror -- the message was not judged, and must not read as fail.
    const deadline = deadline_mod.Deadline.fromNow(ctx.max_evaluation_ms);
    const resolver = ctx.resolver();

    if (deadline.expired()) {
        log.warn("dmarc: evaluation deadline exceeded before policy discovery", .{});
        addArHeaderSimple(conn, ctx, "temperror", "evaluation deadline exceeded") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    }

    var author_walk = treewalk.walk(conn.allocator, resolver, from_domain) catch {
        addArHeaderSimple(conn, ctx, "temperror", "internal error") catch |err|
            return auth_stamp.deferCode(err, "dmarc");
        return @intFromEnum(responses.Code.@"continue");
    };
    defer author_walk.deinit();

    // §4.10.1: the Author Domain's own record wins; otherwise the record
    // belonging to its Organizational or Public Suffix Domain applies.
    const selected = author_walk.recordAtStart() orelse author_walk.policyRecord() orelse {
        if (author_walk.transient_error) {
            addArHeaderSimple(conn, ctx, "temperror", "DNS lookup failed") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
        } else {
            addArHeaderSimple(conn, ctx, "none", "no DMARC record found") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
        }
        return @intFromEnum(responses.Code.@"continue");
    };

    // §4.10.1: a record whose p= is missing or invalid, or which carries an
    // invalid sp= or np=, is not simply ignored. A valid rua= makes it act as
    // p=none; without one, DMARC does not apply to this message at all.
    //
    // The second branch is why this is a decision and not a default: reporting
    // `none` here is the RFC's answer, whereas falling through to a parent's
    // record could apply an organizational `p=reject` to a domain the RFC says
    // to leave alone, and reject mail on the strength of a malformed record.
    var rec = selected;
    switch (rec.applicability()) {
        .apply => {},
        .as_none => {
            rec.policy = .none;
            rec.subdomain_policy = null;
            log.info("dmarc: {s}: record has no usable policy but a valid rua=, applying p=none per RFC 9989 4.10.1", .{from_domain});
        },
        .no_processing => {
            log.info("dmarc: {s}: record has no usable policy and no valid rua=, no DMARC processing per RFC 9989 4.10.1", .{from_domain});
            addArHeaderSimple(conn, ctx, "none", "record has no usable policy") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
            return @intFromEnum(responses.Code.@"continue");
        },
    }

    const from_org = treewalk.organizationalDomain(&author_walk, ctx.psl);
    const is_subdomain = !std.ascii.eqlIgnoreCase(from_domain, from_org);

    // Step 4: Resolve each authenticated identifier's own Organizational
    // Domain. Only needed for relaxed mode and only for identifiers that
    // actually passed — strict mode is a string comparison (§4.10.2).
    var spf_ident = alignment.Identifier{ .domain = envelope_domain, .result = spf_result };

    var spf_walk = treewalk.orgWalk(conn.allocator, resolver, rec.aspf, from_domain, from_org, &spf_ident, ctx.psl);
    defer if (spf_walk) |*w| w.deinit();

    // One walk per DKIM identifier, each kept alive because the identifier's
    // `org_domain` points into it. `orgWalk` returns null for the cases that
    // need no DNS at all (strict mode, a result that did not pass, a domain
    // equal to the Author Domain), so the common single-signature message still
    // costs exactly one walk. MAX_DKIM_IDENTIFIERS is what stops a message
    // carrying a hundred signatures from buying a hundred tree walks (X-4).
    var dkim_walks: [MAX_DKIM_IDENTIFIERS]?treewalk.Walk = @splat(null);
    defer for (&dkim_walks) |*w| {
        if (w.*) |*walk| walk.deinit();
    };
    for (dkim_idents, 0..) |*ident, i| {
        // X-21: each walk costs DNS; the deadline decides whether another is
        // spent. Expiry is a temperror for the whole message -- evaluating
        // alignment from a PARTIAL set of walks would judge the message on
        // evidence we did not gather.
        if (deadline.expired()) {
            log.warn("dmarc: evaluation deadline exceeded during org-domain walks", .{});
            addArHeaderSimple(conn, ctx, "temperror", "evaluation deadline exceeded") catch |err|
                return auth_stamp.deferCode(err, "dmarc");
            return @intFromEnum(responses.Code.@"continue");
        }
        dkim_walks[i] = treewalk.orgWalk(conn.allocator, resolver, rec.adkim, from_domain, from_org, ident, ctx.psl);
    }

    // Step 5: Evaluate alignment
    //
    // The detailed form keeps the two alignment booleans the verdict was built
    // from, which the reporting event has to state and cannot safely re-derive
    // (audit M-7a).
    const evaluation = dmarc.evaluateDetailed(&rec, from_domain, from_org, spf_ident, dkim_idents);
    const result = evaluation.result;

    // Report the signature the verdict actually rests on: the aligned one when
    // there is one, otherwise the first, so a `dkim=pass` in the event is never
    // paired with a `d=` from some other signature — the M-6 defect itself.
    const reported_dkim = dmarc.alignedDkim(&rec, from_domain, from_org, dkim_idents) orelse
        if (dkim_idents.len > 0) dkim_idents[0] else alignment.Identifier{};

    // Step 6: Add Authentication-Results header
    // Sampling keys off the Message-ID so a retried message keeps the verdict it
    // was given; see `dmarc.inSample`. Absent, the message counts as selected.
    const effective = dmarc.effectivePolicySampled(
        &rec,
        is_subdomain,
        ctx.sampling,
        getMessageId(conn),
    );
    const disposition = effective.toString();
    addArHeaderFull(conn, ctx, result.toString(), from_domain, disposition) catch |err|
        return auth_stamp.deferCode(err, "dmarc");

    // A1: disposition enforcement. The stamp is already written before any
    // action: on an SMTP-time reject it never propagates, on a tag it rides
    // along for the LDA.
    const enforcement: settings.Enforcement = if (conn.listener_index < ctx.enforcement.len)
        ctx.enforcement[conn.listener_index]
    else
        .none;

    // The override asks two independent questions: did OUR securearc call the
    // chain valid (arc=pass), and does a trusted sealer's own AAR record pass
    // evidence for this From domain. A valid chain that sealed a failure is
    // custody of bad news, not a reason to soften.
    var override_sealer: ?[]const u8 = null;
    defer if (override_sealer) |s| conn.allocator.free(s);
    if (result == .fail and enforcement == .reject and ctx.trusted_sealers.len > 0) {
        if (up.arc_result) |arc_res| {
            if (std.ascii.eqlIgnoreCase(arc_res, "pass")) {
                override_sealer = upstream.trustedSealerEvidence(
                    conn.allocator,
                    conn.headers.items,
                    ctx.trusted_sealers,
                    from_domain,
                );
            }
        }
    }

    const action = decideGate(result, effective, enforcement, override_sealer != null);

    // Publish ZMQ event with full evaluation details
    publishEvent(ctx, conn.allocator, .{
        // Via the accessor so this is populated on a stock MTA, where the
        // {client_addr} macro is not sent. An empty value here is not cosmetic:
        // client_ip is mandatory on every RFC 7489 SS7.2 <record><row>, so an
        // event without it cannot become a valid aggregate report row.
        .client_ip = conn.clientAddr() orelse "",
        .header_from = from_domain,
        .from_address = getFromAddress(conn) orelse "",
        .envelope_from = envelope_domain orelse "",
        .policy = dmarc.publishedPolicy(&rec, is_subdomain).toString(),
        .disposition = disposition,
        .dmarc_result = result.toString(),
        .spf_result = spf_result orelse "none",
        .spf_aligned = evaluation.spf_aligned,
        .dkim_result = reported_dkim.result orelse "none",
        .dkim_domain = reported_dkim.domain orelse "",
        .dkim_aligned = evaluation.dkim_aligned,
        .policy_override = if (override_sealer) |_| "trusted_forwarder" else "",
    });

    switch (action) {
        .none => {},
        .tag => {
            tagForQuarantine(conn, ctx) catch |err| return auth_stamp.deferCode(err, "dmarc");
            if (override_sealer) |s| {
                log.info("dmarc: {s}: fail under p=reject downgraded to quarantine by trusted ARC sealer {s}", .{ from_domain, s });
            } else {
                log.info("dmarc: {s}: fail under p={s}, tagged {s} for the LDA", .{ from_domain, disposition, ctx.quarantine_header });
            }
        },
        .reject => {
            log.info("dmarc: {s}: fail under p=reject, rejecting at SMTP time", .{from_domain});
            return rejectMessage(conn, ctx, from_domain) catch |err|
                auth_stamp.deferCode(err, "dmarc");
        },
    }

    return @intFromEnum(responses.Code.@"continue");
}

// =============================================================================
// Helper functions
// =============================================================================

fn countFromHeaders(conn: *connection_mod.Connection) usize {
    var count: usize = 0;
    for (conn.headers.items) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "From")) count += 1;
    }
    return count;
}

/// The Message-ID this message carries, if it carries exactly one.
///
/// Null when absent *or* duplicated. A second Message-ID would let a sender pick
/// which one we sample on, and RFC 5322 §3.6 allows at most one, so a message
/// with two has no single identity to key a stable decision to (audit M-4).
fn getMessageId(conn: *connection_mod.Connection) ?[]const u8 {
    var found: ?[]const u8 = null;
    for (conn.headers.items) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "Message-ID")) continue;
        if (found != null) return null;
        found = mem.trim(u8, hdr.value, &std.ascii.whitespace);
    }
    return found;
}

/// The address in the `From` header, without any display name.
///
/// Split out from `getFromDomain` so the reporting event can state the full
/// address RFC 7489 §7.2 asks for without a second, possibly divergent, parse of
/// the same header (audit M-7a).
fn getFromAddress(conn: *connection_mod.Connection) ?[]const u8 {
    for (conn.headers.items) |hdr| {
        if (std.ascii.eqlIgnoreCase(hdr.name, "From")) {
            // Extract email address from From: header value
            // Handle "Display Name <addr@domain>" and bare "addr@domain"
            const val = mem.trim(u8, hdr.value, &std.ascii.whitespace);
            if (mem.lastIndexOfScalar(u8, val, '>')) |gt| {
                if (mem.lastIndexOfScalar(u8, val[0..gt], '<')) |lt| {
                    return val[lt + 1 .. gt];
                }
            }
            return val;
        }
    }
    return null;
}

fn getFromDomain(conn: *connection_mod.Connection) ?[]const u8 {
    return alignment.getDomainFromEmail(getFromAddress(conn) orelse return null);
}

/// Tag a message for the LDA (quarantine enforcement). Any pre-existing
/// instance of the configured header is a forgery -- the tag means nothing
/// unless we added it -- so those go first, newest occurrence of the name
/// first, because SMFIR_CHGHEADER addresses the n-th instance of a name and
/// removing a lower index would renumber the ones above it (header_scrub's
/// rule, by name rather than by authserv-id).
fn tagForQuarantine(conn: *connection_mod.Connection, ctx: MsgCtx) !void {
    // Forward pass, mirroring header_scrub: record each forged instance's
    // list position and its 1-based occurrence among same-name headers.
    const Victim = struct { list_pos: usize, occurrence: u32 };
    var victims: std.ArrayListUnmanaged(Victim) = .{};
    defer victims.deinit(conn.allocator);
    var occurrence: u32 = 0;
    for (conn.headers.items, 0..) |hdr, pos| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, ctx.quarantine_header)) continue;
        occurrence += 1;
        try victims.append(conn.allocator, .{ .list_pos = pos, .occurrence = occurrence });
    }

    if (victims.items.len > 0) {
        if (!conn.negotiated_actions.change_headers) {
            // Forged tag present and we cannot remove it: refuse to tag at all
            // rather than leave the sender's instance beside ours.
            log.err("cannot tag for quarantine: forged {s} present and MTA did not grant SMFIF_CHGHDRS", .{ctx.quarantine_header});
            return error.CannotTag;
        }
        // Delete newest occurrence first: removing a lower index would
        // renumber the ones above it (header_scrub's rule).
        var i: usize = victims.items.len;
        while (i > 0) {
            i -= 1;
            const v = victims.items[i];
            const payload = try responses.changeHeader(conn.allocator, v.occurrence, ctx.quarantine_header, "");
            defer conn.allocator.free(payload);
            try conn.sendPacket(payload);
            conn.removeHeader(v.list_pos);
        }
    }

    const payload = try responses.insertHeader(
        conn.allocator,
        0,
        ctx.quarantine_header,
        "quarantine",
        conn.negotiated_protocol.header_leading_space,
    );
    defer conn.allocator.free(payload);
    try conn.sendPacket(payload);
}

/// Reject at SMTP time. RFC 9989 §7.2 prefers this over a later DSN, which
/// would be backscatter to a forged envelope sender.
fn rejectMessage(conn: *connection_mod.Connection, ctx: MsgCtx, from_domain: []const u8) !u8 {
    // settings refused a template without %s at startup.
    const text = try mem.replaceOwned(u8, conn.allocator, ctx.reject_text, "%s", from_domain);
    defer conn.allocator.free(text);
    const payload = try responses.replyCode(conn.allocator, "550 5.7.1", text);
    defer conn.allocator.free(payload);
    try conn.sendPacket(payload);
    return @intFromEnum(responses.Code.reject);
}

fn getEnvelopeDomain(conn: *connection_mod.Connection) ?[]const u8 {
    const raw = conn.mail_from_raw orelse return null;
    const addr = alignment.stripAngleBrackets(raw);
    return alignment.getDomainFromEmail(addr);
}

/// One DMARC evaluation, as the future `securedmarc-reporter` needs to see it.
///
/// The field set is the one the suite plan specifies, which in turn is what
/// RFC 7489 §7.2 requires of an aggregate report row (audit M-7a). `client_ip`
/// is the field that matters most: it is mandatory on every `<record><row>`
/// and it is the only field here that a subscriber cannot reconstruct after
/// the fact, because the connecting address is known to the milter and to
/// nothing downstream of it.
const Event = struct {
    client_ip: []const u8,

    /// The RFC5322.From **domain**, which is what an aggregate report's
    /// `<header_from>` holds: RFC 9990 SS3.1.1.10 and RFC 7489 Appendix C both
    /// define the element as "the RFC5322.From domain from the message".
    ///
    /// Holding the full mailbox here would make the one field a reporter can
    /// copy straight into the XML the one field it must not. The name is the
    /// report's, so it carries the report's meaning; the mailbox is next door
    /// under a name the RFC does not use for anything.
    header_from: []const u8,

    /// The whole RFC5322.From mailbox, local-part included.
    ///
    /// Ours, not an aggregate-report field -- DMARC authenticates a domain and
    /// RFC 7489 SS1 is explicit that it "does not authenticate the local-part".
    /// Kept because it is useful for forensics and for operators reading the
    /// event stream directly, and deliberately not named `header_from`.
    from_address: []const u8,

    /// The RFC5321.MailFrom **domain** (RFC 9990 SS3.1.1.10), matching
    /// `header_from` in granularity rather than the mailbox above.
    envelope_from: []const u8,
    /// What the Domain Owner published, before `t=y` or `pct=` reduced it.
    policy: []const u8,
    /// What we actually applied, after those reductions.
    disposition: []const u8,
    dmarc_result: []const u8,
    spf_result: []const u8,
    spf_aligned: bool,
    dkim_result: []const u8,
    dkim_domain: []const u8,
    dkim_aligned: bool,
    /// RFC 7489 §7.2 policy_override, present only when one fired. Emitted
    /// rather than left implicit: without it a report consumer cannot tell an
    /// overridden reject apart from a verdict we never enforced.
    policy_override: []const u8 = "",
};

fn publishEvent(ctx: MsgCtx, allocator: Allocator, ev: Event) void {
    const json = formatEvent(allocator, ev) catch return;
    defer allocator.free(json);

    ctx.publisher().publish(json);
}

/// Serialize one event.
///
/// Separate from `publishEvent` so the payload can be asserted on without a ZMQ
/// socket: the field set is a contract with a consumer that does not exist yet,
/// which is exactly the kind of thing that silently rots if nothing checks it.
fn formatEvent(allocator: Allocator, ev: Event) ![]u8 {
    // `header_from`, `from_address`, `dkim_domain` and `envelope_from` all
    // originate in the message or its envelope, so each is sender-chosen; the
    // results, the policy and the disposition are ours, and `client_ip` comes
    // from the MTA rather than the message. An unescaped `"` in a sender-chosen
    // value would end its JSON string early and leave the rest of the payload
    // to be reinterpreted by the consumer (audit X-5), so every value that did
    // not originate here is escaped — `client_ip` included, since a value being
    // trustworthy today is not a reason for the payload to depend on it.
    const base = try std.fmt.allocPrint(allocator,
        \\{{"client_ip":"{f}","header_from":"{f}","from_address":"{f}","envelope_from":"{f}","policy":"{s}","disposition":"{s}","dmarc_result":"{s}","spf_result":"{s}","spf_aligned":{s},"dkim_result":"{s}","dkim_domain":"{f}","dkim_aligned":{s}}}
    , .{
        escape.jsonString(ev.client_ip),
        escape.jsonString(ev.header_from),
        escape.jsonString(ev.from_address),
        escape.jsonString(ev.envelope_from),
        ev.policy,
        ev.disposition,
        ev.dmarc_result,
        ev.spf_result,
        if (ev.spf_aligned) "true" else "false",
        ev.dkim_result,
        escape.jsonString(ev.dkim_domain),
        if (ev.dkim_aligned) "true" else "false",
    });
    if (ev.policy_override.len == 0) return base;
    defer allocator.free(base);
    // Ours and a constant, so no escaping question arises.
    return std.fmt.allocPrint(allocator, "{s},\"policy_override\":\"{s}\"}}", .{
        base[0 .. base.len - 1],
        ev.policy_override,
    });
}

/// Record the DMARC result on the message.
///
/// Both stamping functions here must stay fallible (audit X-9): swallowing a
/// failure would deliver a message carrying no `dmarc=` field while the
/// daemon reported success. This daemon is the end of the chain: its field is
/// what a downstream mailbox provider or a local delivery rule reads to decide
/// disposition. Losing it silently means the message is treated as if DMARC
/// was never evaluated, which for a `p=reject` domain is the difference
/// between a rejection and a delivery.
fn addArHeaderSimple(conn: *connection_mod.Connection, ctx: MsgCtx, result_str: []const u8, reason: []const u8) !void {
    try auth_stamp.stamp(conn, ctx.authserv_id, &.{
        .{
            .method = "dmarc",
            .result = result_str,
            .reason = reason,
            .properties = &.{},
        },
    });
}

fn addArHeaderFull(
    conn: *connection_mod.Connection,
    ctx: MsgCtx,
    result_str: []const u8,
    from_domain: []const u8,
    disposition: []const u8,
) !void {
    const reason = try std.fmt.allocPrint(conn.allocator, "p={s}", .{disposition});
    defer conn.allocator.free(reason);

    try auth_stamp.stamp(conn, ctx.authserv_id, &.{
        .{
            .method = "dmarc",
            .result = result_str,
            .reason = reason,
            .properties = &.{.{
                .ptype = "header",
                .property = "from",
                .value = from_domain,
            }},
        },
    });
}

test "M-7a: the event carries every field an aggregate report row needs" {
    // The consumer does not exist yet, so nothing else would notice a field going
    // missing until the reporter was written and found the data unrecoverable.
    // `client_ip` is the one that cannot be backfilled: it is mandatory on every
    // RFC 7489 §7.2 `<record><row>` and only the milter ever sees it.
    const json = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .header_from = "example.com",
        .from_address = "sender@example.com",
        .envelope_from = "bounce.example.com",
        .policy = "reject",
        .disposition = "quarantine",
        .dmarc_result = "fail",
        .spf_result = "pass",
        .spf_aligned = false,
        .dkim_result = "pass",
        .dkim_domain = "example.com",
        .dkim_aligned = true,
    });
    defer std.testing.allocator.free(json);

    for ([_][]const u8{
        "\"client_ip\":\"203.0.113.42\"",
        // A *domain*, and the fixture says so. RFC 9990 SS3.1.1.10 defines the
        // report element of this name as "the RFC5322.From domain from the
        // message", so a reporter copies this field straight into
        // `<identifiers><header_from>`. Carrying the full mailbox here instead
        // would put a local-part into every report row -- data DMARC does not
        // authenticate and the schema does not describe.
        "\"header_from\":\"example.com\"",
        "\"from_address\":\"sender@example.com\"",
        "\"envelope_from\":\"bounce.example.com\"",
        "\"policy\":\"reject\"",
        "\"disposition\":\"quarantine\"",
        "\"dmarc_result\":\"fail\"",
        "\"spf_aligned\":false",
        "\"dkim_aligned\":true",
    }) |needle| {
        if (mem.indexOf(u8, json, needle) == null) {
            std.debug.print("event payload missing {s}\ngot: {s}\n", .{ needle, json });
            return error.TestFailed;
        }
    }
}

test "gate: only a judged fail under an enforcing listener acts" {
    const P = dmarc.Policy;
    const R = dmarc.Result;
    const E = settings.Enforcement;

    // Verdict gate: pass/none/temperror/permerror never act (RFC 9989 §5.3.6).
    for ([_]R{ .pass, .none, .temperror, .permerror }) |r| {
        try std.testing.expectEqual(GateAction.none, decideGate(r, .reject, .reject, false));
    }
    // p=none never acts, whatever the listener wants.
    try std.testing.expectEqual(GateAction.none, decideGate(R.fail, P.none, E.reject, false));
    // An unenforcing listener stamps, never acts.
    try std.testing.expectEqual(GateAction.none, decideGate(R.fail, P.reject, E.none, false));
    // quarantine enforcement tags both quarantine and reject policies.
    try std.testing.expectEqual(GateAction.tag, decideGate(R.fail, P.quarantine, E.quarantine, false));
    try std.testing.expectEqual(GateAction.tag, decideGate(R.fail, P.reject, E.quarantine, false));
    // reject enforcement: quarantine policy tags, reject policy rejects.
    try std.testing.expectEqual(GateAction.tag, decideGate(R.fail, P.quarantine, E.reject, false));
    try std.testing.expectEqual(GateAction.reject, decideGate(R.fail, P.reject, E.reject, false));
    // The trusted-sealer override downgrades exactly one level.
    try std.testing.expectEqual(GateAction.tag, decideGate(R.fail, P.reject, E.reject, true));
    // and changes nothing where reject was not the action.
    try std.testing.expectEqual(GateAction.none, decideGate(R.fail, P.none, E.reject, true));
    try std.testing.expectEqual(GateAction.tag, decideGate(R.fail, P.quarantine, E.reject, true));
}

test "event records a policy_override only when one fired" {
    const json_plain = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .header_from = "example.com",
        .from_address = "sender@example.com",
        .envelope_from = "bounce.example.com",
        .policy = "reject",
        .disposition = "reject",
        .dmarc_result = "fail",
        .spf_result = "fail",
        .spf_aligned = false,
        .dkim_result = "fail",
        .dkim_domain = "",
        .dkim_aligned = false,
    });
    defer std.testing.allocator.free(json_plain);
    try std.testing.expect(mem.indexOf(u8, json_plain, "policy_override") == null);

    const json_overridden = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .header_from = "example.com",
        .from_address = "sender@example.com",
        .envelope_from = "bounce.example.com",
        .policy = "reject",
        .disposition = "reject",
        .dmarc_result = "fail",
        .spf_result = "fail",
        .spf_aligned = false,
        .dkim_result = "fail",
        .dkim_domain = "",
        .dkim_aligned = false,
        .policy_override = "trusted_forwarder",
    });
    defer std.testing.allocator.free(json_overridden);
    try std.testing.expect(mem.indexOf(u8, json_overridden, "\"policy_override\":\"trusted_forwarder\"") != null);

    // The extended payload must still parse as JSON.
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json_overridden, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "trusted_forwarder",
        parsed.value.object.get("policy_override").?.string,
    );
}

test "M-7a: the published policy and the applied disposition are reported separately" {
    // A domain mid-rollout publishes `p=reject` and gets `quarantine` applied.
    // Reporting only one of the two would make it indistinguishable, in the
    // aggregate report, from a domain that asked for `quarantine` outright -- so
    // the Domain Owner could not tell their own rollout was in effect.
    var record = dmarc.DmarcRecord{ .policy = .reject, .testing = .testing };

    const published = dmarc.publishedPolicy(&record, false);
    const applied = dmarc.effectivePolicySampled(&record, false, .ignore, null);

    try std.testing.expectEqualStrings("reject", published.toString());
    try std.testing.expectEqualStrings("quarantine", applied.toString());

    const json = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .header_from = "example.com",
        .from_address = "sender@example.com",
        .envelope_from = "example.com",
        .policy = published.toString(),
        .disposition = applied.toString(),
        .dmarc_result = "fail",
        .spf_result = "fail",
        .spf_aligned = false,
        .dkim_result = "fail",
        .dkim_domain = "",
        .dkim_aligned = false,
    });
    defer std.testing.allocator.free(json);

    try std.testing.expect(mem.indexOf(u8, json, "\"policy\":\"reject\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"disposition\":\"quarantine\"") != null);
}

test "M-7a: a quote in a sender-chosen field cannot break the payload" {
    // from_address is taken from the message, so it is chosen by whoever sent it.
    // Unescaped, the `"` would close the string and hand the rest of the object to
    // the sender to redefine -- X-5, in a new field.
    const json = try formatEvent(std.testing.allocator, .{
        .client_ip = "203.0.113.42",
        .header_from = "example.com",
        .from_address = "a\",\"policy\":\"none\",\"x\":\"b@example.com",
        .envelope_from = "example.com",
        .policy = "reject",
        .disposition = "reject",
        .dmarc_result = "fail",
        .spf_result = "fail",
        .spf_aligned = false,
        .dkim_result = "fail",
        .dkim_domain = "",
        .dkim_aligned = false,
    });
    defer std.testing.allocator.free(json);

    // The injected `"policy":"none"` must not appear as a structural member.
    try std.testing.expect(mem.indexOf(u8, json, "\"policy\":\"none\"") == null);
    try std.testing.expect(mem.indexOf(u8, json, "\"policy\":\"reject\"") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "reject",
        parsed.value.object.get("policy").?.string,
    );
}
// X-9: both wrappers must stay fallible.
//
// Swallowing a failure would deliver a message with no `dmarc=` field while
// this daemon reported success. This daemon is the end of the chain, so that
// field is the only record of the verdict: losing it silently means the
// message is treated as though DMARC was never evaluated, which for a
// `p=reject` domain is the difference between a rejection and a delivery.
test "the DMARC stamping wrappers cannot swallow failures" {
    comptime {
        for (.{ addArHeaderSimple, addArHeaderFull }) |f| {
            const ret = @typeInfo(@TypeOf(f)).@"fn".return_type.?;
            if (@typeInfo(ret) != .error_union) @compileError(
                "the DMARC stamping wrappers must return an error union. Swallowing a " ++
                    "failure delivers the message with no dmarc= field while reporting " ++
                    "success, and this daemon is the end of the chain: nothing downstream " ++
                    "can reconstruct the verdict (audit X-9).",
            );
            if (@typeInfo(ret).error_union.payload != void) @compileError(
                "the DMARC stamping wrappers should return !void.",
            );
        }
    }
}

test "get from domain" {
    // This test validates the From: header parsing logic conceptually.
    // Full integration with Connection struct requires the milter framework.
    const from_value = "User Name <user@example.com>";
    // Simulate the parsing logic
    if (mem.lastIndexOfScalar(u8, from_value, '>')) |gt| {
        if (mem.lastIndexOfScalar(u8, from_value[0..gt], '<')) |lt| {
            const addr = from_value[lt + 1 .. gt];
            const domain = alignment.getDomainFromEmail(addr);
            try std.testing.expectEqualStrings("example.com", domain.?);
            return;
        }
    }
    return error.TestFailed;
}
