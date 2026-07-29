"""The RFC 9989 Appendix B worked examples, transcribed as executable cases.

Every scenario here comes from the RFC's own text, and every expectation is a
value the RFC states in prose. `source` quotes the sentence that fixes the
expectation, so a disagreement can be adjudicated against the document instead
of against whoever wrote the harness. Where the RFC leaves something free — the
`p=` value in a record whose purpose is only to exist — the choice is marked.

Why transcription is legitimate here, when the gate demands an *external* oracle:
the expectations are authored by the RFC editors, not derived from reading the
normative sections and deciding what they must mean. The distinction matters
because it is exactly the mistake that produced the ARC A-18 error — a rule
implemented straight from a MUST NOT, which the ValiMail suite then contradicted.
Appendix B states outcomes, so it can contradict the implementation the same way.

It is a *small* oracle, and that is a real limitation rather than a presentational
one. RFC 9989 was published in May 2026 and its DNS tree walk replaced the Public
Suffix List, so essentially no other implementation has one yet; differential
testing against another DMARC library would compare against RFC 7489 behaviour
and disagree by design. These examples are, at present, the only external oracle
that exists for this logic.
"""

# A record whose only job is to exist at a name. The RFC's tree-walk examples say
# which names publish a DMARC Policy Record, not what the records contain.
PLAIN = "v=DMARC1; p=reject"
PLAIN_NONE = "v=DMARC1; p=none"

# Relaxed is the default for both adkim= and aspf= (RFC 9989 4.7), so a record
# without them is the relaxed case. Strict needs saying.
STRICT = "v=DMARC1; p=reject; adkim=s; aspf=s"


# =============================================================================
# B.1 Identifier Alignment Examples
# =============================================================================
#
# B.1.1 and B.1.2 give three cases each: identical domains, a parent/child pair,
# and two unrelated domains. The RFC labels the first "strict alignment" and the
# second "relaxed alignment", which fixes the outcome under BOTH modes for each:
# identical domains align either way, a parent/child pair aligns only under
# relaxed, and unrelated domains align under neither. Each example is therefore
# run twice, once per mode.

_B1_ZONE_RELAXED = {
    "_dmarc.example.com": PLAIN,
}
_B1_ZONE_STRICT = {
    "_dmarc.example.com": STRICT,
}

ALIGNMENT_CASES = [
    # --- B.1.1 SPF -----------------------------------------------------------
    {
        "name": "b1_1_spf_identical_relaxed",
        "section": "B.1.1 Example 1",
        "source": "the RFC5321.MailFrom domain and the Author Domain are "
                  "identical. Thus, the identifiers are in strict alignment.",
        "note": "Strict alignment implies relaxed, so this aligns under both.",
        "zone": _B1_ZONE_RELAXED,
        "args": ["--from", "example.com", "--mailfrom", "example.com", "--spf", "pass"],
        "expect": {"spf_aligned": "yes", "result": "pass"},
    },
    {
        "name": "b1_1_spf_identical_strict",
        "section": "B.1.1 Example 1",
        "source": "the identifiers are in strict alignment.",
        "zone": _B1_ZONE_STRICT,
        "args": ["--from", "example.com", "--mailfrom", "example.com", "--spf", "pass"],
        "expect": {"spf_aligned": "yes", "result": "pass"},
    },
    {
        "name": "b1_1_spf_subdomain_relaxed",
        "section": "B.1.1 Example 2",
        "source": "the Author Domain (example.com) is a parent of the "
                  "RFC5321.MailFrom domain. Thus, the identifiers are in relaxed "
                  "alignment because they both have the same Organizational "
                  "Domain (example.com).",
        "zone": _B1_ZONE_RELAXED,
        "args": ["--from", "example.com", "--mailfrom", "child.example.com", "--spf", "pass"],
        "expect": {"spf_aligned": "yes", "spf_org": "example.com", "result": "pass"},
    },
    {
        "name": "b1_1_spf_subdomain_strict",
        "section": "B.1.1 Example 2",
        "source": "the identifiers are in relaxed alignment",
        "note": "Relaxed only. Under strict, a parent is not the same domain.",
        "zone": _B1_ZONE_STRICT,
        "args": ["--from", "example.com", "--mailfrom", "child.example.com", "--spf", "pass"],
        "expect": {"spf_aligned": "no"},
    },
    {
        "name": "b1_1_spf_unrelated_relaxed",
        "section": "B.1.1 Example 3",
        "source": "the RFC5321.MailFrom domain is neither the same as, a parent "
                  "of, nor a child of the Author Domain. Thus, the identifiers "
                  "are not in alignment.",
        "zone": _B1_ZONE_RELAXED,
        "args": ["--from", "child.example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"spf_aligned": "no", "from_org": "example.com", "spf_org": "example.net"},
    },
    {
        "name": "b1_1_spf_unrelated_strict",
        "section": "B.1.1 Example 3",
        "source": "the identifiers are not in alignment.",
        "zone": _B1_ZONE_STRICT,
        "args": ["--from", "child.example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"spf_aligned": "no"},
    },

    # --- B.1.2 DKIM ----------------------------------------------------------
    {
        "name": "b1_2_dkim_identical_relaxed",
        "section": "B.1.2 Example 1",
        "source": "the DKIM \"d\" tag and the Author Domain have identical DNS "
                  "domains. Thus, the identifiers are in strict alignment.",
        "zone": _B1_ZONE_RELAXED,
        "args": ["--from", "example.com", "--dkim", "example.com", "--dkim-result", "pass"],
        "expect": {"dkim_aligned": "yes", "result": "pass"},
    },
    {
        "name": "b1_2_dkim_identical_strict",
        "section": "B.1.2 Example 1",
        "source": "the identifiers are in strict alignment.",
        "zone": _B1_ZONE_STRICT,
        "args": ["--from", "example.com", "--dkim", "example.com", "--dkim-result", "pass"],
        "expect": {"dkim_aligned": "yes", "result": "pass"},
    },
    {
        "name": "b1_2_dkim_parent_relaxed",
        "section": "B.1.2 Example 2",
        "source": "the DKIM signature's \"d\" tag includes a DNS domain that is "
                  "a parent of the Author Domain. Thus, the identifiers are in "
                  "relaxed alignment, as they have the same Organizational "
                  "Domain (example.com).",
        "zone": _B1_ZONE_RELAXED,
        "args": ["--from", "child.example.com", "--dkim", "example.com", "--dkim-result", "pass"],
        "expect": {"dkim_aligned": "yes", "from_org": "example.com",
                   "dkim_org": "example.com", "result": "pass"},
    },
    {
        "name": "b1_2_dkim_parent_strict",
        "section": "B.1.2 Example 2",
        "source": "the identifiers are in relaxed alignment",
        "note": "Relaxed only.",
        "zone": _B1_ZONE_STRICT,
        "args": ["--from", "child.example.com", "--dkim", "example.com", "--dkim-result", "pass"],
        "expect": {"dkim_aligned": "no"},
    },
    {
        "name": "b1_2_dkim_unrelated_relaxed",
        "section": "B.1.2 Example 3",
        "source": "the DKIM signature's \"d\" tag includes a DNS domain that is "
                  "neither the same as, a parent of, nor a child of the Author "
                  "Domain. Thus, the identifiers are not in alignment.",
        "zone": _B1_ZONE_RELAXED,
        "args": ["--from", "child.example.com", "--dkim", "example.net", "--dkim-result", "pass"],
        "expect": {"dkim_aligned": "no", "from_org": "example.com", "dkim_org": "example.net"},
    },
    {
        "name": "b1_2_dkim_unrelated_strict",
        "section": "B.1.2 Example 3",
        "source": "the identifiers are not in alignment.",
        "zone": _B1_ZONE_STRICT,
        "args": ["--from", "child.example.com", "--dkim", "example.net", "--dkim-result", "pass"],
        "expect": {"dkim_aligned": "no"},
    },
]


# =============================================================================
# B.4 Organizational and Policy Domain Tree Walk Examples
# =============================================================================

_B4_1_ZONE = {
    "_dmarc.example.com": PLAIN,
    "_dmarc.signing.example.com": PLAIN_NONE,
    # "_dmarc.com" is deliberately absent.
}

_B4_3_ZONE = {
    # The PSD declares itself. This is what stops the walk.
    "_dmarc.bank.example": "v=DMARC1; p=reject; psd=y",
    "_dmarc.giant.bank.example": "v=DMARC1; p=quarantine",
    # "_dmarc.example", "_dmarc.mega.bank.example" and
    # "_dmarc.mail.mega.bank.example" are all absent.
}

TREE_WALK_CASES = [
    {
        "name": "b4_1_simple",
        "section": "B.4.1",
        "source": "\"example.com\" is the last element of the DNS tree with a "
                  "DMARC Policy Record, so it is the Organizational Domain ... "
                  "Since this is also the Organizational Domain for the Author "
                  "Domain, DKIM is aligned for relaxed alignment ... since the "
                  "RFC5322.From domain has a DMARC Policy Record, that is the "
                  "policy domain.",
        "zone": _B4_1_ZONE,
        "args": ["--from", "example.com",
                 "--mailfrom", "example.com", "--spf", "pass",
                 "--dkim", "signing.example.com", "--dkim-result", "pass"],
        "expect": {
            "from_org": "example.com",
            "spf_org": "example.com",
            "spf_aligned": "yes",
            "dkim_org": "example.com",
            "dkim_aligned": "yes",
            "policy_domain": "example.com",
            "result": "pass",
        },
    },
    {
        "name": "b4_2_deep",
        "section": "B.4.2",
        "source": "Since \"example.com\" is the last element of the DNS tree "
                  "with a DMARC Policy Record, it is the Organizational Domain "
                  "for \"a.b.c.d.e.f.g.h.i.j.k.example.com\" ... the Author "
                  "Domain does not have a DMARC Policy Record, so the policy "
                  "domain is the highest element in the DNS tree with a DMARC "
                  "Policy Record, example.com.",
        "zone": {
            "_dmarc.example.com": PLAIN,
            "_dmarc.signing.example.com": PLAIN_NONE,
        },
        "args": ["--from", "a.b.c.d.e.f.g.h.i.j.k.example.com",
                 "--mailfrom", "example.com", "--spf", "pass",
                 "--dkim", "signing.example.com", "--dkim-result", "pass"],
        "expect": {
            "from_org": "example.com",
            "spf_org": "example.com",
            "spf_aligned": "yes",
            "dkim_org": "example.com",
            "dkim_aligned": "yes",
            "policy_domain": "example.com",
        },
    },
    {
        "name": "b4_3_psd",
        "section": "B.4.3",
        "source": "The Organizational Domain is \"giant.bank.example\" because "
                  "it is the domain directly below the one with \"psd=y\" ... "
                  "The Organizational Domain is \"mega.bank.example\", so DKIM "
                  "is not aligned. Since SPF is aligned, it can be used to "
                  "determine if the message has a DMARC \"pass\" result.",
        "zone": _B4_3_ZONE,
        "args": ["--from", "giant.bank.example",
                 "--mailfrom", "mail.giant.bank.example", "--spf", "pass",
                 "--dkim", "mail.mega.bank.example", "--dkim-result", "pass"],
        "expect": {
            "from_org": "giant.bank.example",
            "spf_org": "giant.bank.example",
            "spf_aligned": "yes",
            "dkim_org": "mega.bank.example",
            "dkim_aligned": "no",
            "policy_domain": "giant.bank.example",
            "result": "pass",
        },
    },
]


# =============================================================================
# Query-sequence cases
# =============================================================================
#
# These assert the names queried on the wire, in order, which §4.10 and B.4.2
# both state literally. They pass only `--from`, so exactly one tree walk runs
# and the resolver's cache cannot hide a query that a later walk would have
# repeated. The multi-identifier cases above therefore check outcomes only; see
# `dmarcdns.DmarcDns.distinct_queries`.
#
# This is where the eight-query bound is actually tested. The RFC's rationale is
# explicit that the bound exists to stop "an ill-intentioned Domain Owner" from
# using a hundred-label Author Domain "for the purpose of executing a
# denial-of-service attack on the Mail Receiver", so an implementation that
# reaches the right Organizational Domain by walking every label is still wrong.

SEQUENCE_CASES = [
    {
        "name": "s4_10_eight_query_bound",
        "section": "4.10",
        "source": "for a message with the arbitrary Author Domain of "
                  "\"a.b.c.d.e.f.g.h.i.j.mail.example.com\", a full DNS Tree "
                  "Walk would require the following eight queries",
        # Nothing published anywhere: the walk must run to its full extent, which
        # is what makes the query list observable.
        "zone": {},
        "args": ["--from", "a.b.c.d.e.f.g.h.i.j.mail.example.com"],
        "expect_queries": [
            "_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com",
            "_dmarc.g.h.i.j.mail.example.com",
            "_dmarc.h.i.j.mail.example.com",
            "_dmarc.i.j.mail.example.com",
            "_dmarc.j.mail.example.com",
            "_dmarc.mail.example.com",
            "_dmarc.example.com",
            "_dmarc.com",
        ],
        # No record anywhere, so DMARC does not apply (4.10.1: "If the set
        # produced by the DNS Tree Walk contains no DMARC Policy Record ...
        # Mail Receivers MUST NOT apply the DMARC mechanism to the message").
        "expect": {"result": "none"},
    },
    {
        "name": "b4_2_deep_query_sequence",
        "section": "B.4.2",
        "source": "query \"_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com\"; then "
                  "query \"_dmarc.g.h.i.j.k.example.com\" (skipping the "
                  "intermediate names); then query "
                  "\"_dmarc.h.i.j.k.example.com\", \"_dmarc.i.j.k.example.com\", "
                  "\"_dmarc.j.k.example.com\", \"_dmarc.k.example.com\", "
                  "\"_dmarc.example.com\", and \"_dmarc.com\".",
        "zone": {"_dmarc.example.com": PLAIN},
        "args": ["--from", "a.b.c.d.e.f.g.h.i.j.k.example.com"],
        "expect_queries": [
            "_dmarc.a.b.c.d.e.f.g.h.i.j.k.example.com",
            "_dmarc.g.h.i.j.k.example.com",
            "_dmarc.h.i.j.k.example.com",
            "_dmarc.i.j.k.example.com",
            "_dmarc.j.k.example.com",
            "_dmarc.k.example.com",
            "_dmarc.example.com",
            "_dmarc.com",
        ],
        "expect": {"from_org": "example.com", "policy_domain": "example.com"},
    },
    {
        "name": "psd_stops_the_walk",
        "section": "4.10 step 2",
        "source": "If a single record remains and it contains a \"psd=n\" or "
                  "\"psd=y\" tag, stop.",
        "note": "Not a numbered Appendix B example. The stop condition is stated "
                "normatively in steps 2 and 6, and B.4.3 exercises it as prose "
                "('stops because of the \"psd=y\" flag') without isolating the "
                "query list. Included because a walk that ignored the stop would "
                "still reach the right answer in B.4.3 and go undetected.",
        "zone": {
            "_dmarc.bank.example": "v=DMARC1; p=reject; psd=y",
            # Present but must never be reached: the walk stops above.
            "_dmarc.example": PLAIN_NONE,
        },
        "args": ["--from", "mail.giant.bank.example"],
        "expect_queries": [
            "_dmarc.mail.giant.bank.example",
            "_dmarc.giant.bank.example",
            "_dmarc.bank.example",
        ],
        "expect": {"from_org": "giant.bank.example"},
    },
]


# =============================================================================
# Normative rules from 4.10 and 4.10.1 that Appendix B does not illustrate
# =============================================================================
#
# **These are a different kind of case from everything above, and the difference
# matters.** Appendix B states outcomes, so it can contradict an implementation
# that read the normative text wrongly. The cases below are transcribed from the
# normative text itself, which means they inherit whatever the transcriber
# understood it to mean -- the exact failure that produced ARC finding A-18,
# where a rule taken straight from a MUST NOT was contradicted by the ValiMail
# suite's own base messages.
#
# They are included anyway, because these rules are unambiguous, single-sentence
# and quoted verbatim in `source` -- and because Appendix B leaves large parts of
# 4.10 untested, including the two "discard" rules that decide whether a record
# is seen at all. Where a rule needed interpretation to become a test, it was
# left out rather than guessed at.

NORMATIVE_CASES = [
    {
        "name": "multiple_records_all_discarded",
        "section": "4.10 step 2",
        "source": "If multiple DMARC Policy Records are returned for a single "
                  "target, they are all discarded.",
        "note": "All discarded, not 'pick one' and not 'permerror' -- so the name "
                "publishes nothing and, with no record anywhere else, DMARC does "
                "not apply at all.",
        "zone": {"_dmarc.example.com": [PLAIN, PLAIN_NONE]},
        "args": ["--from", "example.com", "--mailfrom", "example.com", "--spf", "pass"],
        "expect": {"result": "none"},
    },
    {
        "name": "non_dmarc_txt_discarded",
        "section": "4.10 step 2",
        "source": "Records that do not start with a \"v\" tag that identifies "
                  "the current version of DMARC are discarded.",
        "zone": {"_dmarc.example.com": "v=spf1 -all"},
        "args": ["--from", "example.com", "--mailfrom", "example.com", "--spf", "pass"],
        "expect": {"result": "none"},
    },
    {
        "name": "wrong_dmarc_version_discarded",
        "section": "4.10 step 2",
        "source": "Records that do not start with a \"v\" tag that identifies "
                  "the current version of DMARC are discarded.",
        "note": "A version tag that is present but not the current one. The "
                "analogous DKIM rule (RFC 6376 3.6.1) spells out that \"DKIM1\" "
                "is not \"DKIM1.0\"; DMARC states the requirement without the "
                "worked example.",
        "zone": {"_dmarc.example.com": "v=DMARC2; p=reject"},
        "args": ["--from", "example.com", "--mailfrom", "example.com", "--spf", "pass"],
        "expect": {"result": "none"},
    },
    {
        "name": "one_dmarc_record_beside_unrelated_txt",
        "section": "4.10 step 2",
        "source": "Records that do not start with a \"v\" tag that identifies "
                  "the current version of DMARC are discarded.",
        "note": "The converse of the two above: discarding the non-DMARC records "
                "must leave the single real one usable, not make the name "
                "ambiguous. A name serving SPF and DMARC together is ordinary.",
        "zone": {"_dmarc.example.com": ["v=spf1 -all", PLAIN]},
        "args": ["--from", "example.com", "--mailfrom", "example.com", "--spf", "pass"],
        "expect": {"result": "pass", "policy_domain": "example.com"},
    },
    {
        "name": "sp_applies_to_subdomain",
        "section": "4.10.1",
        "source": "If the DMARC Policy Record to be applied is that of either the "
                  "Organizational Domain or the PSD and the Author Domain is a "
                  "subdomain of that domain, then the Domain Owner Assessment "
                  "Policy is taken from the \"sp\" tag (if any) if the Author "
                  "Domain exists",
        "zone": {"_dmarc.example.com": "v=DMARC1; p=reject; sp=quarantine"},
        "args": ["--from", "child.example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {
            "policy_domain": "example.com",
            "from_org": "example.com",
            "spf_aligned": "no",
            "result": "fail",
            "disposition": "quarantine",
        },
    },
    {
        "name": "p_used_for_subdomain_when_sp_absent",
        "section": "4.10.1",
        "source": "In the absence of applicable \"sp\" or \"np\" tags, the \"p\" "
                  "tag policy is used for subdomains.",
        "zone": {"_dmarc.example.com": PLAIN},
        "args": ["--from", "child.example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"result": "fail", "disposition": "reject"},
    },
    {
        "name": "no_usable_p_with_valid_rua_acts_as_none",
        "section": "4.10.1",
        "source": "If a \"rua\" tag is present and contains at least one "
                  "syntactically valid reporting URI, the Mail Receiver MUST act "
                  "as if a record containing \"p=none\" was retrieved and "
                  "continue processing.",
        "note": "\"Continue processing\" is the load-bearing half: the message is "
                "still evaluated and still fails, it is simply not acted on.",
        "zone": {"_dmarc.example.com": "v=DMARC1; rua=mailto:dmarc@example.com"},
        "args": ["--from", "example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"result": "fail", "disposition": "none"},
    },
    {
        "name": "no_usable_p_and_no_rua_disables_dmarc",
        "section": "4.10.1",
        "source": "Otherwise, the Mail Receiver applies no DMARC processing to "
                  "this message.",
        "zone": {"_dmarc.example.com": "v=DMARC1; adkim=s"},
        "args": ["--from", "example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"result": "none"},
    },
    {
        "name": "invalid_sp_treated_like_missing_p",
        "section": "4.10.1",
        "source": "If a retrieved DMARC Policy Record does not contain a valid "
                  "\"p\" tag, or contains an \"sp\" or \"np\" tag that is not "
                  "valid, then: ... If a \"rua\" tag is present ... act as if a "
                  "record containing \"p=none\" was retrieved",
        "note": "p= is valid here; the sp= is not. The clause makes an invalid "
                "sp= disqualify the whole record, which is easy to miss because "
                "the obvious reading is to fall back to p=.",
        "zone": {"_dmarc.example.com":
                 "v=DMARC1; p=reject; sp=bogus; rua=mailto:dmarc@example.com"},
        "args": ["--from", "example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"result": "fail", "disposition": "none"},
    },
    {
        "name": "test_mode_downgrades_one_level",
        "section": "4.7",
        "source": "t=y ... the Domain Owner is testing ... and expects one level "
                  "below the declared policy to be applied to failing messages",
        "note": "Not 'treat as none'. reject becomes quarantine. The result stays "
                "fail because t= affects disposition, not the evaluation.",
        "zone": {"_dmarc.example.com": "v=DMARC1; p=reject; t=y"},
        "args": ["--from", "example.com", "--mailfrom", "example.net", "--spf", "pass"],
        "expect": {"result": "fail", "disposition": "quarantine"},
    },
]


ALL_CASES = ALIGNMENT_CASES + TREE_WALK_CASES + SEQUENCE_CASES + NORMATIVE_CASES
