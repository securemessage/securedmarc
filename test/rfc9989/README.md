# DMARC conformance suite (RFC 9989 Appendix B)

Drives RFC 9989's own worked examples, plus a set of verbatim normative rules,
against `securedmarc-check`.

Current result: **28 / 28.**

```
$ cd ../.. && zig build                # produces zig-out/bin/securedmarc-check
$ python3 runsuite.py

total=28 passed=28 failed=0
```

No dependencies beyond the Python standard library. Flags: `-v` lists every case
and logs DNS queries, `--test NAME` runs one case, `--section B.4` selects by RFC
section, `--port N` moves the loopback DNS port.
`SECUREDMARC_CHECK=/path/to/binary` overrides the checker location.

## Why this suite is hand-built, when the SPF and ARC ones are vendored

There is no official DMARC conformance suite to vendor. `securespf` runs the
openspf.org RFC 7208 suite and `securearc` runs ValiMail's `arc_test_suite`; the
DMARC equivalent does not exist.

Nor is differential testing against another implementation available.
**RFC 9989 was published in May 2026**, and its DNS Tree Walk (§4.10) *replaced*
the Public Suffix List that RFC 7489 depended on. Essentially every other DMARC
implementation still determines the Organizational Domain from the PSL, so
comparing against one would produce disagreement on nearly every case by design,
and the disagreement would carry no information.

That leaves RFC 9989's own text, which is genuinely external — the expectations
in Appendix B were written by the RFC editors, not derived here.

## What it tests

Three kinds of case, and the distinction between them is deliberate.

### Appendix B worked examples — 15 cases

`B.1.1` and `B.1.2` give three identifier-alignment examples each: identical
domains, a parent/child pair, and two unrelated domains. The RFC calls the first
"strict alignment" and the second "relaxed alignment", which fixes the outcome
under *both* modes for each one — identical domains align either way, a
parent/child pair aligns only under relaxed, unrelated domains align under
neither. Each is therefore run twice, once per mode.

`B.4.1`, `B.4.2` and `B.4.3` are the tree-walk examples. Each states the zone
contents, the expected Organizational Domain for the Author Domain and for both
authenticated identifiers, which identifiers end up aligned, and which name
supplies the policy. `B.4.3` is the one with a `psd=y` Public Suffix Domain, and
it is the case where SPF aligns and DKIM does not.

These are the strongest cases in the suite, because the RFC states the outcomes.
They can contradict an implementation.

### Query-sequence cases — 3 cases

§4.10 and B.4.2 do not only say what a tree walk must conclude. **They state the
exact sequence of names it must query**, and the eight-query bound exists for a
stated security reason:

> the potential exists for an ill-intentioned Domain Owner to send mail with
> Author Domains with tens or even hundreds of labels for the purpose of
> executing a denial-of-service attack on the Mail Receiver

So the queries are expected output, not incidental traffic: an implementation
that reaches the right Organizational Domain after four hundred lookups is
wrong, and no outcome assertion can see that. `dmarcdns.DmarcDns` records every
query in arrival order and the suite compares the sequence.

These cases pass only `--from`, so exactly one walk runs. The resolver under test
caches, so a name already looked up by an earlier walk in the same process does
not reach the wire again — correct behaviour, but it would make a sequence
assertion across three walks depend on cache state rather than on the RFC. The
multi-identifier cases therefore assert outcomes only.

`psd_stops_the_walk` is the one sequence case not drawn from a numbered example.
The stop condition is normative in §4.10 steps 2 and 6, and B.4.3 exercises it in
prose only. It is here because **an implementation that ignored the stop would
still reach the right answer in B.4.3** — verified by deleting the stop, which
fails this case and nothing else.

### Normative-rule cases — 10 cases

Rules stated in §4.10, §4.10.1 and §4.7 that Appendix B never illustrates: the
two "discard" rules that decide whether a record is seen at all, `sp=` for
subdomains, the no-usable-`p=` fallbacks, and `t=y`.

**These are weaker evidence than the Appendix B cases, and the file says so.**
They are transcribed from normative text, so they inherit whatever the
transcriber understood it to mean — which is precisely the mistake that produced
ARC finding **A-18**, where a rule taken straight from a MUST NOT was
contradicted by the ValiMail suite's own base messages. Each one quotes the
sentence it rests on in its `source` field so it can be adjudicated against the
document. Where a rule needed interpretation to become a test, it was left out.

## Result: no defects found

The suite passed 28/28 on the first complete run. That is an honest outcome and
worth stating plainly rather than dressing up: unlike the ARC suite, which found
**nine** real defects immediately, this one found **none**.

The likely reason is that `securedmarc`'s tree walk had already been through
findings **M-1** to **M-10**, several of them from reading RFC 9989 closely —
including **M-2** and **M-10**, both of which lived in exactly this logic and one
of which was rejecting mail. The ground had been covered.

So its value here is a regression barrier and the V1 gate, not discovery. The
gate's five properties still hold, and were each checked rather than assumed:

| property | how it was verified |
|---|---|
| External | Expectations authored by the RFC editors in Appendix B |
| Committed | In this repository, not `/tmp` |
| Proven able to fail | 0/28 against `/usr/bin/true`; three deliberate bug reintroductions, below |
| Correct exit status | Non-zero on any failure, so it can gate a build |
| Exercises the real component | Real resolver over UDP; the checker calls the shipped `treewalk`/`dmarc` functions |

### Bug reintroductions

Each confirms a specific assertion has teeth:

- **Delete the eight-label shortcut** in `nextTarget` — fails
  `s4_10_eight_query_bound`, `b4_2_deep_query_sequence` *and* `b4_2_deep`. The
  walk queries every label and exhausts its eight-query budget **without ever
  reaching `example.com`**, so the bound and the correctness of the result turn
  out to be the same assertion.
- **Ignore the `psd=` stop** — fails `psd_stops_the_walk` only, which is why that
  case exists.
- **Make `applicability()` always `.apply`** — fails
  `no_usable_p_and_no_rua_disables_dmarc` and `invalid_sp_treated_like_missing_p`.

## Known gap: `np=`

`np=` is parsed but not applied. Choosing it over `sp=` requires a DNS existence
check on the Author Domain that the daemon does not make, so a domain publishing
`sp=none; np=reject` still gets `sp=` treatment. Documented at `DmarcRecord.np`
and tracked as post-V1; no case here asserts `np=` behaviour, because the suite
should not claim coverage the daemon does not have.

## Provenance

Cases are transcribed from
<https://www.rfc-editor.org/rfc/rfc9989.txt> — *Domain-based Message
Authentication, Reporting, and Conformance (DMARC)*, May 2026, which obsoletes
RFC 7489 and RFC 9091. Section and appendix numbers in `cases.py` refer to it.
