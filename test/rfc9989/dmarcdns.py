"""Minimal authoritative DNS server serving the TXT records one DMARC scenario needs.

Adapted from `securearc/test/arc_valimail/txtdns.py`, with one capability added
that this suite depends on: **every query is logged in arrival order.**

That matters because RFC 9989 does not only state what a tree walk must
conclude — §4.10 and Appendix B.4.2 state the exact sequence of names it must
query, and the eight-query bound exists specifically to stop a deeply nested
Author Domain from being turned into a denial-of-service amplifier. A harness
that only checked the Organizational Domain would pass an implementation that
reached the right answer after four hundred lookups. So the queries themselves
are part of the expected output, not incidental traffic.

TXT only, and NXDOMAIN for anything not held. `securespf/test/rfc7208/` has a
fuller server because RFC 7208 needs A, AAAA, MX, PTR, CNAME and type 99; a
DMARC tree walk is a series of TXT queries for `_dmarc.<name>` and nothing else.
"""

import socket
import struct
import threading

TYPE_TXT = 16
RCODE_NOERROR = 0
RCODE_NXDOMAIN = 3


def _encode_name(name):
    """Encode a dotted name as DNS labels."""
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def _decode_name(data, offset):
    """Decode a DNS name, following compression pointers. Returns (name, next_offset)."""
    labels = []
    jumped = False
    end = offset
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                end = offset
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
        if not jumped:
            end = offset
    return ".".join(labels), end


def _txt_rdata(value):
    """A TXT rdata field: one or more length-prefixed strings, each <= 255 bytes."""
    raw = value.encode("utf-8")
    chunks = [raw[i:i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


class DmarcDns:
    """Serves {name: txt_value} on a UDP port and records every query.

    `records` maps a full name such as "_dmarc.example.com" to one TXT string. A
    name that is absent from the mapping answers NXDOMAIN, which is how a
    scenario expresses "no DMARC Policy Record is published here".

    A value may also be a *list* of strings, which serves several TXT records at
    one name. RFC 9989 §4.10 steps 2 and 6 require that a name answering with
    more than one DMARC record be treated as publishing none, and that rule is
    unreachable unless the server can actually produce the situation.
    """

    def __init__(self, records, port, verbose=False):
        # Keys are lowercased because DNS names are case-insensitive.
        self.records = {}
        for k, v in (records or {}).items():
            self.records[k.lower().rstrip(".")] = v if isinstance(v, list) else [v]
        self.port = port
        self.verbose = verbose
        self.sock = None
        self.thread = None
        self.running = False
        # Every TXT query, in arrival order, including repeats.
        self.queries = []
        self._lock = threading.Lock()

    def __enter__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.port))
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()
        return False

    def query_log(self):
        """Every TXT query in arrival order, repeats included."""
        with self._lock:
            return list(self.queries)

    def distinct_queries(self):
        """Queried names in first-seen order, repeats collapsed.

        The resolver under test caches, so a name already looked up during an
        earlier walk in the same process does not reach the wire again. That is
        correct behaviour and the reason sequence assertions in this suite are
        made against single-walk scenarios; see `runsuite.py`.
        """
        seen = []
        for q in self.query_log():
            if q not in seen:
                seen.append(q)
        return seen

    def _serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._respond(data)
            except Exception:
                continue
            if reply:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def _respond(self, query):
        if len(query) < 12:
            return None
        txn = query[0:2]
        qname, offset = _decode_name(query, 12)
        if offset + 4 > len(query):
            return None
        qtype, _qclass = struct.unpack("!HH", query[offset:offset + 4])
        question = query[12:offset + 4]

        key = qname.lower().rstrip(".")
        values = self.records.get(key)

        if qtype == TYPE_TXT:
            with self._lock:
                self.queries.append(key)

        if self.verbose:
            print(f"    dns: {qname} type={qtype} -> "
                  f"{'hit' if values is not None else 'NXDOMAIN'}")

        # Anything not held is an authoritative "no such name". NOERROR with no
        # answer would say the name exists without a record, which is a
        # different fact.
        if values is None or qtype != TYPE_TXT:
            flags = 0x8400 | RCODE_NXDOMAIN
            return txn + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + question

        answers = b""
        for value in values:
            rdata = _txt_rdata(value)
            answers += (
                _encode_name(qname)
                + struct.pack("!HHIH", TYPE_TXT, 1, 300, len(rdata))
                + rdata
            )
        flags = 0x8400 | RCODE_NOERROR
        return (txn + struct.pack("!HHHHH", flags, 1, len(values), 0, 0)
                + question + answers)
