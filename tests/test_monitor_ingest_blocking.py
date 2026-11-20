import asyncio

import pytest

from app.blocking import BlocklistFile, valid_domain
from app.ingest import packet_to_query, parse_zeek_dns_log
from app.monitor import DnsmasqLogParser, DnsmasqTailer

# Captured from a real dnsmasq 2.91 instance
REAL_LOG = """\
Nov 14 11:07:09 dnsmasq[1087]: query[A] c.example from 192.168.1.20
Nov 14 11:07:09 dnsmasq[1087]: config c.example is NXDOMAIN
Nov 14 11:07:09 dnsmasq[1087]: query[A] ok.lan from 192.168.1.21
Nov 14 11:07:09 dnsmasq[1087]: config ok.lan is 10.0.0.5
Nov 14 11:07:09 dnsmasq[1087]: query[TXT] data.tunnel.example from 192.168.1.22
Nov 14 11:07:09 dnsmasq[1087]: forwarded data.tunnel.example to 1.1.1.1
Nov 14 11:07:09 dnsmasq[1087]: reply data.tunnel.example is <CNAME>
"""


def parse_all(text, **kw):
    p = DnsmasqLogParser(**kw)
    out = []
    for line in text.splitlines():
        out += p.feed(line, now=0.0)
    return out, p


def test_parser_pairs_queries_with_response_codes():
    out, _ = parse_all(REAL_LOG)
    assert [(q["domain"], q["client_ip"], q["query_type"], q["response_code"]) for q in out] == [
        ("c.example", "192.168.1.20", "A", "NXDOMAIN"),
        ("ok.lan", "192.168.1.21", "A", "NOERROR"),
        ("data.tunnel.example", "192.168.1.22", "TXT", "NOERROR"),
    ]


def test_parser_ignores_noise():
    noise = ("Nov 14 dnsmasq[1]: query[A] health.check.local from 192.168.1.5\n"
             "Nov 14 dnsmasq[1]: config health.check.local is 127.0.0.1\n"
             "Nov 14 dnsmasq[1]: query[PTR] 5.1.168.192.in-addr.arpa from 192.168.1.5\n"
             "Nov 14 dnsmasq[1]: query[A] local.test from 127.0.0.1\n"
             "Nov 14 dnsmasq[1]: reply local.test is 1.2.3.4\n")
    assert parse_all(noise, ignore_localhost=True)[0] == []


def test_parser_flushes_unanswered_queries():
    p = DnsmasqLogParser(pending_timeout=3)
    p.feed("dnsmasq[1]: query[A] slow.example from 10.0.0.2", now=0.0)
    assert p.flush(now=1.0) == []
    out = p.flush(now=4.0)
    assert out and out[0]["domain"] == "slow.example" and out[0]["response_code"] == "SERVFAIL"


def test_tailer_follows_file_and_handles_partial_lines(tmp_path):
    log = tmp_path / "q.log"
    log.write_text("old history line that must not be replayed\n")
    seen = []

    async def handler(batch):
        seen.extend(batch)

    async def scenario():
        t = DnsmasqTailer(str(log), handler, poll=0.05)
        task = asyncio.create_task(t.run())
        await asyncio.sleep(0.2)
        with open(log, "a") as f:
            f.write("dnsmasq[1]: query[A] evil.example from 10.1.1.1\n")
            f.write("dnsmasq[1]: reply evil.example is NXDO")      # partial line
            f.flush()
            await asyncio.sleep(0.3)
            assert seen == []                                      # not processed until complete
            f.write("MAIN\n")
        await asyncio.sleep(0.4)
        task.cancel()

    asyncio.run(scenario())
    assert len(seen) == 1 and seen[0]["response_code"] == "NXDOMAIN"


def test_tailer_survives_log_rotation(tmp_path):
    log = tmp_path / "q.log"
    log.write_text("")
    seen = []

    async def handler(batch):
        seen.extend(batch)

    async def scenario():
        t = DnsmasqTailer(str(log), handler, poll=0.05)
        task = asyncio.create_task(t.run())
        await asyncio.sleep(0.2)
        log.rename(tmp_path / "q.log.1")
        log.write_text("dnsmasq[1]: query[A] after.rotate from 10.1.1.1\ndnsmasq[1]: reply after.rotate is 1.2.3.4\n")
        await asyncio.sleep(0.6)
        task.cancel()

    asyncio.run(scenario())
    assert [q["domain"] for q in seen] == ["after.rotate"]


# ------------------------------------------------------------------- blocking
@pytest.mark.parametrize("bad", ["evil.com\naddress=/x/1.1.1.1", "a/b.com", "evil.com/", "-x.com", "", "nodot",
                                 "a" * 64 + ".com", "evil .com", "evil.com;rm"])
def test_blocklist_rejects_config_injection(bad):
    assert not valid_domain(bad)


def test_blocklist_file_is_atomic_and_filtered(tmp_path):
    path = tmp_path / "sub" / "blocked.conf"
    bl = BlocklistFile(str(path))
    assert bl.write({"evil.com", "bad.example", "injected.com\nserver=/x/1.1.1.1"})
    text = path.read_text()
    assert "server=/evil.com/" in text and "server=/bad.example/" in text and "injected" not in text
    assert not [p for p in path.parent.iterdir() if p.name.endswith(".tmp")]


def test_blocklist_write_failure_is_reported(tmp_path):
    f = tmp_path / "file"
    f.write_text("x")
    assert BlocklistFile(str(f / "nested" / "b.conf")).write({"a.com"}) is False


# --------------------------------------------------------------------- ingest
ZEEK_TSV = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tquery\tqtype_name\trcode_name\n"
            "#types\ttime\tstring\taddr\tstring\tstring\tstring\n"
            "1700000000.1\tC1\t192.168.1.7\tevil.biz\tA\tNXDOMAIN\n"
            "1700000001.1\tC2\t192.168.1.8\t-\tA\t-\n"
            "1700000002.1\tC3\t192.168.1.9\tgithub.com\tAAAA\tNOERROR\n")


def test_zeek_tsv_import():
    rows = parse_zeek_dns_log(ZEEK_TSV)
    assert [(r["domain"], r["client_ip"], r["response_code"]) for r in rows] == [
        ("evil.biz", "192.168.1.7", "NXDOMAIN"), ("github.com", "192.168.1.9", "NOERROR")]


def test_zeek_json_import():
    line = '{"ts":1.0,"id.orig_h":"10.0.0.1","query":"a.b.com","qtype_name":"TXT","rcode_name":"NOERROR"}'
    assert parse_zeek_dns_log(line)[0]["query_type"] == "TXT"


def test_scapy_packet_parsing():   # TC-03: capture UDP/53 and parse the FQDN
    scapy = pytest.importorskip("scapy.all")
    pkt = (scapy.IP(src="192.168.1.50", dst="192.168.1.1") / scapy.UDP(dport=53)
           / scapy.DNS(rd=1, qd=scapy.DNSQR(qname="xk910zp2a88q093.biz", qtype="TXT")))
    q = packet_to_query(pkt)
    assert q["domain"] == "xk910zp2a88q093.biz" and q["client_ip"] == "192.168.1.50" and q["query_type"] == "TXT"
    reply = scapy.IP() / scapy.UDP() / scapy.DNS(qr=1, qd=scapy.DNSQR(qname="x.com"))
    assert packet_to_query(reply) is None
