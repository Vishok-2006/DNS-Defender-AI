"""Offline / alternative ingestion: Zeek dns.log import and Scapy packet capture."""
from __future__ import annotations

import json
import logging
import threading
from typing import Callable, Dict, List, Optional

log = logging.getLogger("defender.ingest")
MAX_ZEEK_ROWS = 50_000


def parse_zeek_dns_log(text: str, limit: int = MAX_ZEEK_ROWS) -> List[Dict]:
    """Parse a Zeek dns.log (tab-separated with #fields header, or JSON lines)."""
    rows, fields = [], None
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("#"):
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            continue
        try:
            if line.lstrip().startswith("{"):
                rec = json.loads(line)
            elif fields:
                rec = dict(zip(fields, line.split("\t")))
            else:
                continue
        except json.JSONDecodeError:
            continue
        query = rec.get("query")
        if not query or query in ("-", "(empty)"):
            continue
        rcode = rec.get("rcode_name") or "NOERROR"
        rows.append(dict(domain=query, client_ip=rec.get("id.orig_h", "0.0.0.0"),
                         query_type=(rec.get("qtype_name") or "A"),
                         response_code="NOERROR" if rcode == "-" else rcode, source="zeek"))
        if len(rows) >= limit:
            break
    return rows


def packet_to_query(pkt) -> Optional[Dict]:
    """Convert a Scapy DNS *query* packet (UDP/53) into a query dict."""
    from scapy.layers.dns import DNS, DNSQR  # lazy: scapy is optional
    from scapy.layers.inet import IP
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)) or pkt[DNS].qr != 0:
        return None
    qname = pkt[DNSQR].qname
    qname = qname.decode(errors="replace") if isinstance(qname, bytes) else str(qname)
    qtypes = {1: "A", 28: "AAAA", 16: "TXT", 15: "MX", 5: "CNAME", 2: "NS", 12: "PTR", 6: "SOA", 33: "SRV"}
    return dict(domain=qname.rstrip("."), client_ip=pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0",
                query_type=qtypes.get(pkt[DNSQR].qtype, str(pkt[DNSQR].qtype)),
                response_code="NOERROR", source="scapy")


class ScapySniffer(threading.Thread):
    """Needs root / CAP_NET_RAW. Response codes are unknown in this mode (queries only)."""

    def __init__(self, handler: Callable[[Dict], None], iface: Optional[str] = None):
        super().__init__(daemon=True, name="scapy-sniffer")
        self.handler, self.iface = handler, iface
        self._stop_evt = threading.Event()
        self.error: Optional[str] = None

    def run(self) -> None:
        try:
            from scapy.all import sniff
            sniff(filter="udp port 53", iface=self.iface, store=False,
                  prn=lambda p: (lambda q: q and self.handler(q))(packet_to_query(p)),
                  stop_filter=lambda _p: self._stop_evt.is_set())
        except Exception as exc:
            self.error = str(exc)
            log.error("Scapy sniffer stopped: %s", exc)

    def stop(self) -> None:
        self._stop_evt.set()
