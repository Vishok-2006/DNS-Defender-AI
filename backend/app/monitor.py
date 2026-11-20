"""
Live DNS ingestion from the dnsmasq query log.

Real log format (dnsmasq 2.9x, verified):
    dnsmasq[12]: query[A] example.com from 192.168.1.20
    dnsmasq[12]: reply example.com is 93.184.216.34          (or config/cached ...)
    dnsmasq[12]: reply nope.example is NXDOMAIN
A query line carries the client; the result line carries the response code, so
the two are paired to give the detector real NXDOMAIN information.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from collections import deque
from typing import Awaitable, Callable, Deque, Dict, List, Optional

log = logging.getLogger("defender.monitor")

QUERY_RE = re.compile(r"query\[(?P<qtype>[A-Za-z0-9]+)\]\s+(?P<domain>\S+)\s+from\s+(?P<client>\S+)")
REPLY_RE = re.compile(r"\b(?:reply|config|cached|cached-stale|auth)\s+(?P<domain>\S+)\s+is\s+(?P<result>.+?)\s*$")
HEALTHCHECK_NAME = "health.check.local"


def _rcode(result: str) -> str:
    r = result.upper()
    for code in ("NXDOMAIN", "SERVFAIL", "REFUSED"):
        if r.startswith(code):
            return code
    return "NOERROR"


class DnsmasqLogParser:
    """Pairs query lines with their result lines."""

    def __init__(self, ignore_localhost: bool = False, pending_timeout: float = 3.0, max_pending: int = 5000):
        self.ignore_localhost = ignore_localhost
        self.pending_timeout = pending_timeout
        self.max_pending = max_pending
        self._pending: Dict[str, Deque[tuple]] = {}
        self._count = 0

    def _skip(self, domain: str, client: str) -> bool:
        if domain.endswith((".arpa", ".arpa.")) or domain.rstrip(".") == HEALTHCHECK_NAME:
            return True
        return self.ignore_localhost and client in ("127.0.0.1", "::1")

    def feed(self, line: str, now: Optional[float] = None) -> List[dict]:
        now = time.time() if now is None else now
        m = QUERY_RE.search(line)
        if m:
            domain = m["domain"].lower().rstrip(".")
            if not self._skip(domain, m["client"]) and self._count < self.max_pending:
                self._pending.setdefault(domain, deque()).append((m["client"], m["qtype"].upper(), now))
                self._count += 1
            return []
        m = REPLY_RE.search(line)
        if not m:
            return []
        domain, code = m["domain"].lower().rstrip("."), _rcode(m["result"])
        if domain == "error":  # "config error is REFUSED": applies to the most recent query
            if code == "NOERROR" or not self._pending:
                return []
            domain = max(self._pending, key=lambda k: self._pending[k][-1][2])
        q = self._pending.get(domain)
        if not q:
            return []
        client, qtype, _ = q.popleft()
        self._count -= 1
        if not q:
            del self._pending[domain]
        return [dict(domain=domain, client_ip=client, query_type=qtype, response_code=code, source="dnsmasq")]

    def flush(self, now: Optional[float] = None) -> List[dict]:
        """Emit queries whose result line never arrived (e.g. upstream timeout)."""
        now = time.time() if now is None else now
        out = []
        for domain in list(self._pending):
            q = self._pending[domain]
            while q and now - q[0][2] >= self.pending_timeout:
                client, qtype, _ = q.popleft()
                self._count -= 1
                out.append(dict(domain=domain, client_ip=client, query_type=qtype,
                                response_code="SERVFAIL", source="dnsmasq"))
            if not q:
                del self._pending[domain]
        return out


class DnsmasqTailer:
    def __init__(self, path: str, handler: Callable[[List[dict]], Awaitable[None]],
                 ignore_localhost: bool = False, poll: float = 0.25):
        self.path, self.handler, self.poll = path, handler, poll
        self.parser = DnsmasqLogParser(ignore_localhost)
        self.running = False
        self.lines_read = 0
        self.queries_processed = 0
        self.last_error: Optional[str] = None

    async def run(self) -> None:
        self.running = True
        fh, inode, buf, first = None, None, "", True
        try:
            while True:
                try:
                    if fh is None:
                        if not os.path.exists(self.path):
                            self.last_error = f"waiting for {self.path}"
                            await asyncio.sleep(1.0)
                            continue
                        fh = open(self.path, "r", errors="replace")
                        inode = os.fstat(fh.fileno()).st_ino
                        if first:        # do not replay history on startup
                            fh.seek(0, os.SEEK_END)
                            first = False
                        self.last_error = None
                        log.info("Tailing %s", self.path)
                    chunk = fh.read()
                    batch: List[dict] = []
                    if chunk:
                        buf += chunk
                        *lines, buf = buf.split("\n")   # keep a trailing partial line
                        for line in lines:
                            self.lines_read += 1
                            batch.extend(self.parser.feed(line))
                    batch.extend(self.parser.flush())
                    if batch:
                        await self.handler(batch)
                        self.queries_processed += len(batch)
                    else:
                        # rotation / truncation: reopen when the inode changes or the file shrinks
                        st = os.stat(self.path)
                        if st.st_ino != inode or st.st_size < fh.tell():
                            fh.close()
                            fh, buf = None, ""
                except FileNotFoundError:
                    if fh:
                        fh.close()
                    fh = None
                except Exception as exc:   # never let ingestion die silently
                    self.last_error = str(exc)
                    log.exception("monitor error")
                    await asyncio.sleep(1.0)
                await asyncio.sleep(self.poll)
        finally:
            self.running = False
            if fh:
                fh.close()
