"""
DNS sinkholing via a dnsmasq *servers-file*.

Each blocked domain becomes ``server=/domain/`` (no upstream), which makes
dnsmasq answer NXDOMAIN for the domain AND all its subdomains, for every record
type. Unlike ``address=`` lines, a servers-file is re-read when dnsmasq receives
SIGHUP (verified against dnsmasq 2.91) - the resolver container's entrypoint
sends that signal whenever this file changes.
"""
from __future__ import annotations

import logging
import os
import re
import tempfile
from typing import Iterable

log = logging.getLogger("defender.blocking")

# Strict validation: this text is written into a resolver config file, so a
# newline or '/' in a "domain" would be a config-injection vector.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$"
)


def valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


class BlocklistFile:
    def __init__(self, path: str):
        self.path = path

    def write(self, domains: Iterable[str]) -> bool:
        """Atomically (re)write the whole file. Returns False if it cannot be written."""
        lines = ["# Managed by DNS Defender AI - do not edit by hand."]
        for d in sorted(set(domains)):
            if valid_domain(d):  # defence in depth
                lines.append(f"server=/{d}/")
        try:
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".blocked-", suffix=".tmp")
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            os.chmod(tmp, 0o644)
            os.replace(tmp, self.path)  # atomic on the same filesystem
            return True
        except OSError as exc:
            log.error("Cannot write blocklist %s: %s", self.path, exc)
            return False
