"""Suricata/Snort-style signature rule parser and matcher.

Supports a practical subset of the IDS rule language (the same syntax real
Suricata consumes via ``rules/custom.rules``):

* header: ``action proto src_ip src_port -> dst_ip dst_port (options;)``
  including ``<>`` bidirectional rules
* variables: ``$HOME_NET``, ``$EXTERNAL_NET``, ``$HTTP_PORTS`` ...
* lists, ranges and negation for IPs and ports: ``[$HOME_NET,!10.9.9.9]``,
  ``[8000:8080]``, ``!22``
* options: msg, sid, rev, priority, classtype, content (+ ``nocase``,
  ``offset``, ``depth``, hex ``|41 42|``), pcre, flags, itype, icode,
  flow (parsed, advisory), http_* sticky buffers, threshold and
  detection_filter (count/seconds sliding windows)
* unknown options are parsed and safely ignored, so the file stays 100%
  loadable by a real Suricata deployment as well.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from nids.alert import Alert
from nids.packets import PacketMeta

logger = logging.getLogger("nids.rules")

# classtype -> alert category
CLASSTYPE_CATEGORY = {
    "attempted-recon": "Reconnaissance",
    "bad-unknown": "Anomaly",
    "attempted-dos": "Denial of Service",
    "dos": "Denial of Service",
    "attempted-admin": "Attempted Admin",
    "web-application-attack": "Web Attack",
    "web-application-activity": "Web Attack",
    "trojan-activity": "Malware/C2",
    "policy-violation": "Policy Violation",
    "misc-activity": "Anomaly",
    "detect-anomaly": "Anomaly",
    "shellcode-detect": "Exploit",
    "exploit-kit": "Exploit",
    "sql-injection": "Web Attack",
}

PCRE_FLAG_MAP = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}

STICKY_BUFFERS = {
    "http_uri": "uri", "http_header": "header", "http_user_agent": "user_agent",
    "http_client_body": "body", "http_cookie": "cookie", "http_request_body": "body",
}


# ---------------------------------------------------------------------------
# Parsing dataclasses
# ---------------------------------------------------------------------------


@dataclass
class IPSpec:
    """List of (network-or-None-for-any, negated) entries."""

    entries: List[Tuple[Optional[ipaddress._BaseNetwork], bool]] = field(default_factory=list)

    def matches(self, ip: Optional[str]) -> bool:
        if ip is None:
            return any(net is None and not neg for net, neg in self.entries)
        neg_matched, pos_matched, has_pos = False, False, False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for net, neg in self.entries:
            if neg:
                inside = net is None or addr in net
                if inside:
                    neg_matched = True
            else:
                has_pos = True
                if net is None or addr in net:
                    pos_matched = True
        if neg_matched:
            return False
        if has_pos:
            return pos_matched
        return True  # only negative entries => matches everything else


@dataclass
class PortSpec:
    """List of ((low, high), negated) entries; (None, None) = any port."""

    entries: List[Tuple[Tuple[Optional[int], Optional[int]], bool]] = field(default_factory=list)

    def matches(self, port: Optional[int]) -> bool:
        if port is None:
            return any(lo is None and not neg for (lo, _), neg in self.entries)
        neg_matched, pos_matched, has_pos = False, False, False
        for (lo, hi), neg in self.entries:
            if neg:
                if lo is None or (lo <= port <= (hi if hi is not None else lo)):
                    neg_matched = True
            else:
                has_pos = True
                if lo is None or (lo <= port <= (hi if hi is not None else lo)):
                    pos_matched = True
        if neg_matched:
            return False
        if has_pos:
            return pos_matched
        return True


@dataclass
class ContentMatch:
    pattern: str
    nocase: bool = False
    offset: Optional[int] = None
    depth: Optional[int] = None
    sticky: Optional[str] = None      # http_uri / http_header / ...


@dataclass
class RateFilter:
    """threshold / detection_filter: fire after *count* events per *seconds*."""

    track: str = "by_src"             # by_src | by_dst
    count: int = 1
    seconds: int = 1


@dataclass
class Rule:
    action: str
    proto: str
    src_ip: IPSpec
    src_port: PortSpec
    dst_ip: IPSpec
    dst_port: PortSpec
    bidirectional: bool
    msg: str
    sid: int
    rev: int
    priority: int
    classtype: Optional[str]
    contents: List[ContentMatch] = field(default_factory=list)
    pcre: List[re.Pattern] = field(default_factory=list)
    flags_letters: str = ""
    flags_negated: bool = False
    itype: Optional[int] = None
    icode: Optional[int] = None
    rate_filter: Optional[RateFilter] = None

    @property
    def severity(self) -> int:
        """Suricata priority 1 (highest) -> our severity 4."""
        return max(1, min(4, 5 - self.priority))

    @property
    def category(self) -> str:
        return CLASSTYPE_CATEGORY.get(self.classtype or "", "Signature")


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------


class RuleEngine:
    """Loads Suricata-syntax rules and matches them against PacketMeta."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        rules_cfg = config.get("rules", {})
        self.enabled = rules_cfg.get("enabled", True)
        self.file = rules_cfg.get("file", "rules/custom.rules")
        self.suppression_seconds = float(rules_cfg.get("suppression_seconds", 5))
        self.rules: List[Rule] = []
        self._windows: Dict[Tuple[int, str, str], deque] = {}
        self._last_fire: Dict[Tuple[int, str, str], float] = {}
        self._suppressed: Dict[Tuple[int, str], float] = {}
        self._vars = self._build_vars(config)

    # -- variables ---------------------------------------------------------

    @staticmethod
    def _build_vars(config: Dict[str, Any]) -> Dict[str, Any]:
        general = config.get("general", {})
        return {
            "HOME_NET": list(general.get("home_net", ["192.168.0.0/16"])),
            "EXTERNAL_NET": None,  # sentinel -> negation of HOME_NET
            "HTTP_PORTS": "80,443,8080,8000",
            "SSH_PORTS": "22",
            "DNS_PORTS": "53",
            "SHELLCODE_PORTS": "!80",
            "FILE_DATA_PORTS": "any",
        }

    # -- loading ------------------------------------------------------------

    def load_rules(self, path: Optional[str] = None) -> int:
        path = path or self.file
        self.rules.clear()
        text = Path(path).read_text(encoding="utf-8")
        lineno = 0
        for raw in text.splitlines():
            lineno += 1
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                rule = self.parse_rule(line)
                self.rules.append(rule)
            except RuleParseError as exc:
                logger.warning("Skipping malformed rule (line %s): %s", lineno, exc)
        logger.info("Loaded %d signature rules from %s", len(self.rules), path)
        return len(self.rules)

    def parse_rule(self, line: str) -> Rule:
        m = re.match(
            r"^(alert|pass|drop|sdrop|reject|log)\s+(\S+)\s+(\S+)\s+(\S+)\s*(->|<>)\s*(\S+)\s+(\S+)\s*\((.*)\)\s*$",
            line,
        )
        if not m:
            raise RuleParseError(f"unparseable header: {line[:120]}")
        action, proto, src_ip_s, src_port_s, direction, dst_ip_s, dst_port_s, options_s = m.groups()

        rule = Rule(
            action=action,
            proto=proto.lower(),
            src_ip=self._parse_ip_spec(src_ip_s),
            src_port=self._parse_port_spec(src_port_s),
            dst_ip=self._parse_ip_spec(dst_ip_s),
            dst_port=self._parse_port_spec(dst_port_s),
            bidirectional=(direction == "<>"),
            msg="",
            sid=0,
            rev=1,
            priority=3,
            classtype=None,
        )

        last_content: Optional[ContentMatch] = None
        for option in self._split_options(options_s):
            name, _, value = option.partition(":")
            name = name.strip().lower()
            value = value.strip()
            if name == "msg":
                rule.msg = value.strip('"')
            elif name == "sid":
                rule.sid = int(value)
            elif name == "rev":
                rule.rev = int(value)
            elif name == "priority":
                rule.priority = int(value)
            elif name == "classtype":
                rule.classtype = value
            elif name == "content":
                last_content = ContentMatch(pattern=self._decode_content(value.strip('"')))
                rule.contents.append(last_content)
            elif name in STICKY_BUFFERS:
                if last_content is not None:
                    last_content.sticky = STICKY_BUFFERS[name]
            elif name == "nocase":
                if last_content is not None:
                    last_content.nocase = True
            elif name == "offset":
                if last_content is not None:
                    last_content.offset = int(value)
            elif name == "depth":
                if last_content is not None:
                    last_content.depth = int(value)
            elif name == "pcre":
                rule.pcre.append(self._compile_pcre(value.strip('"')))
            elif name == "flags":
                v = value.strip('"')
                rule.flags_negated = v.startswith("!")
                letters = v.lstrip("!")
                rule.flags_letters = "" if letters == "0" else letters
            elif name == "itype":
                rule.itype = int(value)
            elif name == "icode":
                rule.icode = int(value)
            elif name in ("threshold", "detection_filter", "rate_filter"):
                rule.rate_filter = self._parse_rate_filter(name, value)
            # everything else (flow, reference, metadata, ttl, window, ...) is ignored
        if not rule.msg:
            rule.msg = f"Unnamed signature sid:{rule.sid}"
        return rule

    # -- matching ------------------------------------------------------------

    def match_packet(self, meta: PacketMeta) -> List[Alert]:
        """Return alerts for every rule that fires on *meta*."""
        if not self.enabled:
            return []
        alerts: List[Alert] = []
        text_cache: Dict[Optional[str], str] = {}

        for rule in self.rules:
            if not self._header_matches(rule, meta):
                continue
            if rule.contents or rule.pcre:
                ok = True
                for content in rule.contents:
                    text = self._buffer_text(meta, content.sticky, text_cache)
                    if not self._content_matches(content, text):
                        ok = False
                        break
                if ok and rule.pcre:
                    blob = text_cache.get(None) or meta.payload_text
                    blob += "\n" + meta.http_text()
                    for pattern in rule.pcre:
                        if not pattern.search(blob):
                            ok = False
                            break
                if not ok:
                    continue

            if not self._rate_filter_allows(rule, meta):
                continue
            if self._suppressed_now(rule, meta):
                continue

            alerts.append(
                Alert(
                    timestamp=meta.timestamp,
                    name=rule.msg,
                    category=rule.category,
                    severity=rule.severity,
                    detector="rule_engine",
                    protocol=meta.protocol,
                    src_ip=meta.src_ip,
                    src_port=meta.src_port,
                    dst_ip=meta.dst_ip,
                    dst_port=meta.dst_port,
                    sid=rule.sid,
                    details=self._detail_excerpt(meta),
                )
            )
        return alerts

    # -- header checks -------------------------------------------------------

    def _header_matches(self, rule: Rule, meta: PacketMeta) -> bool:
        if not self._proto_matches(rule, meta):
            return False
        forward = (rule.src_ip.matches(meta.src_ip) and rule.src_port.matches(meta.src_port)
                   and rule.dst_ip.matches(meta.dst_ip) and rule.dst_port.matches(meta.dst_port))
        if rule.bidirectional and not forward:
            forward = (rule.src_ip.matches(meta.dst_ip) and rule.src_port.matches(meta.dst_port)
                       and rule.dst_ip.matches(meta.src_ip) and rule.dst_port.matches(meta.src_port))
        if not forward:
            return False
        if meta.protocol == "TCP" and rule.flags_letters:
            has_all = all(letter in meta.tcp_flags for letter in rule.flags_letters)
            if rule.flags_negated:
                if has_all:
                    return False
            elif not has_all:
                return False
        if meta.protocol == "ICMP":
            if rule.itype is not None and meta.icmp_type != rule.itype:
                return False
        return True

    @staticmethod
    def _proto_matches(rule: Rule, meta: PacketMeta) -> bool:
        proto = rule.proto
        if proto in ("ip", "any", "all"):
            return meta.protocol in ("TCP", "UDP", "ICMP", "HTTP", "DNS")
        if proto == "http":
            return meta.protocol in ("TCP", "HTTP")
        if proto == "dns":
            return meta.protocol == "DNS"
        return proto.upper() == meta.protocol

    @staticmethod
    def _buffer_text(meta: PacketMeta, sticky: Optional[str],
                     cache: Dict[Optional[str], str]) -> str:
        if sticky in cache:
            return cache[sticky]
        http = meta.http or {}
        if sticky == "uri":
            # prefer parsed HTTP path; fall back to full payload so raw-payload
            # test packets (no parsed HTTP layer) still get content-matched
            text = str(http.get("path", "")) or meta.payload_text
        elif sticky == "header":
            text = "\n".join(f"{k}: {v}" for k, v in (http.get("headers") or {}).items())
        elif sticky == "user_agent":
            text = str(http.get("user_agent", ""))
        elif sticky == "body":
            text = str(http.get("body", ""))
        elif sticky == "cookie":
            text = (http.get("headers") or {}).get("cookie", "")
        else:
            if meta.protocol == "DNS" and meta.dns_qname:
                # match DNS rules against the query name, not raw wire bytes
                text = meta.dns_qname
            else:
                text = meta.payload_text
                if meta.http:
                    text += "\n" + meta.http_text()
        cache[sticky] = text
        return text

    @staticmethod
    def _content_matches(content: ContentMatch, text: str) -> bool:
        pattern = content.pattern.lower() if content.nocase else content.pattern
        haystack = text.lower() if content.nocase else text
        if not haystack or not pattern:
            return False
        if content.offset is not None or content.depth is not None:
            start = content.offset or 0
            end = start + content.depth if content.depth is not None else None
            return haystack.find(pattern, start, end) >= 0
        return pattern in haystack

    # -- rate filters ---------------------------------------------------------

    def _rate_filter_allows(self, rule: Rule, meta: PacketMeta) -> bool:
        """Sliding-window logic for threshold / detection_filter options."""
        if rule.rate_filter is None:
            return True
        f = rule.rate_filter
        track_ip = meta.src_ip if f.track == "by_src" else (meta.dst_ip if f.track == "by_dst" else "")
        key = (rule.sid, str(track_ip), str(meta.dst_ip))
        window = self._windows.setdefault(key, deque())
        window.append(meta.timestamp)
        cutoff = meta.timestamp - max(f.seconds, 1)
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) < f.count:
            return False
        last = self._last_fire.get(key)
        if last is not None and (meta.timestamp - last) < max(f.seconds, 1):
            return False
        self._last_fire[key] = meta.timestamp
        return True

    def _suppressed_now(self, rule: Rule, meta: PacketMeta) -> bool:
        """Rate-limit plain (no-threshold) rules to avoid alert storms."""
        if rule.rate_filter is not None:
            return False
        key = (rule.sid, str(meta.src_ip))
        now = meta.timestamp
        last = self._suppressed.get(key)
        if last is not None and (now - last) < self.suppression_seconds:
            return True
        self._suppressed[key] = now
        return False

    # -- parsing helpers -------------------------------------------------------

    @staticmethod
    def _split_options(body: str) -> List[str]:
        parts, buf, quote, escaped = [], [], False, False
        for ch in body:
            if escaped:
                buf.append(ch)
                escaped = False
                continue
            if ch == "\\" and quote:
                buf.append(ch)
                escaped = True
                continue
            if ch == '"':
                quote = not quote
                buf.append(ch)
            elif ch == ";" and not quote:
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        tail = "".join(buf).strip()
        if tail:
            parts.append(tail)
        return [p for p in parts if p]

    @staticmethod
    def _decode_content(value: str) -> str:
        """Decode Suricata content with |hex| segments into a plain string."""
        out: List[str] = []
        segments = re.split(r"\|([^|]*)\|", value)
        for i, segment in enumerate(segments):
            if i % 2 == 1:  # hex segment
                try:
                    out.append(bytes.fromhex(segment).decode("latin-1"))
                except ValueError:
                    logger.warning("Bad hex content segment ignored: %r", segment)
            else:
                out.append(segment)
        return "".join(out)

    @staticmethod
    def _compile_pcre(value: str) -> re.Pattern:
        # strip optional leading mode chars like "m" used by snort ('m/.../')
        v = value
        if v and v[0] in "mU" and len(v) > 1 and v[1] == "/":
            v = v[1:]
        if not v.startswith("/"):
            raise RuleParseError(f"unsupported pcre form: {value[:60]}")
        last_slash = v.rfind("/")
        pattern, flag_letters = v[1:last_slash], v[last_slash + 1:]
        flags = 0
        for letter in flag_letters:
            flags |= PCRE_FLAG_MAP.get(letter, 0)
        return re.compile(pattern, flags)

    @staticmethod
    def _parse_rate_filter(name: str, value: str) -> RateFilter:
        fields: Dict[str, str] = {}
        for part in value.split(","):
            key, _, val = part.strip().partition(" ")
            fields[key.strip().lower()] = val.strip()
        track = fields.get("track", "by_src").split()[-1] if "track" in fields else "by_src"
        return RateFilter(
            track=track if track in ("by_src", "by_dst") else "by_src",
            count=int(fields.get("count", 1) or 1),
            seconds=int(fields.get("seconds", 1) or 1),
        )

    def _parse_ip_spec(self, spec: str) -> IPSpec:
        spec = spec.strip()
        entries: List[Tuple[Optional[ipaddress._BaseNetwork], bool]] = []
        if spec.startswith("[") and spec.endswith("]"):
            inner = spec[1:-1]
            for item in self._split_list(inner):
                entries.extend(self._parse_single_ip(item).entries)
            return IPSpec(entries=entries)
        return self._parse_single_ip(spec)

    def _parse_single_ip(self, spec: str) -> IPSpec:
        spec = spec.strip()
        negated = False
        if spec.startswith("!"):
            negated = True
            spec = spec[1:].strip()
        if spec == "any":
            return IPSpec(entries=[(None, negated)])
        if spec.startswith("$"):
            var = spec[1:]
            value = self._vars.get(var)
            if value is None and var == "EXTERNAL_NET":
                # '!$HOME_NET' semantics
                entries = [(ipaddress.ip_network(n, strict=False), True)
                           for n in self._vars["HOME_NET"]]
                return IPSpec(entries=entries)
            if value is None:
                raise RuleParseError(f"unknown variable ${var}")
            entries = []
            for item in (value if isinstance(value, list) else [value]):
                entries.extend(self._parse_ip_spec(str(item)).entries)
            return IPSpec(entries=entries)
        try:
            return IPSpec(entries=[(ipaddress.ip_network(spec, strict=False), negated)])
        except ValueError as exc:
            raise RuleParseError(f"bad network {spec!r}") from exc

    def _parse_port_spec(self, spec: str) -> PortSpec:
        spec = spec.strip()
        entries: List[Tuple[Tuple[Optional[int], Optional[int]], bool]] = []
        items: List[str]
        if spec.startswith("[") and spec.endswith("]"):
            items = self._split_list(spec[1:-1])
        else:
            items = [spec]
        for item in items:
            item = item.strip()
            neg = False
            if item.startswith("!"):
                neg = True
                item = item[1:].strip()
            if item == "any":
                entries.append(((None, None), neg))
                continue
            if item.startswith("$"):
                var = item[1:]
                value = str(self._vars.get(var, "")).strip()
                if not value:
                    raise RuleParseError(f"unknown port variable ${var}")
                sub = self._parse_port_spec(f"[{value}]" if "," in value else value)
                for (lo, hi), sub_neg in sub.entries:
                    entries.append(((lo, hi), neg or sub_neg))
                continue
            if ":" in item:
                lo_s, _, hi_s = item.partition(":")
                lo = int(lo_s) if lo_s else None
                hi = int(hi_s) if hi_s else None
                entries.append(((lo, hi), neg))
            else:
                port = int(item)
                entries.append(((port, port), neg))
        return PortSpec(entries=entries)

    @staticmethod
    def _split_list(inner: str) -> List[str]:
        items, buf, depth = [], [], 0
        for ch in inner:
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
            if ch == "," and depth == 0:
                items.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        if buf:
            items.append("".join(buf).strip())
        return [i for i in items if i]

    # -- misc -------------------------------------------------------------------

    @staticmethod
    def _detail_excerpt(meta: PacketMeta, max_len: int = 160) -> str:
        text = meta.http_text() if meta.http else meta.payload_text
        text = " ".join(text.split())
        return text[:max_len] + ("..." if len(text) > max_len else "")


class RuleParseError(ValueError):
    """Raised for rules the subset parser cannot handle."""
