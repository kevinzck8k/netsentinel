#!/usr/bin/env python3
"""
Prepare downloaded public datasets for the Telco AIOps pipeline.

Inputs  (datasets/raw + datasets/extracted)
Outputs:
  datasets/processed/bgp_anomaly_summary.json
  datasets/processed/log_samples.jsonl
  datasets/eval/golden_cases.jsonl
  knowledge/sops/historical_bgp_anomalies.md   (RAG ingest)

Usage:
  python scripts/prepare_datasets.py
"""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTRACTED = ROOT / "datasets" / "extracted"
PROCESSED = ROOT / "datasets" / "processed"
EVAL_DIR = ROOT / "datasets" / "eval"
SOP_DIR = ROOT / "knowledge" / "sops"

BGP_DIR = (
    EXTRACTED
    / "bgp_ripe_csv"
    / "BGP_RIPE_datasets_for_anomaly_detection_csv_revised_19022021"
)

# Feature index (0-based after 4 time columns): announcements=0, withdrawals=1
FEAT_ANNOUNCE = 4
FEAT_WITHDRAW = 5
LABEL_IDX = 41

EVENT_META = {
    "WannaCrypt": {
        "date": "2017-05",
        "type": "ransomware_worm_bgp_churn",
        "summary": (
            "WannaCry ransomware/worm caused large BGP update churn "
            "(announcements/withdrawals spike) visible at RIPE rrc04."
        ),
        "remediation": [
            "Isolate infected Windows hosts (EternalBlue/SMB)",
            "Rate-limit BGP UPDATE storms at edge if control-plane CPU high",
            "Correlate RIPE RIS / peering dashboards for AS-path instability",
        ],
    },
    "Moscow_blackout": {
        "date": "2005-05",
        "type": "power_blackout_ix_disconnect",
        "summary": (
            "Moscow energy ring blackout disconnected MSK-IX; BGP sessions "
            "and traffic exchange failed for hours."
        ),
        "remediation": [
            "Treat as multi-peer facility outage, not single-link fault",
            "Fail over to alternate IX / transit",
            "After power restore, verify BGP Established and prefix baselines",
        ],
    },
    "Slammer": {
        "date": "2003-01",
        "type": "worm_induced_bgp_anomaly",
        "summary": (
            "SQL Slammer worm doubled infections ~every 9s; BGP feature "
            "vectors show anomalous withdrawal/announcement patterns."
        ),
        "remediation": [
            "Patch/filter SQL Server UDP/1434 scanning",
            "Watch for secondary BGP hold-timer expiry under load",
            "Use historical baselines to avoid false-positive peer shutdowns",
        ],
    },
    "Nimda": {
        "date": "2001-09",
        "type": "worm_induced_bgp_anomaly",
        "summary": (
            "Nimda worm exploited IIS; RIPE BGP collectors recorded multi-day "
            "anomalous routing dynamics."
        ),
        "remediation": [
            "Contain web-server malware fan-out",
            "Monitor AS-path length / edit-distance spikes",
            "Document as worm-correlated routing noise in RCA",
        ],
    },
    "Code_Red_I": {
        "date": "2001-07",
        "type": "worm_induced_bgp_anomaly",
        "summary": (
            "Code Red I IIS worm; BGP anomaly labels cover attack day ±2 days."
        ),
        "remediation": [
            "IIS hardening / patching",
            "Separate security incident ticket from pure L3 link RCA",
        ],
    },
}


def summarize_bgp_csvs() -> list[dict]:
    summaries: list[dict] = []
    if not BGP_DIR.exists():
        return summaries

    for csv_path in sorted(BGP_DIR.glob("*.csv")):
        name = csv_path.stem
        with csv_path.open(newline="") as fh:
            rows = list(csv.reader(fh))
        # Files have no header row
        labels = Counter(r[LABEL_IDX] for r in rows if len(r) > LABEL_IDX)
        anom = [r for r in rows if len(r) > LABEL_IDX and r[LABEL_IDX] == "1"]
        ann = [float(r[FEAT_ANNOUNCE]) for r in anom] if anom else [0.0]
        wit = [float(r[FEAT_WITHDRAW]) for r in anom] if anom else [0.0]
        meta = EVENT_META.get(name, {})
        summaries.append(
            {
                "event": name,
                "source": "SFU CNL / RIPE rrc04 feature CSV",
                "rows": len(rows),
                "anomalous_rows": labels.get("1", 0),
                "regular_rows": labels.get("-1", 0),
                "avg_announcements_on_anomaly": round(sum(ann) / len(ann), 2),
                "avg_withdrawals_on_anomaly": round(sum(wit) / len(wit), 2),
                "max_announcements_on_anomaly": max(ann),
                "max_withdrawals_on_anomaly": max(wit),
                **meta,
            }
        )
    return summaries


# Loghub lines carry the real source addresses and reverse-DNS names of the
# hosts that attacked the original honeypot. Republishing them adds nothing to
# the benchmark, so they are pseudonymized before anything is written to disk.
# Private lab ranges are kept: labels and telemetry expectations depend on them.
_PRIVATE_IP_RE = re.compile(
    r"^(?:10\.|127\.|0\.|255\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)
_IP_TOKEN_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Remote hostnames only appear in these positions, so target them instead of
# guessing which dotted token in a log line is a domain.
_REMOTE_HOST_RES = (
    re.compile(r"(?<=rhost=)(?![\d.]+\b)([A-Za-z0-9][\w.-]*\.[A-Za-z]{2,})"),
    re.compile(r"(?<=getaddrinfo for )([A-Za-z0-9][\w.-]*\.[A-Za-z]{2,})"),
    re.compile(r"(?<=from )(?![\d.]+\b)([A-Za-z0-9][\w.-]*\.[A-Za-z]{2,})"),
)
# RFC 5737 documentation ranges: guaranteed never to be routed to a real host.
_DOC_RANGES = ("192.0.2", "198.51.100", "203.0.113")

# Login names are only meaningful here as evidence of credential scanning, so
# keep the generic service and vendor-default accounts and pseudonymise
# anything that could name a person. Allowlisting rather than blocklisting
# means an unfamiliar account in future data gets masked by default.
_USER_RES = (
    re.compile(r"(?<=user=)([^\s\"',]+)"),
    re.compile(r"(?<=for invalid user )(\S+)(?= from)"),
    re.compile(r"(?<=for user )(\S+)(?= from)"),
    re.compile(r"(?<=ruser=)([^\s\"',]+)"),
    re.compile(r"(?<=logname=)([^\s\"',]+)"),
)
_GENERIC_USERS = frozenset(
    """
    root admin administrator guest test user users default nobody daemon bin
    sys sync games man lp mail news uucp proxy backup list irc gnats operator
    monitor support webmaster postmaster info sales api service netops noc
    ftp ftpuser anonymous sshd ssh telnet tomcat jenkins git svn
    postgres pgadmin mysql oracle mongodb redis elastic influx
    www www-data apache nginx httpd nagios zabbix
    pi ubnt cisco inspur management plcmspip matlab
    """.split()
)


def _is_generic_user(name: str) -> bool:
    stripped = name.rstrip("0123456789")
    return (
        name.isdigit()
        or name.lower() in _GENERIC_USERS
        or (bool(stripped) and stripped.lower() in _GENERIC_USERS)
    )


def _named_users(texts: list[str]) -> list[str]:
    found = {
        match
        for text in texts
        for pattern in _USER_RES
        for match in pattern.findall(text)
        if match and not _is_generic_user(match)
    }
    return sorted(found)


def _public_ips(texts: list[str]) -> list[str]:
    found = {
        ip
        for text in texts
        for ip in _IP_TOKEN_RE.findall(text)
        if not _PRIVATE_IP_RE.match(ip)
    }
    return sorted(found)


def _remote_hosts(texts: list[str]) -> list[str]:
    found = {
        match
        for text in texts
        for pattern in _REMOTE_HOST_RES
        for match in pattern.findall(text)
    }
    return sorted(found)


def anonymize_log_samples(samples: list[dict]) -> list[dict]:
    """Replace third-party identifiers with stable stand-ins.

    Addresses move into the RFC 5737 documentation ranges, hostnames into
    example.net, and login names that are not generic service accounts become
    user-NNN. Every mapping is one-to-one, so the `rhost + user` fingerprint
    used to de-duplicate golden cases keeps discriminating exactly as before;
    masking the values away would collapse distinct sources into one case.
    """
    texts = [s["raw_message"] for s in samples]

    ip_map: dict[str, str] = {}
    for index, ip in enumerate(_public_ips(texts)):
        block = _DOC_RANGES[index // 254 % len(_DOC_RANGES)]
        ip_map[ip] = f"{block}.{index % 254 + 1}"

    host_map = {
        host: f"host-{index + 1:03d}.example.net"
        for index, host in enumerate(_remote_hosts(texts))
    }
    user_map = {
        name: f"user-{index + 1:03d}"
        for index, name in enumerate(_named_users(texts))
    }

    def rewrite(text: str) -> str:
        for pattern in _REMOTE_HOST_RES:
            text = pattern.sub(lambda m: host_map[m.group(1)], text)
        for pattern in _USER_RES:
            text = pattern.sub(lambda m: user_map.get(m.group(1), m.group(1)), text)
        return _IP_TOKEN_RE.sub(lambda m: ip_map.get(m.group(0), m.group(0)), text)

    return [{**s, "raw_message": rewrite(s["raw_message"])} for s in samples]


def sample_logs(limit_per_file: int = 400) -> list[dict]:
    patterns = re.compile(
        r"fail|error|down|denied|invalid|refused|unreachable|timeout|critical",
        re.I,
    )
    samples: list[dict] = []
    candidates = [
        ("loghub_linux", EXTRACTED / "Linux.log"),
        ("loghub_apache", EXTRACTED / "Apache.log"),
        ("loghub_zookeeper", EXTRACTED / "Zookeeper.log"),
        ("loghub_ssh", EXTRACTED / "ssh" / "SSH.log"),
    ]
    for source, path in candidates:
        if not path.exists():
            continue
        count = 0
        with path.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not patterns.search(line):
                    continue
                samples.append(
                    {
                        "source": source,
                        "raw_message": line.strip()[:500],
                        "license_note": "Loghub (research use) — cite https://github.com/logpai/loghub",
                    }
                )
                count += 1
                if count >= limit_per_file:
                    break
    return anonymize_log_samples(samples)


SYNTHETIC_CASES: list[dict] = [
    {
        "id": "telco-bgp-down-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:00:01 r1 bgpd[42]: %BGP-5-ADJCHANGE: "
            "neighbor 192.168.12.2 Down - Peer closed the session"
        ),
        "expected_event_type": "bgp_session_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["bgp", "session", "peer"],
        "notes": "Primary FRR lab scenario",
    },
    {
        "id": "telco-iface-down-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:01:00 r1 zebra[10]: %LINK-3-UPDOWN: "
            "Interface eth1, changed state to down"
        ),
        "expected_event_type": "interface_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["interface", "eth1", "down"],
        "notes": "Link failure should drive RCA to eth1",
    },
    {
        "id": "telco-bgp-flap-001",
        "category": "synthetic_telco",
        "syslog": (
            "<165>Jul 30 12:02:00 r2 bgpd[42]: BGP neighbor 192.168.12.1 "
            "flapping - multiple resets within 5 minutes"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["r2"],
        "expected_root_cause_keywords": ["bgp", "session", "flap"],
        "notes": "Flap taxonomy",
    },
    {
        "id": "telco-auth-fail-001",
        "category": "synthetic_telco",
        "syslog": (
            "<164>Jul 30 12:03:00 r1 bgpd[42]: BGP auth failure TCP MD5 "
            "digest mismatch with neighbor 192.168.12.2"
        ),
        "expected_event_type": "auth_failure",
        "expected_severity": "warning",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["auth", "failure", "md5"],
        "notes": "Control-plane auth",
    },
    {
        "id": "telco-ospf-down-001",
        "category": "synthetic_telco",
        "syslog": (
            "<165>Jul 30 12:04:00 r1 ospfd[21]: %OSPF-5-ADJCHG: Process 1, "
            "Nbr 10.0.0.2 on eth1 from FULL to DOWN, Neighbor Down"
        ),
        "expected_event_type": "ospf_adjacency_down",
        "expected_severity": "major",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["ospf", "adjacency", "neighbor"],
        "notes": "IGP adjacency loss",
    },
    {
        "id": "telco-high-cpu-001",
        "category": "synthetic_telco",
        "syslog": (
            "<165>Jul 30 12:05:00 r1 watchfrr[8]: high cpu warning: "
            "CPU utilization 97% sustained for 5 minutes"
        ),
        "expected_event_type": "high_cpu",
        "expected_severity": "major",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["cpu", "utilization"],
        "notes": "Control-plane CPU",
    },
    {
        "id": "telco-high-mem-001",
        "category": "synthetic_telco",
        "syslog": (
            "<165>Jul 30 12:06:00 r2 kernel: memory exhausted on bgpd, "
            "OOM killer invoked for pid 42"
        ),
        "expected_event_type": "high_memory",
        "expected_severity": "major",
        "expected_nodes_contains": ["r2"],
        "expected_root_cause_keywords": ["memory"],
        "notes": "Memory pressure",
    },
    {
        "id": "telco-route-withdraw-001",
        "category": "synthetic_telco",
        "syslog": (
            "<164>Jul 30 12:07:00 r1 bgpd[42]: BGP: prefix 10.20.0.0/16 "
            "withdrawn by neighbor 192.168.12.2 (origin AS 65002)"
        ),
        "expected_event_type": "route_withdrawal",
        "expected_severity": "warning",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["prefix", "withdraw"],
        "notes": "RIB withdraw",
    },
    {
        "id": "telco-link-fail-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:08:00 r1 dvl[3]: carrier lost on interface eth1 "
            "- physical link failure"
        ),
        "expected_event_type": "link_failure",
        "expected_severity": "critical",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["link", "failure", "carrier"],
        "notes": "L1 carrier loss",
    },
    {
        "id": "telco-r2-iface-down-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:09:00 r2 zebra[10]: %LINK-3-UPDOWN: "
            "Interface eth1, changed state to down"
        ),
        "expected_event_type": "interface_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["r2"],
        "expected_root_cause_keywords": ["interface", "down"],
        "notes": "Far-end interface",
    },
    {
        "id": "telco-cisco-bgp-down-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:10:11 pe2 BGP: %BGP-5-ADJCHANGE: neighbor "
            "172.16.0.1 Down - Peer closed the session"
        ),
        "expected_event_type": "bgp_session_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["bgp", "session"],
        "notes": "Cisco IOS-style syslog",
    },
    {
        "id": "telco-junos-bgp-idle-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:11:00 pe1 rpd[123]: BGP_NEIGHBOR_STATE_CHANGED: "
            "BGP peer 192.168.12.2 (External AS 65002) changed state from "
            "Established to Idle (HoldTimerExpired)"
        ),
        "expected_event_type": "bgp_session_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["bgp", "idle"],
        "notes": "JunOS-style syslog",
    },
    {
        "id": "telco-bfd-down-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:12:00 r1 bfdd[15]: BFD session down with "
            "neighbor 192.168.12.2 on eth1 (Control Detection Time Expired)"
        ),
        "expected_event_type": "link_failure",
        "expected_severity": "critical",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["bfd", "link"],
        "notes": "BFD maps to link failure",
    },
    {
        "id": "telco-leaf1-iface-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:13:00 leaf-1 zebra[10]: %LINK-3-UPDOWN: "
            "Interface eth0, changed state to down"
        ),
        "expected_event_type": "interface_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["leaf-1"],
        "expected_root_cause_keywords": ["interface", "down"],
        "notes": "DC leaf naming",
    },
    {
        "id": "telco-hold-timer-001",
        "category": "synthetic_telco",
        "syslog": (
            "<166>Jul 30 12:14:00 r1 bgpd[42]: Hold timer expired, "
            "BGP neighbor 192.168.12.2 Down (Notification sent)"
        ),
        "expected_event_type": "bgp_session_down",
        "expected_severity": "critical",
        "expected_nodes_contains": ["r1"],
        "expected_root_cause_keywords": ["bgp", "hold"],
        "notes": "Hold-timer expiry",
    },
    {
        "id": "telco-r2-auth-md5-001",
        "category": "synthetic_telco",
        "syslog": (
            "<164>Jul 30 12:15:00 r2 bgpd[42]: TCP MD5 digest mismatch "
            "authentication failure with neighbor 192.168.12.1"
        ),
        "expected_event_type": "auth_failure",
        "expected_severity": "warning",
        "expected_nodes_contains": ["r2"],
        "expected_root_cause_keywords": ["auth", "md5"],
        "notes": "Far-end MD5 mismatch",
    },
]

PUBLIC_HISTORICAL: list[dict] = [
    {
        "id": "bgp-hist-youtube-hijack-2008",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<164>2008-02 18:47:00 pe1 bgpd: prefix 208.65.153.0/24 withdrawn "
            "then re-announced by AS17557 (Pakistan Telecom YouTube hijack); "
            "looking-glass shows unexpected origin"
        ),
        "expected_event_type": "route_withdrawal",
        "expected_severity": "warning",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["prefix", "withdraw"],
        "source_dataset": "public_bgp_incident",
        "notes": "youtube_hijack_2008",
    },
    {
        "id": "bgp-hist-as9121-leak",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<164>2004-12 09:20:00 pe2 bgpd: prefix withdraw storm and full-table "
            "leak from AS9121 (TTNet); announcements/withdrawals spike at IX"
        ),
        "expected_event_type": "route_withdrawal",
        "expected_severity": "warning",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["prefix", "withdraw"],
        "source_dataset": "public_bgp_incident",
        "notes": "as9121_route_leak",
    },
    {
        "id": "bgp-hist-code_red_ii",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2001-08 00:00:00 pe1 bgpd: BGP anomaly detected correlating "
            "with historical event Code_Red_II: announcements≈400, withdrawals≈12 "
            "(Code Red II IIS worm; routing churn on attack days)"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "worm_induced_bgp_anomaly",
    },
    {
        "id": "bgp-hist-blaster",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2003-08 00:00:00 pe1 bgpd: BGP anomaly detected correlating "
            "with historical event Blaster: announcements≈510, withdrawals≈18 "
            "(Blaster worm; control-plane load and session flap)"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["bgp", "session", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "worm_induced_bgp_anomaly",
    },
    {
        "id": "bgp-hist-malaysia-leak-2015",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2015-06 10:00:00 pe2 bgpd: BGP anomaly / routing churn after "
            "Malaysia Telecom (AS4788) leaked Google prefixes; "
            "announcements≈1800, withdrawals≈90"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "transit_route_leak",
    },
    {
        "id": "bgp-hist-as7007-1997",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<164>1997-04 11:30:00 pe1 bgpd: full-table leak from AS7007 ; "
            "prefix withdraw storm across transit peers"
        ),
        "expected_event_type": "route_withdrawal",
        "expected_severity": "warning",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["prefix", "withdraw"],
        "source_dataset": "public_bgp_incident",
        "notes": "as7007_leak",
    },
    {
        "id": "bgp-hist-china-telecom-2010",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2010-04 15:50:00 pe2 bgpd: BGP anomaly / routing churn after "
            "AS23724 announced ~50k foreign prefixes; announcements≈5000, "
            "withdrawals≈120"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "china_telecom_18min_hijack",
    },
    {
        "id": "bgp-hist-indosat-2014",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2014-04 04:00:00 pe1 bgpd: BGP anomaly detected after AS4761 "
            "(Indosat) leaked a large share of the global table; "
            "announcements≈4200, withdrawals≈210"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "indosat_route_leak",
    },
    {
        "id": "bgp-hist-mainone-2018",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2018-11 21:10:00 pe2 bgpd: BGP anomaly / routing churn after "
            "AS37282 (MainOne) leaked Google prefixes to China Telecom; "
            "announcements≈1500, withdrawals≈70"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "mainone_google_leak",
    },
    {
        "id": "bgp-hist-route53-2018",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<164>2018-04 11:05:00 pe1 bgpd: prefix 205.251.192.0/24 withdrawn "
            "and reoriginated by AS10297 (Route53 DNS hijack)"
        ),
        "expected_event_type": "route_withdrawal",
        "expected_severity": "warning",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["prefix", "withdraw"],
        "source_dataset": "public_bgp_incident",
        "notes": "amazon_route53_hijack",
    },
    {
        "id": "bgp-hist-cloudflare-verizon-2019",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2019-06 10:30:00 pe2 bgpd: BGP anomaly / routing churn after "
            "AS33154 leaked more-specifics via Verizon AS701; "
            "announcements≈2400, withdrawals≈150"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "verizon_dqe_leak",
    },
    {
        "id": "bgp-hist-rostelecom-2020",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2020-04 19:28:00 pe1 bgpd: BGP anomaly detected after AS12389 "
            "(Rostelecom) originated ~8800 foreign prefixes; "
            "announcements≈3100, withdrawals≈95"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "rostelecom_hijack",
    },
    {
        "id": "bgp-hist-facebook-2021",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<164>2021-10 15:40:00 pe2 bgpd: prefix 129.134.0.0/17 withdrawn by "
            "AS32934 after backbone config push; authoritative DNS unreachable"
        ),
        "expected_event_type": "route_withdrawal",
        "expected_severity": "warning",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["prefix", "withdraw"],
        "source_dataset": "public_bgp_incident",
        "notes": "facebook_self_withdrawal_outage",
    },
    {
        "id": "bgp-hist-level3-2017",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2017-11 17:20:00 pe1 bgpd: BGP anomaly / routing churn after "
            "AS3356 route policy misconfiguration; announcements≈2700, "
            "withdrawals≈180"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe1"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "level3_misconfiguration",
    },
    {
        "id": "bgp-hist-google-japan-2017",
        "category": "historical_bgp_anomaly",
        "syslog": (
            "<166>2017-08 12:22:00 pe2 bgpd: BGP anomaly detected after AS15169 "
            "prefixes were leaked into AS2497 in Japan; announcements≈1900, "
            "withdrawals≈110"
        ),
        "expected_event_type": "bgp_flap",
        "expected_severity": "major",
        "expected_nodes_contains": ["pe2"],
        "expected_root_cause_keywords": ["bgp", "anomaly"],
        "source_dataset": "public_bgp_incident",
        "notes": "google_verizon_japan_leak",
    },
]


# ---------------------------------------------------------------------------
# Programmatic case generation
#
# Canonical cases use real vendor syslog wording (FRR / Cisco IOS / JunOS /
# SNMP traps).  Paraphrased cases deliberately drop the vendor keywords the
# regex taxonomy keys on, so a rule-only baseline degrades to `unknown` while
# an LLM triage agent still has enough context.  Keeping both splits is what
# makes the rule vs LLM comparison meaningful instead of self-fulfilling.
# ---------------------------------------------------------------------------

# Severity comes from the platform taxonomy (schema.EVENT_SEVERITY), which the
# Triage prompt also renders, so labels stay consistent by construction.
sys.path.insert(0, str(ROOT))
from schema import EVENT_SEVERITY  # noqa: E402

EVENT_KEYWORDS = {
    "bgp_session_down": ["bgp", "session"],
    "bgp_flap": ["bgp", "session", "flap"],
    "interface_down": ["interface", "down"],
    "link_failure": ["link", "failure"],
    "ospf_adjacency_down": ["ospf", "adjacency", "neighbor"],
    "high_cpu": ["cpu", "utilization"],
    "high_memory": ["memory"],
    "route_withdrawal": ["prefix", "withdraw"],
    "auth_failure": ["auth", "failure"],
}

# Device names the Triage Agent can resolve (r1/r2 lab + PE/leaf/spine fabric).
DEVICES = [
    "r1",
    "r2",
    "pe1",
    "pe2",
    "pe3",
    "pe4",
    "leaf-1",
    "leaf-2",
    "spine-1",
    "spine-2",
]

CANONICAL_TEMPLATES: dict[str, list[tuple[str, str]]] = {
    "bgp_session_down": [
        ("frr", "bgpd[{pid}]: %BGP-5-ADJCHANGE: neighbor {peer_ip} Down - Peer closed the session"),
        ("junos", "rpd[{pid}]: BGP_NEIGHBOR_STATE_CHANGED: BGP peer {peer_ip} (External AS {peer_as}) changed state from Established to Idle (HoldTimerExpired)"),
        ("frr", "bgpd[{pid}]: Hold timer expired, BGP neighbor {peer_ip} Down (Notification sent)"),
        ("cisco", "%BGP-3-NOTIFICATION: sent to neighbor {peer_ip} 6/4 (Administrative Reset)"),
        ("frr", "bgpd[{pid}]: BGP session with {peer_ip} moved to Idle after TCP connection refused on port 179"),
    ],
    "bgp_flap": [
        ("frr", "bgpd[{pid}]: BGP neighbor {peer_ip} flapping - multiple resets within 5 minutes"),
        ("frr", "bgpd[{pid}]: BGP peer {peer_ip} flap detected: 6 transitions in 10 minutes"),
        ("nms", "routing churn detected: prefix count oscillating for peer {peer_ip}"),
        ("nms", "BGP anomaly detected: update burst from neighbor {peer_ip} exceeds baseline"),
    ],
    "interface_down": [
        ("cisco", "%LINK-3-UPDOWN: Interface {iface}, changed state to down"),
        ("cisco", "%LINEPROTO-5-UPDOWN: Line protocol on Interface {iface}, changed state to down"),
        ("frr", "zebra[{pid}]: interface {iface} is down (admin state up, oper state down)"),
        ("snmp", "SNMP trap: ifOperStatus for interface {iface} transitioned to down(2)"),
    ],
    "link_failure": [
        ("frr", "dvl[{pid}]: carrier lost on {iface} - physical link failure"),
        ("frr", "bfdd[{pid}]: BFD session down with neighbor {peer_ip} on {iface} (Control Detection Time Expired)"),
        ("nokia", "link loss detected on {iface}; optics reporting LOS"),
        ("nms", "physical link failure on {iface} after fiber cut in outside plant"),
    ],
    "ospf_adjacency_down": [
        ("cisco", "%OSPF-5-ADJCHG: Process 1, Nbr {peer_ip} on {iface} from FULL to DOWN, Neighbor Down"),
        ("frr", "ospfd[{pid}]: OSPF adjacency with {peer_ip} lost on {iface}"),
        ("frr", "ospfd[{pid}]: OSPF neighbor {peer_ip} lost: dead timer expired on {iface}"),
        ("junos", "rpd[{pid}]: RPD_OSPF_NBRDOWN: OSPF neighbor {peer_ip} ({iface}) state changed from Full to Down"),
    ],
    "high_cpu": [
        ("frr", "watchfrr[{pid}]: high cpu warning: CPU utilization 97% sustained for 5 minutes"),
        ("nms", "CPU utilization 99% on control plane for 3 minutes"),
        ("frr", "watchfrr[{pid}]: high cpu, top process bgpd at 96%"),
        ("cisco", "%SYS-1-CPURISINGTHRESHOLD: CPU utilization 100% for five seconds"),
    ],
    "high_memory": [
        ("linux", "kernel: memory exhausted on bgpd, OOM killer invoked for pid {pid}"),
        ("nms", "memory pressure: free memory below 5%"),
        ("linux", "kernel: Out of memory: OOM killer killed process {pid}"),
        ("frr", "watchfrr[{pid}]: memory low, routing daemon restart risk"),
    ],
    "route_withdrawal": [
        ("frr", "bgpd[{pid}]: BGP: prefix {prefix} withdrawn by neighbor {peer_ip} (origin AS {peer_as})"),
        ("nms", "route withdrawal received for {prefix} from peer {peer_ip}"),
        ("frr", "bgpd[{pid}]: BGP: prefix {prefix} withdrawn, best path removed"),
        ("frr", "zebra[{pid}]: rib: 12 prefixes withdrawn after policy change"),
    ],
    "auth_failure": [
        ("frr", "bgpd[{pid}]: BGP auth failure TCP MD5 digest mismatch with neighbor {peer_ip}"),
        ("frr", "bgpd[{pid}]: TCP MD5 digest mismatch authentication failure with neighbor {peer_ip}"),
        ("linux", "sshd[{pid}]: Failed password for root from {src_ip} port {port} ssh2"),
        ("aaa", "AAA authentication failure for user netops from {src_ip}"),
    ],
}

# Operator-style paraphrases: same faults, none of the vendor keywords.
PARAPHRASED_TEMPLATES: dict[str, list[str]] = {
    "bgp_session_down": [
        "peer {peer_ip} left Established state after hold time expiry; prefixes purged from the table",
        "our upstream at {peer_ip} stopped answering keepalives and the peering is no longer up",
        "ticket: transit peer {peer_ip} is not exchanging routes any more since 12:04",
    ],
    "bgp_flap": [
        "the peering with {peer_ip} bounced four times in the last ten minutes",
        "peer {peer_ip} keeps coming back and dropping again, roughly every two minutes",
        "unstable peering toward {peer_ip}: repeated transitions all morning",
    ],
    "interface_down": [
        "the uplink port {iface} was shut during maintenance and is no longer forwarding",
        "port {iface} shows no traffic counters incrementing and reports oper state 2",
        "operator note: {iface} was disabled and never re-enabled after the change window",
    ],
    "link_failure": [
        "fibre pair between the two huts was cut by contractors this morning",
        "the span toward {peer_ip} lost light; optics show no receive power at all",
        "outside plant reports a damaged cable on the {iface} span",
    ],
    "ospf_adjacency_down": [
        "igp neighbour {peer_ip} dropped out of FULL on the core facing port",
        "the interior gateway protocol session with {peer_ip} is stuck in ExStart",
        "internal routing neighbour {peer_ip} never reached Full after the reload",
    ],
    "high_cpu": [
        "control plane is pegged at 97 percent and CLI responses lag badly",
        "the box is so busy that keepalives are being processed late",
        "processor load has been at the ceiling for five minutes on this node",
    ],
    "high_memory": [
        "the routing process was terminated after resident size grew unbounded",
        "free RAM is nearly gone and daemons are being reaped",
        "node keeps swapping; the route daemon footprint doubled since the upgrade",
    ],
    "route_withdrawal": [
        "our {prefix} vanished from the peer's table and traffic is blackholing",
        "customer reports their block is unreachable; it is missing from the looking glass",
        "the aggregate {prefix} is no longer advertised to the internet",
    ],
    "auth_failure": [
        "peer {peer_ip} refused our session because the shared secret did not match",
        "someone is hammering the management plane with wrong credentials from {src_ip}",
        "login attempts from {src_ip} keep being rejected by the AAA server",
    ],
}


def _case_context(device: str, index: int) -> dict[str, str]:
    """Deterministic per-case substitution values."""
    octet = 2 + (index % 40)
    return {
        "pid": str(10 + (index % 90)),
        "peer_ip": f"192.168.{12 + (index % 6)}.{octet}",
        "peer_as": str(65000 + (index % 12)),
        "iface": ["eth1", "eth0", "Gi0/0/1", "ge-0/0/2", "xe-1/0/0"][index % 5],
        "prefix": f"10.{20 + (index % 30)}.0.0/16",
        "src_ip": f"203.0.113.{octet}",
        "port": str(30000 + (index * 7) % 20000),
        "ts": f"Jul 30 {12 + (index % 10):02d}:{index % 60:02d}:{(index * 3) % 60:02d}",
    }


def generate_synthetic_cases(per_event: int = 18) -> list[dict]:
    """Canonical vendor-wording cases, evenly spread across the taxonomy."""
    cases: list[dict] = []
    for event, templates in CANONICAL_TEMPLATES.items():
        for i in range(per_event):
            vendor, template = templates[i % len(templates)]
            device = DEVICES[(i * 3) % len(DEVICES)]
            ctx = _case_context(device, i)
            body = template.format(**ctx)
            cases.append(
                {
                    "id": f"syn-{event.replace('_', '-')}-{i + 1:03d}",
                    "category": "synthetic_telco",
                    "syslog": f"<166>{ctx['ts']} {device} {body}",
                    "expected_event_type": event,
                    "expected_severity": EVENT_SEVERITY[event],
                    "expected_nodes_contains": [device],
                    "expected_root_cause_keywords": EVENT_KEYWORDS[event],
                    "source_dataset": f"synthetic_{vendor}",
                    "notes": f"{vendor} wording for {event}",
                }
            )
    return cases


def generate_paraphrased_cases() -> list[dict]:
    """Operator-language cases that the regex taxonomy cannot key on."""
    cases: list[dict] = []
    for event, templates in PARAPHRASED_TEMPLATES.items():
        for i, template in enumerate(templates):
            device = DEVICES[(i * 4 + len(cases)) % len(DEVICES)]
            ctx = _case_context(device, i + 7)
            body = template.format(**ctx)
            cases.append(
                {
                    "id": f"hard-{event.replace('_', '-')}-{i + 1:03d}",
                    "category": "paraphrased_hard",
                    "syslog": f"<165>{ctx['ts']} {device} noc-notes: {body}",
                    "expected_event_type": event,
                    "expected_severity": EVENT_SEVERITY[event],
                    "expected_nodes_contains": [device],
                    "expected_root_cause_keywords": EVENT_KEYWORDS[event],
                    "source_dataset": "synthetic_paraphrased",
                    "notes": f"paraphrased {event}; no vendor keywords",
                }
            )
    return cases


def _syslog_body(syslog: str) -> str:
    """Drop PRI/timestamp/device so near-duplicate wording collapses."""
    return re.sub(r"^<\d+>.*?(?=[a-z]+\[|[A-Za-z]+:)", "", syslog).strip().lower()


def _loghub_fingerprint(msg: str) -> str:
    host = re.search(r"rhost=(\S+)", msg)
    user = re.search(r"(?:user[= ])(\S+)", msg)
    src = re.search(r"from (\S+)", msg)
    low = msg.lower()
    if "failed password" in low:
        kind = "failpw"
    elif "invalid user" in low:
        kind = "invaliduser"
    elif "too many authentication failures" in low:
        kind = "toomany"
    elif "more authentication failures" in low:
        kind = "pam"
    else:
        kind = "auth"
    return "|".join(
        [
            kind,
            host.group(1) if host else "",
            user.group(1) if user else "",
            src.group(1) if src else "",
        ]
    )


def build_golden_cases(
    bgp_summaries: list[dict],
    log_samples: list[dict],
    *,
    per_event: int = 18,
    loghub_quota: int = 40,
) -> list[dict]:
    """Eval set: synthetic telco + paraphrased + historical BGP + Loghub."""
    cases: list[dict] = [dict(c) for c in SYNTHETIC_CASES]
    bodies = {_syslog_body(c["syslog"]) for c in cases}
    for generated in generate_synthetic_cases(per_event):
        body = _syslog_body(generated["syslog"])
        if body in bodies:
            continue
        bodies.add(body)
        cases.append(generated)
    cases.extend(generate_paraphrased_cases())

    for s in bgp_summaries:
        if s.get("anomalous_rows", 0) <= 0:
            continue
        cases.append(
            {
                "id": f"bgp-hist-{s['event'].lower()}",
                "category": "historical_bgp_anomaly",
                "syslog": (
                    f"<166>{s.get('date', 'Jan 01')} 00:00:00 pe1 bgpd: "
                    f"BGP anomaly detected correlating with historical event "
                    f"{s['event']}: announcements≈{s['avg_announcements_on_anomaly']}, "
                    f"withdrawals≈{s['avg_withdrawals_on_anomaly']} "
                    f"({s.get('summary', '')[:160]})"
                ),
                "expected_event_type": "bgp_flap",
                "expected_severity": "major",
                "expected_nodes_contains": ["pe1"],
                "expected_root_cause_keywords": ["bgp", "session", "anomaly"],
                "source_dataset": "SFU BGP RIPE anomaly CSV",
                "notes": s.get("type"),
            }
        )

    cases.extend(dict(c) for c in PUBLIC_HISTORICAL)

    seen: set[str] = set()
    for sample in log_samples:
        msg = sample["raw_message"]
        low = msg.lower()
        if not (
            "authentication failure" in low
            or "failed password" in low
            or "invalid user" in low
        ):
            continue
        fp = _loghub_fingerprint(msg)
        if fp in seen:
            continue
        seen.add(fp)
        cases.append(
            {
                "id": f"loghub-auth-{len(seen):02d}",
                "category": "loghub_adapted",
                "syslog": f"<164>adapted r1 {msg}",
                "expected_event_type": "auth_failure",
                "expected_severity": "warning",
                "expected_nodes_contains": ["r1"],
                "expected_root_cause_keywords": ["auth", "failure"],
                "source_dataset": sample["source"],
                "notes": "Adapted from Loghub; unique rhost/user fingerprint",
            }
        )
        if len(seen) >= loghub_quota:
            break

    return cases


def write_historical_sop(bgp_summaries: list[dict]) -> Path:
    lines = [
        "# Historical BGP Anomalies (RIPE / SFU CNL Dataset)",
        "",
        "**Document ID:** SOP-HIST-BGP-100  ",
        "**Source:** SFU Communication Networks Laboratory BGP RIPE feature CSVs  ",
        "**Raw origin:** RIPE RIS route collector rrc04  ",
        f"**Prepared:** {datetime.now(timezone.utc).date().isoformat()}",
        "",
        "This knowledge article summarizes labeled Internet-scale BGP anomalies "
        "for RAG retrieval during RCA. Feature vectors include announcements, "
        "withdrawals, AS-path length, and edit distance.",
        "",
    ]
    for s in bgp_summaries:
        if not s.get("summary"):
            continue
        lines.extend(
            [
                f"## Case: {s['event']} ({s.get('date', 'n/a')})",
                "",
                f"- **Type:** {s.get('type', 'bgp_anomaly')}",
                f"- **Anomalous minutes:** {s.get('anomalous_rows', 0)} / {s.get('rows', 0)}",
                f"- **Avg announcements (anomaly):** {s.get('avg_announcements_on_anomaly')}",
                f"- **Avg withdrawals (anomaly):** {s.get('avg_withdrawals_on_anomaly')}",
                f"- **Summary:** {s.get('summary')}",
                "",
                "### Remediation Steps",
                "",
            ]
        )
        for i, step in enumerate(s.get("remediation") or [], 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append(
            f"**History:** Cite SFU/RIPE dataset event `{s['event']}` when "
            "RCA involves Internet-wide churn rather than single-link failure."
        )
        lines.append("")
    path = SOP_DIR / "historical_bgp_anomalies.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    EVAL_DIR.mkdir(parents=True, exist_ok=True)
    SOP_DIR.mkdir(parents=True, exist_ok=True)

    bgp = summarize_bgp_csvs()
    (PROCESSED / "bgp_anomaly_summary.json").write_text(
        json.dumps(bgp, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    logs = sample_logs()
    write_jsonl(PROCESSED / "log_samples.jsonl", logs)

    cases = build_golden_cases(bgp, logs)
    write_jsonl(EVAL_DIR / "golden_cases.jsonl", cases)

    sop_path = write_historical_sop(bgp)

    # Compact SSH sample for repo friendliness
    ssh_src = EXTRACTED / "ssh" / "SSH.log"
    if ssh_src.exists():
        sample_path = PROCESSED / "ssh_auth_failures_sample.log"
        picked: list[dict] = []
        with ssh_src.open(encoding="utf-8", errors="replace") as src:
            for line in src:
                if re.search(r"fail|invalid|refused", line, re.I):
                    picked.append({"raw_message": line.rstrip("\n")})
                    if len(picked) >= 200:
                        break
        sample_path.write_text(
            "".join(f"{s['raw_message']}\n" for s in anonymize_log_samples(picked)),
            encoding="utf-8",
        )

    print(
        json.dumps(
            {
                "bgp_events": len(bgp),
                "log_samples": len(logs),
                "golden_cases": len(cases),
                "sop": str(sop_path.relative_to(ROOT)),
                "outputs": [
                    "datasets/processed/bgp_anomaly_summary.json",
                    "datasets/processed/log_samples.jsonl",
                    "datasets/eval/golden_cases.jsonl",
                    "knowledge/sops/historical_bgp_anomalies.md",
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
