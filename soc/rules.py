"""The 8 detection use cases from the capstone design, written as Python rules.

Each rule takes the events in one time window (default: last 5 minutes) and
returns a list of alerts. The rules are pure functions with no Elasticsearch
dependency, so they are unit-tested in tests/test_rules.py.

Severity scale (matches the dashboard colors):
    Critical = red, High = orange, Medium = yellow, Low = blue
"""

import os
from collections import defaultdict

from . import environment as env

# Tuning = allowlists + context-aware thresholds. Set SOC_TUNING=0 to see untuned results.
TUNING = os.environ.get("SOC_TUNING", "1") != "0"

SEVERITY_SCORE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# Thresholds, tuned against the simulated environment (see README "Tuning").
BRUTE_FORCE_FAILURES = 10            # failed logons from one external source IP
BRUTE_FORCE_FAILURES_INTERNAL = 25   # tuned: users fumbling their own password on their own PC
LATERAL_DISTINCT_HOSTS = 3           # hosts one internal IP logs on to over SMB/RDP/WinRM
LATERAL_PORTS = {445, 3389, 5985}
EXFIL_BYTES = 50 * 1024 * 1024       # bytes sent to external IPs by one host
RECON_DISTINCT_PORTS = 20            # ports one source probes on one target
DISABLED_ACCOUNT_MEDIUM = 3          # attempts on a disabled account before Low -> Medium
SUSPICIOUS_PS_MARKERS = ["-enc", "-encodedcommand", "iex", "invoke-expression",
                         "downloadstring", "-w hidden", "-windowstyle hidden", "bypass"]


def _get(doc, dotted, default=None):
    node = doc
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


def _alert(rule_id, name, severity, technique, key, evts, description, **entities):
    times = [e["@timestamp"] for e in evts]
    return {
        "rule": {"id": rule_id, "name": name},
        "alert": {
            "severity": severity,
            "severity_score": SEVERITY_SCORE[severity],
            "key": key,
            "event_count": len(evts),
            "first_seen": min(times),
            "last_seen": max(times),
            "status": "open",
        },
        "threat": {"technique": {"id": technique}},
        "message": description,
        # Lab-only ground truth: which simulated scenario(s) produced the matching events.
        # Lets the dashboard show true vs. false positives. A real SIEM wouldn't have this.
        "labels": {"ground_truth": sorted({_get(e, "labels.scenario", "unknown") for e in evts})},
        **{k: v for k, v in entities.items() if v is not None},
    }


def _host_user(evts):
    return {"host": {"name": _get(evts[-1], "host.name")}, "user": {"name": _get(evts[-1], "user.name")}}


# --------------------------------------------------------------------------- rules

def brute_force(events):
    by_src = defaultdict(list)
    for e in events:
        if _get(e, "event.category") == "authentication" and _get(e, "event.outcome") == "failure" \
                and _get(e, "event.reason") != "account_disabled":
            by_src[_get(e, "source.ip")].append(e)
    alerts = []
    for src, evts in by_src.items():
        threshold = BRUTE_FORCE_FAILURES
        if TUNING and env.is_internal(src or ""):
            threshold = BRUTE_FORCE_FAILURES_INTERNAL
        if len(evts) >= threshold:
            users = sorted({_get(x, "user.name") for x in evts})
            alerts.append(_alert("UC1", "Brute Force Authentication Attack", "High", "T1110", src, evts,
                                 f"{len(evts)} failed logons from {src} targeting {', '.join(users)}",
                                 source={"ip": src}, **_host_user(evts)))
    return alerts


def malware_execution(events):
    alerts = []
    for e in events:
        h = _get(e, "file.hash.sha256")
        if _get(e, "event.category") == "process" and h in env.KNOWN_BAD_HASHES:
            host = _get(e, "host.name")
            alerts.append(_alert("UC2", "Malware Execution", "Critical", "T1204.002", f"{host}|{h}", [e],
                                 f"Known-malicious file {_get(e, 'process.name')} executed on {host}",
                                 file={"hash": {"sha256": h}}, process={"name": _get(e, "process.name")},
                                 **_host_user([e])))
    return alerts


def lateral_movement(events):
    by_src = defaultdict(list)
    for e in events:
        src = _get(e, "source.ip")
        if _get(e, "event.category") == "authentication" and _get(e, "event.outcome") == "success" \
                and _get(e, "destination.port") in LATERAL_PORTS and env.is_internal(src or "") \
                and not (TUNING and src in env.LATERAL_ALLOWED_SOURCES):
            by_src[src].append(e)
    alerts = []
    for src, evts in by_src.items():
        hosts = sorted({_get(x, "host.name") for x in evts})
        if len(hosts) >= LATERAL_DISTINCT_HOSTS:
            alerts.append(_alert("UC3", "Lateral Movement", "High", "T1021", src, evts,
                                 f"{src} logged on to {len(hosts)} hosts over SMB/RDP/WinRM: {', '.join(hosts)}",
                                 source={"ip": src}, user={"name": _get(evts[-1], "user.name")}))
    return alerts


def privilege_escalation(events):
    alerts = []
    for e in events:
        group = _get(e, "group.name")
        if _get(e, "event.action") == "added-member-to-group" and group in env.PRIVILEGED_GROUPS:
            target = _get(e, "user.target.name")
            actor = _get(e, "user.name")
            alerts.append(_alert("UC4", "Privilege Escalation", "High", "T1098", f"{target}|{group}", [e],
                                 f"{actor} added {target} to privileged group '{group}'",
                                 group={"name": group}, **_host_user([e])))
    return alerts


def data_exfiltration(events):
    by_host = defaultdict(list)
    for e in events:
        dst = _get(e, "destination.ip", "")
        if _get(e, "event.category") == "network" and not env.is_internal(dst) \
                and env.is_internal(_get(e, "source.ip", "")) \
                and not (TUNING and dst in env.EXFIL_ALLOWED_DESTINATIONS):
            by_host[_get(e, "host.name")].append(e)
    alerts = []
    for host, evts in by_host.items():
        total = sum(_get(x, "network.bytes", 0) for x in evts)
        if total >= EXFIL_BYTES:
            dests = sorted({_get(x, "destination.ip") for x in evts if _get(x, "network.bytes", 0) > 5_000_000})
            alerts.append(_alert("UC5", "Data Exfiltration", "Critical", "T1048", host, evts,
                                 f"{host} sent {total / 1048576:.0f} MB to external hosts {', '.join(dests)}",
                                 host={"name": host}, network={"bytes": total},
                                 destination={"ip": dests[0] if dests else None}))
    return alerts


def unauthorized_access(events):
    by_acct = defaultdict(list)
    for e in events:
        if _get(e, "event.category") == "authentication" and \
                (_get(e, "user.name") in env.DISABLED_ACCOUNTS or _get(e, "event.reason") == "account_disabled"):
            by_acct[_get(e, "user.name")].append(e)
    alerts = []
    for acct, evts in by_acct.items():
        sev = "Medium" if len(evts) >= DISABLED_ACCOUNT_MEDIUM else "Low"
        alerts.append(_alert("UC6", "Unauthorized Access Attempt", sev, "T1078", acct, evts,
                             f"{len(evts)} logon attempt(s) on disabled account '{acct}'",
                             source={"ip": _get(evts[-1], "source.ip")}, **_host_user(evts)))
    return alerts


def suspicious_powershell(events):
    alerts = []
    for e in events:
        name = (_get(e, "process.name") or "").lower()
        cmd = (_get(e, "process.command_line") or "").lower()
        if name in ("powershell.exe", "pwsh.exe"):
            hits = [m for m in SUSPICIOUS_PS_MARKERS if m in cmd]
            if hits:
                host = _get(e, "host.name")
                alerts.append(_alert("UC7", "Suspicious PowerShell Execution", "High", "T1059.001",
                                     f"{host}|{e['@timestamp']}", [e],
                                     f"PowerShell on {host} used suspicious options: {', '.join(hits)}",
                                     process={"name": name, "command_line": _get(e, "process.command_line")},
                                     **_host_user([e])))
    return alerts


def reconnaissance(events):
    by_pair = defaultdict(list)
    for e in events:
        if _get(e, "event.category") == "network" \
                and not (TUNING and _get(e, "source.ip") in env.RECON_ALLOWED_SOURCES):
            by_pair[(_get(e, "source.ip"), _get(e, "destination.ip"))].append(e)
    alerts = []
    for (src, dst), evts in by_pair.items():
        ports = {_get(x, "destination.port") for x in evts}
        if len(ports) >= RECON_DISTINCT_PORTS:
            alerts.append(_alert("UC8", "Reconnaissance Activity", "Medium", "T1046", f"{src}|{dst}", evts,
                                 f"{src} probed {len(ports)} ports on {dst}",
                                 source={"ip": src}, destination={"ip": dst}))
    return alerts


RULES = {
    "brute_force": brute_force,
    "malware_execution": malware_execution,
    "lateral_movement": lateral_movement,
    "privilege_escalation": privilege_escalation,
    "data_exfiltration": data_exfiltration,
    "unauthorized_access": unauthorized_access,
    "suspicious_powershell": suspicious_powershell,
    "reconnaissance": reconnaissance,
}


def run_all(events):
    alerts = []
    for rule in RULES.values():
        alerts.extend(rule(events))
    return alerts
