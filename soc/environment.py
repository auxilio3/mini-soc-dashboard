"""The simulated organization: hosts, users, groups, and threat intel.

Everything here is fictional. External IPs come from the RFC 5737
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and the
"malware" hashes are SHA-256 digests of placeholder strings, not real samples.
"""

import hashlib
import ipaddress

INTERNAL_NET = ipaddress.ip_network("10.10.0.0/16")

WORKSTATIONS = {f"WS-{i:02d}": f"10.10.1.{10 + i}" for i in range(1, 21)}
SERVERS = {
    "SRV-DC01": "10.10.0.10",
    "SRV-FILE01": "10.10.0.20",
    "SRV-WEB01": "10.10.0.30",
    "SRV-DB01": "10.10.0.40",
    "SRV-VULNSCAN": "10.10.0.50",   # authorized vulnerability scanner
    "ADM-JUMP01": "10.10.0.60",     # IT admin jump box
}
HOSTS = {**WORKSTATIONS, **SERVERS}

USERS = [
    "agarcia", "bnguyen", "cperez", "dsmith", "erodriguez", "fjohnson",
    "gmartinez", "hlee", "ijones", "jhernandez", "kbrown", "lwilliams",
    "mdavis", "nlopez", "omiller", "pgonzalez", "qwilson", "rmoore",
    "staylor", "tanderson",
]
ADMINS = ["it-admin1", "it-admin2"]
DISABLED_ACCOUNTS = ["former.employee1", "former.employee2", "svc-legacy"]

PRIVILEGED_GROUPS = {"Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"}
NORMAL_GROUPS = ["Marketing", "Finance", "HR", "Engineering", "Legal", "VPN Users"]

# Fake IOC list: SHA-256 of placeholder strings, so nothing here is a real sample.
KNOWN_BAD_HASHES = {
    hashlib.sha256(f"mini-soc-fake-malware-{i}".encode()).hexdigest() for i in range(1, 6)
}

BACKUP_PROVIDER_IP = "198.51.100.200"  # offsite backup service (approved)

# ---- Tuning allowlists -----------------------------------------------------
# Added after the first test run flagged known-good activity (see README "Tuning").
RECON_ALLOWED_SOURCES = {"10.10.0.50"}          # SRV-VULNSCAN
LATERAL_ALLOWED_SOURCES = {"10.10.0.60"}        # ADM-JUMP01
EXFIL_ALLOWED_DESTINATIONS = {BACKUP_PROVIDER_IP}

EXTERNAL_BENIGN = [f"198.51.100.{i}" for i in range(10, 60)]   # e.g. SaaS / CDN
EXTERNAL_HOSTILE = [f"203.0.113.{i}" for i in range(100, 140)]  # attacker infrastructure

BENIGN_PROCESSES = ["chrome.exe", "outlook.exe", "teams.exe", "excel.exe", "winword.exe", "explorer.exe"]
BENIGN_POWERSHELL = [
    "powershell.exe Get-Process",
    "powershell.exe Get-Service -Name Spooler",
    "powershell.exe Get-ChildItem C:\\Users\\Public",
    "powershell.exe Test-NetConnection SRV-FILE01 -Port 445",
]


def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in INTERNAL_NET
    except ValueError:
        return False
