import re

from collections import (
    defaultdict,
    Counter
)

from rules import (
    SQL_PATTERNS,
    XSS_PATTERNS,
    SUSPICIOUS_AGENTS,
    MITRE_MAPPING
)

# Extract IPv4 addresses
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"


def extract_ip(log_line):
    """
    Extract first IP address from a log line.
    """

    match = re.search(
        IP_REGEX,
        log_line
    )

    if match:
        return match.group()

    return "-"


def create_alert(
    attack_type,
    severity,
    ip,
    log
):
    """
    Standardized alert structure.
    """

    return {
        "type": attack_type,
        "severity": severity,
        "ip": ip,
        "mitre": MITRE_MAPPING.get(
            attack_type,
            "Unknown"
        ),
        "log": log.strip()
    }


def detect_web_attacks(logs):
    """
    Detect:
    SQLi
    XSS
    Suspicious User Agents
    """

    alerts = []

    for line in logs:

        lower_line = line.lower()

        ip = extract_ip(line)

        # SQL Injection

        for pattern in SQL_PATTERNS:

            if pattern in lower_line:

                alerts.append(
                    create_alert(
                        "SQL Injection",
                        "HIGH",
                        ip,
                        line
                    )
                )

        # XSS

        for pattern in XSS_PATTERNS:

            if pattern in lower_line:

                alerts.append(
                    create_alert(
                        "XSS",
                        "HIGH",
                        ip,
                        line
                    )
                )

        # Suspicious Tools

        for tool in SUSPICIOUS_AGENTS:

            if tool in lower_line:

                alerts.append(
                    create_alert(
                        "Suspicious Tool",
                        "LOW",
                        ip,
                        line
                    )
                )

    return alerts


def detect_bruteforce(logs):

    alerts = []

    failed_attempts = {}

    for line in logs:

        if "failed password" in line.lower():

            ip = extract_ip(line)

            timestamp = " ".join(
                line.split()[:3]
            )

            if ip not in failed_attempts:

                failed_attempts[ip] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            failed_attempts[ip]["count"] += 1
            failed_attempts[ip]["last"] = timestamp

    for ip, data in failed_attempts.items():

        if data["count"] >= 5:

            alerts.append(
                create_alert(
                    "Brute Force",
                    "MEDIUM",
                    ip,
                    (
                        f"Attempts: {data['count']} | "
                        f"First Seen: {data['first']} | "
                        f"Last Seen: {data['last']}"
                    )
                )
            )

    return alerts


def detect_invalid_users(logs):

    alerts = []

    invalid_users = {}

    for line in logs:

        if "invalid user" in line.lower():

            ip = extract_ip(line)

            timestamp = " ".join(
                line.split()[:3]
            )

            if ip not in invalid_users:

                invalid_users[ip] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            invalid_users[ip]["count"] += 1
            invalid_users[ip]["last"] = timestamp

    for ip, data in invalid_users.items():

        alerts.append(
            create_alert(
                "Invalid User Enumeration",
                "MEDIUM",
                ip,
                (
                    f"Attempts: {data['count']} | "
                    f"First Seen: {data['first']} | "
                    f"Last Seen: {data['last']}"
                )
            )
        )

    return alerts


def detect_root_attacks(logs):

    alerts = []

    root_attempts = {}

    for line in logs:

        if "failed password for root" in line.lower():

            ip = extract_ip(line)

            timestamp = " ".join(
                line.split()[:3]
            )

            if ip not in root_attempts:

                root_attempts[ip] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            root_attempts[ip]["count"] += 1
            root_attempts[ip]["last"] = timestamp

    for ip, data in root_attempts.items():

        alerts.append(
            create_alert(
                "Root Login Attack",
                "HIGH",
                ip,
                (
                    f"Attempts: {data['count']} | "
                    f"First Seen: {data['first']} | "
                    f"Last Seen: {data['last']}"
                )
            )
        )

    return alerts

   


def detect_sudo_activity(logs):
    """
    Detect privileged command execution.
    Aggregate by username.
    """

    alerts = []

    users = {}

    for line in logs:

        if "sudo:" in line.lower():

            try:

                user = line.split("sudo:")[1].split(":")[0].strip()

            except:

                user = "Unknown"

            timestamp = " ".join(
                line.split()[:3]
            )

            if user not in users:

                users[user] = {
                    "count": 0,
                    "first": timestamp,
                    "last": timestamp
                }

            users[user]["count"] += 1
            users[user]["last"] = timestamp

    for user, data in users.items():

        alerts.append(
            create_alert(
                "Privileged Command Execution",
                "LOW",
                user,
                (
                    f"User: {user} | "
                    f"Commands: {data['count']} | "
                    f"First Seen: {data['first']} | "
                    f"Last Seen: {data['last']}"
                )
            )
        )

    return alerts

def detect_nmap(logs):

    alerts = []

    patterns = [
        "nmap",
        "Nmap scan report",
        "User-Agent: Nmap"
    ]

    for line in logs:

        if any(p.lower() in line.lower() for p in patterns):

            ip = extract_ip(line)

            alerts.append({

                "severity": "MEDIUM",
                "type": "Nmap Scan",
                "ip": ip,
                "mitre": "T1595",
                "log": line.strip()

            })

    return alerts

def detect_hydra(logs):

    alerts = []

    patterns = [
        "hydra",
        "THC-Hydra"
    ]

    for line in logs:

        if any(p.lower() in line.lower() for p in patterns):

            ip = extract_ip(line)

            alerts.append({

                "severity": "HIGH",
                "type": "Hydra Brute Force",
                "ip": ip,
                "mitre": "T1110",
                "log": line.strip()

            })

    return alerts

def detect_reverse_shell(logs):

    alerts = []

    patterns = [

        "bash -i",
        "nc -e",
        "netcat -e",
        "python -c",
        "/dev/tcp/",
        "socket.connect("

    ]

    for line in logs:

        if any(p.lower() in line.lower() for p in patterns):

            ip = extract_ip(line)

            alerts.append({

                "severity": "HIGH",
                "type": "Reverse Shell",
                "ip": ip,
                "mitre": "T1059",
                "log": line.strip()

            })

    return alerts

def detect_directory_traversal(logs):

    alerts = []

    patterns = [

        "../",
        "..\\",
        "/etc/passwd",
        "/etc/shadow",
        "win.ini"

    ]

    for line in logs:

        if any(
            p.lower() in line.lower()
            for p in patterns
        ):

            ip = extract_ip(line)

            alerts.append(
                create_alert(
                    "Directory Traversal",
                    "HIGH",
                    ip,
                    line
                )
            )

    return alerts

def detect_command_injection(logs):

    alerts = []

    patterns = [

        "; whoami",
        "; id",
        "&& whoami",
        "&& id",
        "| whoami",
        "| id",
        "`whoami`",
        "`id`"

    ]

    for line in logs:

        if any(
            p.lower() in line.lower()
            for p in patterns
        ):

            ip = extract_ip(line)

            alerts.append(
                create_alert(
                    "Command Injection",
                    "HIGH",
                    ip,
                    line
                )
            )

    return alerts

def detect_download_activity(logs):

    alerts = []

    patterns = [

        "curl http",
        "curl https",
        "wget http",
        "wget https"

    ]

    for line in logs:

        if any(
            p.lower() in line.lower()
            for p in patterns
        ):

            ip = extract_ip(line)

            alerts.append(
                create_alert(
                    "Curl/Wget Download",
                    "MEDIUM",
                    ip,
                    line
                )
            )

    return alerts


def run_all_detections(
    apache_logs,
    auth_logs
):
    """
    Master detection engine.
    """

    alerts = []

    alerts.extend(
        detect_web_attacks(
            apache_logs
        )
    )

    alerts.extend(
        detect_bruteforce(
            auth_logs
        )
    )

    alerts.extend(
        detect_invalid_users(
            auth_logs
        )
    )

    alerts.extend(
        detect_root_attacks(
            auth_logs
        )
    )

    alerts.extend(
        detect_sudo_activity(
            auth_logs
        )
    )
    alerts.extend(
        detect_nmap(
            apache_logs
            )
        )

    alerts.extend(
        detect_hydra(
            auth_logs
            )
        )

    alerts.extend(
        detect_reverse_shell(
            auth_logs
            )
        )
    alerts.extend(
        detect_directory_traversal(
            apache_logs)
        )

    alerts.extend(
        detect_command_injection(
            apache_logs)
        )

    alerts.extend(
        detect_download_activity(
            apache_logs)
        )
    return alerts