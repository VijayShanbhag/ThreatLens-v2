
# SQL Injection

SQL_PATTERNS = [

    "' or 1=1",
    "\" or 1=1",
    "union select",
    "information_schema",
    "sleep(",
    "benchmark(",
    "load_file(",
    "into outfile",
    "xp_cmdshell",
    "drop table",
    "insert into",
    "delete from"
]

# Cross Site Scripting

XSS_PATTERNS = [

    "<script>",
    "javascript:",
    "onerror=",
    "onload=",
    "alert(",
    "document.cookie",
    "<img",
    "<svg"
]

# Directory Traversal

TRAVERSAL_PATTERNS = [

    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "boot.ini",
    "win.ini"
]

# Command Injection

COMMAND_INJECTION_PATTERNS = [

    ";",
    "&&",
    "||",
    "| bash",
    "cmd.exe",
    "powershell",
    "wget ",
    "curl "
]

# Web Shell Indicators

WEBSHELL_PATTERNS = [

    "cmd=",
    "shell=",
    "c99",
    "r57",
    "webshell",
    "php?cmd"
]

# Reverse Shell Indicators

REVERSE_SHELL_PATTERNS = [

    "nc -e",
    "bash -i",
    "python -c",
    "socket.connect",
    "/dev/tcp/",
    "mkfifo"
]

# Suspicious Tools

SUSPICIOUS_AGENTS = [

    "sqlmap",
    "nikto",
    "dirbuster",
    "gobuster",
    "wpscan",
    "masscan"
]

# MITRE ATT&CK Mapping

MITRE_MAPPING = {

    "SQL Injection": "T1190",

    "XSS": "T1059",

    "Brute Force": "T1110",

    "Root Login Attack": "T1110",

    "Invalid User Enumeration": "T1580",

    "Privileged Command Execution": "T1548",

    "Suspicious Tool": "T1595",

    "Directory Traversal": "T1083",

    "Command Injection": "T1059",

    "Web Shell": "T1505",

    "Reverse Shell": "T1059",

    "Directory Traversal": "T1190",

    "Command Injection": "T1059",

    "Curl/Wget Download": "T1105"
}

