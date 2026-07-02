"""
ThreatLens GUI v2.1 (Polished Edition)

Key improvements:
- Fixed HTML export
- Timestamped report filenames
- Cleaner comments
- Portfolio-ready structure
"""


import re
import ttkbootstrap as tk
import tkinter as tkinter
from ttkbootstrap.constants import *
from collections import Counter
from datetime import datetime
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk

from parser import read_file

from detector import (
    detect_web_attacks,
    detect_bruteforce,
    detect_invalid_users,
    detect_root_attacks,
    detect_sudo_activity,
    detect_nmap,
    detect_hydra,
    detect_reverse_shell,
    detect_directory_traversal,
    detect_command_injection,
    detect_download_activity
)

from scoring import (
    calculate_score,
    get_risk_level
)


class ThreatLensGUI:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "ThreatLens v2"
        )

        self.root.geometry(
            "1400x800"
        )

        self.file_path = ""

        self.create_widgets()

    def create_widgets(self):
# -------------------------
# Top Frame
# -------------------------

        top_frame = tk.Frame(
            self.root
        )

        top_frame.pack(
            fill="x",
            padx=10,
            pady=10
        )

        # Browse button

        tk.Button(
            top_frame,
            text="Browse File",
            command=self.browse_file
        ).pack(
            side="left"
        )

        # File label

        self.file_label = tk.Label(
            top_frame,
            text="No file selected"
        )

        self.file_label.pack(
            side="left",
            padx=10
        )

        # Export buttons

        tk.Button(
            top_frame,
            text="Export CSV",
            command=self.export_csv
        ).pack(
            side="right",
            padx=5
        )

        tk.Button(
            top_frame,
            text="Export JSON",
            command=self.export_json
        ).pack(
            side="right",
            padx=5
        )

        tk.Button(
            top_frame,
            text="Export HTML",
            command=self.export_html
        ).pack(
            side="right",
            padx=5
        )

        # Scan button

        tk.Button(
            top_frame,
            text="Scan",
            command=self.scan_file
        ).pack(
            side="right",
            padx=5
        )


# -------------------------
# Dashboard
# -------------------------

        dashboard = tk.Frame(
            self.root
        )

        dashboard.pack(
            fill="x",
            padx=10,
            pady=10
        )

        # Threat Score Card

        score_card = tk.LabelFrame(
            dashboard,
            text="Threat Score",
            padx=20,
            pady=10
        )

        score_card.pack(
            side="left",
            padx=10
        )

        self.score_label = tk.Label(
            score_card,
            text="0",
            font=("Arial", 20, "bold")
        )

        self.score_label.pack()

        # Risk Card

        risk_card = tk.LabelFrame(
            dashboard,
            text="Risk Level",
            padx=20,
            pady=10
        )

        risk_card.pack(
            side="left",
            padx=10
        )

        self.risk_label = tk.Label(
            risk_card,
            text="LOW",
            font=("Arial", 20, "bold")
        )

        self.risk_label.pack()

        # Threat Count Card

        threat_card = tk.LabelFrame(
            dashboard,
            text="Threats",
            padx=20,
            pady=10
        )

        threat_card.pack(
            side="left",
            padx=10
        )

        self.threat_label = tk.Label(
            threat_card,
            text="0",
            font=("Arial", 20, "bold")
        )

        self.threat_label.pack()

        # IOC Card

        ioc_card = tk.LabelFrame(
            dashboard,
            text="IOCs",
            padx=20,
            pady=10
        )

        ioc_card.pack(
            side="left",
            padx=10
        )

        self.ioc_label = tk.Label(
            ioc_card,
            text="0",
            font=("Arial", 20, "bold")
        )

        self.ioc_label.pack()

        # Top Attacker Card

        attacker_card = tk.LabelFrame(
            dashboard,
            text="Top Attacker",
            padx=20,
            pady=10
        )

        attacker_card.pack(
            side="left",
            padx=10
        )

        self.attacker_label = tk.Label(
            attacker_card,
            text="-",
            font=("Arial", 14, "bold")
        )

        self.attacker_label.pack()

# -------------------------
# Threat Table
# -------------------------

        table_frame = tk.LabelFrame(
            self.root,
            text="Detected Threats"
        )

        table_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=5
        )

        columns = (
            "Severity",
            "Threat",
            "IP",
            "MITRE",
            "Evidence"
        )

        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings"
        )

        for col in columns:

            self.tree.heading(
                col,
                text=col
            )
            scrollbar = ttk.Scrollbar(
                table_frame,
                orient="vertical",
                command=self.tree.yview
            )

            self.tree.configure(
                yscrollcommand=scrollbar.set
            )

            self.tree.pack(
                side="left",
                fill="both",
                expand=True
            )

            scrollbar.pack(
                side="right",
                fill="y"
            )

            self.tree.column(
                "Severity",
                width=90
            )

            self.tree.column(
                "Threat",
                width=220
            )

            self.tree.column(
                "IP",
                width=150
            )

            self.tree.column(
                "MITRE",
                width=100
            )

            self.tree.column(
                "Evidence",
                width=500
            
            )

            scrollbar = ttk.Scrollbar(
                table_frame,
                orient="vertical",
                command=self.tree.yview
            )

            self.tree.configure(
                yscrollcommand=scrollbar.set
            )

            scrollbar = ttk.Scrollbar(
                table_frame,
                orient="vertical",
                command=self.tree.yview
            )

            self.tree.configure(
                yscrollcommand=scrollbar.set
            )

            scrollbar.pack(
                side="right",
                fill="y"
            )

            self.tree.tag_configure(
                "HIGH",
                foreground="#ff4d4d"
            )

            self.tree.tag_configure(
                "MEDIUM",
                foreground="#ffb84d"
            )

            self.tree.tag_configure(
                "LOW",
                foreground="#66cc66"
            )
            self.tree.tag_configure(
                "oddrow",
                background="#252526"
            )

            self.tree.tag_configure(
                 "evenrow",
                background="#2d2d30"
            )

# -------------------------
# IOC Panel
# -------------------------

        ioc_frame = tk.LabelFrame(
            self.root,
            text="Indicators of Compromise"
        )

        ioc_frame.pack(
            fill="x",
            padx=10,
            pady=5
        )

        self.ioc_text = tk.Text(
            ioc_frame,
            height=6,
            bg="#1e1e1e",
            fg="white"
        )

        self.ioc_text.pack(
            fill="x"
        )
        self.ioc_text.insert(
            tkinter.END,
             "No scan performed yet."
        )

    def browse_file(self):

        path = filedialog.askopenfilename(

            filetypes=[

                (
                    "Supported Files",
                    "*.log *.txt *.csv *.json"
                ),

                (
                    "All Files",
                    "*.*"
                )
            ]
        )

        if path:

            self.file_path = path

            self.file_label.config(
                text=path
            )

    def scan_file(self):

        if not self.file_path:

            messagebox.showerror(
                "Error",
                "Select a file first."
            )
            return

        try:

            logs = read_file(
                self.file_path
            )

            alerts = []

            alerts.extend(
                detect_web_attacks(logs)
            )

            alerts.extend(
                detect_bruteforce(logs)
            )

            alerts.extend(
                detect_invalid_users(logs)
            )

            alerts.extend(
                detect_root_attacks(logs)
            )

            alerts.extend(
                detect_sudo_activity(logs)
            )
            alerts.extend(
                detect_nmap(logs)
            )

            alerts.extend(
                detect_hydra(logs)
            )

            alerts.extend(
                detect_reverse_shell(logs)
            )
            self.current_alerts = alerts
# -------------------------
# Debug Output
# -------------------------

            print("\n" + "=" * 50)
            print("THREATLENS DEBUG")
            print("=" * 50)

            for alert in alerts:
                print(alert)

# -------------------------
# Dashboard Metrics
# -------------------------

            score = calculate_score(
                alerts
            )

            risk = get_risk_level(
                score
            )

            self.risk_label.config(
            text=risk
        )

            if risk == "HIGH":

                self.risk_label.config(
                    foreground="#ff4d4d"
                )

            elif risk == "MEDIUM":

                self.risk_label.config(
                    foreground="#ffb84d"
                )

            else:

                self.risk_label.config(
                    foreground="#66cc66"
                )

# -------------------------
# IOC Extraction
# -------------------------

            import re

            unique_iocs = sorted(
                set(
                    alert.get("ip", "")
                    for alert in alerts
                    if alert.get("ip")
                    and re.match(
                        r"^\d+\.\d+\.\d+\.\d+$",
                        alert.get("ip", "")
                    )
                )
            )

            self.ioc_label.config(
                text=str(len(unique_iocs))
            )
            from collections import Counter

            ips = [
                alert.get("ip")
                for alert in alerts
                if alert.get("ip")
            ]

            if ips:

                top_ip, count = Counter(ips).most_common(1)[0]

                self.attacker_label.config(
                    text=f"{top_ip}\n({count})"
                )

            else:

                self.attacker_label.config(
                    text="None"
                )
# -------------------------
# Clear Table
# -------------------------

            for item in self.tree.get_children():

                self.tree.delete(item)

 # -------------------------
 # Populate Threat Table
 # -------------------------

            for alert in alerts:

                severity = alert.get(
                    "severity",
                    "UNKNOWN"
                )

                threat_type = alert.get(
                    "type",
                    alert.get(
                        "threat",
                        "Unknown Threat"
                    )
                )

                ip = alert.get(
                    "ip",
                    "-"
                )

                mitre = alert.get(
                    "mitre",
                    "-"
                )

                evidence = alert.get(
                    "log",
                    alert.get(
                        "evidence",
                        "-"
                    )
                )

                self.tree.insert(
                    "",
                    "end",
                    values=(
                        severity,
                        threat_type,
                        ip,
                        mitre,
                        evidence
                    ),
                    tags=(severity,)
                )

# -------------------------
# IOC Panel# 
# -------------------------

            self.ioc_text.delete(
                "1.0",
                "end"
            )

            if unique_iocs:

                for ioc in unique_iocs:

                    self.ioc_text.insert(
                        "end",
                        ioc + "\n"
                    )

            else:

                self.ioc_text.insert(
                    "end",
                    "No IOCs Found"
                )

            print("\nIOCs Found:")
            print(unique_iocs)

        except Exception as e:

            messagebox.showerror(
                "Scan Error",
                str(e)
            )

            print("ERROR:", e)

    def export_json(self):

        import json

        if not hasattr(self, "current_alerts"):
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json"
        )

        if not path:
            return

        with open(path, "w", encoding="utf-8") as f:

            json.dump(
                self.current_alerts,
                f,
                indent=4
            )

        messagebox.showinfo(
            "Success",
            "JSON exported."
        )
            
    def export_csv(self):

        import csv

        if not hasattr(self, "current_alerts"):
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv"
        )

        if not path:
            return

        with open(
            path,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "severity",
                    "type",
                    "ip",
                    "mitre",
                    "log"
                ]
            )

            writer.writeheader()

            writer.writerows(
                self.current_alerts
            )

        messagebox.showinfo(
            "Success",
            "CSV exported."
        )

    def export_html(self):

        if not hasattr(self, "current_alerts"):
            return

        timestamp_file = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        path = filedialog.asksaveasfilename(
            initialfile=f"ThreatLens_Report_{timestamp_file}.html",
            defaultextension=".html",
            filetypes=[("HTML Files", "*.html")]
        )

        if not path:
            return

        high = sum(1 for a in self.current_alerts if a["severity"] == "HIGH")
        medium = sum(1 for a in self.current_alerts if a["severity"] == "MEDIUM")
        low = sum(1 for a in self.current_alerts if a["severity"] == "LOW")
        score = calculate_score(
            self.current_alerts
        )

        risk = get_risk_level(
            score
        )

        iocs = sorted(set(
            alert["ip"]
            for alert in self.current_alerts
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", alert["ip"])
        ))

        ips = [
            alert["ip"]
            for alert in self.current_alerts
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", alert["ip"])
        ]

        top_attacker = "None"
        if ips:
            ip, count = Counter(ips).most_common(1)[0]
            top_attacker = f"{ip} ({count})"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""
<!DOCTYPE html>
<html>
<head>
<title>ThreatLens Security Report</title>
<style>
body {{background:#0d1117;color:#f0f6fc;font-family:Segoe UI,Arial;padding:20px;}}
.card {{background:#161b22;padding:20px;margin-bottom:20px;border-radius:8px;}}
.high {{color:#ff4d4d;font-weight:bold;}}
.medium {{color:#ffb84d;font-weight:bold;}}
.low {{color:#66cc66;font-weight:bold;}}
table {{width:100%;border-collapse:collapse;}}
th {{background:#21262d;}}
th,td {{border:1px solid #30363d;padding:10px;}}
</style>
</head>
<body>
<h1>ThreatLens Security Report</h1>
<p>Generated: {timestamp}</p>

<div class="card">
<h2>Threat Score</h2>
<h3>{score}/100</h3>
<p>Risk Level: {risk}</p>
</div>

<div class="card">
<h2>Threat Summary</h2>
<p class="high">HIGH Alerts: {high}</p>
<p class="medium">MEDIUM Alerts: {medium}</p>
<p class="low">LOW Alerts: {low}</p>
<p>Total Threats: {len(self.current_alerts)}</p>
</div>

<div class="card">
<h2>Top Attacker</h2>
<p>{top_attacker}</p>
</div>

<div class="card">
<h2>Indicators of Compromise (IOCs)</h2>
<ul>
"""

        for ioc in iocs:
            html += f"<li>{ioc}</li>"

        html += """
</ul>
</div>

<div class="card">
<h2>Detected Threats</h2>
<table>
<tr>
<th>Severity</th>
<th>Threat</th>
<th>IP</th>
<th>MITRE ATT&CK</th>
<th>Evidence</th>
</tr>
"""

        for alert in self.current_alerts:
            sev = alert["severity"].lower()
            html += f"""
<tr>
<td class="{sev}">{alert['severity']}</td>
<td>{alert['type']}</td>
<td>{alert['ip']}</td>
<td>{alert['mitre']}</td>
<td>{alert['log']}</td>
</tr>
"""

        html += """
</table>
</div>
<hr>
<p>Generated by ThreatLens v2.1</p>
</body>
</html>
"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

        messagebox.showinfo("Success", "HTML report exported.")
