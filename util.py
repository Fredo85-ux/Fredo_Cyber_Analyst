from __future__ import annotations
import subprocess
import shutil
import socket
import os
import json
from datetime import datetime

COMMAND_TIMEOUT_SECONDS = 120

# =========================
# ENV DETECTION
# =========================
def detect_environments() -> dict:
    return {
        "WSL": is_wsl_available(),
        "Kali": is_kali_available(),
        "Docker": is_docker_available(),
        "Ollama": is_ollama_available()
    }

def is_wsl_available() -> bool:
    try:
        return subprocess.run(["wsl", "-l"], capture_output=True, text=True, timeout=5).returncode == 0
    except:
        return False

def is_kali_available() -> bool:
    try:
        distros = get_wsl_distros()

        for d in distros:
            # Fast name check
            if "kali" in d.lower():
                return True

            # Deep OS check
            try:
                res = subprocess.run(
                    ["wsl", "-d", d, "--", "cat", "/etc/os-release"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )

                data = res.stdout.lower()
                if any(x in data for x in ["kali", "id=kali", "kali gnu/linux"]):
                    return True

            except:
                continue

        return False
    except:
        return False

def is_docker_available() -> bool:
    try:
        return subprocess.run(["docker", "--version"], capture_output=True, text=True, timeout=5).returncode == 0
    except:
        return False

def is_ollama_available() -> bool:
    try:
        return subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=5).returncode == 0
    except:
        return False

# =========================
# NETWORK
# =========================
def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# Get VPN IP (if connected)
def get_vpn_ip() -> str:
    try:
        hostname = socket.gethostname()
        ips = socket.getaddrinfo(hostname, None)

        candidates = set()
        for entry in ips:
            ip = entry[4][0]
            # Skip localhost + common LAN ranges
            if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10."):
                continue
            # Likely VPN / external interface
            candidates.add(ip)

        return list(candidates)[0] if candidates else "N/A"

    except:
        return "N/A"

# Get Network Interfaces
def get_network_interfaces() -> dict:
    interfaces = {
        "lan": None,
        "vpn": None,
        "wsl": None
    }

    try:
        output = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True
        ).stdout

        current_adapter = None

        for line in output.splitlines():
            line = line.strip()

            # Detect adapter name
            if "adapter" in line.lower():
                current_adapter = line.lower()

            # Extract IPv4
            if "IPv4 Address" in line or "ipv4" in line.lower():
                ip = line.split(":")[-1].strip()

                if ip.startswith("127."):
                    continue

                # VPN detection (strong heuristics)
                if any(x in current_adapter for x in ["tun", "tap", "vpn", "wireguard"]):
                    interfaces["vpn"] = ip

                # WSL detection
                elif "wsl" in current_adapter:
                    interfaces["wsl"] = ip

                # LAN fallback
                elif not interfaces["lan"]:
                    interfaces["lan"] = ip

        return interfaces

    except:
        return interfaces

# =========================
# RUSTSCAN
# =========================
def get_wsl_distros() -> list[str]:
    try:
        out = subprocess.run(["wsl", "-l", "-q"], capture_output=True, text=True, timeout=5)
        return [d.strip() for d in out.stdout.splitlines() if d.strip()]
    except:
        return []

def find_rustscan_windows() -> str | None:
    path = shutil.which("rustscan")
    if path:
        return path
    for p in [r"C:\Tools\rustscan\rustscan.exe", r"C:\Program Files\RustScan\rustscan.exe"]:
        if os.path.exists(p):
            return p
    return None

def find_rustscan_wsl() -> tuple[str, str] | None:
    for d in get_wsl_distros():
        try:
            out = subprocess.run(["wsl", "-d", d, "which", "rustscan"], capture_output=True, text=True, timeout=5)
            if out.returncode == 0 and out.stdout.strip():
                return ("wsl", d)
        except:
            continue
    return None

def build_scan_command(target: str, mode: str, use_nmap: bool) -> list[str]:
    base = ["rustscan", "-a", target] + (["--ulimit", "5000"] if mode == "red" else ["--ulimit", "1500"])
    if use_nmap:
        base += ["--", "-sC"]
    return base

def run_rustscan(target: str, mode: str = "blue") -> dict:
    # 🔴 PRIORITIZE KALI
    kali_distro = None

    for d in get_wsl_distros():
        if "kali" in d.lower():
            kali_distro = d
            break
        try:
            res = subprocess.run(
                ["wsl", "-d", d, "--", "cat", "/etc/os-release"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if "kali" in res.stdout.lower():
                kali_distro = d
                break
        except:
            continue

    # ✅ If Kali found → use it FIRST
    if kali_distro:
        return run_rustscan_wsl(target, mode)

    # 🟡 fallback to Windows
    rustscan_path = find_rustscan_windows()
    if rustscan_path:
        use_nmap = shutil.which("nmap") is not None
        cmd = build_scan_command(target, mode, use_nmap)
        cmd[0] = rustscan_path

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS)
            if res.returncode != 0 and is_wsl_available():
                return run_rustscan_wsl(target, mode)
            return build_result(res, "windows", target, mode)
        except Exception as e:
            return error_result(str(e), "windows")

    # 🔵 final fallback
    if is_wsl_available():
        return run_rustscan_wsl(target, mode)

    return error_result("RustScan not found", "none")

def run_rustscan_wsl(target: str, mode: str):
    wsl_info = find_rustscan_wsl()
    if not wsl_info:
        return error_result("RustScan not in WSL", "wsl")
    _, distro = wsl_info
    use_nmap = shutil.which("nmap") is not None
    cmd = build_scan_command(target, mode, use_nmap)
    try:
        res = subprocess.run(["wsl", "-d", distro] + cmd, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS)
        return build_result(res, f"wsl:{distro}", target, mode)
    except Exception as e:
        return error_result(str(e), f"wsl:{distro}")

# =========================
# RESULT PARSING / ANALYSIS
# =========================
def build_result(res, method: str, target: str, mode: str) -> dict:
    return {
        "status": "READY" if res.returncode == 0 else "DEGRADED",
        "method": method,
        "target": target,
        "mode": mode,
        "timestamp": datetime.utcnow().isoformat(),
        "output": res.stdout,
        "error": res.stderr,
        "open_ports": extract_ports(res.stdout)
    }

def error_result(msg: str, method: str) -> dict:
    return {"status": "ERROR", "method": method, "output": msg, "open_ports": []}

def extract_ports(output: str) -> list[int]:
    ports = []
    for line in output.splitlines():
        if "Open" in line or "open" in line:
            try:
                ports.append(int(line.split("/")[0]))
            except:
                continue
    return ports

def analyze_results(scan_result: dict) -> str:
    ports = scan_result.get("open_ports", [])
    if not ports:
        return "No open ports detected. System appears quiet."
    findings = []
    for p in ports:
        if p in [22, 23, 80, 443, 445, 3389]:
            findings.append(f"Port {p} is commonly targeted.")
    return "\n".join(findings) if findings else "Open ports detected, but no immediate high-risk flags."

def calculate_threat_score(open_ports: list[int], analysis: str) -> int:
    score = 0
    critical = {445: 30, 22: 20, 3389: 25, 139: 20, 80: 10, 443: 5, 21: 15}
    for p in open_ports:
        score += critical.get(p, 2)
    if "CRITICAL" in analysis.upper():
        score += 20
    elif "HIGH" in analysis.upper():
        score += 10
    elif "MEDIUM" in analysis.upper():
        score += 5
    return min(score, 100)

# =========================
# EXPORT REPORT
# =========================
def export_html_report(target: str, scan_result: dict, analysis: str, filename: str | None = None) -> str:
    if filename is None:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"{target}_fredo_report_{ts}.html"

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fredo Cyber Analyst Report - {target}</title>
<style>
body {{ font-family: Consolas, monospace; background-color: #111; color: #eee; padding:20px; }}
h1 {{ color:#00ff9c; }} h2 {{ color:#ffaa00; }}
.section {{ margin-bottom:20px; padding:10px; border:1px solid #555; border-radius:8px; }}
.ports {{ color:#3ba6ff; }} .threat {{ color:#ff3b3b; font-weight:bold; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
</head>
<body>
<h1>Fredo Cyber Analyst Report</h1>
<div class="section"><h2>Target</h2><p>{target}</p></div>
<div class="section"><h2>Timestamp (UTC)</h2><p>{datetime.utcnow().isoformat()}</p></div>
<div class="section"><h2>Open Ports</h2><p class="ports">{', '.join(map(str, scan_result.get("open_ports", []))) or 'None detected'}</p></div>
<div class="section"><h2>Threat Score</h2><p class="threat">{scan_result.get("threat_score", 'N/A')}</p></div>
<div class="section"><h2>Analysis</h2><pre>{analysis}</pre></div>
</body>
</html>
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    return os.path.abspath(filename)