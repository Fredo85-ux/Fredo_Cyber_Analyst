# Fredo Cyber Analyst

Fredo Cyber Analyst is a lightweight desktop toolkit for quick red-team recon and simple blue-team follow-up. 
The app runs RustScan for port discovery and, when the target is a domain, OWASP Amass for subdomain enumeration.

Important WSL note: install RustScan and Amass inside your Linux distro, not in Windows PowerShell.

## Requirements

- Windows
- Python 3.10+
- Pillow
- Windows Subsystem for Linux (WSL)
- RustScan installed inside WSL
- OWASP Amass installed inside WSL

### Controls
Fullscreen Mode

Press F4 to toggle fullscreen mode on/off

Press ESC to exit fullscreen quickly

## Installation

### 1. Install Python dependency

```bash
pip install pillow
```

### 2. Install WSL

```bash
wsl --install
```

### 3. Install tools inside WSL

Open your Ubuntu or WSL terminal for this step. You can also run the same commands from PowerShell if you prefix them with `wsl`.

```bash
sudo apt update
sudo apt install rustscan amass -y
```

## Run The App

```bash
py -3 main.py
```

If `py` is not available on your system, use your Python launcher instead:

```bash
python main.py
```

## RustScan Syntax

RustScan is used for host or domain port scanning.

For WSL, avoid `--ulimit`. The app uses a safer WSL-friendly form.

### Basic syntax

```bash
rustscan --scripts none -a <target> -b 250 -T 2000
```

### Argument notes

- `--scripts none`: skip the default Nmap handoff
- `-a <target>`: target IP address or hostname
- `-b 250`: conservative batch size for WSL
- `-T 2000`: 2-second timeout in milliseconds

### Examples

Scan a public host:

```bash
wsl rustscan --scripts none -a scanme.nmap.org -b 250 -T 2000
```

Scan an internal IP:

```bash
wsl rustscan --scripts none -a 192.168.1.10 -b 250 -T 2000
```

Scan localhost:

```bash
wsl rustscan --scripts none -a 127.0.0.1 -b 250 -T 2000
```

## Domain Commands

The commands in this section are domain-aware or domain-only.

### RustScan with a domain

RustScan accepts a domain name as the target:

```bash
wsl rustscan --scripts none -a example.com -b 250 -T 2000
```

Use a bare domain or hostname when possible:

- Good: `example.com`
- Good: `api.example.com`
- Avoid: `https://example.com`
- Avoid: `example.com/login`
- Avoid: `example.com:443`

### Amass syntax

Amass is for domain enumeration, not raw IP scanning.

```bash
amass enum -d <domain>
```

### Proper domain annotation

- `enum`: run enumeration mode
- `-d <domain>`: root domain to enumerate
- Domain only: pass a registrable domain such as `example.com`
- Do not use an IP address with `-d`
- Do not pass a full URL such as `https://example.com/path`

### Examples

Basic domain enumeration:

```bash
wsl amass enum -d example.com
```

Verbose enumeration with source reporting:

```bash
wsl amass enum -v -src -d example.com
```

## How The App Uses These Commands

The desktop app normalizes the target before running tools:

- For an IP or hostname: runs RustScan
- For a domain such as `example.com`: runs RustScan, then Amass
- For a full URL entered by mistake: the app attempts to extract the hostname
- RustScan is launched with `--scripts none` so it does not depend on the default Nmap parser flow

## Recommended Input Format

Enter targets in one of these forms:

```text
192.168.1.10
scanme.nmap.org
example.com
subdomain.example.com
```

## Notes

- RustScan is appropriate for IPs and hostnames.
- Amass should be treated as a domain command.
- If a tool fails, confirm it is installed inside WSL and available on the WSL `PATH`.
- If you see `/bin/bash: rustscan: command not found`, WSL started correctly but RustScan is missing inside the Linux distro.
## License

This demo version of Fredo Super Cyber Analyst is licensed under the
**GNU Affero General Public License v3 (AGPL v3)**.

You may use, modify, and redistribute this demo under the terms of
the AGPL v3. Any derivative work must also be released under the
AGPL v3. See the LICENSE file for full details.

© 2026 Fredo Labs
