# Network Recon & Vulnerability Report

A pure-Python port scanner that identifies open ports, flags risky services, and generates a clean HTML vulnerability report.

## Features
- Scans common ports concurrently (fast, uses `ThreadPoolExecutor`).
- Uses Python's built-in `socket` library — no external tools like Nmap required.
- Flags risky services (SMB, exposed databases, etc.) based on a configurable ruleset.
- Generates a professional HTML report using Jinja2.

## Usage
```bash
pip install jinja2
python scanner.py
python report_generator.py
# open report.html in your browser