# Linux Hardening Audit Tool

## Project Overview
This project is a Python-based security auditing tool Designed to check Linux systems for common security misconfigurations. It scans critical areas of the operating system and generates a compliance score based on industry best practices (CIS Benchmarks).

## Features
- **Firewall Check:** Verifies if UFW or IPTables is active.
- **SSH Hardening:** Checks for Root Login and Password Authentication settings.
- **File Integrity:** Audits permissions for `/etc/passwd` and `/etc/shadow`.
- **Rootkit Detection:** Scans for basic indicators of compromise.
- **Scoring System:** Provides a security score (0-80) and actionable fix recommendations.

## Usage
1. Clone the repository.
2. Run the script with root privileges:
   ```bash
   sudo python3 linux_audit.py
