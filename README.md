# Linux Hardening Audit Tool 🛡️

## 📄 Abstract
This tool is a Python-based security auditor designed to assess the security posture of Linux systems. It automates the verification of critical security controls—including firewalls, SSH configurations, and file permissions—against industry standard benchmarks (CIS).

## 🛠️ Tools Used
* **Python 3:** Core logic and system interaction.
* **Subprocess Module:** For executing shell commands.
* **OS Module:** For file permission analysis.
* **Linux (Ubuntu/Debian):** Target operating system environment.

## 🚀 Steps Involved
1.  **System Scanning:** The script queries the OS for active firewalls (UFW/IPTables).
2.  **Configuration Parsing:** It reads `/etc/ssh/sshd_config` to identify insecure settings like Root Login.
3.  **Permission Analysis:** It verifies octal permissions on sensitive files (`/etc/shadow`).
4.  **Scoring & Reporting:** It calculates a security score (0-80) and prints a pass/fail report with remediation steps.

## ⚙️ How to Run
```bash
# Clone the repository
git clone [https://github.com/YOUR-USERNAME/Linux-Hardening-Audit-Tool.git](https://github.com/YOUR-USERNAME/Linux-Hardening-Audit-Tool.git)

# Navigate to directory
cd Linux-Hardening-Audit-Tool

# Run with root privileges
sudo python3 linux_audit.py
