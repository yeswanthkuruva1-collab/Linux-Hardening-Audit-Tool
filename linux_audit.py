import os
import subprocess
import sys

# Linux Hardening Audit Tool
# Objective: Audit Linux system security configuration and generate a compliance score.

def run_command(command):
    """Runs a shell command and returns the output."""
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8').strip()
    except subprocess.CalledProcessError:
        return None

def check_firewall():
    """Checks if a firewall (UFW or IPTables) is active."""
    print("[*] Checking Firewall Status...")
    ufw_status = run_command("ufw status | grep 'Status: active'")
    iptables_rules = run_command("iptables -L")
    
    if ufw_status or (iptables_rules and "Chain INPUT (policy DROP)" in iptables_rules):
        print("   [PASS] Firewall is active.")
        return 20
    else:
        print("   [FAIL] No active firewall detected or policy is not restrictive.")
        print("   -> Recommendation: Enable UFW ('sudo ufw enable') or configure iptables.")
        return 0

def check_ssh_config():
    """Checks SSH configuration for security best practices."""
    print("\n[*] Checking SSH Configuration...")
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            config = f.read()
            
        score = 0
        # Check 1: Root Login
        if "PermitRootLogin no" in config:
            print("   [PASS] Root login is disabled.")
            score += 10
        else:
            print("   [FAIL] Root login might be enabled.")
            print("   -> Recommendation: Set 'PermitRootLogin no' in /etc/ssh/sshd_config")

        # Check 2: Password Authentication (Prefer keys)
        if "PasswordAuthentication no" in config:
            print("   [PASS] Password authentication is disabled (using keys).")
            score += 10
        else:
            print("   [WARN] Password authentication is enabled.")
            print("   -> Recommendation: Use SSH keys and set 'PasswordAuthentication no'.")
            
        return score
    except FileNotFoundError:
        print("   [ERROR] Could not find /etc/ssh/sshd_config.")
        return 0

def check_file_permissions():
    """Verifies permissions on sensitive files (/etc/passwd, /etc/shadow)."""
    print("\n[*] Checking Critical File Permissions...")
    score = 0
    
    files_to_check = {
        "/etc/passwd": "644", # rw-r--r--
        "/etc/shadow": "640"  # rw-r----- or stricter
    }

    for filepath, expected_perm in files_to_check.items():
        if os.path.exists(filepath):
            # Get file permission in octal
            perms = oct(os.stat(filepath).st_mode)[-3:]
            if perms <= expected_perm:
                print(f"   [PASS] {filepath} permissions are secure ({perms}).")
                score += 10
            else:
                print(f"   [FAIL] {filepath} permissions are too open ({perms}).")
                print(f"   -> Recommendation: Run 'chmod {expected_perm} {filepath}'.")
        else:
            print(f"   [WARN] {filepath} not found.")
    
    return score

def check_rootkit_indicators():
    """Basic check for common rootkit indicators or suspicious binaries."""
    print("\n[*] Checking for Rootkit Indicators...")
    # This is a basic check. In a real scenario, use tools like 'rkhunter'.
    suspicious_files = ["/usr/bin/bonk", "/usr/bin/hacker", "/tmp/.hidden"]
    found = False
    
    for f in suspicious_files:
        if os.path.exists(f):
            print(f"   [ALERT] Suspicious file found: {f}")
            found = True
            
    if not found:
        print("   [PASS] No obvious suspicious files found in standard paths.")
        return 20
    else:
        print("   [FAIL] Potential rootkit indicators found.")
        return 0

def main():
    if os.geteuid() != 0:
        print("This script requires root privileges to check system files.")
        print("Please run with: sudo python3 linux_audit.py")
        sys.exit(1)

    print("=== Linux Hardening Audit Tool ===")
    print("Starting System Audit...\n")

    total_score = 0
    max_score = 80 # Sum of max points from all functions

    total_score += check_firewall()
    total_score += check_ssh_config()
    total_score += check_file_permissions()
    total_score += check_rootkit_indicators()

    print("\n" + "="*30)
    print(f"AUDIT COMPLETE")
    print(f"Security Score: {total_score}/{max_score}")
    print("="*30)
    
    if total_score < 50:
        print("Status: CRITICAL - Immediate hardening required.")
    elif total_score < 70:
        print("Status: WARNING - Some security controls are missing.")
    else:
        print("Status: GOOD - Basic hardening measures are in place.")

if __name__ == "__main__":
    main()