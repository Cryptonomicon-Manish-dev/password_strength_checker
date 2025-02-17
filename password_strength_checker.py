import os
import psutil
import getpass
import re
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 🔹 Detect and Kill Suspicious Processes
def detect_suspicious_processes():
    print("\n[🔍] Scanning for Suspicious Processes...")

    suspicious_processes = ["keylogger.exe", "malware.exe", "trojan.exe"]

    for process in psutil.process_iter(['pid', 'name']):
        process_name = process.info['name']
        process_id = process.info['pid']

        if process_name.lower() in suspicious_processes:
            print(f"[⚠️ ALERT] Suspicious Process Found: {process_name} (PID: {process_id})")

            try:
                os.kill(process_id, 9)
                print(f"[✅] Successfully Terminated {process_name} (PID: {process_id})")
            except PermissionError:
                print(f"[❌] Permission Denied: Cannot terminate {process_name}")

# 🔹 Password Strength Checker
def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    else:
        print("[⚠️] Password too short! Use at least 8 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        print("[⚠️] Add at least one UPPERCASE letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        print("[⚠️] Add at least one lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        print("[⚠️] Add at least one number.")

    if re.search(r"[@$!%*?&]", password):
        score += 1
    else:
        print("[⚠️] Add at least one special character (@$!%*?&).")

    strength_levels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
    print(f"\n🔍 Password Strength: {strength_levels[score]}")

    hashed_password = pwd_context.hash(password)
    print(f"\n[🔒] Hashed Password: {hashed_password}")

# 🔹 Main Function
def main():
    print("\n🔰 Security Toolkit 🔰")

    # Run Security Scanner
    detect_suspicious_processes()

    # Run Password Strength Checker
    print("\n🔐 Password Strength Checker 🔐")
    password = getpass.getpass("Enter your password: ")
    check_password_strength(password)

if __name__ == "__main__":
    main()
