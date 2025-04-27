import re

def analyze_failed_logins(log_file):
    failed_attempts = 0
    with open(log_file, 'r') as f:
        logs = f.readlines()
        for log in logs:
            if 'Failed password' in log:
                failed_attempts += 1
    return failed_attempts

def analyze_malware_behaviors(log_file):
    suspicious_behaviors = []
    with open(log_file, 'r') as f:
        logs = f.readlines()
        for log in logs:
            if '/dev/tcp' in log or 'netcat' in log:
                suspicious_behaviors.append(log.strip())
    return suspicious_behaviors

if __name__ == "__main__":
    failed_logins = analyze_failed_logins('failed_login.log')
    print(f"Failed login attempts: {failed_logins}")

    suspicious_malware = analyze_malware_behaviors('malware_behavior.log')
    if suspicious_malware:
        print("Suspicious malware behaviors detected:")
        for behavior in suspicious_malware:
            print(f"- {behavior}")
    else:
        print("No suspicious behaviors detected.")