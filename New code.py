"""
Cybersecurity Log Analyzer
Beginner-friendly defensive cybersecurity project.

This project analyzes a small fictional authentication-log dataset and flags:
1. Repeated failed login attempts (3 or more from one IP)
2. IP addresses with both failed and successful login events
3. Privilege-escalation event records

Educational demonstration only. The records are fictional.
"""

import pandas as pd


def main():
    # 1. Create fictional sample security logs
    logs = [
        {"timestamp": "2026-10-01 09:00:00", "username": "alex", "ip_address": "192.0.2.10", "event": "login_success"},
        {"timestamp": "2026-10-01 09:05:00", "username": "sam", "ip_address": "198.51.100.23", "event": "login_failed"},
        {"timestamp": "2026-10-01 09:06:00", "username": "sam", "ip_address": "198.51.100.23", "event": "login_failed"},
        {"timestamp": "2026-10-01 09:07:00", "username": "sam", "ip_address": "198.51.100.23", "event": "login_failed"},
        {"timestamp": "2026-10-01 09:08:00", "username": "sam", "ip_address": "198.51.100.23", "event": "login_success"},
        {"timestamp": "2026-10-01 09:15:00", "username": "alex", "ip_address": "192.0.2.10", "event": "privilege_escalation"},
        {"timestamp": "2026-10-01 09:20:00", "username": "mia", "ip_address": "203.0.113.8", "event": "login_success"},
        {"timestamp": "2026-10-01 09:25:00", "username": "lee", "ip_address": "203.0.113.44", "event": "login_failed"},
    ]

    df = pd.DataFrame(logs)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    print("\n=== CYBERSECURITY LOG ANALYZER ===")
    print("\n1. Sample security logs:")
    print(df.to_string(index=False))

    # 2. Find IP addresses with at least three failed logins
    failed_logins = df[df["event"] == "login_failed"]
    failed_counts = failed_logins.groupby("ip_address").size().reset_index(name="failed_attempts")
    login_anomalies = failed_counts[failed_counts["failed_attempts"] >= 3]

    print("\n2. Login anomalies (3 or more failed attempts):")
    if login_anomalies.empty:
        print("No matching IP addresses found.")
    else:
        print(login_anomalies.to_string(index=False))

    # 3. Find IP addresses with both failed and successful logins
    event_types_by_ip = df.groupby("ip_address")["event"].agg(set)
    ips_with_both = event_types_by_ip[
        event_types_by_ip.apply(
            lambda events: "login_failed" in events and "login_success" in events
        )
    ].index.tolist()

    print("\n3. IP addresses with both failed and successful logins:")
    if not ips_with_both:
        print("No matching IP addresses found.")
    else:
        print(df[df["ip_address"].isin(ips_with_both)].sort_values("timestamp").to_string(index=False))

    # 4. Find privilege-escalation events
    privilege_events = df[df["event"] == "privilege_escalation"]
    print("\n4. Privilege-escalation events:")
    if privilege_events.empty:
        print("No privilege-escalation events found.")
    else:
        print(privilege_events.to_string(index=False))

    # 5. Print a summary
    print("\n5. Summary:")
    summary = {
        "Total log records": len(df),
        "Failed login records": int((df["event"] == "login_failed").sum()),
        "IPs with 3+ failed attempts": len(login_anomalies),
        "IPs with both failed and successful logins": len(ips_with_both),
        "Privilege-escalation events": len(privilege_events),
    }
    for label, value in summary.items():
        print(f"{label}: {value}")

    print("\nNote: A flagged pattern is an alert for human review, not proof of malicious activity.")


if __name__ == "__main__":
    main()
