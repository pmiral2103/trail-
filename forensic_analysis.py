
import pandas as pd
import numpy as np
import json
import re
from datetime import datetime, timedelta

        self.sms['timestamp'] = pd.to_datetime(self.sms['timestamp'], errors='coerce')
        
        self.risk_report = {
            "summary": {"total_risk_score": 0, "risk_level": "LOW"},
            "detections": {
                "suspicious_behavior": [],
                "malware_indicators": [],
                "integrity_anomalies": []
            }
        }
        self.risk_score = 0

    def analyze(self):
        """Run all analysis modules."""
        print("Starting Forensic Analysis...")
        self._check_integrity()
        self._check_malware_indicators()
        self._check_suspicious_behavior()
        self._calculate_risk_score()
        return self.risk_report

    def _check_suspicious_behavior(self):
        """Detects high frequency calls, odd hours, and interaction patterns."""
        detections = []
        
        # 1. High Frequency Calls (e.g., > 10 calls in 1 hour)
        # Resample by hour to find spikes
        if not self.calls.empty:
            calls_per_hour = self.calls.set_index('timestamp').resample('H').size()
            spikes = calls_per_hour[calls_per_hour > 10]
            if not spikes.empty:
                for time, count in spikes.items():
                    detections.append(f"High frequency call volume detected: {count} calls at {time}")
                    self.risk_score += 10

        # 2. Odd Hours Activity (12 AM - 5 AM)
        odd_hours_calls = self.calls[self.calls['timestamp'].dt.hour.isin([0, 1, 2, 3, 4, 5])]
        odd_hours_sms = self.sms[self.sms['timestamp'].dt.hour.isin([0, 1, 2, 3, 4, 5])]
        
        if len(odd_hours_calls) > 0:
            detections.append(f"Suspicious activity during odd hours: {len(odd_hours_calls)} calls detected between 12 AM - 5 AM")
            self.risk_score += 5 * len(odd_hours_calls)
            
        if len(odd_hours_sms) > 0:
            detections.append(f"Suspicious activity during odd hours: {len(odd_hours_sms)} SMS detected between 12 AM - 5 AM")
            self.risk_score += 5 * len(odd_hours_sms)

        # 3. Repeated calls to same number (Stalking/Harassment or Bot behavior)
        if not self.calls.empty:
            top_contacts = self.calls['receiver_number'].value_counts()
            suspicious_contacts = top_contacts[top_contacts > 15] # Threshold
            if not suspicious_contacts.empty:
                for number, count in suspicious_contacts.items():
                    detections.append(f"High repetition detected: {count} calls to {number}")
                    self.risk_score += 15

        self.risk_report["detections"]["suspicious_behavior"] = detections

    def _check_malware_indicators(self):
        """Detects phishing keywords, bad links, and file extensions."""
        detections = []
        
        # Keywords for phishing/spam
        suspicious_keywords = [r"click here", r"urgent", r"verify", r"free", r"reward", r"lottery", r"winner", r"bank", r"alert"]
        for keyword in suspicious_keywords:
            matches = self.sms[self.sms['message_content'].str.contains(keyword, case=False, na=False)]
            if not matches.empty:
                for _, row in matches.iterrows():
                    detections.append(f"Suspicious keyword '{keyword}' found in SMS from {row['sender']}: '{row['message_content'][:30]}...'")
                    self.risk_score += 20

        # Short URLs and non-HTTPS
        link_pattern = r"(http://|bit\.ly|tinyurl\.com|goo\.gl)"
        unsafe_links = self.sms[self.sms['message_content'].str.contains(link_pattern, case=False, na=False)]
        if not unsafe_links.empty:
             for _, row in unsafe_links.iterrows():
                detections.append(f"Unsafe or short link detected in SMS from {row['sender']}")
                self.risk_score += 25

        # APK/EXE/ZIP references
        file_pattern = r"(\.apk|\.exe|\.zip|\.rar)"
        malicious_files = self.sms[self.sms['message_content'].str.contains(file_pattern, case=False, na=False)]
        if not malicious_files.empty:
             for _, row in malicious_files.iterrows():
                detections.append(f"Potential malware file reference detected in SMS from {row['sender']}")
                self.risk_score += 40

        # Repeated missed calls from unknown/same numbers (Wangiri Fraud indicators)
        missed_calls = self.calls[self.calls['call_type'] == 'Missed']
        if not missed_calls.empty:
            count = missed_calls['caller_number'].value_counts()
            repeated_missed = count[count > 2]
            if not repeated_missed.empty:
                for number, cnt in repeated_missed.items():
                    detections.append(f"Potential fraud (Wangiri): {cnt} missed calls from {number}")
                    self.risk_score += 20

        self.risk_report["detections"]["malware_indicators"] = detections

    def _check_integrity(self):
        """Checks for future timestamps, duplicates, and missing data."""
        detections = []
        now = datetime.now()

        # Future timestamps
        future_calls = self.calls[self.calls['timestamp'] > now]
        if not future_calls.empty:
            detections.append(f"Integrity Breach: {len(future_calls)} call records have future timestamps")
            self.risk_score += 30

        # Duplicates
        dup_calls = self.calls.duplicated().sum()
        if dup_calls > 0:
            detections.append(f"Data Integrity: {dup_calls} duplicate call records found")
            self.risk_score += 10

        # Nulls
        null_sms = self.sms.isnull().sum().sum()
        if null_sms > 0:
            detections.append(f"Data Integrity: {null_sms} missing fields detected in SMS logs")
            self.risk_score += 5

        self.risk_report["detections"]["integrity_anomalies"] = detections

    def _calculate_risk_score(self):
        """Finalizes risk score and category."""
        # Cap score at 100
        self.risk_score = min(100, self.risk_score)
        self.risk_report["summary"]["total_risk_score"] = self.risk_score
        
        if self.risk_score < 30:
            self.risk_report["summary"]["risk_level"] = "LOW"
        elif self.risk_score < 70:
            self.risk_report["summary"]["risk_level"] = "MEDIUM"
        else:
            self.risk_report["summary"]["risk_level"] = "HIGH"

# --- Sample Data Generation for Demonstration ---
def generate_sample_data():
    now = datetime.now()
    
    # helper to create time string
    def t(hours_offset): return now - timedelta(hours=hours_offset)

    call_data = {
        'caller_number': ['+15550123', '+15550123', '+15550123', '+15550123', '+15559999', 'Unknown', '+15557777'],
        'receiver_number': ['Self', 'Self', 'Self', 'Self', 'Self', 'Self', 'Self'],
        'timestamp': [
            t(1), t(1.1), t(1.2), t(1.3), # High frequency burst
            t(26), # Yesterday
            t(3), # odd hour if ran at night, strictly depends on local time vs logic, simplified here
            now + timedelta(days=1) # Future timestamp
        ],
        'duration': [120, 60, 45, 30, 0, 0, 300],
        'call_type': ['Incoming', 'Incoming', 'Incoming', 'Incoming', 'Missed', 'Missed', 'Incoming']
    }

    sms_data = {
        'sender': ['+15558888', '+15551111', '+1555Phish', 'Mom'],
        'receiver': ['Self', 'Self', 'Self', 'Self'],
        'timestamp': [t(5), t(10), t(15), t(20)],
        'message_content': [
            "Hey how are you?", 
            "URGENT! Verify your bank account now at http://bit.ly/fake", 
            "Download this free game.apk now!",
            "Call me back"
        ],
        'contains_link': [False, True, False, False]
    }

    return pd.DataFrame(call_data), pd.DataFrame(sms_data)

if __name__ == "__main__":
    # Load Data
    calls_df, sms_df = generate_sample_data()
    
    # Initialize Analyzer
    analyzer = ForensicAnalyzer(calls_df, sms_df)
    
    # Run Analysis
    report = analyzer.analyze()
    
    # Output Results
    print(json.dumps(report, indent=4, default=str))

    # Save to file for user
    with open('forensic_report.json', 'w') as f:
        json.dump(report, f, indent=4, default=str)
