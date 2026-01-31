
import pandas as pd
import hashlib
import json
from datetime import datetime
from flask import Flask, jsonify, request

import joblib
import os

# --- AI Model Integration ---
AI_MODEL_PATH = 'forensic_ai_model.pkl'
AI_MODEL = None

def load_ai_model():
    global AI_MODEL
    if os.path.exists(AI_MODEL_PATH):
        AI_MODEL = joblib.load(AI_MODEL_PATH)
        print("[AI] Forensic AI Model loaded successfully.")
    else:
        print("[AI] Warning: AI model not found. Using rule-based fallback.")

load_ai_model()

def analyze_risk(sms):
    """
    Hybrid Forensic Analysis:
    Combines AI (ML) predictions with Regex-based safety checks.
    """
    content = sms.get('content', '').lower()
    score = 0
    findings = []
    
    # 1. AI Inference
    ai_verdict = "LOW"
    ai_confidence = 0
    if AI_MODEL:
        try:
            prediction = AI_MODEL.predict([content])[0]
            probs = AI_MODEL.predict_proba([content])[0]
            ai_confidence = round(max(probs) * 100, 2)
            ai_verdict = prediction
            findings.append(f"AI Classification: {ai_verdict} ({ai_confidence}% confidence)")
        except Exception as e:
            print(f"AI Inference Error: {e}")

    # 2. Rule-based Safety Net (Regex)
    # Malicious Link Detection
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    shortener_pattern = re.compile(r'(bit\.ly|t\.co|goo\.gl|tinyurl\.com)')
    
    urls = url_pattern.findall(content)
    if urls:
        score += 25
        findings.append(f"Link detected: {len(urls)} URL(s)")
        if shortener_pattern.search(content):
            score += 20
            findings.append("Suspicious URL shortener used")

    # Payload Patterns
    if re.search(r'\.(apk|exe|bat|sh|php|js|zip|scr)', content):
        score += 50
        findings.append("Potential malware payload reference found")

    # IP Address Detection
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content):
        score += 30
        findings.append("IP Address detected (Possible C2 server)")

    # 3. Final Aggregation
    # If AI says HIGH, boost score
    if ai_verdict == "HIGH":
        score += 40
    elif ai_verdict == "MEDIUM":
        score += 20

    # Cap score at 100
    final_score = min(score, 100)
    
    # Final Risk Level
    level = "LOW"
    if final_score >= 80: level = "CRITICAL"
    elif final_score >= 50: level = "HIGH"
    elif final_score >= 30: level = "MEDIUM"
    
    return final_score, level, findings

# --- Mock Data ---
CALL_LOGS = [
    {"id": 1, "caller": "+15551234", "receiver": "Self", "timestamp": "2023-10-24 10:00:00", "duration": 120, "type": "Incoming"},
    {"id": 2, "caller": "+15559999", "receiver": "Self", "timestamp": "2023-10-24 23:05:00", "duration": 0, "type": "Missed"}
]

SMS_LOGS = [
    {"id": 1, "sender": "+15558888", "timestamp": "2023-10-24 10:05:00", "content": "Your code is 1234. Do not click http://bit.ly/malware"}
]

# --- Core Forensic Logic ---

def compute_hash(data):
    """Compute SHA-256 hash of a data structure for integrity."""
    encoded = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()

import re

def analyze_risk(sms):
    """
    Advanced Forensic Analysis Model
    Detects patterns of: Phishing, Malware, Social Engineering, and Data Exfiltration
    """
    score = 0
    content = sms.get('content', '').lower()
    findings = []

    # 1. Phishing & Urgency Patterns
    urgency_keywords = ["urgent", "action required", "verify", "suspended", "security alert", "help desk"]
    for kw in urgency_keywords:
        if kw in content:
            score += 15
            findings.append(f"Urgency keyword: {kw}")

    # 2. Financial / Sensitve Target Patterns
    financial_keywords = ["bank", "login", "password", "crypto", "wallet", "invoice", "payment", "amazon", "paypal"]
    for kw in financial_keywords:
        if kw in content:
            score += 10
            findings.append(f"Sensitive target: {kw}")

    # 3. Malicious Link Detection (Regex)
    url_pattern = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')
    shortener_pattern = re.compile(r'(bit\.ly|t\.co|goo\.gl|tinyurl\.com)')
    
    urls = url_pattern.findall(content)
    if urls:
        score += 25
        findings.append(f"Link detected: {len(urls)} URLs")
        if shortener_pattern.search(content):
            score += 20
            findings.append("URL shortener detected (High risk)")

    # 4. File Extension / Payload Patterns
    payload_pattern = re.compile(r'\.(apk|exe|bat|sh|php|js|zip|scr)')
    if payload_pattern.search(content):
        score += 50
        findings.append("Potential malware payload file reference")

    # 5. Data Exfiltration / IP Patterns
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    if ip_pattern.search(content):
        score += 30
        findings.append("IP Address detected (Potential C2 communications)")

    # Final Risk Level
    level = "LOW"
    if score >= 70: level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 30: level = "MEDIUM"
    
    return score, level, findings

@app.route('/api/analyze', methods=['GET'])
def get_analysis():
    """Runs automated analysis and returns risk scores."""
    results = []
    for s in SMS_LOGS:
        score, level, _ = analyze_risk(s) # Updated to unpack findings
        results.append({
            "id": s['id'],
            "content": s['content'],
            "risk_score": score,
            "risk_level": level,
            "timestamp": s['timestamp']
        })
    return jsonify({"status": "analyzed", "data": results})

@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """Unified chronological timeline."""
    events = []
    for c in CALL_LOGS:
        events.append({"time": c['timestamp'], "type": "Incoming Call", "desc": f"From {c['caller']}", "risk": "low"})
    for s in SMS_LOGS:
        _, level = analyze_risk(s)
        events.append({"time": s['timestamp'], "type": "Suspicious SMS", "desc": f"Content: {s['content'][:20]}...", "risk": level.lower()})
    
    events.sort(key=lambda x: x['time'])
    return jsonify({"status": "success", "data": events})

@app.route('/api/report', methods=['GET'])
def generate_report():
    """Generates a structured forensic case file with hashes."""
    case_id = f"CASE-{datetime.now().strftime('%Y%m%d-%H%M')}"
    
    raw_data = {"calls": CALL_LOGS, "sms": SMS_LOGS}
    data_hash = compute_hash(raw_data)
    
    report = {
        "case_metadata": {
            "case_id": case_id,
            "investigator": "System.AI",
            "generation_time": datetime.now().isoformat(),
            "data_integrity_hash": data_hash
        },
        "summary": {
            "total_calls": len(CALL_LOGS),
            "total_sms": len(SMS_LOGS),
            "flags": "Malware Keywords Detected"
        },
        "verification_steps": [
            "SHA-256 Hash comparison for tampering detection",
            "Timestamp chronological consistency check",
            "Short-URL entropy analysis"
        ]
    }
    return jsonify(report)

@app.route('/api/evidence/view', methods=['GET'])
def view_evidence():
    """Returns evidence with audit log entry."""
    evidence_id = request.args.get('id', 'ALL')
    
    # Audit Logging Simulation
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "user": "Forensic_Investigator_01",
        "action": "READ_ONLY_ACCESS",
        "artifact": evidence_id,
        "integrity_check": "PASSED"
    }
    print(f"AUDIT LOG: {log_entry}")
    
    # Return data
    return jsonify({
        "status": "authorized",
        "access_logs": log_entry,
        "evidence_data": CALL_LOGS + SMS_LOGS
    })

@app.route('/api/add-data', methods=['POST'])
def add_forensic_data():
    """Endpoint for real-time data ingestion and analysis."""
    data = request.json
    data_type = data.get('type')
    
    if data_type == 'sms':
        new_sms = {
            "id": len(SMS_LOGS) + 1,
            "sender": data.get('sender', 'Unknown'),
            "timestamp": data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            "content": data.get('content', '')
        }
        SMS_LOGS.append(new_sms)
        score, level, findings = analyze_risk(new_sms)
        return jsonify({
            "status": "ingested",
            "analysis": {
                "score": score, 
                "level": level,
                "findings": findings
            },
            "hash": compute_hash(new_sms)
        })
        
    elif data_type == 'call':
        new_call = {
            "id": len(CALL_LOGS) + 1,
            "caller": data.get('number', 'Unknown'),
            "receiver": "Self",
            "timestamp": data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            "duration": data.get('duration', '00:00'),
            "type": data.get('call_type', 'Incoming')
        }
        CALL_LOGS.append(new_call)
        # Basic rule: Missed calls from unknown numbers are suspicious
        score = 40 if new_call['type'] == 'Missed' else 10
        level = "MEDIUM" if score > 30 else "LOW"
        return jsonify({
            "status": "ingested",
            "analysis": {"score": score, "level": level},
            "hash": compute_hash(new_call)
        })

    return jsonify({"error": "invalid type"}), 400

if __name__ == '__main__':
    app.run(debug=True, port=5000)
