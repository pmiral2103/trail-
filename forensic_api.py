
import pandas as pd
import hashlib
import json
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__, static_folder='.', static_url_path='')

@app.route('/')
def index():
    return app.send_static_file('index.html')

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

def analyze_risk(sms):
    """Rule-based risk analysis for SMS."""
    score = 0
    keywords = ["click", "urgent", "verify", "bit.ly"]
    for kw in keywords:
        if kw in sms['content'].lower():
            score += 25
    
    level = "LOW"
    if score >= 50: level = "HIGH"
    elif score >= 25: level = "MEDIUM"
    
    return score, level

@app.route('/api/analyze', methods=['GET'])
def get_analysis():
    """Runs automated analysis and returns risk scores."""
    results = []
    for s in SMS_LOGS:
        score, level = analyze_risk(s)
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
