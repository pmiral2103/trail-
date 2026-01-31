from flask import Flask, jsonify, request
from datetime import datetime
import json

app = Flask(__name__)

# --- Sample Database Data (In-Memory) ---
# In a real scenario, this would come from a SQL/NoSQL DB
CALL_LOGS = [
    {"id": 101, "caller": "+15559876543", "receiver": "Self", "timestamp": "2023-10-24 10:05:23", "duration": "12:45", "type": "Incoming"},
    {"id": 102, "caller": "+15551112222", "receiver": "Self", "timestamp": "2023-10-24 18:20:11", "duration": "00:00", "type": "Missed"},
]

SMS_LOGS = [
    {"id": 201, "sender": "+15550123456", "receiver": "Self", "timestamp": "2023-10-24 14:32:01", "content": "Meeting at 3 PM", "risk": "low"},
    {"id": 202, "sender": "Unknown", "receiver": "Self", "timestamp": "2023-10-25 09:15:00", "content": "Verify bank acc", "risk": "high"},
]

ALERTS = [
    {"id": 301, "type": "Malware", "desc": "Suspicious APK download", "timestamp": "2023-10-24 16:15:00", "score": 90}
]

# --- Helper Functions ---
def normalize_event(event, source_type):
    """Normalize different data structures into a standard Timeline Event."""
    normalized = {
        "timestamp": event["timestamp"],
        "source": source_type,
        "details": {}
    }
    
    if source_type == "call":
        normalized["title"] = f"{event['type']} Call"
        normalized["desc"] = f"From {event['caller']} ({event['duration']})"
        normalized["risk"] = "med" if event['type'] == 'Missed' else "low"
        
    elif source_type == "sms":
        normalized["title"] = "SMS Message"
        normalized["desc"] = f"{event['sender']}: {event['content']}"
        normalized["risk"] = event['risk']
        
    elif source_type == "alert":
        normalized["title"] = f"Security Alert: {event['type']}"
        normalized["desc"] = event['desc']
        normalized["risk"] = "high" if event['score'] > 70 else "med"
        
    return normalized

@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """
    API Endpoint to get reconstructed timeline.
    Query Params: start_date, end_date (optional)
    """
    timeline = []
    
    # Process Calls
    for call in CALL_LOGS:
        timeline.append(normalize_event(call, "call"))
        
    # Process SMS
    for sms in SMS_LOGS:
        timeline.append(normalize_event(sms, "sms"))
        
    # Process Alerts
    for alert in ALERTS:
        timeline.append(normalize_event(alert, "alert"))
        
    # Sort by Timestamp (Earliest -> Latest)
    # ISO format strings sort correctly lexicographically
    timeline.sort(key=lambda x: x['timestamp'])
    
    return jsonify({
        "status": "success",
        "count": len(timeline),
        "data": timeline
    })

if __name__ == '__main__':
    print("Starting Timeline API Server...")
    app.run(debug=True, port=5000)
