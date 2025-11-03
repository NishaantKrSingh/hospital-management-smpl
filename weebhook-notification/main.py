"""
Simple Webhook Receiver for Testing Hospital Alerts
Run this on a separate port to receive webhook notifications
"""

from fastapi import FastAPI, Request
from datetime import datetime
import uvicorn
import json

app = FastAPI(title="Webhook Receiver for Hospital Alerts")

# Store received alerts in memory
alerts_history = []

@app.post("/webhook/alerts")
async def receive_alert(request: Request):
    """Receive and display hospital alerts"""
    body = await request.json()
    
    # Add timestamp
    alert_data = {
        "received_at": datetime.utcnow().isoformat(),
        **body
    }
    
    alerts_history.append(alert_data)
    
    # Print alert to console
    print("\n" + "="*70)
    print("🚨 NEW HOSPITAL ALERT RECEIVED!")
    print("="*70)
    print(f"Alert Type: {body.get('alert_type', 'N/A').upper()}")
    print(f"Patient: {body.get('patient_name', 'N/A')} (ID: {body.get('patient_id', 'N/A')})")
    print(f"Condition: {body.get('condition', 'N/A')}")
    print(f"Heart Rate: {body.get('heart_rate', 'N/A')} bpm")
    print(f"Oxygen Level: {body.get('oxygen_level', 'N/A')}%")
    print(f"Timestamp: {body.get('timestamp', 'N/A')}")
    print(f"Message: {body.get('message', 'N/A')}")
    print("="*70 + "\n")
    
    return {
        "status": "received",
        "alert_id": len(alerts_history),
        "message": "Alert processed successfully"
    }

@app.get("/webhook/alerts")
async def get_alerts_history():
    """Get all received alerts"""
    return {
        "total_alerts": len(alerts_history),
        "alerts": alerts_history
    }

@app.get("/webhook/alerts/latest")
async def get_latest_alert():
    """Get the most recent alert"""
    if alerts_history:
        return alerts_history[-1]
    return {"message": "No alerts received yet"}

@app.delete("/webhook/alerts")
async def clear_alerts():
    """Clear all alerts"""
    alerts_history.clear()
    return {"message": "All alerts cleared"}

@app.get("/")
async def root():
    return {
        "service": "Hospital Alert Webhook Receiver",
        "status": "running",
        "total_alerts": len(alerts_history),
        "endpoints": {
            "receive": "POST /webhook/alerts",
            "history": "GET /webhook/alerts",
            "latest": "GET /webhook/alerts/latest",
            "clear": "DELETE /webhook/alerts"
        }
    }

if __name__ == "__main__":
    print("\n" + "="*70)
    print("  HOSPITAL ALERT WEBHOOK RECEIVER")
    print("="*70)
    print("\nStarting webhook receiver on http://localhost:8001")
    print("\nTo register this webhook in the hospital system:")
    print('  POST http://localhost:8000/api/webhooks')
    print('  Body: {"webhook_url": "http://localhost:8001/webhook/alerts"}')
    print("\nWaiting for alerts...")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8001)