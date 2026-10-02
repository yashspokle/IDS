from datetime import datetime


def create_alert(
    prediction,
    confidence,
    source_ip,
    destination_ip
):

    severity_map = {
        "Normal": "LOW",
        "Probe": "MEDIUM",
        "DoS": "HIGH",
        "R2L": "HIGH",
        "U2R": "CRITICAL"
    }

    severity = severity_map.get(prediction, "UNKNOWN")

    alert = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "attack": prediction,
        "confidence": float(round(confidence * 100, 2)),
        "severity": severity
    }

    return alert