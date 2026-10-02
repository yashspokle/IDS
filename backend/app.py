from flask import Flask, jsonify
from flask_cors import CORS
from database import get_alerts

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "message": "Intrusion Detection System API"
    })


@app.route("/api/alerts")
def alerts():
    rows = get_alerts()

    data = []

    for row in rows:
        data.append({
            "id": row[0],
            "timestamp": row[1],
            "source_ip": row[2],
            "destination_ip": row[3],
            "attack": row[4],
            "confidence": row[5],
            "severity": row[6]
        })

    return jsonify(data)


if __name__ == "__main__":
    app.run(debug=True, port=5000)