import sqlite3

DB_NAME = "ids.db"


def init_db():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            attack TEXT,
            confidence REAL,
            severity TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_alert(alert):
    conn = sqlite3.connect(DB_NAME)

    conn.execute("""
        INSERT INTO alerts
        (timestamp, source_ip, destination_ip, attack, confidence, severity)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert["timestamp"],
        alert["source_ip"],
        alert["destination_ip"],
        alert["attack"],
        float(alert["confidence"]),
        alert["severity"]
    ))

    conn.commit()
    conn.close()


def get_alerts():
    conn = sqlite3.connect(DB_NAME)

    cursor = conn.execute("""
        SELECT * FROM alerts
        ORDER BY id DESC
        LIMIT 100
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows