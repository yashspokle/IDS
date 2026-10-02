import threading
import time

from app import app
from capture_test import start_capture


def run_flask():
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
        use_reloader=False
    )


flask_thread = threading.Thread(
    target=run_flask,
    daemon=True
)

flask_thread.start()

time.sleep(2)

print("=" * 60)
print("INTRUSION DETECTION SYSTEM")
print("=" * 60)
print("Flask API: http://127.0.0.1:5000")
print("Alerts API: http://127.0.0.1:5000/api/alerts")
print("Starting live packet capture...")
print("=" * 60)

start_capture()