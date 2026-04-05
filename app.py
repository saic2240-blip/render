from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import os

# ── ML model (loaded once at startup) ──────────────────────────
import pickle

MODEL_PATH = "model.pkl"
model = None

if os.path.exists(MODEL_PATH):
    model = pickle.load(open(MODEL_PATH, "rb"))
    print(f"[✓] ML model loaded from {MODEL_PATH}")
else:
    print(f"[!] model.pkl not found — falling back to threshold-based detection.")
    print(f"    Run: python train_model.py   to generate the model first.")

# ───────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

request_log  = {}
blocked_ips  = {}
incidents    = []

TIME_WINDOW      = 60
ATTACK_THRESHOLD = 20
BLOCK_THRESHOLD  = 30
AUTO_BLOCK       = True          # toggled via /api/toggle_block


@app.route('/log', methods=['POST'])
def log_request():
    ip  = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = datetime.now()

    # ── track request count per IP in rolling window ────────────
    if ip not in request_log:
        request_log[ip] = []

    request_log[ip] = [
        t for t in request_log[ip]
        if now - t < timedelta(seconds=TIME_WINDOW)
    ]
    request_log[ip].append(now)
    count = len(request_log[ip])

    # ── default values ──────────────────────────────────────────
    label  = "BENIGN"
    action = "ALLOWED"
    reason = "Normal traffic"

    if model:
        # ── ML prediction ────────────────────────────────────────
        # Features: [Flow Duration proxy, Total Fwd Packets proxy]
        if len(request_log[ip]) > 1:
            flow_dur = (request_log[ip][-1] - request_log[ip][0]).total_seconds() * 1000
        else:
            flow_dur = 0.0

        features   = [[flow_dur, count]]
        prediction = model.predict(features)[0]

        if prediction == 1:
            label  = "DDoS"
            action = "FLAGGED"
            reason = "ML detected anomaly"

        if prediction == 1 and count > BLOCK_THRESHOLD and AUTO_BLOCK:
            action          = "BLOCKED"
            blocked_ips[ip] = now
            reason          = "ML detected anomaly — threshold exceeded"

    else:
        # ── fallback: simple threshold detection ─────────────────
        if count > ATTACK_THRESHOLD:
            label  = "DDoS"
            action = "FLAGGED"
            reason = "High request rate"

        if count > BLOCK_THRESHOLD:
            label           = "DDoS"
            action          = "BLOCKED"
            blocked_ips[ip] = now
            reason          = "Exceeded threshold"

    confidence = min(99, count * 3)

    incidents.append({
        "timestamp":  now.strftime("%Y-%m-%d %H:%M:%S"),
        "ip":         ip,
        "label":      label,
        "action":     action,
        "confidence": confidence,
        "reason":     reason
    })

    return jsonify({"status": action})


@app.route('/api/stats')
def stats():
    total   = sum(len(v) for v in request_log.values())
    attacks = len([i for i in incidents if i["label"] == "DDoS"])
    blocked = len(blocked_ips)
    benign  = total - attacks

    return jsonify({
        "total_requests":    total,
        "attacks_detected":  attacks,
        "blocked_ips_count": blocked,
        "benign_requests":   benign,
        "recent_incidents":  incidents[-20:],
        "auto_block":        AUTO_BLOCK,
        "ml_active":         model is not None
    })


@app.route('/api/blocked')
def get_blocked():
    return jsonify({"blocked_ips": list(blocked_ips.keys())})


@app.route('/api/unblock', methods=['POST'])
def unblock():
    ip = request.json.get("ip")
    blocked_ips.pop(ip, None)
    return jsonify({"status": "unblocked"})


@app.route('/api/toggle_block', methods=['POST'])
def toggle_block():
    global AUTO_BLOCK
    AUTO_BLOCK = bool(request.json.get("status", True))
    print(f"[~] AUTO_BLOCK set to {AUTO_BLOCK}")
    return jsonify({"auto_block": AUTO_BLOCK})


if __name__ == '__main__':
    print("[*] Starting DDoS Shield backend on port 5000 ...")
    app.run(port=5000, debug=False)
