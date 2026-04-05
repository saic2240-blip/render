from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from datetime import datetime, timedelta
import os
import pickle

# ── ML model ────────────────────────────────────────────────
MODEL_PATH = "model.pkl"
model = None

if os.path.exists(MODEL_PATH):
    model = pickle.load(open(MODEL_PATH, "rb"))
    print(f"[OK] ML model loaded from {MODEL_PATH}")
else:
    print(f"[!] model.pkl not found — threshold-based fallback active.")

# ────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, origins="*")

request_log   = {}   # ip -> [datetime, ...]
blocked_ips   = {}   # ip -> datetime blocked
incidents     = []   # incident history

TIME_WINDOW      = 60
ATTACK_THRESHOLD = 20
BLOCK_THRESHOLD  = 30
AUTO_BLOCK       = True


def get_ip():
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def count_requests(ip):
    now = datetime.now()
    if ip not in request_log:
        request_log[ip] = []
    request_log[ip] = [t for t in request_log[ip] if now - t < timedelta(seconds=TIME_WINDOW)]
    request_log[ip].append(now)
    return len(request_log[ip])


@app.route('/')
def dashboard():
    return send_file('index.html')


@app.route('/log', methods=['POST'])
def log_request():
    ip    = get_ip()
    now   = datetime.now()
    count = count_requests(ip)

    label      = "BENIGN"
    action     = "ALLOWED"
    reason     = "Normal traffic"
    confidence = min(99, count * 3)

    if AUTO_BLOCK:
        # --- Protection ON: ML + threshold detects and BLOCKS ---
        if model and len(request_log.get(ip, [])) > 1:
            flow_dur   = (request_log[ip][-1] - request_log[ip][0]).total_seconds() * 1000
            features   = [[flow_dur, count]]
            prediction = model.predict(features)[0]

            if prediction == 1:
                label  = "DDoS"
                action = "FLAGGED"
                reason = "ML model detected anomaly"

            if prediction == 1 and count > BLOCK_THRESHOLD:
                action          = "BLOCKED"
                blocked_ips[ip] = now
                reason          = "ML detected anomaly + threshold exceeded — IP blocked"
        else:
            if count > ATTACK_THRESHOLD:
                label  = "DDoS"
                action = "FLAGGED"
                reason = "High request rate detected"
            if count > BLOCK_THRESHOLD:
                label           = "DDoS"
                action          = "BLOCKED"
                blocked_ips[ip] = now
                reason          = "Threshold exceeded — IP auto-blocked"
    else:
        # --- Protection OFF: detect only, NEVER block ---
        # Website gets flooded — requests pass through (simulates overload)
        if count > ATTACK_THRESHOLD:
            label  = "DDoS"
            action = "FLAGGED"
            reason = "Attack detected — protection is OFF, not blocking"
        if count > BLOCK_THRESHOLD:
            label  = "DDoS"
            action = "OVERLOAD"
            reason = "Server overloaded — AUTO BLOCK is OFF"

    incidents.append({
        "timestamp":  now.strftime("%Y-%m-%d %H:%M:%S"),
        "ip":         ip,
        "label":      label,
        "action":     action,
        "confidence": confidence,
        "reason":     reason
    })

    if len(incidents) > 1000:
        incidents.pop(0)

    return jsonify({"status": action, "label": label})


@app.route('/api/stats')
def stats():
    total   = sum(len(v) for v in request_log.values())
    attacks = len([i for i in incidents if i["label"] == "DDoS"])
    blocked = len(blocked_ips)
    benign  = len([i for i in incidents if i["label"] == "BENIGN"])
    ip_counts = {ip: len(times) for ip, times in request_log.items()}

    return jsonify({
        "total_requests":    total,
        "attacks_detected":  attacks,
        "blocked_ips_count": blocked,
        "benign_requests":   benign,
        "recent_incidents":  incidents[-20:],
        "auto_block":        AUTO_BLOCK,
        "ml_active":         model is not None,
        "ip_counts":         ip_counts
    })


@app.route('/api/blocked')
def get_blocked():
    return jsonify({"blocked_ips": list(blocked_ips.keys())})


@app.route('/api/unblock', methods=['POST'])
def unblock():
    data = request.json or {}
    ip   = data.get("ip")
    if ip:
        blocked_ips.pop(ip, None)
        request_log.pop(ip, None)  # reset count too
    return jsonify({"status": "unblocked", "ip": ip})


@app.route('/api/toggle_block', methods=['POST'])
def toggle_block():
    global AUTO_BLOCK
    data       = request.json or {}
    AUTO_BLOCK = bool(data.get("status", True))
    print(f"[~] AUTO_BLOCK → {AUTO_BLOCK}")
    return jsonify({"auto_block": AUTO_BLOCK})


@app.route('/api/reset', methods=['POST'])
def reset():
    global request_log, blocked_ips, incidents
    request_log = {}
    blocked_ips = {}
    incidents   = []
    print("[~] All state reset")
    return jsonify({"status": "reset"})


@app.route('/health')
def health():
    return jsonify({"status": "ok", "ml": model is not None, "auto_block": AUTO_BLOCK})


if __name__ == '__main__':
    print("[*] DDoS Shield backend starting on port 5000")
    print(f"    ML model:   {'loaded' if model else 'not found — using threshold fallback'}")
    print(f"    AUTO_BLOCK: {AUTO_BLOCK}")
    app.run(host='0.0.0.0', port=5000, debug=False)
