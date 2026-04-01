from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

request_log = {}
blocked_ips = {}
incidents = []

TIME_WINDOW = 60
ATTACK_THRESHOLD = 20
BLOCK_THRESHOLD = 30

@app.route('/log', methods=['POST'])
def log_request():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = datetime.now()

    if ip not in request_log:
        request_log[ip] = []

    request_log[ip] = [
        t for t in request_log[ip]
        if now - t < timedelta(seconds=TIME_WINDOW)
    ]

    request_log[ip].append(now)
    count = len(request_log[ip])

    label = "BENIGN"
    action = "ALLOWED"
    reason = "Normal traffic"

    if count > ATTACK_THRESHOLD:
        label = "DDoS"
        action = "FLAGGED"
        reason = "High request rate"

    if count > BLOCK_THRESHOLD:
        label = "DDoS"
        action = "BLOCKED"
        blocked_ips[ip] = now
        reason = "Exceeded threshold"

    incidents.append({
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "label": label,
        "action": action,
        "confidence": min(99, count * 3),
        "reason": reason
    })

    return jsonify({"status": action})


@app.route('/api/stats')
def stats():
    total = sum(len(v) for v in request_log.values())
    attacks = len([i for i in incidents if i["label"] == "DDoS"])
    blocked = len(blocked_ips)

    benign = total - attacks

    return jsonify({
        "total_requests": total,
        "attacks_detected": attacks,
        "blocked_ips_count": blocked,
        "benign_requests": benign,
        "recent_incidents": incidents[-20:]
    })


@app.route('/api/blocked')
def get_blocked():
    return jsonify({
        "blocked_ips": list(blocked_ips.keys())
    })


@app.route('/api/unblock', methods=['POST'])
def unblock():
    ip = request.json.get("ip")
    blocked_ips.pop(ip, None)
    return jsonify({"status": "unblocked"})


if __name__ == '__main__':
    app.run(port=5000)