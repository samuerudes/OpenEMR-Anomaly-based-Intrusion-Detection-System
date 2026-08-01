"""
Healthcare IDS Web Interface — Flask backend
Always-on live detection, session export, attack summary dashboard.
Auto-starts capture on launch.
"""
from flask import Flask, render_template, jsonify, request, send_file, Response
import os, warnings
warnings.filterwarnings('ignore')

import detector

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

# ── Page routes ────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('summary.html')

@app.route('/summary')
def summary():
    return render_template('summary.html')

@app.route('/live')
def live():
    return render_template('live.html')

# ── Live Detection API ─────────────────────────────────────────────────────────
@app.route('/api/live/status')
def live_status():
    info = detector.get_launch_info()
    return jsonify({
        'running':      detector.is_running(),
        'iface':        detector.current_iface,
        'launch_time':  info['launch_time'],
        'latest_time':  info['latest_time'],
        'total_logged': info['total_logged_flows'],
        'stats':        detector.get_stats(),
        'alerts':       detector.get_alerts()[:20],
        'settings':     detector.get_settings(),
    })

@app.route('/api/live/restart', methods=['POST'])
def restart_detection():
    iface = (request.json or {}).get('iface', 'enp0s3')
    return jsonify(detector.restart(iface))

@app.route('/api/live/settings', methods=['GET'])
def get_settings():
    return jsonify(detector.get_settings())

@app.route('/api/live/settings', methods=['POST'])
def set_settings():
    data = request.json or {}
    return jsonify(detector.update_settings(
        min_confidence=data.get('min_confidence'),
        min_flow_packets=data.get('min_flow_packets'),
    ))

# ── Session save / export ──────────────────────────────────────────────────────
@app.route('/api/live/save_session', methods=['POST'])
def save_session():
    data = request.json or {}
    return jsonify(detector.save_session(
        mode=data.get('mode', 'last_minutes'),
        minutes=data.get('minutes', 15),
        start_time=data.get('start_time'),
        end_time=data.get('end_time'),
    ))

@app.route('/api/live/sessions')
def list_sessions():
    return jsonify(detector.list_sessions())

@app.route('/api/live/session/<session_id>/download/<filetype>')
def download_session_file(session_id, filetype):
    paths = detector.get_session_paths(session_id)
    if filetype not in paths:
        return jsonify({'error': 'Invalid file type. Use pcap or csv.'}), 400
    path = paths[filetype]
    if not os.path.exists(path):
        return jsonify({'error': 'File not found'}), 404
    return send_file(path, as_attachment=True,
                     download_name=f"{session_id}_{filetype}.{filetype}")

@app.route('/api/live/export/csv')
def export_csv():
    start = request.args.get('start')
    end   = request.args.get('end')
    try:
        csv_text, rows = detector.export_csv(start, end)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    return Response(csv_text, mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename="ids_export.csv"'})

@app.route('/api/live/export/pcap')
def export_pcap():
    start = request.args.get('start')
    end   = request.args.get('end')
    try:
        path, _ = detector.export_pcap(start, end)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    if path is None:
        return jsonify({'error': 'No capture file available yet'}), 404
    return send_file(path, as_attachment=True, download_name='ids_export.pcap')

# ── Attack Summary API ─────────────────────────────────────────────────────────
@app.route('/api/live/summary')
def live_summary():
    mode    = request.args.get('mode', 'last_minutes')
    minutes = request.args.get('minutes', 15, type=float)
    start   = request.args.get('start')
    end     = request.args.get('end')
    result  = detector.get_attack_summary(mode=mode, minutes=minutes,
                                           start_time=start, end_time=end)
    if 'error' in result:
        return jsonify(result), 400
    return jsonify(result)

# ── Error handlers ─────────────────────────────────────────────────────────────
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large (max 200 MB)'}), 413

@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': f'Internal server error: {e}'}), 500

# ── Auto-start on launch ───────────────────────────────────────────────────────
def _auto_start():
    if detector.model_ready():
        result = detector.start('enp0s3')
        print(f"[Startup] {result}")
    else:
        print("[Startup] Model not trained — run train_model.py first, "
              "then POST /api/live/restart to begin capture.")

if __name__ == '__main__':
    _auto_start()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
