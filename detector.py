"""
Live detection engine — runs continuously in the background from the
moment the Flask app starts. Every processed flow is appended to an
in-memory log and also written to a rolling pcap. Attack-flagged flows
are tagged with a heuristic attack_type and severity for the dashboard
and Telegram alerts. Saving a session snapshots a chosen timeframe
from the running log without interrupting ongoing capture.
"""
import threading
import time
import subprocess
import tempfile
import requests
import numpy as np
import pandas as pd
import joblib
import os
from collections import defaultdict
from datetime import datetime
from io import StringIO

try:
    from scapy.all import sniff, IP, TCP, UDP, PcapWriter
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

BASE_DIR        = os.path.dirname(__file__)
SESSIONS_DIR    = os.path.join(BASE_DIR, 'sessions')
CONTINUOUS_DIR  = os.path.join(BASE_DIR, 'continuous')
CONTINUOUS_PCAP = os.path.join(CONTINUOUS_DIR, 'capture.pcap')
MODEL_DIR       = os.path.join(BASE_DIR, 'model')
os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(CONTINUOUS_DIR, exist_ok=True)

# ── Telegram ──────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = '8252145983:AAGdh-At4ixinqnEPsnYmjlEyIrsxpWg3PM'
TELEGRAM_CHAT_ID = '6518084073'
TELEGRAM_URL     = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'

def send_telegram(message: str):
    try:
        requests.post(TELEGRAM_URL, json={
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'HTML'
        }, timeout=5)
    except Exception as e:
        print(f"[Telegram] Error: {e}")

# ── Model ─────────────────────────────────────────────────────────────────────
def load_model():
    rf       = joblib.load(os.path.join(MODEL_DIR, 'rf_model.pkl'))
    scaler   = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
    features = joblib.load(os.path.join(MODEL_DIR, 'features.pkl'))
    return rf, scaler, features

def model_ready():
    return os.path.exists(os.path.join(MODEL_DIR, 'rf_model.pkl'))

# ── Config (mutable at runtime) ────────────────────────────────────────────────
_settings_lock = threading.Lock()
settings = {
    'min_confidence':   70.0,
    'min_flow_packets': 3,
}

def get_settings():
    with _settings_lock:
        return dict(settings)

def update_settings(min_confidence=None, min_flow_packets=None):
    with _settings_lock:
        if min_confidence is not None:
            settings['min_confidence'] = max(0.0, min(100.0, float(min_confidence)))
        if min_flow_packets is not None:
            settings['min_flow_packets'] = max(1, int(min_flow_packets))
        return dict(settings)

# ── Shared state ──────────────────────────────────────────────────────────────
alerts        = []
stats         = {'total': 0, 'attacks': 0, 'normal': 0}
running       = False
launch_time   = None
latest_time   = None
current_iface = None

_lock         = threading.Lock()
_flows        = defaultdict(list)
_flow_lock    = threading.Lock()

_records_lock = threading.Lock()
_all_records  = []

_pcap_writer  = None
_sniff_t      = None
_process_t    = None

# ── Attack classification ─────────────────────────────────────────────────────
SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

SEVERITY_BY_TYPE = {
    'DDoS / Flood':                 'critical',
    'Data Exfiltration':            'critical',
    'DNS Tunneling / Exfiltration': 'high',
    'Brute Force / Auth Attempt':   'high',
    'Slow DoS (Slowloris-style)':   'high',
    'Port Scan / Probe':            'medium',
    'Other Anomaly':                'low',
}

def _severity_for(attack_type, confidence):
    base = SEVERITY_BY_TYPE.get(attack_type, 'low')
    if confidence < 80:
        idx = max(SEVERITY_ORDER.index(base) - 1, 0)
        return SEVERITY_ORDER[idx]
    return base

def _classify_attack_type(record):
    """
    Heuristic attack categorisation based on observed flow statistics
    from the captured dataset. Only runs on flows already confirmed as
    attacks by the Random Forest model.

    Key observations from dataset statistics:
    - 75th percentile of attack mean_packet_size = 60 bytes (pure SYN probes)
    - Median attack pps = 8,692  /  normal pps = 2,621
    - Nmap SYN flows: 2 packets, 60-byte mean, sub-ms duration
    - Hydra brute-force: port 80, HTTP payload (>60 bytes), short duration
    - Dirb enumeration: port 80, larger packets, low-medium rate
    - Data exfiltration: large total_bytes (>5000), duration > 0.5s
    - DDoS/flood: very high pps (>50000) or very high bps (>10M)
    - DNS tunneling: UDP port 53
    - Slowloris: long duration (>15s), very low pps (<5)
    """
    pps      = record.get('packets_per_second', 0)
    bps      = record.get('bytes_per_second', 0)
    total_b  = record.get('total_bytes', 0)
    total_p  = record.get('total_packets', 0)
    mean_sz  = record.get('mean_packet_size', 0)
    duration = record.get('flow_duration', 0)
    dst_port = record.get('dst_port')
    protocol = record.get('protocol')

    # 1. DNS tunneling — UDP/53 regardless of other features
    if protocol == 'UDP' and dst_port == 53:
        return 'DNS Tunneling / Exfiltration'

    # 2. Volumetric flood — pps or bps far exceeding any normal flow
    #    Normal 75th pct pps = 2,954 — set threshold well above that
    if pps > 50000 or bps > 10_000_000:
        return 'DDoS / Flood'

    # 3. Slowloris-style — very long lived, near-zero packet rate
    if duration > 15 and pps < 5:
        return 'Slow DoS (Slowloris-style)'

    # 4. Data exfiltration — substantial data transfer over a sustained flow
    #    Normal 75th pct total_bytes = 608, attack 75th = 120
    #    Large sustained flows stand out clearly
    if total_b > 5000 and duration > 0.5:
        return 'Data Exfiltration'

    # 5. Pure SYN probe signature — Nmap SYN scan produces 2-packet flows
    #    with exactly 60-byte packets (bare TCP SYN, no payload)
    #    75th pct of attack mean_packet_size = 60 bytes exactly
    if mean_sz <= 64 and total_p <= 4 and duration < 1.0:
        return 'Port Scan / Probe'

    # 6. HTTP brute-force — application-layer, port 80/443, carries HTTP
    #    payload so slightly larger than bare SYN, short individual flows
    if dst_port in (80, 443, 8080) and mean_sz > 64 and duration < 5.0:
        return 'Brute Force / Auth Attempt'

    # 7. General enumeration / scanning — elevated rate but not flood-level
    #    Attack median pps = 8,692 vs normal median = 2,621
    #    Use 5,000 as the dividing line (above normal 75th pct of 2,954)
    if pps > 5000:
        return 'Port Scan / Probe'

    # 8. Low-rate anomalous flows on HTTP — likely slow enumeration (Dirb)
    if dst_port in (80, 443, 8080):
        return 'Brute Force / Auth Attempt'

    # 9. Fallback — RF flagged it but no specific signature matched
    return 'Other Anomaly'

# ── Feature extraction ────────────────────────────────────────────────────────
def _flow_features(pkts):
    lengths    = [p['length'] for p in pkts]
    timestamps = sorted([p['timestamp'] for p in pkts])
    iats       = np.diff(timestamps)
    dur        = timestamps[-1] - timestamps[0]
    feats = {
        'flow_duration':      dur,
        'total_packets':      len(pkts),
        'total_bytes':        sum(lengths),
        'mean_packet_size':   float(np.mean(lengths)),
        'std_packet_size':    float(np.std(lengths)),
        'min_packet_size':    min(lengths),
        'max_packet_size':    max(lengths),
        'mean_iat':           float(np.mean(iats))  if len(iats) > 0 else 0,
        'std_iat':            float(np.std(iats))   if len(iats) > 0 else 0,
        'min_iat':            float(min(iats))      if len(iats) > 0 else 0,
        'max_iat':            float(max(iats))      if len(iats) > 0 else 0,
        'bytes_per_second':   sum(lengths) / (dur + 1e-9),
        'packets_per_second': len(pkts)    / (dur + 1e-9),
    }
    return feats, timestamps[-1]

# ── Packet callback ───────────────────────────────────────────────────────────
def _packet_callback(pkt):
    global _pcap_writer
    if _pcap_writer is not None:
        try:
            _pcap_writer.write(pkt)
        except Exception:
            pass
    if not pkt.haslayer(IP):
        return
    if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)):
        return
    proto    = 'TCP' if pkt.haslayer(TCP) else 'UDP'
    src      = pkt[IP].src
    dst      = pkt[IP].dst
    sp       = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
    dp       = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
    flow_key = tuple(sorted([(src, sp), (dst, dp)]) + [proto])
    with _flow_lock:
        _flows[flow_key].append({
            'timestamp': float(pkt.time),
            'length':    len(pkt),
            'src': src, 'dst': dst,
            'src_port': sp, 'dst_port': dp, 'proto': proto
        })

# ── Flow processor (every 10 s) ───────────────────────────────────────────────
def _process_flows(rf, scaler, features):
    global latest_time
    with _flow_lock:
        flows_copy = dict(_flows)
        _flows.clear()

    cfg = get_settings()
    for flow_key, pkts in flows_copy.items():
        if len(pkts) < cfg['min_flow_packets']:
            continue
        feat_dict, flow_end_ts = _flow_features(pkts)
        X        = np.array([[feat_dict.get(f, 0) for f in features]])
        X_scaled = scaler.transform(X)
        pred     = rf.predict(X_scaled)[0]
        proba    = rf.predict_proba(X_scaled)[0]
        conf     = round(float(max(proba)) * 100, 1)
        is_atk   = (pred == 1 and conf >= cfg['min_confidence'])

        attack_type = None
        severity    = None

        record = dict(feat_dict)
        record.update({
            'timestamp':  flow_end_ts,
            'src_ip':     pkts[0]['src'],
            'dst_ip':     pkts[0]['dst'],
            'src_port':   pkts[0]['src_port'],
            'dst_port':   pkts[0]['dst_port'],
            'protocol':   pkts[0]['proto'],
            'confidence': conf,
            'label':      'attack' if is_atk else 'normal',
        })

        if is_atk:
            attack_type = _classify_attack_type(record)
            severity    = _severity_for(attack_type, conf)

        record['attack_type'] = attack_type
        record['severity']    = severity

        with _records_lock:
            _all_records.append(record)

        with _lock:
            stats['total'] += 1
            latest_time = datetime.fromtimestamp(flow_end_ts)
            if is_atk:
                stats['attacks'] += 1
                alert = {
                    'time':        latest_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src_ip':      record['src_ip'],
                    'dst_ip':      record['dst_ip'],
                    'src_port':    record['src_port'],
                    'dst_port':    record['dst_port'],
                    'protocol':    record['protocol'],
                    'confidence':  conf,
                    'packets':     len(pkts),
                    'bytes':       int(sum(p['length'] for p in pkts)),
                    'pps':         round(feat_dict['packets_per_second'], 1),
                    'attack_type': attack_type,
                    'severity':    severity,
                }
                alerts.insert(0, alert)
                if len(alerts) > 100:
                    alerts.pop()

                msg = (
                    f"<b>HEALTHCARE IDS ALERT</b>\n\n"
                    f"Time: {alert['time']}\n"
                    f"Source: {alert['src_ip']}:{alert['src_port']}\n"
                    f"Target: {alert['dst_ip']}:{alert['dst_port']}\n"
                    f"Protocol: {alert['protocol']}\n"
                    f"Attack Type: {attack_type}\n"
                    f"Severity: {severity.upper()}\n"
                    f"Packets: {alert['packets']} ({alert['pps']} pkt/s)\n"
                    f"Bytes: {alert['bytes']}\n"
                    f"Confidence: {conf}%"
                )
                threading.Thread(target=send_telegram, args=(msg,), daemon=True).start()
            else:
                stats['normal'] += 1

# ── Background threads ─────────────────────────────────────────────────────────
def _sniff_thread(iface):
    sniff(iface=iface, prn=_packet_callback,
          store=False, stop_filter=lambda _: not running)

def _process_thread(rf, scaler, features):
    while running:
        time.sleep(10)
        if running:
            _process_flows(rf, scaler, features)

# ── Capture control ────────────────────────────────────────────────────────────
def start(iface='enp0s3'):
    global running, _sniff_t, _process_t, _pcap_writer, launch_time, current_iface
    if running:
        return {'status': 'already_running', 'iface': current_iface}
    if not model_ready():
        return {'error': 'Model not trained yet. Run train_model.py first.'}
    rf, scaler, features = load_model()
    _pcap_writer = PcapWriter(CONTINUOUS_PCAP,
                               append=os.path.exists(CONTINUOUS_PCAP), sync=True)
    if launch_time is None:
        launch_time = datetime.now()
    current_iface = iface
    running = True
    _sniff_t   = threading.Thread(target=_sniff_thread,   args=(iface,),              daemon=True)
    _process_t = threading.Thread(target=_process_thread, args=(rf, scaler, features), daemon=True)
    _sniff_t.start()
    _process_t.start()
    print(f"[Detector] Started on {iface}")
    return {'status': 'started', 'iface': iface,
            'launch_time': launch_time.strftime('%Y-%m-%dT%H:%M:%S')}

def _stop_internal():
    global running, _pcap_writer
    if not running:
        return
    running = False
    time.sleep(1.5)
    if _pcap_writer is not None:
        try:
            _pcap_writer.close()
        except Exception:
            pass
        _pcap_writer = None

def restart(iface='enp0s3'):
    _stop_internal()
    return start(iface)

def is_running():
    return running

def get_launch_info():
    return {
        'launch_time':       launch_time.strftime('%Y-%m-%dT%H:%M:%S') if launch_time else None,
        'latest_time':       latest_time.strftime('%Y-%m-%dT%H:%M:%S') if latest_time else None,
        'total_logged_flows': len(_all_records),
    }

def get_alerts():
    with _lock:
        return list(alerts)

def get_stats():
    with _lock:
        return dict(stats)

# ── Time-window helpers ─────────────────────────────────────────────────────────
def _resolve_mode_window(mode='last_minutes', minutes=15, start_time=None, end_time=None):
    now_ts = time.time()
    if mode == 'last_minutes':
        return now_ts - (float(minutes) * 60), now_ts
    elif mode == 'since_launch':
        return (launch_time.timestamp() if launch_time else 0), now_ts
    elif mode == 'custom':
        return datetime.fromisoformat(start_time).timestamp(), \
               datetime.fromisoformat(end_time).timestamp()
    raise ValueError(f'Unknown mode: {mode}')

def _filter_records(start_ts, end_ts):
    with _records_lock:
        return [r for r in _all_records if start_ts <= r['timestamp'] <= end_ts]

def export_csv(start=None, end=None):
    start_ts, end_ts = _resolve_mode_window('since_launch') if not start else \
                       (datetime.fromisoformat(start).timestamp(),
                        datetime.fromisoformat(end).timestamp())
    subset = _filter_records(start_ts, end_ts)
    df  = pd.DataFrame(subset)
    buf = StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue(), len(df)

def export_pcap(start=None, end=None):
    start_ts, end_ts = _resolve_mode_window('since_launch') if not start else \
                       (datetime.fromisoformat(start).timestamp(),
                        datetime.fromisoformat(end).timestamp())
    if not os.path.exists(CONTINUOUS_PCAP):
        return None, 0
    tmp_dir  = tempfile.mkdtemp(prefix='ids_export_')
    out_path = os.path.join(tmp_dir, 'export.pcap')
    start_str = datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S')
    end_str   = datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S')
    try:
        subprocess.run(['editcap', '-A', start_str, '-B', end_str,
                        CONTINUOUS_PCAP, out_path],
                       check=True, capture_output=True, timeout=180)
        return (out_path, 0) if os.path.exists(out_path) else (None, 0)
    except Exception as e:
        print(f"[Detector] editcap error: {e}")
        return None, 0

# ── Persistent sessions ────────────────────────────────────────────────────────
def save_session(mode='last_minutes', minutes=15, start_time=None, end_time=None):
    try:
        start_ts, end_ts = _resolve_mode_window(mode, minutes, start_time, end_time)
    except Exception as e:
        return {'error': str(e)}
    if start_ts >= end_ts:
        return {'error': 'Start time must be before end time'}
    subset = _filter_records(start_ts, end_ts)
    if not subset:
        return {'error': 'No flows recorded in that timeframe yet.'}
    session_id  = datetime.now().strftime('%Y%m%d_%H%M%S')
    session_dir = os.path.join(SESSIONS_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)
    csv_path = os.path.join(session_dir, 'session_dataset.csv')
    df = pd.DataFrame(subset)
    df.to_csv(csv_path, index=False)
    pcap_path = os.path.join(session_dir, 'session.pcap')
    pcap_ok   = False
    if os.path.exists(CONTINUOUS_PCAP):
        try:
            s_str = datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S')
            e_str = datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S')
            subprocess.run(['editcap', '-A', s_str, '-B', e_str,
                            CONTINUOUS_PCAP, pcap_path],
                           check=True, capture_output=True, timeout=180)
            pcap_ok = os.path.exists(pcap_path)
        except Exception:
            pass
    lc = df['label'].value_counts().to_dict() if 'label' in df.columns else {}
    return {
        'session_id':     session_id,
        'window_start':   datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S'),
        'window_end':     datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S'),
        'total_flows':    len(df),
        'normal_flows':   int(lc.get('normal', 0)),
        'attack_flows':   int(lc.get('attack', 0)),
        'pcap_available': pcap_ok,
    }

def list_sessions():
    out = []
    if not os.path.exists(SESSIONS_DIR):
        return out
    for sid in sorted(os.listdir(SESSIONS_DIR), reverse=True):
        sdir     = os.path.join(SESSIONS_DIR, sid)
        csv_path = os.path.join(sdir, 'session_dataset.csv')
        if not os.path.isdir(sdir):
            continue
        entry = {'session_id': sid,
                 'has_csv':  os.path.exists(csv_path),
                 'has_pcap': os.path.exists(os.path.join(sdir, 'session.pcap'))}
        if entry['has_csv']:
            try:
                df   = pd.read_csv(csv_path)
                dist = df['label'].value_counts().to_dict() if 'label' in df.columns else {}
                entry['total_flows']  = len(df)
                entry['normal_flows'] = int(dist.get('normal', 0))
                entry['attack_flows'] = int(dist.get('attack', 0))
            except Exception:
                pass
        out.append(entry)
    return out

def get_session_paths(session_id):
    sdir = os.path.join(SESSIONS_DIR, session_id)
    return {
        'csv':  os.path.join(sdir, 'session_dataset.csv'),
        'pcap': os.path.join(sdir, 'session.pcap'),
    }

# ── Attack Summary ─────────────────────────────────────────────────────────────
def get_attack_summary(mode='last_minutes', minutes=15, start_time=None, end_time=None, buckets=12):
    try:
        start_ts, end_ts = _resolve_mode_window(mode, minutes, start_time, end_time)
    except Exception as e:
        return {'error': str(e)}
    if start_ts >= end_ts:
        return {'error': 'Start time must be before end time'}

    subset  = _filter_records(start_ts, end_ts)
    attacks = [r for r in subset if r.get('label') == 'attack']
    normals = [r for r in subset if r.get('label') == 'normal']

    empty = {
        'window_start': datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S'),
        'window_end':   datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S'),
        'total_flows': 0, 'attack_flows': 0, 'normal_flows': 0,
        'unique_attackers': 0, 'unique_targets': 0, 'total_attack_bytes': 0,
        'avg_confidence': 0,
        'type_breakdown': {}, 'severity_breakdown': {}, 'protocol_breakdown': {},
        'top_sources': [], 'top_targets': [], 'top_ports': [],
        'recent_critical': [], 'timeline': [], 'bucket_seconds': 0,
    }
    if not subset:
        return empty

    from collections import Counter
    type_counts     = Counter(r.get('attack_type', 'Other Anomaly') for r in attacks)
    severity_counts = Counter(r.get('severity',    'low')            for r in attacks)
    protocol_counts = Counter(r.get('protocol',    'UNKNOWN')        for r in subset)
    src_counter     = Counter(r['src_ip']                             for r in attacks)
    dst_counter     = Counter(f"{r['dst_ip']}:{r['dst_port']}"       for r in attacks)
    port_counter    = Counter(r['dst_port']                           for r in attacks)

    bucket_width = max((end_ts - start_ts) / buckets, 1)
    timeline = [0] * buckets
    for r in attacks:
        idx = min(int((r['timestamp'] - start_ts) / bucket_width), buckets - 1)
        timeline[max(idx, 0)] += 1

    avg_conf = round(sum(r.get('confidence', 0) for r in attacks) / len(attacks), 1) if attacks else 0

    hp = sorted([r for r in attacks if r.get('severity') in ('critical', 'high')],
                key=lambda r: r['timestamp'], reverse=True)
    recent_critical = [{
        'time':        datetime.fromtimestamp(r['timestamp']).strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip':      r['src_ip'], 'src_port': r['src_port'],
        'dst_ip':      r['dst_ip'], 'dst_port': r['dst_port'],
        'protocol':    r['protocol'],
        'attack_type': r.get('attack_type'),
        'severity':    r.get('severity'),
        'confidence':  r.get('confidence'),
        'total_bytes': r.get('total_bytes'),
        'pps':         round(r.get('packets_per_second', 0), 1),
    } for r in hp[:15]]

    return {
        'window_start':       datetime.fromtimestamp(start_ts).strftime('%Y-%m-%d %H:%M:%S'),
        'window_end':         datetime.fromtimestamp(end_ts).strftime('%Y-%m-%d %H:%M:%S'),
        'total_flows':        len(subset),
        'attack_flows':       len(attacks),
        'normal_flows':       len(normals),
        'unique_attackers':   len(src_counter),
        'unique_targets':     len(dst_counter),
        'total_attack_bytes': int(sum(r.get('total_bytes', 0) for r in attacks)),
        'avg_confidence':     avg_conf,
        'type_breakdown':     dict(type_counts),
        'severity_breakdown': dict(severity_counts),
        'protocol_breakdown': dict(protocol_counts),
        'top_sources':  [{'ip': ip, 'count': c} for ip, c in src_counter.most_common(10)],
        'top_targets':  [{'target': t, 'count': c} for t, c in dst_counter.most_common(10)],
        'top_ports':    [{'port': p, 'count': c} for p, c in port_counter.most_common(10)],
        'recent_critical': recent_critical,
        'timeline':         timeline,
        'bucket_seconds':   round(bucket_width, 1),
    }
