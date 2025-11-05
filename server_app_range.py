#!/usr/bin/env python3
# Server coordinating multi-CH range assignments and triggers

import os
import socket
import hashlib
import time
import urllib.parse
import urllib.request
from flask import Flask, jsonify, request, send_from_directory

HTTP_HOST = os.environ.get('OTA_HTTP_HOST', '0.0.0.0')
HTTP_PORT = int(os.environ.get('OTA_HTTP_PORT', '8000'))

FW_DIR  = os.environ.get('OTA_FW_DIR', os.path.join(os.getcwd(), 'OTA'))
FW_FILE = os.environ.get('OTA_FW_FILE', 'firmware.bin')

TRIGGER_PORT   = int(os.environ.get('OTA_TRIGGER_PORT', '5010'))
TRIGGER_TOKEN  = os.environ.get('OTA_TRIGGER_TOKEN', 'cdsl-ota-trigger')
API_TOKEN      = os.environ.get('OTA_API_TOKEN', 'cdsl-ota-test')

CHUNK = 200

app = Flask(__name__)
REG = {}  # key: mac or ip -> {ip, mac, role, battery, ts}


def _fw_path():
    return os.path.join(FW_DIR, FW_FILE)


def fw_info(fw_url: str | None = None):
    """Return firmware size/sha/total_chunks.

    Priority:
    1) When fw_url is provided and maps to local OTA path, read local file.
    2) When fw_url is provided and not local, fetch over HTTP and compute.
    3) Otherwise, fall back to configured FW_DIR/FW_FILE.
    """
    # Try URL-aware path first
    if fw_url:
        try:
            pu = urllib.parse.urlparse(fw_url)
            if pu.scheme in ('http', 'https') and pu.path:
                # If path looks like /OTA/<file>, try FW_DIR mapping
                base = os.path.basename(pu.path)
                if base:
                    local = os.path.join(FW_DIR, base)
                    if os.path.isfile(local):
                        with open(local, 'rb') as f:
                            h = hashlib.sha256()
                            size = 0
                            while True:
                                b = f.read(65536)
                                if not b:
                                    break
                                h.update(b)
                                size += len(b)
                        sha = h.hexdigest()[:32]
                        total_chunks = (size + CHUNK - 1) // CHUNK
                        return {'length': size, 'sha': sha, 'total_chunks': total_chunks}
                # Otherwise fetch over HTTP and compute
                with urllib.request.urlopen(fw_url, timeout=20) as resp:
                    h = hashlib.sha256()
                    size = 0
                    while True:
                        b = resp.read(65536)
                        if not b:
                            break
                        h.update(b)
                        size += len(b)
                sha = h.hexdigest()[:32]
                total_chunks = (size + CHUNK - 1) // CHUNK
                return {'length': size, 'sha': sha, 'total_chunks': total_chunks}
        except Exception as ex:
            # Fall through to local file handling; the caller may still use fw_url for CH
            app.logger.warning('fw_info: failed to fetch from fw_url=%s: %s', fw_url, ex)

    # Default: local configured file
    fpath = _fw_path()
    if not os.path.isfile(fpath):
        raise FileNotFoundError(fpath)
    h = hashlib.sha256()
    size = 0
    with open(fpath, 'rb') as f:
        while True:
            b = f.read(65536)
            if not b:
                break
            h.update(b)
            size += len(b)
    sha  = h.hexdigest()[:32]
    total_chunks = (size + CHUNK - 1) // CHUNK
    return {'length': size, 'sha': sha, 'total_chunks': total_chunks}


def tcp_trigger_line(ch_ip, line, timeout_s=5.0):
    with socket.create_connection((ch_ip, TRIGGER_PORT), timeout=timeout_s) as s:
        s.sendall(line)
        try:
            s.settimeout(2.0)
            resp = s.recv(64) or b''
        except OSError:
            resp = b''
    return resp


@app.route('/OTA/<path:fname>')
def get_fw(fname: str):
    d = os.path.abspath(FW_DIR)
    return send_from_directory(d, fname, as_attachment=False)


@app.route('/ota/register', methods=['POST'])
def register():
    auth = request.headers.get('Authorization', '')
    if auth:
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'unauthorized'}), 401
        token = auth.split(' ', 1)[1]
        if API_TOKEN and token != API_TOKEN:
            return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    ip   = data.get('ip') or request.remote_addr
    mac  = data.get('mac') or ''
    role = data.get('role') or 'UNKNOWN'
    bat  = data.get('battery')
    ts   = int(time.time())
    REG[mac or ip] = {'ip': ip, 'mac': mac, 'role': role, 'battery': bat, 'ts': ts}
    app.logger.info('REGISTER %s', REG[mac or ip])
    try:
        print(f"[REGISTER] ip={ip} mac={mac} role={role} battery={bat}")
    except Exception:
        pass
    return jsonify({'status': 'ok'})


@app.route('/ota/trigger2', methods=['POST'])
def trigger2():
    # Compute per-CH chunk assignments and send trigger lines
    data = request.get_json(silent=True) or {}
    fw_url = data.get('fw_url') or f"http://{request.host}/OTA/{FW_FILE}"
    use_range = bool(data.get('use_range', True))
    # collect CH entries
    chs = [v for v in REG.values() if v.get('role') == 'CH']
    if not chs:
        return jsonify({'error': 'no CH registered'}), 400

    # Non-range mode: just send START with URL and return
    if not use_range:
        results = []
        for c in chs:
            line = f"START {TRIGGER_TOKEN} {fw_url}\n".encode('utf-8')
            try:
                resp = tcp_trigger_line(c['ip'], line)
                results.append({'ip': c['ip'], 'resp': resp.decode(errors='ignore')})
            except Exception as ex:
                results.append({'ip': c['ip'], 'error': str(ex)})
        return jsonify({'status': 'sent', 'assignments': results, 'mode': 'single'})

    info = fw_info(fw_url)
    D = info['total_chunks']
    n = len(chs)
    # weights based on battery deviation percentage: w_i = max(0, 1 + dev/100)
    bats = []
    for c in chs:
        b = c.get('battery')
        bats.append(b if isinstance(b, (int, float)) else None)
    avg = sum(b for b in bats if b is not None)/max(1, sum(1 for b in bats if b is not None))
    weights = []
    for b in bats:
        if b is None:
            w = 1.0
        else:
            dev = (b - avg)  # percent deviation
            w = 1.0 + (dev/100.0)
            if w < 0:
                w = 0.0
        weights.append(w)
    sum_w = sum(weights) or float(n)
    # initial floor allocation and residuals
    sizes = []
    residuals = []
    total = 0
    for w in weights:
        exact = D * (w / sum_w)
        sz = int(exact)  # floor
        sizes.append(sz)
        residuals.append(exact - sz)
        total += sz
    # distribute remaining chunks by residuals (largest first)
    rem = D - total
    if rem > 0:
        order = sorted(range(n), key=lambda i: residuals[i], reverse=True)
        for i in range(rem):
            sizes[order[i % n]] += 1
    # build contiguous, non-overlapping ranges covering [0, D-1]
    ranges = []
    cur = 0
    for sz in sizes:
        if sz <= 0:
            ranges.append((cur, cur-1))  # empty range for this CH
            continue
        start = cur
        end   = cur + sz - 1
        ranges.append((start, end))
        cur = end + 1
    # assert full cover
    if cur != D:
        # fix last range to end exactly at D-1
        if ranges:
            s, _ = ranges[-1]
            ranges[-1] = (s, D-1)

    # trigger each CH with url and range
    results = []
    for c, (s,e) in zip(chs, ranges):
        # Append total CH count so CH can propagate it in M
        line = f"START {TRIGGER_TOKEN} {fw_url} {s}:{e} {n}\n".encode('utf-8')
        try:
            resp = tcp_trigger_line(c['ip'], line)
            results.append({'ip': c['ip'], 'range': [s,e], 'resp': resp.decode(errors='ignore')})
        except Exception as ex:
            results.append({'ip': c['ip'], 'range': [s,e], 'error': str(ex)})
    return jsonify({'status': 'sent', 'assignments': results, 'total_chunks': D, 'mode': 'range'})


if __name__ == '__main__':
    os.makedirs(FW_DIR, exist_ok=True)
    app.logger.info('Serving firmware from %s (file=%s)', os.path.abspath(FW_DIR), FW_FILE)
    app.run(host=HTTP_HOST, port=HTTP_PORT)
