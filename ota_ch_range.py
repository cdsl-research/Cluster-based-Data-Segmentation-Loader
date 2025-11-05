import time, network, espnow, urequests as rq, uhashlib as uh, ustruct as st, esp32, machine, esp

# ========== CONFIG ==========
WIFI_SSID   = ****
WIFI_PASS   = ****
FW_URL      = "http://192.168.100.84:8000/OTA/ESP32_GENERIC-OTA-20250911-v1.26.1.app-bin"
AD_URL      = "http://192.168.100.84:8000/ota/all_done"
PEERS       = [b'\x10R\x1cizD', b'x!\x84\x9d\x1b\x00', b"\xfc\xf5\xc4'\xb0T"]  # CM peers (STA MAC)
BROADCAST   = b'\xff'*6
CHUNK       = 200
ESPNOW_CHANNEL = 6  # Fixed ESP-NOW channel to use during range transfer

# Optional server notify after completion
API_TOKEN         = None

# Total CH count (range mode)
CH_TOTAL = None

# Assigned range [start, end] inclusive; if None, full image
ASSIGNED_RANGE = None

# ========== Helpers ==========

# Backward-compat alias (typo tolerance)
def _hs(b):
    return uh.sha256(b).digest()[:8]

def _split(msg):
    return (msg[0:1], msg[1:]) if msg else (b"", b"")

# M (meta)
def _pkM(total_len, sha16, ch_total, r0, r1):
    # total_len(4) + sha16(16) + ch_total(2) + r0(4) + r1(4)
    return b'M', st.pack(">I", total_len) + sha16 + st.pack(">HII", int(ch_total or 1), int(r0), int(r1))

# D (data)
def _pkD(seq, data):
    return b'D', st.pack(">HH", seq, len(data)) + _hs(data) + data

# R (range: start:uint32, end:uint32 inclusive)
    return b'D', st.pack(">HH", seq, len(data)) + _hs(data) + data

def _pkD_ack(seq):
    return b'D', st.pack(">HH", seq, 0)

# P (params)
def _pkP_total(n):
    return b'P', st.pack(">H", n)

def _unP_missing(p):
    if not p:
        return []
    cnt = p[0]
    out = []
    off = 1
    for _ in range(cnt):
        out.append(st.unpack(">H", p[off:off+2])[0])
        off += 2
    return out

def _pkP_ack(n):
    return b'P', st.pack(">H", n)

# F (status)
def _pkF_status(code):
    return b'F', st.pack(">H", code)

def _unF_status(p):
    return st.unpack(">H", p[:2])[0] if len(p) >= 2 else None

def _is_ack(expect_kind, t, p):
    if t != expect_kind:
        return False
    if t == b'M':
        # M-ACK is 2-byte short payload
        return len(p) == 2
    if t == b'D':
        if len(p) < 4:
            return False
        _, ln = st.unpack(">HH", p[:4])
        return ln == 0
    if t == b'P':
        return len(p) == 2
    if t == b'F':
        return _unF_status(p) is not None
    return False

# ========== OTA Writer ==========
BLK = 4096

class OTADirectWriter:
    def __init__(self, total_len=0, sha16=b"\x00"*16):
        self.run  = esp32.Partition(esp32.Partition.RUNNING)
        self.part = self.run.get_next_update()
        if self.part is None:
            raise OSError("No OTA update partition")
        _t, _st, addr, psize, _label, _enc = self.part.info()
        self.addr  = addr
        self.psize = psize
        self.total = total_len or psize
        self.sha16 = sha16 or b"\x00"*16
        self.h     = uh.sha256()
        self.buf   = bytearray(BLK)
        self.boff  = 0
        self.written = 0
        nblk = (self.total + BLK - 1) // BLK
        if hasattr(self.part, "erase_blocks"):
            self.part.erase_blocks(0, nblk)
        else:
            start_sector = addr // BLK
            for i in range(nblk):
                esp.flash_erase(start_sector + i)

    def write(self, data):
        mv = memoryview(data)
        self.h.update(mv)
        off = 0
        while off < len(mv):
            n = min(len(mv) - off, BLK - self.boff)
            self.buf[self.boff:self.boff+n] = mv[off:off+n]
            self.boff += n
            off += n
            if self.boff == BLK:
                bi = self.written // BLK
                self.part.writeblocks(bi, self.buf)
                self.written += BLK
                self.boff = 0

    def finalize(self):
        if self.boff:
            for i in range(self.boff, BLK):
                self.buf[i] = 0xFF
            bi = self.written // BLK
            self.part.writeblocks(bi, self.buf)
            self.written += BLK
            self.boff = 0
        ok = True
        if self.sha16 and self.sha16 != b"\x00"*16:
            ok = (self.h.digest()[:16] == self.sha16)
        return ok

    def switch_and_reboot(self):
        # Immediately set next boot partition (no marker file)
        try:
            try:
                esp32.Partition.set_boot(self.part)
            except Exception:
                runp = esp32.Partition(esp32.Partition.RUNNING)
                nxtp = runp.get_next_update()
                if nxtp:
                    esp32.Partition.set_boot(nxtp)
        except Exception:
            pass
        machine.reset()

def init(fw_url, assigned_range, ch_total=None):
    global FW_URL, ASSIGNED_RANGE, CH_TOTAL
    if fw_url:
        FW_URL = fw_url
    if assigned_range:
        ASSIGNED_RANGE = assigned_range
    if ch_total is not None:
        CH_TOTAL = ch_total

# ========== Flash read ==========
def _read_chunk_from_flash(base_addr, total_len, idx, chunk_size=CHUNK):
    off = idx * chunk_size
    if off >= total_len:
        return b""
    n = total_len - off
    if n > chunk_size:
        n = chunk_size
    buf = bytearray(n)
    try:
        esp.flash_read(base_addr + off, buf)
    except Exception:
        return b""
    return bytes(buf)

# ========== WiFi/ESP-NOW ==========
def _wifi():
    s = network.WLAN(network.STA_IF)
    if not s.active():
        print("[CH][range][WiFi] Activating STA interface")
        s.active(True)
    if not s.isconnected():
        print(f"[CH][range][WiFi] Connecting to SSID='{WIFI_SSID}")
        s.connect(WIFI_SSID, WIFI_PASS)
        t0 = time.ticks_ms()
        while not s.isconnected() and time.ticks_diff(time.ticks_ms(), t0) < 15000:
            time.sleep_ms(200)
    if s.isconnected():
        try:
            print("[CH][range][WiFi] Connected:", s.ifconfig())
        except Exception:
            pass
    if not s.isconnected():
        raise OSError("WiFi connect failed")
    return s

def _espnow():
    print("[CH][range][ESPNOW] Initializing")
    e = espnow.ESPNow(); e.active(True)
    e.add_peer(BROADCAST, channel=ESPNOW_CHANNEL)
    for i, p in enumerate(PEERS):
        try:
            e.add_peer(p, channel=ESPNOW_CHANNEL)
            print(f"[CH][range][ESPNOW] Peer added {i}: {p}")
        except Exception as ex:
            print(f"[CH][range][ESPNOW][WARN] add_peer failed {i}: {ex}")
    print(f"[CH][range][ESPNOW] Peers total: {len(PEERS)} on ch={ESPNOW_CHANNEL}")
    return e

def _await_ack(e, peer, expect_kind, timeout_ms=1000):
    h, m = e.recv(timeout_ms)
    if h != peer or not m:
        return False
    t, p = _split(m)
    return _is_ack(expect_kind, t, p)

def _send_until_ack(e, peer, payload, expect_kind, timeout_ms=1000):
    while True:
        try:
            e.send(peer, payload)
        except OSError:
            pass
        if _await_ack(e, peer, expect_kind, timeout_ms):
            break
    return True

def _send_ack_until_quiet(e, peer, ack_payload, observe_kind, quiet_ms=2000):
    # Send ACK repeatedly and wait until we observe a quiet window
    # (no further frames of observe_kind), then return.
    while True:
        try:
            e.send(peer, ack_payload)
        except OSError:
            pass
        h, m = e.recv(quiet_ms)
        if h == peer and m:
            t, p = _split(m)
            if t == observe_kind:
                continue
        elif h is None:
            break



def _send_p_total_and_handle_requests_range(e, peer, total_chunks, writer, total_len, r0, r1):
    # Send P(total) and then handle either a missing-list (treated as ACK) or finalization(F)
    pt_total, pp_total = _pkP_total(total_chunks)
    handshake_done = False
    timeout_ms = 1000
    while True:
        if not handshake_done:
            try:
                e.send(peer, pt_total + pp_total)
            except OSError:
                pass

        h, m = e.recv(timeout_ms)
        if h != peer or not m:
            continue
        t, p = _split(m)
        if t == b'P' and len(p) != 2:
            # Treat first missing-list as ACK to P(total)
            handshake_done = True
            missing = [idx for idx in _unP_missing(p) if r0 <= idx <= r1]
            if missing:
                print(f"[CH][range] Missing from {peer}: count={len(missing)} -> resend")
                pt_ack, pp_ack = _pkP_ack(50)
                _send_ack_until_quiet(e, peer, pt_ack + pp_ack, b'P')
                for idx in missing:
                    data = _read_chunk_from_flash(writer.addr, total_len, idx, CHUNK)
                    if data:
                        dt, dp = _pkD(idx, data)
                        print(f"[CH][range] Resend D seq={idx} to {peer}")
                        _send_until_ack(e, peer, dt + dp, b'D')
                        print(f"[CH][range] D-ACK seq={idx} from {peer}")
                    else:
                        print("[CH][range][WARN] requested idx out of range", idx)
                    time.sleep_ms(2)
        elif t == b'F':
            stc = _unF_status(p)
            if stc is not None:
                print(f"[CH][range] Completion(F={stc}) from {peer}. Send F-ACK until quiet...")
                ft, fp = _pkF_status(200)
                _send_ack_until_quiet(e, peer, ft + fp, b'F')
                return True
        elif t == b'P' and len(p) == 2:
            # Plain P-ACK; keep waiting for list or F
            handshake_done = True
        # other messages ignored

def run(fw_url=None, range_assign=None, ch_total=None):
    init(fw_url, range_assign, ch_total)
    r0, r1 = (range_assign or ASSIGNED_RANGE or (0, None))
    _wifi(); e = _espnow()

    # Download firmware (HTTP over WiFi)
    writer = OTADirectWriter(0, b"\x00"*16)
    h = uh.sha256(); total_len = 0
    r = rq.get(FW_URL)
    if r.status_code != 200:
        r.close(); raise OSError("HTTP {}".format(r.status_code))
    try:
        while True:
            b = r.raw.read(CHUNK)
            if not b:
                break
            writer.write(b)
            h.update(b)
            total_len += len(b)
    finally:
        r.close()
    sha16 = h.digest()[:16]
    writer.finalize()

    # After download: disconnect Wi窶詮i and anchor radio on fixed ESP窶鮮OW channel via AP_IF
    sta = network.WLAN(network.STA_IF)
    if sta.isconnected():
        print("[CH][range][WiFi] Disconnect STA before ESPNOW phase")
        sta.disconnect()
        time.sleep_ms(200)
    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    ap.config(channel=ESPNOW_CHANNEL)
    print("[CH][range][WiFi] AP channel set to", ESPNOW_CHANNEL)

    total_chunks = (total_len + CHUNK - 1) // CHUNK
    if r1 is None or r1 >= total_chunks:
        r1 = total_chunks - 1
    if r0 < 0:
        r0 = 0
    if r0 > r1:
        r0, r1 = 0, total_chunks - 1

    # Send meta M (includes CH total and assigned range)
    mt, mp = _pkM(total_len, sha16, (CH_TOTAL or len(PEERS) or 1), r0, r1)
    for p in PEERS:
        print(f"[CH][range] Send M to {p} and wait ACK")
        _send_until_ack(e, p, mt+mp, b'M')
        print(f"[CH][range] M-ACK from {p}")
    time.sleep_ms(10000)
    # Broadcast only assigned range
    for seq in range(r0, r1+1):
        data = _read_chunk_from_flash(writer.addr, total_len, seq, CHUNK)
        if not data:
            break
        dt, dp = _pkD(seq, data)
        try:
            e.send(BROADCAST, dt+dp, False)
        except OSError:
            pass
        if (seq & 63) == 0:
            print("[CH][range] sent D seq=", seq)
        time.sleep_ms(150)

    # Unicast resend/complete per peer
    for p in PEERS:
        # send total for sync; then handle only indices inside [r0,r1]
        print(f"[CH][range] Send P(total={total_chunks}) to {p}...")
        _send_p_total_and_handle_requests_range(e, p, total_chunks, writer, total_len, r0, r1)


    # Apply own update
    ok = writer.finalize()
    print("[CH][range] self finalize:", ok)
    if ok:
        # Reconnect WiFi and notify server after all CMs are complete
        _wifi()
        if AD_URL:
            try:
                print("[CH][range] Notify server:", AD_URL)
                rq.post(AD_URL, json={"ok": True}, headers={"Authorization":"Bearer "+(API_TOKEN or "")}, timeout=5).close()
            except Exception as ex:
                print("[CH][range] notify err:", ex)
        writer.switch_and_reboot()


