import time, espnow, network, ustruct as st, uhashlib as uh, esp32, machine, esp

# ========== CONFIG ==========
MASTER = b'\xacg\xb2*~\x89'  # CH AP MAC (any one; R and D can arrive from multiple CH if added)
CHUNK  = 200
ESPNOW_CHANNEL = 6  # Must match CH side

# ========== Helpers ==========
def _hs(b):
    return uh.sha256(b).digest()[:8]

def _split(msg):
    return (msg[0:1], msg[1:]) if msg else (b"", b"")

def _unM(p):
    total = st.unpack(">I", p[:4])[0]
    sha16 = p[4:20]
    ch_total = None
    r0 = 0
    r1 = -1
    if len(p) >= 30:
        ch_total, r0, r1 = st.unpack(">HII", p[20:30])
    return total, sha16, ch_total, r0, r1

def _pkM_ack():
    return b'M', b"\x00\x00"

def _unD(p):
    i  = st.unpack(">H", p[:2])[0]
    ln = st.unpack(">H", p[2:4])[0]
    sg = p[4:12]
    d  = p[12:12+ln]
    return i, ln, sg, d

def _pkD_ack(seq):
    return b'D', st.pack(">HH", seq, 0)

def _unP_total(p):
    return st.unpack(">H", p[:2])[0] if len(p) >= 2 else None

def _pkP_ack(n):
    return b'P', st.pack(">H", n)

def _pkP_missing(lst):
    lst = lst[:50]
    return b'P', bytes([len(lst)]) + b"".join(st.pack(">H", x) for x in lst)

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

def _pkF_status(code):
    return b'F', st.pack(">H", code)

def _is_ack(expect_kind, t, p):
    if t != expect_kind:
        return False
    if t == b'M':
        return len(p) != 20
    if t == b'D':
        if len(p) < 4:
            return False
        _, ln = st.unpack(">HH", p[:4])
        return ln == 0
    if t == b'P':
        return len(p) == 2
    if t == b'F':
        return len(p) >= 2
    return False

# ========== OTA Writer ==========
BLK = 4096

class OTARandomWriter:
    def __init__(self, total_len, sha16):
        self.run  = esp32.Partition(esp32.Partition.RUNNING)
        self.part = self.run.get_next_update()
        if self.part is None:
            raise OSError("No OTA update partition")
        _t, _st, addr, psize, _label, _enc = self.part.info()
        if total_len and total_len > psize:
            raise OSError("Image too large")
        self.addr   = addr
        self.total  = total_len or psize
        self.sha16  = sha16
        nblk = (self.total + BLK - 1) // BLK
        if hasattr(self.part, "erase_blocks"):
            self.part.erase_blocks(0, nblk)
        else:
            start_sector = addr // BLK
            for i in range(nblk):
                esp.flash_erase(start_sector + i)

    def write_at(self, seq, data):
        off = seq * CHUNK
        if off >= self.total:
            return
        n = min(len(data), self.total - off)
        ln4 = (n + 3) & ~3
        buf = bytearray(ln4)
        mv  = memoryview(buf)
        mv[:n] = data[:n]
        for i in range(n, ln4):
            buf[i] = 0xFF
        esp.flash_write(self.addr + off, buf)

    def finalize(self):
        # Verify full image by reading back and hashing
        if self.sha16 and self.sha16 != b"\x00"*16:
            h = uh.sha256()
            pos = 0
            rb = bytearray(CHUNK)
            while pos < self.total:
                n = min(CHUNK, self.total - pos)
                esp.flash_read(self.addr + pos, rb)
                h.update(memoryview(rb)[:n])
                pos += n
            return h.digest()[:16] == self.sha16
        return True

# ========== ESPNOW ==========
def _espnow():
    s = network.WLAN(network.STA_IF)
    if not s.active():
        s.active(True)
    print(s.config("mac"))
    e = espnow.ESPNow(); e.active(True)
    try:
        e.add_peer(MASTER, channel=ESPNOW_CHANNEL)
    except Exception:
        pass
    return e

def _ack_until_quiet_to(e, peer, expect_kind, ack_payload, match_seq=None, quiet_ms=2000):
    while True:
        try:
            e.send(peer, ack_payload)
            send_time = time.ticks_ms()
        except OSError:
            pass
        while time.ticks_diff(time.ticks_ms(), send_time) < quiet_ms:
            h, m = e.recv(0)
            if h == peer and m:
                t, p = _split(m)
                if t == expect_kind:
                    if match_seq is not None and t == b'D':
                        if len(p) >= 2 and st.unpack(">H", p[:2])[0] != match_seq:
                            return
                    continue
                else:
                    return
        return

def _await_ack(e, peer, expect_kind, timeout_ms=1000):
    now = time.ticks_ms()
    while time.ticks_diff(time.ticks_ms(), now) < timeout_ms:
        h, m = e.recv(0)
        if h != peer or not m:
            continue
        else:
            t, p = _split(m)
            return _is_ack(expect_kind, t, p)
    return False

def _send_until_ack(e, peer, payload, expect_kind, timeout_ms=1000):
    while True:
        try:
            e.send(peer, payload)
        except OSError:
            pass
        if _await_ack(e, peer, expect_kind, timeout_ms):
            break
    return True


def run():
    print("[CM][range] ready")
    # Anchor radio on fixed channel via AP_IF to match CH
    ap = network.WLAN(network.AP_IF)
    ap.active(True)
    ap.config(channel=ESPNOW_CHANNEL)
    try:
        print('[CM][range][WiFi] AP channel set to', ESPNOW_CHANNEL)
    except Exception:
        pass
    e = _espnow()

    writer = None
    total_len = 0
    sha16 = b"\x00"*16
    total_chunks = None
    received = None
    seen = set()  # collect seq received before we know total_chunks
    ranges = {}  # host -> (start,end)
    chs_seen = set()
    ch_total_required = 1

    while True:
        host, msg = e.recv()
        # print minimal recv host for tracing
        # print("[CM][range] recv from", host)
        if not msg:
            continue
        t, p = _split(msg)

        if t == b'M':
            total_len, sha16, ch_total, rs, re = _unM(p)
            if ch_total:
                ch_total_required = ch_total
            print(f"[CM][range] M: total_len={total_len} sha16={sha16.hex()} ch_total={ch_total_required} range=[{rs}:{re}]")
            if writer is None:
                writer = OTARandomWriter(total_len, sha16)
            ranges[host] = (rs, re)
            chs_seen.add(host)
            try:
                e.add_peer(host, channel=ESPNOW_CHANNEL)
            except Exception as ex:
                print("[CM][range][ESPNOW][WARN] add_peer host:", ex)
            mt, mp = _pkM_ack()
            print("[CM][range] Send M-ACK until quiet…")
            _ack_until_quiet_to(e, host, b'M', mt+mp, None)

        elif t == b'R':
            # R unused in new protocol; ignore
            pass

        elif t == b'D':
            seq, ln, sig, data = _unD(p)
            if ln != len(data) or _hs(data) != sig:
                continue
            if writer:
                writer.write_at(seq, data)
            if (seq & 63) == 0:
                print("[CM][range] got D seq=", seq)
            if received is not None and 0 <= seq < len(received):
                received[seq] = 1
            else:
                seen.add(seq)

        elif t == b'P':
            tot = _unP_total(p)
            if tot is None:
                continue
            total_chunks = tot
            if len(chs_seen) < ch_total_required:
                # Wait for all CH to announce via M before repair/finalize
                continue
            if received is None:
                received = bytearray(total_chunks)
                # mark previously seen seqs
                for s in seen:
                    if 0 <= s < total_chunks:
                        received[s] = 1
                seen.clear()
            # Iterate until this host's assigned range is complete
            while True:
                # Build missing list within this host's assigned range only
                rs, re = ranges.get(host, (0, -1))
                if re < 0 and total_chunks is not None:
                    re = total_chunks - 1
                rs = max(0, rs); re = min(re, total_chunks - 1)
                batch = []
                if re >= rs:
                    for i in range(rs, re + 1):
                        if not received[i]:
                            batch.append(i)
                            if len(batch) >= 50:
                                break
                if not batch:
                    # inform this CH that its assigned range is complete
                    ft, fp = _pkF_status(1)
                    print(f"[CM][range] Range complete for {host}. Send F until ACK…")
                    stop_at = time.ticks_ms() + 800
                    while time.ticks_diff(stop_at, time.ticks_ms()) > 0:
                        try:
                            e.send(host, ft+fp)
                        except OSError:
                            pass
                        h2, m2 = e.recv(400)
                        if h2 == host and m2:
                            t2, p2 = _split(m2)
                            if _is_ack(b'F', t2, p2):
                                break
                    # If all chunks received globally, finalize and reboot
                    if received is not None and total_chunks is not None and all(received[:total_chunks]):
                        ok = writer.finalize() if writer else False
                        if ok:
                            print("[CM][range] Finalize OK. Rebooting…")
                            # Immediately set next boot partition (no marker file)
                            try:
                                try:
                                    esp32.Partition.set_boot(writer.part)
                                except Exception:
                                    runp = esp32.Partition(esp32.Partition.RUNNING)
                                    nxtp = runp.get_next_update()
                                    if nxtp:
                                        esp32.Partition.set_boot(nxtp)
                            except Exception as ex:
                                print('[CM][range][WARN] set_boot failed:', ex)
                            import machine
                            machine.reset()
                        else:
                            print('[CM][range][ERROR] SHA verification failed. Not rebooting.')
                    break
                # send missing
                ptm, ppm = _pkP_missing(batch)
                print(f"[CM][range] Send missing size={len(batch)} first={batch[0]} last={batch[-1]}")
                _send_until_ack(e, host, ptm+ppm, b'P')
                # accept D repairs for this batch
                pending = set(batch)
                while len(pending):
                    h2, m2 = e.recv()
                    if h2 == host and m2:
                        t2, p2 = _split(m2)
                        if t2 == b'D':
                            s2, ln2, sg2, d2 = _unD(p2)
                            if ln2 == len(d2) and _hs(d2) == sg2:
                                if writer:
                                    writer.write_at(s2, d2)
                                if received is not None and 0 <= s2 < len(received):
                                    received[s2] = 1
                                if s2 in pending:
                                    pending.discard(s2)
                                dt2, dp2 = _pkD_ack(s2)
                                _ack_until_quiet_to(e, host, b'D', dt2+dp2, s2)

