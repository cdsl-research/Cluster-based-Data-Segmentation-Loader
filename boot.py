"""
MicroPython boot script for ESP32 to run OTA CH/CM roles
- Place at device root (/)
- Create 'role.txt' with 'CH' or 'CM'
- Optional: pull SAFE_PIN low at boot to skip auto-run
"""

import machine, esp32
import time
from esp32 import Partition
import uos as os

# SAFE mode pin (tie to GND at boot to skip auto-run)
SAFE_PIN = 2
P2 = None


def _safe_mode():
    global P2
    try:
        from machine import Pin
        P2 = Pin(SAFE_PIN, Pin.OUT)
        P2.on()
        return P2.value() == 0
    except Exception:
        return False


def _read_role():
    try:
        with open('role.txt', 'r') as f:
            role = f.read().strip().upper()
            if role in ('CH', 'CM'):
                return role
    except Exception:
        pass
    return 'CM'

def cancel():
    """Always attempt to mark app valid and cancel rollback (ignore errors)."""
    try:
        if hasattr(Partition, 'mark_app_valid_cancel_rollback'):
            try:
                Partition.mark_app_valid_cancel_rollback()
                print('[BOOT] Marked app valid; rollback canceled.')
            except Exception as e:
                print('[BOOT][WARN] cancel rollback failed:', e)
    except Exception as ex:
        print('[BOOT][WARN] cancel() failed:', ex)


def _run():

    if _safe_mode():
        print('[BOOT] SAFE mode: skipping auto-start')
        return

    role = _read_role()
    # Log running partition label and firmware version
    try:
        run = Partition(Partition.RUNNING)
        info = run.info()
        label = info[4] if len(info) >= 5 else None
    except Exception:
        label = None
    try:
        u = os.uname()
        fw_ver = getattr(u, 'version', None) or getattr(u, 'release', None)
    except Exception:
        fw_ver = None
    if fw_ver is not None:
        print('[BOOT] role =', role, 'running=', label, 'fw=', fw_ver)
    else:
        print('[BOOT] role =', role, 'running=', label)

    if role == 'CH':
        try:
            import trigger_ch as app
        except Exception as ex:
            print('[BOOT][ERR] import trigger_ch:', ex)
            return
    else:
        try:
            import ota_cm as app
        except Exception as ex:
            print('[BOOT][ERR] import ota_cm:', ex)
            return

    for i in range(3, 0, -1):
        print('[BOOT] starting in', i)
        time.sleep(1)

    try:
        app.run()
    except Exception:
        raise
    finally:
        try:
            if P2 is not None and hasattr(P2, 'off'):
                P2.off()
        except Exception:
            pass


cancel()
_run()

