#!/usr/bin/env python3
"""Receive-only beacon watcher. Python standard library; no packet injection."""
import argparse
import collections
import fcntl
import json
import os
from pathlib import Path
import queue
import selectors
import signal
import struct
import subprocess
import threading
import time


def has_one_trailing_unicode_character(candidate_hex, trusted_hex):
    """True when candidate is trusted SSID plus exactly one UTF-8 character."""
    try:
        candidate = bytes.fromhex(candidate_hex).decode('utf-8', 'strict')
        trusted = bytes.fromhex(trusted_hex).decode('utf-8', 'strict')
    except (ValueError, UnicodeDecodeError):
        return False
    return bool(trusted) and len(candidate) == len(trusted) + 1 and candidate[:-1] == trusted


def security_ie(data):
    """Canonical RSN/WPA suites, ignoring PMKID lists and replay counters."""
    if len(data) < 8 or data[:2] != b'\x01\x00':
        raise ValueError('Invalid RSN/WPA version')
    group = data[2:6].hex()
    pos = 6
    lists = []
    for _ in range(2):
        count = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        if not count or pos + 4 * count > len(data):
            raise ValueError('Truncated suite list')
        lists.append(sorted(set(data[i:i+4].hex() for i in range(pos, pos+4*count, 4))))
        pos += 4 * count
    if len(data) == pos + 1:
        raise ValueError('Truncated capabilities')
    caps = struct.unpack_from('<H', data, pos)[0] if len(data) >= pos+2 else 0
    # PMF required/capable bits. Other capabilities vary without changing crypto.
    return [group, lists[0], lists[1], caps & 0xc0]


def decode(packet):
    """Return (BSSID, raw SSID hex, security fingerprint, dBm) or None."""
    try:
        if len(packet) < 8 or packet[0] != 0:
            return None
        length, present = struct.unpack_from('<HI', packet, 2)
        if length > len(packet) or length < 8:
            return None
        pos, word = 8, present
        while word & (1 << 31):
            if pos + 4 > length:
                return None
            word = struct.unpack_from('<I', packet, pos)[0]
            pos += 4
        flags, rssi = 0, None
        for bit, (align, size) in enumerate([(8, 8), (1, 1), (1, 1), (2, 4), (2, 2), (1, 1)]):
            if present & (1 << bit):
                pos += (-pos) % align
                if pos + size > length:
                    return None
                if bit == 1:
                    flags = packet[pos]
                if bit == 5:
                    rssi = struct.unpack_from('b', packet, pos)[0]
                pos += size
        if rssi is None or not -127 <= rssi < 0 or flags & 0x40:
            return None
        frame = packet[length:]
        if flags & 0x10:
            frame = frame[:-4]  # FCS is not an information element.
        if len(frame) < 36 or frame[0] != 0x80:
            return None
        mac = frame[16:22]
        if mac[0] & 1 or mac == b'\x00' * 6:
            return None
        bssid = ':'.join('%02x' % b for b in mac)
        privacy = bool(struct.unpack_from('<H', frame, 34)[0] & 0x10)
        pos, ssid, crypto = 36, None, []
        while pos < len(frame):
            if pos + 2 > len(frame):
                return None
            tag, size = frame[pos:pos+2]
            pos += 2
            value = frame[pos:pos+size]
            if len(value) != size:
                return None
            pos += size
            if tag == 0:
                if ssid is not None or size > 32:
                    return None
                ssid = value.hex() if value.strip(b'\x00') else ''
            elif tag == 48:
                crypto.append(['RSN', security_ie(value)])
            elif tag == 221 and value[:4] == b'\x00\x50\xf2\x01':
                crypto.append(['WPA', security_ie(value[4:])])
        if ssid is None:
            return None
        security = json.dumps(sorted(crypto), separators=(',', ':')) if crypto else ('PRIVACY_UNKNOWN' if privacy else 'OPEN')
        return bssid, ssid, security, rssi
    except (ValueError, struct.error, IndexError):
        return None


class PcapStream:
    def __init__(self):
        self.buffer = bytearray()
        self.endian = None

    def feed(self, data):
        self.buffer.extend(data)
        if self.endian is None:
            if len(self.buffer) < 24:
                return []
            magic = bytes(self.buffer[:4])
            orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
                      b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}
            if magic not in orders:
                raise ValueError('Expected classic PCAP stream')
            self.endian = orders[magic]
            link = struct.unpack_from(self.endian+'I', self.buffer, 20)[0] & 0xffff
            if link != 127:
                raise ValueError('Capture lacks radiotap (link type 127); RSSI unavailable')
            del self.buffer[:24]
        packets = []
        while len(self.buffer) >= 16:
            size = struct.unpack_from(self.endian+'I', self.buffer, 8)[0]
            if size > 65535:
                raise ValueError('Invalid capture record length')
            if len(self.buffer) < 16 + size:
                break
            packets.append(bytes(self.buffer[16:16+size]))
            del self.buffer[:16+size]
        return packets


class Detector:
    def __init__(self, baseline, start, threshold=-80, count=3, window=15, cooldown=300):
        self.baseline = baseline
        self.learning = baseline is None
        if baseline is None:
            self.baseline = {}
        self.start, self.threshold = start, threshold
        self.count, self.window, self.cooldown = count, window, cooldown
        self.samples, self.last_seen, self.pending, self.alarms = {}, {}, {}, {}
        self.ready = False

    def tick(self, now):
        if not self.ready and now - self.start >= 60:
            self.ready = True
            self.learning = False
            self.samples.clear()
            return True
        # Bound session state by time; persistent baseline remains unchanged.
        for key in list(self.samples):
            if now - self.samples[key][-1] > self.window:
                del self.samples[key]
        for bssid in list(self.last_seen):
            if now - self.last_seen[bssid] > 3600:
                del self.last_seen[bssid]
                self.pending.pop(bssid, None)
        for key in list(self.alarms):
            if now - self.alarms[key] >= self.cooldown:
                del self.alarms[key]
        return False

    def observe(self, obs, now):
        bssid, ssid, security, rssi = obs
        previous = self.last_seen.get(bssid)
        if previous is None or now - previous >= 60:
            self.pending[bssid] = True
        self.last_seen[bssid] = now  # Weak beacons also establish recent presence.
        key = (bssid, ssid, security)
        if rssi < self.threshold:
            # A dip below the threshold breaks this candidate's confirmation.
            self.samples.pop(key, None)
            return []
        samples = self.samples.setdefault(key, collections.deque())
        second = int(now)
        while samples and now - samples[0] > self.window:
            samples.popleft()
        if not samples or samples[-1] != second:
            samples.append(second)
        if len(samples) < self.count:
            return []
        profile = [ssid, security]
        if self.learning:
            profiles = self.baseline.setdefault(bssid, [])
            if profile not in profiles:
                profiles.append(profile)
            self.pending[bssid] = False
            return []
        known = self.baseline.get(bssid, [])
        profile_trusted_anywhere = any(
            profile in profiles for profiles in self.baseline.values())
        lookalikes = {
            (mac, trusted_ssid)
            for mac, profiles in self.baseline.items()
            for trusted_ssid, _trusted_security in profiles
            if has_one_trailing_unicode_character(ssid, trusted_ssid)
        }
        types = []
        if not self.ready:
            self.pending[bssid] = False
        if self.ready and self.pending.get(bssid):
            types.append('RETURNED_AP' if bssid in self.baseline else 'NEW_AP')
            self.pending[bssid] = False
        if known and profile not in known:
            if any(s == ssid and enc != security for s, enc in known):
                types.append('SECURITY_CHANGED')
            elif ssid and not any(s == ssid for s, _ in known):
                types.append('SSID_CHANGED')
        # Compare against the fixed trusted baseline and confirmed live identities.
        peers = {mac for mac, profiles in self.baseline.items()
                 if mac != bssid and ssid and any(s == ssid for s, _ in profiles)}
        peers.update(mac for (mac, s, _), hits in self.samples.items()
                     if mac != bssid and s == ssid and ssid and len(hits) >= self.count
                     and now - hits[-1] <= self.window)
        if peers and profile not in known:
            live = any(now - self.last_seen.get(mac, -1e12) < 60 for mac in peers)
            types.append('SSID_COPY' if live else 'BSSID_CHANGED')
            if any(s == ssid and enc != security for mac in peers
                   for s, enc in self.baseline.get(mac, [])):
                types.append('SECURITY_CHANGED')
        if lookalikes and not profile_trusted_anywhere:
            # Policy: an untrusted AP appending one character to a trusted SSID
            # is the deliberate anti-grouping pattern and receives top priority.
            types = [kind for kind in types if kind not in
                     ('NEW_AP', 'RETURNED_AP', 'BSSID_CHANGED', 'SSID_COPY', 'SSID_CHANGED')]
            types.append('EVIL_TWIN_CERTAIN')
        events = []
        for kind in sorted(set(types)):
            alarm_key = (kind,) + key
            if now - self.alarms.get(alarm_key, -1e12) >= self.cooldown:
                self.alarms[alarm_key] = now
                event = {'event': kind, 'bssid': bssid, 'ssid_hex': ssid,
                         'security': security, 'rssi': rssi,
                         'peers': sorted(peers | {mac for mac, _ssid in lookalikes})}
                if kind == 'EVIL_TWIN_CERTAIN':
                    event['trusted_ssids_hex'] = sorted(
                        {trusted_ssid for _mac, trusted_ssid in lookalikes})
                events.append(event)
        return events


def ui(command, *args):
    try:
        subprocess.run([command, *args], timeout=4, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        pass


def notifier(messages):
    while True:
        kind, message = messages.get()
        if kind == 'EVIL_TWIN_CERTAIN':
            ui('LOG', 'red', message)
            ui('VIBRATE', '300', '100', '300', '100', '300')
            ui('RINGTONE', 'warning')
            ui('ALERT', message)
        else:
            ui('LOG', 'yellow', message)
            ui('VIBRATE', '200', '100', '200')
            ui('RINGTONE', 'alert')


def load_baseline(path):
    if not path.exists():
        return None
    obj = json.loads(path.read_text())
    if obj.get('version') != 1 or not isinstance(obj.get('aps'), dict):
        raise ValueError('Invalid baseline; move file aside to relearn')
    for mac, profiles in obj['aps'].items():
        if len(bytes.fromhex(mac.replace(':', ''))) != 6 or not isinstance(profiles, list):
            raise ValueError('Invalid baseline AP')
        for profile in profiles:
            if not isinstance(profile, list) or len(profile) != 2 or not all(isinstance(v, str) for v in profile):
                raise ValueError('Invalid baseline profile')
            if len(bytes.fromhex(profile[0])) > 32:
                raise ValueError('Invalid baseline SSID')
    return obj['aps']


def run(args):
    print('Home WiFi Watch: Python %s; interface %s' %
          ('.'.join(str(part) for part in os.sys.version_info[:3]), args.interface),
          flush=True)
    directory = Path(args.directory)
    directory.mkdir(parents=True, exist_ok=True)
    lock = (directory / 'watch.lock').open('w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    path = directory / 'baseline.json'
    baseline = load_baseline(path)
    detector = Detector(baseline, time.monotonic(), args.threshold,
                        args.confirm_count, args.confirm_window, args.cooldown)
    messages = queue.Queue(maxsize=64)
    threading.Thread(target=notifier, args=(messages,), daemon=True).start()
    ui('LOG', 'cyan', 'Learning baseline for 60s...' if baseline is None else 'Saved baseline loaded; security checks active, presence warm-up 60s.')
    proc = subprocess.Popen(['tcpdump', '-i', args.interface, '-n', '-p', '-U', '-s', '4096',
                             '-w', '-', 'type mgt subtype beacon'], stdout=subprocess.PIPE)
    print('Home WiFi Watch: tcpdump started (pid %d)' % proc.pid, flush=True)
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    stream = PcapStream()
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    last_valid = time.monotonic()
    next_warning = last_valid + 60
    try:
        while True:
            now = time.monotonic()
            if detector.tick(now):
                if baseline is None:
                    if not detector.baseline:
                        raise ValueError('No stable AP in first minute; baseline not saved. Check radio/channel/RSSI.')
                    temp = path.with_suffix('.tmp')
                    temp.write_text(json.dumps({'version': 1, 'aps': detector.baseline}, indent=2))
                    os.replace(temp, path)
                ui('LOG', 'green', 'Monitoring active. Baseline APs: %d' % len(detector.baseline))
                ui('LED', 'GREEN')
            if now >= next_warning:
                if now - last_valid >= 60:
                    ui('LOG', 'red', 'No valid beacons with RSSI for 60s: check capture coverage.')
                next_warning = now + 60
            for _key, _mask in selector.select(timeout=1):
                data = os.read(proc.stdout.fileno(), 65536)
                if not data:
                    raise ValueError('tcpdump stopped; inspect its error above')
                for packet in stream.feed(data):
                    obs = decode(packet)
                    if obs is None:
                        continue
                    now = time.monotonic()
                    last_valid = now
                    for event in detector.observe(obs, now):
                        event['time'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')
                        logfile = directory / 'events.jsonl'
                        if logfile.exists() and logfile.stat().st_size > 2 * 1024 * 1024:
                            os.replace(logfile, directory / 'events.previous.jsonl')
                        with logfile.open('a') as out:
                            out.write(json.dumps(event) + '\n')
                        name = json.dumps(bytes.fromhex(event['ssid_hex']).decode('utf-8', 'backslashreplace'), ensure_ascii=True)
                        message = '%s %s %s %s dBm' % (event['event'], name, event['bssid'], event['rssi'])
                        if event['event'] in ('SSID_COPY', 'BSSID_CHANGED'):
                            message += ' Possible Evil Twin OR legitimate mesh/AP.'
                        try:
                            messages.put_nowait((event['event'], message))
                        except queue.Full:
                            pass  # Complete event history is still on disk.
    finally:
        selector.close()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        lock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', default='wlan1mon')
    parser.add_argument('--directory', default='/root/loot/home_wifi_watch')
    parser.add_argument('--threshold', type=int, default=-80)
    parser.add_argument('--confirm-count', type=int, default=3)
    parser.add_argument('--confirm-window', type=int, default=15)
    parser.add_argument('--cooldown', type=int, default=300)
    args = parser.parse_args()
    if not (-127 <= args.threshold < 0 and 2 <= args.confirm_count <= args.confirm_window <= 60 and args.cooldown >= 60):
        parser.error('Invalid threshold/confirmation/cooldown settings')
    os.umask(0o077)
    try:
        run(args)
    except KeyboardInterrupt:
        return
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('Home WiFi Watch: %s' % exc, flush=True)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
