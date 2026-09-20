import json
import struct
import tempfile
import unittest
from pathlib import Path
from watch import (Detector, PcapStream, decode,
                   has_one_trailing_unicode_character, load_baseline, security_ie)

A = '02:00:00:00:00:01'
B = '02:00:00:00:00:02'
SSID = b'Home'.hex()
BASE = {A: [[SSID, 'RSN']]}


def beacon(ssid=b'Home', rssi=-60, ies=b'', flags=0):
    rt = struct.pack('<BBHI', 0, 0, 10, (1 << 1) | (1 << 5))
    rt += struct.pack('<Bb', flags, rssi)
    mac = bytes.fromhex(A.replace(':', ''))
    frame = b'\x80\x00\x00\x00' + b'\xff'*6 + mac + mac + b'\x00\x00'
    frame += b'\x00'*8 + b'\x64\x00\x00\x00'
    frame += bytes([0, len(ssid)]) + ssid + ies
    return rt + frame + (b'\x00'*4 if flags & 0x10 else b'')


def confirmed(det, mac=B, ssid=SSID, enc='RSN', start=61, rssi=-60):
    events = []
    for t in range(start, start+3):
        det.tick(t)
        events.extend(det.observe((mac, ssid, enc, rssi), t))
    return {e['event'] for e in events}


class DetectionTests(unittest.TestCase):
    def detector(self):
        d = Detector(BASE, 0)
        d.tick(60)
        return d

    def test_learning_and_restart(self):
        d = Detector(None, 0)
        self.assertFalse(confirmed(d, A, start=1))
        self.assertEqual(d.baseline, BASE)
        self.assertTrue(d.tick(60))
        self.assertFalse(confirmed(d, A, start=61))
        restarted = Detector(d.baseline, 100)
        self.assertFalse(confirmed(restarted, A, start=101))
        self.assertIn('SECURITY_CHANGED', confirmed(restarted, A, enc='OPEN', start=110))

    def test_threshold_inclusive(self):
        self.assertIn('NEW_AP', confirmed(self.detector(), ssid='abcd', rssi=-80))
        self.assertFalse(confirmed(self.detector(), ssid='abcd', rssi=-81))

    def test_burst_not_confirmation(self):
        d = self.detector()
        for _ in range(100):
            self.assertFalse(d.observe((B, SSID, 'RSN', -60), 61))

    def test_fading_breaks_confirmation(self):
        d = self.detector()
        for t, rssi in [(61,-60), (62,-81), (63,-60), (64,-81), (65,-60)]:
            self.assertFalse(d.observe((B, SSID, 'RSN', rssi), t))

    def test_sparse_observations(self):
        d = self.detector()
        for t in [61, 80, 100]:
            d.tick(t)
            self.assertFalse(d.observe((B, SSID, 'RSN', -60), t))

    def test_security_change_and_cooldown(self):
        d = self.detector()
        self.assertIn('SECURITY_CHANGED', confirmed(d, A, enc='OPEN'))
        self.assertFalse(confirmed(d, A, enc='OPEN', start=70))
        self.assertEqual(d.baseline, BASE)
        self.assertIn('SECURITY_CHANGED', confirmed(d, A, enc='OPEN', start=365))

    def test_copy_and_replacement(self):
        d = self.detector()
        confirmed(d, A)
        self.assertIn('SSID_COPY', confirmed(d, start=65))
        self.assertIn('BSSID_CHANGED', confirmed(self.detector()))

    def test_changed_bssid_and_encryption(self):
        self.assertIn('SECURITY_CHANGED', confirmed(self.detector(), enc='OPEN'))

    def test_legitimate_mesh_in_baseline(self):
        d = Detector({A: [[SSID,'RSN']], B: [[SSID,'RSN']]}, 0)
        confirmed(d, A, start=1)
        self.assertFalse(confirmed(d, B, start=5))
        d.tick(60)
        self.assertFalse(confirmed(d, B, start=61))

    def test_return_after_minute(self):
        d = self.detector()
        self.assertIn('NEW_AP', confirmed(d, ssid='abcd'))
        self.assertFalse(confirmed(d, ssid='abcd', start=110))
        self.assertIn('NEW_AP', confirmed(d, ssid='abcd', start=400))

    def test_short_absence_no_realert_after_cooldown(self):
        d = self.detector()
        confirmed(d, ssid='abcd')
        for t in range(70, 401, 10):
            self.assertNotIn('NEW_AP', confirmed(d, ssid='abcd', start=t))

    def test_hidden_ssids_not_copies(self):
        d = Detector({A: [['','OPEN']]}, 0)
        d.tick(60)
        self.assertEqual(confirmed(d, ssid='', enc='OPEN'), {'NEW_AP'})

    def test_ssid_change(self):
        self.assertIn('SSID_CHANGED', confirmed(self.detector(), A, ssid='abcd'))

    def test_one_trailing_invisible_character_is_certain_evil_twin(self):
        twin = (bytes.fromhex(SSID).decode() + '\u200b').encode().hex()
        self.assertEqual(confirmed(self.detector(), B, ssid=twin),
                         {'EVIL_TWIN_CERTAIN'})

    def test_one_trailing_visible_character_is_certain_evil_twin(self):
        twin = (bytes.fromhex(SSID).decode() + '1').encode().hex()
        self.assertEqual(confirmed(self.detector(), B, ssid=twin),
                         {'EVIL_TWIN_CERTAIN'})

    def test_two_or_non_trailing_characters_are_not_certain(self):
        d = self.detector()
        self.assertNotIn('EVIL_TWIN_CERTAIN', confirmed(d, B, ssid=b'Home12'.hex()))
        self.assertNotIn('EVIL_TWIN_CERTAIN', confirmed(self.detector(), B,
                                                       ssid=b'HoXme'.hex()))

    def test_trusted_trailing_variant_is_not_alarm(self):
        twin = ('Home\u200b').encode().hex()
        d = Detector({A: [[SSID, 'RSN']], B: [[twin, 'RSN']]}, 0)
        d.tick(60)
        self.assertNotIn('EVIL_TWIN_CERTAIN', confirmed(d, B, ssid=twin))

    def test_trailing_character_requires_valid_utf8(self):
        self.assertTrue(has_one_trailing_unicode_character('486f6d65e2808b', SSID))
        self.assertFalse(has_one_trailing_unicode_character('486f6d65ff', SSID))


class ParserTests(unittest.TestCase):
    def test_open_and_raw_ssid(self):
        self.assertEqual(decode(beacon(b'A\x00\n\xff')), (A, b'A\x00\n\xff'.hex(), 'OPEN', -60))

    def test_fcs_and_bad_fcs(self):
        self.assertEqual(decode(beacon(flags=16)), decode(beacon()))
        self.assertIsNone(decode(beacon(flags=64)))

    def test_truncation(self):
        packet = beacon()
        for n in range(len(packet)):
            self.assertIsNone(decode(packet[:n]))

    def test_missing_rssi(self):
        packet = bytearray(beacon())
        packet[4:8] = b'\x00'*4
        self.assertIsNone(decode(packet))

    def test_extended_bitmap_alignment(self):
        rt = struct.pack('<BBHII', 0, 0, 25, (1 << 31) | 1 | (1 << 5), 0)
        rt += b'\x00'*4 + b'\x00'*8 + struct.pack('b', -73)
        self.assertEqual(decode(rt + beacon()[10:])[-1], -73)

    def test_rsn(self):
        rsn = bytes.fromhex('0100000fac040100000fac040100000fac020000')
        self.assertEqual(security_ie(rsn)[2], ['000fac02'])
        packet = beacon(ies=bytes([48, len(rsn)])+rsn)
        self.assertIn('RSN', decode(packet)[2])
        self.assertIsNone(decode(beacon(ies=b'\x30\x01\x00')))
        self.assertNotEqual(security_ie(rsn), security_ie(rsn[:-2]+b'\xc0\x00'))

    def test_pcap_split_reads_both_endians(self):
        packet = beacon()
        for order, magic in [('<', b'\xd4\xc3\xb2\xa1'), ('>', b'\xa1\xb2\xc3\xd4')]:
            data = magic + struct.pack(order+'HHIIII', 2,4,0,0,4096,127)
            data += struct.pack(order+'IIII', 1,0,len(packet),len(packet))+packet
            p = PcapStream()
            result = []
            for byte in data:
                result.extend(p.feed(bytes([byte])))
            self.assertEqual(result, [packet])

    def test_wrong_link_type(self):
        with self.assertRaises(ValueError):
            PcapStream().feed(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,4096,1))

    def test_baseline_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/'baseline.json'
            self.assertIsNone(load_baseline(p))
            p.write_text(json.dumps({'version':1,'aps':BASE}))
            self.assertEqual(load_baseline(p), BASE)
            p.write_text('{"version":2,"aps":{}}')
            with self.assertRaises(ValueError):
                load_baseline(p)


if __name__ == '__main__':
    unittest.main()
