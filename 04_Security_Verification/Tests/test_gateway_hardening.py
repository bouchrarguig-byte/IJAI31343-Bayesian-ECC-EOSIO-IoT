#!/usr/bin/env python3
"""Loopback tests for the v2 gateway hardening (software only, no ESP8266).

Covers: forged-alarm flood cap, replay events only for authenticated messages,
strict hex parsing and the per-peer cap on unauthenticated /begin requests.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_gateway_epoch_loopback import GATEWAY_FILES, SimulatedDevice


def start_gateway(extra_env):
    tmp = tempfile.TemporaryDirectory()
    directory = Path(tmp.name)
    for name, src in GATEWAY_FILES.items():
        shutil.copy2(src, directory / name)
    psk = os.urandom(32)
    (directory / 'device_psk.hex').write_text(psk.hex())
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        port = s.getsockname()[1]
    env = {**os.environ, 'IJAI_BIND': '127.0.0.1', 'IJAI_PORT': str(port),
           'IJAI_SCENARIO_HORIZON_SECONDS': '600', **extra_env}
    proc = subprocess.Popen([sys.executable, '-u', 'gateway_epoch.py'], cwd=str(directory),
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                break
        except OSError:
            if proc.poll() is not None:
                raise AssertionError('Gateway failed to start')
            time.sleep(.04)
    else:
        raise AssertionError('Gateway not listening')
    return tmp, directory, proc, psk, f'http://127.0.0.1:{port}'


def read_log(directory):
    path = directory / 'epoch_events.jsonl'
    if not path.is_file():
        return []
    return [json.loads(x) for x in path.read_text().splitlines()]


class GatewayCase(unittest.TestCase):
    ENV = {}

    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.directory, cls.proc, cls.psk, cls.base = start_gateway(cls.ENV)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        cls.tmp.cleanup()


class TestFloodCap(GatewayCase):
    ENV = {'IJAI_MAX_SUSPICIOUS_PER_WINDOW': '3', 'IJAI_SUSPICIOUS_WINDOW_SECONDS': '60'}

    def test_unauthenticated_flood_cannot_move_policy_beyond_cap(self):
        d = SimulatedDevice(self.base, self.psk)
        status, _, _ = d.handshake()
        self.assertEqual(status, 200)
        for counter in range(1, 51):                 # 50 forged messages, wrong MAC
            code, resp = d.data(counter, tamper=True)
            self.assertEqual(code, 403)
            self.assertEqual(resp['error'], 'invalid_data_mac')
        rows = read_log(self.directory)
        counted = [r for r in rows if r['kind'] == 'risk_observation']
        suppressed = [r for r in rows if r['kind'] == 'risk_observation_suppressed']
        self.assertEqual(len(counted), 3)
        self.assertEqual(len(suppressed), 47)
        # The genuine device is still served afterwards.
        code, resp = d.data(1)
        self.assertEqual(code, 200)
        self.assertTrue(resp['accepted'])


class TestReplayClassification(GatewayCase):
    ENV = {'IJAI_MAX_SUSPICIOUS_PER_WINDOW': '0'}      # cap disabled: count everything

    def test_stale_counter_without_valid_mac_is_not_a_replay(self):
        d = SimulatedDevice(self.base, self.psk)
        d.handshake()
        self.assertEqual(d.data(1)[0], 200)
        # Anyone who sees the clear-text sid/epoch can send a stale counter.
        code, resp = d.data(1, tamper=True)
        self.assertEqual((code, resp['error']), (403, 'invalid_data_mac'))
        # An authenticated old message is a genuine replay.
        code, resp = d.data(1)
        self.assertEqual((code, resp['error']), (403, 'replayed_counter'))
        cats = [r['category'] for r in read_log(self.directory) if r['kind'] == 'risk_observation']
        self.assertEqual(cats, ['invalid_proof', 'replay'])


class TestStrictHex(GatewayCase):
    def test_whitespace_padded_hex_is_rejected(self):
        d = SimulatedDevice(self.base, self.psk)
        bad_pub = '11' * 31 + '  '          # 64 characters, but only 31 hex bytes
        code, resp = d.post('/begin', {'device_id': 'testtag1', 'client_pub': bad_pub,
                                       'client_nonce': '22' * 16})
        self.assertEqual(code, 400)
        self.assertIn('client_pub', resp['error'])
        code, resp = d.post('/begin', {'device_id': 'testtag1', 'client_pub': '11' * 32,
                                       'client_nonce': 'zz' * 16})
        self.assertEqual(code, 400)


class TestPerPeerHandshakeCap(GatewayCase):
    ENV = {'IJAI_MAX_HANDSHAKES_PER_IP': '4'}

    def test_one_peer_cannot_fill_the_handshake_table(self):
        d = SimulatedDevice(self.base, self.psk)
        codes = []
        for _ in range(6):
            code, _ = d.post('/begin', {'device_id': 'testtag1',
                                        'client_pub': os.urandom(32).hex(),
                                        'client_nonce': os.urandom(16).hex()})
            codes.append(code)
        self.assertEqual(codes, [200, 200, 200, 200, 429, 429])


if __name__ == '__main__':
    unittest.main(verbosity=2)
