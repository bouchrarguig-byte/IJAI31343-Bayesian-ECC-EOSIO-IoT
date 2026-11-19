#!/usr/bin/env python3
"""LOOPBACK software integration ONLY: Python mock X25519 device, NO ESP8266."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError,URLError
from urllib.request import Request,urlopen

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

REPO=Path(__file__).resolve().parents[2]
# v2: repository layout. Destination file name in the temporary gateway
# directory -> source file in this repository.
GATEWAY_FILES={
    'gateway_epoch.py': REPO/'01_ECC_Key_Renewal/Gateway/gateway_epoch_stage7.py',
    'epoch_protocol.py': REPO/'01_ECC_Key_Renewal/Gateway/epoch_protocol_stage7.py',
    'intelligent_key_renewal.py': REPO/'02_Bayesian_AI/Controller/intelligent_key_renewal.py',
}

def mac(k,m):
    return hmac.new(k,m,hashlib.sha256).digest()

class SimulatedDevice:
    def __init__(self,base,psk):
        self.base=base
        self.psk=psk
        self.epoch=0
        self.sid=None
    def post(self,route,body):
        req=Request(self.base+route,json.dumps(body).encode(),{'Content-Type':'application/json'},method='POST')
        try:
            with urlopen(req,timeout=5) as r:
                return r.status,json.loads(r.read())
        except HTTPError as ex:
            return ex.code,json.loads(ex.read())
    def handshake(self,ack_override=None):
        private=X25519PrivateKey.generate()
        cp=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        cn=os.urandom(16).hex()
        status,b=self.post('/begin',{'device_id':'testtag1','client_pub':cp,'client_nonce':cn})
        assert status==200,(status,b)
        sid=b['session_id']
        tx=('IJAI31343-v1|'+'|'.join(['testtag1',cp,cn,b['server_pub'],b['server_nonce'],sid])).encode()
        assert hmac.compare_digest(mac(self.psk,b'SERVER|'+tx).hex(),b['server_mac'])
        sh=private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(b['server_pub'])))
        key=HKDF(algorithm=hashes.SHA256(),length=32,
                 salt=bytes.fromhex(cn+b['server_nonce']),info=b'IJAI31343-SESSION-V1|'+tx).derive(sh)
        status,resp=self.post('/finish',{'session_id':sid,
                                         'client_mac':mac(self.psk,b'CLIENT|'+tx).hex(),
                                         'client_key_mac':mac(key,b'CLIENTKEY|'+tx).hex()})
        assert status==200,(status,resp)
        assert hmac.compare_digest(mac(key,b'SERVERKEY|'+tx).hex(),resp['server_key_mac'])
        proof=mac(key,b'DEVICE-ACK|'+tx).hex() if ack_override is None else ack_override
        status,ack=self.post('/ack',{'session_id':sid,'ack_mac':proof})
        if ack_override is not None:
            self._pending_candidate=(sid,key,tx)
            return (status,ack,sid)
        assert status==200,(status,ack)
        epoch=ack['epoch']
        expected_mac = mac(
            key, b'SERVER-ACK|' + tx + b'|' + str(epoch).encode()
            + b'|' + str(ack['interval_seconds']).encode()
        ).hex()
        if not hmac.compare_digest(expected_mac, ack['ack_server_mac']):
            raise ValueError('ACK_FAILED gateway activation/lifetime proof')
        self.key=key
        self.sid=sid
        self.epoch=epoch
        self.interval=ack['interval_seconds']
        return (status,ack,sid)
    def data(self,counter,value=42,epoch=None,sid=None,tamper=False):
        epoch=self.epoch if epoch is None else epoch
        sid=self.sid if sid is None else sid
        message=f'DATA|testtag1|{sid}|{epoch}|{counter}|{value}'.encode()
        proof=mac(self.key,message).hex()
        if tamper:
            proof='0'*64 if proof!='0'*64 else '1'*64
        return self.post('/data',{'session_id':sid,'epoch':epoch,'counter':counter,
                                  'value':value,'data_mac':proof})

class TestLoopbackEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        cls.directory=Path(cls.tmp.name)
        for n,src in GATEWAY_FILES.items():
            shutil.copy2(src,cls.directory/n)
        cls.psk=os.urandom(32)
        (cls.directory/'device_psk.hex').write_text(cls.psk.hex())
        with socket.socket() as s:
            s.bind(('127.0.0.1',0))
            cls.port=s.getsockname()[1]
        env={**os.environ,'IJAI_BIND':'127.0.0.1','IJAI_PORT':str(cls.port),
             'IJAI_SCENARIO_HORIZON_SECONDS':'600',
             'IJAI_BASELINE_SECONDS':'120','IJAI_MIN_SECONDS':'10','IJAI_MAX_SECONDS':'300'}
        cls.proc=subprocess.Popen([sys.executable,'-u','gateway_epoch.py'],cwd=str(cls.directory),
                                  env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        cls.base=f'http://127.0.0.1:{cls.port}'
        for i in range(100):
            try:
                with socket.create_connection(('127.0.0.1',cls.port),timeout=.2):
                    break
            except OSError:
                if cls.proc.poll() is not None:
                    raise AssertionError('Gateway failed to start')
                time.sleep(.04)
        else:
            raise AssertionError('Gateway not listening')
    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try: cls.proc.wait(timeout=5)
        except subprocess.TimeoutExpired: cls.proc.kill()
        cls.tmp.cleanup()

    def test_01_bad_ack_does_not_activate(self):
        d=SimulatedDevice(self.base,self.psk)
        status,resp,sid=d.handshake(ack_override='0'*64)
        self.assertEqual(status,403)
        self.assertEqual(resp['error'],'invalid_ack_mac')
        status,resp=d.post('/data',{'session_id':sid,'epoch':1,'counter':1,'value':42,'data_mac':'0'*64})
        self.assertEqual(status,403)
        # A bad (possibly injected) ACK must not prevent the genuine device
        # from completing its pending handshake with the correct proof.
        _,key,tx=d._pending_candidate
        status,ack=d.post('/ack',{'session_id':sid,'ack_mac':mac(key,b'DEVICE-ACK|'+tx).hex()})
        self.assertEqual(status,200)
        self.assertEqual(ack['epoch'],1)
    def test_02_good_ack_enables_data_and_replay_rejected(self):
        self.device=SimulatedDevice(self.base,self.psk)
        status,resp,sid=self.device.handshake()
        self.assertEqual(status,200)
        self.assertEqual(self.device.epoch,2)
        status,resp=self.device.data(1)
        self.assertEqual(status,200)
        self.assertTrue(resp['accepted'])
        status,resp=self.device.data(1)
        self.assertEqual(status,403)
        self.assertEqual(resp['error'],'replayed_counter')
        status,resp=self.device.data(2,tamper=True)
        self.assertEqual(status,403)
        self.assertEqual(resp['error'],'invalid_data_mac')
        status,resp=self.device.data(2)
        self.assertEqual(status,200)
        status,resp=self.device.post('/ack',{'session_id':sid,'ack_mac':'0'*64})
        self.assertEqual(status,403)
    def test_03_rekey_invalidates_old_session(self):
        d=SimulatedDevice(self.base,self.psk)
        oldstatus,oldresp,oldsid=d.handshake()
        self.assertEqual(oldstatus,200)
        self.assertEqual(d.epoch,3)
        status,_=d.data(1)
        self.assertEqual(status,200)
        d.handshake()
        self.assertEqual(d.epoch,4)
        status,resp=d.data(2,epoch=3,sid=oldsid)
        self.assertEqual(status,403)
        self.assertEqual(resp['error'],'wrong_epoch_or_session')
        status,resp=d.data(1)
        self.assertEqual(status,200)
    def test_04_log_contains_no_secrets(self):
        rows=[json.loads(x) for x in (self.directory/'epoch_events.jsonl').read_text().splitlines()]
        self.assertGreaterEqual(len(rows),3)
        self.assertFalse(any('key' in key or 'psk' in key for row in rows for key in row.keys()))
        self.assertTrue(any(row['kind']=='epoch_activated' for row in rows))
        self.assertTrue(all(row['experiment']=='Stage3_lab_no_eosio' for row in rows))

    def test_05_tampered_lifetime_rejected(self):
        """An altered /ack TTL must not be installed by the simulated client.

        The server has already accepted /ack; this models response tampering
        and does not prove that server-side activation is rolled back.
        """
        d = SimulatedDevice(self.base, self.psk)
        original_post = d.post
        changes = []

        def tamper_ack_response(route, body):
            status, reply = original_post(route, body)
            if route == '/ack' and status == 200:
                forged = dict(reply)
                forged['interval_seconds'] = float(reply['interval_seconds']) + 60.0
                changes.append((reply['interval_seconds'], forged['interval_seconds']))
                return status, forged
            return status, reply

        d.post = tamper_ack_response
        with self.assertRaisesRegex(ValueError, 'ACK_FAILED gateway activation/lifetime proof'):
            d.handshake()
        self.assertEqual(len(changes), 1, 'Expected to intercept one successful /ack response')
        self.assertEqual(d.epoch, 0, 'Tampered TTL must not activate client epoch')
        self.assertIsNone(d.sid, 'Tampered TTL must not install the client SID')
        self.assertFalse(hasattr(d, 'key'), 'Tampered TTL must not install session key')

        # The gateway may have committed an epoch already. A fresh handshake
        # should restore a legitimate client/server session without rollback.
        d.post = original_post
        status, _, _ = d.handshake()
        self.assertEqual(status, 200)
        self.assertGreater(d.epoch, 0)
        status, response = d.data(1)
        self.assertEqual(status, 200)
        self.assertTrue(response['accepted'])

    def test_06_lost_ack_response_after_server_activation(self):
        """Drop only the successful /ack RESPONSE, after gateway activation.

        Scope: simulated client + loopback gateway. Replay old /ack and attempt
        a fresh legitimate exchange. No physical network fault is generated.
        """
        d = SimulatedDevice(self.base, self.psk)
        real_post = d.post
        intercepted = []

        def drop_successful_ack_reply(route, body):
            status, reply = real_post(route, body)
            if route == '/ack' and status == 200:
                intercepted.append({
                    'body': dict(body),
                    'server_epoch': int(reply['epoch']),
                })
                # The server has already processed /ack; only the RESPONSE
                # is hidden from the simulated client.
                raise ConnectionResetError('SIMULATED_LOST_ACK_RESPONSE')
            return status, reply

        d.post = drop_successful_ack_reply
        with self.assertRaisesRegex(ConnectionResetError, 'SIMULATED_LOST_ACK_RESPONSE'):
            d.handshake()
        self.assertEqual(len(intercepted), 1, 'Expected exactly one accepted /ack')
        self.assertEqual(d.epoch, 0, 'Client must not install an unconfirmed epoch')
        self.assertIsNone(d.sid, 'Client must not install an unconfirmed SID')
        self.assertFalse(hasattr(d, 'key'), 'Client must not install an unconfirmed key')

        # Re-sending exactly the already consumed ACK must not activate twice.
        replay_status, replay_reply = real_post('/ack', intercepted[0]['body'])
        self.assertEqual(replay_status, 403, 'Replay of consumed ACK accepted')
        self.assertEqual(replay_reply.get('error'), 'unknown_or_replayed_ack')

        # Reconciliation is probed through a fresh authenticated handshake.
        d.post = real_post
        status, _, _ = d.handshake()
        self.assertEqual(status, 200, 'Fresh handshake did not recover')
        self.assertGreater(d.epoch, intercepted[0]['server_epoch'],
                           'Fresh handshake failed to advance beyond lost epoch')
        data_status, data_reply = d.data(1)
        self.assertEqual(data_status, 200, 'Data rejected after recovery')
        self.assertTrue(data_reply.get('accepted'), 'Recovered data not accepted')

if __name__=='__main__': unittest.main(verbosity=2)
