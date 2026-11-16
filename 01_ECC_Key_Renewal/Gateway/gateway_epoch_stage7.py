#!/usr/bin/env python3
"""IJ-AI 31343 — LAB ONLY: authenticated ephemeral X25519 + actual epoch use.

Each /begin starts a fresh X25519 handshake.  /finish verifies proof and
stages a candidate epoch. Only a separate /ack MAC can activate it.
/data verifies an HMAC with the *active* ephemeral session key, monotonic
counter and non-expired policy epoch. Data are NOT ENCRYPTED (no AEAD here).

NO EOSIO submission. Horizon is EXTERNALLY SUPPLIED scenario, NOT actual
quantum break time. Not for production or the public Internet.
"""
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from epoch_protocol import EpochCoordinator, RotationProtocolError
from intelligent_key_renewal import PolicyConfig, UnsafePolicyError

HERE = Path(__file__).resolve().parent
DEVICE_ID = 'testtag1'
HOST = os.environ.get('IJAI_BIND','0.0.0.0')
PORT = int(os.environ.get('IJAI_PORT','8767'))
TTL = 45.0
MAX_SESSIONS = 24
# The current lab uses an external, explicitly assumed horizon. No quantum measurement.
def _number_from_env(name, default):
    val = float(os.environ.get(name,default))
    if not math.isfinite(val):
        raise RuntimeError(f'{name} must be finite')
    return val
HORIZON = _number_from_env('IJAI_SCENARIO_HORIZON_SECONDS',600.0)
CFG = PolicyConfig(baseline_seconds=_number_from_env('IJAI_BASELINE_SECONDS',120),
                   minimum_seconds=_number_from_env('IJAI_MIN_SECONDS',10),
                   maximum_seconds=_number_from_env('IJAI_MAX_SECONDS',300),
                   risk_sensitivity=_number_from_env('IJAI_RISK_SENSITIVITY',4.0),
                   posterior_samples=1024)
PSK_FILE = HERE / 'device_psk.hex'
if not PSK_FILE.is_file():
    raise SystemExit('Missing Pi_Gateway/device_psk.hex; copy your existing securely provisioned file (do not publish).')
try:
    PSK = bytes.fromhex(PSK_FILE.read_text(encoding='ascii').strip())
except ValueError:
    raise SystemExit('Invalid PSK file format')
if len(PSK) != 32:
    raise SystemExit('Expected 32-byte provisioned PSK')

lock = threading.RLock()
handshakes = {}
pending_keys = {}  # sid -> {key,tx,created}; never serialized/logged
active = None      # {key, sid, epoch, counter}, key stays only in RAM
coordinator = EpochCoordinator(HORIZON, CFG)
LOG_FILE = HERE / 'epoch_events.jsonl'
EXPERIMENT = os.environ.get('IJAI_EXPERIMENT_LABEL','Stage3_lab_no_eosio')
POLICY_MODE = 'fixed' if CFG.risk_sensitivity == 0 else 'adaptive'

def mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key,msg,hashlib.sha256).digest()

def transcript(device_id, cp, cn, sp, sn, sid):
    return ('IJAI31343-v1|'+'|'.join((device_id,cp,cn,sp,sn,sid))).encode('ascii')

def hexfield(data, name, size):
    raw = data.get(name)
    if not isinstance(raw,str) or len(raw)!=size*2:
        raise ValueError(f'Invalid {name}')
    try:
        return bytes.fromhex(raw)
    except ValueError as e:
        raise ValueError(f'Invalid {name}') from e

def record(kind, **details):
    row = {'ts_utc': datetime.now(timezone.utc).isoformat(),
           'device_id': DEVICE_ID, 'kind':kind,
           'experiment':EXPERIMENT,**details}
    with LOG_FILE.open('a',encoding='utf-8') as out:
        out.write(json.dumps(row,separators=(',',':'))+'\n')

def observe_and_record(event):
    """Audit each suspicious policy observation (no session secrets logged).

    Caller already holds `lock`. The event may be user-generated and is NOT
    automatically a real attack nor independent ground-truth maliciousness.
    """
    before = coordinator.policy.select_interval(HORIZON)
    coordinator.observe(event)
    after = coordinator.policy.select_interval(HORIZON)
    record('risk_observation', category=event,
           events_normal=coordinator.model.normal_events,
           events_suspicious=coordinator.model.anomalies,
           risk_upper_before=before['risk_posterior_upper_mc'],
           risk_upper_after=after['risk_posterior_upper_mc'],
           interval_before_seconds=before['interval_seconds'],
           interval_after_seconds=after['interval_seconds'],
           policy_mode=POLICY_MODE)


def expire_pending(now):
    # Only called under lock. Invalidate provisional states on timeout.
    expired = [sid for sid,p in pending_keys.items() if now-p['created']>TTL]
    for sid in expired:
        pending_keys.pop(sid,None)
        if coordinator.pending and coordinator.pending.session_id == sid:
            coordinator.pending = None
        record('ack_timeout',session_id_prefix=sid[:8])

class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def json_reply(self, status, obj):
        b=json.dumps(obj,separators=(',',':')).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type','application/json')
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length',str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def do_POST(self):
        if self.path not in ('/begin','/finish','/ack','/data'):
            return self.json_reply(404,{'error':'unknown_endpoint'})
        try:
            n=int(self.headers.get('Content-Length','-1'))
            if not (0 < n <= 2048):
                return self.json_reply(413,{'error':'invalid_request_size'})
            body=json.loads(self.rfile.read(n))
            if not isinstance(body,dict):
                raise ValueError('Expected object')
            return {'/begin':self.begin_handshake,
                    '/finish':self.finish_handshake,
                    '/ack':self.acknowledge,
                    '/data':self.submit_data}[self.path](body)
        except (ValueError,TypeError,KeyError) as exc:
            return self.json_reply(400,{'error':str(exc)})
        except Exception as exc:
            print('[LAB_SERVER_ERROR]',type(exc).__name__,flush=True)
            return self.json_reply(500,{'error':'internal_error'})
    def begin_handshake(self,body):
        if body.get('device_id') != DEVICE_ID:
            return self.json_reply(403,{'error':'unknown_device'})
        cp=hexfield(body,'client_pub',32).hex()
        cn=hexfield(body,'client_nonce',16).hex()
        priv=X25519PrivateKey.generate()
        sp=priv.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
        sn=secrets.token_bytes(16).hex()
        sid=secrets.token_bytes(16).hex()
        tx=transcript(DEVICE_ID,cp,cn,sp,sn,sid)
        now=time.monotonic()
        with lock:
            expire_pending(now)
            for key in list(handshakes):
                if now-handshakes[key]['created']>TTL:
                    del handshakes[key]
            if len(handshakes)>=MAX_SESSIONS:
                return self.json_reply(429,{'error':'too_many_handshakes'})
            if coordinator.pending is not None:
                return self.json_reply(409,{'error':'another_handshake_awaits_ack'})
            handshakes[sid]={'private':priv,'pub':bytes.fromhex(cp),
                              'cn':bytes.fromhex(cn),'sn':bytes.fromhex(sn),
                              'tx':tx,'created':now}
        return self.json_reply(200,{'session_id':sid,'server_pub':sp,'server_nonce':sn,
                                    'server_mac':mac(PSK,b'SERVER|'+tx).hex()})
    def finish_handshake(self,body):
        sid=body.get('session_id')
        if not isinstance(sid,str) or len(sid)!=32:
            return self.json_reply(400,{'error':'invalid_session'})
        cm=hexfield(body,'client_mac',32)
        km=hexfield(body,'client_key_mac',32)
        with lock:
            sess=handshakes.pop(sid,None)
            if sess is None:
                return self.json_reply(403,{'error':'unknown_or_replayed_session'})
            if time.monotonic()-sess['created']>TTL:
                return self.json_reply(403,{'error':'expired_session'})
            tx=sess['tx']
            if not hmac.compare_digest(cm,mac(PSK,b'CLIENT|'+tx)):
                observe_and_record('invalid_proof')
                return self.json_reply(403,{'error':'invalid_device_proof'})
            try:
                shared=sess['private'].exchange(X25519PublicKey.from_public_bytes(sess['pub']))
            except (ValueError,TypeError):
                observe_and_record('failed_auth')
                return self.json_reply(403,{'error':'invalid_peer_key'})
            key=HKDF(algorithm=hashes.SHA256(),length=32,
                     salt=sess['cn']+sess['sn'],info=b'IJAI31343-SESSION-V1|'+tx).derive(shared)
            if not hmac.compare_digest(km,mac(key,b'CLIENTKEY|'+tx)):
                observe_and_record('invalid_proof')
                return self.json_reply(403,{'error':'invalid_key_confirmation'})
            try:
                coordinator.stage_gateway_verified(sid,hashlib.sha256(sess['pub']).hexdigest(),time.monotonic())
            except (RotationProtocolError,UnsafePolicyError,ValueError):
                return self.json_reply(403,{'error':'rotation_policy_rejected'})
            pending_keys[sid]={'key':key,'tx':tx,'created':time.monotonic()}
        return self.json_reply(200,{'authenticated':True,
                                    'server_key_mac':mac(key,b'SERVERKEY|'+tx).hex(),
                                    'ack_required':True,
                                    'blockchain_tx':False})
    def acknowledge(self,body):
        global active
        sid=body.get('session_id')
        if not isinstance(sid,str) or len(sid)!=32:
            return self.json_reply(400,{'error':'invalid_session'})
        ack_mac=hexfield(body,'ack_mac',32)
        now=time.monotonic()
        with lock:
            expire_pending(now)
            pending=pending_keys.get(sid)
            if pending is None or coordinator.pending is None:
                return self.json_reply(403,{'error':'unknown_or_replayed_ack'})
            if not hmac.compare_digest(ack_mac,mac(pending['key'],b'DEVICE-ACK|'+pending['tx'])):
                observe_and_record('invalid_proof')
                return self.json_reply(403,{'error':'invalid_ack_mac'})
            try:
                new_epoch=coordinator.confirm_device_ack(sid,now,cryptographic_ack_verified=True)
            except (RotationProtocolError,UnsafePolicyError,ValueError):
                return self.json_reply(403,{'error':'ack_policy_rejected'})
            # Epoch activation and private session key switch are simultaneous under lock.
            active={'key':pending['key'],'sid':sid,'epoch':new_epoch,'counter':0}
            pending_keys.pop(sid,None)
            stat=coordinator.state(now)
            record('epoch_activated',epoch=new_epoch,interval_seconds=stat['interval_seconds'],
                   scenario_horizon_seconds=HORIZON,
                   risk_posterior_upper_mc=stat['risk_posterior_upper_mc'],
                   events_normal=stat['events_normal'],
                   events_suspicious=stat['events_suspicious'],
                   policy_mode=POLICY_MODE,
                   risk_sensitivity=CFG.risk_sensitivity,
                   blockchain_tx=False)
            server_ack=mac(active['key'],b'SERVER-ACK|'+pending['tx']+b'|'+str(new_epoch).encode()+b'|'+str(stat['interval_seconds']).encode()).hex()
        return self.json_reply(200,{'epoch':new_epoch,'interval_seconds':stat['interval_seconds'],
                                    'ack_server_mac':server_ack,'blockchain_tx':False})
    def submit_data(self,body):
        try:
            epoch=int(body.get('epoch'))
            counter=int(body.get('counter'))
            value=int(body.get('value'))
        except (TypeError,ValueError):
            return self.json_reply(400,{'error':'invalid_data'})
        sid=body.get('session_id')
        if not isinstance(sid,str) or len(sid)!=32 or epoch<1 or counter<1 or counter>2**31 or abs(value)>10**7:
            return self.json_reply(400,{'error':'invalid_data_fields'})
        tag=hexfield(body,'data_mac',32)
        with lock:
            if active is None or sid!=active['sid'] or epoch!=active['epoch']:
                return self.json_reply(403,{'error':'wrong_epoch_or_session'})
            if not coordinator.authorize_payload(epoch,time.monotonic()):
                return self.json_reply(403,{'error':'epoch_expired_rotate_first'})
            if counter<=active['counter']:
                observe_and_record('replay')
                return self.json_reply(403,{'error':'replayed_counter'})
            msg=f'DATA|{DEVICE_ID}|{sid}|{epoch}|{counter}|{value}'.encode('ascii')
            if not hmac.compare_digest(tag,mac(active['key'],msg)):
                observe_and_record('invalid_proof')
                return self.json_reply(403,{'error':'invalid_data_mac'})
            active['counter']=counter
            record('data_accepted',epoch=epoch,counter=counter,value=value,blockchain_tx=False)
        return self.json_reply(200,{'accepted':True,'epoch':epoch,'blockchain_tx':False})

if __name__=='__main__':
    print(f'STAGE4 LAB: {HOST}:{PORT} policy={POLICY_MODE} sensitivity={CFG.risk_sensitivity} experiment={EXPERIMENT} horizon={HORIZON} sec (NOT quantum); NO EOSIO; DATA HMAC ONLY')
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
