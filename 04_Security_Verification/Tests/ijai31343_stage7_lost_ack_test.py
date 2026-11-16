#!/usr/bin/env python3
"""IJ-AI 31343 | Stage7 software fault-injection test of a lost /ack response.

Clones the existing Tools/test_gateway_epoch_loopback.py into a NEW runner
inside the same Stage7 Tools directory and injects one new test method.
Does NOT change the existing test, gateway, firmware, secrets, Stage4 or Stage6.

Use:
  python ijai31343_stage7_lost_ack_test.py --root ~/IJAI_31343_Work --run

Only test software. No claim of hardware deployment, EOSIO end-to-end,
or post-compromise security.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

STAGE7 = Path('Revision_31343/IJAI_31343_Stage7_Instrumented')
TEST_REL = Path('Tools/test_gateway_epoch_loopback.py')
RUNNER_REL = Path('Tools/loss_ack_fault_injection_runner.py')
ANCHOR = "if __name__=='__main__': unittest.main(verbosity=2)"
NEW_TEST = '''    def test_06_lost_ack_response_after_server_activation(self):
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

'''


def checksum(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.home() / 'IJAI_31343_Work')
    parser.add_argument('--run', action='store_true',
                        help='execute the isolated loopback test suite after cloning')
    args = parser.parse_args()

    root = args.root.expanduser().resolve()
    stage = root / STAGE7
    source = stage / TEST_REL
    runner = stage / RUNNER_REL

    if not stage.is_dir() or not source.is_file() or source.is_symlink() or runner.is_symlink():
        raise SystemExit('REFUSED: expected Stage7 test source is missing or a symlink')
    if source.resolve().parent != (stage / 'Tools').resolve():
        raise SystemExit('REFUSED: unexpected test source path')

    original = source.read_text(encoding='utf-8')
    if original.count(ANCHOR) != 1:
        raise SystemExit('REFUSED: unexpected unittest entry point (do not patch unknown source)')
    for expected in ('class SimulatedDevice:', 'class TestLoopbackEndToEnd(',
                     'def test_05_tampered_lifetime_rejected(', 'def handshake(',
                     'def data(', "'/ack'"):
        if expected not in original:
            raise SystemExit('REFUSED: missing expected fixture anchor: ' + expected)
    if 'def test_06_lost_ack_response_after_server_activation' in original:
        raise SystemExit('REFUSED: original test file already contains test_06')
    amended = original.replace(ANCHOR, NEW_TEST + ANCHOR)
    ast.parse(amended, filename=str(runner))

    if runner.exists():
        if runner.read_text(encoding='utf-8') != amended:
            raise SystemExit('REFUSED: existing runner differs; original left unchanged')
        print('Existing identical runner reused:', runner)
    else:
        runner.write_text(amended, encoding='utf-8')
        print('Created separate runner:', runner)
    print('Original test SHA256:', checksum(original.encode()))
    print('Injected runner SHA256:', checksum(amended.encode()))
    print('Original test remains unchanged. No secret key files inspected.')

    if not args.run:
        print('Prepared only. To execute, add --run.')
        return 0

    print('=== Stage7 loopback: five original tests + lost-ACK fault injection ===', flush=True)
    try:
        finished = subprocess.run(
            [sys.executable, str(runner)],
            cwd=str(stage / 'Tools'),
            capture_output=True, text=True,
            timeout=180,
            check=False,
        )
        output = (finished.stdout or '') + (finished.stderr or '')
        code = finished.returncode
    except subprocess.TimeoutExpired:
        output, code = 'TIMEOUT: Loopback suite exceeded 180 s.\n', 124

    print(output, end='' if output.endswith('\n') else '\n')
    dest = root / 'Revision_31343' / 'Experimental_Results' / 'Stage7_Fixed_vs_Adaptive' / 'Security_Fault_Injection'
    dest.mkdir(parents=True, exist_ok=True)
    evidence = dest / 'lost_ack_loopback_test_output.txt'
    evidence.write_text(output, encoding='utf-8')
    report = {
        'timestamp_utc': datetime.now(timezone.utc).isoformat(),
        'experiment': 'Stage7_loopback_fault_injection_lost_ack_response',
        'scope': 'software simulation, local loopback gateway and simulated device only',
        'source_test_sha256': checksum(original.encode()),
        'injected_runner_sha256': checksum(amended.encode()),
        'captured_output_sha256': checksum(output.encode()),
        'return_code': code,
        'status': 'PASS' if code == 0 and 'test_06_lost_ack_response_after_server_activation' in output and 'OK' in output else 'REVIEW',
        'limitations': [
            'A gateway activation may occur before the client receives its acknowledgement.',
            'No physical packet loss, ESP8266 firmware execution or EOSIO transaction was tested.',
            'A successful fresh handshake is loopback recovery, not cryptographic post-compromise recovery.',
        ],
    }
    (dest / 'lost_ack_loopback_report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('Evidence:', evidence)
    print('Report:', dest / 'lost_ack_loopback_report.json')
    print('Result:', report['status'])
    return 0 if report['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
