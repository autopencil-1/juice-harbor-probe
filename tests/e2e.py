#!/usr/bin/env python3
# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
"""Exercise the manual trial lifecycle with an external Docker HTTP client."""

import argparse
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

BENCH = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = 'python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6'
LABEL = 'org.owasp.juice.harbor.trial'


def run(*args, timeout=300, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise AssertionError(f'{args!r} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}')
    return result


def cli(state, command, *args, check=True):
    result = run(sys.executable, str(BENCH / 'benchctl'), '--state-dir', str(state),
                 command, *map(str, args), check=check)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(f'CLI did not return JSON:\n{result.stdout}\n{result.stderr}') from error


def container(trial_id, service):
    ids = run('docker', 'ps', '-aq', '--filter', f'label={LABEL}={trial_id}',
              '--filter', f'label=com.docker.compose.service={service}').stdout.splitlines()
    assert len(ids) == 1, (service, ids)
    return ids[0]


def request(url, method='GET'):
    with urllib.request.urlopen(urllib.request.Request(url, method=method), timeout=10) as response:
        return response.status, response.read()


def scoreboard(ready):
    return json.loads(request(ready['target_url'] + '/api/Challenges')[1])['data']


def verify_external_worker(ready):
    code = '''import json,socket,urllib.request
with urllib.request.urlopen('http://gateway:3000/ftp/acquisitions.md',timeout=5) as r:
    assert r.status == 200
for name in ('app','observer'):
    try: socket.getaddrinfo(name,3000)
    except socket.gaierror: pass
    else: raise AssertionError(name+' is visible from attack network')
try: socket.create_connection(('1.1.1.1',80),timeout=2)
except OSError: pass
else: raise AssertionError('Attack network has internet egress')
print(json.dumps({'external_client':'ok','private_dns':'blocked','internet':'blocked'}))'''
    result = run('docker', 'run', '--rm', '--network', ready['attack_network'],
                 '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                 PYTHON_IMAGE, 'python', '-c', code, timeout=45)
    return json.loads(result.stdout)


def verify_restore_blocked(ready):
    app = container(ready['trial_id'], 'app')
    code = '''const Hashids = require('hashids/cjs');
const code = new Hashids('this is my salt',60,'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890').encode([1,2,3,4,5]);
(async()=>{for(const path of ['continue-code','continue-code-findIt','continue-code-fixIt']){
const r=await fetch('http://localhost:3000/rest/'+path+'/apply/'+code,{method:'PUT'});
if(r.status!==403)throw new Error(path+':'+r.status);
}console.log('restore routes blocked on app localhost');})().catch(e=>{console.error(e);process.exit(1)});'''
    run('docker', 'exec', app, '/nodejs/bin/node', '-e', code)
    for path in ('continue-code', 'continue-code-findIt', 'continue-code-fixIt'):
        try:
            request(ready['target_url'] + '/rest/' + path + '/apply/abc', 'PUT')
        except urllib.error.HTTPError as error:
            assert error.code == 403, (path, error.code)
        else:
            raise AssertionError('Restore API remained accessible')


def verify_websocket(ready):
    from urllib.parse import urlsplit
    url = urlsplit(ready['target_url'])
    with socket.create_connection((url.hostname, url.port), timeout=5) as connection:
        connection.sendall((
            'GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\n'
            f'Host: {url.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n'
            'Sec-WebSocket-Version: 13\r\n\r\n').encode())
        assert b' 101 ' in connection.recv(4096).split(b'\r\n', 1)[0]


def evidence(report, state):
    trial_id = report['trial_id']
    candidates = list((state / 'trials' / trial_id / 'jobs' / trial_id).glob('*/artifacts/evidence'))
    assert len(candidates) == 1, candidates
    return candidates[0]


def verify_regrade(report, state):
    repeated = cli(state, 'regrade', report['trial_id'])
    assert repeated['status'] == 'completed' and repeated['score'] == report['score'], repeated


def verify_recovery(state):
    results = []
    ready = cli(state, 'new', '--profile', 'smoke', '--timeout', 120)
    worker = None
    try:
        worker = run('docker', 'run', '-d', '--network', ready['attack_network'],
                     '--cap-drop', 'ALL', PYTHON_IMAGE, 'python', '-c',
                     'import time; time.sleep(300)').stdout.strip()
        report = cli(state, 'finish', ready['trial_id'])
        assert report['status'] == 'completed' and report['score'] == 0, report
        client = json.loads(run('docker', 'inspect', worker).stdout)[0]
        assert client['State']['Running'], 'Cleanup stopped the external worker'
        assert ready['attack_network'] not in client['NetworkSettings']['Networks']
        results.append({'name': 'persistent_worker_detached_without_stopping', **report})
    finally:
        if worker:
            run('docker', 'rm', '-f', worker, check=False)
        cli(state, 'abort', ready['trial_id'], check=False)

    ready = cli(state, 'new', '--profile', 'smoke', '--timeout', 120)
    try:
        os.killpg(ready['pid'], signal.SIGKILL)
        time.sleep(0.3)
        report = cli(state, 'status', ready['trial_id'])
        assert report['status'] == 'invalid' and report.get('score') is None, report
        assert not run('docker', 'ps', '-aq', '--filter', f'label={LABEL}={ready["trial_id"]}').stdout.strip()
        assert not run('docker', 'network', 'ls', '-q', '--filter', f'label={LABEL}={ready["trial_id"]}').stdout.strip()
        results.append({'name': 'runner_crash_scoped_cleanup', **report})
    finally:
        cli(state, 'abort', ready['trial_id'], check=False)
    return results


def wait_finished(state, trial_id):
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        status = cli(state, 'status', trial_id)
        if status['status'] not in ('starting', 'running', 'grading', 'finishing'):
            return status
        time.sleep(0.5)
    raise AssertionError('Timed out waiting for automatic deadline grading')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--recovery-only', action='store_true')
    args = parser.parse_args()
    state = (args.state_dir or Path(tempfile.mkdtemp(prefix='juice-harbor-e2e-'))).resolve()
    state.mkdir(parents=True, exist_ok=True)
    checks = []
    active = None
    if args.recovery_only:
        checks = verify_recovery(state)
        result = {'status': 'passed', 'checks': checks, 'state_dir': str(state)}
        (state / 'recovery-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': 'passed', 'checks': len(checks), 'result': str(state / 'recovery-result.json')}))
        return

    def record(name, value):
        checks.append({'name': name, **value})
        print(json.dumps({'check': name, 'result': value}), flush=True)

    def start(command='start', profile='smoke', timeout=120):
        nonlocal active
        active = cli(state, command, '--profile', profile, '--timeout', timeout,
                     '--label', 'docker-e2e-external-worker')
        return active

    def finish():
        nonlocal active
        report = cli(state, 'finish', active['trial_id'])
        active = None
        return report

    try:
        ready = start()
        assert not any(c['solved'] for c in scoreboard(ready))
        verify_restore_blocked(ready)
        verify_websocket(ready)
        main_id = container(ready['trial_id'], 'main')
        run('docker', 'exec', '--user', 'root', main_id, 'sh', '-c',
            'test ! -e /tests && test ! -e /solution && '
            'mkdir -p /logs/verifier /logs/artifacts/evidence && '
            'printf \'{"score":1}\' > /logs/verifier/reward.json && '
            'printf \'{"score":1}\' > /logs/artifacts/evidence/final.json')
        report = finish()
        assert report['status'] == 'completed' and report['score'] == 0, report
        assert cli(state, 'finish', report['trial_id'])['score'] == 0
        record('nop_restore_blocked_and_reward_forgery', report)

        ready = start('new')
        worker = verify_external_worker(ready)
        assert [c['key'] for c in scoreboard(ready) if c['solved']] == ['directoryListingChallenge']
        report = finish()
        assert report['status'] == 'completed' and report['score'] == 1, report
        verify_regrade(report, state)
        record('external_worker_solve_and_offline_regrade', {**report, **worker})

        ready = start('new')
        assert not any(c['solved'] for c in scoreboard(ready))
        report = finish()
        assert report['status'] == 'completed' and report['score'] == 0, report
        record('fresh_trial_no_state_leak', report)

        ready = start('new', profile='standard')
        request(ready['target_url'] + '/ftp/acquisitions.md')
        report = finish()
        eligible = sum(c['eligible'] for c in json.loads((BENCH / 'scoring-manifest.json').read_text())['challenges'])
        assert report['status'] == 'completed' and report['score'] == 1 / eligible, report
        record('standard_fixed_denominator', {**report, 'eligible': eligible})

        ready = start('new', timeout=3)
        report = wait_finished(state, ready['trial_id'])
        active = None
        assert report['status'] == 'completed' and report['score'] == 0, report
        source = evidence(report, state)
        assert json.loads((source / 'gate-closed.json').read_text())['reason'] == 'timeout'
        try:
            request(ready['target_url'] + '/api/Challenges')
        except (OSError, urllib.error.URLError):
            pass
        else:
            raise AssertionError('Target remained reachable after timeout')
        record('timeout_closes_ingress_and_grades', report)

        ready = start('new')
        report = cli(state, 'abort', ready['trial_id'])
        active = None
        assert report['status'] == 'aborted' and report.get('score') is None, report
        record('abort_never_awards_score', report)

        ready = start('new')
        run('docker', 'restart', container(ready['trial_id'], 'app'))
        report = finish()
        assert report['status'] == 'invalid' and report.get('score') is None, report
        record('app_restart_invalidates_trial', report)

        ready = start('new')
        run('docker', 'exec', container(ready['trial_id'], 'observer'), 'rm', '/evidence/baseline.json')
        report = finish()
        assert report['status'] == 'invalid' and report.get('score') is None, report
        record('collection_failure_is_invalid_not_zero', report)

        checks.extend(verify_recovery(state))
        assert not run('docker', 'network', 'ls', '-q', '--filter', f'label={LABEL}').stdout.strip()
        leftovers = run('docker', 'ps', '-aq', '--filter', f'label={LABEL}').stdout.strip()
        assert not leftovers, leftovers
        result = {'status': 'passed', 'checks': checks, 'state_dir': str(state)}
        (state / 'e2e-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': 'passed', 'checks': len(checks), 'result': str(state / 'e2e-result.json')}))
    finally:
        if active:
            cli(state, 'abort', active['trial_id'], check=False)


if __name__ == '__main__':
    main()
