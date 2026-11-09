# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT

"""Collect scoreboard evidence without exposing a network listener."""

import hashlib
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


EVIDENCE = Path('/evidence')
MANIFEST = Path('/opt/benchmark/scoring-manifest.json')
URL = 'http://app:3000/api/Challenges'
STATIC_FIELDS = (
    'name', 'difficulty', 'disabledEnv', 'category', 'description', 'tags',
    'mitigationUrl', 'tutorialOrder', 'hasCodingChallenge', 'createdAt',
)


def now():
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        json.dump(value, output, sort_keys=True, allow_nan=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(value):
    def unique_pairs(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError('Duplicated JSON object key: ' + key)
            result[key] = item
        return result

    def invalid_constant(value):
        raise ValueError('Non-finite JSON number: ' + value)

    return json.loads(value, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)


def read_json(path):
    return strict_json(path.read_text())


def dependencies(value):
    if not isinstance(value, list):
        raise ValueError('ChallengeDependencies must be an array')
    result = {}
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get('key'), str):
            raise ValueError('Invalid challenge dependency')
        if type(item.get('missing')) is not bool or item['key'] in result:
            raise ValueError('Invalid or duplicated challenge dependency')
        result[item['key']] = item['missing']
    return result


def records(snapshot, manifest):
    if not isinstance(snapshot, dict) or snapshot.get('status') != 'success':
        raise ValueError('Challenges API did not return success')
    data = snapshot.get('data')
    if not isinstance(data, list):
        raise ValueError('Challenges API data must be an array')
    expected = {item['key']: item for item in manifest['challenges']}
    result = {}
    for item in data:
        if not isinstance(item, dict) or not isinstance(item.get('key'), str):
            raise ValueError('Invalid challenge record')
        key = item['key']
        if key in result or key not in expected:
            raise ValueError('Unexpected or duplicated challenge key: ' + key)
        spec = expected[key]
        for field in ('name', 'difficulty', 'disabledEnv'):
            if item.get(field) != spec[field] or type(item.get(field)) is not type(spec[field]):
                raise ValueError('Challenge metadata differs: ' + key + '.' + field)
        if type(item.get('solved')) is not bool:
            raise ValueError('solved must be a boolean: ' + key)
        if not isinstance(item.get('createdAt'), str):
            raise ValueError('Missing challenge creation timestamp: ' + key)
        if dependencies(item.get('ChallengeDependencies')) != dependencies(spec['dependencies']):
            raise ValueError('Challenge dependencies differ: ' + key)
        result[key] = item
    if result.keys() != expected.keys():
        raise ValueError('Challenge catalog differs from scoring manifest')
    return result


def fetch_snapshot(manifest, timeout=3):
    request = urllib.request.Request(URL, headers={'User-Agent': 'JuiceHarborObserver/1'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        if response.status != 200:
            raise ValueError('Challenges API returned a non-200 response')
        if response.geturl() != URL:
            raise ValueError('Challenges API redirected the observer')
        body = response.read(2_000_001)
        if len(body) > 2_000_000:
            raise ValueError('Challenges API response exceeds the evidence limit')
        snapshot = strict_json(body)
    records(snapshot, manifest)
    return snapshot


def check_same_instance(baseline, final):
    for key in baseline:
        for field in STATIC_FIELDS:
            if baseline[key].get(field) != final[key].get(field):
                raise ValueError('Challenge instance or metadata changed: ' + key + '.' + field)


def baseline(manifest, trial_id):
    deadline = time.monotonic() + 60
    while True:
        try:
            snapshot = fetch_snapshot(manifest)
            break
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
    if any(item['solved'] for item in snapshot['data']):
        raise ValueError('Baseline contains solved challenges')
    atomic_json(EVIDENCE / 'session.json', {
        'schema_version': 1,
        'trial_id': trial_id,
        'manifest_sha256': digest(MANIFEST),
        'started_at': now(),
    })
    atomic_json(EVIDENCE / 'baseline.json', snapshot)
    while True:
        time.sleep(60)


def final(manifest, trial_id):
    for name in ('final.json', 'complete.json', 'error.json'):
        (EVIDENCE / name).unlink(missing_ok=True)
    session = read_json(EVIDENCE / 'session.json')
    gate = read_json(EVIDENCE / 'gate-closed.json')
    if session.get('trial_id') != trial_id or gate.get('trial_id') != trial_id:
        raise ValueError('Evidence belongs to another trial')
    if session.get('manifest_sha256') != digest(MANIFEST):
        raise ValueError('Scoring manifest changed during trial')
    if gate.get('gateway_stopped') is not True or gate.get('app_unchanged') is not True:
        raise ValueError('Gateway closure and unchanged app must be confirmed')
    if gate.get('reason') not in ('finished', 'timeout'):
        raise ValueError('Trial was aborted or has an invalid termination reason')
    if not isinstance(gate.get('closed_at'), str):
        raise ValueError('Missing gateway closure timestamp')
    initial = records(read_json(EVIDENCE / 'baseline.json'), manifest)
    if any(item['solved'] for item in initial.values()):
        raise ValueError('Baseline contains solved challenges')
    deadline = time.monotonic() + 10
    time.sleep(1)
    previous = None
    while time.monotonic() < deadline:
        snapshot = fetch_snapshot(manifest, timeout=min(3, max(0.1, deadline - time.monotonic())))
        current = records(snapshot, manifest)
        check_same_instance(initial, current)
        state = {key: item['solved'] for key, item in current.items()}
        if state == previous:
            atomic_json(EVIDENCE / 'final.json', snapshot)
            atomic_json(EVIDENCE / 'complete.json', {
                'schema_version': 1,
                'trial_id': trial_id,
                'manifest_sha256': digest(MANIFEST),
                'baseline_sha256': digest(EVIDENCE / 'baseline.json'),
                'final_sha256': digest(EVIDENCE / 'final.json'),
                'completed_at': now(),
            })
            return
        previous = state
        time.sleep(0.5)
    raise ValueError('Scoreboard did not stabilize within the collection deadline')


def main():
    trial_id = os.environ.get('JUICE_TRIAL_ID')
    if not trial_id:
        raise ValueError('JUICE_TRIAL_ID is required')
    manifest = read_json(MANIFEST)
    if type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1 or not manifest.get('challenges'):
        raise ValueError('Invalid scoring manifest')
    if len({item['key'] for item in manifest['challenges']}) != len(manifest['challenges']):
        raise ValueError('Duplicated manifest challenge key')
    phase = sys.argv[1] if len(sys.argv) == 2 else None
    if phase == 'baseline':
        baseline(manifest, trial_id)
    elif phase == 'final':
        final(manifest, trial_id)
    else:
        raise ValueError('Expected baseline or final command')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        atomic_json(EVIDENCE / 'error.json', {
            'trial_id': os.environ.get('JUICE_TRIAL_ID'),
            'error': str(error),
            'recorded_at': now(),
        })
        print(str(error), file=sys.stderr)
        sys.exit(1)
