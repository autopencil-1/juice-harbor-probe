# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT

"""Grade trusted observer artifacts in a fresh, offline verifier."""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path


STATIC_FIELDS = (
    'name', 'difficulty', 'disabledEnv', 'category', 'description', 'tags',
    'mitigationUrl', 'tutorialOrder', 'hasCodingChallenge', 'createdAt',
)


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


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
    try:
        return strict_json(path.read_text())
    except (OSError, ValueError) as error:
        raise EvidenceError('Cannot read valid JSON from ' + path.name) from error


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timestamp(value, field):
    require(isinstance(value, str), 'Missing timestamp: ' + field)
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as error:
        raise EvidenceError('Invalid timestamp: ' + field) from error
    require(parsed.tzinfo is not None, 'Timestamp must include a timezone: ' + field)
    return parsed


def dependencies(value):
    require(isinstance(value, list), 'Dependencies must be an array')
    result = {}
    for item in value:
        require(isinstance(item, dict), 'Invalid dependency')
        key = item.get('key')
        require(isinstance(key, str) and bool(key), 'Dependency key is required')
        require(key not in result, 'Duplicated dependency key')
        require(type(item.get('missing')) is bool, 'Dependency missing must be boolean')
        result[key] = item['missing']
    return result


def validate_manifest(manifest):
    require(isinstance(manifest, dict) and type(manifest.get('schema_version')) is int and manifest['schema_version'] == 1, 'Invalid manifest schema')
    require(isinstance(manifest.get('app_version'), str), 'Manifest app version is required')
    require(isinstance(manifest.get('base_image'), str), 'Manifest base image is required')
    challenges = manifest.get('challenges')
    require(isinstance(challenges, list) and bool(challenges), 'Manifest challenges are required')
    result = {}
    for item in challenges:
        require(isinstance(item, dict), 'Invalid manifest challenge')
        key = item.get('key')
        require(isinstance(key, str) and bool(key), 'Manifest key is required')
        require(key not in result, 'Duplicated manifest key: ' + key)
        require(isinstance(item.get('name'), str), 'Manifest name is required: ' + key)
        require(type(item.get('difficulty')) is int and 1 <= item['difficulty'] <= 6, 'Invalid manifest difficulty')
        disabled = item.get('disabledEnv')
        require(disabled is None or isinstance(disabled, str), 'Invalid disabledEnv')
        deps = dependencies(item.get('dependencies'))
        require(type(item.get('eligible')) is bool, 'Manifest eligible must be boolean')
        if item['eligible']:
            require(item.get('exclusion_reason') is None, 'Eligible challenge cannot have an exclusion reason')
            require(not disabled and not any(deps.values()), 'Unavailable challenge cannot be eligible: ' + key)
            require(key != 'continueCodeChallenge', 'Progress restoration cannot be scored')
        else:
            require(isinstance(item.get('exclusion_reason'), str) and bool(item['exclusion_reason']), 'Excluded challenge needs a reason')
        result[key] = item
    require(any(item['eligible'] for item in result.values()), 'Manifest has no eligible challenges')
    return result


def records(snapshot, expected):
    require(isinstance(snapshot, dict) and snapshot.get('status') == 'success', 'Invalid Challenges API status')
    require(isinstance(snapshot.get('data'), list), 'Invalid Challenges API data')
    result = {}
    for item in snapshot['data']:
        require(isinstance(item, dict), 'Invalid challenge record')
        key = item.get('key')
        require(isinstance(key, str) and key in expected, 'Unknown challenge key')
        require(key not in result, 'Duplicated challenge key: ' + key)
        for field in ('name', 'difficulty', 'disabledEnv'):
            require(field in item and item[field] == expected[key][field]
                    and type(item[field]) is type(expected[key][field]), 'Challenge metadata differs: ' + key + '.' + field)
        require(type(item.get('solved')) is bool, 'solved must be boolean: ' + key)
        timestamp(item.get('createdAt'), key + '.createdAt')
        require(dependencies(item.get('ChallengeDependencies')) == dependencies(expected[key]['dependencies']), 'Challenge dependencies differ: ' + key)
        result[key] = item
    require(result.keys() == expected.keys(), 'Challenge catalog differs from manifest')
    return result


def grade(evidence_dir, manifest_path):
    require(not (evidence_dir / 'error.json').exists(), 'Observer reported an error')
    manifest = read_json(manifest_path)
    expected = validate_manifest(manifest)
    manifest_hash = digest(manifest_path)
    session = read_json(evidence_dir / 'session.json')
    complete = read_json(evidence_dir / 'complete.json')
    gate = read_json(evidence_dir / 'gate-closed.json')
    require(all(isinstance(value, dict) for value in (session, complete, gate)), 'Invalid evidence metadata')
    trial_id = session.get('trial_id')
    require(isinstance(trial_id, str) and bool(trial_id), 'Trial identity is required')
    require(complete.get('trial_id') == trial_id == gate.get('trial_id'), 'Evidence trial identity differs')
    require(type(session.get('schema_version')) is int and session['schema_version'] == 1
            and type(complete.get('schema_version')) is int and complete['schema_version'] == 1, 'Invalid evidence schema')
    require(session.get('manifest_sha256') == manifest_hash == complete.get('manifest_sha256'), 'Manifest hash differs')
    require(gate.get('gateway_stopped') is True, 'Gateway was not confirmed stopped')
    require(gate.get('app_unchanged') is True, 'App instance changed during trial')
    require(gate.get('reason') in ('finished', 'timeout'), 'Trial is aborted or has an invalid termination reason')
    started = timestamp(session.get('started_at'), 'started_at')
    closed = timestamp(gate.get('closed_at'), 'closed_at')
    completed = timestamp(complete.get('completed_at'), 'completed_at')
    require(started <= closed <= completed, 'Evidence timestamps are out of order')
    for name in ('baseline', 'final'):
        path = evidence_dir / (name + '.json')
        require(path.is_file(), 'Missing snapshot: ' + name)
        require(complete.get(name + '_sha256') == digest(path), 'Snapshot hash differs: ' + name)
    initial = records(read_json(evidence_dir / 'baseline.json'), expected)
    final = records(read_json(evidence_dir / 'final.json'), expected)
    require(not any(item['solved'] for item in initial.values()), 'Baseline contains solved challenges')
    for key in expected:
        for field in STATIC_FIELDS:
            require(initial[key].get(field) == final[key].get(field), 'Challenge instance or metadata changed: ' + key + '.' + field)
    eligible = {key for key, item in expected.items() if item['eligible']}
    solved = {key for key, item in final.items() if item['solved']}
    scored = sorted(solved & eligible)
    score = len(scored) / len(eligible)
    return {
        'schema_version': 1,
        'trial_id': trial_id,
        'score': score,
        'solved_count': len(scored),
        'eligible_count': len(eligible),
        'challenge_count': len(expected),
        'solved_keys': scored,
        'unscored_solved_keys': sorted(solved - eligible),
        'exclusions': {key: item['exclusion_reason'] for key, item in expected.items() if not item['eligible']},
        'reason': gate['reason'],
        'manifest_sha256': manifest_hash,
        'started_at': session['started_at'],
        'closed_at': gate['closed_at'],
        'completed_at': complete['completed_at'],
    }


def atomic_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        json.dump(value, output, indent=2, sort_keys=True, allow_nan=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--evidence', type=Path, default=Path('/evidence'))
    parser.add_argument('--manifest', type=Path, default=Path('/opt/benchmark/scoring-manifest.json'))
    parser.add_argument('--output', type=Path, default=Path('/logs/verifier'))
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    for name in ('reward.json', 'reward.txt', 'details.json', 'invalid.json'):
        (args.output / name).unlink(missing_ok=True)
    try:
        details = grade(args.evidence, args.manifest)
    except (EvidenceError, OSError) as error:
        atomic_json(args.output / 'invalid.json', {'valid': False, 'error': str(error)})
        print(str(error), file=sys.stderr)
        return 1
    atomic_json(args.output / 'details.json', details)
    atomic_json(args.output / 'reward.json', {'score': details['score']})
    print(json.dumps({'trial_id': details['trial_id'], 'score': details['score'], 'solved_keys': details['solved_keys']}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
