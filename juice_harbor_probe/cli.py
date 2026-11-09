# Copyright (c) 2026 OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
"""Manual trial lifecycle. Control files stay on the trusted Harbor host."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parents[1]
PROJECT = HERE
TERMINAL = {'completed', 'invalid', 'aborted'}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, indent=2)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'))


def trial_path(state_dir, trial_id):
    try:
        canonical = str(uuid.UUID(trial_id))
    except (ValueError, AttributeError) as error:
        raise ValueError('Trial ID must be a UUID') from error
    if canonical != trial_id:
        raise ValueError('Trial ID must be a canonical UUID')
    return state_dir / 'trials' / canonical


@contextmanager
def lock_state(state_dir):
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (state_dir / '.lock').open('a+') as handle:
        os.chmod(state_dir / '.lock', 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def checked(command, **kwargs):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed: {result.stderr.strip() or result.stdout.strip()}')
    return result.stdout.strip()


def process_identity(pid):
    try:
        stat = Path(f'/proc/{int(pid)}/stat').read_text().rsplit(')', 1)[1].split()
        if stat[0] == 'Z':
            return None
        return stat[19]
    except (OSError, ValueError, IndexError):
        return None


def process_alive(state):
    identity = process_identity(state.get('pid', 0))
    return bool(identity and identity == state.get('pid_start'))


def resolve_trial(state_dir, requested=None):
    if requested is None:
        active = state_dir / 'active.json'
        if not active.exists():
            raise ValueError('No trial exists; use start first')
        requested = read_json(active)['trial_id']
    directory = trial_path(state_dir, requested)
    if not (directory / 'state.json').is_file():
        raise ValueError('Unknown trial ID')
    return directory


def result_report(directory):
    state = read_json(directory / 'state.json')
    trial_id = state['trial_id']
    control = directory / 'control'
    job = directory / 'jobs' / trial_id
    job_result_path = job / 'result.json'
    report = dict(state)
    report.update({'trial_id': trial_id, 'score': None,
                   'result_path': str(job_result_path), 'control_dir': str(control)})
    ready_path = control / 'ready.json'
    if ready_path.exists():
        try:
            ready = read_json(ready_path)
            if not isinstance(ready, dict):
                raise ValueError('Ready file must be an object')
        except (ValueError, OSError):
            report.update(status='invalid', error='Ready file is malformed')
            return report
        if ready.get('trial_id') != trial_id:
            report.update(status='invalid', error='Ready file belongs to another trial')
            return report
        report.update(ready)
    report['status'] = 'running' if ready_path.exists() else 'starting'
    if (control / 'closed.json').exists():
        report['reason'] = read_json(control / 'closed.json').get('reason')
    job_result = read_json(job_result_path) if job_result_path.is_file() else None
    if job_result and job_result.get('finished_at'):
        results = list(job.glob('*/result.json'))
        if len(results) != 1:
            report.update(status='invalid', error='Expected exactly one Harbor trial result')
            return report
        result = read_json(results[0])
        rewards = (result.get('verifier_result') or {}).get('rewards') or {}
        score = rewards.get('score')
        finish = read_json(control / 'finish.json') if (control / 'finish.json').exists() else {}
        invalid_path = control / 'invalid.json'
        if finish.get('reason') == 'aborted':
            report.update(status='aborted', error='Trial cancelled by operator')
        elif invalid_path.exists():
            report.update(status='invalid', error=read_json(invalid_path).get('error'))
        elif type(score) in (int, float) and math.isfinite(score) and 0 <= score <= 1:
            report.update(status='completed', score=score)
        else:
            report.update(status='invalid', error=(result.get('exception_info') or {}).get(
                'exception_message', 'Verifier did not produce a valid score'))
        report['trial_result_path'] = str(results[0])
        report['evidence_dir'] = str(results[0].parent / 'artifacts' / 'evidence')
        report['verifier_dir'] = str(results[0].parent / 'verifier')
        report['harbor_exception'] = result.get('exception_info')
        report['finished_at'] = job_result['finished_at']
    elif not process_alive(state):
        report.update(status='invalid', error='Harbor runner exited before completing this trial')
    return report


def cleanup(directory, stop_runner=False):
    state = read_json(directory / 'state.json')
    if stop_runner and process_alive(state):
        os.killpg(state['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 5
        while process_alive(state) and time.monotonic() < deadline:
            time.sleep(0.1)
        if process_alive(state):
            os.killpg(state['pid'], signal.SIGKILL)
    label = f'org.owasp.juice.harbor.trial={state["trial_id"]}'
    ids = checked(['docker', 'ps', '-aq', '--filter', f'label={label}']).splitlines()
    projects = set()
    networks = set()
    if ids:
        for container in json.loads(checked(['docker', 'inspect', *ids])):
            projects.add(container['Config']['Labels'].get('com.docker.compose.project'))
            networks.update(container['NetworkSettings']['Networks'])
        checked(['docker', 'rm', '-f', *ids])
    networks.update(checked(['docker', 'network', 'ls', '-q', '--filter', f'label={label}']).splitlines())
    inspected = {}
    for name in networks:
        info = json.loads(checked(['docker', 'network', 'inspect', name]))[0]
        inspected[info.get('Id', name)] = info
    for name, info in inspected.items():
        labels = info.get('Labels') or {}
        owned = labels.get('org.owasp.juice.harbor.trial') == state['trial_id']
        if owned:
            for endpoint in (info.get('Containers') or {}):
                checked(['docker', 'network', 'disconnect', '--force', name, endpoint])
        if owned or labels.get('com.docker.compose.project') in projects:
            remaining = json.loads(checked(['docker', 'network', 'inspect', name]))[0]
            if not remaining.get('Containers'):
                checked(['docker', 'network', 'rm', name])


def set_agent_timeout(text, timeout):
    pattern = re.compile(r'(?ms)(^\[agent\]\s*\n)(.*?)(?=^\[|\Z)')
    found = pattern.search(text)
    if not found:
        raise ValueError('Task template has no agent section')
    section = found.group(2)
    section, count = re.subn(r'(?m)^timeout_sec\s*=.*$', f'timeout_sec = {timeout}', section)
    if count != 1:
        raise ValueError('Task template must have one agent timeout')
    return text[:found.start()] + found.group(1) + section + text[found.end():]


def materialize(directory, profile, timeout):
    task = directory / 'task'
    shutil.copytree(HERE / 'task', task, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    manifest = read_json(HERE / 'scoring-manifest.json')
    implementation = hashlib.sha256()
    sources = sorted(path for path in task.rglob('*') if path.is_file())
    sources += [Path(__file__).resolve(), Path(__file__).with_name('manual_agent.py')]
    for source in sources:
        implementation.update(source.name.encode() + b'\0' + source.read_bytes())
    manifest['implementation_sha256'] = implementation.hexdigest()
    manifest['harbor_version'] = '0.25.0'
    manifest['attack_timeout_sec'] = timeout
    manifest['profile'] = profile
    if profile == 'smoke':
        for challenge in manifest['challenges']:
            challenge['eligible'] = challenge['key'] == 'directoryListingChallenge'
            challenge['exclusion_reason'] = None if challenge['eligible'] else 'smoke-profile'
    encoded = (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode()
    for subdirectory in ('environment', 'tests'):
        (task / subdirectory / 'scoring-manifest.json').write_bytes(encoded)
    (directory / 'scoring-manifest.json').write_bytes(encoded)
    config = task / 'task.toml'
    config.write_text(set_agent_timeout(config.read_text(), timeout + 60))
    return task, hashlib.sha256(encoded).hexdigest()


def start(args):
    with lock_state(args.state_dir):
        active = args.state_dir / 'active.json'
        if active.exists():
            previous = resolve_trial(args.state_dir)
            report = result_report(previous)
            if report['status'] not in TERMINAL:
                raise ValueError(f'Trial {report["trial_id"]} is active; finish or abort it first')
            cleanup(previous, stop_runner=process_alive(read_json(previous / 'state.json')))
        harbor = shutil.which('harbor')
        if harbor is None:
            raise RuntimeError('Install Harbor 0.25.0 before starting a trial')
        if checked([harbor, '--version']) != '0.25.0':
            raise RuntimeError('This benchmark requires Harbor 0.25.0')
        checked(['docker', 'version', '--format', '{{.Server.Version}}'])
        checked(['docker', 'compose', 'version'])
        trial_id = str(uuid.uuid4())
        directory = trial_path(args.state_dir, trial_id)
        control = directory / 'control'
        control.mkdir(parents=True, mode=0o700)
        task, manifest_hash = materialize(directory, args.profile, args.timeout)
        command = [harbor, 'run', '-p', str(task), '-a',
                   'juice_harbor_probe.manual_agent:ManualExternalAgent',
                   '--ak', f'control_dir={control}', '--ak', f'trial_id={trial_id}',
                   '--ak', f'external_agent_label={args.label}',
                   '--ak', f'timeout_sec={args.timeout}',
                   '--ak', f'manifest_sha256={manifest_hash}',
                   '--env', 'docker', '-n', '1', '--job-name', trial_id,
                   '-o', str(directory / 'jobs'), '--debug']
        env = os.environ.copy()
        env.update(JUICE_TRIAL_ID=trial_id, JUICE_BIND_PORT=str(args.port),
                   PYTHONPATH=str(PROJECT) + os.pathsep + env.get('PYTHONPATH', ''))
        with (directory / 'runner.log').open('w') as log:
            process = subprocess.Popen(command, cwd=PROJECT, env=env, stdout=log,
                                       stderr=subprocess.STDOUT, start_new_session=True)
        state = {'trial_id': trial_id, 'status': 'starting', 'pid': process.pid,
                 'pid_start': process_identity(process.pid), 'profile': args.profile,
                 'created_at': utc_now(), 'timeout_sec': args.timeout,
                 'manifest_sha256': manifest_hash, 'runner_log': str(directory / 'runner.log')}
        write_json(directory / 'state.json', state)
        write_json(active, {'trial_id': trial_id})
        try:
            deadline = time.monotonic() + args.startup_timeout
            while time.monotonic() < deadline:
                report = result_report(directory)
                if report['status'] == 'running':
                    return report
                if report['status'] in TERMINAL:
                    raise RuntimeError(f'Trial failed to start: {report.get("error")}; log: {state["runner_log"]}')
                time.sleep(0.2)
            raise RuntimeError(f'Startup timed out; log: {state["runner_log"]}')
        except BaseException as error:
            invalid = {'trial_id': trial_id, 'error': str(error) or type(error).__name__}
            try:
                cleanup(directory, stop_runner=True)
            except Exception as cleanup_error:
                invalid['cleanup_error'] = str(cleanup_error)
            write_json(control / 'invalid.json', invalid)
            raise


def wait_report(directory, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        report = result_report(directory)
        if report['status'] in TERMINAL:
            with lock_state(directory.parent.parent):
                report = result_report(directory)
                cleanup(directory)
                write_json(directory / 'report.json', report)
            return report
        time.sleep(0.2)
    raise TimeoutError('Grading is still running; inspect status or wait with finish again')


def finish(args, reason='finished'):
    with lock_state(args.state_dir):
        directory = resolve_trial(args.state_dir, args.trial_id)
        report = result_report(directory)
        if report['status'] in TERMINAL:
            cleanup(directory, stop_runner=process_alive(read_json(directory / 'state.json')))
            return report
        control = directory / 'control'
        path = control / 'finish.json'
        expected = {'trial_id': report['trial_id'], 'reason': reason}
        if path.exists():
            existing = read_json(path)
            if existing.get('trial_id') != report['trial_id']:
                raise ValueError('Existing finish signal belongs to a different trial')
            if existing.get('reason') != reason:
                raise ValueError('A different finish request is already pending')
        else:
            write_json(path, {**expected, 'requested_at': utc_now()})
    return wait_report(directory, args.wait_timeout)


def regrade(args):
    with lock_state(args.state_dir):
        directory = resolve_trial(args.state_dir, args.trial_id)
        report = result_report(directory)
        if report['status'] not in TERMINAL:
            raise ValueError('Finish the trial before regrading it')
        evidence = Path(report.get('evidence_dir', directory / 'missing-evidence'))
        if not evidence.is_dir():
            raise ValueError('Trial has no archived observer evidence')
        output = directory / 'regrades' / str(uuid.uuid4())
        output.mkdir(parents=True, mode=0o700)
        grader = HERE / 'task/tests/grader.py'
        manifest = directory / 'scoring-manifest.json'
        command = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--user', f'{os.getuid()}:{os.getgid()}']
        for source, target in ((evidence, '/evidence'),
                               (manifest, '/opt/benchmark/scoring-manifest.json'),
                               (grader, '/tests/grader.py')):
            command.extend(['--mount', f'type=bind,src={source},dst={target},readonly'])
        command.extend(['--mount', f'type=bind,src={output},dst=/logs/verifier',
                        'python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6',
                        'python', '/tests/grader.py'])
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        metadata = {'trial_id': report['trial_id'], 'regraded_at': utc_now(),
                    'verifier_dir': str(output),
                    'grader_sha256': hashlib.sha256(grader.read_bytes()).hexdigest()}
        if result.returncode:
            invalid = output / 'invalid.json'
            if not invalid.is_file():
                raise RuntimeError('Regrade failed: ' + result.stderr.strip())
            return {**metadata, 'status': 'invalid', 'score': None,
                    'error': read_json(invalid)['error']}
        return {**metadata, 'status': 'completed',
                'score': read_json(output / 'reward.json')['score']}


def parser():
    result = argparse.ArgumentParser(description='Operate a manual Juice Shop Harbor trial')
    result.add_argument('--state-dir', type=lambda value: Path(value).expanduser().resolve(),
                        default=HERE / '.state')
    commands = result.add_subparsers(dest='command', required=True)
    for name in ('start', 'new'):
        command = commands.add_parser(name)
        command.add_argument('--label', default='external')
        command.add_argument('--profile', choices=['standard', 'smoke'], default='standard')
        command.add_argument('--timeout', type=int, default=3600)
        command.add_argument('--port', type=int, default=0)
        command.add_argument('--startup-timeout', type=float, default=180)
    for name in ('status', 'regrade'):
        command = commands.add_parser(name)
        command.add_argument('trial_id', nargs='?')
    for name in ('finish', 'abort'):
        command = commands.add_parser(name)
        command.add_argument('trial_id', nargs='?')
        command.add_argument('--wait-timeout', type=float, default=180)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command in ('start', 'new'):
            if args.timeout < 1 or args.startup_timeout < 1 or not 0 <= args.port <= 65535:
                raise ValueError('Timeouts must be positive and port must be between 0 and 65535')
            report = start(args)
        elif args.command == 'regrade':
            report = regrade(args)
        elif args.command == 'status':
            with lock_state(args.state_dir):
                directory = resolve_trial(args.state_dir, args.trial_id)
                report = result_report(directory)
                if report['status'] in TERMINAL:
                    cleanup(directory, stop_runner=process_alive(read_json(directory / 'state.json')))
        else:
            if args.wait_timeout <= 0:
                raise ValueError('Wait timeout must be positive')
            report = finish(args, 'aborted' if args.command == 'abort' else 'finished')
        print(json.dumps(report, ensure_ascii=False))
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'error', 'error': str(error)}, ensure_ascii=False))
        raise SystemExit(1)


if __name__ == '__main__':
    main()
