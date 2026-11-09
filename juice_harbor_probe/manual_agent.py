# Copyright (c) 2026 OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
"""Host-side Harbor adapter for an external, manually operated agent."""

import asyncio
import json
import os
from pathlib import Path
import shlex
import time
from datetime import datetime, timezone
import urllib.request
import uuid

from harbor.agents.base import BaseAgent


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w', encoding='utf-8') as output:
        os.chmod(temporary, 0o600)
        json.dump(value, output, indent=2)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


class ManualExternalAgent(BaseAgent):
    def __init__(self, *args, control_dir, trial_id, external_agent_label='external',
                 timeout_sec=3600, manifest_sha256, **kwargs):
        super().__init__(*args, **kwargs)
        self.trial_id = str(uuid.UUID(str(trial_id)))
        self.control = Path(control_dir).resolve()
        self.control.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.external_agent_label = str(external_agent_label)
        self.timeout_sec = float(timeout_sec)
        self.manifest_sha256 = str(manifest_sha256)
        self.gateway = None
        self.app = None
        self.session = None

    @staticmethod
    def name():
        return 'juice-shop-manual-external'

    def version(self):
        return '1.0.0'

    async def docker(self, *args):
        process = await asyncio.create_subprocess_exec(
            'docker', *args, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        try:
            output, error = await asyncio.wait_for(process.communicate(), timeout=30)
        except BaseException:
            process.kill()
            await process.wait()
            raise
        if process.returncode:
            raise RuntimeError(f'Docker command failed: {error.decode().strip()}')
        return output.decode().strip()

    async def container(self, service):
        output = await self.docker(
            'ps', '-aq', '--filter', f'label=org.owasp.juice.harbor.trial={self.trial_id}',
            '--filter', f'label=com.docker.compose.service={service}')
        ids = output.splitlines()
        if len(ids) != 1:
            raise RuntimeError(f'Expected one {service} container for this trial')
        return json.loads(await self.docker('inspect', ids[0]))[0]

    async def observer_json(self, environment, filename, value=None):
        if value is None:
            code = f"from pathlib import Path; print(Path('/evidence/{filename}').read_text())"
        else:
            encoded = json.dumps(value)
            code = (
                'import json,os; from pathlib import Path; '
                f"p=Path('/evidence/{filename}'); t=p.with_suffix('.tmp'); "
                f't.write_text({encoded!r}); '
                'f=t.open("r"); os.fsync(f.fileno()); f.close(); t.replace(p)')
        result = await environment.service_exec(
            'python -c ' + shlex.quote(code), service='observer', timeout_sec=15)
        if result.return_code:
            raise RuntimeError(f'Observer {filename} failed: {result.stderr}')
        return json.loads(result.stdout) if value is None else value

    async def setup(self, environment):
        self.session = await self.observer_json(environment, 'session.json')
        if self.session.get('trial_id') != self.trial_id:
            raise RuntimeError('Observer trial identity does not match')
        if self.session.get('manifest_sha256') != self.manifest_sha256:
            raise RuntimeError('Observer manifest does not match the prepared task')
        self.gateway = await self.container('gateway')
        self.app = await self.container('app')
        if not self.gateway['State']['Running'] or not self.app['State']['Running']:
            raise RuntimeError('Trial containers are not running')

    async def freeze(self, environment, reason):
        await environment.stop_service('gateway')
        gateway = await self.container('gateway')
        if gateway['State']['Running'] or gateway['Id'] != self.gateway['Id']:
            raise RuntimeError('Gateway did not stop')
        app = await self.container('app')
        unchanged = (
            app['Id'] == self.app['Id']
            and app['State']['Running']
            and app['State']['StartedAt'] == self.app['State']['StartedAt']
            and app['RestartCount'] == self.app['RestartCount'])
        closed = {
            'trial_id': self.trial_id, 'reason': reason,
            'gateway_stopped': True, 'app_unchanged': bool(unchanged),
            'closed_at': timestamp(),
            'app_image_id': self.app['Image'],
            'gateway_image_id': self.gateway['Image'],
            'harbor_version': '0.25.0',
        }
        await self.observer_json(environment, 'gate-closed.json', closed)
        write_json(self.control / 'closed.json', closed)
        if not unchanged:
            write_json(self.control / 'invalid.json', {
                'trial_id': self.trial_id, 'error': 'App stopped or restarted during trial'})
        return closed

    async def run(self, instruction, environment, context):
        reason = 'aborted'
        try:
            opened = await environment.service_exec(
                'cp /opt/gateway/open.conf /etc/nginx/conf.d/default.conf && nginx -s reload',
                service='gateway', timeout_sec=15)
            if opened.return_code:
                raise RuntimeError(f'Gateway could not open: {opened.stderr}')
            ports = (await self.docker('port', self.gateway['Id'], '3000/tcp')).splitlines()
            if len(ports) != 1 or not ports[0].startswith('127.0.0.1:'):
                raise RuntimeError('Gateway must expose exactly one loopback port')
            target_url = 'http://' + ports[0]
            deadline = time.time() + self.timeout_sec
            monotonic_deadline = time.monotonic() + self.timeout_sec
            for attempt in range(40):
                try:
                    def check():
                        with urllib.request.urlopen(target_url + '/api/Challenges', timeout=2) as response:
                            if response.status != 200:
                                raise RuntimeError('Gateway is not ready')
                    await asyncio.to_thread(check)
                    break
                except Exception:
                    if attempt == 39:
                        raise RuntimeError('Gateway readiness timed out')
                    await asyncio.sleep(0.1)
            networks = self.gateway['NetworkSettings']['Networks']
            attack = [name for name in networks if name.endswith('_attack')]
            if len(attack) != 1:
                raise RuntimeError('Expected exactly one trial attack network')
            ready = {
                'trial_id': self.trial_id, 'status': 'running', 'score': None,
                'target_url': target_url, 'docker_target_url': 'http://gateway:3000',
                'attack_network': attack[0], 'control_dir': str(self.control),
                'deadline': datetime.fromtimestamp(deadline, timezone.utc).isoformat(),
                'manifest_sha256': self.manifest_sha256,
                'external_agent_label': self.external_agent_label,
                'app_image_id': self.app['Image'],
                'gateway_image_id': self.gateway['Image'],
            }
            write_json(self.control / 'ready.json', ready)
            context.metadata = {'external_agent_label': self.external_agent_label,
                                'trial_id': self.trial_id, 'opened_at': timestamp()}
            while True:
                if time.monotonic() >= monotonic_deadline:
                    reason = 'timeout'
                    break
                signal = self.control / 'finish.json'
                if signal.exists():
                    finish = json.loads(signal.read_text())
                    if finish.get('trial_id') != self.trial_id:
                        raise RuntimeError('Finish signal belongs to a different trial')
                    reason = finish.get('reason')
                    if reason not in ('finished', 'aborted'):
                        raise RuntimeError('Unknown finish reason')
                    break
                await asyncio.sleep(0.2)
        except asyncio.CancelledError:
            reason = 'timeout'
            raise
        except Exception as error:
            write_json(self.control / 'invalid.json', {
                'trial_id': self.trial_id, 'error': str(error)})
            raise
        finally:
            try:
                await asyncio.wait_for(asyncio.shield(self.freeze(environment, reason)), timeout=45)
                if context.metadata is not None:
                    context.metadata['reason'] = reason
            except Exception as error:
                write_json(self.control / 'invalid.json', {
                    'trial_id': self.trial_id, 'error': f'Could not freeze ingress: {error}'})
                raise
