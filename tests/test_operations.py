# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
import uuid

from juice_harbor_probe import cli


class OperationsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.trial_id = str(uuid.uuid4())

    def test_start_interruption_closes_owned_environment(self):
        args = argparse.Namespace(state_dir=self.root, profile='smoke', timeout=10,
                                  port=0, label='test', startup_timeout=10)
        with patch.object(cli.shutil, 'which', return_value='/usr/bin/harbor'), \
                patch.object(cli, 'checked', side_effect=['0.25.0', '29.7.2', '5.4.0']), \
                patch.object(cli, 'materialize', return_value=(self.root, 'a' * 64)), \
                patch.object(cli.subprocess, 'Popen', return_value=Mock(pid=123)), \
                patch.object(cli, 'process_identity', return_value='test-process'), \
                patch.object(cli, 'result_report', side_effect=KeyboardInterrupt), \
                patch.object(cli, 'cleanup') as cleanup:
            with self.assertRaises(KeyboardInterrupt):
                cli.start(args)
        directory = next((self.root / 'trials').iterdir())
        cleanup.assert_called_once_with(directory, stop_runner=True)
        self.assertEqual(cli.read_json(directory / 'control/invalid.json')['error'], 'KeyboardInterrupt')

    def test_cleanup_detaches_worker_only_from_owned_trial_network(self):
        directory = self.root / 'trials' / self.trial_id
        cli.write_json(directory / 'state.json', {'trial_id': self.trial_id})
        info = {'Labels': {'org.owasp.juice.harbor.trial': self.trial_id},
                'Containers': {'external-worker-id': {'Name': 'external-worker'}}}
        empty = {**info, 'Containers': {}}
        with patch.object(cli, 'checked', side_effect=[
                '', 'owned-network', json.dumps([info]), '', json.dumps([empty]), '']) as checked:
            cli.cleanup(directory)
        commands = [call.args[0] for call in checked.call_args_list]
        self.assertIn(['docker', 'network', 'disconnect', '--force', 'owned-network', 'external-worker-id'], commands)
        self.assertIn(['docker', 'network', 'rm', 'owned-network'], commands)
        self.assertFalse(any('prune' in command for command in commands))

    def test_cleanup_deduplicates_network_id_and_name(self):
        directory = self.root / 'trials' / self.trial_id
        cli.write_json(directory / 'state.json', {'trial_id': self.trial_id})
        container = {'Config': {'Labels': {'com.docker.compose.project': 'our-project'}},
                     'NetworkSettings': {'Networks': {'our-network': {}}}}
        info = {'Id': 'network-id', 'Labels': {'org.owasp.juice.harbor.trial': self.trial_id},
                'Containers': {}}
        responses = ['container-id', json.dumps([container]), '', 'network-id',
                     json.dumps([info]), json.dumps([info]), json.dumps([info]), '']
        with patch.object(cli, 'checked', side_effect=responses) as checked:
            cli.cleanup(directory)
        removals = [call.args[0] for call in checked.call_args_list
                    if call.args[0][:3] == ['docker', 'network', 'rm']]
        self.assertEqual(removals, [['docker', 'network', 'rm', 'network-id']])

    def test_regrade_uses_archived_manifest_and_network_free_container(self):
        directory = self.root / 'trials' / self.trial_id
        evidence = directory / 'evidence'
        evidence.mkdir(parents=True)
        cli.write_json(directory / 'state.json', {'trial_id': self.trial_id})
        cli.write_json(directory / 'scoring-manifest.json', {'original': True})
        report = {'trial_id': self.trial_id, 'status': 'completed', 'evidence_dir': str(evidence)}

        def docker(command, **kwargs):
            mount = next(value for value in command if value.endswith('dst=/logs/verifier'))
            output = Path(mount.split('src=', 1)[1].split(',dst=', 1)[0])
            cli.write_json(output / 'reward.json', {'score': 0.5})
            return subprocess.CompletedProcess(command, 0, '', '')

        args = argparse.Namespace(state_dir=self.root, trial_id=self.trial_id)
        with patch.object(cli, 'result_report', return_value=report), \
                patch.object(cli.subprocess, 'run', side_effect=docker) as run:
            result = cli.regrade(args)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('--read-only', command)
        self.assertIn(f'type=bind,src={directory / "scoring-manifest.json"},dst=/opt/benchmark/scoring-manifest.json,readonly', command)
        self.assertEqual(result['score'], 0.5)
        self.assertTrue((directory / 'regrades').is_dir())

    def test_malformed_ready_file_is_invalid_and_recoverable(self):
        directory = self.root / 'trials' / self.trial_id
        cli.write_json(directory / 'state.json', {'trial_id': self.trial_id})
        control = directory / 'control'
        control.mkdir()
        (control / 'ready.json').write_text('{unfinished')
        report = cli.result_report(directory)
        self.assertEqual(report['status'], 'invalid')
        self.assertEqual(report['error'], 'Ready file is malformed')

    def test_regrade_refuses_live_trial(self):
        directory = self.root / 'trials' / self.trial_id
        cli.write_json(directory / 'state.json', {'trial_id': self.trial_id})
        args = argparse.Namespace(state_dir=self.root, trial_id=self.trial_id)
        with patch.object(cli, 'result_report', return_value={'status': 'running'}), \
                self.assertRaisesRegex(ValueError, 'Finish the trial'):
            cli.regrade(args)


if __name__ == '__main__':
    unittest.main()
