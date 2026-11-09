# Copyright (c) 2026 OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

from juice_harbor_probe import cli


class ManualLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trial_id = str(uuid.uuid4())
        self.directory = cli.trial_path(self.root, self.trial_id)
        self.control = self.directory / 'control'
        self.control.mkdir(parents=True)
        cli.write_json(self.directory / 'state.json', {
            'trial_id': self.trial_id, 'pid': 123, 'pid_start': '1234'})
        cli.write_json(self.root / 'active.json', {'trial_id': self.trial_id})

    def completed(self, score=0.5, exception=None):
        job = self.directory / 'jobs' / self.trial_id
        cli.write_json(job / 'result.json', {'finished_at': '2026-11-09T00:00:00Z'})
        cli.write_json(job / 'one-trial' / 'result.json', {
            'verifier_result': {'rewards': {'score': score}}, 'exception_info': exception})

    def test_trial_id_rejects_path_traversal_and_noncanonical_values(self):
        for value in ('../../elsewhere', 'bad', self.trial_id.upper(), '{' + self.trial_id + '}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                cli.trial_path(self.root, value)

    def test_active_trial_resolution_does_not_accept_unknown_id(self):
        self.assertEqual(cli.resolve_trial(self.root), self.directory)
        with self.assertRaises(ValueError):
            cli.resolve_trial(self.root, str(uuid.uuid4()))

    def test_dead_runner_is_invalid_instead_of_running_forever(self):
        with patch.object(cli, 'process_alive', return_value=False):
            self.assertEqual(cli.result_report(self.directory)['status'], 'invalid')

    def test_stale_ready_identity_is_rejected(self):
        cli.write_json(self.control / 'ready.json', {'trial_id': str(uuid.uuid4())})
        self.assertEqual(cli.result_report(self.directory)['status'], 'invalid')

    def test_completed_reward_accepts_zero_and_timeout(self):
        self.completed(0.0, {'exception_type': 'AgentTimeoutError'})
        cli.write_json(self.control / 'closed.json', {'reason': 'timeout'})
        report = cli.result_report(self.directory)
        self.assertEqual(report['status'], 'completed')
        self.assertEqual(report['score'], 0.0)
        self.assertEqual(report['reason'], 'timeout')

    def test_missing_or_nonnumeric_reward_is_invalid(self):
        for score in (None, '1', True, -0.1, 1.1, float('nan')):
            with self.subTest(score=score):
                self.completed(score)
                self.assertEqual(cli.result_report(self.directory)['status'], 'invalid')

    def test_freeze_failure_rejects_even_a_reward(self):
        self.completed(1)
        cli.write_json(self.control / 'invalid.json', {'error': 'Gateway remained open'})
        report = cli.result_report(self.directory)
        self.assertEqual(report['status'], 'invalid')
        self.assertIsNone(report['score'])

    def test_abort_does_not_report_zero_as_valid(self):
        self.completed(None)
        cli.write_json(self.control / 'finish.json', {
            'trial_id': self.trial_id, 'reason': 'aborted'})
        self.assertEqual(cli.result_report(self.directory)['status'], 'aborted')

    def test_finish_is_idempotent_for_completed_trial(self):
        self.completed(1)
        args = argparse.Namespace(state_dir=self.root, trial_id=self.trial_id, wait_timeout=1)
        with patch.object(cli, 'cleanup'), patch.object(cli, 'process_alive', return_value=False):
            self.assertEqual(cli.finish(args)['score'], 1)
            self.assertEqual(cli.finish(args)['score'], 1)
        self.assertFalse((self.control / 'finish.json').exists())

    def test_finish_rejects_stale_signal(self):
        cli.write_json(self.control / 'finish.json', {
            'trial_id': str(uuid.uuid4()), 'reason': 'finished'})
        args = argparse.Namespace(state_dir=self.root, trial_id=self.trial_id, wait_timeout=1)
        with patch.object(cli, 'process_alive', return_value=True), self.assertRaises(ValueError):
            cli.finish(args)

    def test_timeout_edit_only_changes_agent_section(self):
        template = '[agent]\ntimeout_sec = 3600\n\n[verifier]\ntimeout_sec = 60\n'
        changed = cli.set_agent_timeout(template, 15)
        self.assertIn('[agent]\ntimeout_sec = 15', changed)
        self.assertIn('[verifier]\ntimeout_sec = 60', changed)

    def test_manifest_materialization_keeps_one_smoke_target(self):
        template = self.root / 'template'
        (template / 'task/environment').mkdir(parents=True)
        (template / 'task/tests').mkdir()
        (template / 'task/task.toml').write_text('[agent]\ntimeout_sec = 3600\n')
        cli.write_json(template / 'scoring-manifest.json', {'challenges': [
            {'key': 'directoryListingChallenge', 'eligible': True, 'exclusion_reason': None},
            {'key': 'otherChallenge', 'eligible': True, 'exclusion_reason': None}]})
        with patch.object(cli, 'HERE', template):
            task, digest = cli.materialize(self.directory, 'smoke', 10)
        a = (task / 'environment/scoring-manifest.json').read_bytes()
        b = (task / 'tests/scoring-manifest.json').read_bytes()
        self.assertEqual(a, b)
        self.assertEqual(len(digest), 64)
        manifest = cli.read_json(task / 'tests/scoring-manifest.json')
        self.assertEqual([c['key'] for c in manifest['challenges'] if c['eligible']],
                         ['directoryListingChallenge'])

    def test_write_json_permissions_are_private(self):
        path = self.control / 'signal.json'
        cli.write_json(path, {'trial_id': self.trial_id})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
