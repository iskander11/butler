import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from flask import Flask
from app import firewall as fw


class ApplyRegressionTests(unittest.TestCase):
    def test_multiport_limit_and_deduplication(self):
        commands = [fw._ufw_cmd('allow', f'{p}/tcp', 'comment', 'butler')
                    for p in list(range(8000, 8031)) + [8000]]
        result = fw._compact_rules(commands)
        self.assertEqual(len(result), 3)
        actual = set()
        for command in result:
            ports = command[4].split('/')[0].split(',')
            self.assertLessEqual(len(ports), 15)
            actual.update(map(int, ports))
        self.assertEqual(actual, set(range(8000, 8031)))

    def test_source_allows_precede_denies(self):
        commands = []
        for p in [8020, 8888]:
            commands.extend([
                fw._ufw_cmd('allow', 'from', '192.0.2.1', 'to', 'any',
                            'port', str(p), 'proto', 'tcp', 'comment', 'butler'),
                fw._ufw_cmd('deny', f'{p}/tcp', 'comment', 'butler')])
        result = fw._compact_rules(commands)
        self.assertEqual([r[3] for r in result], ['allow', 'deny'])
        self.assertIn('192.0.2.1', result[0])
        self.assertIn('8020,8888', result[0])

    def test_deletion_uses_exact_tag_and_saved_rules(self):
        output = "ufw allow 22/tcp\nufw allow 8888/tcp comment 'butler'\nufw route allow to 172.18.0.5 port 80 comment 'butler-docker'\n"
        with patch.object(fw, 'run_command', return_value=SimpleNamespace(stdout=output)) as run:
            self.assertEqual(fw._delete_tagged_rules('butler'), 1)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0][3:6], ['--force', 'delete', 'allow'])

    def test_concurrent_apply_rejected_and_lock_released(self):
        import fcntl
        app = Flask(__name__)
        with tempfile.TemporaryDirectory() as directory, app.app_context():
            app.config['DATABASE'] = str(Path(directory) / 'test.sqlite3')
            function = fw._exclusive_apply(lambda: 'done')
            with (Path(directory) / 'test.apply.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                with self.assertRaisesRegex(RuntimeError, 'уже применяются'):
                    function()
            self.assertEqual(function(), 'done')
