"""Policy regression tests; no subprocess may reach the host firewall."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class AccessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        env = root / 'test.env'
        env.write_text('')
        self.env = patch.dict(os.environ, {
            'BUTLER_ENV_FILE': str(env), 'BUTLER_DATABASE': str(root / 'db.sqlite3'),
            'BUTLER_SECRET_KEY': 'test', 'BUTLER_ADMIN_USER': 'admin',
            'BUTLER_ADMIN_PASS': 'test-password', 'BUTLER_PORT': '5050',
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        # Any unexpected system command is a test failure.
        guard = patch('subprocess.run', side_effect=AssertionError('Unexpected system command'))
        guard.start()
        self.addCleanup(guard.stop)
        from app import create_app
        from app import firewall, ufw_docker
        from app.db import get_db
        self.fw, self.docker = firewall, ufw_docker
        self.app = create_app()
        self.app.config['TESTING'] = True
        ctx = self.app.app_context()
        ctx.push()
        self.addCleanup(ctx.pop)
        self.db = get_db()
        self.published = patch.object(firewall, '_docker_published_host_ports', return_value={8020, 8090})
        self.published.start()
        self.addCleanup(self.published.stop)

    def service(self):
        self.db.execute("INSERT INTO services(name,port,ports_raw,protocol) VALUES ('web',8020,'8020','tcp')")
        self.db.commit()

    def ip(self, enabled=1):
        self.db.execute('INSERT INTO whitelist_entries(ip_address,enabled) VALUES (?,?)', ('192.0.2.5', enabled))
        self.db.commit()

    def rules(self):
        return [c[3:] for c in self.fw._rule_commands()[0]]

    def routes(self):
        d = self.docker
        publications = [d.DockerPublish(8020,80,'tcp','172.18.0.5','web'),
                        d.DockerPublish(8090,8080,'tcp','172.18.0.6','other'),
                        d.DockerPublish(8020,80,'udp','172.18.0.5','udp')]
        with patch.object(d, '_ensure_ufw_docker_installed'), patch.object(d, 'delete_butler_docker_routes'), \
                patch.object(d, '_ufw_docker_block_present', return_value=True), \
                patch.object(d, 'iter_docker_publishes', return_value=publications), \
                patch.object(d, 'run_command') as run:
            d.sync_docker_whitelist_from_db()
        return [call.args[0][3:] for call in run.call_args_list]

    def test_unlisted_closed_even_with_whitelist(self):
        self.ip()
        self.assertFalse(any(c[0] == 'allow' for c in self.rules()))
        self.assertEqual(self.routes(), [])

    def test_empty_whitelist_opens_only_listed_service(self):
        self.service()
        self.assertIn(['allow','8020/tcp','comment','butler'], self.rules())
        routes = self.routes()
        self.assertEqual(len(routes), 1)
        self.assertEqual(routes[0][4:8], ['from','any','to','172.18.0.5'])

    def test_whitelist_restricts_listed_service(self):
        self.service()
        self.ip()
        rules = self.rules()
        self.assertNotIn(['allow','8020/tcp','comment','butler'], rules)
        self.assertIn(['deny','8020/tcp','comment','butler'], rules)
        self.assertTrue(any('192.0.2.5' in c and c[0]=='allow' for c in rules))
        self.assertEqual(self.routes()[0][5], '192.0.2.5')

    def test_disabled_entries_do_not_restrict(self):
        self.service()
        self.ip(enabled=0)
        self.assertIn(['allow','8020/tcp','comment','butler'], self.rules())
        self.assertEqual(self.routes()[0][5], 'any')

    def test_deleting_last_ip_reopens_listed_service(self):
        self.service()
        self.ip()
        self.db.execute('DELETE FROM whitelist_entries')
        self.db.commit()
        self.assertEqual(self.routes()[0][5], 'any')
        self.db.execute('DELETE FROM services')
        self.db.commit()
        self.assertEqual(self.routes(), [])

    def test_ui_and_crud_wait_for_apply(self):
        client = self.app.test_client()
        client.post('/login', data={'username':'admin','password':'test-password'})
        page = client.get('/firewall').get_data(as_text=True)
        self.assertNotIn('Диагностика порта', page)
        self.assertNotIn('под капотом', page)
        self.assertIn('Применить правила', page)
        with client.session_transaction() as session:
            token = session['csrf_token']
        with patch.object(self.fw, 'apply_firewall_rules', return_value=(None,None,None)) as apply:
            response = client.post('/services', data={'csrf_token':token, 'name':'web',
                'ports_raw':'8020','protocol':'tcp','description':''})
            self.assertEqual(response.status_code,302)
            response = client.post('/whitelist', data={'csrf_token':token,
                'ip_address':'192.0.2.5','owner_name':'test','comment':''})
            self.assertEqual(response.status_code,302)
            client.post('/whitelist/1/delete', data={'csrf_token':token})
            client.get('/firewall')
            apply.assert_not_called()
            response = client.post('/firewall/apply', data={'csrf_token':token,'confirm_apply':'yes'})
            self.assertEqual(response.status_code,302)
            apply.assert_called_once()


if __name__ == '__main__':
    unittest.main()
