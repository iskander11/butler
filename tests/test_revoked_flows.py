import ipaddress
import unittest
from app.firewall import _revoked_flows


class RevocationTests(unittest.TestCase):
    def flows(self, rows, specs=(), whitelist=()):
        return list(_revoked_flows('\n'.join(rows), {'192.168.100.10', '2001:db8::10'},
            set(specs), [ipaddress.ip_network(x) for x in whitelist], {22,5050}))

    def flow(self, port, src='192.168.100.5', dst='192.168.100.10'):
        return f'ipv4 2 tcp 6 431000 ESTABLISHED src={src} dst={dst} sport=45000 dport={port} src={dst} dst={src} sport={port} dport=45000'

    def test_deleted_host_service_is_revoked(self):
        self.assertEqual(self.flows([self.flow(8888)])[0][-1], '8888')

    def test_management_and_outbound_are_preserved(self):
        self.assertEqual(self.flows([self.flow(22),self.flow(5050),
            self.flow(443,src='192.168.100.10',dst='1.1.1.1')]), [])

    def test_public_and_whitelisted_services_are_preserved(self):
        self.assertEqual(self.flows([self.flow(8888)],[(8888,'tcp')]), [])
        self.assertEqual(self.flows([self.flow(8888)],[(8888,'tcp')],['192.168.100.0/24']), [])
        self.assertEqual(len(self.flows([self.flow(8888)],[(8888,'tcp')],['192.0.2.1'])),1)

    def test_docker_uses_original_published_port(self):
        flow=self.flow(8020).replace('src=192.168.100.10 dst=192.168.100.5 sport=8020',
            'src=172.18.0.5 dst=192.168.100.5 sport=80')
        self.assertEqual(self.flows([flow])[0][-1],'8020')
        self.assertEqual(self.flows([flow],[(8020,'tcp')]),[])

    def test_ipv6_deleted_service(self):
        self.assertEqual(len(self.flows([self.flow(8888,'2001:db8::5','2001:db8::10')])),1)
