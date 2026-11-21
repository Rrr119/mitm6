"""
Simulation tests for mitm6's controlled-takeover features.

Simulates 100 virtual hosts sending DHCPv6 and DNS traffic through the
packet parsing logic (with packet sending mocked out) and verifies:
- OU and hostname based filtering
- Configurable DHCPv6 lease times
- Restoration of the original DNS state within 30 seconds of interruption
"""
import argparse
import time

import pytest
from scapy.all import Ether, IPv6, UDP, DNS, DNSQR, DNSRR
from scapy.layers.dhcp6 import (
    DHCP6_Solicit,
    DHCP6_Request,
    DHCP6_Advertise,
    DHCP6_Reply,
    DHCP6OptClientId,
    DHCP6OptClientFQDN,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptServerId,
    DUID_LL,
)

import mitm6.mitm6 as mitm6

HOST_COUNT = 100
ATTACKER_MAC = '02:00:00:00:00:01'

OU_MAP = {
    'SALES': ['.sales.'],
    'IT': ['.it.'],
}


def make_args(**overrides):
    defaults = dict(
        interface='eth0',
        ipv4='192.168.56.10',
        ipv6='fe80::1',
        mac=ATTACKER_MAC,
        relay=None,
        domain=[],
        blocklist=[],
        host_allowlist=[],
        host_blocklist=[],
        ignore_nofqdn=False,
        localdomain=None,
        debug=False,
        verbose=False,
        ou=[],
        ou_blocklist=[],
        ou_file=None,
        lease_time=300,
        dns_server=None,
        restore_timeout=30,
        no_restore=False,
        no_ra=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def make_host(index):
    mac = '02:00:00:00:%02x:%02x' % (index // 256, index % 256)
    ou = 'sales' if index % 2 == 0 else 'it'
    fqdn = 'host%d.%s.corp.local' % (index, ou)
    v6addr = 'fe80::%x' % (index + 1)
    return {'mac': mac, 'fqdn': fqdn, 'v6': v6addr, 'ou': ou.upper()}


HOSTS = [make_host(i) for i in range(HOST_COUNT)]


class Env(object):
    def __init__(self, config, sent):
        self.config = config
        self.sent = sent

    def of_type(self, pkt_type):
        return [p for p in self.sent if pkt_type in p]


@pytest.fixture
def env_factory(monkeypatch):
    def factory(**arg_overrides):
        sent = []
        monkeypatch.setattr(mitm6, 'sendp', lambda p, **kwargs: sent.append(p))
        mitm6.pcdict.clear()
        mitm6.journal = mitm6.SpoofJournal()
        config = mitm6.Config(make_args(**arg_overrides))
        config.ou_map = dict(OU_MAP)
        mitm6.config = config
        return Env(config, sent)
    return factory


def simulate_solicit(host, trid=0x1000):
    return (Ether(src=host['mac'], dst='33:33:00:01:00:02')
            / IPv6(src=host['v6'], dst='ff02::1:2')
            / UDP(sport=546, dport=547)
            / DHCP6_Solicit(trid=trid)
            / DHCP6OptClientId(duid=DUID_LL(lladdr=host['mac']))
            / DHCP6OptClientFQDN(fqdn=host['fqdn'])
            / DHCP6OptIA_NA(iaid=0xabcd))


def simulate_request(host, config, addr, trid=0x2000):
    opt = DHCP6OptIAAddress(preflft=config.lease_time, validlft=config.lease_time, addr=addr)
    return (Ether(src=host['mac'], dst='33:33:00:01:00:02')
            / IPv6(src=host['v6'], dst='ff02::1:2')
            / UDP(sport=546, dport=547)
            / DHCP6_Request(trid=trid)
            / DHCP6OptClientId(duid=DUID_LL(lladdr=host['mac']))
            / DHCP6OptServerId(duid=config.selfduid)
            / DHCP6OptClientFQDN(fqdn=host['fqdn'])
            / DHCP6OptIA_NA(ianaopts=[opt], iaid=0xabcd))


def simulate_dns_query(host, qname, qtype=1, sport=53000):
    return (Ether(src=host['mac'], dst=ATTACKER_MAC)
            / IPv6(src=host['v6'], dst='fe80::1')
            / UDP(sport=sport, dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype, qclass=1)))


def run_takeover(env, hosts):
    """Run the full solicit -> request -> DNS query flow for the given hosts."""
    for host in hosts:
        mitm6.parsepacket(simulate_solicit(host))
    # Extract the leased address per host from the advertise messages
    leased = {}
    for adv in env.of_type(DHCP6_Advertise):
        leased[adv[Ether].dst] = adv[DHCP6OptIAAddress].addr
    for host in hosts:
        if host['mac'] in leased:
            mitm6.parsepacket(simulate_request(host, env.config, leased[host['mac']]))
    for host in hosts:
        if host['mac'] in leased:
            mitm6.parsepacket(simulate_dns_query(host, host['fqdn']))
    return leased


def test_ou_allowlist_filters_100_hosts(env_factory):
    env = env_factory(ou=['SALES'], domain=['corp.local'])
    for host in HOSTS:
        mitm6.parsepacket(simulate_solicit(host))
    advertises = env.of_type(DHCP6_Advertise)
    # Only the 50 SALES hosts should receive an advertise
    assert len(advertises) == HOST_COUNT // 2
    answered_macs = set(p[Ether].dst for p in advertises)
    expected = set(h['mac'] for h in HOSTS if h['ou'] == 'SALES')
    assert answered_macs == expected


def test_ou_blocklist_and_hostname_filter(env_factory):
    env = env_factory(ou_blocklist=['IT'], host_blocklist=['host2.', 'host4.'],
                      domain=['corp.local'])
    for host in HOSTS:
        mitm6.parsepacket(simulate_solicit(host))
    advertises = env.of_type(DHCP6_Advertise)
    answered_macs = set(p[Ether].dst for p in advertises)
    expected = set(h['mac'] for h in HOSTS
                   if h['ou'] != 'IT' and not h['fqdn'].startswith(('host2.', 'host4.')))
    assert answered_macs == expected
    assert len(advertises) == HOST_COUNT // 2 - 2


def test_configurable_lease_time(env_factory):
    env = env_factory(lease_time=120, domain=['corp.local'])
    host = HOSTS[0]
    mitm6.parsepacket(simulate_solicit(host))
    adv = env.of_type(DHCP6_Advertise)[0]
    assert adv[DHCP6OptIAAddress].validlft == 120
    assert adv[DHCP6OptIAAddress].preflft == 120
    assert adv[DHCP6OptIA_NA].T1 == 60
    assert adv[DHCP6OptIA_NA].T2 == 96
    # The reply to the request should carry the same lease time
    addr = adv[DHCP6OptIAAddress].addr
    mitm6.parsepacket(simulate_request(host, env.config, addr))
    reply = env.of_type(DHCP6_Reply)[0]
    assert reply[DHCP6OptIAAddress].validlft == 120
    assert reply[DHCP6OptIAAddress].preflft == 120


def test_restore_within_30_seconds_100_hosts(env_factory):
    env = env_factory(domain=['corp.local'], restore_timeout=30)
    env.config.resolver = lambda qname, qtype: '10.0.0.5'
    leased = run_takeover(env, HOSTS)
    assert len(leased) == HOST_COUNT
    assert len(mitm6.journal.leases) == HOST_COUNT
    assert len(mitm6.journal.dns_records) == HOST_COUNT

    env.sent[:] = []
    start = time.monotonic()
    deprecated, restored, failed = mitm6.restore_network()
    elapsed = time.monotonic() - start

    # Restoration must complete within 30 seconds of the interruption
    assert elapsed < 30
    assert deprecated == HOST_COUNT
    assert restored == HOST_COUNT
    assert failed == 0

    # Every lease must be deprecated with lifetime 0
    replies = env.of_type(DHCP6_Reply)
    assert len(replies) == HOST_COUNT
    for reply in replies:
        assert reply[DHCP6OptIAAddress].validlft == 0
        assert reply[DHCP6OptIAAddress].preflft == 0

    # Every spoofed DNS record must be corrected with the real record
    dns_answers = [p for p in env.sent if DNS in p and p[DNS].qr == 1]
    assert len(dns_answers) == HOST_COUNT
    restored_names = set(p[DNS].an.rrname.decode().rstrip('.') for p in dns_answers)
    expected_names = set(h['fqdn'] for h in HOSTS)
    assert restored_names == expected_names
    for p in dns_answers:
        assert p[DNS].an.rdata == '10.0.0.5'


def test_restore_respects_timeout_budget(env_factory):
    env = env_factory(domain=['corp.local'], restore_timeout=1)

    def slow_resolver(qname, qtype):
        time.sleep(0.05)
        return '10.0.0.5'

    env.config.resolver = slow_resolver
    run_takeover(env, HOSTS)

    start = time.monotonic()
    mitm6.restore_network()
    elapsed = time.monotonic() - start
    # Even with a slow upstream resolver, restoration must stop at the deadline
    assert elapsed < 2


def test_no_restore_flag_skips_restoration(env_factory, capsys):
    env = env_factory(domain=['corp.local'], no_restore=True)
    run_takeover(env, HOSTS[:5])
    env.sent[:] = []
    mitm6.shutdownnotice()
    assert env.sent == []
