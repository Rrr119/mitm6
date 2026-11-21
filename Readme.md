# mitm6
![Python 2.7 and 3 compatible](https://img.shields.io/badge/python-2.7%2C%203.x-blue.svg)
![PyPI version](https://img.shields.io/pypi/v/mitm6.svg)
![License: GPLv2](https://img.shields.io/pypi/l/mitm6.svg)

mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. It does this by replying to DHCPv6 messages, providing victims with a link-local IPv6 address and setting the attackers host as default DNS server. As DNS server, mitm6 will selectively reply to DNS queries of the attackers choosing and redirect the victims traffic to the attacker machine instead of the legitimate server. For a full explanation of the attack, see our [blog about mitm6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/). Mitm6 is designed to work together with [ntlmrelayx from impacket](https://github.com/CoreSecurity/impacket) for WPAD spoofing and credential relaying.

## Dependencies and installation
mitm6 is compatible with both Python 2.7 and 3.x. You can install the requirements for your version with `pip install -r requirements.txt`. In both cases, mitm6 uses the following packages:
- Scapy
- Twisted
- netifaces

For python 2.7, it uses the `ipaddress` backport module.
You can install the latest release from PyPI with `pip install mitm6`, or the latest version from source with `python setup.py install` after cloning this git repository.

## Usage
After installation, mitm6 will be available as a command line program called `mitm6`. Since it uses raw packet capture with Scapy, it should be run as root. mitm6 should detect your network settings by default and use your primary interface for its spoofing. The only option you will probably need to specify is the AD `domain` that you are spoofing. For advanced tuning, the following options are available:

```
usage: mitm6 [-h] [-i INTERFACE] [-l LOCALDOMAIN] [-4 ADDRESS] [-6 ADDRESS] [-m ADDRESS] [-a] [-r TARGET] [-v] [--debug]
             [-d DOMAIN] [-b DOMAIN] [-hw DOMAIN] [-hb DOMAIN] [--ignore-nofqdn] [--ou OU] [--ou-blocklist OU] [--ou-file FILE]
             [--lease-time SECONDS] [--dns-server ADDRESS] [--restore-timeout SECONDS] [--no-restore]

mitm6 - pwning IPv4 via IPv6
For help or reporting issues, visit https://github.com/dirkjanm/mitm6

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Interface to use (default: autodetect)
  -l LOCALDOMAIN, --localdomain LOCALDOMAIN
                        Domain name to use as DNS search domain (default: use first DNS domain)
  -4 ADDRESS, --ipv4 ADDRESS
                        IPv4 address to send packets from (default: autodetect)
  -6 ADDRESS, --ipv6 ADDRESS
                        IPv6 link-local address to send packets from (default: autodetect)
  -m ADDRESS, --mac ADDRESS
                        Custom mac address - probably breaks stuff (default: mac of selected interface)
  -a, --no-ra           Do not advertise ourselves (useful for networks which detect rogue Router Advertisements)
  -r TARGET, --relay TARGET
                        Authentication relay target, will be used as fake DNS server hostname to trigger Kerberos auth
  -v, --verbose         Show verbose information
  --debug               Show debug information

Filtering options:
  -d DOMAIN, --domain DOMAIN
                        Domain name to filter DNS queries on (Allowlist principle, multiple can be specified.)
  -b DOMAIN, --blocklist DOMAIN, --blacklist DOMAIN
                        Domain name to filter DNS queries on (Blocklist principle, multiple can be specified.)
  -hw DOMAIN, -ha DOMAIN, --host-allowlist DOMAIN, --host-whitelist DOMAIN
                        Hostname (FQDN) to filter DHCPv6 queries on (Allowlist principle, multiple can be specified.)
  -hb DOMAIN, --host-blocklist DOMAIN, --host-blacklist DOMAIN
                        Hostname (FQDN) to filter DHCPv6 queries on (Blocklist principle, multiple can be specified.)
  --ignore-nofqdn       Ignore DHCPv6 queries that do not contain the Fully Qualified Domain Name (FQDN) option.
  --ou OU               Organizational Unit to filter DHCPv6 queries on (Allowlist principle, multiple can be specified. Requires an OU map file.)
  --ou-blocklist OU     Organizational Unit to filter DHCPv6 queries on (Blocklist principle, multiple can be specified.)
  --ou-file FILE        JSON file mapping OU names to hostname patterns (default: ou_map.json in current directory)

Takeover and restoration options:
  --lease-time SECONDS  DHCPv6 lease time in seconds (default: 300)
  --dns-server ADDRESS  Upstream DNS server used to resolve real records during restoration (default: system resolver)
  --restore-timeout SECONDS
                        Maximum time in seconds to restore the original DNS state after interruption (default: 30)
  --no-restore          Do not restore the original network state on shutdown
```

You can manually override most of the autodetect options (though overriding the MAC address will break things). If the network has some hardware which blocks or detects rogue Router Advertisement messages, you can add the `--no-ra` flag to not broadcast those. Router Advertisements are not needed for mitm6 to work since it relies mainly on DHCPv6 messages.

### Filtering options
Several filtering options are available to select which hosts you want to attack and spoof. First there are the `--host-allowlist` and `--host-blocklist` options (or `-hw` and `-hb` for short), which take a (partial) domain as argument. Incoming DHCPv6 requests will be filtered against this list. The property checked is the DHCPv6 FQND option, in which the client provides its hostname. 

#### OU filtering
Since DHCPv6 messages do not carry Organizational Unit information, OU membership is resolved through a hostname-pattern map. Create a JSON file (default `ou_map.json`, override with `--ou-file`) mapping OU names to (partial) hostname patterns, for example:

```json
{
  "SALES": [".sales.corp.local"],
  "IT": [".it.corp.local", "srv-"]
}
```

Then use `--ou SALES` to only target hosts in the SALES OU (allowlist principle), or `--ou-blocklist IT` to exclude the IT OU. OU filtering can be combined with the hostname allowlist/blocklist.

### Lease time and restoration
The DHCPv6 lease time handed out to targets can be controlled with `--lease-time` (default 300 seconds); renewal timers T1/T2 are derived from it (0.5x and 0.8x the lease time).

While running, mitm6 keeps a journal of every lease it handed out and every DNS record it spoofed. On shutdown (for example after Ctrl+C), it restores the original network state within `--restore-timeout` seconds (default 30):

1. Every leased IPv6 address is deprecated by sending the client a DHCPv6 reply with lifetime 0.
2. Every spoofed DNS record is re-resolved against the real DNS server (`--dns-server`, or the system resolver by default) and the correct record is pushed to the affected clients with a low TTL.

Restoration can be disabled with `--no-restore`. Note that the corrected DNS responses are a best-effort cache correction; clients will also recover on their own once the spoofed records' TTLs expire.

### Running the tests
A simulation test suite covering 100 virtual hosts (OU/hostname filtering, lease times, and restoration within the 30 second budget) is included:

```
pip install pytest
python -m pytest tests/
```
The same applies for DNS requests, for this the `--domain` option (or `-d`) is available, where you can supply which domain(s) you want to spoof. Blocking specific domains is also possible with `--blocklist`/`-b`. Both parameters can be specified multiple times to include/block multiple domains (for example `-d domain.local -d otherdomain.local -b somehost.domain.local -b somehost.otherdomain.local`).

For both the host and DNS filtering, simple string matching is performed. So if you choose to reply to `wpad`, it will also reply to queries for `wpad.corpdomain.com`. If you want more specific filtering, use both the allowlist and blocklist options, since the blocklist takes precedence over the allowlist.
By default the first domain specified will be used as the DNS search domain, if you explicitliy want to specify this domain yourself use the `--localdomain` option.

## About network impact and restoring the network
mitm6 is designed as a penetration testing tool and should thus impact the network as little as possible. This is the main reason mitm6 doesn't implement a full machine-in-the-middle attack currently, like we see in for example the SLAAC attack.
To further minimize the impact, the IP addresses assigned have low time-to-live (TTL) values. The lease will expire within 5 minutes when mitm6 is stopped, which will remove the DNS server from the victims configuration.
To prevent DNS replies getting cached, all replies are sent with a TTL of 100 seconds, which makes sure the cache is cleared within minutes after the tool exits.

## Usage with ntlmrelayx
mitm6 is designed to be used with ntlmrelayx. You should run the tools next to each other, in this scenario mitm6 will spoof the DNS, causing victims to connect to ntlmrelayx for HTTP and SMB connections. For this you have to make sure to run ntlmrelayx with the `-6` option, which will make it listen on both IPv4 and IPv6. To obtain credentials for WPAD, specify the WPAD hostname to spoof with `-wh HOSTNAME` (any non-existing hostname in the local domain will work since mitm6 is the DNS server). Optionally you can also use the `-wa N` parameter with a number of attempts to prompt for authentication for the WPAD file itself in case you suspect victims do not have the MS16-077 patch applied.

## Usage with krbrelayx
You can also use mitm6 to relay Kerberos authentication, especially via DNS. To do this, use the `--relay` parameter and specify a host that you want to relay to. This host will be impersonated, and mitm6 will try to convince your victims to send authenticated dynamic updates using Kerberos authentication to krbrelayx. More info about this attack is available on the following blog: <https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/>

## Detection
The Fox-IT Security Research Team team has released Snort and Suricata signatures to detect rogue DHCPv6 traffic and WPAD replies over IPv6. The signatures are available here: https://gist.github.com/fox-srt/98f29051fe56a1695de8e914c4a2373f
