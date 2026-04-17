import semver
from datetime import datetime
from ipaddress import ip_address
from vpns.openvpn.data_collector import VPNDataCollector


# ---------------------------------------------------------------------------
# Test data: raw responses matching OpenVPN management protocol output
# ---------------------------------------------------------------------------

VERSION_23 = (
    "OpenVPN Version: OpenVPN 2.3.10 x86_64-pc-linux-gnu "
    "[SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [MH] [IPv6] built on Jan  4 2016\r\n"
    "Management Version: 1\r\n"
    "END\r\n"
)

VERSION_26 = (
    "OpenVPN Version: OpenVPN 2.6.14 x86_64-pc-linux-gnu "
    "[SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH] [AEAD] built on Feb 11 2026\r\n"
    "Management Version: 5\r\n"
    "END\r\n"
)

VERSION_27 = (
    "OpenVPN Version: OpenVPN 2.7.0 [git:makepkg/ee1577744fb09af7+] x86_64-pc-linux-gnu "
    "[SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] [DCO] built on Feb 11 2026\r\n"
    "Management Version: 5\r\n"
    "END\r\n"
)

STATE_SERVER = "1457583275,CONNECTED,SUCCESS,10.10.10.1,\r\nEND\r\n"
STATE_CLIENT = "1457583275,CONNECTED,SUCCESS,10.10.10.1,192.168.1.1\r\nEND\r\n"
STATE_SERVER_V27 = "1776395681,CONNECTED,SUCCESS,10.29.12.1,,,,,2a00:dcc0:dead:a05b:8000::2\r\nEND\r\n"

STATS = "SUCCESS: nclients=3,bytesin=556794,bytesout=1483013\r\n"

# OpenVPN 2.3 status output (no IPv6 virtual address, no client_id/peer_id)
STATUS_V23 = (
    "TITLE\tOpenVPN 2.3.10\r\n"
    "TIME\tWed Mar 23 21:42:22 2016\t1458729742\r\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\r\n"
    "CLIENT_LIST\thost1\t59.167.120.211:12345\t10.10.10.7\t"
    "369528\t1216150\tWed Mar 23 21:40:15 2016\t1458729615\tuser1\r\n"
    "CLIENT_LIST\tuser2\t2001:4860:4801:3::20\t10.10.10.8\t"
    "12345\t11615\tWed Mar 23 21:43:25 2016\t1458729815\tuser2\r\n"
    "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\r\n"
    "ROUTING_TABLE\t10.10.10.7\thost1\t59.167.120.211:12345\t"
    "Wed Mar 23 21:42:22 2016\t1458729742\r\n"
    "ROUTING_TABLE\t10.10.10.8\tuser2\t2001:4860:4801:3::20\t"
    "Wed Mar 23 21:42:22 2016\t1458729742\r\n"
    "GLOBAL_STATS\tMax bcast/mcast queue length\t0\r\n"
    "END\r\n"
)

# OpenVPN 2.6 status output (has IPv6 virtual address, client_id, peer_id)
STATUS_V26 = (
    "TITLE\tOpenVPN 2.6.14\r\n"
    "TIME\t2026-02-22 02:36:42\t1771727802\r\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t"
    "Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\r\n"
    "CLIENT_LIST\tDesktopXYZ\t203.0.113.5:52137\t192.0.2.2\t\t"
    "8226\t9033\t2026-02-22 02:20:04\t1771726804\trichard\t0\t0\tAES-256-GCM\r\n"
    "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\r\n"
    "ROUTING_TABLE\t192.0.2.2\tDesktopXYZ\t203.0.113.5:52137\t"
    "2026-02-22 02:20:04\t1771726804\r\n"
    "GLOBAL_STATS\tMax bcast/mcast queue length\t0\r\n"
    "END\r\n"
)

# OpenVPN 2.7 status output (protocol prefix on addresses)
STATUS_V27 = (
    "TITLE\tOpenVPN 2.7.0\r\n"
    "TIME\t2026-02-22 02:36:42\t1771727802\r\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t"
    "Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\r\n"
    "CLIENT_LIST\tLaptopABC\tudp4:203.0.113.5:52137\t192.0.2.2\t\t"
    "8226\t9033\t2026-02-22 02:20:04\t1771726804\trichard\t0\t0\tAES-256-GCM\r\n"
    "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)\r\n"
    "ROUTING_TABLE\t192.0.2.2\tLaptopABC\tudp4:203.0.113.5:52137\t"
    "2026-02-22 02:20:04\t1771726804\r\n"
    "GLOBAL_STATS\tMax bcast/mcast queue length\t0\r\n"
    "GLOBAL_STATS\tdco_enabled\t1\r\n"
    "END\r\n"
)

# OpenVPN 2.7 status with dual-stack client (both IPv4 and IPv6 virtual addresses)
STATUS_V27_DUALSTACK = (
    "TITLE\tOpenVPN 2.7.1\r\n"
    "TIME\t2026-04-16 23:16:38\t1776395798\r\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
    "Virtual IPv6 Address\tBytes Received\tBytes Sent\tConnected Since\t"
    "Connected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\r\n"
    "CLIENT_LIST\tfurlongm\tudp4:72.89.79.107:34908\t10.29.12.2\t"
    "2a00:dcc0:dead:a05b:8000::1001\t435895\t365168\t2026-04-16 23:14:52\t"
    "1776395692\tfurlongm\t0\t0\tAES-256-GCM\r\n"
    "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\t"
    "Last Ref\tLast Ref (time_t)\r\n"
    "ROUTING_TABLE\t2a00:dcc0:dead:a05b:8000::1001\tfurlongm\t"
    "udp4:72.89.79.107:34908\t2026-04-16 23:16:30\t1776395790\r\n"
    "ROUTING_TABLE\t10.29.12.2\tfurlongm\tudp4:72.89.79.107:34908\t"
    "2026-04-16 23:16:38\t1776395798\r\n"
    "GLOBAL_STATS\tMax bcast/mcast queue length\t1\r\n"
    "GLOBAL_STATS\tdco_enabled\t0\r\n"
    "END\r\n"
)


# ---------------------------------------------------------------------------
# parse_remote_address
# ---------------------------------------------------------------------------

class TestParseRemoteAddress:

    def test_ipv4_with_port(self):
        assert VPNDataCollector.parse_remote_address('203.0.113.5:52137') == \
            ('203.0.113.5', '52137', None)

    def test_ipv4_with_port_parens(self):
        assert VPNDataCollector.parse_remote_address('203.0.113.5(52137)') == \
            ('203.0.113.5', '52137', None)

    def test_ipv6_no_port(self):
        assert VPNDataCollector.parse_remote_address('2001:4860:4801:3::20') == \
            ('2001:4860:4801:3::20', None, None)

    def test_ipv6_mapped_ipv4(self):
        assert VPNDataCollector.parse_remote_address('::ffff:59.167.120.210') == \
            ('::ffff:59.167.120.210', None, None)

    def test_udp4_prefix(self):
        assert VPNDataCollector.parse_remote_address('udp4:203.0.113.5:52137') == \
            ('203.0.113.5', '52137', 'udp4')

    def test_tcp4_prefix(self):
        assert VPNDataCollector.parse_remote_address('tcp4:10.0.0.1:443') == \
            ('10.0.0.1', '443', 'tcp4')

    def test_udp6_prefix_with_ipv6(self):
        assert VPNDataCollector.parse_remote_address('udp6:::ffff:59.167.120.210') == \
            ('::ffff:59.167.120.210', None, 'udp6')

    def test_tcp6_prefix(self):
        assert VPNDataCollector.parse_remote_address('tcp6:2001:db8::1') == \
            ('2001:db8::1', None, 'tcp6')


# ---------------------------------------------------------------------------
# parse_version
# ---------------------------------------------------------------------------

class TestParseVersion:

    def test_version_23(self):
        result = VPNDataCollector.parse_version(VERSION_23)
        assert result is not None
        assert '2.3.10' in result

    def test_version_26(self):
        result = VPNDataCollector.parse_version(VERSION_26)
        assert result is not None
        assert '2.6.14' in result

    def test_version_27(self):
        result = VPNDataCollector.parse_version(VERSION_27)
        assert result is not None
        assert '2.7.0' in result

    def test_no_version_returns_none(self):
        assert VPNDataCollector.parse_version("no version here\n") is None

    def test_empty_string_returns_none(self):
        assert VPNDataCollector.parse_version("") is None

    def test_semver_parseable(self):
        """Extracted version string can be parsed by semver."""
        for data in [VERSION_23, VERSION_26, VERSION_27]:
            release = VPNDataCollector.parse_version(data)
            version_str = release.split(' ')[1]
            v = semver.Version.parse(version_str)
            assert v.major >= 2


# ---------------------------------------------------------------------------
# parse_state
# ---------------------------------------------------------------------------

class TestParseState:

    def test_server_mode(self):
        state = VPNDataCollector.parse_state(STATE_SERVER)
        assert state['connected'] == 'CONNECTED'
        assert state['success'] == 'SUCCESS'
        assert state['local_ip'] == ip_address('10.10.10.1')
        assert state['remote_ip'] == ''
        assert state['mode'] == 'Server'
        assert isinstance(state['up_since'], datetime)

    def test_client_mode(self):
        state = VPNDataCollector.parse_state(STATE_CLIENT)
        assert state['mode'] == 'Client'
        assert state['remote_ip'] == ip_address('192.168.1.1')

    def test_skips_info_lines(self):
        data = ">INFO:some info\r\n1457583275,CONNECTED,SUCCESS,10.10.10.1,\r\nEND\r\n"
        state = VPNDataCollector.parse_state(data)
        assert state['connected'] == 'CONNECTED'

    def test_server_v27_with_ipv6(self):
        state = VPNDataCollector.parse_state(STATE_SERVER_V27)
        assert state['connected'] == 'CONNECTED'
        assert state['local_ip'] == ip_address('10.29.12.1')
        assert state['local_ipv6'] == ip_address('2a00:dcc0:dead:a05b:8000::2')
        assert state['mode'] == 'Server'

    def test_no_ipv6_in_state(self):
        state = VPNDataCollector.parse_state(STATE_SERVER)
        assert 'local_ipv6' not in state


# ---------------------------------------------------------------------------
# parse_stats
# ---------------------------------------------------------------------------

class TestParseStats:

    def test_basic_stats(self):
        stats = VPNDataCollector.parse_stats(STATS)
        assert stats['nclients'] == 3
        assert stats['bytesin'] == 556794
        assert stats['bytesout'] == 1483013

    def test_zero_stats(self):
        data = "SUCCESS: nclients=0,bytesin=0,bytesout=0\r\n"
        stats = VPNDataCollector.parse_stats(data)
        assert stats['nclients'] == 0
        assert stats['bytesin'] == 0
        assert stats['bytesout'] == 0


# ---------------------------------------------------------------------------
# parse_status — full session parsing
# ---------------------------------------------------------------------------

class TestParseStatus:

    def _make_collector(self):
        """Create a VPNDataCollector without triggering __init__ connections."""
        collector = object.__new__(VPNDataCollector)
        return collector

    def test_v23_sessions(self):
        collector = self._make_collector()
        version = semver.Version.parse('2.3.10')
        sessions = collector.parse_status(STATUS_V23, version, gi=None)

        assert '10.10.10.7' in sessions
        assert '10.10.10.8' in sessions

        s1 = sessions['10.10.10.7']
        assert s1['remote_ip'] == ip_address('59.167.120.211')
        assert s1['port'] == 12345
        assert s1['username'] == 'user1'
        assert s1['hostname'] == 'host1'
        assert s1['bytes_recv'] == 369528
        assert s1['bytes_sent'] == 1216150
        assert isinstance(s1['connected_since'], datetime)
        assert 'last_seen' in s1
        # No client_id for v2.3
        assert 'client_id' not in s1

    def test_v23_username_fallback_to_common_name(self):
        collector = self._make_collector()
        version = semver.Version.parse('2.3.10')
        sessions = collector.parse_status(STATUS_V23, version, gi=None)

        s2 = sessions['10.10.10.8']
        # common_name == username == 'user2', so no hostname set
        assert s2['username'] == 'user2'
        assert 'hostname' not in s2

    def test_v26_sessions(self):
        collector = self._make_collector()
        version = semver.Version.parse('2.6.14')
        sessions = collector.parse_status(STATUS_V26, version, gi=None)

        assert '192.0.2.2' in sessions
        s = sessions['192.0.2.2']
        assert s['remote_ip'] == ip_address('203.0.113.5')
        assert s['port'] == 52137
        assert s['username'] == 'richard'
        assert s['hostname'] == 'DesktopXYZ'
        assert s['client_id'] == '0'
        assert s['peer_id'] == '0'
        assert 'protocol' not in s

    def test_v27_protocol_prefix(self):
        collector = self._make_collector()
        version = semver.Version.parse('2.7.0')
        sessions = collector.parse_status(STATUS_V27, version, gi=None)

        assert '192.0.2.2' in sessions
        s = sessions['192.0.2.2']
        assert s['remote_ip'] == ip_address('203.0.113.5')
        assert s['port'] == 52137
        assert s['protocol'] == 'udp4'
        assert s['username'] == 'richard'
        assert s['hostname'] == 'LaptopABC'
        assert s['client_id'] == '0'

    def test_v27_routing_table_matching(self):
        collector = self._make_collector()
        version = semver.Version.parse('2.7.0')
        sessions = collector.parse_status(STATUS_V27, version, gi=None)

        s = sessions['192.0.2.2']
        assert 'last_seen' in s

    def test_empty_status(self):
        collector = self._make_collector()
        version = semver.Version.parse('2.6.14')
        data = "TITLE\tOpenVPN 2.6.14\r\nEND\r\n"
        sessions = collector.parse_status(data, version, gi=None)
        assert sessions == {}

    def test_v27_dualstack_keyed_by_ipv4(self):
        """Dual-stack client should be keyed by IPv4 with IPv6 stored separately."""
        collector = self._make_collector()
        version = semver.Version.parse('2.7.1')
        sessions = collector.parse_status(STATUS_V27_DUALSTACK, version, gi=None)

        assert '10.29.12.2' in sessions
        assert '2a00:dcc0:dead:a05b:8000::1001' not in sessions

        s = sessions['10.29.12.2']
        assert s['local_ip'] == ip_address('10.29.12.2')
        assert s['local_ipv6'] == ip_address('2a00:dcc0:dead:a05b:8000::1001')
        assert s['username'] == 'furlongm'
        assert s['protocol'] == 'udp4'

    def test_v27_dualstack_ipv6_route_matches(self):
        """IPv6 routing table entry should match the session via local_ipv6."""
        collector = self._make_collector()
        version = semver.Version.parse('2.7.1')
        sessions = collector.parse_status(STATUS_V27_DUALSTACK, version, gi=None)

        s = sessions['10.29.12.2']
        assert 'last_seen' in s
        # last_seen should be the latest of the two route entries (IPv4 = 1776395798)
        assert s['last_seen'].timestamp() == 1776395798


# ---------------------------------------------------------------------------
# is_mac_address
# ---------------------------------------------------------------------------

class TestIsMacAddress:

    def test_valid_mac(self):
        assert VPNDataCollector.is_mac_address('aa:bb:cc:dd:ee:ff') is True

    def test_valid_mac_uppercase(self):
        assert VPNDataCollector.is_mac_address('AA:BB:CC:DD:EE:FF') is True

    def test_invalid_too_short(self):
        assert VPNDataCollector.is_mac_address('aa:bb:cc') is False

    def test_invalid_ip(self):
        assert VPNDataCollector.is_mac_address('10.10.10.6') is False

    def test_invalid_chars(self):
        assert VPNDataCollector.is_mac_address('gg:hh:ii:jj:kk:ll') is False


# ---------------------------------------------------------------------------
# get_remote_address
# ---------------------------------------------------------------------------

class TestGetRemoteAddress:

    def test_with_port(self):
        assert VPNDataCollector.get_remote_address(ip_address('1.2.3.4'), 5678) == '1.2.3.4:5678'

    def test_without_port(self):
        assert VPNDataCollector.get_remote_address(ip_address('1.2.3.4'), '') == '1.2.3.4'

    def test_without_port_none(self):
        assert VPNDataCollector.get_remote_address(ip_address('1.2.3.4'), None) == '1.2.3.4'

    def test_ipv6(self):
        result = VPNDataCollector.get_remote_address(ip_address('::ffff:59.167.120.210'), None)
        assert result == '::ffff:59.167.120.210'
