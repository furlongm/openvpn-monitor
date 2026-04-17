import configparser
import os
import tempfile
from config.loader import ConfigLoader


def _write_config(content):
    """Write config content to a temp file and return the path."""
    f = tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False)
    f.write(content)
    f.close()
    return f.name


class TestConfigLoader:

    def test_loads_global_settings(self):
        path = _write_config(
            "[openvpn-monitor]\n"
            "site=Test Site\n"
            "enable_maps=True\n"
            "geoip_data=/usr/share/GeoIP/GeoLite2-City.mmdb\n"
            "datetime_format=%d/%m/%Y %H:%M:%S\n"
        )
        try:
            config = ConfigLoader(path)
            assert config.settings['site'] == 'Test Site'
            assert config.settings['enable_maps'] == 'True'
            assert config.settings['geoip_data'] == '/usr/share/GeoIP/GeoLite2-City.mmdb'
        finally:
            os.unlink(path)

    def test_loads_vpn_section(self):
        path = _write_config(
            "[openvpn-monitor]\n"
            "site=Test\n"
            "\n"
            "[MyVPN]\n"
            "host=10.0.0.1\n"
            "port=5555\n"
            "name=My VPN\n"
            "password=secret\n"
            "show_disconnect=True\n"
        )
        try:
            config = ConfigLoader(path)
            assert 'MyVPN' in config.vpns
            vpn = config.vpns['MyVPN']
            assert vpn['host'] == '10.0.0.1'
            assert vpn['port'] == '5555'
            assert vpn['name'] == 'My VPN'
            assert vpn['show_disconnect'] is True
        finally:
            os.unlink(path)

    def test_show_disconnect_defaults_false(self):
        path = _write_config(
            "[openvpn-monitor]\n"
            "site=Test\n"
            "\n"
            "[VPN1]\n"
            "host=localhost\n"
            "port=5555\n"
        )
        try:
            config = ConfigLoader(path)
            assert config.vpns['VPN1']['show_disconnect'] is False
        finally:
            os.unlink(path)

    def test_fallback_default_settings(self):
        path = '/nonexistent/config/file.conf'
        config = ConfigLoader(path)
        assert config.settings['site'] == 'Default Site'
        assert config.settings['enable_maps'] is False
        assert 'Default VPN' in config.vpns

    def test_multiple_vpns_preserve_order(self):
        path = _write_config(
            "[openvpn-monitor]\n"
            "site=Test\n"
            "\n"
            "[Alpha VPN]\n"
            "host=10.0.0.1\n"
            "port=5555\n"
            "\n"
            "[Beta VPN]\n"
            "host=10.0.0.2\n"
            "port=5556\n"
        )
        try:
            config = ConfigLoader(path)
            vpn_names = list(config.vpns.keys())
            assert vpn_names == ['Alpha VPN', 'Beta VPN']
        finally:
            os.unlink(path)

    def test_maps_key_not_accepted(self):
        """Only 'enable_maps' is recognized, not 'maps'."""
        path = _write_config(
            "[openvpn-monitor]\n"
            "site=Test\n"
            "maps=True\n"
        )
        try:
            config = ConfigLoader(path)
            assert 'enable_maps' not in config.settings
        finally:
            os.unlink(path)
