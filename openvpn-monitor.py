#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2019 Marcus Furlong <furlongm@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 only.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

try:
    from ipaddr import IPAddress as ip_address
except ImportError:
    from ipaddress import ip_address

try:
    import GeoIP as geoip1
    geoip1_available = True
except ImportError:
    geoip1_available = False

try:
    from geoip2 import database
    from geoip2.errors import AddressNotFoundError
    geoip2_available = True
except ImportError:
    geoip2_available = False

import argparse
import os
import re
import socket
import string
import sys
import jinja2
from datetime import datetime
from humanize import naturalsize
from collections import OrderedDict, deque
from pprint import pformat
from semantic_version import Version as semver

if sys.version_info[0] == 2:
    reload(sys) # noqa
    sys.setdefaultencoding('utf-8')


def output(s):
    global wsgi, wsgi_output
    if not wsgi:
        print(s)
    else:
        wsgi_output += s


def info(*objs):
    print("INFO:", *objs, file=sys.stderr)


def warning(*objs):
    print("WARNING:", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y")
    else:
        return datetime.fromtimestamp(float(date_string))


def get_str(s):
    if sys.version_info[0] == 2 and s is not None:
        return s.decode('ISO-8859-1')
    else:
        return s


def is_truthy(s):
    return s in ['True', 'true', 'Yes', 'yes', True]


class ConfigLoader(object):

    def __init__(self, config_file):
        self.settings = {}
        self.vpns = OrderedDict()
        config = configparser.RawConfigParser()
        contents = config.read(config_file)

        if not contents and config_file == './openvpn-monitor.conf':
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            if sys.prefix == '/usr':
                conf_path = '/etc/'
            else:
                conf_path = sys.prefix + '/etc/'
            config_file = conf_path + 'openvpn-monitor.conf'
            contents = config.read(config_file)

        if contents:
            info('Using config file: {0!s}'.format(config_file))
        else:
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            self.load_default_settings()

        for section in config.sections():
            if section.lower() == 'openvpn-monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def load_default_settings(self):
        info('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site',
                         'maps': 'True',
                         'geoip_data': '/usr/share/GeoIP/GeoIPCity.dat',
                         'datetime_format': '%d/%m/%Y %H:%M:%S'}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'password': '',
                                    'show_disconnect': False}

    def parse_global_section(self, config):
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps', 'maps_height', 'geoip_data', 'datetime_format']
        for var in global_vars:
            try:
                self.settings[var] = config.get('openvpn-monitor', var)
            except configparser.NoSectionError:
                # backwards compat
                try:
                    self.settings[var] = config.get('OpenVPN-Monitor', var)
                except configparser.NoOptionError:
                    pass
            except configparser.NoOptionError:
                pass
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(self.settings))

    def parse_vpn_section(self, config, section):
        self.vpns[section] = {}
        vpn = self.vpns[section]
        options = config.options(section)
        for option in options:
            try:
                vpn[option] = config.get(section, option)
                if vpn[option] == -1:
                    warning('CONFIG: skipping {0!s}'.format(option))
            except configparser.Error as e:
                warning('CONFIG: {0!s} on option {1!s}: '.format(e, option))
                vpn[option] = None
        vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))


class OpenvpnMgmtInterface(object):

    def __init__(self, cfg, **kwargs):
        self.vpns = cfg.vpns

        if kwargs.get('vpn_id'):
            vpn = self.vpns[kwargs['vpn_id']]
            disconnection_allowed = vpn['show_disconnect']
            if disconnection_allowed:
                self._socket_connect(vpn)
                if vpn['socket_connected']:
                    release = self.send_command('version\n')
                    version = semver(self.parse_version(release).split(' ')[1])
                    command = False
                    client_id = int(kwargs.get('client_id'))
                    if version.major == 2 and \
                            version.minor >= 4 and \
                            client_id:
                        command = 'client-kill {0!s}\n'.format(client_id)
                    else:
                        ip = ip_address(kwargs['ip'])
                        port = int(kwargs['port'])
                        if ip and port:
                            command = 'kill {0!s}:{1!s}\n'.format(ip, port)
                    if command:
                        self.send_command(command)
                    self._socket_disconnect()

        geoip_data = cfg.settings['geoip_data']
        self.geoip_version = None
        self.gi = None
        try:
            if geoip_data.endswith('.mmdb') and geoip2_available:
                self.gi = database.Reader(geoip_data)
                self.geoip_version = 2
            elif geoip_data.endswith('.dat') and geoip1_available:
                self.gi = geoip1.open(geoip_data, geoip1.GEOIP_STANDARD)
                self.geoip_version = 1
            else:
                warning('No compatible geoip1 or geoip2 data/libraries found.')
        except IOError:
            warning('No compatible geoip1 or geoip2 data/libraries found.')

        for _, vpn in list(self.vpns.items()):
            vpn['id'] = _
            self._socket_connect(vpn)
            if vpn['socket_connected']:
                self.collect_data(vpn)
                self._socket_disconnect()

    def collect_data(self, vpn):
        ver = self.send_command('version\n')
        vpn['release'] = self.parse_version(ver)
        vpn['version'] = semver(vpn['release'].split(' ')[1])
        state = self.send_command('state\n')
        vpn['state'] = self.parse_state(state)
        stats = self.send_command('load-stats\n')
        vpn['stats'] = self.parse_stats(stats)
        status = self.send_command('status 3\n')
        vpn['sessions'] = self.parse_status(status, vpn['version'])

    def _socket_send(self, command):
        if sys.version_info[0] == 2:
            self.s.send(command)
        else:
            self.s.send(bytes(command, 'utf-8'))

    def _socket_recv(self, length):
        if sys.version_info[0] == 2:
            return self.s.recv(length)
        else:
            return self.s.recv(length).decode('utf-8')

    def _socket_connect(self, vpn):
        timeout = 3
        self.s = False
        try:
            if vpn.get('socket'):
                self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.s.connect(vpn['socket'])
            else:
                host = vpn['host']
                port = int(vpn['port'])
                self.s = socket.create_connection((host, port), timeout)
            if self.s:
                password = vpn.get('password')
                if password:
                    self.wait_for_data(password=password)
                vpn['socket_connected'] = True
        except socket.timeout as e:
            vpn['error'] = '{0!s}'.format(e)
            warning('socket timeout: {0!s}'.format(e))
            vpn['socket_connected'] = False
            if self.s:
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
        except socket.error as e:
            vpn['error'] = '{0!s}'.format(e.strerror)
            warning('socket error: {0!s}'.format(e))
            vpn['socket_connected'] = False
        except Exception as e:
            vpn['error'] = '{0!s}'.format(e)
            warning('unexpected error: {0!s}'.format(e))
            vpn['socket_connected'] = False

    def _socket_disconnect(self):
        self._socket_send('quit\n')
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()

    def send_command(self, command):
        info('Sending command: {0!s}'.format(command))
        self._socket_send(command)
        if command.startswith('kill') or command.startswith('client-kill'):
            return
        return self.wait_for_data(command=command)

    def wait_for_data(self, password=None, command=None):
        data = ''
        while 1:
            socket_data = self._socket_recv(1024)
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
            if data.endswith('ENTER PASSWORD:'):
                if password:
                    self._socket_send('{0!s}\n'.format(password))
                else:
                    warning('password requested but no password supplied by configuration')
            if data.endswith('SUCCESS: password is correct\r\n'):
                break
            if command == 'load-stats\n' and data != '':
                break
            elif data.endswith("\nEND\r\n"):
                break
        if args.debug:
            debug("=== begin raw data\n{0!s}\n=== end raw data".format(data))
        return data

    @staticmethod
    def parse_state(data):
        state = {}
        for line in data.splitlines():
            parts = line.split(',')
            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
            if parts[0].startswith('>INFO') or \
               parts[0].startswith('END') or \
               parts[0].startswith('>CLIENT'):
                continue
            else:
                state['up_since'] = get_date(date_string=parts[0], uts=True)
                state['connected'] = parts[1]
                state['success'] = parts[2]
                if parts[3]:
                    state['local_ip'] = ip_address(parts[3])
                else:
                    state['local_ip'] = ''
                if parts[4]:
                    state['remote_ip'] = ip_address(parts[4])
                    state['mode'] = 'Client'
                else:
                    state['remote_ip'] = ''
                    state['mode'] = 'Server'
        return state

    @staticmethod
    def parse_stats(data):
        stats = {}
        line = re.sub('SUCCESS: ', '', data)
        parts = line.split(',')
        if args.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
        stats['nclients'] = int(re.sub('nclients=', '', parts[0]))
        stats['bytesin'] = int(re.sub('bytesin=', '', parts[1]))
        stats['bytesout'] = int(re.sub('bytesout=', '', parts[2]).replace('\r\n', ''))
        return stats

    def parse_status(self, data, version):
        gi = self.gi
        geoip_version = self.geoip_version
        client_section = False
        routes_section = False
        sessions = {}
        client_session = {}

        for line in data.splitlines():
            parts = deque(line.split('\t'))
            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))

            if parts[0].startswith('END'):
                break
            if parts[0].startswith('TITLE') or \
               parts[0].startswith('GLOBAL') or \
               parts[0].startswith('TIME'):
                continue
            if parts[0] == 'HEADER':
                if parts[1] == 'CLIENT_LIST':
                    client_section = True
                    routes_section = False
                if parts[1] == 'ROUTING_TABLE':
                    client_section = False
                    routes_section = True
                continue

            if parts[0].startswith('TUN') or \
               parts[0].startswith('TCP') or \
               parts[0].startswith('Auth'):
                parts = parts[0].split(',')
            if parts[0] == 'TUN/TAP read bytes':
                client_session['tuntap_read'] = int(parts[1])
                continue
            if parts[0] == 'TUN/TAP write bytes':
                client_session['tuntap_write'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP read bytes':
                client_session['tcpudp_read'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP write bytes':
                client_session['tcpudp_write'] = int(parts[1])
                continue
            if parts[0] == 'Auth read bytes':
                client_session['auth_read'] = int(parts[1])
                sessions['Client'] = client_session
                continue

            if client_section:
                session = {}
                parts.popleft()
                common_name = parts.popleft()
                remote_str = parts.popleft()
                if remote_str.count(':') == 1:
                    remote, port = remote_str.split(':')
                elif '(' in remote_str:
                    remote, port = remote_str.split('(')
                    port = port[:-1]
                else:
                    remote = remote_str
                    port = None
                remote_ip = ip_address(remote)
                session['remote_ip'] = remote_ip
                if port:
                    session['port'] = int(port)
                else:
                    session['port'] = ''
                if session['remote_ip'].is_private:
                    session['location'] = 'RFC1918'
                elif session['remote_ip'].is_loopback:
                    session['location'] = 'loopback'
                else:
                    try:
                        if geoip_version == 1:
                            gir = gi.record_by_addr(str(session['remote_ip']))
                            if gir is not None:
                                session['location'] = gir['country_code']
                                session['region'] = get_str(gir['region'])
                                session['city'] = get_str(gir['city'])
                                session['country'] = gir['country_name']
                                session['longitude'] = gir['longitude']
                                session['latitude'] = gir['latitude']
                        elif geoip_version == 2:
                            gir = gi.city(str(session['remote_ip']))
                            session['location'] = gir.country.iso_code
                            session['region'] = gir.subdivisions.most_specific.iso_code
                            session['city'] = gir.city.name
                            session['country'] = gir.country.name
                            session['longitude'] = gir.location.longitude
                            session['latitude'] = gir.location.latitude
                    except AddressNotFoundError:
                        pass
                    except SystemError:
                        pass
                local_ipv4 = parts.popleft()
                if local_ipv4:
                    session['local_ip'] = ip_address(local_ipv4)
                else:
                    session['local_ip'] = ''
                if version.major >= 2 and version.minor >= 4:
                    local_ipv6 = parts.popleft()
                    if local_ipv6:
                        session['local_ip'] = ip_address(local_ipv6)
                session['bytes_recv'] = int(parts.popleft())
                session['bytes_sent'] = int(parts.popleft())
                parts.popleft()
                session['connected_since'] = get_date(parts.popleft(), uts=True)
                username = parts.popleft()
                if username != 'UNDEF':
                    session['username'] = username
                else:
                    session['username'] = common_name
                if version.major == 2 and version.minor >= 4:
                    session['client_id'] = parts.popleft()
                    session['peer_id'] = parts.popleft()
                sessions[str(session['local_ip'])] = session

            if routes_section:
                local_ip = parts[1]
                remote_ip = parts[3]
                last_seen = get_date(parts[5], uts=True)
                if sessions.get(local_ip):
                    sessions[local_ip]['last_seen'] = last_seen
                elif self.is_mac_address(local_ip):
                    matching_local_ips = [sessions[s]['local_ip']
                                          for s in sessions if remote_ip ==
                                          self.get_remote_address(sessions[s]['remote_ip'], sessions[s]['port'])]
                    if len(matching_local_ips) == 1:
                        local_ip = '{0!s}'.format(matching_local_ips[0])
                        if sessions[local_ip].get('last_seen'):
                            prev_last_seen = sessions[local_ip]['last_seen']
                            if prev_last_seen < last_seen:
                                sessions[local_ip]['last_seen'] = last_seen
                        else:
                            sessions[local_ip]['last_seen'] = last_seen

        if args.debug:
            if sessions:
                pretty_sessions = pformat(sessions)
                debug("=== begin sessions\n{0!s}\n=== end sessions".format(pretty_sessions))
            else:
                debug("no sessions")

        return sessions

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith('OpenVPN'):
                return line.replace('OpenVPN Version: ', '')

    @staticmethod
    def is_mac_address(s):
        return len(s) == 17 and \
            len(s.split(':')) == 6 and \
            all(c in string.hexdigits for c in s.replace(':', ''))

    @staticmethod
    def get_remote_address(ip, port):
        if port:
            return '{0!s}:{1!s}'.format(ip, port)
        else:
            return '{0!s}'.format(ip)

def build_template_context(cfg, monitor):
    if args.debug:
        pretty_vpns = pformat((dict(monitor.vpns)))
        debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))
    return {
        'site': cfg.settings.get('site', 'Example'),
        'vpns': list(monitor.vpns.items()),
        'maps': is_truthy(cfg.settings.get('maps', False)),
        'maps_height': cfg.settings.get('maps_height', 500),
        'latitude': cfg.settings.get('latitude', 40.72),
        'longitude': cfg.settings.get('longitude', -74),
        'datetime_format': cfg.settings.get('datetime_format')
    }

def get_args():
    parser = argparse.ArgumentParser(
        description='Display a html page with openvpn status and connections')
    parser.add_argument('-d', '--debug', action='store_true',
                        required=False, default=False,
                        help='Run in debug mode')
    parser.add_argument('-c', '--config', type=str,
                        required=False, default='./openvpn-monitor.conf',
                        help='Path to config file openvpn-monitor.conf')
    return parser.parse_args()

env = jinja2.Environment(
    loader = jinja2.FileSystemLoader('./templates'),
    extensions = ["jinja2_humanize_extension.HumanizeExtension"]
)

env.globals.update({
    'now': datetime.now,
})

if __name__ == '__main__':
    args = get_args()
    wsgi = False
    template = env.get_template('openvpn-monitor.html.j2')
    cfg = ConfigLoader(args.config)
    monitor = OpenvpnMgmtInterface(cfg)

    output(template.render(build_template_context(cfg, monitor)))

def view(template_name):
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(*args, **kwargs):
            response = view_func(*args, **kwargs)
            if isinstance(response, dict):
                template = env.get_or_select_template(template_name)
                return template.render(**response)
            else:
                return response

        return wrapper

    return decorator

def monitor_wsgi():

    owd = os.getcwd()
    if owd.endswith('site-packages') and sys.prefix != '/usr':
        # virtualenv
        image_dir = owd + '/../../../share/openvpn-monitor/'
    else:
        image_dir = ''

    app = Bottle()

    @app.hook('before_request')
    def strip_slash():
        request.environ['PATH_INFO'] = request.environ.get('PATH_INFO', '/').rstrip('/')
        if args.debug:
            debug(pformat(request.environ))

    @app.route('/', method='GET')
    @view('openvpn-monitor.html.j2')
    def get_slash():
        cfg = ConfigLoader(args.config)
        monitor = OpenvpnMgmtInterface(cfg)

        return build_template_context(cfg, monitor)

    @app.route('/', method='POST')
    @view('openvpn-monitor.html.j2')
    def post_slash():
        cfg = ConfigLoader(args.config)
        monitor = OpenvpnMgmtInterface(cfg, monitor)

        return build_template_context(vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)

    @app.route('/<filename:re:.*\.(jpg|png)>', method='GET')
    def get_images(filename):
        return static_file(filename, image_dir)

    return app


if __name__.startswith('_mod_wsgi_') or \
        __name__ == 'openvpn-monitor' or \
        __name__ == 'uwsgi_file_openvpn-monitor':
    if __file__ != 'openvpn-monitor.py':
        os.chdir(os.path.dirname(__file__))
        sys.path.append(os.path.dirname(__file__))
    from bottle import Bottle, response, request, static_file, functools

    class args(object):
        debug = False
        config = './openvpn-monitor.conf'

    wsgi = True
    wsgi_output = ''
    application = monitor_wsgi()
