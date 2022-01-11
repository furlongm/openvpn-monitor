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


class OpenvpnHtmlPrinter(object):

    def __init__(self, cfg, monitor):
        self.init_vars(cfg.settings, monitor)
        self.print_html_header()
        for key, vpn in self.vpns:
            if vpn['socket_connected']:
                self.print_vpn(key, vpn)
            else:
                self.print_unavailable_vpn(vpn)
        if self.maps:
            self.print_maps_html()
            self.print_html_footer()

    def init_vars(self, settings, monitor):
        self.vpns = list(monitor.vpns.items())
        self.site = settings.get('site', 'Example')
        self.logo = settings.get('logo')
        self.maps = is_truthy(settings.get('maps', False))
        if self.maps:
            self.maps_height = settings.get('maps_height', 500)
        self.latitude = settings.get('latitude', 40.72)
        self.longitude = settings.get('longitude', -74)
        self.datetime_format = settings.get('datetime_format')

    def print_html_header(self):

        global wsgi
        if not wsgi:
            output("Content-Type: text/html\n")
        output('<!doctype html>')
        output('<html lang="en"><head>')
        output('<meta charset="utf-8">')
        output('<meta http-equiv="X-UA-Compatible" content="IE=edge">')
        output('<meta name="viewport" content="width=device-width, initial-scale=1">')
        output('<title>{0!s} OpenVPN Status Monitor</title>'.format(self.site))
        output('<meta http-equiv="refresh" content="300" />')

        # css
        output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.4.1/css/bootstrap.min.css" integrity="sha512-Dop/vW3iOtayerlYAqCgkVr2aTr2ErwwTYOvRFUpzl2VhCMJyjQF0Q9TjUXIo6JhuM/3i0vVEt2e/7QQmnHQqw==" crossorigin="anonymous" />')  # noqa
        output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.4.1/css/bootstrap-theme.min.css" integrity="sha512-iy8EXLW01a00b26BaqJWaCmk9fJ4PsMdgNRqV96KwMPSH+blO82OHzisF/zQbRIIi8m0PiO10dpS0QxrcXsisw==" crossorigin="anonymous" />')  # noqa
        output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/css/theme.bootstrap_3.min.css" integrity="sha512-1r2gsUynzocV5QbYgEwbcNGYQeQ4jgHUNZLl+PMr6o248376S3f9k8zmXvsKkU06wH0MrmQacKd0BjJ/kWeeng==" crossorigin="anonymous" />')  # noqa
        if self.maps:
            output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/leaflet.min.css" integrity="sha512-1xoFisiGdy9nvho8EgXuXvnpR5GAMSjFwp40gSRE3NwdUdIMIKuPa7bqoUhLD0O/5tPNhteAsE5XyyMi5reQVA==" crossorigin="anonymous" />')  # noqa
            output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet.fullscreen/2.0.0/Control.FullScreen.min.css" integrity="sha512-DRkMa+fn898M1uc6s9JZeztUoXN6viuHsXmh/pgz3jG6a77YWO3U3QYEjLoqbxOeclc2NunWfMTya4Y5twXAKA==" crossorigin="anonymous" />')  # noqa
        output('<style>')
        output('.panel-custom {')
        output('   background-color:#777;')
        output('   color:#fff;')
        output('   font-size:80%;')
        output('   vertical-align:baseline;')
        output('   padding:.4em .4em .4em;')
        output('   line-height:1;')
        output('   font-weight:700;')
        output('}')
        output('</style>')

        # js
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js" integrity="sha512-bLT0Qm9VnAYZDflyKcBaQ2gg0hSYNQrJ8RilYldYQ1FxQYoCLtUjuuRuZo+fjqhx/qtq/1itJ0C2ejDxltZVFg==" crossorigin="anonymous"></script>')  # noqa
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/jquery.tablesorter.min.js" integrity="sha512-qzgd5cYSZcosqpzpn7zF2ZId8f/8CHmFKZ8j7mU4OUXTNRd5g+ZHBPsgKEwoqxCtdQvExE5LprwwPAgoicguNg==" crossorigin="anonymous"></script>')  # noqa
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/jquery.tablesorter.widgets.min.js" integrity="sha512-dj/9K5GRIEZu+Igm9tC16XPOTz0RdPk9FGxfZxShWf65JJNU2TjbElGjuOo3EhwAJRPhJxwEJ5b+/Ouo+VqZdQ==" crossorigin="anonymous"></script>')  # noqa
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/parsers/parser-network.min.js" integrity="sha512-13ZRU2LDOsGjGgqBkQPKQ/JwT/SfWhtAeFNEbB0dFG/Uf/D1OJPbTpeK2AedbDnTLYWCB6VhTwLxlD0ws6EqCw==" crossorigin="anonymous"></script>')  # noqa
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.3/js/parsers/parser-duration.min.js" integrity="sha512-X7QJLLEO6yg8gSlmgRAP7Ec2qDD+ndnFcd8yagZkkN5b/7bCMbhRQdyJ4SjENUEr+4eBzgwvaFH5yR/bLJZJQA==" crossorigin="anonymous"></script>')  # noqa
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.4.1/js/bootstrap.min.js" integrity="sha512-oBTprMeNEKCnqfuqKd6sbvFzmFQtlXS3e0C/RGFV0hD6QzhHV+ODfaQbAlmY6/q0ubbwlAM/nCJjkrgA3waLzg==" crossorigin="anonymous"></script>')  # noqa
        output('<script>$(document).ready(function(){')
        output('$("table.tablesorter").tablesorter({')
        output('sortList: [[0,0]], theme:"bootstrap", headerTemplate:"{content} {icon}", widgets:["uitheme"],')
        output('durationLabels : "(?:years|year|y),(?:days|day|d),(?:hours|hour|h),(?:minutes|minute|min|m),(?:seconds|second|sec|s)"')
        output('});')
        output('});</script>')
        if self.maps:
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/leaflet.min.js" integrity="sha512-SeiQaaDh73yrb56sTW/RgVdi/mMqNeM2oBwubFHagc5BkixSpP1fvqF47mKzPGWYSSy4RwbBunrJBQ4Co8fRWA==" crossorigin="anonymous"></script>')  # noqa
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/OverlappingMarkerSpiderfier-Leaflet/0.2.6/oms.min.js" integrity="sha512-V8RRDnS4BZXrat3GIpnWx+XNYBHQGdK6nKOzMpX4R0hz9SPWt7fltGmmyGzUkVFZUQODO1rE+SWYJJkw3SYMhg==" crossorigin="anonymous"></script>')  # noqa
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet.fullscreen/2.0.0/Control.FullScreen.min.js" integrity="sha512-c6ydt5Rypa1ptlnH2U1u+JybARYppbD1qxgythCI4pJ9EOfNYEWlLBjxBX926O3tq5p4Aw5GTY68vT0FdKbG3w==" crossorigin="anonymous"></script>')  # noqa

        output('</head><body>')

        output('<nav class="navbar navbar-inverse">')
        output('<div class="container-fluid">')
        output('<div class="navbar-header">')
        output('<button type="button" class="navbar-toggle" ')
        output('data-toggle="collapse" data-target="#myNavbar">')
        output('<span class="icon-bar"></span>')
        output('<span class="icon-bar"></span>')
        output('<span class="icon-bar"></span>')
        output('</button>')

        output('<a class="navbar-brand" href="#">')
        output('{0!s} OpenVPN Status Monitor</a>'.format(self.site))

        output('</div><div class="collapse navbar-collapse" id="myNavbar">')
        output('<ul class="nav navbar-nav"><li class="dropdown">')
        output('<a class="dropdown-toggle" data-toggle="dropdown" href="#">VPN')
        output('<span class="caret"></span></a>')
        output('<ul class="dropdown-menu">')

        for _, vpn in self.vpns:
            if vpn['name']:
                anchor = vpn['name'].lower().replace(' ', '_')
                output('<li><a href="#{0!s}">{1!s}</a></li>'.format(anchor, vpn['name']))
        output('</ul></li>')

        if self.maps:
            output('<li><a href="#map_canvas">Map View</a></li>')

        output('</ul>')

        if self.logo:
            output('<a href="#" class="pull-right"><img alt="Logo" ')
            output('style="max-height:46px; padding-top:3px;" ')
            if self.logo.startswith("http"):
                output('src="{0!s}"></a>'.format(self.logo))
            else:
                output('src="images/{0!s}"></a>'.format(self.logo))

        output('</div></div></nav>')
        output('<div class="container-fluid">')

    @staticmethod
    def print_session_table_headers(vpn_mode, show_disconnect):
        server_headers = ['Username / Hostname', 'VPN IP',
                          'Remote IP', 'Location', 'Bytes In',
                          'Bytes Out', 'Connected Since', 'Last Ping', 'Time Online']
        if show_disconnect:
            server_headers.append('Action')

        client_headers = ['Tun-Tap-Read', 'Tun-Tap-Write', 'TCP-UDP-Read',
                          'TCP-UDP-Write', 'Auth-Read']

        if vpn_mode == 'Client':
            headers = client_headers
        elif vpn_mode == 'Server':
            headers = server_headers

        output('<div class="table-responsive">')
        output('<table id="sessions" class="table table-striped table-bordered ')
        output('table-hover table-condensed table-responsive ')
        output('tablesorter tablesorter-bootstrap">')
        output('<thead><tr>')
        for header in headers:
            if header == 'Time Online':
                output('<th class="sorter-duration">{0!s}</th>'.format(header))
            else:
                output('<th>{0!s}</th>'.format(header))
        output('</tr></thead><tbody>')

    @staticmethod
    def print_session_table_footer():
        output('</tbody></table></div>')

    @staticmethod
    def print_unavailable_vpn(vpn):
        anchor = vpn['name'].lower().replace(' ', '_')
        output('<div class="panel panel-danger" id="{0!s}">'.format(anchor))
        output('<div class="panel-heading">')
        output('<h3 class="panel-title">{0!s}</h3></div>'.format(vpn['name']))
        output('<div class="panel-body">')
        output('Could not connect to ')
        if vpn.get('host') and vpn.get('port'):
            output('{0!s}:{1!s} ({2!s})</div></div>'.format(vpn['host'],
                                                            vpn['port'],
                                                            vpn['error']))
        elif vpn.get('socket'):
            output('{0!s} ({1!s})</div></div>'.format(vpn['socket'],
                                                      vpn['error']))
        else:
            warning('failed to get socket or network info: {}'.format(vpn))
            output('network or unix socket</div></div>')

    def print_vpn(self, vpn_id, vpn):

        if vpn['state']['success'] == 'SUCCESS':
            pingable = 'Yes'
        else:
            pingable = 'No'

        connection = vpn['state']['connected']
        nclients = vpn['stats']['nclients']
        bytesin = vpn['stats']['bytesin']
        bytesout = vpn['stats']['bytesout']
        vpn_mode = vpn['state']['mode']
        vpn_sessions = vpn['sessions']
        local_ip = vpn['state']['local_ip']
        remote_ip = vpn['state']['remote_ip']
        up_since = vpn['state']['up_since']
        show_disconnect = vpn['show_disconnect']

        anchor = vpn['name'].lower().replace(' ', '_')
        output('<div class="panel panel-success" id="{0!s}">'.format(anchor))
        output('<div class="panel-heading"><h3 class="panel-title">{0!s}</h3>'.format(
            vpn['name']))
        output('</div><div class="panel-body">')
        output('<div class="table-responsive">')
        output('<table class="table table-condensed table-responsive">')
        output('<thead><tr><th>VPN Mode</th><th>Status</th><th>Pingable</th>')
        output('<th>Clients</th><th>Total Bytes In</th><th>Total Bytes Out</th>')
        output('<th>Up Since</th><th>Local IP Address</th>')
        if vpn_mode == 'Client':
            output('<th>Remote IP Address</th>')
        output('</tr></thead><tbody>')
        output('<tr><td>{0!s}</td>'.format(vpn_mode))
        output('<td>{0!s}</td>'.format(connection))
        output('<td>{0!s}</td>'.format(pingable))
        output('<td>{0!s}</td>'.format(nclients))
        output('<td>{0!s} ({1!s})</td>'.format(bytesin, naturalsize(bytesin, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(bytesout, naturalsize(bytesout, binary=True)))
        output('<td>{0!s}</td>'.format(up_since.strftime(self.datetime_format)))
        output('<td>{0!s}</td>'.format(local_ip))
        if vpn_mode == 'Client':
            output('<td>{0!s}</td>'.format(remote_ip))
        output('</tr></tbody></table></div>')

        if vpn_mode == 'Client' or nclients > 0:
            self.print_session_table_headers(vpn_mode, show_disconnect)
            self.print_session_table(vpn_id, vpn_mode, vpn_sessions, show_disconnect)
            self.print_session_table_footer()

        output('</div>')
        output('<div class="panel-footer panel-custom">')
        output('{0!s}'.format(vpn['release']))
        output('</div>')
        output('</div>')

    @staticmethod
    def print_client_session(session):
        tuntap_r = session['tuntap_read']
        tuntap_w = session['tuntap_write']
        tcpudp_r = session['tcpudp_read']
        tcpudp_w = session['tcpudp_write']
        auth_r = session['auth_read']
        output('<td>{0!s} ({1!s})</td>'.format(tuntap_r, naturalsize(tuntap_r, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(tuntap_w, naturalsize(tuntap_w, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(tcpudp_r, naturalsize(tcpudp_w, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(tcpudp_w, naturalsize(tcpudp_w, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(auth_r, naturalsize(auth_r, binary=True)))

    def print_server_session(self, vpn_id, session, show_disconnect):
        total_time = str(datetime.now() - session['connected_since'])[:-7]
        bytes_recv = session['bytes_recv']
        bytes_sent = session['bytes_sent']
        output('<td>{0!s}</td>'.format(session['username']))
        output('<td>{0!s}</td>'.format(session['local_ip']))
        output('<td>{0!s}</td>'.format(session['remote_ip']))

        if session.get('location'):
            flag = 'images/flags/{0!s}.png'.format(session['location'].lower())
            if session.get('country'):
                country = session['country']
                full_location = country
            if session.get('region'):
                region = session['region']
                full_location = '{0!s}, {1!s}'.format(region, full_location)
            if session.get('city'):
                city = session['city']
                full_location = '{0!s}, {1!s}'.format(city, full_location)
            if session['location'] in ['RFC1918', 'loopback']:
                if session['location'] == 'RFC1918':
                    city = 'RFC1918'
                elif session['location'] == 'loopback':
                    city = 'loopback'
                country = 'Internet'
                full_location = '{0!s}, {1!s}'.format(city, country)
                flag = 'images/flags/rfc.png'
            output('<td><img src="{0!s}" title="{1!s}" alt="{1!s}" /> '.format(flag, full_location))
            output('{0!s}</td>'.format(full_location))
        else:
            output('<td>Unknown</td>')

        output('<td>{0!s} ({1!s})</td>'.format(bytes_recv, naturalsize(bytes_recv, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(bytes_sent, naturalsize(bytes_sent, binary=True)))
        output('<td>{0!s}</td>'.format(
            session['connected_since'].strftime(self.datetime_format)))
        if session.get('last_seen'):
            output('<td>{0!s}</td>'.format(
                session['last_seen'].strftime(self.datetime_format)))
        else:
            output('<td>Unknown</td>')
        output('<td>{0!s}</td>'.format(total_time))
        if show_disconnect:
            output('<td><form method="post">')
            output('<input type="hidden" name="vpn_id" value="{0!s}">'.format(vpn_id))
            if session.get('port'):
                output('<input type="hidden" name="ip" value="{0!s}">'.format(session['remote_ip']))
                output('<input type="hidden" name="port" value="{0!s}">'.format(session['port']))
            if session.get('client_id'):
                output('<input type="hidden" name="client_id" value="{0!s}">'.format(session['client_id']))
            output('<button type="submit" class="btn btn-xs btn-danger">')
            output('<span class="glyphicon glyphicon-remove"></span> ')
            output('Disconnect</button></form></td>')

    def print_session_table(self, vpn_id, vpn_mode, sessions, show_disconnect):
        for _, session in list(sessions.items()):
            if vpn_mode == 'Client':
                output('<tr>')
                self.print_client_session(session)
                output('</tr>')
            elif vpn_mode == 'Server' and session['local_ip']:
                output('<tr>')
                self.print_server_session(vpn_id, session, show_disconnect)
                output('</tr>')

    def print_maps_html(self):
        output('<div class="panel panel-info"><div class="panel-heading">')
        output('<h3 class="panel-title">Map View</h3></div><div class="panel-body">')
        output('<div id="map_canvas" style="height:{0!s}px"></div>'.format(self.maps_height))
        output('<script>')
        output('var map = L.map("map_canvas", { fullscreenControl: true, '
               'fullscreenControlOptions: { position: "topleft" }  });')
        output('var centre = L.latLng({0!s}, {1!s});'.format(self.latitude, self.longitude))
        output('map.setView(centre, 8);')
        output('url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";')
        output('var layer = new L.TileLayer(url, {});')
        output('map.addLayer(layer);')
        output('var bounds = L.latLngBounds(centre);')
        output('var oms = new OverlappingMarkerSpiderfier '
               '(map,{keepSpiderfied:true});')
        # spiderfy - add popups for closeby icons
        output('var popup = new L.Popup({closeButton:false,'
               'offset:new L.Point(0.5,-24)});')
        output('oms.addListener("click", function(marker) {')
        output('   popup.setContent(marker.alt);')
        output('   popup.setLatLng(marker.getLatLng());')
        output('   map.openPopup(popup);')
        output('});')
        # spiderfy - close popups when clicking elsewhere
        output('oms.addListener("spiderfy", function(markers) {')
        output('   map.closePopup();')
        output('});')
        for _, vpn in self.vpns:
            if vpn.get('sessions'):
                output('bounds.extend(centre);')
                for _, session in list(vpn['sessions'].items()):
                    if not session.get('local_ip'):
                        continue
                    if session.get('latitude') and session.get('longitude'):
                        output('var latlng = new L.latLng({0!s}, {1!s});'.format(
                            session['latitude'], session['longitude']))
                        output('bounds.extend(latlng);')
                        output('var client_marker = L.marker(latlng).addTo(map);')
                        output('oms.addMarker(client_marker);')
                        output('var client_popup = L.popup().setLatLng(latlng);')
                        output('client_popup.setContent("{0!s} - {1!s}");'.format(
                            session['username'], session['remote_ip']))
                        output('client_marker.bindPopup(client_popup);')
        output('map.fitBounds(bounds);')
        output('</script>')
        output('</div></div>')

    def print_html_footer(self):
        output('<div class="well well-sm">')
        output('Page automatically reloads every 5 minutes.')
        output('Last update: <b>{0!s}</b></div>'.format(
            datetime.now().strftime(self.datetime_format)))
        output('</div></body></html>')


def main(**kwargs):
    cfg = ConfigLoader(args.config)
    monitor = OpenvpnMgmtInterface(cfg, **kwargs)
    OpenvpnHtmlPrinter(cfg, monitor)
    if args.debug:
        pretty_vpns = pformat((dict(monitor.vpns)))
        debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))


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


if __name__ == '__main__':
    args = get_args()
    wsgi = False
    main()


def monitor_wsgi():

    owd = os.getcwd()
    if owd.endswith('site-packages') and sys.prefix != '/usr':
        # virtualenv
        image_dir = owd + '/../../../share/openvpn-monitor/'
    else:
        image_dir = ''

    app = Bottle()

    def render(**kwargs):
        global wsgi_output
        wsgi_output = ''
        main(**kwargs)
        response.content_type = 'text/html;'
        return wsgi_output

    @app.hook('before_request')
    def strip_slash():
        request.environ['PATH_INFO'] = request.environ.get('PATH_INFO', '/').rstrip('/')
        if args.debug:
            debug(pformat(request.environ))

    @app.route('/', method='GET')
    def get_slash():
        return render()

    @app.route('/', method='POST')
    def post_slash():
        vpn_id = request.forms.get('vpn_id')
        ip = request.forms.get('ip')
        port = request.forms.get('port')
        client_id = request.forms.get('client_id')
        return render(vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)

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
    from bottle import Bottle, response, request, static_file

    class args(object):
        debug = False
        config = './openvpn-monitor.conf'

    wsgi = True
    wsgi_output = ''
    application = monitor_wsgi()
