#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Licensed under GPL v3
# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2016 Marcus Furlong <furlongm@gmail.com>

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
    from ipaddr import IPv6Address
except ImportError:
    from ipaddress import ip_address, IPv6Address


import socket
import re
import argparse
import GeoIP
import sys
import os
from datetime import datetime
from humanize import naturalsize
from collections import OrderedDict, deque
from pprint import pformat
from semantic_version import Version as semver

if sys.version_info[0] == 2:
    reload(sys)
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
            if section == 'OpenVPN-Monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def load_default_settings(self):
        info('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site',
                         'geoip_data': '/usr/share/GeoIP/GeoIPCity.dat',
                         'datetime_format': '%d/%m/%Y %H:%M:%S',
                         'marker': False,
                         'externalip': '0.0.0.0',
                         'pervpn_control': False,
                         'itemtype_control': False,
                         'allowFullscreen': False}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'show_disconnect': False,
                                    'externalip': '0.0.0.0',
                                    'latitude': '-35.308065',
                                    'longitude': '149.124521',
                                    'marker': False,
                                    'connection_lines': False}


    def parse_global_section(self, config):
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps',
                       'geoip_data', 'datetime_format', 'marker',
                       'externalip', 'pervpn_control',
                       'itemtype_control', 'allowFullscreen']
        for var in global_vars:
            try:
                self.settings[var] = config.get('OpenVPN-Monitor', var)
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
        vpn['show_disconnect'] = bool('show_disconnect' in vpn and
                                      vpn['show_disconnect'] == 'True')
        vpn['marker'] = bool('marker' in vpn and vpn['marker'] == 'True')
        vpn['connection_lines'] = bool('connection_lines' in vpn and
                                       vpn['connection_lines'] == 'True')
        if 'externalip' not in vpn:
            vpn['externalip'] = '0.0.0.0'
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))


class OpenvpnMgmtInterface(object):

    def __init__(self, cfg, **kwargs):
        self.vpns = cfg.vpns

        if 'vpn_id' in kwargs:
            vpn = self.vpns[kwargs['vpn_id']]
            self._socket_connect(vpn)
            if vpn['socket_connected']:
                version = self.send_command('version\n')
                sem_ver = semver(self.parse_version(version).split(' ')[1])
                if sem_ver.minor == 4 and 'port' not in kwargs:
                    command = 'client-kill {0!s}\n'.format(kwargs['client_id'])
                else:
                    command = 'kill {0!s}:{1!s}\n'.format(kwargs['ip'], kwargs['port'])
                info('Sending command: {0!s}'.format(command))
                self.send_command(command)
                self._socket_disconnect()

        geoip_data = cfg.settings['geoip_data']
        self.gi = GeoIP.open(geoip_data, GeoIP.GEOIP_STANDARD)

        for key, vpn in list(self.vpns.items()):
            self._socket_connect(vpn)
            if vpn['socket_connected']:
                self.collect_data(vpn)
                self._socket_disconnect()

    def collect_data(self, vpn):
        version = self.send_command('version\n')
        vpn['version'] = self.parse_version(version)
        vpn['semver'] = semver(vpn['version'].split(' ')[1])
        state = self.send_command('state\n')
        vpn['state'] = self.parse_state(state)
        stats = self.send_command('load-stats\n')
        vpn['stats'] = self.parse_stats(stats)
        status = self.send_command('status 3\n')
        vpn['sessions'] = self.parse_status(status, self.gi, vpn['semver'])
        if 'latitude' not in vpn or 'longitude' not in vpn:
            # default Canberra
            vpn['longitude'] = '149.124521'
            vpn['latitude'] = '-35.308065'
            if 'externalip' in vpn:
                try:
                    gir = self.gi.record_by_addr(str(vpn['externalip']))
                except SystemError:
                    gir = None
                if gir is not None:
                    vpn['longitude'] = gir['longitude']
                    vpn['latitude'] = gir['latitude']

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
        host = vpn['host']
        port = int(vpn['port'])
        timeout = 3
        self.s = False
        try:
            self.s = socket.create_connection((host, port), timeout)
            if self.s:
                vpn['socket_connected'] = True
                data = ''
                while 1:
                    socket_data = self._socket_recv(1024)
                    data += socket_data
                    if data.endswith('\r\n'):
                        break
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
        self._socket_send(command)
        data = ''
        if command.startswith('kill') or command.startswith('client-kill'):
            return
        while 1:
            socket_data = self._socket_recv(1024)
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
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

    @staticmethod
    def parse_status(data, gi, version):
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
                if isinstance(remote_ip, IPv6Address) and \
                        remote_ip.ipv4_mapped is not None:
                    session['remote_ip'] = remote_ip.ipv4_mapped
                else:
                    session['remote_ip'] = remote_ip
                if port:
                    session['port'] = int(port)
                else:
                    session['port'] = ''
                if session['remote_ip'].is_private:
                    session['location'] = 'RFC1918'
                else:
                    try:
                        gir = gi.record_by_addr(str(session['remote_ip']))
                    except SystemError:
                        gir = None
                    if gir is not None:
                        session['location'] = gir['country_code']
                        session['city'] = get_str(gir['city'])
                        session['country_name'] = gir['country_name']
                        session['longitude'] = gir['longitude']
                        session['latitude'] = gir['latitude']
                local_ipv4 = parts.popleft()
                if local_ipv4:
                    session['local_ip'] = ip_address(local_ipv4)
                else:
                    session['local_ip'] = ''
                if version.minor == 4:
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
                if version.minor == 4:
                    session['client_id'] = parts.popleft()
                    session['peer_id'] = parts.popleft()
                sessions[str(session['local_ip'])] = session

            if routes_section:
                local_ip = parts[1]
                last_seen = parts[5]
                if local_ip in sessions:
                    sessions[local_ip]['last_seen'] = get_date(last_seen, uts=True)

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
        self.gi = monitor.gi

        self.site = 'Example'
        if 'site' in settings:
            self.site = settings['site']

        self.logo = None
        if 'logo' in settings:
            self.logo = settings['logo']

        self.maps = False
        if 'maps' in settings and settings['maps'] == 'True':
            self.maps = True

        self.externalip = '0.0.0.0'
        if 'externalip' in settings:
            self.externalip = settings['externalip']

        # default melbourne
        self.latitude = -37.8067
        self.longitude = 144.9635
        if 'latitude' in settings and 'longitude' in settings:
            self.latitude = settings['latitude']
            self.longitude = settings['longitude']
        else:
            try:
                gir = self.gi.record_by_addr(self.externalip)
            except SystemError:
                gir = None
            if gir is not None:
                self.location = gir['country_code']
                self.city = get_str(gir['city'])
                self.country_name = gir['country_name']
                self.longitude = gir['longitude']
                self.latitude = gir['latitude']

        self.marker = False
        if 'marker' in settings and settings['marker'] == 'True':
            self.marker = True

        self.pervpn_control = False
        if ('pervpn_control' in settings and
                settings['pervpn_control'] == 'True'):
            self.pervpn_control = True

        self.itemtype_control = False
        if ('itemtype_control' in settings and
                settings['itemtype_control'] == 'True'):
            self.itemtype_control = True

        self.allowFullscreen = False
        if ('allowFullscreen' in settings and
                settings['allowFullscreen'] == 'True'):
            self.allowFullscreen = True

        self.datetime_format = settings['datetime_format']

    def print_html_header(self):

        global wsgi
        if not wsgi:
            output("Content-Type: text/html\n")
        output('<!doctype html>')
        output('<html><head>')
        output('<meta charset="utf-8">')
        output('<meta http-equiv="X-UA-Compatible" content="IE=edge">')
        output('<meta name="viewport" content="width=device-width, initial-scale=1">')
        output('<title>{0!s} OpenVPN Status Monitor</title>'.format(self.site))
        output('<meta http-equiv="refresh" content="300" />')

        # css
        output('<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous" />')
        output('<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous" />')
        output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.28.4/css/theme.bootstrap.min.css" integrity="sha256-cerl+DYHeG2ZhV/9iueb8E+s7rubli1gsnKuMbKDvho=" crossorigin="anonymous" />')
        if self.maps:
            output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet/1.0.2/leaflet.css" integrity="sha256-9mfj77orHLh2GsN7CbMvpjO/Wny/ZZhR7Pu7hy0Yig4=" crossorigin="anonymous" />')
        if self.maps and self.allowFullscreen:
            # Leaflet.Control.FullScreen css
            output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet.fullscreen/1.4.2/Control.FullScreen.min.css" integrity="sha256-5cUdI/OZOFcVL9i5LiXvBL5UCGT+AFANIphndyL8SBk=" crossorigin="anonymous" />')  # noqa: E501
        output('<style>')
        output('.panel-custom {')
        output('   background-color:#777;')
        output('   color:#fff;')
        output('   font-size:75%;')
        output('   vertical-align:baseline;')
        output('   padding:.2em .6em .3em;')
        output('   line-height:1;')
        output('   font-weight:700;')
        output('{')
        output('</style>')

        # favicon
        output('<link rel="shortcut icon" href="/images/favicon.ico" />')

        # js
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.1.1/jquery.min.js" integrity="sha256-hVVnYaiADRTO2PzUGmuLJr8BLUSjGIZsDYGmIJLv2b8=" crossorigin="anonymous"></script>')
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.28.4/js/jquery.tablesorter.min.js" integrity="sha256-etMCBAdNUB2TBSMUe3GISzr+drx6+BjwAt9T3qjO2xk=" crossorigin="anonymous"></script>')
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.28.4/js/jquery.tablesorter.widgets.min.js" integrity="sha256-29n48bNY/veiCp3sAG1xntm9MdMT5+IuZNpeJtV/xEg=" crossorigin="anonymous"></script>')
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.28.4/js/parsers/parser-network.min.js" integrity="sha256-E0X65/rdWP806UYOzvOzTshT6a3R74j/9UOqcB9+6lc=" crossorigin="anonymous"></script>')
        output('<script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>')
        output('<script>$(document).ready(function(){')
        output('$("table.tablesorter").tablesorter({theme:"bootstrap", headerTemplate:"{content} {icon}", widgets:["uitheme"]});')
        output('});</script>')
        if self.maps:
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet/1.0.2/leaflet.js" integrity="sha256-RS5bDpN9YmmUIdtdu8ESPjNp1Bg/Fqu90PwN3uawdSQ=" crossorigin="anonymous"></script>')
            # spiderfy
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/OverlappingMarkerSpiderfier-Leaflet/0.2.6/oms.min.js" integrity="sha256-t+V41b9l6j8GMYAbpcnZbib1XiYwCAsDibD8sI1D7+Y=" crossorigin="anonymous"></script>')  # noqa: E501
        if self.maps and self.allowFullscreen:
            # Leaflet.Control.FullScreen js
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet.fullscreen/1.4.2/Control.FullScreen.min.js" integrity="sha256-1k7z6MchW2n/LeqU0PNtvEgBYSPvtt+eDrUKaR/rksI=" crossorigin="anonymous"></script>')  # noqa: E501

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

        for key, vpn in self.vpns:
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
            output('src="{0!s}"></a>'.format(self.logo))

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
        output('{0!s}:{1!s} ({2!s})</div></div>'.format(vpn['host'],
                                                        vpn['port'],
                                                        vpn['error']))

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
        output('{0!s}'.format(vpn['version']))
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

        if 'location' in session:
            if session['location'] == 'RFC1918':
                output('<td>RFC1918</td>')
            else:
                loc = session['location'].lower()
                flag = '{0!s}images/flags/{1!s}.png'.format(image_path, loc)
                if 'city' in session and 'country_name' in session:
                    country = session['country_name']
                    city = session['city']
                    if city:
                        full_location = '{0!s}, {1!s}'.format(city, country)
                    else:
                        full_location = country
                output('<td><img src="{0!s}" title="{1!s}" alt="{1!s}" /> '.format(flag, full_location))
                output('{0!s}</td>'.format(full_location))
        else:
            output('<td>Unknown</td>')

        output('<td>{0!s} ({1!s})</td>'.format(bytes_recv, naturalsize(bytes_recv, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(bytes_sent, naturalsize(bytes_sent, binary=True)))
        output('<td>{0!s}</td>'.format(
            session['connected_since'].strftime(self.datetime_format)))
        if 'last_seen' in session:
            output('<td>{0!s}</td>'.format(
                session['last_seen'].strftime(self.datetime_format)))
        else:
            output('<td>ERROR</td>')
        output('<td>{0!s}</td>'.format(total_time))
        if show_disconnect:
            output('<td><form method="post">')
            output('<input type="hidden" name="vpn_id" value="{0!s}">'.format(vpn_id))
            if 'port' in session:
                output('<input type="hidden" name="ip" value="{0!s}">'.format(session['remote_ip']))
                output('<input type="hidden" name="port" value="{0!s}">'.format(session['port']))
            if 'client_id' in session:
                output('<input type="hidden" name="client_id" value="{0!s}">'.format(session['client_id']))
            output('<button type="submit" class="btn btn-xs btn-danger">')
            output('<span class="glyphicon glyphicon-remove"></span> ')
            output('Disconnect</button></form></td>')

    def print_session_table(self, vpn_id, vpn_mode, sessions, show_disconnect):
        for key, session in list(sessions.items()):
            output('<tr>')
            if vpn_mode == 'Client':
                self.print_client_session(session)
            elif vpn_mode == 'Server':
                self.print_server_session(vpn_id, session, show_disconnect)
            output('</tr>')

    def print_maps_html(self):
        output('<div class="panel panel-info"><div class="panel-heading">')
        output('<h3 class="panel-title">Map View</h3></div><div class="panel-body">')
        output('<div id="map_canvas" style="height:500px"></div>')
        output('<script type="text/javascript">')
        if self.allowFullscreen:
            output('var map = L.map("map_canvas", { fullscreenControl: true, '
                   'fullscreenControlOptions: { position: "topleft" }  });')
        else:
            output('var map = L.map("map_canvas");')
        output('var centre = L.latLng({0!s}, {1!s});'.format(self.latitude, self.longitude))
        output('map.setView(centre, 8);')
        output('url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";')
        output('var layer = new L.TileLayer(url, {});')
        output('map.addLayer(layer);')
        output('var bounds = L.latLngBounds(centre);')

        # spiderfy closeby clients
        output('var oms = new OverlappingMarkerSpiderfier '
               '(map,{keepSpiderfied:true});')

        # Extend the Default marker class
        output('var LeafIcon = L.Icon.extend('
               '{options: {iconAnchor: [12, 41]}});')
        output('var redIcon = new LeafIcon('
               '{iconUrl: "images/marker-icon-red.png"});')
        output('var orangeIcon = new LeafIcon('
               '{iconUrl: "images/marker-icon-orange.png"});')
        output('var greenIcon = new LeafIcon('
               '{iconUrl: "images/marker-icon-green.png"});')
        output('var blueIcon = new LeafIcon('
               '{iconUrl: "images/marker-icon-blue.png"});')

        # used later to add per vpn layers
        output('var overlayMaps = {};')
        output('var overlayPerVPN = {};')

        output('var monitorLayer = L.layerGroup();')
        # add marker for monitor box
        if self.marker:
            output('var monitor = L.marker(centre, {icon: greenIcon});')
            output('monitor.alt = "Type: Monitor<br/>'
                   'Name: {0!s}<br/>IP:{1!s}";'.format(
                    self.site, self.externalip))
            output('monitorLayer.addLayer(monitor);')
            output('oms.addMarker(monitor);')
        output('monitorLayer.addTo(map);')

        output('var vpnclientLayer = L.layerGroup();')
        output('var vpnserverLayer = L.layerGroup();')
        output('var vpnconnectionsLayer = L.layerGroup();')

        display_connection_legend = False
        display_server_legend = False
        for vkey, vpn in self.vpns:
            if 'sessions' in vpn:
                output('bounds.extend(centre);')
                # create per vpn layer
                output('var pervpnLayer = L.layerGroup();')
                # add self marker per vpn
                if ('longitude' in vpn and
                        'latitude' in vpn and
                        vpn['marker'] is True):
                    display_server_legend = True
                    output('var latlng = new L.latLng({0!s}, {1!s});'.format(
                        vpn['latitude'], vpn['longitude']))
                    output('bounds.extend(latlng);')
                    output('var server_marker = L.marker(latlng, '
                           '{icon: orangeIcon}).addTo(vpnserverLayer)'
                           '.addTo(pervpnLayer);')
                    output('oms.addMarker(server_marker);')
                    output('server_marker.alt = "Type: Server<br/>'
                           'Name: {0!s}<br/>IP: {1!s}";'.format(
                            vpn['name'], vpn['externalip']))

                for skey, session in list(vpn['sessions'].items()):
                    if 'longitude' in session and 'latitude' in session:
                        output('var latlng = new L.latLng({0!s}, {1!s});'.format(
                            session['latitude'], session['longitude']))
                        output('bounds.extend(latlng);')
                        output('var client_marker = L.marker(latlng)'
                               '.addTo(vpnclientLayer).addTo(pervpnLayer);')
                        output('oms.addMarker(client_marker);')
                        output('client_marker.alt = "Type: Client<br/>'
                               'Name: {0!s}<br/>IP: {1!s}";'.format(
                                   session['username'], session['remote_ip']))
                        # adding routing lines (they rely on server info)
                        if (vpn['connection_lines'] is True and
                                vpn['marker'] is True and
                                'longitude' in vpn and
                                'latitude' in vpn):
                            display_connection_legend = True
                            output('var latlngs = Array();')
                            output('latlngs.push(client_marker.getLatLng());')
                            output('latlngs.push(server_marker.getLatLng());')
                            output('var polyline = L.polyline(latlngs,'
                                   '{color:"blue",weight:2,opacity:0.5})'
                                   '.addTo(vpnconnectionsLayer)'
                                   '.addTo(pervpnLayer).addTo(map);')

                # add to map
                output('pervpnLayer.addTo(map);')
                # add per vpn layers
                output('if(!$.isEmptyObject(pervpnLayer.getLayers())){')
                output('overlayPerVPN["{0!s}"] = '
                       'pervpnLayer;'.format(vpn['name']))
                output('}')

        output('vpnclientLayer.addTo(map);')
        output('vpnserverLayer.addTo(map);')
        output('vpnconnectionsLayer.addTo(map);')
        output('map.fitBounds(bounds);')

        # add Layer objects for non empty items
        output('if(!$.isEmptyObject(monitorLayer.getLayers()))')
        output('{overlayMaps["VPN Monitor"] = monitorLayer;}')
        output('if(!$.isEmptyObject(vpnclientLayer.getLayers()))')
        output('{overlayMaps["VPN Clients"] = vpnclientLayer;}')
        output('if(!$.isEmptyObject(vpnserverLayer.getLayers()))')
        output('{overlayMaps["VPN Servers"] = vpnserverLayer;}')
        output('if(!$.isEmptyObject(vpnconnectionsLayer.getLayers()))')
        output('{overlayMaps["VPN Routes"] = vpnconnectionsLayer;}')
        if self.itemtype_control:
            output('if(!$.isEmptyObject(overlayMaps))')
            output('{L.control.layers(null,overlayMaps,'
                   '{position:"topright"}).addTo(map);}')
        if self.pervpn_control:
            output('if(!$.isEmptyObject(overlayPerVPN))')
            output('{L.control.layers(null,overlayPerVPN,'
                   '{position:"bottomleft"}).addTo(map);}')

        # spiderfy - add pop ups for close by icons
        output('var popup = new L.Popup({closeButton:false,'
               'offset:new L.Point(0.5,-24)});')
        output('oms.addListener("click", function(marker) {')
        output('   popup.setContent(marker.alt);')
        output('   popup.setLatLng(marker.getLatLng());')
        output('   map.openPopup(popup);')
        output('});')
        # spiderfy - close pop-ups when clicking elsewhere
        output('oms.addListener("spiderfy", function(markers) {')
        output('   map.closePopup();')
        output('});')

        output('</script>')

        output('<ul style="list-style:none;padding-top:5px;'
               'padding-left:0px;">')
        if self.marker:
            output('<li style="float:left;margin-right:10px;">')
            output('<span>')
            output('<img src="images/marker-icon-green.png" '
                   'style="width:20px;"/>')
            output('</span>')
            output('<span>Monitor</span>')
            output('</li>')
        if display_server_legend:
            output('<li style="float:left;margin-right:10px;">')
            output('<span>')
            output('<img src="images/marker-icon-orange.png" '
                   'style="width:20px;"/>')
            output('</span>')
            output('<span>Server</span>')
            output('</li>')
        output('<li style="float:left;margin-right:10px;">')
        output('<span>')
        output('<img src="images/marker-icon-blue.png" '
               'style="width:20px;"/>')
        output('</span>')
        output('<span>Client</span>')
        output('</li>')
        if display_connection_legend:
            output('<li style="float:left;margin-right:10px;">')
            output('<span>')
            output('<img src="images/route-icon.png" style="width:20px;"/>')
            output('</span>')
            output('<span>Route</span>')
            output('</li>')
        output('</ul>')

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
    image_path = 'images/'
    main()
else:
    from bottle import response, request, get, post, static_file, default_app

    class args(object):
        debug = False
        config = './openvpn-monitor.conf'

    wsgi = True
    wsgi_output = ''
    image_path = ''

    owd = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    sys.path.append(os.path.dirname(__file__))
    if owd != os.getcwd() and sys.prefix != '/usr':
        # virtualenv
        images_dir = owd + '/share/openvpn-monitor/images/'
    else:
        images_dir = 'images'

    application = default_app()

    @get('/')
    def get_slash():
        return render()

    @post('/')
    def post_slash():
        vpn_id = request.forms.get('vpn_id')
        ip = request.forms.get('ip')
        port = request.forms.get('port')
        client_id = request.forms.get('client_id')
        return render(vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)

    def render(**kwargs):
        global wsgi_output
        wsgi_output = ''
        main(**kwargs)
        response.content_type = 'text/html;'
        return wsgi_output

    @get('/<filename:re:.*\.(jpg|png)>')
    def images(filename):
        return static_file(filename, root=images_dir)
