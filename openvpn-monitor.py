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
                         'datetime_format': '%d/%m/%Y %H:%M:%S'}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'show_disconnect': False}

    def parse_global_section(self, config):
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps', 'geoip_data', 'datetime_format']
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
        if 'show_disconnect' in vpn and vpn['show_disconnect'] == 'True':
            vpn['show_disconnect'] = True
        else:
            vpn['show_disconnect'] = False
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
                #Obtain IPv6 address data from routing tables
                remote_str_route = parts[3]
                if remote_str_route.count(':') == 1:
                    remote_route, port_route = remote_str_route.split(':')
                elif '(' in remote_str_route:
                    remote_route, port_route = remote_str_route.split('(')
                    port_route = port_route[:-1]
                else:
                    remote_route = remote_str_route
                    port_route = None
                for key, session in list(sessions.items()):
                    if isinstance(ip_address(local_ip), IPv6Address) \
                            and session['remote_ip'] == ip_address(remote_route) \
                            and session['port'] == int(port_route):
                        sessions[key]['local_ipv6_new'] = ip_address(local_ip)
                        break

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

        self.site = 'Example'
        if 'site' in settings:
            self.site = settings['site']

        self.logo = None
        if 'logo' in settings:
            self.logo = settings['logo']

        self.maps = False
        if 'maps' in settings and settings['maps'] == 'True':
            self.maps = True

        self.latitude = 40.72
        self.longitude = -74
        if 'latitude' in settings:
            self.latitude = settings['latitude']
        if 'longitude' in settings:
            self.longitude = settings['longitude']

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
        '''comment the old headers
        server_headers = ['Username / Hostname', 'VPN IP',
                          'Remote IP', 'Location', 'Bytes In',
                          'Bytes Out', 'Connected Since', 'Last Ping', 'Time Online']
        '''
        #add new header
        server_headers = ['Username / Hostname', 'VPN IP', 'VPN IPv6',
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

        output('<table id="sessions" class="table table-striped table-bordered ')
        output('table-hover table-condensed table-responsive ')
        output('tablesorter tablesorter-bootstrap">')
        output('<thead><tr>')
        for header in headers:
            output('<th>{0!s}</th>'.format(header))
        output('</tr></thead><tbody>')

    @staticmethod
    def print_session_table_footer():
        output('</tbody></table>')

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
        output('</tr></tbody></table>')

        if vpn_mode == 'Client' or nclients > 0:
            self.print_session_table_headers(vpn_mode, show_disconnect)
            self.print_session_table(vpn_id, vpn_mode, vpn_sessions, show_disconnect)
            self.print_session_table_footer()

        output('<span class="label label-default">{0!s}</span>'.format(vpn['version']))
        output('</div></div>')

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
        if session['local_ipv6_new']:
            output('<td>{0!s}</td>'.format(session['local_ipv6_new']))
        else:
            output('<td>{0!s}</td>'.format('N/A'))
        output('<td>{0!s}</td>'.format(session['remote_ip']))

        if 'location' in session:
            if session['location'] == 'RFC1918':
                output('<td>RFC1918</td>')
            else:
                flag = '{0!s}flags/{1!s}.png'.format(image_path, session['location'].lower())
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
        output('var map = L.map("map_canvas");')
        output('var centre = L.latLng({0!s}, {1!s});'.format(self.latitude, self.longitude))
        output('map.setView(centre, 8);')
        output('url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";')
        output('var layer = new L.TileLayer(url, {});')
        output('map.addLayer(layer);')
        output('var bounds = L.latLngBounds(centre);')
        for vkey, vpn in self.vpns:
            if 'sessions' in vpn:
                output('bounds.extend(centre);')
                for skey, session in list(vpn['sessions'].items()):
                    if 'longitude' in session and 'latitude' in session:
                        output('var latlng = new L.latLng({0!s}, {1!s});'.format(
                            session['latitude'], session['longitude']))
                        output('bounds.extend(latlng);')
                        output('var marker = L.marker(latlng).addTo(map);')
                        output('var popup = L.popup().setLatLng(latlng);')
                        output('popup.setContent("{0!s} - {1!s}");'.format(
                            session['username'], session['remote_ip']))
                        output('marker.bindPopup(popup);')
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
