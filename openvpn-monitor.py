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
from uuid import uuid4
from datetime import datetime
from humanize import naturalsize
from collections import OrderedDict
from pprint import pformat

if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')


def output(s):
    global wsgi, wsgi_output
    if not wsgi:
        print(s)
    else:
        wsgi_output += s


def warning(*objs):
    output("WARNING: ", *objs, file=sys.stderr)


def debug(*objs):
    output("DEBUG:\n", *objs, file=sys.stderr)


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

        if not contents:
            output('Config file does not exist or is unreadable')
            self.load_default_settings()

        for section in config.sections():
            if section == 'OpenVPN-Monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def load_default_settings(self):
        warning('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site'}
        self.vpns['Default VPN'] = {'name': 'default', 'host': 'localhost',
                                    'port': '5555', 'order': '1'}

    def parse_global_section(self, config):
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps']
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
                    output(('CONFIG: skipping {0!s}'.format(option)))
            except configparser.Error as e:
                output(('CONFIG: {0!s} on option {1!s}: '.format(e, option)))
                vpn[option] = None
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))


class OpenvpnMonitor(object):

    def __init__(self, vpns):
        self.vpns = vpns
        for key, vpn in list(self.vpns.items()):
            self._socket_connect(vpn)
            if self.s:
                self.collect_data(vpn)
                self._socket_disconnect()

    def collect_data(self, vpn):
        version = self.send_command('version\n')
        vpn['version'] = self.parse_version(version)
        state = self.send_command('state\n')
        vpn['state'] = self.parse_state(state)
        stats = self.send_command('load-stats\n')
        vpn['stats'] = self.parse_stats(stats)
        status = self.send_command('status 3\n')
        vpn['sessions'] = self.parse_status(status)

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
        try:
            self.s = socket.create_connection((host, port), timeout)
            vpn['socket_connected'] = True
        except socket.error:
            self.s = False
            vpn['socket_connected'] = False

    def _socket_disconnect(self):
        self._socket_send('quit\n')
        self.s.close()

    def send_command(self, command):
        self._socket_send(command)
        data = ''
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
    def parse_status(data):
        client_section = False
        routes_section = False
        status_version = 1
        sessions = {}
        client_session = {}
        gi = GeoIP.open(args.geoip_data, GeoIP.GEOIP_STANDARD)

        for line in data.splitlines():

            if ',' in line:
                parts = line.split(',')
            else:
                parts = line.split('\t')

            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))

            if parts[0].startswith('GLOBAL'):
                break
            if parts[0] == 'HEADER':
                status_version = 3
                if parts[1] == 'CLIENT_LIST':
                    client_section = True
                    routes_section = False
                if parts[1] == 'ROUTING_TABLE':
                    client_section = False
                    routes_section = True
                continue
            if parts[0] == 'Updated':
                continue
            if parts[0] == 'Common Name':
                status_version = 1
                client_section = True
                routes_section = False
                continue
            if parts[0] == 'ROUTING TABLE' or parts[0] == 'Virtual Address':
                status_version = 1
                client_section = False
                routes_section = True
                continue
            if parts[0].startswith('>CLIENT'):
                continue

            session = {}
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
            if client_section and not routes_section:
                if status_version == 1:
                    ident = parts[1]
                    sessions[ident] = session
                    session['username'] = parts[0]
                    remote_ip, port = parts[1].split(':')
                    session['bytes_recv'] = int(parts[2])
                    session['bytes_sent'] = int(parts[3])
                    session['connected_since'] = get_date(parts[4])
                elif status_version == 3:
                    local_ip = parts[3]
                    if local_ip:
                        ident = local_ip
                    else:
                        ident = str(uuid4())
                    sessions[ident] = session
                    if parts[8] != 'UNDEF':
                        session['username'] = parts[8]
                    else:
                        session['username'] = parts[0]
                    if parts[2].count(':') == 1:
                        remote_ip, port = parts[2].split(':')
                    else:
                        remote_ip = parts[2]
                        port = None
                    remote_ip_address = ip_address(remote_ip)
                    if local_ip:
                        session['local_ip'] = ip_address(local_ip)
                    else:
                        session['local_ip'] = ''
                    session['bytes_recv'] = int(parts[4])
                    session['bytes_sent'] = int(parts[5])
                    session['connected_since'] = get_date(parts[7], uts=True)
                    session['last_seen'] = session['connected_since']
                session['location'] = 'Unknown'
                if isinstance(remote_ip_address, IPv6Address) and \
                        remote_ip_address.ipv4_mapped is not None:
                    session['remote_ip'] = remote_ip_address.ipv4_mapped
                else:
                    session['remote_ip'] = remote_ip_address
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
            if routes_section and not client_section:
                if status_version == 1:
                    ident = parts[2]
                    sessions[ident]['local_ip'] = ip_address(parts[0])
                    sessions[ident]['last_seen'] = get_date(parts[3])
                elif status_version == 3:
                    local_ip = parts[1]
                    if local_ip in sessions:
                        sessions[local_ip]['last_seen'] = get_date(parts[5], uts=True)

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
                self.print_vpn(vpn)
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

        self.latitude = -37.8067
        self.longitude = 144.9635
        if 'latitude' in settings:
            self.latitude = settings['latitude']
        if 'longitude' in settings:
            self.longitude = settings['longitude']

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

        if self.maps:
            self.print_maps_header()

        output('<script src="//cdnjs.cloudflare.com/ajax/libs/jquery/3.1.0/jquery.min.js"></script>')
        output('<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous">')
        output('<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous">')
        output('<script src="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>')
        output('<body>')

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
            output('<a href="#" class="pull-right"><img alt="self.logo" ')
            output('style="max-height:46px; padding-top:3px;" ')
            output('src="{0!s}"></a>'.format(self.logo))

        output('</div></div></nav>')
        output('<div class="container-fluid">')

    @staticmethod
    def print_session_table_headers(vpn_mode):

        server_headers = ['Username / Hostname', 'VPN IP Address',
                          'Remote IP Address', 'Port', 'Location', 'Bytes In',
                          'Bytes Out', 'Connected Since', 'Last Ping', 'Time Online']
        client_headers = ['Tun-Tap-Read', 'Tun-Tap-Write', 'TCP-UDP-Read',
                          'TCP-UDP-Write', 'Auth-Read']

        if vpn_mode == 'Client':
            headers = client_headers
        elif vpn_mode == 'Server':
            headers = server_headers

        output('<table class="table table-striped table-bordered table-hover ')
        output('table-condensed table-responsive">')
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
        output('Connection refused to {0!s}:{1!s} </div></div>'.format(vpn['host'], vpn['port']))

    def print_vpn(self, vpn):

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
        output('<td>{0!s}</td>'.format(up_since.strftime('%d/%m/%Y %H:%M:%S')))
        output('<td>{0!s}</td>'.format(local_ip))
        if vpn_mode == 'Client':
            output('<td>{0!s}</td>'.format(remote_ip))
        output('</tr></tbody></table>')

        if vpn_mode == 'Client' or nclients > 0:
            self.print_session_table_headers(vpn_mode)
            self.print_session_table(vpn_mode, vpn_sessions)
            self.print_session_table_footer()

        output('<span class="label label-default">{0!s}</span>'.format(vpn['version']))
        output('</div></div>')

    @staticmethod
    def print_client_session(session):
        output('<td>{0!s}</td>'.format(session['tuntap_read']))
        output('<td>{0!s}</td>'.format(session['tuntap_write']))
        output('<td>{0!s}</td>'.format(session['tcpudp_read']))
        output('<td>{0!s}</td>'.format(session['tcpudp_write']))
        output('<td>{0!s}</td>'.format(session['auth_read']))

    @staticmethod
    def print_server_session(session):

        total_time = str(datetime.now() - session['connected_since'])[:-7]
        bytes_recv = session['bytes_recv']
        bytes_sent = session['bytes_sent']
        output('<td>{0!s}</td>'.format(session['username']))
        output('<td>{0!s}</td>'.format(session['local_ip']))
        output('<td>{0!s}</td>'.format(session['remote_ip']))
        output('<td>{0!s}</td>'.format(session['port']))

        if 'city' in session and 'country_name' in session:
            country = session['country_name']
            city = session['city']
            if city:
                full_location = '{0!s}, {1!s}'.format(city, country)
            else:
                full_location = country
            flag = '{0!s}flags/{1!s}.png'.format(image_path, session['location'].lower())
            output('<td><img src="{0!s}" title="{1!s}" alt="{1!s}" /> '.format(flag, full_location))
            output('{0!s}</td>'.format(full_location))
        else:
            output('<td>{0!s}</td>'.format(session['location']))

        output('<td>{0!s} ({1!s})</td>'.format(bytes_recv, naturalsize(bytes_recv, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(bytes_sent, naturalsize(bytes_sent, binary=True)))
        output('<td>{0!s}</td>'.format(
            session['connected_since'].strftime('%d/%m/%Y %H:%M:%S')))
        if 'last_seen' in session:
            output('<td>{0!s}</td>'.format(
                session['last_seen'].strftime('%d/%m/%Y %H:%M:%S')))
        else:
            output('<td>ERROR</td>')
        output('<td>{0!s}</td>'.format(total_time))

    def print_session_table(self, vpn_mode, sessions):
        for key, session in list(sessions.items()):
            output('<tr>')
            if vpn_mode == 'Client':
                self.print_client_session(session)
            elif vpn_mode == 'Server':
                self.print_server_session(session)
            output('</tr>')

    @staticmethod
    def print_maps_header():
        output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/leaflet.css" />')
        output('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/leaflet.js"></script>')

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

    @staticmethod
    def print_html_footer():
        output('<div class="well well-sm">')
        output('Page automatically reloads every 5 minutes.')
        output('Last update: <b>{0!s}</b></div>'.format(
            datetime.now().strftime('%a %d/%m/%Y %H:%M:%S')))
        output('</div></body></html>')


def main():
    cfg = ConfigLoader(args.config)
    monitor = OpenvpnMonitor(cfg.vpns)
    OpenvpnHtmlPrinter(cfg, monitor)
    if args.debug:
        pretty_vpns = pformat((dict(monitor.vpns)))
        debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))


def collect_args():
    parser = argparse.ArgumentParser(
        description='Display a html page with openvpn status and connections')
    parser.add_argument('-d', '--debug', action='store_true',
                        required=False, default=False,
                        help='Run in debug mode')
    parser.add_argument('-c', '--config', type=str,
                        required=False, default='./openvpn-monitor.cfg',
                        help='Path to config file openvpn.cfg')
    parser.add_argument('-g', '--geoip-data', type=str,
                        required=False,
                        default='/usr/share/GeoIP/GeoIPCity.dat',
                        help='Path to GeoIPCity.dat')
    return parser


if __name__ == '__main__':
    args = collect_args().parse_args()
    wsgi = False
    image_path = 'images/'
    main()
else:
    class args:
        debug = False
        config = './openvpn-monitor.cfg'
        geoip_data = '/usr/share/GeoIP/GeoIPCity.dat'

    image_path = ''
    wsgi = True
    wsgi_output = ''
