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
from datetime import datetime
from humanize import naturalsize
from collections import OrderedDict
from pprint import pformat

if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')


def warning(*objs):
    print("WARNING: ", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)


def socket_send(s, command):
    if sys.version_info[0] == 2:
        s.send(command)
    else:
        s.send(bytes(command, 'utf-8'))


def socket_recv(s, length):
    if sys.version_info[0] == 2:
        return s.recv(length)
    else:
        return s.recv(length).decode('utf-8')


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y")
    else:
        return datetime.fromtimestamp(float(date_string))


class config_loader(object):

    def __init__(self, config_file):

        self.settings = {}
        self.vpns = OrderedDict()
        config = configparser.RawConfigParser()
        contents = config.read(config_file)

        if not contents:
            print('Config file does not exist or is unreadable')
            self.load_default_settings()

        for section in config.sections():
            if section == 'OpenVPN-Monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def get_settings(self):
        return self.settings

    def get_vpns(self):
        return self.vpns

    def load_default_settings(self):
        warning('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site'}
        self.vpns['Default VPN'] = {'name': 'default', 'host': 'localhost',
                                   'port': '5555', 'order': '1'}

    def parse_global_section(self, config):
        vars = ['site', 'logo', 'latitude', 'longitude', 'maps']
        for var in vars:
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
                    print(('CONFIG: skipping {0!s}'.format(option)))
            except:
                print(('CONFIG: exception on {0!s}'.format(option)))
                vpn[option] = None
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))


def openvpn_connect(vpn):

    host = vpn['host']
    port = int(vpn['port'])
    timeout = 3

    try:
        s = socket.create_connection((host, port), timeout)
        vpn['socket_connected'] = True
        return s
    except socket.error:
        vpn['socket_connected'] = False
        return False


def openvpn_disconnect(s):
    s.close()


def openvpn_send_command(vpn, command):

    s = openvpn_connect(vpn)
    data = ''
    socket_send(s, command)

    while 1:
        socket_data = socket_recv(s, 1024)
        socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
        data += socket_data
        if command == 'load-stats\n' and data != '':
            break
        elif data.endswith("\nEND\r\n"):
            break

    socket_send(s, 'quit\n')
    openvpn_disconnect(s)

    if args.debug:
        debug("=== begin raw data\n{0!s}\n=== end raw data".format(data))

    return data


def openvpn_parse_state(data):

    state = {}

    for line in data.splitlines():
        tmp = line.split(',')
        if args.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(tmp))
        if tmp[0].startswith('>INFO') or \
           tmp[0].startswith('END') or \
           tmp[0].startswith('>CLIENT'):
            continue
        else:
            state['up_since'] = get_date(date_string=tmp[0], uts=True)
            state['connected'] = tmp[1]
            state['success'] = tmp[2]
            if tmp[3]:
                state['local_ip'] = ip_address(tmp[3])
            else:
                state['local_ip'] = ''
            if tmp[4]:
                state['remote_ip'] = ip_address(tmp[4])
                state['mode'] = 'Client'
            else:
                state['remote_ip'] = ''
                state['mode'] = 'Server'

    return state


def openvpn_parse_stats(data):

    stats = {}

    line = re.sub('SUCCESS: ', '', data)
    tmp = line.split(',')

    if args.debug:
        debug("=== begin split line\n{0!s}\n=== end split line".format(tmp))

    stats['nclients'] = int(re.sub('nclients=', '', tmp[0]))
    stats['bytesin'] = int(re.sub('bytesin=', '', tmp[1]))
    stats['bytesout'] = int(re.sub('bytesout=', '', tmp[2]).replace('\r\n', ''))

    return stats


def openvpn_parse_status(data):

    client_section = False
    routes_section = False
    status_version = 1
    sessions = {}
    client_session = {}
    gi = GeoIP.open(args.geoip_data, GeoIP.GEOIP_STANDARD)

    for line in data.splitlines():

        if ',' in line:
            tmp = line.split(',')
        else:
            tmp = line.split('\t')

        if args.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(tmp))

        if tmp[0].startswith('GLOBAL'):
            break
        if tmp[0] == 'HEADER':
            status_version = 3
            if tmp[1] == 'CLIENT_LIST':
                client_section = True
                routes_section = False
            if tmp[1] == 'ROUTING_TABLE':
                client_section = False
                routes_section = True
            continue
        if tmp[0] == 'Updated':
            continue
        if tmp[0] == 'Common Name':
            status_version = 1
            client_section = True
            routes_section = False
            continue
        if tmp[0] == 'ROUTING TABLE' or tmp[0] == 'Virtual Address':
            status_version = 1
            client_section = False
            routes_section = True
            continue
        if tmp[0].startswith('>CLIENT'):
            continue

        session = {}
        if tmp[0] == 'TUN/TAP read bytes':
            client_session['tuntap_read'] = int(tmp[1])
            continue
        if tmp[0] == 'TUN/TAP write bytes':
            client_session['tuntap_write'] = int(tmp[1])
            continue
        if tmp[0] == 'TCP/UDP read bytes':
            client_session['tcpudp_read'] = int(tmp[1])
            continue
        if tmp[0] == 'TCP/UDP write bytes':
            client_session['tcpudp_write'] = int(tmp[1])
            continue
        if tmp[0] == 'Auth read bytes':
            client_session['auth_read'] = int(tmp[1])
            sessions['Client'] = client_session
            continue
        if client_section and not routes_section:
            if status_version == 1:
                ident = tmp[1]
                sessions[ident] = session
                session['username'] = tmp[0]
                remote_ip, port = tmp[1].split(':')
                session['bytes_recv'] = int(tmp[2])
                session['bytes_sent'] = int(tmp[3])
                session['connected_since'] = get_date(tmp[4])
            if status_version == 3:
                ident = tmp[2]
                sessions[ident] = session
                session['username'] = tmp[1]
                if tmp[2].count(':') == 1:
                    remote_ip, port = tmp[2].split(':')
                else:
                    remote_ip = tmp[2]
                    port = None
                remote_ip_address = ip_address(remote_ip)
                local_ip = tmp[3]
                if local_ip == '':
                    session['local_ip'] = ''
                else:
                    session['local_ip'] = ip_address(tmp[3])
                session['bytes_recv'] = int(tmp[4])
                session['bytes_sent'] = int(tmp[5])
                session['connected_since'] = get_date(tmp[7], uts=True)
            session['location'] = 'Unknown'
            if type(remote_ip_address) == IPv6Address and \
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
                gir = gi.record_by_addr(str(session['remote_ip']))
                if gir is not None:
                    session['location'] = gir['country_code']
                    session['city'] = gir['city']
                    session['country_name'] = gir['country_name']
                    session['longitude'] = gir['longitude']
                    session['latitude'] = gir['latitude']
        if routes_section and not client_section:
            if status_version == 1:
                ident = tmp[2]
                sessions[ident]['local_ip'] = ip_address(tmp[0])
                sessions[ident]['last_seen'] = get_date(tmp[3])
            if status_version == 3:
                ident = tmp[3]
                sessions[ident]['last_seen'] = get_date(tmp[5], uts=True)

    if args.debug:
        if sessions:
            pretty_sessions = pformat(sessions)
            debug("=== begin sessions\n{0!s}\n=== end sessions".format(pretty_sessions))
        else:
            debug("no sessions")

    return sessions


def openvpn_parse_version(data):

    for line in data.splitlines():
        if line.startswith('OpenVPN'):
            return line.replace('OpenVPN Version: ', '')


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

    print('<table class="table table-striped table-bordered table-hover ')
    print('table-condensed table-responsive">')
    print('<thead><tr>')
    for header in headers:
        print('<th>{0!s}</th>'.format(header))
    print('</tr></thead><tbody>')


def print_session_table_footer():
    print('</tbody></table>')


def print_unavailable_vpn(vpn):

    anchor = vpn['name'].lower().replace(' ', '_')
    print('<div class="panel panel-danger" id="{0!s}">'.format(anchor))
    print('<div class="panel-heading">')
    print('<h3 class="panel-title">{0!s}</h3></div>'.format(vpn['name']))
    print('<div class="panel-body">')
    print('Connection refused to {0!s}:{1!s} </div></div>'.format(vpn['host'], vpn['port']))


def print_vpn(vpn):

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
    print('<div class="panel panel-success" id="{0!s}">'.format(anchor))
    print('<div class="panel-heading"><h3 class="panel-title">{0!s}</h3>'.format(
        vpn['name']))
    print('</div><div class="panel-body">')
    print('<table class="table table-condensed table-responsive">')
    print('<thead><tr><th>VPN Mode</th><th>Status</th><th>Pingable</th>')
    print('<th>Clients</th><th>Total Bytes In</th><th>Total Bytes Out</th>')
    print('<th>Up Since</th><th>Local IP Address</th>')
    if vpn_mode == 'Client':
        print('<th>Remote IP Address</th>')
    print('</tr></thead><tbody>')
    print('<tr><td>{0!s}</td>'.format(vpn_mode))
    print('<td>{0!s}</td>'.format(connection))
    print('<td>{0!s}</td>'.format(pingable))
    print('<td>{0!s}</td>'.format(nclients))
    print('<td>{0!s} ({1!s})</td>'.format(bytesin, naturalsize(bytesin, binary=True)))
    print('<td>{0!s} ({1!s})</td>'.format(bytesout, naturalsize(bytesout, binary=True)))
    print('<td>{0!s}</td>'.format(up_since.strftime('%d/%m/%Y %H:%M:%S')))
    print('<td>{0!s}</td>'.format(local_ip))
    if vpn_mode == 'Client':
        print('<td>{0!s}</td>'.format(remote_ip))
    print('</tr></tbody></table>')

    if vpn_mode == 'Client' or nclients > 0:
        print_session_table_headers(vpn_mode)
        print_session_table(vpn_mode, vpn_sessions)
        print_session_table_footer()

    print('<span class="label label-default">{0!s}</span>'.format(vpn['version']))
    print('</div></div>')


def print_client_session(session):

    print('<td>{0!s}</td>'.format(session['tuntap_read']))
    print('<td>{0!s}</td>'.format(session['tuntap_write']))
    print('<td>{0!s}</td>'.format(session['tcpudp_read']))
    print('<td>{0!s}</td>'.format(session['tcpudp_write']))
    print('<td>{0!s}</td>'.format(session['auth_read']))


def print_server_session(session):

    total_time = str(datetime.now() - session['connected_since'])[:-7]
    bytes_recv = session['bytes_recv']
    bytes_sent = session['bytes_sent']
    print('<td>{0!s}</td>'.format(session['username']))
    print('<td>{0!s}</td>'.format(session['local_ip']))
    print('<td>{0!s}</td>'.format(session['remote_ip']))
    print('<td>{0!s}</td>'.format(session['port']))

    if 'city' in session and 'country_name' in session:
        country = session['country_name']
        city = session['city']
        if city:
            full_location = '{0!s}, {1!s}'.format(city, country)
        else:
            full_location = country
        flag = 'flags/{0!s}.png'.format(session['location'].lower())
        print('<td><img src="{0!s}" title="{1!s}" alt="{1!s}" /> '.format(flag, full_location))
        print('{0!s}</td>'.format(full_location))
    else:
        print('<td>{0!s}</td>'.format(session['location']))

    print('<td>{0!s} ({1!s})</td>'.format(bytes_recv, naturalsize(bytes_recv, binary=True)))
    print('<td>{0!s} ({1!s})</td>'.format(bytes_sent, naturalsize(bytes_sent, binary=True)))
    print('<td>{0!s}</td>'.format(
        session['connected_since'].strftime('%d/%m/%Y %H:%M:%S')))
    if 'last_seen' in session:
        print('<td>{0!s}</td>'.format(
            session['last_seen'].strftime('%d/%m/%Y %H:%M:%S')))
    else:
        print('<td>ERROR</td>')
    print('<td>{0!s}</td>'.format(total_time))


def print_session_table(vpn_mode, sessions):

    for key, session in list(sessions.items()):
        print('<tr>')
        if vpn_mode == 'Client':
            print_client_session(session)
        elif vpn_mode == 'Server':
            print_server_session(session)
        print('</tr>')


def print_maps_header():

    print('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/leaflet.css" />')
    print('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet/0.7.7/leaflet.js"></script>')


def print_maps_html(vpns, latitude, longitude):

    print('<div class="panel panel-info"><div class="panel-heading">')
    print('<h3 class="panel-title">Map View</h3></div><div class="panel-body">')
    print('<div id="map_canvas" style="height:500px"></div>')
    print('<script type="text/javascript">')
    print('var map = L.map("map_canvas");')
    print('var centre = L.latLng({0!s}, {1!s});'.format(latitude, longitude))
    print('map.setView(centre, 8);')
    print('url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";')
    print('var layer = new L.TileLayer(url, {});')
    print('map.addLayer(layer);')
    print('var bounds = L.latLngBounds(centre);')
    for vkey, vpn in list(vpns.items()):
        if 'sessions' in vpn:
            print('bounds.extend(centre);')
            for skey, session in list(vpn['sessions'].items()):
                if 'longitude' in session and 'latitude' in session:
                    print('var latlng = new L.latLng({0!s}, {1!s});'.format(
                        session['latitude'], session['longitude']))
                    print('bounds.extend(latlng);')
                    print('var marker = L.marker(latlng).addTo(map);')
                    print('var popup = L.popup().setLatLng(latlng);')
                    print('popup.setContent("{0!s} - {1!s}");'.format(
                        session['username'], session['remote_ip']))
                    print('marker.bindPopup(popup);')
    print('map.fitBounds(bounds);')
    print('</script>')
    print('</div></div>')


def print_html_header(site, logo, vpns, maps):

    print("Content-Type: text/html\n")
    print('<!doctype html>')
    print('<html><head>')
    print('<meta charset="utf-8">')
    print('<meta http-equiv="X-UA-Compatible" content="IE=edge">')
    print('<meta name="viewport" content="width=device-width, initial-scale=1">')
    print('<title>{0!s} OpenVPN Status Monitor</title>'.format(site))
    print('<meta http-equiv="refresh" content="300" />')

    if maps:
        print_maps_header()

    print('<script src="//code.jquery.com/jquery-1.12.1.min.js"></script>')
    print('<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap.min.css" integrity="sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7" crossorigin="anonymous">')
    print('<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/css/bootstrap-theme.min.css" integrity="sha384-fLW2N01lMqjakBkx3l/M9EahuwpSfeNvV63J5ezn3uZzapT0u7EYsXMjQV+0En5r" crossorigin="anonymous">')
    print('<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.6/js/bootstrap.min.js" integrity="sha384-0mSbJDEHialfmuBBQP6A4Qrprq5OVfW37PRR3j5ELqxss1yVqOtnepnHVP9aJ7xS" crossorigin="anonymous"></script>')
    print('<body>')

    print('<nav class="navbar navbar-inverse">')
    print('<div class="container-fluid">')
    print('<div class="navbar-header">')
    print('<button type="button" class="navbar-toggle" ')
    print('data-toggle="collapse" data-target="#myNavbar">')
    print('<span class="icon-bar"></span>')
    print('<span class="icon-bar"></span>')
    print('<span class="icon-bar"></span>')
    print('</button>')

    print('<a class="navbar-brand" href="#">')
    print('{0!s} OpenVPN Status Monitor</a>'.format(site))

    print('</div><div class="collapse navbar-collapse" id="myNavbar">')
    print('<ul class="nav navbar-nav"><li class="dropdown">')
    print('<a class="dropdown-toggle" data-toggle="dropdown" href="#">VPN')
    print('<span class="caret"></span></a>')
    print('<ul class="dropdown-menu">')

    for key, vpn in vpns:
        if vpn['name']:
            anchor = vpn['name'].lower().replace(' ', '_')
            print('<li><a href="#{0!s}">{1!s}</a></li>'.format(anchor, vpn['name']))
    print('</ul></li>')

    if maps:
        print('<li><a href="#map_canvas">Map View</a></li>')

    print('</ul>')

    if logo:
        print('<a href="#" class="pull-right"><img alt="logo" ')
        print('style="max-height:46px; padding-top:3px;" ')
        print('src="{0!s}"></a>'.format(logo))

    print('</div></div></nav>')
    print('<div class="container-fluid">')


def print_html_footer():

    print('<div class="well well-sm">')
    print('Page automatically reloads every 5 minutes.')
    print('Last update: <b>{0!s}</b></div>'.format(
        datetime.now().strftime('%a %d/%m/%Y %H:%M:%S')))
    print('</div></body></html>')


def openvpn_collect_data(vpn):

    version = openvpn_send_command(vpn, 'version\n')
    vpn['version'] = openvpn_parse_version(version)

    state = openvpn_send_command(vpn, 'state\n')
    vpn['state'] = openvpn_parse_state(state)

    stats = openvpn_send_command(vpn, 'load-stats\n')
    vpn['stats'] = openvpn_parse_stats(stats)

    status = openvpn_send_command(vpn, 'status 3\n')
    vpn['sessions'] = openvpn_parse_status(status)


def init_vars(settings):

    site = 'Example'
    if 'site' in settings:
        site = settings['site']

    logo = None
    if 'logo' in settings:
        logo = settings['logo']

    maps = False
    if 'maps' in settings and settings['maps'] == 'True':
        maps = True

    latitude = -37.8067
    longitude = 144.9635
    if 'latitude' in settings:
        latitude = settings['latitude']
    if 'longitude' in settings:
        longitude = settings['longitude']

    return site, logo, maps, latitude, longitude


def main():

    cfg = config_loader(args.config)
    settings = cfg.get_settings()
    vpns = cfg.get_vpns()

    site, logo, maps, latitude, longitude = init_vars(settings)

    print_html_header(site, logo, list(vpns.items()), maps)

    for key, vpn in list(vpns.items()):
        s = openvpn_connect(vpn)
        if s:
            openvpn_disconnect(s)
            openvpn_collect_data(vpn)
        if vpn['socket_connected']:
            print_vpn(vpn)
        else:
            print_unavailable_vpn(vpn)

    if maps:
        print_maps_html(vpns, latitude, longitude)

    print_html_footer()

    if args.debug:
        pretty_vpns = pformat((dict(vpns)))
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
    main()
