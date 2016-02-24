#!/usr/bin/env python

# Licensed under GPL v3
# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2015 Marcus Furlong <furlongm@gmail.com>


import socket
import ConfigParser
import locale
import re
import argparse
from datetime import datetime
import GeoIP
from ipaddr import IPv4Address


def get_config(config_file):

    config = ConfigParser.RawConfigParser()
    data = config.read(config_file)
    if len(data) == 0:
        print 'Config file does not exist or is unreadable'
        return default_settings()

    vpns = {}
    settings = {}
    sections = []
    try:
        sections = config.sections()
        for section in sections:
            if section == 'OpenVPN-Monitor':
                settings = parse_global_section(config)
            else:
                vpns[section] = parse_vpn_section(config, section)
    except:
        print 'Syntax error reading config file'
        return default_settings()

    return settings, vpns


def get_date(string):

    return datetime.strptime(string, "%a %b %d %H:%M:%S %Y")


def default_settings():

    print 'Using default of localhost:5555'

    vpns = {}
    settings = {'site': 'Default Site'}
    vpns['Default VPN'] = {'name': 'default', 'host': 'localhost',
                           'port': '5555', 'order': '1'}

    return settings, vpns


def parse_global_section(config):

    global debug

    tmp = {}
    vars = ['site', 'logo', 'height', 'width', 'lat', 'long', 'maps']

    for var in vars:
        try:
            tmp[var] = config.get('OpenVPN-Monitor', var)
        except ConfigParser.NoOptionError:
            pass

    if debug:
        print "=== begin section\n{0!s}\n=== end section".format(tmp)

    return tmp


def parse_vpn_section(config, section):

    global debug

    tmp = {}
    options = config.options(section)

    for option in options:
        try:
            tmp[option] = config.get(section, option)
            if tmp[option] == -1:
                print('CONFIG: skipping {0!s}'.format(option))
        except:
            print('CONFIG: exception on {0!s}'.format(option))
            tmp[option] = None

    if debug:
        print "=== begin section\n{0!s}\n=== end section".format(tmp)

    return tmp


def openvpn_connect(vpn, command):

    global debug

    host = vpn['host']
    port = int(vpn['port'])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data = ''

    try:
        s.connect((host, port))
        vpn['socket_connect'] = True
    except socket.error:
        vpn['socket_connect'] = False
        return False
    s.send(command)

    while 1:
        socket_data = s.recv(1024)
        socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
        data += socket_data
        if command == 'load-stats\n' and data != '':
            break
        elif data.endswith("\nEND\r\n"):
            break
    s.send('quit\n')
    s.close()

    if debug:
        print "=== begin raw data\n{0!s}\n=== end raw data".format(data)

    return data


def openvpn_parse_state(data):

    global debug

    state = {}

    for line in data.splitlines():
        tmp = line.split(',')
        if debug:
            print "=== begin split line\n{0!s}\n=== end split line".format(tmp)
        if tmp[0].startswith('>INFO') or \
           tmp[0].startswith('END') or \
           tmp[0].startswith('>CLIENT'):
            continue
        else:
            state['identifier'] = tmp[0]
            state['connected'] = tmp[1]
            state['success'] = tmp[2]
            state['local_ip'] = tmp[3]
            if tmp[4]:
                state['remote_ip'] = tmp[4]
                state['type'] = 'tap'
            else:
                state['type'] = 'tun'

    return state


def openvpn_parse_stats(data):

    global debug

    stats = {}

    line = re.sub('SUCCESS: ', '', data)
    tmp = line.split(',')

    if debug:
        print "=== begin split line\n{0!s}\n=== end split line".format(tmp)

    stats['nclients'] = re.sub('nclients=', '', tmp[0])
    stats['bytesin'] = re.sub('bytesin=', '', tmp[1])
    stats['bytesout'] = re.sub('bytesout=', '', tmp[2])

    return stats


def openvpn_parse_status(data):

    global debug

    client_section = False
    routes_section = False
    status_version = 1
    sessions = {}
    tap_session = {}
    gi = GeoIP.open(args.geoip_data, GeoIP.GEOIP_STANDARD)

    for line in data.splitlines():

        if ',' in line:
            tmp = line.split(',')
        else:
            tmp = line.split('\t')

        if debug:
            print "=== begin split line\n{0!s}\n=== end split line".format(tmp)

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
            tap_session['tuntap_read'] = tmp[1]
            continue
        if tmp[0] == 'TUN/TAP write bytes':
            tap_session['tuntap_write'] = tmp[1]
            continue
        if tmp[0] == 'TCP/UDP read bytes':
            tap_session['tcpudp_read'] = tmp[1]
            continue
        if tmp[0] == 'TCP/UDP write bytes':
            tap_session['tcpudp_write'] = tmp[1]
            continue
        if tmp[0] == 'Auth read bytes':
            tap_session['auth_read'] = tmp[1]
            sessions['tuntap'] = tap_session
            continue
        if client_section and not routes_section:
            if status_version == 1:
                sessions[tmp[1]] = session
                session['username'] = tmp[0]
                session['remote_ip'], session['port'] = tmp[1].split(':')
                session['bytes_recv'] = tmp[2]
                session['bytes_sent'] = tmp[3]
                session['connected_since'] = get_date(tmp[4])
            if status_version == 3:
                sessions[tmp[2]] = session
                session['username'] = tmp[1]
                session['remote_ip'], session['port'] = tmp[2].split(':')
                session['local_ip'] = tmp[3]
                session['bytes_recv'] = tmp[4]
                session['bytes_sent'] = tmp[5]
                session['connected_since'] = get_date(tmp[6])
            session['country'] = 'Unknown'
            ipaddr = IPv4Address(session['remote_ip'])
            if ipaddr.is_private:
                session['country'] = 'RFC1918'
            else:
                gir = gi.record_by_addr(session['remote_ip'])
                if gir is not None:
                    session['country'] = gir['country_code']
                    session['city'] = gir['city']
                    session['country_name'] = gir['country_name']
                    session['longitude'] = gir['longitude']
                    session['latitude'] = gir['latitude']
        if routes_section and not client_section:
            if status_version == 1:
                sessions[tmp[2]]['local_ip'] = tmp[0]
                sessions[tmp[2]]['last_seen'] = get_date(tmp[3])
            if status_version == 3:
                sessions[tmp[3]]['last_seen'] = get_date(tmp[4])

    if debug:
        if sessions:
            print "=== begin sessions\n{0!s}\n=== end sessions".format(sessions)

    return sessions


def print_table_headers(headers):

    print '<table><tr>'
    for header in headers:
        print '<th>{0!s}</th>'.format(header)
    print '</tr>'


def openvpn_print_html(vpn):

    if vpn['state']['connected'] == 'CONNECTED':
        connection = 'Connection up'
    else:
        connection = 'Connection down'

    if vpn['state']['success'] == 'SUCCESS':
        pingable = 'pingable'
    else:
        pingable = 'not pingable'

    nclients = vpn['stats']['nclients']
    bytesin = vpn['stats']['bytesin']
    bytesout = vpn['stats']['bytesout']

    print '<div><table><tr><td class="left">'
    print '{0!s} - {1!s}, {2!s}. {3!s} clients, {4!s} bytes in, {5!s} bytes out '.format(vpn['name'], connection, pingable, nclients, bytesin, bytesout)
    print '</td><td class="right">[ {0!s}'.format(vpn['state']['local_ip'])

    tun_headers = ['Username / Hostname', 'VPN IP Address',
                   'Remote IP Address', 'Port', 'Location', 'Recv', 'Sent',
                   'Connected Since', 'Last Ping', 'Time Online']
    tap_headers = ['Tun-Tap-Read', 'Tun-Tap-Write', 'TCP-UDP-Read',
                   'TCP-UDP-Write', 'Auth-Read']

    vpn_type = vpn['state']['type']
    vpn_sessions = vpn['sessions']

    print vpn_type

    if vpn_type == 'tun':
        print ']</td></tr></table>'
        print_table_headers(tun_headers)
    elif vpn_type == 'tap':
        print ' &lt;-&gt; {0!s}]</td></tr></table>'.format(vpn['state']['remote_ip'])
        print_table_headers(tap_headers)

    for key, session in vpn_sessions.items():
        print '<tr>'
        if vpn_type == 'tap':
            print '<td>{0!s}</td>'.format(locale.format('%d', int(session['tuntap_read']), True))
            print '<td>{0!s}</td>'.format(locale.format('%d', int(session['tuntap_write']), True))
            print '<td>{0!s}</td>'.format(locale.format('%d', int(session['tcpudp_read']), True))
            print '<td>{0!s}</td>'.format(locale.format('%d', int(session['tcpudp_write']), True))
            print '<td>{0!s}</td>'.format(locale.format('%d', int(session['auth_read']), True))
        else:
            country = None
            gir = None
            total_time = str(datetime.now() - session['connected_since'])[:-7]
            bytes_recv = int(session['bytes_recv'])
            bytes_sent = int(session['bytes_sent'])
            print '<td>{0!s}</td>'.format(session['username'])
            if 'local_ip' in session:
                print '<td>{0!s}</td>'.format(session['local_ip'])
            else:
                print '<td>ERROR</td>'
            print '<td>{0!s}</td>'.format(session['remote_ip'])
            print '<td>{0!s}</td>'.format(session['port'])

            if 'city' in session and 'country_name' in session:
                print '<td><img src="{0!s}" title="{1!s}, {2!s}" /></td>'.format('flags/{0!s}.png'.format(session['country'].lower()),
                     session['city'], session['country_name'])
            else:
                print '<td>{0!s}</td>'.format(session['country'])

            print '<td>{0!s}</td>'.format(locale.format('%d', bytes_recv, True))
            print '<td>{0!s}</td>'.format(locale.format('%d', bytes_sent, True))
            print '<td>{0!s}</td>'.format(str(session['connected_since'].strftime('%d/%m/%Y %H:%M:%S')))
            if 'last_seen' in session:
                print '<td>{0!s}</td>'.format(str(session['last_seen'].strftime('%d/%m/%Y %H:%M:%S')))
            else:
                print '<td>ERROR</td>'
            print '<td>{0!s}</td>'.format(total_time)
        print '</tr>'
    print '</table></div><br /><br />'


def google_maps_js(vpns, loc_lat, loc_long):

    sessions = 0
    print '<script type="text/javascript" src="https://maps.google.com/maps/api/js?sensor=true"></script>'
    print '<script type="text/javascript">'
    print 'function initialize() {'
    print 'var bounds = new google.maps.LatLngBounds();'
    print 'var markers = new Array();'
    for vkey, vpn in vpns:
        if 'sessions' in vpn:
            for skey, session in vpn['sessions'].items():
                if 'longitude' in session and 'latitude' in session:
                    print 'var latlng = new google.maps.LatLng({0!s}, {1!s});'.format(session['latitude'], session['longitude'])
                    print 'bounds.extend(latlng);'
                    print 'markers.push(new google.maps.Marker({{position: latlng, title: "{0!s}\n{1!s}"}}));'.format(session['username'], session['remote_ip'])
                    sessions = sessions + 1
    if sessions != 0:
        if sessions == 1:
            print 'bounds.extend(new google.maps.LatLng({0!s}, {1!s}));'.format(loc_lat, loc_long)
        print 'var myOptions = { zoom: 8, mapTypeId: google.maps.MapTypeId.ROADMAP };'
        print 'var map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);'
        print 'map.fitBounds(bounds);'
        print 'for ( var i=markers.length-1; i>=0; --i ) { markers[i].setMap(map); }'
        print '}'
        print '</script>'
    else:
        print 'var latlng = new google.maps.LatLng({0!s}, {1!s});'.format(loc_lat, loc_long)
        print 'var myOptions = { zoom: 8, center: latlng, mapTypeId: google.maps.MapTypeId.ROADMAP };'
        print 'var map = new google.maps.Map(document.getElementById("map_canvas"), myOptions);'
        print '}'
        print '</script>'


def google_maps_html():

    print '<div id="map_canvas" style="width:100%; height:300px"></div>'


def html_header(settings, vpns, maps):

    if 'lat' in settings:
        loc_lat = settings['lat']
    else:
        loc_lat = -37.8067
    if 'long' in settings:
        loc_long = settings['long']
    else:
        loc_long = 144.9635

    print "Content-Type: text/html\n"
    print '<!doctype html>'
    print '<html><head><meta charset="utf-8">'
    print '<title>{0!s} OpenVPN Status Monitor</title>'.format(settings['site'])
    print '<meta http-equiv="refresh" content="300" />'

    if maps:
        google_maps_js(vpns, loc_lat, loc_long)

    print '<style type="text/css">'
    print 'body { font-family: sans-serif; font-size: 12px; background-color: #FFFFFF; margin: auto; }'
    print 'h1 { color: #222222; font-size: 20px; text-align: center; padding-bottom: 0; margin-bottom: 0; }'
    print 'table { margin: auto; width:900px; border-collapse: collapse; }'
    print 'td.left {text-align: left; color: #232355; font-weight: bold; font-size: 14px; }'
    print 'td.right {text-align: right; color: #656511; font-weight: bold; font-size: 14px; }'
    print 'th { background: #555555; color: white; text-align: left; padding-left: 10px;}'
    print 'td { padding: 10px 10px 5px 5px; }'
    print 'div { padding: 7px 4px 6px 6px; margin: 0px auto; text-align: center; }'
    print 'div.footer { text-align: center; }'
    print '</style></head><body onload="initialize()">'
    if 'logo' in settings:
        print '<div><img class="logo" src="{0!s}" alt="logo" '.format(settings['logo'])
        if 'height' in settings and 'width' in settings:
            print 'height="{0!s}" width="{1!s}"'.format(settings['height'], settings['width'])
        print '/></div>'
    print '<h1>{0!s} OpenVPN Status Monitor</h1><br />'.format(settings['site'])


def sort_dict(adict):

    keys = adict.keys()
    keys.sort()

    return map(adict.get, keys)


def main(args):

    global debug
    debug = args.debug
    settings, vpns = get_config(args.config)

    sort_dict(vpns)

    for key, vpn in vpns.items():

        data = openvpn_connect(vpn, 'state\n')

        if vpn['socket_connect']:

            state = openvpn_parse_state(data)
            vpns[key]['state'] = state

            data = openvpn_connect(vpn, 'load-stats\n')
            stats = openvpn_parse_stats(data)
            vpns[key]['stats'] = stats

            data = openvpn_connect(vpn, 'status\n')
            sessions = openvpn_parse_status(data)
            vpns[key]['sessions'] = sessions

    if 'maps' in settings and settings['maps'] == 'True':
        maps = True
    else:
        maps = False

    html_header(settings, vpns.items(), maps)

    for key, vpn in vpns.items():
        if vpn['socket_connect']:
            openvpn_print_html(vpn)
        else:
            print '<div><table><tr><td class="left">'
            print '{0!s} - Connection refused to {1!s}:{2!s} </td>'.format(vpn['name'], vpn['host'], vpn['port'])
            print '</tr></table></div><br /><br />'

    if maps:
        google_maps_html()

    if debug:
        print "=== begin vpns\n{0!s}\n=== end vpns".format(vpns)

    print '<div class="footer">Page automatically reloads every 5 minutes'
    print '<br/>Last update: <b>{0!s}</b></div>'.format( \
        datetime.now().strftime('%a %d/%m/%Y %H:%M:%S'))
    print '</body></html>'


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
    main(args)
