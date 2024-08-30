#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2024 Marcus Furlong <furlongm@gmail.com>
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

import logging
import os
import secrets
import sys
from datetime import datetime
from flask import Flask, request, render_template
from flask_wtf import CSRFProtect
from humanize import naturalsize
from pprint import pformat

cwd = os.path.dirname(__file__)
os.chdir(cwd)
sys.path.append(cwd)
from config.loader import ConfigLoader                    # noqa
from vpns.openvpn.data_collector import VPNDataCollector  # noqa
from vpns.openvpn.disconnector import VPNDisconnector     # noqa
from location_data.maxmind.geoip import GeoipDBLoader     # noqa
from util import is_truthy                                # noqa

logging.basicConfig(stream=sys.stderr, format='[%(asctime)s] [%(process)d] [%(levelname)s] %(message)s')
logging.getLogger().setLevel(logging.INFO)


def openvpn_monitor_wsgi():

    app = Flask(__name__)
    app.url_map.strict_slashes = False
    csrf = CSRFProtect(app)
    csrf.init_app(app)
    secret_key = secrets.token_hex(16)
    app.secret_key = secret_key

    if app.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    config_file = os.getenv('OPENVPNMONITOR_CONFIG_FILE', '/etc/openvpn-monitor/openvpn-monitor.conf')
    config = ConfigLoader(config_file)
    settings = config.settings
    loaded_vpns = config.vpns
    geoip_db = GeoipDBLoader(settings)

    @app.template_filter()
    def get_formatted_time_now(datetime_format):
        return datetime.now().strftime(datetime_format)

    @app.template_filter()
    def get_vpn_anchor(vpn):
        if vpn.get('name'):
            return vpn.get('name').lower().replace(' ', '_')

    @app.template_filter()
    def get_naturalsize(nbytes):
        if nbytes:
            return naturalsize(nbytes, binary=True)

    @app.template_filter()
    def get_full_location(session):
        full_location = ''
        location = session.get('location')
        if location:
            if location in ['RFC1918', 'loopback']:
                city = location
                country = 'Internet'
                full_location = f'{city}, {country}'
            else:
                if session.get('country'):
                    country = session.get('country')
                    full_location = country
                if session.get('region'):
                    region = session.get('region')
                    full_location = f'{region}, {full_location}'
                if session.get('city'):
                    city = session.get('city')
                    full_location = f'{city}, {full_location}'
        return full_location

    @app.template_filter()
    def get_flag(session):
        flag = ''
        location = session.get('location')
        if location:
            if location in ['RFC1918', 'loopback']:
                flag = 'images/flags/rfc.png'
            else:
                flag = f'images/flags/{location.lower()}.png'
        return flag

    @app.template_filter()
    def get_vpn_error(vpn):
        name = vpn.get('name')
        host = vpn.get('host')
        port = vpn.get('port')
        socket = vpn.get('socket')
        error = vpn.get('error')
        if host and port:
            return f'{host}:{port} ({error})'
        elif socket:
            return f'{socket} ({error})'
        else:
            logging.error(f'unknown error with vpn {name} - {error}')
            return f'network or unix socket ({error})'

    @app.template_filter()
    def get_session_headers(vpn_mode):
        server_headers = [
            'Username / Hostname',
            'VPN IP',
            'Remote IP',
            'Location',
            'Bytes In',
            'Bytes Out',
            'Connected Since',
            'Last Ping',
            'Time Online'
        ]
        client_headers = [
            'Tun-Tap-Read',
            'Tun-Tap-Write',
            'TCP-UDP-Read',
            'TCP-UDP-Write',
            'Auth-Read'
        ]
        if vpn_mode == 'Client':
            headers = client_headers
        elif vpn_mode == 'Server':
            headers = server_headers
        return headers

    @app.template_filter()
    def get_total_connected_time(connected_since):
        return str(datetime.now() - connected_since)[:-7]

    @app.context_processor
    def inject_settings():
        site = settings.get('site', 'Example')
        logo = settings.get('logo')
        enable_maps = is_truthy(settings.get('enable_maps', False))
        maps_height = settings.get('maps_height', 500)
        latitude = settings.get('latitude', 40.72)
        longitude = settings.get('longitude', -74)
        datetime_format = settings.get('datetime_format', '%d/%m/%Y %H:%M:%S')
        return dict(
            site=site,
            logo=logo,
            enable_maps=enable_maps,
            maps_height=maps_height,
            latitude=latitude,
            longitude=longitude,
            datetime_format=datetime_format,
        )

    @app.route('/', methods=['GET', 'POST'])
    def handle_root():
        vpn_data = VPNDataCollector(loaded_vpns, geoip_db.gi)
        vpns = vpn_data.vpns.items()
        pretty_vpns = pformat((dict(vpns)))
        logging.debug(f'=== begin vpns\n{pretty_vpns}\n=== end vpns')
        if request.method == 'GET':
            return render_template('base.html', vpns=vpns)
        elif request.method == 'POST':
            vpn_id = request.form.get('vpn_id')
            ip = request.form.get('ip')
            port = request.form.get('port')
            client_id = request.form.get('client_id')
            VPNDisconnector(
                vpns=vpns,
                vpn_id=vpn_id,
                ip=ip,
                port=port,
                client_id=client_id,
            )
            return render_template('base.html', vpns=vpns)

    return app


application = openvpn_monitor_wsgi()
