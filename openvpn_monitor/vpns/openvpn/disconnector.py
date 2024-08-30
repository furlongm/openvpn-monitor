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
from ipaddress import ip_address
from vpns.openvpn.management_connection import ManagementConnection


class VPNDisconnector(object):

    def __init__(self, vpns, **kwargs):
        self.vpns = dict(vpns)
        self.check_disconnects(**kwargs)

    def check_disconnects(self, **kwargs):
        vpn_id = kwargs.get('vpn_id')
        if vpn_id:
            vpn = self.vpns[vpn_id]
            disconnection_allowed = vpn.get('show_disconnect')
            if disconnection_allowed:
                self.disconnect_client(vpn, **kwargs)

    def disconnect_client(self, vpn, **kwargs):
        connection = ManagementConnection(vpn)
        connection.connect()
        if connection.is_connected():
            name = vpn.get('name')
            version = vpn.get('version')
            command = False
            client_id = None
            if kwargs.get('client_id'):
                client_id = kwargs.get('client_id')
            if client_id and version.major == 2 and version.minor >= 4:
                logging.info(f'[{name}] Disconnecting client id `{client_id}`')
                command = f'client-kill {client_id}'
            else:
                ip = ip_address(kwargs.get('ip'))
                port = kwargs.get('port')
                if ip and port:
                    logging.info(f'[{name}] Disconnecting client `{ip}:{port}`')
                    command = f'kill {ip}:{port}'
            if command:
                connection.send_command(command)
            connection.disconnect()
