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
import re
import socket
import ssl


class ManagementConnection(object):

    def __init__(self, vpn_config):
        self.__vpn_config = vpn_config
        self.__name = self.__vpn_config.get('name')
        self.__timeout = 3
        self.__error = False
        self.__socket = False
        self.__vpn_config['management_connection_successful'] = False

    def is_connected(self):
        return self.__socket

    def connect(self):
        try:
            self.__connect()
            self.__authenticate()
            self.__vpn_config['management_connection_successful'] = True
        except socket.timeout as e:
            self.__handle_connect_error(e, 'socket timeout')
        except socket.error as e:
            self.__handle_connect_error(e, 'socket error')
        except ssl.SSLError as e:
            self.__handle_connect_error(e, 'ssl error')
        except Exception as e:
            self.__handle_connect_error(e, 'unexpected error')

    def __handle_connect_error(self, error, msg):
        self.__error = error
        self.__vpn_config['error'] = self.__error
        self.__close()
        logging.warning(f'{msg}: {error}')

    def send_command(self, command):
        logging.info(f'[{self.__name}] Sending openvpn management command: `{command.rstrip()}`')
        self.__send(f'{command}\n')
        if command.startswith('kill') or command.startswith('client-kill'):
            return
        return self.__wait_for_data(command=command)

    def __wait_for_data(self, password=None, command=None):
        data = ''
        while 1:
            try:
                socket_data = self.__recv(1024)
            except TimeoutError:
                logging.error(f'[{self.__name}] Timeout receiving data')
                break
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
            if data.endswith('ENTER PASSWORD:'):
                if password:
                    self.__send(f'{password}\n')
                else:
                    logging.warning(f'[{self.__name}] Password requested but no password supplied by configuration')
            if data.endswith('SUCCESS: password is correct\r\n'):
                break
            if command == 'load-stats' and data != '':
                break
            if command == 'quit':
                break
            elif data.endswith("\nEND\r\n"):
                break
        logging.debug(f'[{self.__name}] === begin raw data\n{data}\n=== end raw data')
        return data

    def __send(self, data):
        self.__socket.send(bytes(data, 'utf-8'))

    def __recv(self, length):
        return self.__socket.recv(length).decode('utf-8')

    def disconnect(self):
        if self.__socket:
            self.send_command('quit')
            self.__close()

    def __close(self):
        if self.__socket:
            self.__socket.shutdown(socket.SHUT_RDWR)
            self.__socket.close()
            self.__socket = False

    def __authenticate(self):
        if (self.__vpn_config.get('password')):
            self.__wait_for_data(password=self.__vpn_config.get('password'))

    def __connect(self):
        if self.__is_tls_socket():
            self.__connect_tls()
        elif self.__is_tcp_socket():
            self.__connect_tcp()
        elif self.__is_unix_socket():
            self.__connect_unix()
        else:
            raise Exception('Unknown socket type')

    def __is_tls_socket(self):
        return self.__vpn_config.get('host') and self.__vpn_config.get('ssl')

    def __connect_tls(self):
        logging.info(f'[{self.__name}] Initiating TLS socket connection')
        context = self.__create_tls_context()
        self.__connect_tcp()
        self.__socket = context.wrap_socket(self.__socket)

    def __create_tls_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        if (self.__vpn_config.get('ssl') == 'any-cert'):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    def __is_tcp_socket(self):
        return self.__vpn_config.get('host') and not self.__vpn_config.get('ssl')

    def __connect_tcp(self):
        host = self.__vpn_config['host']
        port = int(self.__vpn_config['port'])
        logging.info(f'[{self.__name}] Initiating TCP socket connection to {host}:{port}')
        self.__socket = socket.create_connection((host, port), self.__timeout)

    def __is_unix_socket(self):
        return bool(self.__vpn_config.get('socket'))

    def __connect_unix(self):
        self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_socket = self.__vpn_config['socket']
        logging.info(f'[{self.__name}] Initiating UNIX socket connection to {unix_socket}')
        self.__socket.connect(unix_socket)
