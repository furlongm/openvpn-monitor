#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020-2023 Marcus Furlong <furlongm@gmail.com>
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
import select
import socket
import sys

logging.basicConfig(stream=sys.stderr, format='[%(asctime)s] [%(process)d] [%(levelname)s] %(message)s')
logging.getLogger().setLevel(logging.INFO)

host = '127.0.0.1'
port = 5555
timeout = 3

status = """TITLE	OpenVPN 2.3.10 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [MH] [IPv6] built on Jan  4 2016\r
TIME	Wed Mar 23 21:42:22 2016	1458729742\r
HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username\r
CLIENT_LIST	furlongm	::ffff:59.167.120.210	10.10.10.6	369528	1216150	Wed Mar 23 21:40:15 2016	1458729615	furlongm\r
CLIENT_LIST	furlongm	59.167.120.211:12345	10.10.10.7	12345	11615	Wed Mar 23 21:41:45 2016	1458729715	furlongm\r
CLIENT_LIST	furlongm	2001:4860:4801:3::20	10.10.10.8	12345	11615	Wed Mar 23 21:43:25 2016	1458729815	furlongm\r
HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)\r
ROUTING_TABLE	10.10.10.6	furlongm	::ffff:59.167.120.210	Wed Mar 23 21:42:22 2016	1458729742\r
ROUTING_TABLE	10.10.10.7	furlongm	59.167.120.211:12345	Wed Mar 23 21:42:22 2016	1458729742\r
ROUTING_TABLE	10.10.10.8	furlongm	2001:4860:4801:3::20	Wed Mar 23 21:42:22 2016	1458729742\r
GLOBAL_STATS	Max bcast/mcast queue length	0\r
END\r
"""
state = """1457583275,CONNECTED,SUCCESS,10.10.10.1,\r
END\r
"""
version = """OpenVPN Version: OpenVPN 2.3.10 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [MH] [IPv6] built on Jan  4 2016\r
Management Version: 1\r
END\r
"""
stats = """SUCCESS: nclients=1,bytesin=556794,bytesout=1483013\r
"""


def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(timeout)
        return s
    except socket.error as e:
        logging.error(f'Failed to create socket: {e}')
        sys.exit(1)


def socket_connection_listener(s):
    logging.info(f'Listening for connections on {host}:{port}')
    data = b''
    exit_listener = False
    while not exit_listener:
        conn, address = s.accept()
        logging.info(f'Connection from {address}')
        while 1:
            try:
                readable, writeable, in_error = \
                    select.select([conn, ], [conn, ], [], timeout)
            except (select.error, socket.error):
                logging.error(f'Closing connection from {address}')
                conn.shutdown(2)
                conn.close()
                break
            if readable:
                data = conn.recv(1024)
            if data.decode().endswith('\n'):
                if data.decode().startswith('status 3'):
                    conn.send(bytes(status, 'utf-8'))
                    data = b''
                elif data.decode().startswith('state'):
                    conn.send(bytes(state, 'utf-8'))
                    data = b''
                elif data.decode().startswith('version'):
                    conn.send(bytes(version, 'utf-8'))
                    data = b''
                elif data.decode().startswith('load-stats'):
                    conn.send(bytes(stats, 'utf-8'))
                    data = b''
                elif data.decode().startswith('quit'):
                    logging.info(f'Closing connection from {address}')
                    conn.close()
                    data = b''
                    break
                elif data.decode().startswith('exit'):
                    logging.info(f'Closing connection from {address}')
                    conn.shutdown(2)
                    conn.close()
                    s.close()
                    exit_listener = True
                    break
                else:
                    pass
            elif readable and writeable:
                logging.info(f'Closing connection from {address}')
                conn.shutdown(2)
                conn.close()
                break
    logging.info(f'Closing socket: {host}:{port}')


if __name__ == '__main__':
    s = create_socket()
    socket_connection_listener(s)
