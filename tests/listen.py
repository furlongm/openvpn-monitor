#!/usr/bin/env python

import sys
import socket
import select

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

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(timeout)
except socket.error as e:
    print('Failed to create socket: {0}').format(e)
    sys.exit(1)

print('[+] Listening for connections on {0}:{1}'.format(host, port))

data = ''
received_exit = False
while not received_exit:
    conn, address = s.accept()
    print('[+] Connection from {0}'.format(address))
    while 1:
        try:
            readable, writable, exceptional = \
                select.select([conn], [conn], [], timeout)
        except select.error:
            print('[+] Exception. Closing connection from {0}'.format(address))
            conn.shutdown(2)
            conn.close()
            break
        if readable:
            data = conn.recv(1024)
        if data.endswith(u'\n'):
            if data.startswith(u'status 3'):
                conn.send(status)
                data = ''
            elif data.startswith(u'state'):
                conn.send(state)
                data = ''
            elif data.startswith(u'version'):
                conn.send(version)
                data = ''
            elif data.startswith(u'load-stats'):
                conn.send(stats)
                data = ''
            elif data.startswith(u'quit'):
                print('[+] Closing connection from {0}'.format(address))
                conn.shutdown(2)
                conn.close()
                data = ''
                break
            elif data.startswith(u'exit'):
                print('[+] Closing connection from {0}'.format(address))
                conn.shutdown(2)
                conn.close()
                s.close()
                received_exit = True
                break
            else:
                pass
        elif readable and writable:
            print('[+] Closing connection from {0}'.format(address))
            conn.shutdown(2)
            conn.close()
            break
print('[+] Closing socket: {0}:{1}'.format(host, port))
