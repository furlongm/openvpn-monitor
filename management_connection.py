import re
import socket
import ssl
import sys

from logging import debug, info, warning

class ManagementConnection(object):

    def __init__(self, vpn_config, debug = False):
        self.__vpn_config = vpn_config
        self.__debug = debug
        self.__timeout = 3
        self.__error = False
        self.__socket = False
        self.__vpn_config['socket_connected'] = False
        
    def is_connected(self):
        return self.__socket

    def connect(self):
        try:
            self.__connect()
            self.__authenticate()
            self.__vpn_config['socket_connected'] = True
        except socket.timeout as e:
            self.__handle_connect_error(e, 'socket timeout')
        except socket.error as e:
            self.__handle_connect_error(e, 'socket error')
        except ssl.SSLError as e:
            self.__handle_connect_error(e, 'ssl error')
        except Exception as e:
            self.__handle_connect_error(e,'unexpected error')

    def __handle_connect_error(self, error, msg):
        self.__error = '{0!s}'.format(error)
        self.__vpn_config['error'] = self.__error
        self.__close()
        warning('{0!s}: {0!s}'.format(msg, error))

    def send_command(self, command):
        info('Sending command: {0!s}'.format(command))
        self.__send('{0!s}\n'.format(command))
        if command.startswith('kill') or command.startswith('client-kill'):
            return
        return self.__wait_for_data(command=command)

    def __wait_for_data(self, password=None, command=None):
        data = ''
        while 1:
            socket_data = self.__recv(1024)
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
            if data.endswith('ENTER PASSWORD:'):
                if password:
                    self.__send('{0!s}\n'.format(password))
                else:
                    warning('password requested but no password supplied by configuration')
            if data.endswith('SUCCESS: password is correct\r\n'):
                break
            if command == 'load-stats' and data != '':
                break
            if command == 'quit':
                break
            elif data.endswith("\nEND\r\n"):
                break
        if self.__debug:
            debug("=== begin raw data\n{0!s}\n=== end raw data".format(data))
        return data

    def __send(self, data):
        if sys.version_info[0] == 2:
            self.__socket.send(data)
        else:
            self.__socket.send(bytes(data, 'utf-8'))

    def __recv(self, length):
        if sys.version_info[0] == 2:
            return self.__socket.recv(length)

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
            self.__wait_for_data(password = self.__vpn_config.get('password'))

    def __connect(self):
        if self.__is_tls_socket():
            self.__connect_tls()
        elif self.__is_tcp_socket():
            self.__connect_tcp()
        elif self.__is_unix_socket():
            self.__connect_unix()    
        else:
            raise Exception('Unkwnown socket type')

    def __is_tls_socket(self):
        return self.__vpn_config.get('host') and self.__vpn_config.get('ssl')

    def __connect_tls(self):
        info('TLS socket connect')
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
        info('TCP socket connect')
        host = self.__vpn_config['host']
        port = int(self.__vpn_config['port'])
        self.__socket = socket.create_connection((host, port), self.__timeout)

    def __is_unix_socket(self):
        
        return bool(self.__vpn_config.get('socket'))

    def __connect_unix(self):
        info('UNIX socket connect')
        self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.__socket.connect(self.__vpn_config['socket'])    
