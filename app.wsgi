import sys, os

os.chdir(os.path.dirname(__file__))
sys.path.append(os.path.dirname(__file__))

import bottle
openvpn_monitor = __import__('openvpn-monitor')
application=bottle.default_app()

from bottle import route, response, get, static_file

@route('/')
def root():
    openvpn_monitor.wsgi_output = ''
    openvpn_monitor.main()
    response.content_type = 'text/html;'
    return openvpn_monitor.wsgi_output

@get('/<filename:re:.*\.(jpg|png)>')
def images(filename):
    return static_file(filename, root='images')
