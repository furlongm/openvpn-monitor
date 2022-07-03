#!/usr/bin/env python3

import os
import sys
from setuptools import setup

with open('VERSION.txt', 'r') as v:
    version = v.readline().strip()

with open('README.md', 'r') as r:
    long_description = r.read()

for dirpath, dirnames, filenames in os.walk('images/flags'):
    data_files = [('share/openvpn-monitor/images/flags',
                  [os.path.join(dirpath, f) for f in filenames])]

with open('requirements.txt') as rt:
    install_requires = []
    for line in rt.read().splitlines():
        if line.endswith("python_version <= '2.7'"):
            if sys.version_info[0] == 2:
                install_requires.append(line.split(';')[0])
        else:
            install_requires.append(line)

if sys.prefix == '/usr':
    conf_path = '/etc'
else:
    conf_path = sys.prefix
data_files.append((conf_path, ['openvpn-monitor.conf.example']))

setup(
    name='openvpn-monitor',
    version=version,
    author='Marcus Furlong',
    author_email='furlongm@gmail.com',
    description=('A simple web based openvpn monitor'),
    license='GPLv3',
    keywords='web openvpn monitor',
    url='http://openvpn-monitor.openbytes.ie',
    py_modules=['openvpn-monitor', ],
    install_requires=install_requires,
    long_description=long_description,
    long_description_content_type='text/markdown',
    data_files=data_files,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Application',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
)
