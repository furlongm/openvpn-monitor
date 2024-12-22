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

import os
import sys
from setuptools import setup, find_packages

with open('VERSION.txt', 'r', encoding='utf_8') as v:
    version = v.readline().strip()

with open('README.md', 'r', encoding='utf_8') as r:
    long_description = r.read()

with open('requirements.txt', 'r', encoding='utf_8') as rt:
    install_requires = rt.read().splitlines()

package_files = []
for directory in ['openvpn_monitor/static', 'openvpn_monitor/templates']:
    for (path, directories, filenames) in os.walk(directory):
        for filename in filenames:
            trimmed_path = path.replace('openvpn_monitor/', '')
            package_files.append(os.path.join(trimmed_path, filename))

if sys.prefix == '/usr':
    conf_path = '/etc'
else:
    conf_path = sys.prefix

data_files = []
for dirpath, dirnames, filenames in os.walk('etc'):
    for i, dirname in enumerate(dirnames):
        if dirname.startswith('.'):
            del dirnames[i]
    if filenames:
        data_files.append(
            ['/etc/openvpn-monitor', [os.path.join(dirpath, f) for f in filenames]]
        )

setup(
    name='openvpn-monitor',
    version=version,
    author='Marcus Furlong',
    author_email='furlongm@gmail.com',
    description=('A simple web based openvpn monitor'),
    license='GPLv3',
    keywords='web openvpn monitor',
    url='http://openvpn-monitor.openbytes.ie',
    packages=find_packages(),
    package_data={'openvpn_monitor': package_files},
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
