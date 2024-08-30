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

import configparser
import logging
import os
from collections import OrderedDict
from pprint import pformat
from util import is_truthy, multiline_info_log


class ConfigLoader(object):

    def __init__(self, config_file):
        self.settings = {}
        self.vpns = OrderedDict()
        self.load_config_file(config_file)
        logging.debug(f'=== begin section\n{self.settings}\n=== end section')
        logging.debug(f'=== begin section\n{self.vpns}\n=== end section')

    def load_config_file(self, config_file):
        if os.path.isfile(config_file) and os.access(config_file, os.R_OK):
            logging.info(f'Using config file: {config_file}')
        else:
            logging.error(f'Config file does not exist or is unreadable: {config_file}')
            config_file = os.path.join(os.path.abspath(os.getcwd()), 'openvpn-monitor.conf')
            logging.warning(f'Trying {config_file} as config file')
        config = configparser.RawConfigParser()
        contents = config.read(config_file)
        if contents:
            self.parse_config(config)
        else:
            logging.error(f'No settings found in config file: {config_file}')
            logging.warning(f'Falling back to default settings')
            self.load_default_settings()

    def parse_config(self, config):
        for section in config.sections():
            if section.lower() == 'openvpn-monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)
        multiline_info_log(f'Using loaded config:\n{pformat(config._sections)}')

    def load_default_settings(self):
        self.settings = {'site': 'Default Site',
                         'enable_maps': False,
                         'geoip_data': '/usr/share/GeoIP/GeoLite2-City.mmdb',
                         'datetime_format': '%d/%m/%Y %H:%M:%S'}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'password': '',
                                    'show_disconnect': False}
        logging.info('Using default settings:')
        multiline_info_log(pformat(self.settings))
        multiline_info_log(pformat(self.vpns))

    def parse_global_section(self, config):
        global_vars = [
            'site',
            'logo',
            'latitude',
            'longitude',
            'enable_maps',
            'maps_height',
            'geoip_data',
            'datetime_format'
        ]
        for var in global_vars:
            try:
                self.settings[var] = config.get('openvpn-monitor', var)
            except configparser.NoOptionError:
                pass

    def parse_vpn_section(self, config, section):
        self.vpns[section] = {}
        vpn = self.vpns[section]
        options = config.options(section)
        for option in options:
            try:
                vpn[option] = config.get(section, option)
                if vpn[option] == -1:
                    logging.warning(f'config: skipping {option}')
            except configparser.Error as e:
                logging.warning(f'config: {e} on option {option}: ')
                vpn[option] = None
        vpn['show_disconnect'] = is_truthy(vpn.get('show_disconnect', False))
