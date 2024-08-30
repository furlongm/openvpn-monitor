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

from geoip2 import database
from util import is_truthy


class GeoipDBLoader(object):

    def __init__(self, settings):
        geoip_data = settings.get('geoip_data')
        enable_maps = is_truthy(settings.get('enable_maps', False))
        self.gi = False
        if enable_maps and geoip_data:
            self.gi = database.Reader(geoip_data)
