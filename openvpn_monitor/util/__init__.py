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
from datetime import datetime


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, '%a %b %d %H:%M:%S %Y')
    else:
        return datetime.fromtimestamp(float(date_string))


def is_truthy(s):
    return s in ['True', 'true', 'Yes', 'yes', True]


def multiline_info_log(s):
    for line in s.splitlines():
        logging.info(line)
