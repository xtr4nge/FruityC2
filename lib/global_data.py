#!/usr/bin/python

# Copyright (C) 2017 xtr4nge [_AT_] gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# GLOBAL
option_base64 = False
option_encryption = False
option_compression = True
option_debug = False

class global_data():
    def __init__(self):
        self.target = {} # IN USE: FruityC2.py, libs/Utils.py
        self.payload = {}
        self.web_delivery = {}
        self.listener = {}
        self.listener_details = {}
        self.credentials = {} # IN USE: FruityC2.py, libs/Utils.py
        
        self.profile_file = ""
        self.key = "SECRET"
        self.utimestamp = ""
        self.load_command = ""

gdata = global_data()
