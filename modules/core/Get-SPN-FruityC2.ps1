function Get-SPN-FruityC2() {
    param (
        $search = "*"
    )
    
    $strFilter = "(&(servicePrincipalName="+$search+")(!ObjectCategory=Computer))"
    
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.SearchRoot = $objDomain
    $objSearcher.PageSize = 1000
    $objSearcher.Filter = $strFilter
    $objSearcher.SearchScope = "Subtree"
    
    $objSearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
    $objSearcher.PropertiesToLoad.Add("userPrincipalName")  | Out-Null
    $objSearcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null
    
    $colProplist = "name"
    
    $colResults = $objSearcher.FindAll()
    
    foreach ($objResult in $colResults) {
        $objItem = $objResult.Properties;
        foreach ($s_name in $objItem.serviceprincipalname) {
            $samaccountname = $objItem.samaccountname
            $userprincipalname = $s_name # $objItem.serviceprincipalname
            Write-Output "$samaccountname|$userprincipalname"
        }
    }
}