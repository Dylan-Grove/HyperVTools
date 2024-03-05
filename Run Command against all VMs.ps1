
$Username = "user"
$Password = "user" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

$ScriptBlock = {
    
    $DLLfound = test-path "C:\Program Files (x86)\Punchh"
    Write-host "$Env:Computername : $DLLFound"
}


#Run against all VMs
Get-vm | %{Invoke-Command -VMName $_.Name -ScriptBlock $ScriptBlock -Credential $credential}

#Run against just VMS with "KDS" in the name (includes the server)
Get-vm | Where {$Name -like "*KDS*"}| %{Invoke-Command -VMName $_.Name -ScriptBlock $ScriptBlock -Credential $credential}