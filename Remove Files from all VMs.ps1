#Run this on the HyperV server to remove files from all VMs with TB in the name
$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)


$ScriptBlock = {

    Get-process -name ServiceHost | stop-process -force
    

    $path='C:\Micros\Simphony\WebServer\wwwroot\EGateway\Handlers\ExtensionApplications\PunchhInterface'
    Get-ChildItem $path -Recurse | Remove-Item -Force 
    Remove-Item $path -Recurse -Force
    Remove-item -Path C:\Micros\Simphony\WebServer\wwwroot\EGateway\Handlers\ExtensionApplications\PunchhSimphony -Recurse -force
    Remove-item -Path C:\Micros\Simphony\WebServer\wwwroot\EGateway\Handlers\ExtensionApplications\PunchhConnInfo_Abbotsford -Recurse -force
    shutdown /r /t 0

}


#Run against all VMs
Get-vm | where {$_.Name -like "*tb*"}| %{Invoke-Command -VMName $_.Name -ScriptBlock $ScriptBlock -Credential $credential}