#Deploys a file to a VM and installs it

get-vm | Enable-VMIntegrationService -Name 'Guest Service Interface'

$Username = ""
$Password = "" | ConvertTo-SecureString -asPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($username,$password)

$ScriptBlock = {
    
    start c:\Temp\syncroinstaller.exe

}


#Run against all VMs
Get-VM | %{Copy-VMFile -VMName $_.Name -SourcePath "C:\syncroinstaller.exe" -DestinationPath "C:\Temp\syncroinstaller.exe" -CreateFullPath -FileSource Host -verbose}
Get-vm | %{Invoke-Command -VMName $_.Name -ScriptBlock $ScriptBlock -Credential $credential}
