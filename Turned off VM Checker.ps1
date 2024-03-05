#Looks for VMs that are turned off and then deploys an automation to turn them on.
Import-Module $env:SyncroModule

$Whitelist = @(
    'PCNAME',
    )


$VMs = get-vm | where {$_.State -eq "Off" -and $_.Name -notin $Whitelist}
$VMs | Select Name,State  > C:\windows\temp\PoweredoffVMs.txt
$PoweredOffVMs = Get-content C:\windows\temp\PoweredoffVMs.txt -raw

$Body = @"
The following VMs were turned off:
$PoweredOffVMs

 Deploying Automated Remediation...
"@


If($VMs){
    Rmm-Alert -Category 'Powered Off VM' -Body $Body
}