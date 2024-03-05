Import-Module $env:SyncroModule


get-vm | where {$_.State -eq "Off" -and $_.Name -ne "V4 Gold" -and $_.Name -ne "POS-TOWNSHIP"} | Start-VM

Rmm-Alert -Category 'Powered Off Vm' -Body "All VMs have been powered on."