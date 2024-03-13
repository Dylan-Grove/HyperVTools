Get-VM | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $Switch
Get-VM | Set-VMNetworkAdapterVlan -VlanId $ID -Access
Get-VM | Where-Object {$_.Name -like "*P39*"}| Set-VMNetworkAdapterVlan -VlanId 11 -Access