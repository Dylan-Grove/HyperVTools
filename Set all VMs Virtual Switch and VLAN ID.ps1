Get-VM | Get-VMNetworkAdapter | Connect-VMNetworkAdapter -SwitchName $Switch
Get-VM | Set-VMNetworkAdapterVlan -VlanId $ID -Access