#Shutsdown, deletes, and then rebuilds a RES3700 workstation. Configures the workstation, reboots, then runs CAL.
#Requires the image file to be store in D:\Images\Micros
#Enter the WorkstationRange as 12,23,43 (Only Tablets 12, 23 and 43 will be done).
#Once the script is done, the workstation will be on the desktop and ready to change the resolution to 1024x768 and then run CAL.


Import-Module $env:SyncroModule

$Range = $WorkstationRange.ToCharArray()

Try{ If($Range -isnot [Array]){Throw} }
Catch{Throw "WorkstationRange Variable is not an array. Please format as 1,5,9,10 or just 1"}

Try{ If(!(Test-Path -Path "D:\Images\MicrosGoldEnterprise64bitV4.1.VHDX")){Throw} }
Catch{Throw "D:\Images\MicrosGoldEnterprise64bitV4.1.VHDX was not found. Please download the file to this folder on the Hyper-V"}

Try{ If ($WorkstationRange.Split(',')[0].ToInt32($null) -isnot [INT32]){Throw} }
Catch {Throw "Invalid characters found in WorkstationRange, please only use numbers."}




$Computername  = hostname
$Gold          = Get-Item -Path "D:\Images\MicrosGoldEnterprise64bitV4.1.VHDX"
$VirtualDisks  = [STRING](get-item 'D:\Hyper-V\Virtual Hard*').FullName
$Site          = [int]$Computername.ToUpper().split('P').split('H')[1]
$SiteIP        = ((Get-NetIPAddress -InterfaceAlias NIC1 -AddressFamily IPv4).IPAddress).split('.')[2]
$Timezone      = (Get-TimeZone).Id
$Username      = ""
$Password      = "" | ConvertTo-SecureString -asPlainText -Force
$credential    = New-Object System.Management.Automation.PSCredential($username,$password)
$VirtualSwitch = (Get-VMNetworkAdapter -VM (Get-VM | select -first 1)).SwitchName
$VLAN          = (Get-VMNetworkAdapterVLAN -VM (Get-VM | select -first 1)).AccessVlanId


$WorkstationRange.Split(',') | %{
    $VM = $_.ToInt32($null)

    if($VM -gt 9){$Name = "WKS32-"+"$VM"}
    else{$Name = "WKS32-"+"0$VM"}

    
    # Remove old VM
    Get-VM $Name | Stop-VM -Force -Turnoff
    Get-VM $Name | Remove-VM -Force
    Remove-item $VirtualDisks\$Name.vhdx -force

    # Build VHD from gold image.
    if( ! (Test-Path "$VirtualDisks\$Name.vhdx" )){
        Copy-Item $Gold -Destination "$VirtualDisks\$Name.vhdx" 
    }
    else{ Write-Host -ForegroundColor red "$VirtualDisks\$Name.vhdx Already exists."}
    
    # Build VM configuration
    New-VM -Name $Name -SwitchName $VirtualSwitch -VHDPath "$VirtualDisks\$Name.vhdx" -Generation 2 -MemoryStartupBytes 4GB
    Set-VMProcessor -VMName $Name -Count 2
    set-vm -VMName $Name -CheckpointType Disabled -AutomaticStopAction ShutDown
    Enable-VMIntegrationService -Name 'Guest Service Interface' -VMName $Name
    Set-VMNetworkAdapterVlan -VlanId $VLAN -Access -VMName $Name
    Start-VM $Name
    
    # Wait for VM to start
    Sleep 180

    # Start Configuration
    $subnetfull = "10.10."+ $siteIP + "."
    
    $IP = $subnetfull+($VM+10)
    If($siteIP -eq 0){ $DG = $subnetfull+"62"}
    Else{$DG = $subnetfull+"126"}
    $DNS1 = $subnetfull+"126"
    $DNS2 = "1.1.1.1"

    $ScriptBlock = {
        param($Name,$IP,$Subnetfull,$site,$DG,$DNS1,$DNS2,$Timezone)
        
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name AutoAdminLogon -Value "1"
        New-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultUserName -Value ""
        New-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultPassword -Value ''
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultUserName -Value ""
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultPassword -Value ''

        Set-TimeZone -ID $Timezone
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
        netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
        Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0
        Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6' | Disable-NetAdapterBinding -ComponentID 'ms_tcpip6'
        
        $Newname = $name
        Rename-Computer -NewName $newName
        
        Remove-Item "C:\Users\User\Desktop\Micros Simphony ServiceHost.lnk" -force
        
        New-NetIPAddress -IPAddress ($ip) -DefaultGateway $DG -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex (Get-NetIPInterface -AddressFamily IPv4 | Select -first 1 |select InterfaceIndex).InterfaceIndex
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPInterface -AddressFamily IPv4 | Select -first 1 |select InterfaceIndex).InterfaceIndex -ServerAddresses ($DNS1,$DNS2)

        Remove-LocalUser temp
        shutdown /r /t 0
    }

    Invoke-Command -VMName $Name -ScriptBlock $ScriptBlock -ArgumentList $Name,$IP,$Subnetfull,$site,$DG,$DNS1,$DNS2,$Timezone -Credential $credential
    Display-Alert -Message "Running Automation [Rebuild Workstation (RES3700)] on $WorkstationRange. Once the devices are displaying the desktop, please set the resolution to 1024x768 and then CAL the devices."

}