Import-Module $env:SyncroModule
$BUILDorREBUILD = "Build"
$KDSVMName = ""
$GoldImagePath = ""
$VirtualDisksPath = ""

$Computername  = hostname
$SiteNumber    = [int]$Computername.ToUpper().split('P').split('H')[1]
$Timezone      = (Get-TimeZone).Id
$Username      = ""
$Password      = "" | ConvertTo-SecureString -asPlainText -Force
$credential    = New-Object System.Management.Automation.PSCredential($username,$password)
$Name          = $KDSVMName #(Get-VM $KDSVMName).name
$VirtualSwitch = [STRING](Get-VMNetworkAdapter -VM (Get-VM | select -first 1)).SwitchName
$VLAN          = (Get-VMNetworkAdapterVLAN -VM (Get-VM | select -first 1)).AccessVlanId
$VirtualDisks  = [STRING](get-item 'D:\Hyper-V\Virtual Disks*').FullName
$RAM           = 4GB
$VMDiskPath    = "$VirtualDisks\$Name.vhdx"

$KDSNames = @(
    "WSKDSDP${SiteNumber}EXPO",
    "WSKDSDP${SiteNumber}CALL",
    "WSKDSDP${SiteNumber}GRILL",
    "WSKDSDP${SiteNumber}APP",
    "WSKDSDP${SiteNumber}PIZZA",
    "WSKDSDP${SiteNumber}SPECIA",
    "WSKDSDP${SiteNumber}BBAREX",
    "WSKDSDP${SiteNumber}BBAR",
    "WSKDSDP${SiteNumber}FBAREX",
    "WSKDSDP${SiteNumber}FBAR"
    "WSKDSDP${SiteNumber}UBAREX",
    "WSKDSDP${SiteNumber}UBAR",
    "WSKDSDP${SiteNumber}DBAREX",
    "WSKDSDP${SiteNumber}DBAR"
)


$Date = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFileFolder = "C:\CBH-IT\Scripts\Logs\"
$LogFile = $LogFileFolder + "BuildRebuildKDSVM-$Date.txt"
If( !(test-path $LogFileFolder)){Mkdir $LogFileFolder}


Function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('INFO','WARN','ERROR')]
        [string]$Severity = 'INFO'
    )

    [pscustomobject]@{
        Time = (Get-Date -f g)
        Severity = $Severity
        Message = $Message
    } | Export-Csv -Path $Logfile -Append -NoTypeInformation
 }

Function CreateVirtualMachine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
 
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String]$VirtualDisksPath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String]$GoldImagePath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $MemoryStartupBytes,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Int32]$CPUCores,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Get-VMSwitch -Name $_})]
        [String]$VirtualSwitchName
    )
    
    Write-Log "Attempting to create Virtual Machine '$Name'" -Severity INFO

    # Create Virtual Disk
    if (!(Test-Path "$VirtualDisksPath\$Name.vhdx")) {
        Write-Host "Creating $Name's Virtual Disk..."
        Write-Log "Creating $Name's Virtual Disk..." -Severity INFO
        Copy-Item $GoldImagePath -Destination "$VirtualDisksPath\$Name.vhdx" 
    }
    else {
        Write-Host -ForegroundColor Yellow "$VirtualDisksPath\$Name.vhdx already exists. Skipping creation."
        Write-Log "$VirtualDisksPath\$Name.vhdx already exists. Skipping creation." -Severity WARN
    }

    # Create Virtual Machine
    if(!(get-vm $Name -erroraction silentlycontinue)){
        Write-Host "Creating $Name's Virtual Machine..."
        Write-Log "Creating $Name's Virtual Machine..." -Severity INFO
        New-VM -Name $Name -SwitchName $VirtualSwitchName -VHDPath "$VirtualDisksPath\$Name.vhdx" -Generation 2 -MemoryStartupBytes $MemoryStartupBytes
        Set-VMProcessor -VMName $Name -Count $CPUCores
        Set-VM -VMName $Name -CheckpointType Disabled -AutomaticStopAction ShutDown
        Enable-VMIntegrationService -Name 'Guest Service Interface' -VMName $Name
    }
    else{
        Write-Host -ForegroundColor Yellow "$Name's Virtual Machine already exists. Skipping creation."
        Write-Log "$Name's Virtual Machine already exists. Skipping creation." -Severity WARN
    }

    # Confirm Configuration
    If((Get-Item "$VirtualDisksPath\$Name.vhdx") -and (Get-VM $Name)){ Write-Log "Virtual Machine $Name creation completed successfully." -Severity INFO }
    If(!(Get-Item "$VirtualDisksPath\$Name.vhdx")){Write-Log "$Name's disk failed to create." -Severity ERROR}
    If(!(Get-VM $Name)){Write-Log "$Name's virtual machine failed to create." -Severity ERROR}

}

Function ConfigureVirtualMachine{
    [CmdletBinding()]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]$Name,
 
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [IPAddress]$IP
    )

    $ScriptBlock = {
        param($Name,$IP,$SiteSubnet,$SiteNumber,$DefaultGateway,$DNS1,$DNS2,$Timezone)
        

        # Remove existing IP address
        $interfaceIndex = (Get-NetIPInterface -AddressFamily IPv4 | Select -First 1).InterfaceIndex
        Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -erroraction silentlycontinue
        get-NetRoute -InterfaceIndex $interfaceIndex | Remove-NetRoute -Confirm:$false -erroraction silentlycontinue

        # Set autologin,timezone,ip address,firewall,disable ipv6,remove temp user
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name AutoAdminLogon -Value "1" 2>&1 | out-null
        New-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultUserName -Value "user" 2>&1 | out-null
        New-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultPassword -Value 'user' 2>&1 | out-null
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultUserName -Value "user" 2>&1 | out-null
        Set-ItemProperty –Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' –Name DefaultPassword -Value 'user' 2>&1 | out-null
        Set-TimeZone -ID $Timezone 2>&1 | out-null
        Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private 2>&1 | out-null
        netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes 2>&1 | out-null
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False 2>&1 | out-null
        Set-ItemProperty -Path REGISTRY::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name ConsentPromptBehaviorAdmin -Value 0 2>&1 | out-null
        Get-NetAdapterBinding | Where-Object ComponentID -EQ 'ms_tcpip6' | Disable-NetAdapterBinding -ComponentID 'ms_tcpip6' 2>&1 | out-null
        New-NetIPAddress -IPAddress ($IP) -DefaultGateway $DefaultGateway -AddressFamily IPv4 -PrefixLength 24 -InterfaceIndex (Get-NetIPInterface -AddressFamily IPv4 | Select -first 1 |select InterfaceIndex).InterfaceIndex | out-null
        Set-DnsClientServerAddress -InterfaceIndex (Get-NetIPInterface -AddressFamily IPv4 | Select -first 1 |select InterfaceIndex).InterfaceIndex -ServerAddresses ($DNS1,$DNS2) 2>&1 | out-null
        Remove-LocalUser temp -erroraction silentlycontinue

        # Write to log file that configuration has been run previously
        $Date = Get-Date -Format "yyyyMMdd_HHmmss"
        $LogFileFolder = "C:\CBH-IT\Scripts\Logs\"
        $LogFile = $LogFileFolder + "CreateAndConfigureVirtualMachines-$Date.txt"
        If( !(test-path $LogFileFolder)){Mkdir $LogFileFolder}
        "Configured=True" > $LogFile
        
        If ($Name -ne $env:COMPUTERNAME){
            Rename-Computer -NewName $Name -Confirm:$False -force 2>&1 | out-null
            shutdown /r /t 0
        }
    }
    

    If((Invoke-Command -VMName $Name -ErrorAction SilentlyContinue -Credential $credential -ScriptBlock{Get-Content C:\CBH-IT\Scripts\Logs\CreateAndConfigureVirtualMachines*}) -eq "Configured=True"){
        Write-Host "$Name has already been configured. Skipping."
        Write-Log "$Name has already been configured. Skipping." -Severity WARN
    }
    else{
        Write-Host "Configuring $Name's Virtual Machine..."
        Write-Log "Configuring $Name's Virtual Machine..." -Severity INFO
        Invoke-Command -VMName $Name -ScriptBlock $ScriptBlock -ArgumentList $Name,$IP,$SiteSubnet,$SiteNumber,$DefaultGateway,$DNS1,$DNS2,$Timezone -Credential $credential
    }
    
}

# Script start

Write-Log "Confirming all user-entered variables are valid..." -Severity INFO

Try {
    If (!(Test-Path -Path $GoldImagePath)) {Throw "GoldImagePath $GoldImagePath was not found. Please download the file to this folder on the Hyper-V"}
    If (!(Test-Path -Path $VirtualDisksPath)) {Throw "VirtualDisksPath $VirtualDisksPath was not found. Please ensure the correct path is entered and the folder exists on the server."}
    If ($BUILDorREBUILD -eq "Rebuild" -and !(Get-VM $KDSVMName)) {Throw "VM $KDSVMName was not found. Please ensure the name is correct."}
} Catch {
    Write-Host "Variable confirmation failed. Refer to the log for more information - $LogFile" -ForegroundColor Red
    Write-Log "Variable confirmation failed. Refer to the log for more information - $LogFile" -Severity ERROR
    Write-Log $_ -Severity ERROR
    Throw $_
}


    
# Get IP Info from server nic
If ((Get-NetIPAddress -InterfaceAlias NIC1 -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress){ 
    $SiteIP  = ((Get-NetIPAddress -InterfaceAlias NIC1 -AddressFamily IPv4).IPAddress).split('.')[2]
    $BrandIP = ((Get-NetIPAddress -InterfaceAlias NIC1 -AddressFamily IPv4).IPAddress).split('.')[1]
    }
Else{
    $SiteIP  = ((Get-NetIPAddress -InterfaceAlias NIC2 -AddressFamily IPv4).IPAddress).split('.')[2]
    $BrandIP = ((Get-NetIPAddress -InterfaceAlias NIC2 -AddressFamily IPv4).IPAddress).split('.')[1]
    }

# Remove old VM
if($BUILDorREBUILD -eq "Rebuild"){
    Get-VM $Name | Stop-VM -Force -Turnoff
    Get-VM $Name | Remove-VM -Force
    Remove-item $VMDiskPath -force
}

# Build VHD from gold image.
CreateVirtualMachine -Name $Name -MemoryStartupBytes $RAM -CPUCores 4 -VirtualDisksPath $VirtualDisksPath -GoldImagePath $GoldImagePath -VirtualSwitchName $VirtualSwitch
    
# Wait for VM to start
Write-Log "Virtual Machine creation completed. Moving on to configuration." -Severity INFO
Write-Log "Attempting to start all virtual machines..." -Severity INFO
Get-VM $name | Start-VM
Sleep 60
    


# Start Configuration
$subnetfull = "10."+$BrandIP+"."+ $siteIP + "."
$Index = $KDSNames.IndexOf($Name)
$IP = $subnetfull+($Index+101)
If($siteIP -eq 0){ $DG = $subnetfull+"62"}
Else{$DG = $subnetfull+"126"}
$DNS1 = $subnetfull+"126"
$DNS2 = "1.1.1.1"

ConfigureVirtualMachine -Name $name -IP $subnetfull

# Wait for Syncros Install
Sleep 40
    
# Install Syncros
Copy-VMFile -VMName $Name -SourcePath "C:\syncroinstaller.exe" -DestinationPath "C:\Temp\syncroinstaller.exe" -CreateFullPath -FileSource Host
Invoke-Command -VMName $Name -ScriptBlock {start c:\Temp\syncroinstaller.exe} -Credential $credential






Display-Alert -Message "Completed Automation [Rebuild Workstation (Simphony)] on $WorkstationRange. Once the devices are displaying the desktop, please run the CAL script in syncros to complete the process and delete the old device out of syncros. The device should appear in syncros under the Unassigned site."